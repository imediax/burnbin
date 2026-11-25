"""
Zero-Knowledge Self-Destructing Secret Pastebin (Burn-on-Read).
Standard library Python HTTP Server with pluggable SQLite/Firestore persistence.
"""

import argparse
import hashlib
import json
import mimetypes
import os
import re
import secrets
import signal
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlparse

from db import PayloadTooLargeError, SecretStore, create_secret_store

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Safety limits & shared client configuration
APP_VERSION = "2.0.2"
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2MB max encrypted envelope (supports ~1MB binary attachment)
MAX_ATTACHMENT_BYTES = 1024 * 1024  # 1MB unencrypted attachment ceiling
MAX_TEXT_BYTES = 4 * 1024 * 1024  # 4MB V2 text/metadata ceiling
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 2592000  # 30 days
TTL_PRESETS = [300, 600, 3600, 86400, 604800, 2592000]
MAX_VIEWS_PRESETS = [1, 3, 5]
MAX_VIEWS_LIMIT = 20
SOCKET_TIMEOUT_SECONDS = 15.0
SECRET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
KEY_LOG_REDACT_PATTERN = re.compile(r"([?&]key=)[^&\s\"']+", re.IGNORECASE)
DEFAULT_SHA256_FINGERPRINT = "7E:D4:97:03:14:8D:3C:F6:EA:7C:12:EC:BC:D8:9B:29:21:42:EC:AF:AA:BE:6C:E5:6F:46:DC:DB:DC:5E:65:FA"
RELEASE_SHA256_FINGERPRINT = "CD:1F:E7:33:69:1F:C9:93:BB:EF:A3:63:D4:B7:02:7D:91:1E:56:AA:31:B9:FE:9B:37:6E:FA:53:59:9C:6B:13"

_SHELL_ASSET_FILES = (
    "style.css",
    "shared.js",
    "crypto.js",
    "qr.js",
    "create.js",
    "view.js",
    "icon.svg",
)


def _compute_shell_cache_name() -> str:
    h = hashlib.sha256()
    h.update(APP_VERSION.encode("utf-8"))
    for rel_name in _SHELL_ASSET_FILES:
        asset_path = os.path.join(STATIC_DIR, rel_name)
        if os.path.isfile(asset_path):
            with open(asset_path, "rb") as f:
                h.update(rel_name.encode("utf-8"))
                h.update(f.read())
    return f"burnbin-shell-v{APP_VERSION}-{h.hexdigest()[:8]}"


_SHELL_CACHE_NAME = _compute_shell_cache_name()

_EXPLICIT_MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webmanifest": "application/manifest+json; charset=utf-8",
}

_STRICT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none';"
)


class RateLimiter:
    """
    Thread-safe in-memory sliding-window per-IP rate limiter.

    Counters are intentionally per Cloud Run instance rather than persisted in
    Firestore to avoid write amplification under abusive traffic; effective
    global bursts remain bounded by Cloud Run max-instances.
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, deque] = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def allow(self, client_ip: str) -> tuple[bool, int]:
        if self.max_requests <= 0 or self.window_seconds <= 0:
            return True, 0

        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            # Periodically prune inactive IPs to keep memory bounded
            if now - self._last_prune >= self.window_seconds:
                stale_ips = [ip for ip, q in self._hits.items() if not q or q[-1] <= cutoff]
                for ip in stale_ips:
                    del self._hits[ip]
                self._last_prune = now

            q = self._hits.setdefault(client_ip, deque())
            while q and q[0] <= cutoff:
                q.popleft()

            if len(q) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (now - q[0])) + 1)
                return False, retry_after

            q.append(now)
            return True, 0


class SecretRequestHandler(BaseHTTPRequestHandler):
    db: SecretStore
    rate_limiter: Optional[RateLimiter] = None
    read_rate_limiter: Optional[RateLimiter] = None

    def setup(self):
        super().setup()
        if getattr(self, "request", None) is not None:
            try:
                self.request.settimeout(SOCKET_TIMEOUT_SECONDS)
            except Exception:
                pass

    def _get_client_ip(self) -> str:
        try:
            hops = int(os.environ.get("TRUST_PROXY_HOPS", "1"))
        except (TypeError, ValueError):
            hops = 1
        forwarded_for = self.headers.get("X-Forwarded-For", "").strip()
        if hops > 0 and forwarded_for:
            parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
            if parts:
                return parts[-min(hops, len(parts))]
        return self.client_address[0] if self.client_address else "unknown"

    def log_message(self, format, *args):
        # Sanitize logged URLs so ?key=... is never written to server logs
        message = KEY_LOG_REDACT_PATTERN.sub(r"\1[REDACTED]", format % args)
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {message}\n")

    def _send_security_headers(self, corp: str = "same-origin"):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
        self.send_header("Cross-Origin-Resource-Policy", corp)
        self.send_header("Content-Security-Policy", _STRICT_CSP)
        if self.headers.get("X-Forwarded-Proto", "").strip().lower() == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def _send_text(self, status: int, text: str, head_only: bool = False):
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self._send_security_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)

    def _send_json(
        self,
        status: int,
        data: Any,
        corp: str = "same-origin",
        extra_headers: Optional[Dict[str, str]] = None,
        head_only: bool = False,
    ):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Vary", "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self._send_security_headers(corp=corp)
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)

    def _send_file(
        self,
        file_path: str,
        status: int = 200,
        content_type: Optional[str] = None,
        cache_control: Optional[str] = None,
        head_only: bool = False,
    ):
        if not os.path.isfile(file_path):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        if not content_type:
            ext = os.path.splitext(file_path)[1].lower()
            content_type = _EXPLICIT_MIME_TYPES.get(ext) or mimetypes.guess_type(file_path)[0] or "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            if cache_control:
                self.send_header("Cache-Control", cache_control)
            elif file_path.endswith((".html", ".js", ".css", ".webmanifest")):
                self.send_header("Cache-Control", "no-cache")
            else:
                self.send_header("Cache-Control", "public, max-age=86400")
            self._send_security_headers()
            self.end_headers()
            if not head_only:
                self.wfile.write(content)
        except Exception as e:
            sys.stderr.write(f"[Server] Error reading static file '{file_path}': {e}\n")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")

    def _enforce_rate_limit(self, limiter: Optional[RateLimiter], message: str) -> bool:
        if limiter is None:
            return True
        allowed, retry_after = limiter.allow(self._get_client_ip())
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": message},
                extra_headers={"Retry-After": str(retry_after)},
            )
            return False
        return True

    def _check_fetch_metadata_mutation(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if fetch_site and fetch_site not in ("same-origin", "none"):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Cross-site API request blocked"})
            return False
        return True

    def _handle_non_mutating_routes(self, path: str, head_only: bool = False) -> bool:
        """Handles GET/HEAD routes that never burn secrets. Returns True if matched."""
        if path == "/":
            self._send_file(os.path.join(STATIC_DIR, "index.html"), head_only=head_only)
            return True

        if path == "/robots.txt":
            self._send_text(
                HTTPStatus.OK,
                "User-agent: *\nDisallow: /secret/\nDisallow: /api/\n",
                head_only=head_only,
            )
            return True

        if path in ("/health", "/healthz"):
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok"},
                head_only=head_only,
            )
            return True

        if path == "/api/config":
            self._send_json(
                HTTPStatus.OK,
                {
                    "version": APP_VERSION,
                    "max_payload_bytes": MAX_PAYLOAD_BYTES,
                    "max_attachment_bytes": MAX_ATTACHMENT_BYTES,
                    "max_text_bytes": MAX_TEXT_BYTES,
                    "min_ttl_seconds": MIN_TTL_SECONDS,
                    "max_ttl_seconds": MAX_TTL_SECONDS,
                    "ttl_presets": TTL_PRESETS,
                    "max_views_presets": MAX_VIEWS_PRESETS,
                    "max_views": MAX_VIEWS_LIMIT,
                },
                head_only=head_only,
            )
            return True

        if path == "/manifest.webmanifest":
            self._send_file(
                os.path.join(STATIC_DIR, "manifest.webmanifest"),
                content_type="application/manifest+json; charset=utf-8",
                cache_control="no-cache",
                head_only=head_only,
            )
            return True

        if path == "/sw.js":
            sw_path = os.path.join(STATIC_DIR, "sw.js")
            if not os.path.isfile(sw_path):
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return True
            try:
                with open(sw_path, "r", encoding="utf-8") as f:
                    raw_sw = f.read()
                rendered_sw = re.sub(
                    r'const SHELL_CACHE = "[^"]+";',
                    f'const SHELL_CACHE = "{_SHELL_CACHE_NAME}";',
                    raw_sw,
                    count=1,
                ).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(rendered_sw)))
                self.send_header("Cache-Control", "no-cache")
                self._send_security_headers()
                self.end_headers()
                if not head_only:
                    self.wfile.write(rendered_sw)
            except Exception as e:
                sys.stderr.write(f"[Server] Error serving sw.js: {e}\n")
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")
            return True

        if path == "/.well-known/assetlinks.json":
            fingerprints = [RELEASE_SHA256_FINGERPRINT]
            include_debug = os.environ.get("ASSETLINKS_INCLUDE_DEBUG", "").strip().lower() in ("1", "true", "yes")
            if include_debug and DEFAULT_SHA256_FINGERPRINT not in fingerprints:
                fingerprints.append(DEFAULT_SHA256_FINGERPRINT)
            extra = os.environ.get("ASSETLINKS_RELEASE_SHA256", "")
            for fp in extra.split(","):
                clean_fp = fp.strip().upper()
                if clean_fp and clean_fp not in fingerprints:
                    fingerprints.append(clean_fp)

            assetlinks = [
                {
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {
                        "namespace": "android_app",
                        "package_name": "com.burnbin.app",
                        "sha256_cert_fingerprints": fingerprints,
                    },
                }
            ]
            self._send_json(HTTPStatus.OK, assetlinks, corp="cross-origin", head_only=head_only)
            return True

        if path.startswith("/secret/"):
            self._send_file(os.path.join(STATIC_DIR, "view.html"), head_only=head_only)
            return True

        if path.startswith("/static/"):
            rel_path = unquote(path[len("/static/"):]).lstrip("/")
            if "\x00" in rel_path or not rel_path:
                self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
                return True
            static_root = os.path.abspath(STATIC_DIR)
            safe_path = os.path.abspath(os.path.join(static_root, rel_path))
            if os.path.commonpath([static_root, safe_path]) != static_root:
                self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
                return True
            self._send_file(safe_path, head_only=head_only)
            return True

        return False

    def _consume_secret_response(self, secret_id: str):
        if not SECRET_ID_PATTERN.match(secret_id):
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid secret ID"})
        try:
            secret = self.db.consume_secret(secret_id)
        except Exception as e:
            sys.stderr.write(f"[Server] Error consuming secret '{secret_id}': {e}\n")
            return self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error"})
        if not secret:
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Secret not found, expired, or already destroyed"})
        return self._send_json(HTTPStatus.OK, secret)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if self._handle_non_mutating_routes(path, head_only=True):
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"}, head_only=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if self._handle_non_mutating_routes(path, head_only=False):
            return

        # Route: Check Secret Metadata (/api/secrets/<id>/meta)
        if path.startswith("/api/secrets/") and path.endswith("/meta"):
            parts = path.split("/")
            if len(parts) == 5:
                if not self._enforce_rate_limit(
                    self.read_rate_limiter,
                    "Too many requests. Please slow down and try again shortly.",
                ):
                    return
                secret_id = parts[3]
                if not SECRET_ID_PATTERN.match(secret_id):
                    return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid secret ID"})
                try:
                    meta = self.db.get_meta(secret_id)
                except Exception as e:
                    sys.stderr.write(f"[Server] Error getting metadata for '{secret_id}': {e}\n")
                    return self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error"})
                if not meta:
                    return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Secret not found or already destroyed"})
                return self._send_json(HTTPStatus.OK, meta)

        # Legacy GET burn route removed to prevent link-prefetchers/scanners from consuming secrets.
        if path.startswith("/api/secrets/"):
            return self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "Method not allowed. Use POST /api/secrets/<id>/consume to reveal or DELETE to revoke."},
                extra_headers={"Allow": "POST, DELETE"},
            )

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/secrets":
            if not self._check_fetch_metadata_mutation():
                return
            if not self._enforce_rate_limit(
                self.rate_limiter,
                "Too many secrets created. Please slow down and try again shortly.",
            ):
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length header"})

            if content_length <= 0 or content_length > MAX_PAYLOAD_BYTES:
                return self._send_json(HTTPStatus.BAD_REQUEST, {
                    "error": f"Payload must be between 1 byte and {MAX_PAYLOAD_BYTES} bytes"
                })

            try:
                body = self.rfile.read(content_length)
                data = json.loads(body.decode("utf-8"))
            except Exception:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON format"})

            if not isinstance(data, dict):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "JSON payload must be an object"})

            ciphertext = data.get("ciphertext")
            iv = data.get("iv")
            salt = data.get("salt")

            try:
                raw_max_views = data.get("max_views", 1)
                raw_ttl = data.get("ttl_seconds", 3600)
                if isinstance(raw_max_views, bool) or isinstance(raw_ttl, bool):
                    raise ValueError("Boolean not allowed")
                max_views = int(raw_max_views)
                ttl_seconds = int(raw_ttl)
            except (TypeError, ValueError):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid 'max_views' or 'ttl_seconds'"})

            if not ciphertext or not isinstance(ciphertext, str):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing or invalid 'ciphertext'"})
            if not iv or not isinstance(iv, str) or len(iv) > 256:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing or invalid 'iv'"})
            if salt is not None and (not isinstance(salt, str) or len(salt) > 128):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid 'salt'"})

            # Bounds check
            max_views = max(1, min(max_views, MAX_VIEWS_LIMIT))
            ttl_seconds = max(MIN_TTL_SECONDS, min(ttl_seconds, MAX_TTL_SECONDS))

            # Cryptographically secure random ID (URL safe)
            secret_id = secrets.token_urlsafe(16)

            try:
                result = self.db.save_secret(
                    secret_id=secret_id,
                    ciphertext=ciphertext,
                    iv=iv,
                    salt=salt,
                    max_views=max_views,
                    ttl_seconds=ttl_seconds,
                )
            except PayloadTooLargeError as e:
                return self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(e)})
            except Exception as e:
                sys.stderr.write(f"[Server] Error saving secret: {e}\n")
                return self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error"})
            return self._send_json(HTTPStatus.CREATED, result)

        # Preferred mutating route: POST /api/secrets/<id>/consume
        if path.startswith("/api/secrets/") and path.endswith("/consume"):
            parts = path.split("/")
            if len(parts) == 5:
                if not self._check_fetch_metadata_mutation():
                    return
                if not self._enforce_rate_limit(
                    self.read_rate_limiter,
                    "Too many requests. Please slow down and try again shortly.",
                ):
                    return
                return self._consume_secret_response(parts[3])

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/secrets/"):
            if not self._check_fetch_metadata_mutation():
                return
            if not self._enforce_rate_limit(
                self.read_rate_limiter,
                "Too many requests. Please slow down and try again shortly.",
            ):
                return
            secret_id = path[len("/api/secrets/"):]
            if not SECRET_ID_PATTERN.match(secret_id):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid secret ID"})

            delete_token = self.headers.get("X-BurnBin-Delete-Token", "").strip()
            if not delete_token:
                return self._send_json(HTTPStatus.FORBIDDEN, {"error": "Missing revocation token"})

            try:
                outcome = self.db.revoke_secret(secret_id, delete_token)
            except Exception as e:
                sys.stderr.write(f"[Server] Error revoking secret '{secret_id}': {e}\n")
                return self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error"})
            if outcome == "ok":
                return self._send_json(HTTPStatus.OK, {"revoked": True, "id": secret_id})
            if outcome == "forbidden":
                return self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid revocation token"})
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Secret not found, expired, or already destroyed"})

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})


def run_background_purger(
    db: SecretStore,
    interval_seconds: int = 60,
    stop_event: Optional[threading.Event] = None,
):
    """Periodically purges expired secrets until stop_event is set."""
    stopper = stop_event or threading.Event()
    while not stopper.wait(interval_seconds):
        try:
            purged = db.purge_expired()
            if purged > 0:
                print(f"[Purger] Removed {purged} expired secrets.")
        except Exception as e:
            print(f"[Purger] Error purging secrets: {e}", file=sys.stderr)


def run_server(host: str = "0.0.0.0", port: int = 8000, db_path: str = "secrets.db"):
    # Ensure static directory exists
    os.makedirs(STATIC_DIR, exist_ok=True)

    db = create_secret_store(db_path=db_path)

    # Start background cleanup thread for SQLite (Firestore uses native TTL policy unless opted in)
    stop_event = threading.Event()
    enable_purger_env = os.environ.get("ENABLE_IN_APP_PURGER", "").strip().lower() in ("1", "true", "yes")
    if db.backend_name != "firestore" or enable_purger_env:
        purger_thread = threading.Thread(
            target=run_background_purger,
            args=(db, 60, stop_event),
            daemon=True,
        )
        purger_thread.start()
        purger_mode = "background SQLite/in-app purger active"
    else:
        purger_mode = "native Firestore TTL active (in-app purger skipped)"

    max_req = int(os.environ.get("RATE_LIMIT_MAX", 30))
    read_max_req = int(os.environ.get("READ_RATE_LIMIT_MAX", 60))
    window_sec = int(os.environ.get("RATE_LIMIT_WINDOW", 60))
    limiter = RateLimiter(max_requests=max_req, window_seconds=window_sec)
    read_limiter = RateLimiter(max_requests=read_max_req, window_seconds=window_sec)

    # Pass db and rate limiters to handler
    class BoundRequestHandler(SecretRequestHandler):
        pass

    BoundRequestHandler.db = db
    BoundRequestHandler.rate_limiter = limiter
    BoundRequestHandler.read_rate_limiter = read_limiter

    server = ThreadingHTTPServer((host, port), BoundRequestHandler)
    print(f"🔥 Secret Pastebin running at http://{host}:{port}/")
    storage_desc = os.path.abspath(db_path) if db.backend_name == "sqlite" else f"Firestore ({getattr(db, 'project_id', '')})"
    print(f"📁 Storage ({db.backend_name}): {storage_desc} ({purger_mode})")
    print(f"🔒 Zero-Knowledge client-side encryption ready.")

    def _request_shutdown(signum, _frame):
        print(f"\nReceived signal {signum}; shutting down server gracefully...")
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    prev_sigterm = None
    if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGTERM"):
        prev_sigterm = signal.signal(signal.SIGTERM, _request_shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        stop_event.set()
        server.server_close()
        if prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)


if __name__ == "__main__":
    default_port = int(os.environ.get("PORT", 8000))
    default_db = os.environ.get("DB_PATH", "secrets.db")

    parser = argparse.ArgumentParser(description="Zero-Knowledge Self-Destructing Secret Pastebin")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to bind to (default: {default_port})")
    parser.add_argument("--db", default=default_db, help=f"Path to SQLite database (default: {default_db})")

    args = parser.parse_args()
    run_server(host=args.host, port=args.port, db_path=args.db)
