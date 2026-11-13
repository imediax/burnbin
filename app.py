"""
Zero-Knowledge Self-Destructing Secret Pastebin (Burn-on-Read).
Standard library Python HTTP Server with SQLite persistence.
"""

import argparse
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import unquote, urlparse

from db import SecretDB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Safety limits
MAX_PAYLOAD_BYTES = 1024 * 1024  # 1MB max encrypted secret
SECRET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
KEY_LOG_REDACT_PATTERN = re.compile(r"([?&]key=)[^&\s\"']+", re.IGNORECASE)
DEFAULT_SHA256_FINGERPRINT = "7E:D4:97:03:14:8D:3C:F6:EA:7C:12:EC:BC:D8:9B:29:21:42:EC:AF:AA:BE:6C:E5:6F:46:DC:DB:DC:5E:65:FA"


class RateLimiter:
    """Thread-safe in-memory sliding-window per-IP rate limiter."""

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
    db: SecretDB
    rate_limiter: Optional[RateLimiter] = None

    def _get_client_ip(self) -> str:
        forwarded_for = self.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "unknown"

    def log_message(self, format, *args):
        # Sanitize logged URLs so ?key=... is never written to server logs
        message = KEY_LOG_REDACT_PATTERN.sub(r"\1[REDACTED]", format % args)
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {message}\n")

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
        )

    def _send_json(self, status: int, data: any):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, file_path: str, status: int = 200):
        if not os.path.isfile(file_path):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(status)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            if file_path.endswith((".html", ".js", ".css")):
                self.send_header("Cache-Control", "no-cache")
            else:
                self.send_header("Cache-Control", "public, max-age=86400")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading file: {e}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # Route: Serve Home (Create secret)
        if path == "/":
            index_path = os.path.join(STATIC_DIR, "index.html")
            return self._send_file(index_path)

        # Route: Health Check
        if path in ("/health", "/healthz"):
            return self._send_json(HTTPStatus.OK, {"status": "ok"})

        # Route: Android App Links Digital Asset Links
        if path == "/.well-known/assetlinks.json":
            fingerprints = [DEFAULT_SHA256_FINGERPRINT]
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
                    }
                }
            ]
            return self._send_json(HTTPStatus.OK, assetlinks)

        # Route: View Secret Page (/secret/<id>)
        if path.startswith("/secret/"):
            view_path = os.path.join(STATIC_DIR, "view.html")
            return self._send_file(view_path)

        # Route: Check Secret Metadata (/api/secrets/<id>/meta)
        if path.startswith("/api/secrets/") and path.endswith("/meta"):
            parts = path.split("/")
            if len(parts) == 5:
                secret_id = parts[3]
                if not SECRET_ID_PATTERN.match(secret_id):
                    return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid secret ID"})
                meta = self.db.get_meta(secret_id)
                if not meta:
                    return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Secret not found or already destroyed"})
                return self._send_json(HTTPStatus.OK, meta)

        # Route: Retrieve & Burn Secret (/api/secrets/<id>)
        if path.startswith("/api/secrets/"):
            secret_id = path[len("/api/secrets/"):]
            if not SECRET_ID_PATTERN.match(secret_id):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid secret ID"})

            secret = self.db.consume_secret(secret_id)
            if not secret:
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Secret not found, expired, or already destroyed"})
            return self._send_json(HTTPStatus.OK, secret)

        # Route: Static Assets (/static/*)
        if path.startswith("/static/"):
            rel_path = unquote(path[len("/static/"):]).lstrip("/")
            if "\x00" in rel_path or not rel_path:
                return self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            static_root = os.path.abspath(STATIC_DIR)
            safe_path = os.path.abspath(os.path.join(static_root, rel_path))
            if os.path.commonpath([static_root, safe_path]) != static_root:
                return self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            return self._send_file(safe_path)

        # Default 404
        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/secrets":
            if self.rate_limiter is not None:
                allowed, retry_after = self.rate_limiter.allow(self._get_client_ip())
                if not allowed:
                    payload = json.dumps({"error": "Too many secrets created. Please slow down and try again shortly."}).encode("utf-8")
                    self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Retry-After", str(retry_after))
                    self.send_header("Cache-Control", "no-store")
                    self._send_security_headers()
                    self.end_headers()
                    self.wfile.write(payload)
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
            max_views = max(1, min(max_views, 20))
            ttl_seconds = max(60, min(ttl_seconds, 604800))  # Between 1 minute and 7 days

            # Cryptographically secure random ID (URL safe)
            secret_id = secrets.token_urlsafe(16)

            result = self.db.save_secret(
                secret_id=secret_id,
                ciphertext=ciphertext,
                iv=iv,
                salt=salt,
                max_views=max_views,
                ttl_seconds=ttl_seconds
            )
            return self._send_json(HTTPStatus.CREATED, result)

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})


def run_background_purger(db: SecretDB, interval_seconds: int = 60):
    """Periodically purges expired secrets in a daemon thread."""
    while True:
        try:
            time.sleep(interval_seconds)
            purged = db.purge_expired()
            if purged > 0:
                print(f"[Purger] Removed {purged} expired secrets.")
        except Exception as e:
            print(f"[Purger] Error purging secrets: {e}", file=sys.stderr)


def run_server(host: str = "0.0.0.0", port: int = 8000, db_path: str = "secrets.db"):
    # Ensure static directory exists
    os.makedirs(STATIC_DIR, exist_ok=True)

    db = SecretDB(db_path=db_path)

    # Start background cleanup thread
    purger_thread = threading.Thread(target=run_background_purger, args=(db, 60), daemon=True)
    purger_thread.start()

    max_req = int(os.environ.get("RATE_LIMIT_MAX", 30))
    window_sec = int(os.environ.get("RATE_LIMIT_WINDOW", 60))
    limiter = RateLimiter(max_requests=max_req, window_seconds=window_sec)

    # Pass db and rate_limiter instance to handler
    class BoundRequestHandler(SecretRequestHandler):
        pass
    BoundRequestHandler.db = db
    BoundRequestHandler.rate_limiter = limiter

    server = ThreadingHTTPServer((host, port), BoundRequestHandler)
    print(f"🔥 Secret Pastebin running at http://{host}:{port}/")
    print(f"📁 Database: {os.path.abspath(db_path)}")
    print(f"🔒 Zero-Knowledge client-side encryption ready.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.server_close()


if __name__ == "__main__":
    default_port = int(os.environ.get("PORT", 8000))
    default_db = os.environ.get("DB_PATH", "secrets.db")

    parser = argparse.ArgumentParser(description="Zero-Knowledge Self-Destructing Secret Pastebin")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to bind to (default: {default_port})")
    parser.add_argument("--db", default=default_db, help=f"Path to SQLite database (default: {default_db})")

    args = parser.parse_args()
    run_server(host=args.host, port=args.port, db_path=args.db)
