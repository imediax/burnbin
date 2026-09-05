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
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from db import SecretDB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Safety limits
MAX_PAYLOAD_BYTES = 1024 * 1024  # 1MB max encrypted secret
SECRET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{12,64}$")


class SecretRequestHandler(BaseHTTPRequestHandler):
    db: SecretDB

    def log_message(self, format, *args):
        # Clean formatted logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def _send_json(self, status: int, data: dict):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
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
            rel_path = path[len("/static/"):]
            # Prevent directory traversal
            safe_path = os.path.abspath(os.path.join(STATIC_DIR, rel_path))
            if not safe_path.startswith(STATIC_DIR):
                return self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            return self._send_file(safe_path)

        # Default 404
        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/secrets":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0 or content_length > MAX_PAYLOAD_BYTES:
                return self._send_json(HTTPStatus.BAD_REQUEST, {
                    "error": f"Payload must be between 1 byte and {MAX_PAYLOAD_BYTES} bytes"
                })

            try:
                body = self.rfile.read(content_length)
                data = json.loads(body.decode("utf-8"))
            except Exception:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON format"})

            ciphertext = data.get("ciphertext")
            iv = data.get("iv")
            salt = data.get("salt")
            max_views = int(data.get("max_views", 1))
            ttl_seconds = int(data.get("ttl_seconds", 3600))

            if not ciphertext or not isinstance(ciphertext, str):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing or invalid 'ciphertext'"})
            if not iv or not isinstance(iv, str):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing or invalid 'iv'"})

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

    # Pass db instance to handler
    class BoundRequestHandler(SecretRequestHandler):
        pass
    BoundRequestHandler.db = db

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
    parser = argparse.ArgumentParser(description="Zero-Knowledge Self-Destructing Secret Pastebin")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--db", default="secrets.db", help="Path to SQLite database (default: secrets.db)")

    args = parser.parse_args()
    run_server(host=args.host, port=args.port, db_path=args.db)
