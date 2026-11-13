"""
Automated Integration and Unit Tests for Secret Pastebin.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib import request, error

from app import RateLimiter, SecretRequestHandler
from db import FirestoreSecretDB, SecretDB


class TestSecretDB(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_secrets.db")
        self.db = SecretDB(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_save_and_get_meta(self):
        secret_id = "test-secret-1234"
        res = self.db.save_secret(
            secret_id=secret_id,
            ciphertext="my-encrypted-data",
            iv="iv123456",
            salt="salt123456",
            max_views=1,
            ttl_seconds=3600
        )
        self.assertEqual(res["id"], secret_id)

        # Check metadata
        meta = self.db.get_meta(secret_id)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["id"], secret_id)
        self.assertTrue(meta["requires_passphrase"])
        self.assertEqual(meta["views_left"], 1)

    def test_single_use_burn_on_read(self):
        secret_id = "test-secret-single"
        self.db.save_secret(
            secret_id=secret_id,
            ciphertext="single-use-cipher",
            iv="single-iv",
            max_views=1,
            ttl_seconds=300
        )

        # 1st consume: should succeed and be burned
        res = self.db.consume_secret(secret_id)
        self.assertIsNotNone(res)
        self.assertEqual(res["ciphertext"], "single-use-cipher")
        self.assertTrue(res["burned"])
        self.assertEqual(res["views_left"], 0)

        # 2nd consume: should be gone (burned)
        res_after = self.db.consume_secret(secret_id)
        self.assertIsNone(res_after)

        # Meta after burn should also be None
        meta_after = self.db.get_meta(secret_id)
        self.assertIsNone(meta_after)

    def test_multi_view_secret(self):
        secret_id = "test-secret-multi"
        self.db.save_secret(
            secret_id=secret_id,
            ciphertext="multi-cipher",
            iv="multi-iv",
            max_views=3,
            ttl_seconds=300
        )

        # 1st consume
        res1 = self.db.consume_secret(secret_id)
        self.assertFalse(res1["burned"])
        self.assertEqual(res1["views_left"], 2)

        # 2nd consume
        res2 = self.db.consume_secret(secret_id)
        self.assertFalse(res2["burned"])
        self.assertEqual(res2["views_left"], 1)

        # 3rd consume
        res3 = self.db.consume_secret(secret_id)
        self.assertTrue(res3["burned"])
        self.assertEqual(res3["views_left"], 0)

        # 4th consume: gone
        res4 = self.db.consume_secret(secret_id)
        self.assertIsNone(res4)

    def test_expiration_purge(self):
        secret_id = "test-secret-expired"
        # 1-second TTL
        self.db.save_secret(
            secret_id=secret_id,
            ciphertext="expired-cipher",
            iv="expired-iv",
            max_views=1,
            ttl_seconds=1
        )
        time.sleep(1.2)

        # Consuming an expired secret returns None
        res = self.db.consume_secret(secret_id)
        self.assertIsNone(res)


class TestSecretServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_server.db")
        cls.db = SecretDB(cls.db_path)

        class BoundHandler(SecretRequestHandler):
            pass
        BoundHandler.db = cls.db

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.temp_dir)

    def test_create_and_burn_flow(self):
        # 1. Create a secret
        payload = json.dumps({
            "ciphertext": "encrypted-payload-12345",
            "iv": "abcdef123456",
            "salt": None,
            "max_views": 1,
            "ttl_seconds": 600
        }).encode("utf-8")

        req = request.Request(
            f"{self.base_url}/api/secrets",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            data = json.loads(resp.read().decode())
            self.assertIn("id", data)
            secret_id = data["id"]

        # 2. Check metadata without burning
        meta_req = request.Request(f"{self.base_url}/api/secrets/{secret_id}/meta")
        with request.urlopen(meta_req) as resp:
            self.assertEqual(resp.status, 200)
            meta = json.loads(resp.read().decode())
            self.assertEqual(meta["views_left"], 1)
            self.assertFalse(meta["requires_passphrase"])

        # 3. Retrieve and Burn
        get_req = request.Request(f"{self.base_url}/api/secrets/{secret_id}")
        with request.urlopen(get_req) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode())
            self.assertEqual(body["ciphertext"], "encrypted-payload-12345")
            self.assertTrue(body["burned"])

        # 4. Subsequent retrieval must be 404 (Burned)
        burn_check_req = request.Request(f"{self.base_url}/api/secrets/{secret_id}")
        with self.assertRaises(error.HTTPError) as ctx:
            request.urlopen(burn_check_req)
        self.assertEqual(ctx.exception.code, 404)

    def test_static_routes(self):
        # Home
        with request.urlopen(f"{self.base_url}/") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read()
            self.assertIn(b"BurnBin", body)
            self.assertIn(b"noindex, nofollow", body)
            self.assertEqual(resp.headers.get("X-Robots-Tag"), "noindex, nofollow, noarchive")

        # View route
        with request.urlopen(f"{self.base_url}/secret/dummy-id") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read()
            self.assertIn(b"BurnBin", body)
            self.assertIn(b"noindex, nofollow", body)
            self.assertEqual(resp.headers.get("X-Robots-Tag"), "noindex, nofollow, noarchive")

        # Crawler Guard (/robots.txt)
        with request.urlopen(f"{self.base_url}/robots.txt") as resp:
            self.assertEqual(resp.status, 200)
            robots = resp.read().decode("utf-8")
            self.assertIn("Disallow: /secret/", robots)
            self.assertIn("Disallow: /api/", robots)

        # Static assets
        with request.urlopen(f"{self.base_url}/static/crypto.js") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"SecretCrypto", resp.read())

        # Health check
        with request.urlopen(f"{self.base_url}/health") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode())["status"], "ok")
            self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

        # Android App Links Digital Asset Links
        with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["target"]["package_name"], "com.burnbin.app")

    def test_input_validation_and_traversal_protection(self):
        # Non-object JSON body
        for bad_body in [b"[1,2,3]", b"null", json.dumps({"ciphertext": "abc", "iv": "def", "max_views": "bad"}).encode(), json.dumps({"ciphertext": "abc", "iv": "def", "salt": 123}).encode()]:
            req = request.Request(
                f"{self.base_url}/api/secrets",
                data=bad_body,
                headers={"Content-Type": "application/json"}
            )
            with self.assertRaises(error.HTTPError) as ctx:
                request.urlopen(req)
            self.assertEqual(ctx.exception.code, 400)

        # Static path traversal attempt
        for bad_path in ["/static/../app.py", "/static/%2e%2e/app.py"]:
            with self.assertRaises(error.HTTPError) as ctx:
                request.urlopen(f"{self.base_url}{bad_path}")
            self.assertIn(ctx.exception.code, (403, 404))

    def test_log_redaction_strips_query_key(self):
        import io
        from contextlib import redirect_stderr

        class DummyHandler(SecretRequestHandler):
            def __init__(self):
                pass
            def address_string(self):
                return "127.0.0.1"
            def log_date_time_string(self):
                return "now"

        handler = DummyHandler()
        buf = io.StringIO()
        with redirect_stderr(buf):
            handler.log_message('"%s" %s %s', "GET /secret/AbCdEf123456?key=0123456789abcdef HTTP/1.1", "200", "-")
        logged = buf.getvalue()
        self.assertNotIn("0123456789abcdef", logged)
        self.assertIn("?key=[REDACTED]", logged)

    def test_rate_limiter_enforces_limit_and_headers(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        self.assertEqual(limiter.allow("1.2.3.4")[0], True)
        self.assertEqual(limiter.allow("1.2.3.4")[0], True)
        allowed, retry_after = limiter.allow("1.2.3.4")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)
        # Different IP should still be allowed
        self.assertTrue(limiter.allow("5.6.7.8")[0])

    def test_post_rate_limit_returns_429(self):
        original_limiter = self.server.RequestHandlerClass.rate_limiter
        self.server.RequestHandlerClass.rate_limiter = RateLimiter(max_requests=1, window_seconds=60)
        try:
            payload = json.dumps({"ciphertext": "abc", "iv": "def"}).encode("utf-8")
            req1 = request.Request(
                f"{self.base_url}/api/secrets",
                data=payload,
                headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.99"},
            )
            with request.urlopen(req1) as resp:
                self.assertEqual(resp.status, 201)

            req2 = request.Request(
                f"{self.base_url}/api/secrets",
                data=payload,
                headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.99"},
            )
            with self.assertRaises(error.HTTPError) as ctx:
                request.urlopen(req2)
            self.assertEqual(ctx.exception.code, 429)
            self.assertIsNotNone(ctx.exception.headers.get("Retry-After"))
        finally:
            self.server.RequestHandlerClass.rate_limiter = original_limiter

    def test_assetlinks_extra_fingerprint_env(self):
        extra_fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as base_resp:
            base_fps = json.loads(base_resp.read().decode())[0]["target"]["sha256_cert_fingerprints"]

        old = os.environ.get("ASSETLINKS_RELEASE_SHA256")
        os.environ["ASSETLINKS_RELEASE_SHA256"] = extra_fp.lower()
        try:
            with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as resp:
                data = json.loads(resp.read().decode())
                fps = data[0]["target"]["sha256_cert_fingerprints"]
                self.assertEqual(len(fps), len(base_fps) + 1)
                self.assertIn(extra_fp, fps)
        finally:
            if old is None:
                os.environ.pop("ASSETLINKS_RELEASE_SHA256", None)
            else:
                os.environ["ASSETLINKS_RELEASE_SHA256"] = old

    def test_early_revocation_flow(self):
        payload = json.dumps({
            "ciphertext": "burn-before-read",
            "iv": "iv001122",
            "max_views": 2,
            "ttl_seconds": 600,
        }).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/secrets",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(req) as resp:
            created = json.loads(resp.read().decode())
        secret_id = created["id"]
        delete_token = created["delete_token"]
        self.assertTrue(delete_token)

        # Wrong delete token -> 403
        bad_del = request.Request(
            f"{self.base_url}/api/secrets/{secret_id}",
            method="DELETE",
            headers={"X-BurnBin-Delete-Token": "wrong-token"},
        )
        with self.assertRaises(error.HTTPError) as ctx:
            request.urlopen(bad_del)
        self.assertEqual(ctx.exception.code, 403)

        # Correct delete token -> 200 and secret gone
        good_del = request.Request(
            f"{self.base_url}/api/secrets/{secret_id}",
            method="DELETE",
            headers={"X-BurnBin-Delete-Token": delete_token},
        )
        with request.urlopen(good_del) as resp:
            self.assertEqual(resp.status, 200)
            self.assertTrue(json.loads(resp.read().decode())["revoked"])

        # Subsequent meta or delete -> 404
        with self.assertRaises(error.HTTPError) as ctx2:
            request.urlopen(f"{self.base_url}/api/secrets/{secret_id}/meta")
        self.assertEqual(ctx2.exception.code, 404)

    def test_firestore_backend_mock_flow(self):
        from http.server import BaseHTTPRequestHandler
        docs = {}
        version_counter = [0]

        class MockFirestoreHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                doc_path = self.path.split("/v1/")[-1]
                doc = docs.get(doc_path)
                if not doc:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(doc).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                if "?documentId=" in self.path:
                    base, qs = self.path.split("?documentId=", 1)
                    doc_id = qs.split("&")[0]
                    collection_path = base.split("/v1/")[-1]
                    doc_name = f"{collection_path}/{doc_id}"
                    version_counter[0] += 1
                    docs[doc_name] = {
                        "name": doc_name,
                        "fields": data["fields"],
                        "updateTime": f"v{version_counter[0]}",
                    }
                    body = json.dumps(docs[doc_name]).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path.endswith(":commit"):
                    for w in data.get("writes", []):
                        pre = w.get("currentDocument", {}).get("updateTime")
                        if "delete" in w:
                            target = w["delete"]
                            if target not in docs or (pre and docs[target]["updateTime"] != pre):
                                self.send_response(409)
                                self.end_headers()
                                return
                            del docs[target]
                        elif "update" in w:
                            target = w["update"]["name"]
                            if target not in docs or (pre and docs[target]["updateTime"] != pre):
                                self.send_response(409)
                                self.end_headers()
                                return
                            version_counter[0] += 1
                            docs[target]["fields"] = w["update"]["fields"]
                            docs[target]["updateTime"] = f"v{version_counter[0]}"
                    body = b"{}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

        mock_srv = ThreadingHTTPServer(("127.0.0.1", 0), MockFirestoreHandler)
        mock_port = mock_srv.server_address[1]
        t = threading.Thread(target=mock_srv.serve_forever, daemon=True)
        t.start()
        try:
            fs = FirestoreSecretDB(
                project_id="test-proj",
                emulator_host=f"127.0.0.1:{mock_port}",
            )
            created = fs.save_secret("fsSecret123456", "cipher-fs", "iv-fs", max_views=2, ttl_seconds=300)
            meta = fs.get_meta("fsSecret123456")
            self.assertEqual(meta["views_left"], 2)

            first = fs.consume_secret("fsSecret123456")
            self.assertFalse(first["burned"])
            self.assertEqual(first["views_left"], 1)

            second = fs.consume_secret("fsSecret123456")
            self.assertTrue(second["burned"])
            self.assertEqual(second["views_left"], 0)
            self.assertIsNone(fs.consume_secret("fsSecret123456"))

            # Save and revoke before read
            created2 = fs.save_secret("fsSecretRevoke12", "cipher-2", "iv-2", max_views=1, ttl_seconds=300)
            self.assertEqual(fs.revoke_secret("fsSecretRevoke12", "bad"), "forbidden")
            self.assertEqual(fs.revoke_secret("fsSecretRevoke12", created2["delete_token"]), "ok")
            self.assertEqual(fs.revoke_secret("fsSecretRevoke12", created2["delete_token"]), "not_found")
        finally:
            mock_srv.shutdown()
            mock_srv.server_close()


if __name__ == "__main__":
    unittest.main()
