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

from app import (
    APP_VERSION,
    DEFAULT_SHA256_FINGERPRINT,
    MAX_ATTACHMENT_BYTES,
    MAX_TEXT_BYTES,
    MAX_VIEWS_LIMIT,
    RELEASE_SHA256_FINGERPRINT,
    TTL_PRESETS,
    RateLimiter,
    SecretRequestHandler,
    run_background_purger,
)
from db import FirestoreSecretDB, PayloadTooLargeError, SecretDB


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

        # 3. Legacy GET /api/secrets/<id> must return 405 without burning
        get_req = request.Request(f"{self.base_url}/api/secrets/{secret_id}")
        with self.assertRaises(error.HTTPError) as get_ctx:
            request.urlopen(get_req)
        self.assertEqual(get_ctx.exception.code, 405)

        # Verify secret is still intact after rejected GET
        with request.urlopen(request.Request(f"{self.base_url}/api/secrets/{secret_id}/meta")) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode())["views_left"], 1)

        # 4. Retrieve and Burn via POST /api/secrets/<id>/consume
        consume_req = request.Request(
            f"{self.base_url}/api/secrets/{secret_id}/consume",
            data=b"",
            method="POST",
        )
        with request.urlopen(consume_req) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode())
            self.assertEqual(body["ciphertext"], "encrypted-payload-12345")
            self.assertTrue(body["burned"])

        # 5. Subsequent consume must be 404 (Burned)
        burn_check_req = request.Request(
            f"{self.base_url}/api/secrets/{secret_id}/consume",
            data=b"",
            method="POST",
        )
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

        # Health check (should not disclose storage backend details)
        with request.urlopen(f"{self.base_url}/health") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode()), {"status": "ok"})
            self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

        # Shared client config endpoint
        with request.urlopen(f"{self.base_url}/api/config") as resp:
            self.assertEqual(resp.status, 200)
            cfg = json.loads(resp.read().decode())
            self.assertEqual(cfg["version"], APP_VERSION)
            self.assertEqual(cfg["max_attachment_bytes"], MAX_ATTACHMENT_BYTES)
            self.assertEqual(cfg["max_text_bytes"], MAX_TEXT_BYTES)
            self.assertEqual(cfg["ttl_presets"], TTL_PRESETS)
            self.assertEqual(cfg["max_views"], MAX_VIEWS_LIMIT)

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
        old_debug = os.environ.pop("ASSETLINKS_INCLUDE_DEBUG", None)
        old_extra = os.environ.pop("ASSETLINKS_RELEASE_SHA256", None)
        try:
            with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as base_resp:
                base_fps = json.loads(base_resp.read().decode())[0]["target"]["sha256_cert_fingerprints"]
            self.assertEqual(base_fps, [RELEASE_SHA256_FINGERPRINT])
            self.assertNotIn(DEFAULT_SHA256_FINGERPRINT, base_fps)

            os.environ["ASSETLINKS_INCLUDE_DEBUG"] = "1"
            with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as dbg_resp:
                dbg_fps = json.loads(dbg_resp.read().decode())[0]["target"]["sha256_cert_fingerprints"]
            self.assertIn(DEFAULT_SHA256_FINGERPRINT, dbg_fps)

            os.environ.pop("ASSETLINKS_INCLUDE_DEBUG", None)
            os.environ["ASSETLINKS_RELEASE_SHA256"] = extra_fp.lower()
            with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as resp:
                data = json.loads(resp.read().decode())
                fps = data[0]["target"]["sha256_cert_fingerprints"]
                self.assertEqual(len(fps), len(base_fps) + 1)
                self.assertIn(extra_fp, fps)
        finally:
            if old_debug is None:
                os.environ.pop("ASSETLINKS_INCLUDE_DEBUG", None)
            else:
                os.environ["ASSETLINKS_INCLUDE_DEBUG"] = old_debug
            if old_extra is None:
                os.environ.pop("ASSETLINKS_RELEASE_SHA256", None)
            else:
                os.environ["ASSETLINKS_RELEASE_SHA256"] = old_extra

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
                raw_path, _, query = self.path.partition("?")
                doc_path = raw_path.split("/v1/")[-1]
                doc = docs.get(doc_path)
                if not doc:
                    self.send_response(404)
                    self.end_headers()
                    return
                fields = doc["fields"]
                if "mask.fieldPaths=" in query:
                    from urllib.parse import parse_qs
                    masked_keys = parse_qs(query).get("mask.fieldPaths", [])
                    if masked_keys:
                        fields = {k: v for k, v in fields.items() if k in masked_keys}
                out_doc = {
                    "name": doc["name"],
                    "fields": fields,
                    "updateTime": doc["updateTime"],
                }
                body = json.dumps(out_doc).encode("utf-8")
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
                        current_doc = w.get("currentDocument", {})
                        pre = current_doc.get("updateTime")
                        exists_pre = current_doc.get("exists")
                        if "delete" in w:
                            target = w["delete"]
                            if pre:
                                if target not in docs or docs[target]["updateTime"] != pre:
                                    self.send_response(409)
                                    self.end_headers()
                                    return
                                del docs[target]
                            else:
                                docs.pop(target, None)
                        elif "update" in w:
                            target = w["update"]["name"]
                            if exists_pre is False:
                                if target in docs:
                                    self.send_response(409)
                                    self.end_headers()
                                    return
                                version_counter[0] += 1
                                docs[target] = {
                                    "name": target,
                                    "fields": dict(w["update"]["fields"]),
                                    "updateTime": f"v{version_counter[0]}",
                                }
                            else:
                                if target not in docs or (pre and docs[target]["updateTime"] != pre):
                                    self.send_response(409)
                                    self.end_headers()
                                    return
                                version_counter[0] += 1
                                if "updateMask" in w:
                                    for fp in w["updateMask"].get("fieldPaths", []):
                                        if fp in w["update"]["fields"]:
                                            docs[target]["fields"][fp] = w["update"]["fields"][fp]
                                else:
                                    docs[target]["fields"] = dict(w["update"]["fields"])
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
            single_doc = docs["projects/test-proj/databases/(default)/documents/burnbin_secrets/fsSecret123456"]
            single_ts = single_doc["fields"]["expire_at"].get("timestampValue", "")
            self.assertTrue(single_ts.endswith("Z"), f"Expected UTC timestampValue, got {single_ts}")
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

            # Chunked large payload (~1.45M chars across 2 chunks) with max_views=2
            large_cipher = ("A" * 800_000) + ("B" * 650_000)
            fs.save_secret("fsChunked12345", large_cipher, "iv-chunked", max_views=2, ttl_seconds=300)
            parent_key = "projects/test-proj/databases/(default)/documents/burnbin_secrets/fsChunked12345"
            self.assertIn(f"{parent_key}/chunks/0", docs)
            self.assertIn(f"{parent_key}/chunks/1", docs)
            self.assertTrue(docs[parent_key]["fields"]["expire_at"]["timestampValue"].endswith("Z"))
            self.assertTrue(docs[f"{parent_key}/chunks/0"]["fields"]["expire_at"]["timestampValue"].endswith("Z"))
            self.assertTrue(docs[f"{parent_key}/chunks/1"]["fields"]["expire_at"]["timestampValue"].endswith("Z"))

            chunk_meta = fs.get_meta("fsChunked12345")
            self.assertEqual(chunk_meta["views_left"], 2)

            c_first = fs.consume_secret("fsChunked12345")
            self.assertFalse(c_first["burned"])
            self.assertEqual(c_first["views_left"], 1)
            self.assertEqual(c_first["ciphertext"], large_cipher)
            self.assertIn(f"{parent_key}/chunks/0", docs)

            c_second = fs.consume_secret("fsChunked12345")
            self.assertTrue(c_second["burned"])
            self.assertEqual(c_second["views_left"], 0)
            self.assertEqual(c_second["ciphertext"], large_cipher)
            self.assertNotIn(parent_key, docs)
            self.assertNotIn(f"{parent_key}/chunks/0", docs)
            self.assertNotIn(f"{parent_key}/chunks/1", docs)

            # Chunked secret early revocation deletes parent + chunks
            c_rev = fs.save_secret("fsChunkRevoke12", large_cipher, "iv-cr", max_views=1, ttl_seconds=300)
            rev_parent = "projects/test-proj/databases/(default)/documents/burnbin_secrets/fsChunkRevoke12"
            self.assertIn(f"{rev_parent}/chunks/0", docs)
            self.assertEqual(fs.revoke_secret("fsChunkRevoke12", c_rev["delete_token"]), "ok")
            self.assertNotIn(rev_parent, docs)
            self.assertNotIn(f"{rev_parent}/chunks/0", docs)
            self.assertNotIn(f"{rev_parent}/chunks/1", docs)

            # Oversized payload (> 2.4M chars) raises PayloadTooLargeError
            with self.assertRaises(PayloadTooLargeError):
                fs.save_secret("fsTooBig12345678", "x" * 2_450_000, "iv-big", max_views=1, ttl_seconds=300)
        finally:
            mock_srv.shutdown()
            mock_srv.server_close()

    def test_post_consume_head_security_headers_and_pwa_routes(self):
        # Create secret with 30-day TTL (2592000s) and consume via POST /api/secrets/<id>/consume
        payload = json.dumps({
            "ciphertext": "post-consume-cipher",
            "iv": "iv001122",
            "max_views": 1,
            "ttl_seconds": 2592000,
        }).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/secrets",
            data=payload,
            headers={"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"},
        )
        with request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            created = json.loads(resp.read().decode())
            self.assertGreaterEqual(created["expires_at"], int(time.time()) + 2592000 - 15)
            csp = resp.headers.get("Content-Security-Policy", "")
            self.assertNotIn("unsafe-inline", csp)
            self.assertIn("style-src 'self'", csp)
            self.assertIn("object-src 'none'", csp)
            self.assertEqual(resp.headers.get("Cross-Origin-Resource-Policy"), "same-origin")
            self.assertEqual(resp.headers.get("Cross-Origin-Opener-Policy"), "same-origin-allow-popups")
            self.assertIn("camera=()", resp.headers.get("Permissions-Policy", ""))

        secret_id = created["id"]
        consume_req = request.Request(
            f"{self.base_url}/api/secrets/{secret_id}/consume",
            data=b"",
            method="POST",
        )
        with request.urlopen(consume_req) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode())
            self.assertTrue(body["burned"])
            self.assertEqual(body["ciphertext"], "post-consume-cipher")

        # Second consume must return 404
        with self.assertRaises(error.HTTPError) as ctx:
            request.urlopen(request.Request(f"{self.base_url}/api/secrets/{secret_id}/consume", data=b"", method="POST"))
        self.assertEqual(ctx.exception.code, 404)

        # Cross-site POST /api/secrets must be rejected by Fetch Metadata guard
        cross_req = request.Request(
            f"{self.base_url}/api/secrets",
            data=payload,
            headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
        )
        with self.assertRaises(error.HTTPError) as cross_ctx:
            request.urlopen(cross_req)
        self.assertEqual(cross_ctx.exception.code, 403)

        # HEAD /health and X-Forwarded-Proto HSTS check
        head_req = request.Request(
            f"{self.base_url}/health",
            method="HEAD",
            headers={"X-Forwarded-Proto": "https"},
        )
        with request.urlopen(head_req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), b"")
            self.assertIn("max-age=", resp.headers.get("Strict-Transport-Security", ""))

        # PWA routes
        with request.urlopen(f"{self.base_url}/manifest.webmanifest") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/manifest+json", resp.headers.get("Content-Type", ""))
            manifest = json.loads(resp.read().decode())
            self.assertEqual(manifest["short_name"], "BurnBin")

        with request.urlopen(f"{self.base_url}/sw.js") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("javascript", resp.headers.get("Content-Type", ""))
            self.assertIn(f"burnbin-shell-v{APP_VERSION}-", resp.read().decode())

    def test_proxy_xff_spoof_resistant_and_read_rate_limit(self):
        original_create = self.server.RequestHandlerClass.rate_limiter
        original_read = self.server.RequestHandlerClass.read_rate_limiter
        self.server.RequestHandlerClass.rate_limiter = RateLimiter(max_requests=1, window_seconds=60)
        self.server.RequestHandlerClass.read_rate_limiter = RateLimiter(max_requests=2, window_seconds=60)
        try:
            payload = json.dumps({"ciphertext": "abc", "iv": "def"}).encode("utf-8")
            # Left-most XFF varies, right-most (trusted hop) stays 198.51.100.77
            r1 = request.Request(
                f"{self.base_url}/api/secrets",
                data=payload,
                headers={"Content-Type": "application/json", "X-Forwarded-For": "1.1.1.1, 198.51.100.77"},
            )
            with request.urlopen(r1) as resp:
                self.assertEqual(resp.status, 201)

            r2 = request.Request(
                f"{self.base_url}/api/secrets",
                data=payload,
                headers={"Content-Type": "application/json", "X-Forwarded-For": "2.2.2.2, 198.51.100.77"},
            )
            with self.assertRaises(error.HTTPError) as ctx:
                request.urlopen(r2)
            self.assertEqual(ctx.exception.code, 429)

            # Read/meta endpoint rate limiting
            for _ in range(2):
                with self.assertRaises(error.HTTPError) as m_ctx:
                    request.urlopen(
                        request.Request(
                            f"{self.base_url}/api/secrets/nonexistent1234/meta",
                            headers={"X-Forwarded-For": "9.9.9.9, 198.51.100.88"},
                        )
                    )
                self.assertEqual(m_ctx.exception.code, 404)

            with self.assertRaises(error.HTTPError) as rl_ctx:
                request.urlopen(
                    request.Request(
                        f"{self.base_url}/api/secrets/nonexistent1234/meta",
                        headers={"X-Forwarded-For": "8.8.8.8, 198.51.100.88"},
                    )
                )
            self.assertEqual(rl_ctx.exception.code, 429)
        finally:
            self.server.RequestHandlerClass.rate_limiter = original_create
            self.server.RequestHandlerClass.read_rate_limiter = original_read

    def test_sqlite_secure_delete_enabled(self):
        with self.db.get_db() as conn:
            val = conn.execute("PRAGMA secure_delete;").fetchone()[0]
            self.assertEqual(val, 1)

    def test_purger_stop_event(self):
        stop_event = threading.Event()
        stop_event.set()
        t = threading.Thread(target=run_background_purger, args=(self.db, 60, stop_event), daemon=True)
        t.start()
        t.join(timeout=1.0)
        self.assertFalse(t.is_alive())


if __name__ == "__main__":
    unittest.main()
