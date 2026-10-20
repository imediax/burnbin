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

from app import SecretRequestHandler
from db import SecretDB


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
            self.assertIn(b"BurnBin", resp.read())

        # View route
        with request.urlopen(f"{self.base_url}/secret/dummy-id") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"BurnBin", resp.read())

        # Static assets
        with request.urlopen(f"{self.base_url}/static/crypto.js") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"SecretCrypto", resp.read())

        # Android App Links Digital Asset Links
        with request.urlopen(f"{self.base_url}/.well-known/assetlinks.json") as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["target"]["package_name"], "com.burnbin.app")


if __name__ == "__main__":
    unittest.main()
