"""
Database management for Self-Destructing Secret Pastebin.
Supports zero-dependency SQLite (WAL mode) by default and an optional durable
Google Cloud Firestore REST backend (STORAGE_BACKEND=firestore).
"""

import contextlib
import hashlib
import hmac
import json
import os
import secrets as py_secrets
import sqlite3
import threading
import time
from typing import Any, Dict, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


def _hash_delete_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SecretDB:
    backend_name = "sqlite"

    def __init__(self, db_path: str = "secrets.db"):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def get_db(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.get_db() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id TEXT PRIMARY KEY,
                    ciphertext TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    salt TEXT,
                    max_views INTEGER NOT NULL DEFAULT 1,
                    views_count INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    delete_token_hash TEXT
                );
            """)
            # Migrate existing tables created before delete_token_hash existed
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(secrets)").fetchall()}
            if "delete_token_hash" not in cols:
                conn.execute("ALTER TABLE secrets ADD COLUMN delete_token_hash TEXT;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);")
            conn.commit()

    def save_secret(
        self,
        secret_id: str,
        ciphertext: str,
        iv: str,
        salt: Optional[str] = None,
        max_views: int = 1,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Saves an encrypted secret with view limits, expiration, and a creator revocation token."""
        now = int(time.time())
        expires_at = now + ttl_seconds
        delete_token = py_secrets.token_urlsafe(24)
        delete_token_hash = _hash_delete_token(delete_token)

        with self.get_db() as conn:
            conn.execute(
                """
                INSERT INTO secrets (
                    id, ciphertext, iv, salt, max_views, views_count,
                    expires_at, created_at, delete_token_hash
                )
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
                """,
                (secret_id, ciphertext, iv, salt, max_views, expires_at, now, delete_token_hash),
            )
            conn.commit()
        return {
            "id": secret_id,
            "expires_at": expires_at,
            "max_views": max_views,
            "delete_token": delete_token,
        }

    def get_meta(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """Checks if a secret exists and is valid without burning it."""
        now = int(time.time())
        with self.get_db() as conn:
            row = conn.execute(
                "SELECT id, salt, max_views, views_count, expires_at, created_at FROM secrets WHERE id = ?",
                (secret_id,),
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] <= now or row["views_count"] >= row["max_views"]:
                conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                conn.commit()
                return None
            return {
                "id": row["id"],
                "requires_passphrase": bool(row["salt"]),
                "views_left": row["max_views"] - row["views_count"],
                "max_views": row["max_views"],
                "expires_at": row["expires_at"],
            }

    def consume_secret(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """
        Atomically increments views and retrieves ciphertext.
        Burns (deletes) the secret immediately if max_views is reached.
        """
        now = int(time.time())
        with self.get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute(
                    "SELECT id, ciphertext, iv, salt, max_views, views_count, expires_at FROM secrets WHERE id = ?",
                    (secret_id,),
                ).fetchone()

                if not row:
                    conn.rollback()
                    return None

                if row["expires_at"] <= now:
                    cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                    conn.commit()
                    return None

                new_views = row["views_count"] + 1
                views_left = row["max_views"] - new_views

                if views_left <= 0:
                    cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                else:
                    cursor.execute(
                        "UPDATE secrets SET views_count = ? WHERE id = ?",
                        (new_views, secret_id),
                    )
                conn.commit()

                return {
                    "id": row["id"],
                    "ciphertext": row["ciphertext"],
                    "iv": row["iv"],
                    "salt": row["salt"],
                    "views_left": max(0, views_left),
                    "burned": views_left <= 0,
                }
            except Exception:
                conn.rollback()
                raise

    def revoke_secret(self, secret_id: str, delete_token: str) -> str:
        """
        Early-revokes an unread secret when presented with the matching creator delete_token.
        Returns 'ok', 'forbidden', or 'not_found'.
        """
        if not delete_token:
            return "forbidden"
        candidate_hash = _hash_delete_token(delete_token)
        with self.get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute(
                    "SELECT id, delete_token_hash FROM secrets WHERE id = ?",
                    (secret_id,),
                ).fetchone()
                if not row:
                    conn.rollback()
                    return "not_found"
                stored_hash = row["delete_token_hash"] or ""
                if not stored_hash or not hmac.compare_digest(stored_hash, candidate_hash):
                    conn.rollback()
                    return "forbidden"
                cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                conn.commit()
                return "ok"
            except Exception:
                conn.rollback()
                raise

    def purge_expired(self) -> int:
        """Purges any secrets that have expired."""
        now = int(time.time())
        with self.get_db() as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE expires_at <= ?", (now,))
            conn.commit()
            return cursor.rowcount


class FirestoreSecretDB:
    """
    Zero-dependency Google Cloud Firestore REST storage backend.
    Uses optimistic updateTime preconditions on documents:commit so multi-instance
    Cloud Run deployments never double-read or lose state across cold starts.
    """

    backend_name = "firestore"
    _METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"

    def __init__(
        self,
        project_id: Optional[str] = None,
        collection: str = "burnbin_secrets",
        database: str = "(default)",
        emulator_host: Optional[str] = None,
    ):
        self.emulator_host = (emulator_host or os.environ.get("FIRESTORE_EMULATOR_HOST", "")).strip()
        self.project_id = (
            project_id
            or os.environ.get("FIRESTORE_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT")
            or self._fetch_metadata("/project/project-id")
        )
        if not self.project_id:
            raise RuntimeError("FIRESTORE_PROJECT or Cloud Run metadata project-id is required for Firestore backend.")
        self.collection = collection
        self.database = database
        self._token_lock = threading.Lock()
        self._cached_token: Optional[str] = None
        self._token_expiry: float = 0.0

    @property
    def _api_origin(self) -> str:
        if self.emulator_host:
            host = self.emulator_host
            if not host.startswith(("http://", "https://")):
                host = f"http://{host}"
            return host.rstrip("/")
        return "https://firestore.googleapis.com"

    @property
    def _db_root(self) -> str:
        return f"projects/{self.project_id}/databases/{self.database}/documents"

    def _doc_name(self, secret_id: str) -> str:
        return f"{self._db_root}/{self.collection}/{secret_id}"

    def _fetch_metadata(self, path: str) -> Optional[str]:
        if self.emulator_host:
            return None
        try:
            req = urllib_request.Request(
                f"{self._METADATA_BASE}{path}",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib_request.urlopen(req, timeout=3.0) as resp:
                return resp.read().decode("utf-8").strip()
        except Exception:
            return None

    def _get_access_token(self) -> Optional[str]:
        if self.emulator_host:
            return "owner"
        env_token = (
            os.environ.get("FIRESTORE_ACCESS_TOKEN")
            or os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")
        )
        if env_token:
            return env_token.strip()

        now = time.monotonic()
        with self._token_lock:
            if self._cached_token and now < self._token_expiry:
                return self._cached_token
            raw = self._fetch_metadata("/instance/service-accounts/default/token")
            if not raw:
                return None
            data = json.loads(raw)
            token = data.get("access_token")
            expires_in = int(data.get("expires_in", 300))
            if token:
                self._cached_token = token
                self._token_expiry = now + max(30, expires_in - 60)
            return token

    def _request_json(self, method: str, url: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        token = self._get_access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body_bytes = None
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
            body_bytes = json.dumps(payload).encode("utf-8")

        req = urllib_request.Request(url, data=body_bytes, headers=headers, method=method)
        with urllib_request.urlopen(req, timeout=10.0) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    @staticmethod
    def _encode_fields(values: Dict[str, Any]) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        for key, val in values.items():
            if val is None:
                fields[key] = {"nullValue": None}
            elif isinstance(val, bool):
                fields[key] = {"booleanValue": val}
            elif isinstance(val, int):
                fields[key] = {"integerValue": str(val)}
            else:
                fields[key] = {"stringValue": str(val)}
        return fields

    @staticmethod
    def _decode_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, typed in fields.items():
            if "stringValue" in typed:
                out[key] = typed["stringValue"]
            elif "integerValue" in typed:
                out[key] = int(typed["integerValue"])
            elif "booleanValue" in typed:
                out[key] = bool(typed["booleanValue"])
            elif "nullValue" in typed:
                out[key] = None
        return out

    def _get_doc(self, secret_id: str) -> Optional[Dict[str, Any]]:
        safe_id = urllib_parse.quote(secret_id, safe="")
        url = f"{self._api_origin}/v1/{self._db_root}/{self.collection}/{safe_id}"
        try:
            return self._request_json("GET", url)
        except urllib_error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def _commit_writes(self, writes: list[Dict[str, Any]]) -> None:
        url = f"{self._api_origin}/v1/{self._db_root}:commit"
        self._request_json("POST", url, {"writes": writes})

    def save_secret(
        self,
        secret_id: str,
        ciphertext: str,
        iv: str,
        salt: Optional[str] = None,
        max_views: int = 1,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        now = int(time.time())
        expires_at = now + ttl_seconds
        delete_token = py_secrets.token_urlsafe(24)
        delete_token_hash = _hash_delete_token(delete_token)

        safe_id = urllib_parse.quote(secret_id, safe="")
        url = f"{self._api_origin}/v1/{self._db_root}/{self.collection}?documentId={safe_id}"
        fields = self._encode_fields({
            "id": secret_id,
            "ciphertext": ciphertext,
            "iv": iv,
            "salt": salt,
            "max_views": max_views,
            "views_count": 0,
            "expires_at": expires_at,
            "created_at": now,
            "delete_token_hash": delete_token_hash,
        })
        self._request_json("POST", url, {"fields": fields})
        return {
            "id": secret_id,
            "expires_at": expires_at,
            "max_views": max_views,
            "delete_token": delete_token,
        }

    def get_meta(self, secret_id: str) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        doc = self._get_doc(secret_id)
        if not doc:
            return None
        data = self._decode_fields(doc.get("fields", {}))
        if data.get("expires_at", 0) <= now or data.get("views_count", 0) >= data.get("max_views", 1):
            update_time = doc.get("updateTime")
            if update_time:
                try:
                    self._commit_writes([{
                        "delete": doc.get("name", self._doc_name(secret_id)),
                        "currentDocument": {"updateTime": update_time},
                    }])
                except urllib_error.HTTPError:
                    pass
            return None
        max_views = int(data.get("max_views", 1))
        views_count = int(data.get("views_count", 0))
        return {
            "id": secret_id,
            "requires_passphrase": bool(data.get("salt")),
            "views_left": max_views - views_count,
            "max_views": max_views,
            "expires_at": int(data.get("expires_at", 0)),
        }

    def consume_secret(self, secret_id: str) -> Optional[Dict[str, Any]]:
        now = int(time.time())
        for _ in range(5):
            doc = self._get_doc(secret_id)
            if not doc:
                return None
            doc_name = doc.get("name", self._doc_name(secret_id))
            update_time = doc.get("updateTime")
            fields = dict(doc.get("fields", {}))
            data = self._decode_fields(fields)

            if data.get("expires_at", 0) <= now:
                try:
                    self._commit_writes([{
                        "delete": doc_name,
                        "currentDocument": {"updateTime": update_time},
                    }])
                except urllib_error.HTTPError:
                    pass
                return None

            max_views = int(data.get("max_views", 1))
            new_views = int(data.get("views_count", 0)) + 1
            views_left = max_views - new_views

            if views_left <= 0:
                write = {
                    "delete": doc_name,
                    "currentDocument": {"updateTime": update_time},
                }
            else:
                fields["views_count"] = {"integerValue": str(new_views)}
                write = {
                    "update": {"name": doc_name, "fields": fields},
                    "updateMask": {"fieldPaths": ["views_count"]},
                    "currentDocument": {"updateTime": update_time},
                }

            try:
                self._commit_writes([write])
                return {
                    "id": secret_id,
                    "ciphertext": data["ciphertext"],
                    "iv": data["iv"],
                    "salt": data.get("salt"),
                    "views_left": max(0, views_left),
                    "burned": views_left <= 0,
                }
            except urllib_error.HTTPError as e:
                if e.code in (400, 404, 409, 412):
                    continue
                raise
        return None

    def revoke_secret(self, secret_id: str, delete_token: str) -> str:
        if not delete_token:
            return "forbidden"
        candidate_hash = _hash_delete_token(delete_token)
        for _ in range(3):
            doc = self._get_doc(secret_id)
            if not doc:
                return "not_found"
            data = self._decode_fields(doc.get("fields", {}))
            stored_hash = data.get("delete_token_hash") or ""
            if not stored_hash or not hmac.compare_digest(stored_hash, candidate_hash):
                return "forbidden"
            doc_name = doc.get("name", self._doc_name(secret_id))
            update_time = doc.get("updateTime")
            try:
                self._commit_writes([{
                    "delete": doc_name,
                    "currentDocument": {"updateTime": update_time},
                }])
                return "ok"
            except urllib_error.HTTPError as e:
                if e.code == 404:
                    return "not_found"
                if e.code in (400, 409, 412):
                    continue
                raise
        return "not_found"

    def purge_expired(self) -> int:
        now = int(time.time())
        url = f"{self._api_origin}/v1/{self._db_root}:runQuery"
        query = {
            "structuredQuery": {
                "from": [{"collectionId": self.collection}],
                "where": {
                    "fieldFilter": {
                        "field": {"fieldPath": "expires_at"},
                        "op": "LESS_THAN_OR_EQUAL",
                        "value": {"integerValue": str(now)},
                    }
                },
                "limit": 100,
            }
        }
        try:
            req = urllib_request.Request(
                url,
                data=json.dumps(query).encode("utf-8"),
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    **(
                        {"Authorization": f"Bearer {self._get_access_token()}"}
                        if self._get_access_token()
                        else {}
                    ),
                },
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=10.0) as resp:
                rows = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return 0

        writes = []
        for row in rows:
            doc = row.get("document")
            if doc and "name" in doc:
                writes.append({"delete": doc["name"]})
        if not writes:
            return 0
        self._commit_writes(writes)
        return len(writes)


def create_secret_store(db_path: str = "secrets.db"):
    """Selects SQLite (default) or durable Firestore REST backend via STORAGE_BACKEND."""
    backend = os.environ.get("STORAGE_BACKEND", "sqlite").strip().lower()
    if backend == "firestore":
        return FirestoreSecretDB(
            collection=os.environ.get("FIRESTORE_COLLECTION", "burnbin_secrets"),
            database=os.environ.get("FIRESTORE_DATABASE", "(default)"),
        )
    return SecretDB(db_path=db_path)
