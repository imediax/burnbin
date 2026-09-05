"""
Database management for Self-Destructing Secret Pastebin.
Uses SQLite with Write-Ahead Logging (WAL) for safe concurrent access.
"""

import contextlib
import os
import sqlite3
import time
from typing import Optional, Dict, Any


class SecretDB:
    def __init__(self, db_path: str = "secrets.db"):
        self.db_path = db_path
        self._init_db()

    @contextlib.contextmanager
    def get_db(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id TEXT PRIMARY KEY,
                    ciphertext TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    salt TEXT,
                    max_views INTEGER NOT NULL DEFAULT 1,
                    views_count INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);")
            conn.commit()

    def save_secret(
        self,
        secret_id: str,
        ciphertext: str,
        iv: str,
        salt: Optional[str] = None,
        max_views: int = 1,
        ttl_seconds: int = 3600
    ) -> Dict[str, Any]:
        """Saves an encrypted secret with view limits and expiration."""
        now = int(time.time())
        expires_at = now + ttl_seconds
        with self.get_db() as conn:
            conn.execute(
                """
                INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views_count, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (secret_id, ciphertext, iv, salt, max_views, expires_at, now)
            )
            conn.commit()
        return {
            "id": secret_id,
            "expires_at": expires_at,
            "max_views": max_views
        }

    def get_meta(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """Checks if a secret exists and is valid without burning it."""
        self.purge_expired()
        now = int(time.time())
        with self.get_db() as conn:
            row = conn.execute(
                "SELECT id, salt, max_views, views_count, expires_at, created_at FROM secrets WHERE id = ?",
                (secret_id,)
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] <= now or row["views_count"] >= row["max_views"]:
                # Clean up if already exhausted
                conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                conn.commit()
                return None
            return {
                "id": row["id"],
                "requires_passphrase": bool(row["salt"]),
                "views_left": row["max_views"] - row["views_count"],
                "max_views": row["max_views"],
                "expires_at": row["expires_at"]
            }

    def consume_secret(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """
        Atomically increments views and retrieves ciphertext.
        Burns (deletes) the secret immediately if max_views is reached.
        """
        now = int(time.time())
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            row = cursor.execute(
                "SELECT id, ciphertext, iv, salt, max_views, views_count, expires_at FROM secrets WHERE id = ?",
                (secret_id,)
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
                # Burn immediately
                cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            else:
                cursor.execute(
                    "UPDATE secrets SET views_count = ? WHERE id = ?",
                    (new_views, secret_id)
                )
            conn.commit()

            return {
                "id": row["id"],
                "ciphertext": row["ciphertext"],
                "iv": row["iv"],
                "salt": row["salt"],
                "views_left": max(0, views_left),
                "burned": views_left <= 0
            }

    def purge_expired(self) -> int:
        """Purges any secrets that have expired."""
        now = int(time.time())
        with self.get_db() as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE expires_at <= ?", (now,))
            conn.commit()
            return cursor.rowcount
