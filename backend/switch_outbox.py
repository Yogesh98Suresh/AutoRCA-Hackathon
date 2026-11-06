"""SQLite-backed Switch delivery queue and inbound event deduplication."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SwitchOutbox:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = RLock()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                handoff_kind TEXT NOT NULL,
                room_id TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','failed','unknown')),
                error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(investigation_id, handoff_kind)
            );
            CREATE TABLE IF NOT EXISTS inbound_events (
                sequence INTEGER PRIMARY KEY,
                message_id TEXT NOT NULL UNIQUE,
                investigation_id TEXT NOT NULL,
                room_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                thread_id TEXT,
                content TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stream_state (
                connection_id TEXT PRIMARY KEY,
                cursor INTEGER NOT NULL DEFAULT 0,
                generation INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS stream_gaps (
                connection_id TEXT PRIMARY KEY,
                details TEXT NOT NULL,
                history_rechecked INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
        """)
        return connection

    @contextmanager
    def _db(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def enqueue(self, investigation_id: str, room_id: str, content: str, handoff_kind: str = "approved_plan") -> dict:
        with self._lock, self._db() as db:
            db.execute("""INSERT OR IGNORE INTO deliveries
                (investigation_id, handoff_kind, room_id, content, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
                (investigation_id, handoff_kind, room_id, content, _now(), _now()))
            row = db.execute("SELECT * FROM deliveries WHERE investigation_id=? AND handoff_kind=?",
                             (investigation_id, handoff_kind)).fetchone()
            return dict(row)

    def claim(self, delivery_id: int) -> dict | None:
        with self._lock, self._db() as db:
            changed = db.execute("UPDATE deliveries SET status='sending', error='', updated_at=? WHERE id=? AND status='pending'",
                                 (_now(), delivery_id)).rowcount
            row = db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            return dict(row) if changed and row else None

    def set_delivery(self, delivery_id: int, status: str, error: str = "") -> dict:
        if status not in {"pending", "sent", "failed", "unknown"}:
            raise ValueError("Invalid delivery state.")
        with self._lock, self._db() as db:
            db.execute("UPDATE deliveries SET status=?, error=?, updated_at=? WHERE id=?",
                       (status, error[:300], _now(), delivery_id))
            row = db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            return dict(row)

    def get_delivery(self, investigation_id: str, handoff_kind: str = "approved_plan") -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM deliveries WHERE investigation_id=? AND handoff_kind=?",
                             (investigation_id, handoff_kind)).fetchone()
            return dict(row) if row else None

    def get_latest_delivery(self, investigation_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM deliveries WHERE investigation_id=? ORDER BY id DESC LIMIT 1",
                             (investigation_id,)).fetchone()
            return dict(row) if row else None

    def list_pending(self, limit: int = 100) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM deliveries WHERE status='pending' ORDER BY id LIMIT ?", (limit,)).fetchall()
            return [dict(row) for row in rows]

    def recover_inflight(self) -> int:
        """An interrupted send has an ambiguous outcome; never auto-retry it."""
        with self._db() as db:
            result = db.execute("UPDATE deliveries SET status='unknown', error='Process stopped during send; reconcile before retrying.', updated_at=? WHERE status='sending'",
                                (_now(),))
            return result.rowcount

    def save_stream_state(self, connection_id: str, cursor: int, generation: int) -> None:
        with self._db() as db:
            db.execute("""INSERT INTO stream_state(connection_id,cursor,generation) VALUES(?,?,?)
                ON CONFLICT(connection_id) DO UPDATE SET cursor=MAX(cursor,excluded.cursor), generation=excluded.generation""",
                (connection_id, cursor, generation))

    def get_stream_state(self, connection_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT cursor,generation FROM stream_state WHERE connection_id=?", (connection_id,)).fetchone()
            return dict(row) if row else {"cursor": 0, "generation": 0}

    def record_gap(self, connection_id: str, details: dict, history_rechecked: bool) -> None:
        with self._db() as db:
            db.execute("""INSERT INTO stream_gaps(connection_id,details,history_rechecked,updated_at)
                VALUES(?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET
                details=excluded.details, history_rechecked=excluded.history_rechecked, updated_at=excluded.updated_at""",
                (connection_id, json.dumps(details, sort_keys=True)[:2000], int(history_rechecked), _now()))

    def get_gap_state(self, connection_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT details,history_rechecked,updated_at FROM stream_gaps WHERE connection_id=?",
                             (connection_id,)).fetchone()
            return dict(row) if row else None

    def save_inbound(self, *, sequence: int, message_id: str, investigation_id: str,
                     room_id: str, sender: str, thread_id: str | None, content: str) -> bool:
        with self._db() as db:
            result = db.execute("""INSERT OR IGNORE INTO inbound_events
                (sequence,message_id,investigation_id,room_id,sender,thread_id,content,received_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (sequence, message_id, investigation_id, room_id, sender, thread_id, content, _now()))
            return result.rowcount == 1

    def list_inbound(self, investigation_id: str) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT sequence,message_id,investigation_id,room_id,sender,thread_id,content,received_at FROM inbound_events WHERE investigation_id=? ORDER BY sequence",
                              (investigation_id,)).fetchall()
            return [dict(row) for row in rows]
