from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

SCHEMA_VERSION = 1
DEFAULT_INTERVAL_SECONDS = 30
DEFAULT_RETENTION_DAYS = 30
MAX_SAMPLE_ROWS = 250_000
MAX_INCIDENT_ROWS = 10_000
MAX_CHANGE_ROWS = 10_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ReliabilityStore:
    """Small, local SQLite store with explicit schema migrations and bounded history."""

    def __init__(self, path: str | Path | None = None):
        if path is None:
            path = Path(user_data_dir("fedora-doctor")) / "reliability.sqlite3"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def _initialize(self) -> None:
        with self._lock, self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"База надёжности новее приложения: schema {version}"
                )
            migrations = {
                1: """
                    CREATE TABLE incidents (
                        id INTEGER PRIMARY KEY,
                        fingerprint TEXT NOT NULL UNIQUE,
                        occurred_at TEXT NOT NULL,
                        category TEXT NOT NULL,
                        process TEXT,
                        pid INTEGER,
                        signal TEXT,
                        exit_code TEXT,
                        app_version TEXT,
                        stack_trace TEXT,
                        source TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        evidence_json TEXT NOT NULL DEFAULT '[]',
                        group_key TEXT,
                        confidence REAL NOT NULL DEFAULT 0.3,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        occurrences INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE INDEX incidents_time_idx ON incidents(occurred_at DESC);
                    CREATE INDEX incidents_group_idx ON incidents(group_key, occurred_at);
                    CREATE TABLE samples (
                        id INTEGER PRIMARY KEY,
                        captured_at TEXT NOT NULL,
                        cpu_percent REAL,
                        ram_percent REAL,
                        ram_available INTEGER,
                        swap_percent REAL,
                        gpu_percent REAL,
                        vram_used INTEGER,
                        vram_total INTEGER,
                        temperatures_json TEXT NOT NULL DEFAULT '{}',
                        disk_io_json TEXT NOT NULL DEFAULT '{}',
                        network_json TEXT NOT NULL DEFAULT '{}',
                        load_json TEXT NOT NULL DEFAULT '[]'
                    );
                    CREATE INDEX samples_time_idx ON samples(captured_at DESC);
                    CREATE TABLE changes (
                        id INTEGER PRIMARY KEY,
                        fingerprint TEXT NOT NULL UNIQUE,
                        occurred_at TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        details_json TEXT NOT NULL DEFAULT '{}',
                        source TEXT NOT NULL
                    );
                    CREATE INDEX changes_time_idx ON changes(occurred_at DESC);
                    CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                """,
            }
            for next_version in range(version + 1, SCHEMA_VERSION + 1):
                db.executescript(migrations[next_version])
                db.execute(f"PRAGMA user_version={next_version}")
            db.executemany(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
                [
                    ("interval_seconds", str(DEFAULT_INTERVAL_SECONDS)),
                    ("retention_days", str(DEFAULT_RETENTION_DAYS)),
                    ("max_sample_rows", str(MAX_SAMPLE_ROWS)),
                ],
            )

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (TypeError, json.JSONDecodeError):
            return row["value"]

    def set_setting(self, key: str, value: Any) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, ensure_ascii=False)),
            )

    def add_incident(self, incident: dict[str, Any]) -> bool:
        """Insert an incident idempotently; return True when the fingerprint was new."""
        now = utc_now()
        with self._lock, self._connect() as db:
            existed = (
                db.execute(
                    "SELECT 1 FROM incidents WHERE fingerprint=?",
                    (incident["fingerprint"],),
                ).fetchone()
                is not None
            )
            cur = db.execute(
                """INSERT INTO incidents(fingerprint,occurred_at,category,process,pid,signal,exit_code,
                   app_version,stack_trace,source,summary,evidence_json,group_key,confidence,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   evidence_json=CASE WHEN excluded.evidence_json='[]' THEN incidents.evidence_json ELSE excluded.evidence_json END""",
                (
                    incident["fingerprint"],
                    incident.get("occurred_at") or now,
                    incident.get("category", "system"),
                    incident.get("process"),
                    incident.get("pid"),
                    incident.get("signal"),
                    incident.get("exit_code"),
                    incident.get("app_version"),
                    incident.get("stack_trace"),
                    incident.get("source", "journal"),
                    incident.get("summary", "Системное событие"),
                    json.dumps(incident.get("evidence", []), ensure_ascii=False),
                    incident.get("group_key"),
                    float(incident.get("confidence", 0.3)),
                    now,
                    now,
                ),
            )
            return not existed and cur.rowcount == 1

    def add_sample(self, sample: dict[str, Any]) -> None:
        fields = (
            "cpu_percent",
            "ram_percent",
            "ram_available",
            "swap_percent",
            "gpu_percent",
            "vram_used",
            "vram_total",
        )
        values = [sample.get(k) for k in fields]
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO samples(captured_at,cpu_percent,ram_percent,ram_available,swap_percent,gpu_percent,
                   vram_used,vram_total,temperatures_json,disk_io_json,network_json,load_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    sample.get("captured_at") or utc_now(),
                    *values,
                    json.dumps(sample.get("temperatures", {}), ensure_ascii=False),
                    json.dumps(sample.get("disk_io", {}), ensure_ascii=False),
                    json.dumps(sample.get("network", {}), ensure_ascii=False),
                    json.dumps(sample.get("load", []), ensure_ascii=False),
                ],
            )

    def update_stack_trace(self, fingerprint: str, stack_trace: str) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute(
                "UPDATE incidents SET stack_trace=? WHERE fingerprint=?",
                (stack_trace[:12000], fingerprint),
            )
            return cur.rowcount == 1

    def add_change(self, change: dict[str, Any]) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO changes(fingerprint,occurred_at,kind,subject,details_json,source) VALUES(?,?,?,?,?,?)",
                (
                    change["fingerprint"],
                    change.get("occurred_at") or utc_now(),
                    change["kind"],
                    change["subject"],
                    json.dumps(change.get("details", {}), ensure_ascii=False),
                    change.get("source", "snapshot"),
                ),
            )
            return cur.rowcount == 1

    def incidents(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM incidents ORDER BY occurred_at DESC,id DESC LIMIT ?",
                (max(1, min(limit, 2000)),),
            ).fetchall()
        result = [dict(row) for row in rows]
        for row in result:
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return result

    def samples(self, limit: int = 3000) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM samples ORDER BY captured_at DESC,id DESC LIMIT ?",
                (max(1, min(limit, 50000)),),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def changes(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM changes ORDER BY occurred_at DESC,id DESC LIMIT ?",
                (max(1, min(limit, 2000)),),
            ).fetchall()
        result = [dict(row) for row in rows]
        for row in result:
            row["details"] = json.loads(row.pop("details_json"))
        return result

    def rotate(self, now: datetime | None = None) -> dict[str, int]:
        now = now or datetime.now(timezone.utc)
        retention = max(
            1,
            min(int(self.get_setting("retention_days", DEFAULT_RETENTION_DAYS)), 3650),
        )
        max_samples = max(
            100,
            min(int(self.get_setting("max_sample_rows", MAX_SAMPLE_ROWS)), 2_000_000),
        )
        cutoff = (now - timedelta(days=retention)).isoformat()
        with self._lock, self._connect() as db:
            samples = db.execute(
                "DELETE FROM samples WHERE captured_at < ?", (cutoff,)
            ).rowcount
            incidents = db.execute(
                "DELETE FROM incidents WHERE occurred_at < ?", (cutoff,)
            ).rowcount
            changes = db.execute(
                "DELETE FROM changes WHERE occurred_at < ?", (cutoff,)
            ).rowcount
            excess = (
                db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] - max_samples
            )
            if excess > 0:
                db.execute(
                    "DELETE FROM samples WHERE id IN (SELECT id FROM samples ORDER BY captured_at ASC,id ASC LIMIT ?)",
                    (excess,),
                )
            incident_excess = (
                db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                - MAX_INCIDENT_ROWS
            )
            if incident_excess > 0:
                db.execute(
                    "DELETE FROM incidents WHERE id IN (SELECT id FROM incidents ORDER BY occurred_at ASC,id ASC LIMIT ?)",
                    (incident_excess,),
                )
            change_excess = (
                db.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
                - MAX_CHANGE_ROWS
            )
            if change_excess > 0:
                db.execute(
                    "DELETE FROM changes WHERE id IN (SELECT id FROM changes ORDER BY occurred_at ASC,id ASC LIMIT ?)",
                    (change_excess,),
                )
            db.commit()
            db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return {
            "samples": samples + max(0, excess),
            "incidents": incidents + max(0, incident_excess),
            "changes": changes + max(0, change_excess),
        }
