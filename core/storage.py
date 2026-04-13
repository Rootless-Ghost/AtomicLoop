"""
AtomicLoop — SQLite storage for test run artifacts.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime

logger = logging.getLogger("atomicloop.storage")


class RunStorage:
    """Manages the SQLite database for test run results."""

    def __init__(self, db_path: str = "./atomicloop.db"):
        self.db_path = db_path
        self._init_db()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id               TEXT PRIMARY KEY,
                    technique_id     TEXT NOT NULL,
                    test_number      INTEGER NOT NULL DEFAULT 1,
                    test_name        TEXT NOT NULL DEFAULT '',
                    executor_type    TEXT NOT NULL DEFAULT '',
                    exit_code        INTEGER,
                    executed_at      TEXT NOT NULL,
                    duration_ms      INTEGER DEFAULT 0,
                    event_count      INTEGER DEFAULT 0,
                    detection_fired  INTEGER DEFAULT -1,
                    dry_run          INTEGER DEFAULT 0,
                    run_json         TEXT NOT NULL,
                    created_at       TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_runs_technique
                ON runs (technique_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_runs_executed
                ON runs (executed_at DESC)
            """)
            conn.commit()
        logger.info("Storage initialised: %s", self.db_path)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_run(self, run: dict) -> dict:
        """Persist a run result. Generates a UUID if not present. Returns updated run."""
        run_id = run.get("id") or str(uuid.uuid4())
        now    = datetime.utcnow().isoformat() + "Z"

        detection_fired_raw = run.get("detection_fired")
        if detection_fired_raw is True:
            detection_fired_int = 1
        elif detection_fired_raw is False:
            detection_fired_int = 0
        else:
            detection_fired_int = -1  # not evaluated

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO runs
                    (id, technique_id, test_number, test_name, executor_type,
                     exit_code, executed_at, duration_ms, event_count,
                     detection_fired, dry_run, run_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    run.get("technique_id", ""),
                    run.get("test_number", 1),
                    run.get("test_name", ""),
                    run.get("executor_type", ""),
                    run.get("exit_code"),
                    run.get("executed_at", now),
                    run.get("duration_ms", 0),
                    len(run.get("events", [])),
                    detection_fired_int,
                    1 if run.get("dry_run") else 0,
                    json.dumps(run, ensure_ascii=False),
                    now,
                ),
            )
            conn.commit()

        run["id"]         = run_id
        run["created_at"] = now
        logger.info(
            "Saved run %s (%s test %s)",
            run_id, run.get("technique_id"), run.get("test_number"),
        )
        return run

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_run(self, run_id: str) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        data             = json.loads(row["run_json"])
        data["id"]       = row["id"]
        data["created_at"] = row["created_at"]
        return data

    def list_runs(
        self,
        page:         int = 1,
        per_page:     int = 50,
        search:       str = "",
        technique_id: str = "",
    ) -> dict:
        conditions: list[str] = []
        params:     list      = []

        if search:
            conditions.append("(LOWER(test_name) LIKE LOWER(?) OR LOWER(technique_id) LIKE LOWER(?))")
            params.extend([f"%{search}%", f"%{search}%"])
        if technique_id:
            conditions.append("technique_id = ?")
            params.append(technique_id.upper())

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM runs {where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, technique_id, test_number, test_name, executor_type,
                       exit_code, executed_at, duration_ms, event_count,
                       detection_fired, dry_run, created_at
                FROM runs {where}
                ORDER BY executed_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()

        return {
            "items":    [dict(r) for r in rows],
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_run(self, run_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            conn.commit()
        return cur.rowcount > 0

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM runs")
            conn.commit()
        return cur.rowcount
