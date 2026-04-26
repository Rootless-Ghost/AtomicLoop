"""
AtomicLoop — Run storage layer.

Supports SQLite (default, zero-config) and PostgreSQL.

Backend selection:
  • If DATABASE_URL starts with "postgresql://" or "postgres://" → PostgreSQL
  • Otherwise the value is treated as a local file path → SQLite

SQLite is the default for standalone/development use; PostgreSQL is used in
the Docker / Nebula Forge suite via the DATABASE_URL environment variable.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger("atomicloop.storage")

_PG_PREFIXES = ("postgresql://", "postgres://")


def _is_pg_url(url: str) -> bool:
    return url.lower().startswith(_PG_PREFIXES)


class RunStorage:

    def __init__(self, database_url: str = "./atomicloop.db"):
        url = os.environ.get("DATABASE_URL") or database_url
        self._backend = "postgresql" if _is_pg_url(url) else "sqlite"

        if self._backend == "postgresql":
            import psycopg2
            import psycopg2.extras
            from psycopg2.pool import ThreadedConnectionPool
            self._pg_extras = psycopg2.extras
            self._pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=url)
            logger.info("Storage backend: PostgreSQL (%s)", url.split("@")[-1])
        else:
            self._lock = threading.Lock()
            conn = sqlite3.connect(url, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._sqlite_conn = conn
            self._ensure_schema()
            logger.info("Storage backend: SQLite (%s)", url)

    def _ensure_schema(self) -> None:
        """Create the runs table and indexes if they do not exist (SQLite only)."""
        self._sqlite_conn.executescript("""
            CREATE TABLE IF NOT EXISTS atomicloop_runs (
                id               TEXT    PRIMARY KEY,
                technique_id     TEXT    NOT NULL,
                test_number      INTEGER NOT NULL,
                test_name        TEXT    NOT NULL,
                executor_type    TEXT    NOT NULL,
                exit_code        INTEGER,
                executed_at      TEXT    NOT NULL,
                duration_ms      INTEGER NOT NULL DEFAULT 0,
                event_count      INTEGER NOT NULL DEFAULT 0,
                detection_fired  INTEGER NOT NULL DEFAULT -1,
                dry_run          INTEGER NOT NULL DEFAULT 0,
                run_json         TEXT    NOT NULL,
                created_at       TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_runs_technique ON atomicloop_runs (technique_id);
            CREATE INDEX IF NOT EXISTS idx_runs_executed  ON atomicloop_runs (executed_at);
        """)
        self._sqlite_conn.commit()

    @contextmanager
    def _get_conn(self):
        """Yield a connection with appropriate lifecycle management."""
        if self._backend == "sqlite":
            with self._lock:
                try:
                    yield self._sqlite_conn
                except Exception:
                    self._sqlite_conn.rollback()
                    raise
        else:
            conn = self._pool.getconn()
            try:
                yield conn
            except Exception:
                conn.rollback()
                raise
            finally:
                self._pool.putconn(conn)

    def _q(self, sql: str) -> str:
        """Translate %s placeholders to ? for SQLite."""
        return sql.replace("%s", "?") if self._backend == "sqlite" else sql

    def _cursor(self, conn):
        """Return a dict-row cursor for the current backend."""
        if self._backend == "sqlite":
            return conn.cursor()          # row_factory=sqlite3.Row set at __init__
        return conn.cursor(cursor_factory=self._pg_extras.RealDictCursor)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_run(self, run: dict) -> dict:
        run_id = run.get("id") or str(uuid.uuid4())
        now    = datetime.utcnow().isoformat() + "Z"

        detection_fired_raw = run.get("detection_fired")
        if detection_fired_raw is True:
            detection_fired_int = 1
        elif detection_fired_raw is False:
            detection_fired_int = 0
        else:
            detection_fired_int = -1

        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute(
                self._q("""
                INSERT INTO atomicloop_runs
                    (id, technique_id, test_number, test_name, executor_type,
                     exit_code, executed_at, duration_ms, event_count,
                     detection_fired, dry_run, run_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """),
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

    def update_run_validation(self, run_id: str, run: dict) -> bool:
        """Update detection_fired and run_json for an existing run in-place."""
        detection_fired_raw = run.get("detection_fired")
        if detection_fired_raw is True:
            detection_fired_int = 1
        elif detection_fired_raw is False:
            detection_fired_int = 0
        else:
            detection_fired_int = -1

        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute(
                self._q("""
                UPDATE atomicloop_runs
                   SET detection_fired = %s,
                       run_json        = %s
                 WHERE id = %s
                """),
                (
                    detection_fired_int,
                    json.dumps(run, ensure_ascii=False),
                    run_id,
                ),
            )
            updated = cur.rowcount > 0
            conn.commit()

        if updated:
            logger.info("Updated validation for run %s (detection_fired=%s)", run_id, detection_fired_raw)
        else:
            logger.warning("update_run_validation: run %s not found", run_id)
        return updated

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_run(self, run_id: str) -> dict | None:
        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute(
                self._q("SELECT * FROM atomicloop_runs WHERE id = %s"),
                (run_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        data               = json.loads(row["run_json"])
        data["id"]         = row["id"]
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
            conditions.append(
                "(LOWER(test_name) LIKE LOWER(%s) OR LOWER(technique_id) LIKE LOWER(%s))"
            )
            params.extend([f"%{search}%", f"%{search}%"])
        if technique_id:
            conditions.append("technique_id = %s")
            params.append(technique_id.upper())

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute(
                self._q(f"SELECT COUNT(*) AS count FROM atomicloop_runs {where}"),
                params,
            )
            total = cur.fetchone()["count"]
            cur.execute(
                self._q(f"""
                SELECT id, technique_id, test_number, test_name, executor_type,
                       exit_code, executed_at, duration_ms, event_count,
                       detection_fired, dry_run, created_at
                FROM atomicloop_runs {where}
                ORDER BY executed_at DESC
                LIMIT %s OFFSET %s
                """),
                params + [per_page, offset],
            )
            items = [dict(r) for r in cur.fetchall()]

        return {
            "items":    items,
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_run(self, run_id: str) -> bool:
        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute(
                self._q("DELETE FROM atomicloop_runs WHERE id = %s"),
                (run_id,),
            )
            deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            cur = self._cursor(conn)
            cur.execute("DELETE FROM atomicloop_runs")
            count = cur.rowcount
            conn.commit()
        return count
