"""
AtomicLoop — PostgreSQL storage for test run artifacts.

Schema is managed externally via init-db/. Table expected: atomicloop_runs
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime

import psycopg2
import psycopg2.extras

logger = logging.getLogger("atomicloop.storage")


class RunStorage:

    def __init__(self, db_path: str = "./atomicloop.db"):
        self._url = os.environ.get("DATABASE_URL") or db_path

    def _get_conn(self):
        return psycopg2.connect(self._url)

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
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO atomicloop_runs
                        (id, technique_id, test_number, test_name, executor_type,
                         exit_code, executed_at, duration_ms, event_count,
                         detection_fired, dry_run, run_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM atomicloop_runs WHERE id = %s", (run_id,)
                )
                row = cur.fetchone()
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
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) FROM atomicloop_runs {where}", params)
                total = cur.fetchone()["count"]
                cur.execute(
                    f"""
                    SELECT id, technique_id, test_number, test_name, executor_type,
                           exit_code, executed_at, duration_ms, event_count,
                           detection_fired, dry_run, created_at
                    FROM atomicloop_runs {where}
                    ORDER BY executed_at DESC
                    LIMIT %s OFFSET %s
                    """,
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
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM atomicloop_runs WHERE id = %s", (run_id,)
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM atomicloop_runs")
                count = cur.rowcount
            conn.commit()
        return count
