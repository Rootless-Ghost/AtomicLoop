-- AtomicLoop run history schema
-- Compatible with SQLite 3.x and PostgreSQL 14+
--
-- SQLite:     sqlite3 atomicloop.db < init-db/schema.sql
-- PostgreSQL: psql $DATABASE_URL    < init-db/schema.sql
--
-- Note: SQLite deployments do not need to run this manually — the schema
-- is created automatically by RunStorage._ensure_schema() on first startup.

CREATE TABLE IF NOT EXISTS atomicloop_runs (
    id               TEXT    PRIMARY KEY,
    technique_id     TEXT    NOT NULL,
    test_number      INTEGER NOT NULL,
    test_name        TEXT    NOT NULL,
    executor_type    TEXT    NOT NULL,
    exit_code        INTEGER,                        -- NULL for dry runs / manual tests
    executed_at      TEXT    NOT NULL,               -- ISO-8601, e.g. 2026-04-26T14:30:00Z
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    event_count      INTEGER NOT NULL DEFAULT 0,
    detection_fired  INTEGER NOT NULL DEFAULT -1,    -- -1 = pending, 0 = miss, 1 = fired
    dry_run          INTEGER NOT NULL DEFAULT 0,     -- 0 = live, 1 = dry
    run_json         TEXT    NOT NULL,               -- full run payload serialised as JSON
    created_at       TEXT    NOT NULL                -- row insert timestamp (ISO-8601)
);

CREATE INDEX IF NOT EXISTS idx_runs_technique ON atomicloop_runs (technique_id);
CREATE INDEX IF NOT EXISTS idx_runs_executed  ON atomicloop_runs (executed_at);
