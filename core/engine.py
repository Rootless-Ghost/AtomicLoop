"""
AtomicLoop — Main engine.

Orchestrates:
  1. Atomic test lookup
  2. Command variable substitution
  3. Execution via executor (with safety controls)
  4. Windows Event Log capture
  5. Optional LogNorm normalization
  6. Detection validation via DriftWatch
  7. Run persistence
  8. Markdown export
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from .atomics        import get_all_techniques, get_technique, get_test
from .executor       import execute, execute_cleanup, substitute_variables, DEFAULT_TIMEOUT
from .event_collector import collect_events, normalize_via_lognorm
from .validator      import validate_detection, validate_events_only
from .storage        import RunStorage

logger = logging.getLogger("atomicloop.engine")

DEFAULT_CONFIRM_REQUIRED = True


class AtomicEngine:
    """Main engine: runs atomic tests, captures events, validates detections."""

    def __init__(self, config: dict):
        self.config      = config
        self.storage     = RunStorage(config.get("db_path", "./atomicloop.db"))
        exec_cfg         = config.get("execution", {})
        self.default_timeout   = int(exec_cfg.get("timeout", DEFAULT_TIMEOUT))
        self.default_confirm   = bool(exec_cfg.get("require_confirm", DEFAULT_CONFIRM_REQUIRED))
        self.auto_save         = bool(exec_cfg.get("auto_save", True))
        integrations           = config.get("integrations", {})
        self.lognorm_url       = integrations.get("lognorm_url",    "http://127.0.0.1:5006")
        self.huntforge_url     = integrations.get("huntforge_url",  "http://127.0.0.1:5007")
        self.driftwatch_url    = integrations.get("driftwatch_url", "http://127.0.0.1:5008")
        logger.info(
            "AtomicEngine initialised (timeout=%ds, auto_save=%s)",
            self.default_timeout, self.auto_save,
        )

    # ── Atomics catalogue ──────────────────────────────────────────────────────

    def get_atomics(self, technique_id: str | None = None) -> list[dict] | dict | None:
        """Return all techniques (list) or a single technique (dict)."""
        if technique_id:
            return get_technique(technique_id)
        return get_all_techniques()

    # ── Primary: run test ──────────────────────────────────────────────────────

    def run_test(
        self,
        technique_id:    str,
        test_number:     int   = 1,
        confirm:         bool  = False,
        dry_run:         bool  = False,
        capture_events:  bool  = True,
        normalize:       bool  = True,
        timeout:         int | None = None,
        input_arguments: dict | None = None,
        save:            bool  = True,
    ) -> dict:
        """
        Execute an atomic test and capture the artifacts.

        Safety: if confirm=False and dry_run=False the call is rejected.
        dry_run=True always proceeds (shows command, no execution).

        Args:
            technique_id:    MITRE technique ID (e.g. "T1059.001").
            test_number:     1-based test index within the technique.
            confirm:         Must be True to actually execute (safety control).
            dry_run:         If True, show command without executing.
            capture_events:  If True, collect Windows Event Log events.
            normalize:       If True, attempt LogNorm normalization of events.
            timeout:         Execution timeout in seconds.
            input_arguments: Variable substitutions for #{variable} placeholders.
            save:            Persist the run to SQLite.

        Returns:
            Full run dict with execution results, events, and metadata.
        """
        # Safety gate
        if not dry_run and not confirm:
            return {
                "success": False,
                "error": (
                    "Execution requires explicit confirmation. "
                    "Set confirm=true in the request body, or use dry_run=true to preview."
                ),
            }

        # Look up test definition
        test = get_test(technique_id, test_number)
        if test is None:
            return {
                "success": False,
                "error": (
                    f"Test not found: technique_id={technique_id!r} test_number={test_number}. "
                    "Call GET /api/atomics to list available techniques."
                ),
            }

        effective_timeout = timeout if timeout is not None else self.default_timeout
        input_args        = input_arguments or {}

        if not isinstance(input_args, dict):
            return {
                "success": False,
                "error": "input_arguments must be an object/dictionary.",
            }

        # Strict validation for user-provided substitutions to reduce command-injection risk.
        # Allow a conservative character set commonly needed for file paths, flags, and identifiers.
        safe_value_pattern = re.compile(r"^[A-Za-z0-9 _.:/\\+=,@%-]*$")
        for arg_name, arg_value in input_args.items():
            if not isinstance(arg_value, (str, int, float, bool)):
                return {
                    "success": False,
                    "error": f"Invalid input argument type for {arg_name!r}.",
                }
            if isinstance(arg_value, str):
                if len(arg_value) > 512:
                    return {
                        "success": False,
                        "error": f"Input argument {arg_name!r} exceeds maximum length.",
                    }
                if any(ord(ch) < 32 for ch in arg_value):
                    return {
                        "success": False,
                        "error": f"Control characters are not allowed in input argument {arg_name!r}.",
                    }
                if not safe_value_pattern.fullmatch(arg_value):
                    return {
                        "success": False,
                        "error": f"Unsafe characters detected in input argument {arg_name!r}.",
                    }

        # Substitute variables in command
        command  = substitute_variables(
            test["command"], input_args, test.get("input_arguments", {})
        )
        cleanup_cmd_raw = test.get("cleanup_command")
        cleanup_command = substitute_variables(
            cleanup_cmd_raw, input_args, test.get("input_arguments", {})
        ) if cleanup_cmd_raw else None

        executed_at = datetime.utcnow().isoformat() + "Z"

        # Execute
        result = execute(
            command=command,
            executor_type=test["executor_type"],
            timeout=effective_timeout,
            dry_run=dry_run,
        )

        # Capture events (only on actual execution)
        events: list[dict] = []
        if capture_events and not dry_run and result.error is None:
            raw_events = collect_events(
                start_time_iso=executed_at,
                log_sources=test.get("expected_log_sources"),
                timeout=effective_timeout,
            )
            if normalize and raw_events:
                events = normalize_via_lognorm(raw_events, self.lognorm_url)
            else:
                events = raw_events

        # Build run dict
        run = {
            "success":          result.error is None,
            "technique_id":     technique_id.upper(),
            "technique_name":   test.get("technique_name", ""),
            "tactic":           test.get("tactic", ""),
            "test_number":      test_number,
            "test_name":        test["test_name"],
            "description":      test["description"],
            "executor_type":    test["executor_type"],
            "required_permissions": test.get("required_permissions", "user"),
            "platforms":        test.get("platforms", []),
            "command":          command,
            "cleanup_command":  cleanup_command,
            "executed_at":      executed_at,
            "exit_code":        result.exit_code,
            "raw_output":       result.stdout,
            "stderr":           result.stderr,
            "duration_ms":      result.duration_ms,
            "timed_out":        result.timed_out,
            "dry_run":          dry_run,
            "events":           events,
            "event_count":      len(events),
            "expected_event_ids":    test.get("expected_event_ids", []),
            "expected_log_sources":  test.get("expected_log_sources", []),
            "detection_fired":  None,   # filled in by validate step
            "validation":       None,
            "error":            result.error,
        }

        # Save before returning so run_id is available immediately
        if save and self.auto_save:
            run = self.storage.save_run(run)

        run["run_id"] = run.get("id")
        return run

    # ── Secondary: validate ────────────────────────────────────────────────────

    def validate(
        self,
        run_id:     str | None,
        sigma_rule: str,
        events:     list[dict] | None = None,
    ) -> dict:
        """
        Validate a Sigma rule against the events from a stored run.

        If events is provided it overrides the run's captured events.

        Args:
            run_id:     UUID of a stored run (optional if events is provided directly).
            sigma_rule: Sigma YAML rule string.
            events:     Override event list (optional).

        Returns:
            Detection validation result with gap analysis.
        """
        expected_event_ids:  list[int] = []
        expected_log_sources: list[str] = []

        if run_id:
            run = self.storage.get_run(run_id)
            if run is None:
                return {"success": False, "error": f"Run {run_id!r} not found"}
            if events is None:
                events = run.get("events", [])
            expected_event_ids  = run.get("expected_event_ids", [])
            expected_log_sources = run.get("expected_log_sources", [])

            # Update stored run with validation result
            result = validate_detection(
                sigma_rule=sigma_rule,
                events=events or [],
                expected_event_ids=expected_event_ids,
                expected_log_sources=expected_log_sources,
                driftwatch_url=self.driftwatch_url,
            )
            run["detection_fired"] = result["detection_fired"]
            run["validation"]      = result
            self.storage.save_run({**run, "id": None})  # save updated copy
        else:
            events = events or []
            result = validate_detection(
                sigma_rule=sigma_rule,
                events=events,
                expected_event_ids=expected_event_ids,
                expected_log_sources=expected_log_sources,
                driftwatch_url=self.driftwatch_url,
            )

        return {
            "success":          True,
            "detection_fired":  result["detection_fired"],
            "matched_events":   result["matched_events"],
            "match_count":      result["match_count"],
            "gap_analysis":     result["gap_analysis"],
            "source":           result["source"],
        }

    # ── Storage proxies ────────────────────────────────────────────────────────

    def get_results(self, **kwargs) -> dict:
        return self.storage.list_runs(**kwargs)

    def get_result(self, run_id: str) -> dict | None:
        return self.storage.get_run(run_id)

    def delete_result(self, run_id: str) -> bool:
        return self.storage.delete_run(run_id)

    # ── Markdown export ────────────────────────────────────────────────────────

    def to_markdown(self, run: dict) -> str:
        ts        = (run.get("executed_at") or "")[:10]
        fired_str = {True: "FIRED", False: "NOT FIRED", None: "NOT EVALUATED"}
        fired_val = run.get("detection_fired")

        lines = [
            f"# AtomicLoop Run — {run.get('technique_id', '')} / {run.get('test_name', '')}",
            "",
            f"> **Technique:** {run.get('technique_id', '')} — {run.get('technique_name', '')}  ",
            f"> **Tactic:** {run.get('tactic', '')}  ",
            f"> **Test:** #{run.get('test_number', 1)} — {run.get('test_name', '')}  ",
            f"> **Executed:** {ts}  ",
            f"> **Executor:** {run.get('executor_type', '')}  ",
            f"> **Exit Code:** {run.get('exit_code', 'N/A')}  ",
            f"> **Duration:** {run.get('duration_ms', 0)}ms  ",
            f"> **Dry Run:** {'Yes' if run.get('dry_run') else 'No'}  ",
            f"> **Detection:** {fired_str.get(fired_val, 'N/A')}  ",
            "",
            "---",
            "",
            "## Description",
            "",
            run.get("description", ""),
            "",
            "---",
            "",
            "## Command Executed",
            "",
            "```",
            run.get("command", ""),
            "```",
            "",
        ]

        if run.get("raw_output"):
            lines += [
                "## Execution Output",
                "",
                "```",
                (run["raw_output"] or "")[:2000],
                "```",
                "",
            ]

        events = run.get("events", [])
        if events:
            lines += [
                f"## Captured Events ({len(events)})",
                "",
                "| Timestamp | EventID | Source | Action |",
                "|-----------|---------|--------|--------|",
            ]
            for e in events[:20]:
                ev   = e.get("event", {})
                code = ev.get("code", "")
                src  = e.get("log", {}).get("name", "")
                act  = ev.get("action", "")
                ts_e = (e.get("@timestamp") or "")[:19]
                lines.append(f"| {ts_e} | {code} | {src} | {act} |")
            if len(events) > 20:
                lines.append(f"| … | … | … | *{len(events) - 20} more not shown* |")
            lines.append("")

        validation = run.get("validation")
        if validation:
            lines += [
                "## Detection Validation",
                "",
                f"**Result:** {fired_str.get(validation.get('detection_fired'), 'N/A')}  ",
                f"**Matched Events:** {validation.get('match_count', 0)}  ",
                f"**Source:** {validation.get('source', '')}  ",
                "",
                "**Gap Analysis:**",
                "",
                validation.get("gap_analysis", ""),
                "",
            ]

        lines += [
            "---",
            "",
            "*Generated by AtomicLoop v1.0.0 — Rootless-Ghost / Nebula Forge Suite*",
        ]
        return "\n".join(lines)
