"""
AtomicLoop — Detection validator.

Validates whether a Sigma rule fires against captured ECS-lite events
by posting to DriftWatch /api/validate.

Falls back to a local event-ID-based heuristic when DriftWatch is
unavailable, so the tool is useful offline.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("atomicloop.validator")


def validate_detection(
    sigma_rule:          str,
    events:              list[dict],
    expected_event_ids:  list[int] | None  = None,
    expected_log_sources: list[str] | None = None,
    driftwatch_url:      str               = "http://127.0.0.1:5008",
    timeout:             int               = 10,
) -> dict:
    """
    Validate whether a Sigma rule fires against the captured events.

    Attempts DriftWatch /api/validate first; falls back to a local
    event-ID heuristic when DriftWatch is unreachable.

    Args:
        sigma_rule:           Sigma YAML rule string.
        events:               ECS-lite event list from event_collector.
        expected_event_ids:   Event IDs the test was expected to produce.
        expected_log_sources: Log channels the test was expected to touch.
        driftwatch_url:       DriftWatch base URL.
        timeout:              HTTP request timeout.

    Returns:
        {
          "detection_fired":  bool,
          "matched_events":   [...],
          "match_count":      int,
          "gap_analysis":     str,
          "source":           "driftwatch" | "local_heuristic",
          "error":            str | None,
        }
    """
    if not sigma_rule or not sigma_rule.strip():
        return _no_rule_result(events, expected_event_ids, expected_log_sources)

    # Try DriftWatch first
    dw_result = _driftwatch_validate(sigma_rule, events, driftwatch_url, timeout)
    if dw_result is not None:
        fired          = bool(dw_result.get("fired"))
        matched_events = dw_result.get("matched_events") or []
        match_count    = dw_result.get("match_count", len(matched_events))
        gap = _build_gap_narrative(
            fired=fired,
            match_count=match_count,
            total_events=len(events),
            expected_event_ids=expected_event_ids or [],
            captured_event_ids=_extract_event_ids(events),
            expected_log_sources=expected_log_sources or [],
            captured_log_sources=_extract_log_sources(events),
            source="driftwatch",
        )
        return {
            "detection_fired":  fired,
            "matched_events":   matched_events,
            "match_count":      match_count,
            "gap_analysis":     gap,
            "source":           "driftwatch",
            "error":            dw_result.get("parse_error"),
        }

    # Local heuristic fallback
    return _local_heuristic(
        events, expected_event_ids or [], expected_log_sources or []
    )


def validate_events_only(
    events:              list[dict],
    expected_event_ids:  list[int],
    expected_log_sources: list[str],
) -> dict:
    """
    Validate detection coverage using only event IDs (no Sigma rule needed).
    Used for gap analysis when no sigma_rule is provided.
    """
    return _local_heuristic(events, expected_event_ids, expected_log_sources)


# ── DriftWatch integration ────────────────────────────────────────────────────

def _driftwatch_validate(
    sigma_rule:     str,
    events:         list[dict],
    driftwatch_url: str,
    timeout:        int,
) -> dict | None:
    """POST to DriftWatch /api/validate. Returns parsed response or None."""
    try:
        payload = json.dumps({
            "rules_yaml":        sigma_rule,
            "events_json":       json.dumps(events),
            "time_window_hours": 1,
        }, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            f"{driftwatch_url.rstrip('/')}/api/validate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            if data.get("success"):
                return data
    except urllib.error.URLError as exc:
        logger.debug("DriftWatch unreachable (%s) — using local heuristic", exc)
    except Exception as exc:
        logger.warning("DriftWatch validation error: %s", exc)
    return None


# ── Local heuristic fallback ──────────────────────────────────────────────────

def _local_heuristic(
    events:              list[dict],
    expected_event_ids:  list[int],
    expected_log_sources: list[str],
) -> dict:
    """Event-ID-based detection estimate when DriftWatch is unavailable."""
    captured_eids  = _extract_event_ids(events)
    captured_srcs  = _extract_log_sources(events)

    matched = [
        e for e in events
        if int(e.get("event", {}).get("code", -1)) in expected_event_ids
    ] if expected_event_ids else []

    fired = len(matched) > 0 if expected_event_ids else (len(events) > 0)

    gap = _build_gap_narrative(
        fired=fired,
        match_count=len(matched),
        total_events=len(events),
        expected_event_ids=expected_event_ids,
        captured_event_ids=captured_eids,
        expected_log_sources=expected_log_sources,
        captured_log_sources=captured_srcs,
        source="local_heuristic",
    )

    return {
        "detection_fired":  fired,
        "matched_events":   matched[:20],
        "match_count":      len(matched),
        "gap_analysis":     gap,
        "source":           "local_heuristic",
        "error":            None,
    }


def _no_rule_result(
    events:              list[dict],
    expected_event_ids:  list[int] | None,
    expected_log_sources: list[str] | None,
) -> dict:
    """Result when no Sigma rule was provided — report artifact coverage only."""
    captured_eids = _extract_event_ids(events)
    captured_srcs = _extract_log_sources(events)

    exp_eids = expected_event_ids or []
    exp_srcs = expected_log_sources or []

    found_eids    = [e for e in exp_eids if e in captured_eids]
    missing_eids  = [e for e in exp_eids if e not in captured_eids]
    found_srcs    = [s for s in exp_srcs if any(s.lower() in c.lower() for c in captured_srcs)]
    missing_srcs  = [s for s in exp_srcs if not any(s.lower() in c.lower() for c in captured_srcs)]

    parts = ["No Sigma rule provided — reporting artifact coverage only."]
    if found_eids:
        parts.append(f"Captured expected Event IDs: {found_eids}.")
    if missing_eids:
        parts.append(f"Missing expected Event IDs: {missing_eids} — "
                     "verify audit policy and Sysmon are configured.")
    if found_srcs:
        parts.append(f"Events found in expected log sources: {found_srcs}.")
    if missing_srcs:
        parts.append(f"No events from expected log sources: {missing_srcs}.")
    if not events:
        parts.append("No events were captured. "
                     "Enable Process Auditing (EID 4688) and Sysmon for better coverage.")

    return {
        "detection_fired":  None,
        "matched_events":   [],
        "match_count":      0,
        "gap_analysis":     " ".join(parts),
        "source":           "no_rule",
        "error":            None,
    }


# ── Gap narrative builder ─────────────────────────────────────────────────────

def _build_gap_narrative(
    fired:               bool,
    match_count:         int,
    total_events:        int,
    expected_event_ids:  list[int],
    captured_event_ids:  set[int],
    expected_log_sources: list[str],
    captured_log_sources: set[str],
    source:              str,
) -> str:
    """Build a human-readable gap analysis narrative."""
    parts: list[str] = []

    if source == "driftwatch":
        parts.append("Validated via DriftWatch.")
    else:
        parts.append("DriftWatch unavailable — using event-ID heuristic.")

    if fired:
        parts.append(
            f"Detection FIRED: Sigma rule matched {match_count} of {total_events} captured events."
        )
    else:
        parts.append("Detection DID NOT fire.")
        if total_events == 0:
            parts.append(
                "No events were captured during the test window. "
                "Ensure Process Creation auditing (EID 4688) and Sysmon are enabled. "
                "Try re-running with a longer timeout."
            )
        elif match_count == 0 and expected_event_ids:
            missing_eids = [e for e in expected_event_ids if e not in captured_event_ids]
            if missing_eids:
                parts.append(
                    f"Expected Event IDs not captured: {missing_eids}. "
                    "Verify audit policy covers these event types."
                )
            else:
                parts.append(
                    "Expected Event IDs were captured but the Sigma rule did not match. "
                    "Check field mappings in the rule (ECS-lite dot-notation required). "
                    "Common mismatches: CommandLine vs process.command_line, "
                    "Image vs process.executable."
                )

    # Log source coverage
    if expected_log_sources:
        missing_srcs = [
            s for s in expected_log_sources
            if not any(s.lower() in c.lower() for c in captured_log_sources)
        ]
        if missing_srcs:
            parts.append(
                f"Events from {missing_srcs} were not captured. "
                "Install Sysmon and enable the relevant audit subcategories."
            )

    # EID coverage summary
    if expected_event_ids and captured_event_ids:
        found    = [e for e in expected_event_ids if e in captured_event_ids]
        missing  = [e for e in expected_event_ids if e not in captured_event_ids]
        if found:
            parts.append(f"Artifact coverage: found EIDs {found}.")
        if missing:
            parts.append(f"Missing EIDs: {missing}.")

    return " ".join(parts)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_event_ids(events: list[dict]) -> set[int]:
    result: set[int] = set()
    for e in events:
        code = e.get("event", {}).get("code", "")
        if str(code).isdigit():
            result.add(int(code))
    return result


def _extract_log_sources(events: list[dict]) -> set[str]:
    result: set[str] = set()
    for e in events:
        name = e.get("log", {}).get("name", "")
        if name:
            result.add(name)
    return result
