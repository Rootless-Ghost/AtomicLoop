"""
AtomicLoop — Windows Event Log collector.

Captures events from Security, Sysmon, and System channels that were
generated during a test execution window.

On Windows: uses PowerShell Get-WinEvent to query event logs.
On non-Windows or when WEL is unavailable: returns empty list.

Captured raw events are then mapped to ECS-lite format by _to_ecs_lite().
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
import tempfile
from datetime import datetime, timezone

logger = logging.getLogger("atomicloop.collector")

# Default log channels to collect from
DEFAULT_LOG_SOURCES = [
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]

# Max events per channel per collection
MAX_EVENTS_PER_CHANNEL = 100


# PowerShell script that queries WEL for events since a start time
_PS_COLLECT = r"""
param([string]$StartTime, [string]$LogNamesJson, [int]$MaxPerLog)
$start = [datetime]::Parse($StartTime).ToLocalTime()
$logs  = $LogNamesJson | ConvertFrom-Json
$all   = @()
foreach ($logName in $logs) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$start} `
                    -ErrorAction SilentlyContinue |
                Select-Object -First $MaxPerLog
        foreach ($e in $evts) {
            $msg = ''
            try { $msg = ($e.Message -replace '\r?\n',' ').Substring(0, [Math]::Min(512, $e.Message.Length)) } catch {}
            $all += [PSCustomObject]@{
                log_name      = $e.LogName
                event_id      = $e.Id
                time_created  = $e.TimeCreated.ToUniversalTime().ToString('o')
                provider_name = $e.ProviderName
                message       = $msg
                level         = $e.LevelDisplayName
                computer_name = $e.MachineName
                user_id       = if ($e.UserId) { $e.UserId.Value } else { '' }
            }
        }
    } catch {}
}
$all | ConvertTo-Json -Depth 2 -Compress
"""


def collect_events(
    start_time_iso: str,
    log_sources:    list[str] | None = None,
    max_per_channel: int = MAX_EVENTS_PER_CHANNEL,
    timeout:        int = 30,
) -> list[dict]:
    """
    Collect Windows Event Log events generated since start_time_iso.

    Args:
        start_time_iso:  ISO8601 timestamp marking the start of the collection window.
        log_sources:     Log channel names to query (defaults to DEFAULT_LOG_SOURCES).
        max_per_channel: Maximum events to retrieve per channel.
        timeout:         Seconds before the collection query is killed.

    Returns:
        List of ECS-lite event dicts. Empty on non-Windows or on error.
    """
    if platform.system().lower() != "windows":
        logger.debug("Event collection skipped: not running on Windows")
        return []

    if not log_sources:
        log_sources = DEFAULT_LOG_SOURCES
    else:
        allowed = set(DEFAULT_LOG_SOURCES)
        log_sources = [src for src in log_sources if src in allowed]
        if not log_sources:
            log_sources = DEFAULT_LOG_SOURCES

    raw_events = _query_wel(start_time_iso, log_sources, max_per_channel, timeout)
    ecs_events = [_to_ecs_lite(e) for e in raw_events]
    logger.info("Collected %d events from WEL (start=%s)", len(ecs_events), start_time_iso)
    return ecs_events


def _query_wel(
    start_time_iso:  str,
    log_sources:     list[str],
    max_per_channel: int,
    timeout:         int,
) -> list[dict]:
    """Run the PowerShell collection script and return parsed raw events."""
    try:
        log_names_json = json.dumps(log_sources)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False, encoding="utf-8") as ps_file:
            ps_file.write(_PS_COLLECT)
            script_path = ps_file.name

        ps_args = [
            "powershell.exe",
            "-NonInteractive",
            "-NoProfile",
            "-File",
            script_path,
            "-StartTime",
            start_time_iso,
            "-LogNamesJson",
            log_names_json,
            "-MaxPerLog",
            str(max_per_channel),
        ]
        try:
            proc = subprocess.run(
                ps_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        finally:
            try:
                import os
                os.unlink(script_path)
            except Exception:
                pass
        raw_output = (proc.stdout or "").strip()
        if not raw_output or raw_output in ("null", ""):
            return []

        parsed = json.loads(raw_output)
        if isinstance(parsed, dict):
            # Single-item result from ConvertTo-Json
            parsed = [parsed]
        if isinstance(parsed, list):
            return [e for e in parsed if isinstance(e, dict)]
        return []

    except subprocess.TimeoutExpired:
        logger.warning("WEL collection timed out after %ds", timeout)
        return []
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse WEL JSON output: %s", exc)
        return []
    except Exception as exc:
        logger.warning("WEL collection error: %s", exc)
        return []


def _to_ecs_lite(raw: dict) -> dict:
    """Map a raw WEL event dict to ECS-lite format."""
    event_id   = raw.get("event_id", "")
    log_name   = raw.get("log_name", "")
    provider   = raw.get("provider_name", "")
    ts         = raw.get("time_created", "")
    message    = raw.get("message", "")
    level      = (raw.get("level") or "").lower()
    computer   = raw.get("computer_name", "")

    # Determine severity from level
    severity_map = {
        "critical":    1,
        "error":       2,
        "warning":     3,
        "information": 4,
        "verbose":     5,
        "audit failure": 2,
        "audit success": 4,
    }
    severity = severity_map.get(level, 4)

    # Derive event.category from log_name
    category: list[str] = []
    if "security" in log_name.lower():
        category = ["authentication", "iam"]
    elif "sysmon" in log_name.lower():
        category = ["process", "network", "file", "registry"]
    elif "system" in log_name.lower():
        category = ["host"]
    elif "powershell" in log_name.lower():
        category = ["process"]

    ecs: dict = {
        "@timestamp": ts,
        "event": {
            "code":     str(event_id),
            "provider": provider,
            "severity": severity,
            "original": message[:512],
            "dataset":  _log_name_to_dataset(log_name),
            "module":   "windows",
            "category": category,
            "kind":     "event",
        },
        "log": {
            "level": level,
            "name":  log_name,
        },
        "host": {
            "name": computer,
        },
        "_source": "atomicloop_wel",
    }

    # Enrich well-known Event IDs
    _enrich_event_id(ecs, event_id, message)
    return ecs


def _log_name_to_dataset(log_name: str) -> str:
    ln = log_name.lower()
    if "sysmon" in ln:
        return "windows.sysmon"
    if "security" in ln:
        return "windows.security"
    if "system" in ln:
        return "windows.system"
    if "powershell" in ln:
        return "windows.powershell"
    return "windows.events"


def _enrich_event_id(ecs: dict, event_id: int | str, message: str) -> None:
    """Add process/network fields for well-known EventIDs."""
    eid = int(event_id) if str(event_id).isdigit() else 0
    msg = message.lower()

    if eid == 4688:
        # New process created
        ecs["event"]["action"] = "process_creation"
        ecs["event"]["type"]   = ["start"]
        # Best-effort extract from message
        for pattern, field_path in [
            (r"New Process Name:\s+(.+?)(?:\r|\n|$)", ("process", "executable")),
            (r"Process Command Line:\s+(.+?)(?:\r|\n|$)", ("process", "command_line")),
            (r"Creator Process Name:\s+(.+?)(?:\r|\n|$)", ("process", "parent", "executable")),
            (r"Account Name:\s+(.+?)(?:\r|\n|$)", ("user", "name")),
        ]:
            import re
            m = re.search(pattern, message, re.IGNORECASE)
            if m:
                _set_nested(ecs, field_path, m.group(1).strip())

    elif eid == 4625:
        ecs["event"]["action"]   = "logon_failed"
        ecs["event"]["type"]     = ["start"]
        ecs["event"]["outcome"]  = "failure"
        ecs["event"]["category"] = ["authentication"]

    elif eid == 4624:
        ecs["event"]["action"]   = "logon_success"
        ecs["event"]["type"]     = ["start"]
        ecs["event"]["outcome"]  = "success"
        ecs["event"]["category"] = ["authentication"]

    elif eid == 4698:
        ecs["event"]["action"] = "scheduled_task_created"
        ecs["event"]["type"]   = ["creation"]

    elif eid == 4657:
        ecs["event"]["action"] = "registry_value_set"
        ecs["event"]["type"]   = ["change"]

    elif eid == 1102:
        ecs["event"]["action"] = "event_log_cleared"
        ecs["event"]["type"]   = ["deletion"]

    elif eid == 5156:
        ecs["event"]["action"]   = "network_connection_allowed"
        ecs["event"]["category"] = ["network"]

    elif eid in (1, 3, 11, 12, 13) and "sysmon" in ecs.get("event", {}).get("dataset", ""):
        _enrich_sysmon(ecs, eid, message)


def _enrich_sysmon(ecs: dict, eid: int, message: str) -> None:
    """Enrich Sysmon-specific events."""
    if eid == 1:
        ecs["event"]["action"] = "process_creation"
        ecs["event"]["type"]   = ["start"]
    elif eid == 3:
        ecs["event"]["action"]   = "network_connection"
        ecs["event"]["category"] = ["network"]
    elif eid == 11:
        ecs["event"]["action"] = "file_created"
        ecs["event"]["type"]   = ["creation"]
    elif eid in (12, 13, 14):
        ecs["event"]["action"] = "registry_event"
        ecs["event"]["type"]   = ["change"]
    elif eid == 10:
        ecs["event"]["action"] = "process_accessed"
        ecs["event"]["type"]   = ["access"]


def _set_nested(obj: dict, path: tuple[str, ...], value: str) -> None:
    """Set a nested dict value given a path tuple."""
    for part in path[:-1]:
        obj = obj.setdefault(part, {})
    obj[path[-1]] = value


def normalize_via_lognorm(
    events:      list[dict],
    lognorm_url: str,
    timeout:     int = 10,
) -> list[dict]:
    """
    Attempt to enhance event normalization via the LogNorm API.

    Posts events formatted as NDJSON to LogNorm and returns enhanced
    ECS-lite events. Falls back to the input events on any error.

    Args:
        events:      ECS-lite events from collect_events() to enhance.
        lognorm_url: Base URL of the LogNorm service (e.g. http://127.0.0.1:5006).
        timeout:     Request timeout in seconds.

    Returns:
        Enhanced ECS-lite events, or original events if LogNorm unavailable.
    """
    import urllib.request
    import urllib.error

    if not events:
        return events

    try:
        # Format events as NDJSON for LogNorm batch endpoint
        ndjson = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
        boundary = "atomicloopboundary"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"events.ndjson\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{ndjson}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"source_type\"\r\n\r\n"
            f"wel\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        req = urllib.request.Request(
            f"{lognorm_url.rstrip('/')}/api/normalize/batch",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            if data.get("success") and data.get("events"):
                logger.info("LogNorm enhanced %d events", len(data["events"]))
                return data["events"]
    except Exception as exc:
        logger.debug("LogNorm normalization skipped: %s", exc)

    return events
