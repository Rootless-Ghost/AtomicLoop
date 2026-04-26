"""
AtomicLoop — WinRM Remote Executor.

Executes Atomic Red Team test commands on a remote Windows host via
PowerShell Remoting (WinRM) using New-PSSession / Invoke-Command /
Remove-PSSession.

MITRE ATT&CK: T1021.006 — Remote Services: Windows Remote Management

━━━ Regex / Allowlist Audit (executor.py) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Patterns found in executor.py
  1. _PLACEHOLDER_RE = re.compile(r"#\{([A-Za-z0-9_]+)\}")
     Where applied: substitute_variables() and substitute_variables_safe()
     only.  execute() does NOT call either helper — the pattern is NEVER
     matched against the command string inside execute() itself.

  2. _is_allowed_atomic_command(command, executor_type) — called at the
     top of execute() before dry_run / subprocess dispatch.
     Mechanism: exact string equality against every test.command and
     test.cleanup_command stored in the embedded ATOMICS dict.
     This is NOT a regex; it is a verbatim match.

Impact on the WinRM wrapper constructed here:
  A script of the form
      "$_s = New-PSSession -ComputerName '...'; Invoke-Command ...; Remove-PSSession $_s"
  will NEVER match any stored atomic command exactly.  Passing it to
  execute() would be rejected immediately with:
      "Command is not in the embedded atomic allowlist."

Mitigation applied in this module:
  • The *original* atomic command (the value the caller wants to run
    remotely) is pre-validated via _is_allowed_atomic_command() before
    the wrapper is built — preserving the allowlist security intent.
  • The WinRM wrapper is then dispatched via subprocess.run() directly,
    reproducing the same execution path execute() follows after allowlist
    clearance (_build_command → subprocess.run).
  • target_host is validated against a strict hostname/IPv4/IPv6 regex
    before interpolation into the PowerShell string to prevent injection
    through the -ComputerName parameter.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import subprocess
import time

from .executor import ExecutionResult, _is_allowed_atomic_command, _lookup_canonical_command  # noqa: PLC2701

logger = logging.getLogger("atomicloop.remote_executor")

# Validates ComputerName values to a strict set of characters:
#   hostname labels (RFC 1123), dotted-decimal IPv4, or bare IPv6.
# Rejects anything containing shell metacharacters.
_HOST_RE = re.compile(
    r"^(?:"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?))*"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|[0-9A-Fa-f:]{2,39}"
    r")$"
)


def execute_remote_winrm(
    command: str,
    executor_type: str,
    target_host: str,
    credential: dict | None = None,
    timeout: int = 30,
    dry_run: bool = False,
) -> ExecutionResult:
    """
    Execute a command on a remote Windows host via WinRM (PS Remoting).

    Builds a PowerShell script that opens a PSSession, runs the command
    inside an Invoke-Command ScriptBlock, then tears the session down.
    The original atomic command is validated against the embedded allowlist
    before the wrapper is constructed or dispatched.

    Args:
        command:       Atomic test command to run on the remote host.
        executor_type: Executor type used for allowlist validation
                       (e.g. "powershell").
        target_host:   Remote host — hostname or IP address.
        credential:    Optional dict with 'username' and 'password' keys.
                       When supplied, a PSCredential is created and passed
                       to New-PSSession via -Credential.
        timeout:       Seconds before the PowerShell process is killed.
        dry_run:       If True, return a description without executing.

    Returns:
        ExecutionResult populated with stdout / stderr / exit_code /
        duration_ms, or an error message if validation fails.
    """
    if dry_run:
        logger.info("[DRY RUN] WinRM target=%s command=%s", target_host, command[:80])
        return ExecutionResult(
            dry_run=True,
            command=command,
            exit_code=None,
            stdout=f"[DRY RUN] Would PSRemote to {target_host}:\n{command}",
        )

    # ── Input validation ──────────────────────────────────────────────────────

    if not target_host:
        return ExecutionResult(
            command=command,
            error="target_host is required for WinRM execution.",
        )

    if not _HOST_RE.match(target_host):
        logger.warning("WinRM rejected invalid target_host=%r", target_host)
        return ExecutionResult(
            command=command,
            error=(
                f"Invalid target_host: {target_host!r}. "
                "Must be a valid hostname or IP address."
            ),
        )

    # ── Allowlist check on the original atomic command ────────────────────────
    # See module docstring: we cannot pass the WinRM wrapper to execute()
    # because it won't match any allowlisted atomic command.  We validate the
    # caller's command here and then dispatch the wrapper ourselves.

    if not _is_allowed_atomic_command(command, executor_type):
        logger.warning(
            "WinRM rejected non-allowlisted command executor=%s target=%s",
            executor_type, target_host,
        )
        return ExecutionResult(
            command=command,
            error="Command is not in the embedded atomic allowlist.",
        )

    # ── Build PSSession wrapper ───────────────────────────────────────────────

    username_arg = ""
    password_arg = ""
    if credential:
        username_arg = str(credential.get("username", ""))
        password_arg = str(credential.get("password", ""))

    canonical = _lookup_canonical_command(command, executor_type)
    if canonical is None:
        logger.warning(
            "WinRM rejected command: GUID allowlist validation failed executor=%s target=%s",
            executor_type, target_host,
        )
        return ExecutionResult(
            command=command,
            error="Command GUID failed allowlist validation.",
        )

    ps_script = (
        "param([string]$ComputerName, [string]$Username, [string]$Password) "
        "if ($Username) { "
        "  $_cred = New-Object System.Management.Automation.PSCredential("
        "    $Username, (ConvertTo-SecureString $Password -AsPlainText -Force)"
        "  ); "
        "  $_s = New-PSSession -ComputerName $ComputerName -Credential $_cred; "
        "} else { "
        "  $_s = New-PSSession -ComputerName $ComputerName; "
        "} "
        f"Invoke-Command -Session $_s -ScriptBlock {{ {canonical} }}; "
        "Remove-PSSession -Session $_s"
    )

    # ── Dispatch ──────────────────────────────────────────────────────────────

    target_host = str(target_host or "").strip()
    normalized_host = ""
    try:
        # Canonicalize literal IPs (IPv4 / IPv6)
        normalized_host = str(ipaddress.ip_address(target_host))
    except ValueError:
        # Validate hostname labels (RFC 1123-style)
        if (
            not target_host
            or len(target_host) > 253
            or target_host.endswith(".")
            or not _HOST_RE.fullmatch(target_host)
        ):
            return ExecutionResult(
                command=command,
                error="Invalid target_host: must be a valid hostname, IPv4, or IPv6 literal.",
                duration_ms=0,
            )
        labels = target_host.split(".")
        label_ok = all(
            1 <= len(lbl) <= 63
            and lbl[0].isalnum()
            and lbl[-1].isalnum()
            and all(ch.isalnum() or ch == "-" for ch in lbl)
            for lbl in labels
        )
        if not label_ok:
            return ExecutionResult(
                command=command,
                error="Invalid target_host: must be a valid hostname, IPv4, or IPv6 literal.",
                duration_ms=0,
            )
        normalized_host = target_host

    target_host = normalized_host

    system = platform.system().lower()
    if system == "windows":
        cmd_list = [
            "powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script,
            "-ComputerName", target_host, "-Username", username_arg, "-Password", password_arg,
        ]
    else:
        cmd_list = [
            "pwsh", "-NonInteractive", "-NoProfile", "-Command", ps_script,
            "-ComputerName", target_host, "-Username", username_arg, "-Password", password_arg,
        ]

    logger.info(
        "WinRM remote exec: target=%s executor=%s timeout=%ds",
        target_host, executor_type, timeout,
    )
    start = time.monotonic()

    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "WinRM exec complete: exit_code=%s duration=%dms stdout_len=%d",
            proc.returncode, duration_ms, len(proc.stdout or ""),
        )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=(proc.stdout or "")[:8192],
            stderr=(proc.stderr or "")[:4096],
            duration_ms=duration_ms,
            command=command,
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning("WinRM exec timed out after %ds target=%s", timeout, target_host)
        return ExecutionResult(
            exit_code=-1,
            stdout="",
            stderr=f"Process killed: remote execution exceeded {timeout}s timeout.",
            duration_ms=duration_ms,
            timed_out=True,
            command=command,
        )

    except FileNotFoundError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error("PowerShell binary not found: %s", exc)
        return ExecutionResult(
            command=command,
            error=f"Executor not found: {exc}",
            duration_ms=duration_ms,
        )

    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error("WinRM execution error: %s", exc)
        return ExecutionResult(
            command=command,
            error=str(exc),
            duration_ms=duration_ms,
        )
