"""
AtomicLoop — Test executor.

Runs atomic test commands on the local host with safety controls:
  - dry_run: show command without executing
  - confirm: must be True to actually execute (prevents accidents)
  - timeout: hard kill after N seconds (default 30)

Supports executors: powershell | cmd | bash | manual
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger("atomicloop.executor")

DEFAULT_TIMEOUT = 30

# Compiled once at import time — identifier restricted to [A-Za-z0-9_]+ to
# prevent polynomial backtracking on crafted placeholder strings (ReDoS).
_PLACEHOLDER_RE = re.compile(r"#\{([A-Za-z0-9_]+)\}")
_MAX_SUBST_LEN = 500


@dataclass
class ExecutionResult:
    """Result of a single test execution."""
    exit_code:   int | None = None
    stdout:      str        = ""
    stderr:      str        = ""
    duration_ms: int        = 0
    timed_out:   bool       = False
    dry_run:     bool       = False
    command:     str        = ""
    error:       str | None = None


def substitute_variables(command: str, input_args: dict, test_input_defs: dict) -> str:
    """Replace #{variable} placeholders with provided or default values."""
    result = command
    for arg_name, arg_def in test_input_defs.items():
        value = str(input_args.get(arg_name, arg_def.get("default", "")))
        if len(value) > _MAX_SUBST_LEN:
            raise ValueError(
                f"Substituted value for '{arg_name}' exceeds {_MAX_SUBST_LEN}-character limit"
            )
        result = result.replace(f"#{{{arg_name}}}", value)

    # Replace any remaining #{identifier} placeholders (safety net).
    # Pattern restricted to [A-Za-z0-9_]+ — avoids polynomial backtracking
    # on attacker-controlled input (ReDoS fix for CodeQL py/polynomial-redos).
    def _replace(m: re.Match) -> str:
        key = m.group(1)
        val = str(input_args.get(key, f"MISSING_{key}"))
        if len(val) > _MAX_SUBST_LEN:
            raise ValueError(
                f"Substituted value for '{key}' exceeds {_MAX_SUBST_LEN}-character limit"
            )
        return val

    result = _PLACEHOLDER_RE.sub(_replace, result)
    return result


def _escape_for_executor(value: object, executor_type: str) -> str:
    """Escape user-controlled values for the target shell/interpreter."""
    s = str(value)
    et = (executor_type or "").lower().strip()

    if et in {"bash", "sh"}:
        return shlex.quote(s)

    if et == "powershell":
        # PowerShell single-quoted string escaping: ' -> ''
        return "'" + s.replace("'", "''") + "'"

    if et == "cmd":
        # Conservative quoting for cmd.exe arguments.
        return '"' + s.replace('"', '""') + '"'

    # Fallback: safe POSIX-style quoting.
    return shlex.quote(s)


def substitute_variables_safe(
    command: str,
    input_args: dict,
    test_input_defs: dict,
    executor_type: str,
) -> str:
    """Replace #{variable} placeholders with safely escaped values for executor_type."""
    result = command
    for arg_name, arg_def in test_input_defs.items():
        value = str(input_args.get(arg_name, arg_def.get("default", "")))
        if len(value) > _MAX_SUBST_LEN:
            raise ValueError(
                f"Substituted value for '{arg_name}' exceeds {_MAX_SUBST_LEN}-character limit"
            )
        result = result.replace(f"#{{{arg_name}}}", _escape_for_executor(value, executor_type))

    # Replace any remaining #{identifier} placeholders with escaped value or marker.
    # Pattern restricted to [A-Za-z0-9_]+ — avoids polynomial backtracking
    # on attacker-controlled input (ReDoS fix for CodeQL py/polynomial-redos).
    def _replace_safe(m: re.Match) -> str:
        key = m.group(1)
        val = str(input_args.get(key, f"MISSING_{key}"))
        if len(val) > _MAX_SUBST_LEN:
            raise ValueError(
                f"Substituted value for '{key}' exceeds {_MAX_SUBST_LEN}-character limit"
            )
        return _escape_for_executor(val, executor_type)

    result = _PLACEHOLDER_RE.sub(_replace_safe, result)
    return result


def _is_allowed_atomic_command(command: str, executor_type: str) -> bool:
    """Return True if command exactly matches an embedded atomic test/cleanup command."""
    try:
        from .atomics import ATOMICS  # local import to avoid circular import at module load
    except Exception:
        return False

    et = (executor_type or "").lower().strip()
    for technique in ATOMICS.values():
        for test in technique.get("tests", []):
            if str(test.get("executor_type", "")).lower().strip() != et:
                continue
            test_cmd = test.get("command")
            cleanup_cmd = test.get("cleanup_command")
            if command == test_cmd or (cleanup_cmd is not None and command == cleanup_cmd):
                return True
    return False


def execute(
    command:       str,
    executor_type: str,
    timeout:       int  = DEFAULT_TIMEOUT,
    dry_run:       bool = False,
    env:           dict | None = None,
    working_dir:   str | None  = None,
) -> ExecutionResult:
    """
    Execute a command using the specified executor.

    Args:
        command:       The command string to run.
        executor_type: powershell | cmd | bash | manual
        timeout:       Seconds before the process is killed.
        dry_run:       If True, return the command without executing.
        env:           Extra environment variables to set.
        working_dir:   Working directory for the process.

    Returns:
        ExecutionResult with stdout/stderr/exit_code/duration.
    """
    executor_type = executor_type.lower().strip()

    if not _is_allowed_atomic_command(command, executor_type):
        logger.warning("Rejected non-allowlisted command for executor=%s", executor_type)
        return ExecutionResult(
            command=command,
            error="Command is not in the embedded atomic allowlist.",
        )

    if dry_run:
        logger.info("[DRY RUN] executor=%s command=%s", executor_type, command[:80])
        return ExecutionResult(
            dry_run=True,
            command=command,
            exit_code=None,
            stdout=f"[DRY RUN] Would execute:\n{command}",
        )

    if executor_type == "manual":
        logger.info("Manual executor — skipping execution")
        return ExecutionResult(
            dry_run=True,
            command=command,
            exit_code=None,
            stdout="[MANUAL] This test requires manual execution. See command for details.",
        )

    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    cmd_list = _build_command(command, executor_type)
    if cmd_list is None:
        return ExecutionResult(
            command=command,
            error=f"Unsupported executor type: {executor_type!r}",
        )

    logger.info("Executing: executor=%s timeout=%ds cmd=%s", executor_type, timeout, command[:80])
    start = time.monotonic()
    timed_out = False

    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=proc_env,
            cwd=working_dir,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        logger.info(
            "Execution complete: exit_code=%s duration=%dms stdout_len=%d",
            proc.returncode, duration_ms, len(stdout),
        )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=stdout[:8192],
            stderr=stderr[:4096],
            duration_ms=duration_ms,
            command=command,
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning("Execution timed out after %ds", timeout)
        return ExecutionResult(
            exit_code=-1,
            stdout="",
            stderr=f"Process killed: execution exceeded {timeout}s timeout.",
            duration_ms=duration_ms,
            timed_out=True,
            command=command,
        )

    except FileNotFoundError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error("Executor binary not found: %s", exc)
        return ExecutionResult(
            command=command,
            error=f"Executor not found: {exc}",
            duration_ms=duration_ms,
        )

    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error("Execution error: %s", exc)
        return ExecutionResult(
            command=command,
            error=str(exc),
            duration_ms=duration_ms,
        )


def execute_cleanup(
    cleanup_command: str | None,
    executor_type:   str,
    timeout:         int = DEFAULT_TIMEOUT,
) -> ExecutionResult | None:
    """Run cleanup command after a test. Returns None if no cleanup."""
    if not cleanup_command:
        return None
    logger.info("Running cleanup command")
    return execute(cleanup_command, executor_type, timeout=timeout)


# ── Private helpers ───────────────────────────────────────────────────────────

def _build_command(command: str, executor_type: str) -> list[str] | None:
    """Build the subprocess command list for the given executor type."""
    system = platform.system().lower()

    if executor_type == "powershell":
        if system == "windows":
            return [
                "powershell.exe",
                "-NonInteractive",
                "-NoProfile",
                "-Command",
                command,
            ]
        # PowerShell Core on Linux/Mac
        return ["pwsh", "-NonInteractive", "-NoProfile", "-Command", command]

    if executor_type == "cmd":
        if system == "windows":
            return ["cmd.exe", "/c", command]
        # Fall back to sh on non-Windows
        return ["sh", "-c", command]

    if executor_type == "bash":
        return ["bash", "-c", command]

    if executor_type == "sh":
        return ["sh", "-c", command]

    return None


def is_executor_available(executor_type: str) -> bool:
    """Check whether the required executor binary is present."""
    system = platform.system().lower()
    executor_type = executor_type.lower()

    if executor_type in ("cmd",):
        return system == "windows"
    if executor_type == "powershell":
        for binary in ("powershell.exe", "pwsh"):
            try:
                subprocess.run([binary, "-Command", "exit 0"],
                               capture_output=True, timeout=5)
                return True
            except Exception:
                pass
        return False
    if executor_type in ("bash", "sh"):
        try:
            subprocess.run([executor_type, "-c", "exit 0"],
                           capture_output=True, timeout=5)
            return True
        except Exception:
            return False
    if executor_type == "manual":
        return True
    return False
