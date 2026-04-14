# Changelog

All notable changes to AtomicLoop are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.0.0-dev] — unreleased

### Added

- **WinRM remote execution** (`core/remote_executor.py`) — new
  `execute_remote_winrm()` function wraps an arbitrary allowlisted atomic
  command in a `New-PSSession` / `Invoke-Command` / `Remove-PSSession`
  PowerShell script and dispatches it to a remote Windows host.
  MITRE ATT&CK: T1021.006 — Remote Services: Windows Remote Management.

- **Credential support for WinRM** — optional `credential` dict
  (`username` / `password`) is converted to a `PSCredential` object and
  passed as `-Credential` to `New-PSSession`.

- **`target_host` injection prevention** — `_HOST_RE` regex restricts
  the `-ComputerName` value to RFC 1123 hostnames, dotted-decimal IPv4,
  and bare IPv6 notation; shell metacharacters are rejected before string
  interpolation.

- **`POST /execute` route** (`app.py`) — direct command execution
  endpoint that routes to local `execute()` or `execute_remote_winrm()`
  based on the `transport` field. Supports all fields: `command`,
  `executor_type`, `target_host`, `transport`, `credential`, `timeout`,
  `dry_run`.

- **API key authentication on `/execute`** — `ATOMICLOOP_API_KEY`
  environment variable. When set, all `POST /execute` requests must carry
  a matching `X-API-Key` header; missing or incorrect values return
  `401 {"error": "unauthorized"}`. Unset env var preserves backward
  compatibility (unauthenticated, local-testing mode). Startup warning
  logged when the variable is absent.

- **WinRM Prerequisites** section added to `README.md` — covers
  `Enable-PSRemoting`, `TrustedHosts`, port requirements (5985/5986),
  and credential handling notes.

- **`POST /execute` API reference** added to `README.md` — full field
  table, local and WinRM request examples, dry-run example, and all error
  response codes.

### Fixed

- **LogNorm Wazuh adapter** (`LogNorm/adapters/wazuh.py`) — added
  mapping `data.win.eventdata.commandLine` → `process.command_line`
  (ECS-lite field `process_cmdline`). Previously this field was silently
  dropped; Windows process-creation events (e.g. EventID 4688) now
  populate `process.command_line` correctly. The Linux audit path
  (`data.audit.command` / `execve.a0`) is retained as a fallback.

---

## [1.0.0] — initial release

### Added

- **20 embedded MITRE ATT&CK techniques** (T1059.001 – T1190) with
  curated test and cleanup commands; no internet or external framework
  required at runtime.

- **Local execution engine** (`core/executor.py`) — PowerShell, cmd,
  bash, and sh executors via `subprocess.run`. Includes:
  - Atomic allowlist check (`_is_allowed_atomic_command`) — exact-match
    guard against the embedded technique library.
  - Variable substitution with ReDoS-safe regex
    (`#\{[A-Za-z0-9_]+\}` pattern, `_MAX_SUBST_LEN` cap).
  - Shell-safe value escaping per executor type (`_escape_for_executor`).
  - `dry_run` mode, configurable timeout, and hard process kill on
    `TimeoutExpired`.

- **AtomicEngine** (`core/engine.py`) — orchestrates test lookup,
  execution, event capture, LogNorm normalization, and DriftWatch
  validation in a single `run_test()` call.

- **Event capture** — reads Windows Security and Sysmon event logs
  during the test window; events normalized to ECS-lite format.

- **Flask web application** (`app.py`) with routes:
  - `GET /api/health`
  - `GET /api/atomics`, `GET /api/atomics/<technique_id>`
  - `POST /api/run` — full engine path with confirm gate, dry-run,
    event capture, and Sigma validation.
  - `POST /api/validate` — validate a Sigma rule against stored events.
  - `GET /api/results`, `GET /api/result/<run_id>`,
    `DELETE /api/result/<run_id>`, `GET /api/result/<run_id>/export`

- **Web UI** — technique browser, execution panel, detection validation,
  and persistent run history.

- **CLI** (`cli.py`) — `--list`, `--technique`, `--test`, `--dry-run`,
  `--confirm`, `--validate`, `--sigma`, `--arg`, `--output`, `--results`.

- **SQLite result storage** (`core/storage.py`) — persistent run history
  with search and paginated listing.

- **LogNorm integration** — event normalization forwarded to port 5006.

- **DriftWatch integration** — Sigma rule validation forwarded to
  port 5008 with local fallback gap analysis.

- **Safety controls** — `confirm` flag, `dry_run`, server-side
  `require_confirm` config gate, per-execution timeout.

- **Configuration** — `config.yaml` with deep-merge defaults for port,
  database path, execution settings, and integration URLs.
