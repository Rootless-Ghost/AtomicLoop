<div align="center">

# AtomicLoop — Atomic Red Team Test Runner and Detection Validator

Part of the **Nebula Forge** security tools suite.

AtomicLoop closes the **purple team validation loop**: simulate an attack technique, capture endpoint events, and immediately validate whether your Sigma/Wazuh rules fire. No need for the full Atomic Red Team framework.

![version](https://img.shields.io/badge/version-v1.0.0-blueviolet?style=flat-square) ![port](https://img.shields.io/badge/port-5011-5d5d5d?style=flat-square) ![python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python) ![framework](https://img.shields.io/badge/framework-Flask-000000?style=flat-square&logo=flask) ![MITRE%20ATT%26CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-e63946?style=flat-square) ![part%20of](https://img.shields.io/badge/part%20of-Nebula%20Forge-7c3aed?style=flat-square) ![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

```
Write Sigma rule → Simulate attack (AtomicLoop) → Capture events (LogNorm)
      → Validate detection (DriftWatch) → Fix gap → Repeat
```

---

## Pipeline Position

![Nebula Forge pipeline — AtomicLoop highlighted](docs/Pipeline.svg)

> **purple-loop:** `AtomicLoop → LogNorm → ClusterIQ → HuntForge → DriftWatch → repeat`

---

## Screenshots

### Dashboard

![Technique Browser](docs/AtomicLoop-Dashboard.png)


---

## Core Features

- **20 embedded MITRE ATT&CK techniques** — curated tests for T1059.001 through T1190, no internet or framework required
- **Safety controls** — dry_run preview + explicit `confirm` flag prevents accidental execution
- **Local execution** — PowerShell, cmd, and bash executors with configurable timeout
- **WinRM remote execution** — run atomic tests on remote Windows hosts via PS Remoting (T1021.006); optional credential support
- **Event capture** — reads Windows Security + Sysmon event logs during the test window
- **LogNorm integration** — normalizes captured events to ECS-lite format (port 5006)
- **DriftWatch integration** — validates Sigma rules against captured events (port 5008)
- **Gap analysis** — explains exactly why a detection fired or missed
- **Persistent history** — SQLite (default, zero-config) or PostgreSQL run library with search, export, and delete
- **CLI** — offline operation without the web UI

---

## Quick Start

```bash
cd AtomicLoop
pip install -r requirements.txt
cp config.example.yaml config.yaml   # optional
python app.py
```

Open [http://127.0.0.1:5011](http://127.0.0.1:5011)

---

## Docker (Nebula Forge suite)

This tool runs as a containerized service in the Nebula Forge suite.
The recommended way to start everything together:

```bash
# From the Nebula-Forge repo root
cp .env.example .env          # add secrets (NVD_API_KEY, ATOMICLOOP_API_KEY, POSTGRES_PASSWORD — all required)
docker compose up -d          # starts all services including atomicloop
```

**Access:** http://localhost:5011

**Standalone container:**
```bash
docker build -t atomicloop .
docker run -p 5011:5011 \
  -e DATABASE_URL=postgresql://nebula:changeme@localhost:5432/nebula_forge \
  -e ATOMICLOOP_API_KEY=your-key-here \
  atomicloop
```

---

## Usage

### Web UI

1. Browse techniques in the left panel (grouped by tactic).
2. Click a technique to expand its test list.
3. Select a test to see command preview, expected artifacts, and input arguments.
4. Toggle **Dry Run** to preview the command without executing.
5. When ready: disable Dry Run, check the **confirm checkbox**, set timeout.
6. Click **Execute Test** — results appear in the right panel.
7. Paste a Sigma rule in the **Detection Validation** panel and click **Validate Detection**.

### CLI

```bash
# List all techniques
python cli.py --list

# Show tests for a technique
python cli.py --technique T1059.001

# Dry run (preview command only)
python cli.py --technique T1059.001 --test 1 --dry-run

# Execute with confirmation
python cli.py --technique T1059.001 --test 1 --confirm

# Execute and validate against a Sigma rule
python cli.py --technique T1059.001 --test 1 --confirm --validate --sigma rule.yml

# Custom input arguments
python cli.py --technique T1059.001 --test 2 --confirm --arg target_url=http://127.0.0.1:8080

# Save output to file
python cli.py --technique T1059.001 --test 1 --confirm --output result.md

# List saved runs
python cli.py --results
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/health`                     | Health check |
| GET    | `/api/atomics`                    | List all techniques |
| GET    | `/api/atomics/<technique_id>`     | Get tests for a technique |
| POST   | `/api/run`                        | Execute an atomic test (engine path) — API key required. |
| POST   | `/api/validate`                   | Validate Sigma rule against events |
| GET    | `/api/results`                    | List past runs (paginated) |
| GET    | `/api/result/<run_id>`            | Get a single run |
| DELETE | `/api/result/<run_id>`            | Delete a run |
| GET    | `/api/result/<run_id>/export`     | Export run (JSON or Markdown) |
| POST   | `/execute`                        | Direct command execution — local or WinRM remote (API key protected) |

### POST /api/run

```json
{
  "technique_id":    "T1059.001",
  "test_number":     1,
  "confirm":         true,
  "dry_run":         false,
  "capture_events":  true,
  "normalize":       true,
  "timeout":         30,
  "input_arguments": {"target_url": "http://127.0.0.1:8080"}
}
```

**Response:**
```json
{
  "success":       true,
  "run_id":        "uuid",
  "technique_id":  "T1059.001",
  "test_name":     "PowerShell Encoded Command Execution",
  "executed_at":   "2025-01-01T12:00:00Z",
  "exit_code":     0,
  "duration_ms":   1240,
  "event_count":   12,
  "events":        [{...ECS-lite...}],
  "raw_output":    "AtomicTest T1059.001-1: Encoded execution"
}
```

### POST /execute

Executes an allowlisted atomic command directly — locally or on a remote Windows host via WinRM. Protected by `ATOMICLOOP_API_KEY` — required at startup (see [Environment variables](#environment-variables)).

**Request headers (required):**
```
X-API-Key: <your-key>
Content-Type: application/json
```

**Request body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `command` | string | Yes | — | Atomic test command to execute. Must match a command in the embedded allowlist. |
| `executor_type` | string | No | `"powershell"` | Executor used for allowlist lookup and local dispatch: `powershell`, `cmd`, `bash`. |
| `target_host` | string | Conditional | — | Remote host (hostname or IPv4/IPv6). Required when `transport` is `"winrm"`. |
| `transport` | string | No | — | Set to `"winrm"` to execute on `target_host` via PS Remoting. Omit for local execution. |
| `credential` | object | No | — | `{"username": "DOMAIN\\user", "password": "secret"}`. Passed as `-Credential` to `New-PSSession`. Only used when `transport` is `"winrm"`. |
| `timeout` | integer | No | `30` | Seconds before the process or remote session is killed. |
| `dry_run` | boolean | No | `false` | If `true`, returns the command that would be run without executing it. |

**Local execution example:**
```json
{
  "command":       "Get-Process",
  "executor_type": "powershell",
  "timeout":       30,
  "dry_run":       false
}
```

**WinRM remote execution example:**
```json
{
  "command":       "Get-Process",
  "executor_type": "powershell",
  "target_host":   "192.168.1.50",
  "transport":     "winrm",
  "credential":    {"username": "CORP\\svctest", "password": "hunter2"},
  "timeout":       60,
  "dry_run":       false
}
```

**Dry-run example (no execution, no API key required logic applies normally):**
```json
{
  "command":     "Get-Process",
  "target_host": "192.168.1.50",
  "transport":   "winrm",
  "dry_run":     true
}
```

**Response:**
```json
{
  "success":     true,
  "exit_code":   0,
  "stdout":      "...",
  "stderr":      "",
  "duration_ms": 1340,
  "timed_out":   false,
  "dry_run":     false,
  "command":     "Get-Process",
  "error":       null
}
```

**Error responses:**

| Status | Body | Cause |
|--------|------|-------|
| `400` | `{"success": false, "error": "command is required"}` | Empty or missing `command` field |
| `400` | `{"success": false, "error": "target_host is required when transport is 'winrm'"}` | `transport=winrm` with no `target_host` |
| `200` | `{"success": false, "error": "Command is not in the embedded atomic allowlist."}` | Command does not match any embedded atomic test |
| `200` | `{"success": false, "error": "Invalid target_host: ..."}` | `target_host` contains characters outside hostname/IP character set |
| `401` | `{"error": "unauthorized"}` | `X-API-Key` header missing or incorrect |

### POST /api/validate

```json
{
  "run_id":     "uuid",
  "sigma_rule": "title: Detect PowerShell Encoded Command\ndetection:\n  ..."
}
```

**Response:**
```json
{
  "success":         true,
  "detection_fired": true,
  "matched_events":  [{...}],
  "match_count":     3,
  "gap_analysis":    "Validated via DriftWatch. Detection FIRED: Sigma rule matched 3 of 12 captured events.",
  "source":          "driftwatch"
}
```

---

## Embedded Technique Library

| Technique | Name | Tactic |
|-----------|------|--------|
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1055     | Process Injection | Defense Evasion |
| T1003     | OS Credential Dumping | Credential Access |
| T1082     | System Information Discovery | Discovery |
| T1083     | File and Directory Discovery | Discovery |
| T1057     | Process Discovery | Discovery |
| T1069     | Permission Groups Discovery | Discovery |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1547.001 | Registry Run Keys | Persistence |
| T1053.005 | Scheduled Task | Persistence |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1112     | Modify Registry | Defense Evasion |
| T1027     | Obfuscated Files | Defense Evasion |
| T1562.001 | Impair Defenses | Defense Evasion |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1078     | Valid Accounts | Defense Evasion |
| T1110.001 | Password Guessing | Credential Access |
| T1190     | Exploit Public-Facing Application | Initial Access |

---

## WinRM Prerequisites

The `/execute` route with `transport=winrm` uses PowerShell Remoting (`New-PSSession` / `Invoke-Command`). The following must be true on the **target host** before remote execution will succeed.

### Target host (Windows)

```powershell
# Enable PS Remoting (run as Administrator)
Enable-PSRemoting -Force

# Confirm WinRM is listening
winrm enumerate winrm/config/listener

# If the source host is not domain-joined, add it to TrustedHosts on the source
# (run on the AtomicLoop host, not the target)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.50" -Force
```

### Network

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5985 | HTTP | Source → Target | WinRM (unencrypted, lab use) |
| 5986 | HTTPS | Source → Target | WinRM over TLS (recommended for non-lab) |

### Credentials

Pass credentials via the `credential` field in the request body. The account must have permission to create PS sessions on the target (local Administrator or a delegated WinRM user).

> **Note:** Credentials are transmitted in the JSON request body and embedded in a PowerShell `-Command` string. Use HTTPS between your client and the AtomicLoop server, and rotate test credentials after exercises.

### AtomicLoop host

PowerShell (Windows: `powershell.exe`) or PowerShell Core (Linux/macOS: `pwsh`) must be installed and on `PATH`. The executor is selected automatically based on the OS AtomicLoop is running on.

---

## Configuration

### config.yaml

| Key | Default | Description |
|-----|---------|-------------|
| `port` | `5011` | HTTP port |
| `db_path` | `./atomicloop.db` | SQLite file path (used when `DATABASE_URL` is not set) |
| `execution.timeout` | `30` | Default execution timeout (seconds) |
| `execution.require_confirm` | `true` | Require explicit confirm flag |
| `execution.auto_save` | `true` | Persist every run automatically |
| `integrations.lognorm_url` | `http://127.0.0.1:5006` | LogNorm endpoint |
| `integrations.driftwatch_url` | `http://127.0.0.1:5008` | DriftWatch endpoint |

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ATOMICLOOP_API_KEY` | Yes | Required. Shared secret for the `X-API-Key` header on `POST /execute` and `POST /api/run`. The app will not start if this variable is unset. Set it in your `.env` file for Docker or as an environment variable for standalone runs. |
| `DATABASE_URL` | No | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/db`). When unset, AtomicLoop uses the SQLite file specified by `db_path` in `config.yaml`. |

```bash
# Example — set before starting the server
export ATOMICLOOP_API_KEY="change-me-before-exposing-to-a-network"
python app.py
```

When the key is configured, every `POST /execute` call must include the header:

```
X-API-Key: <your-key>
```

Requests with a missing or incorrect header receive `401 {"error": "unauthorized"}`.

> **Key rotation:** `ATOMICLOOP_API_KEY` is read once at process startup (module import time). Changing the environment variable has no effect on a running server — the process must be restarted to pick up a new value.

---

## Safety Controls

AtomicLoop includes several controls to prevent accidental execution:

1. **`confirm: true`** — required in every `POST /api/run` body to execute. Without it, the request is rejected.
2. **`dry_run: true`** — shows the command without executing. Always safe. Supported on both `/api/run` and `/execute`.
3. **`require_confirm: true`** (config) — server-enforced gate on all live executions.
4. **Timeout** — hard kill after N seconds (default 30). Applied to both local processes and WinRM sessions.
5. **Atomic allowlist** — `/execute` only dispatches commands that appear verbatim in the embedded MITRE technique library. Arbitrary commands are rejected.
6. **`ATOMICLOOP_API_KEY`** — required to start the server. Both `/execute` and `/api/run` require a matching `X-API-Key` header. The app exits at startup if this variable is not set.
7. **API key setup** — set `ATOMICLOOP_API_KEY` in your `.env` file (Docker) or as a terminal environment variable (standalone). Generate a key with: `python -c "import secrets; print(secrets.token_hex(32))"`
8. **`cleanup_command`** — each test includes a cleanup command. Run it after testing.

---

## Nebula Forge Integration

Add to `nebula-dashboard/config.yaml`:

```yaml
tools:
  atomicloop:
    label:       "AtomicLoop"
    url:         "http://127.0.0.1:5011"
    health_path: "/api/health"
    description: "Atomic Red Team test runner and detection validator"
    category:    "Detection"
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.


<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

Part of the **Nebula Forge** security tools suite.

</div>
