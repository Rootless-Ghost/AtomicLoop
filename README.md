# AtomicLoop — Atomic Red Team Test Runner and Detection Validator

Part of the **Nebula Forge** security tools suite.

AtomicLoop closes the **purple team validation loop**: simulate an attack technique, capture endpoint events, and immediately validate whether your Sigma/Wazuh rules fire. No need for the full Atomic Red Team framework.

```
Write Sigma rule → Simulate attack (AtomicLoop) → Capture events (LogNorm)
      → Validate detection (DriftWatch) → Fix gap → Repeat
```

---

## Core Features

- **20 embedded MITRE ATT&CK techniques** — curated tests for T1059.001 through T1190, no internet or framework required
- **Safety controls** — dry_run preview + explicit `confirm` flag prevents accidental execution
- **Windows-first execution** — PowerShell + cmd executors with configurable timeout
- **Event capture** — reads Windows Security + Sysmon event logs during the test window
- **LogNorm integration** — normalizes captured events to ECS-lite format (port 5006)
- **DriftWatch integration** — validates Sigma rules against captured events (port 5008)
- **Gap analysis** — explains exactly why a detection fired or missed
- **Persistent history** — SQLite session library with search, export, and delete
- **CLI** — offline operation without the web UI

---

## Quick Start

```bash
cd AtomicLoop
pip install -r requirements.txt
cp config.example.yaml config.yaml   # optional
python app.py
```

Open [http://127.0.0.1:5011](http://127.0.0.1:5011).

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
| POST   | `/api/run`                        | Execute a test |
| POST   | `/api/validate`                   | Validate Sigma rule against events |
| GET    | `/api/results`                    | List past runs (paginated) |
| GET    | `/api/result/<run_id>`            | Get a single run |
| DELETE | `/api/result/<run_id>`            | Delete a run |
| GET    | `/api/result/<run_id>/export`     | Export run (JSON or Markdown) |

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

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `port` | `5011` | HTTP port |
| `db_path` | `./atomicloop.db` | SQLite database |
| `execution.timeout` | `30` | Default execution timeout (seconds) |
| `execution.require_confirm` | `true` | Require explicit confirm flag |
| `execution.auto_save` | `true` | Persist every run automatically |
| `integrations.lognorm_url` | `http://127.0.0.1:5006` | LogNorm endpoint |
| `integrations.driftwatch_url` | `http://127.0.0.1:5008` | DriftWatch endpoint |

---

## Safety Controls

AtomicLoop includes several controls to prevent accidental execution:

1. **`confirm: true`** — required in every `POST /api/run` body to execute. Without it, the request is rejected.
2. **`dry_run: true`** — shows the command without executing. Always safe.
3. **`require_confirm: true`** (config) — server-enforced gate on all live executions.
4. **Timeout** — hard kill after N seconds (default 30).
5. **`cleanup_command`** — each test includes a cleanup command. Run it after testing.

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
