"""
AtomicLoop — Atomic Red Team Test Runner and Detection Validator

Part of the Nebula Forge security tools suite.

Usage:
    python app.py
    python app.py --config /path/to/config.yaml
    python app.py --port 5011
"""

import argparse
import io
import ipaddress
import json
import logging
import os
import re
import sys
import uuid

import yaml
from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from core.engine import AtomicEngine

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

_HOST_RE = re.compile(
    r"^(?:"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?))*"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|[0-9A-Fa-f:]{2,39}"
    r")$"
)


def _is_valid_target_host(value: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        if not _HOST_RE.match(candidate):
            return False
        labels = candidate.split(".")
        return all(
            1 <= len(label) <= 63
            and label[0] != "-"
            and label[-1] != "-"
            for label in labels
        )
logger = logging.getLogger("atomicloop")

# ── Config ────────────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
    "port":    5011,
    "db_path": "./atomicloop.db",
    "execution": {
        "timeout":         30,
        "require_confirm": True,
        "auto_save":       True,
        "max_events":      500,
    },
    "integrations": {
        "lognorm_url":    "http://127.0.0.1:5006",
        "huntforge_url":  "http://127.0.0.1:5007",
        "driftwatch_url": "http://127.0.0.1:5008",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ── App factory ───────────────────────────────────────────────────────────────

app      = Flask(__name__)
_config: dict          = {}
_engine: AtomicEngine  = None  # type: ignore

# Per-worker in-memory store — with 2 Gunicorn workers a client effectively
# gets 2× the stated limit. For cross-worker enforcement replace "memory://"
# with "redis://localhost:6379" and add redis to requirements.txt.
_limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response
_API_KEY: str          = os.environ.get("ATOMICLOOP_API_KEY", "")


@app.context_processor
def _inject_api_key():
    return {"api_key": _API_KEY}


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = AtomicEngine(_config)
    if not _API_KEY:
        logger.error(
            "ATOMICLOOP_API_KEY is not set — refusing to start. "
            "Set this env var to an API key before launching AtomicLoop."
        )
        sys.exit(1)
    return app


def _check_api_key() -> bool:
    """Return True only when the request header matches the configured API key."""
    if not _API_KEY:
        return False
    return request.headers.get("X-API-Key", "") == _API_KEY


def _is_valid_run_id(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/run/<run_id>")
def run_page(run_id: str):
    if not _is_valid_run_id(run_id):
        return render_template("index.html", error=f"Run {run_id!r} not found"), 404
    run = _engine.get_result(run_id)
    if run is None:
        return render_template("index.html", error=f"Run {run_id!r} not found"), 404
    return render_template("run.html", run=run)


@app.route("/results")
def results_page():
    return render_template("library.html")


# ── API: health ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "tool": "atomicloop", "version": "1.0.0"})


# ── API: atomics catalogue ────────────────────────────────────────────────────

@app.route("/api/atomics")
def api_atomics():
    """List all available techniques with test counts."""
    techniques = _engine.get_atomics()
    return jsonify({"success": True, "techniques": techniques, "count": len(techniques)})


@app.route("/api/atomics/<technique_id>")
def api_atomics_technique(technique_id: str):
    """Get all tests for a specific technique."""
    tech = _engine.get_atomics(technique_id)
    if tech is None:
        return jsonify({"success": False, "error": f"Technique {technique_id!r} not found"}), 404
    return jsonify({"success": True, **tech})


# ── API: run test ─────────────────────────────────────────────────────────────

@app.route("/api/run", methods=["POST"])
@_limiter.limit("10/minute")
def api_run():
    """
    Execute an atomic test.

    Body (JSON):
      {
        "technique_id":       "T1059.001",
        "test_number":        1,
        "confirm":            true,       # required to execute (safety control)
        "dry_run":            false,      # show command only
        "capture_events":     true,
        "normalize":          true,
        "timeout":            30,
        "input_arguments":    {"arg": "value"},
        "label":              "optional note"
      }

    Returns full run result including events and execution output.
    """
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}

    technique_id    = str(body.get("technique_id", "")).strip().upper()
    test_number     = int(body.get("test_number", 1))
    confirm         = bool(body.get("confirm", False))
    dry_run         = bool(body.get("dry_run", False))
    capture_events  = bool(body.get("capture_events", True))
    normalize       = bool(body.get("normalize", True))
    input_arguments = body.get("input_arguments") or {}
    timeout_raw     = body.get("timeout")
    try:
        timeout = max(1, min(int(timeout_raw), 300)) if timeout_raw is not None else None
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "timeout must be an integer between 1 and 300"}), 400

    if not technique_id:
        return jsonify({"success": False, "error": "technique_id is required"}), 400

    exec_cfg    = _config.get("execution", {})
    auto_save   = bool(exec_cfg.get("auto_save", True))

    try:
        result = _engine.run_test(
            technique_id=technique_id,
            test_number=test_number,
            confirm=confirm,
            dry_run=dry_run,
            capture_events=capture_events,
            normalize=normalize,
            timeout=timeout,
            input_arguments=input_arguments,
            save=auto_save,
        )
        status = 200 if result.get("success") else (
            403 if "confirmation" in result.get("error", "") else 400
        )
        return jsonify(result), status

    except Exception as exc:
        logger.error("Run error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": "An internal error has occurred."}), 500


# ── API: direct command execution ────────────────────────────────────────────

@app.route("/execute", methods=["POST"])
@_limiter.limit("10/minute")
def execute_route():
    """
    Execute a command locally or on a remote host.

    Body (JSON):
      {
        "command":       "Write-Output 'hello'",
        "executor_type": "powershell",
        "target_host":   "192.168.1.10",          # optional
        "transport":     "winrm",                  # optional; "winrm" => remote
        "credential":    {"username": "u", "password": "p"},  # optional
        "timeout":       30,
        "dry_run":       false
      }

    When transport == "winrm", target_host is required and the command is
    dispatched via New-PSSession / Invoke-Command / Remove-PSSession
    (MITRE T1021.006).  All other transport values use local execution.
    """
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401

    from core.executor import execute, _is_allowed_atomic_command
    from core.remote_executor import execute_remote_winrm

    body = request.get_json(silent=True) or {}

    # Resolve executable command from a server-side allowlist key, not raw user command text.
    command_catalog = {
        # command_id: command_literal
        # Populate with supported atomic commands exposed by this API.
    }
    command_id    = str(body.get("command_id", "")).strip()
    command       = command_catalog.get(command_id, "")
    executor_type = str(body.get("executor_type", "powershell")).strip().lower()
    target_host   = str(body.get("target_host", "")).strip()
    transport     = str(body.get("transport", "")).strip().lower()
    credential    = body.get("credential") or None
    timeout_raw   = body.get("timeout")
    try:
        timeout = max(1, min(int(timeout_raw), 300)) if timeout_raw is not None else 30
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "timeout must be an integer between 1 and 300"}), 400
    dry_run       = bool(body.get("dry_run", False))

    if not command_id:
        return jsonify({"success": False, "error": "command_id is required"}), 400

    if not command:
        return jsonify({"success": False, "error": "unknown command_id"}), 400

    if not _is_allowed_atomic_command(command, executor_type):
        return jsonify({
            "success": False,
            "error": "command is not in the embedded atomic allowlist for this executor",
        }), 400

    if transport == "winrm":
        if not target_host:
            return jsonify({
                "success": False,
                "error": "target_host is required when transport is 'winrm'",
            }), 400
        if not _is_valid_target_host(target_host):
            return jsonify({
                "success": False,
                "error": "Invalid target_host: must be a valid hostname, IPv4, or IPv6 literal.",
            }), 400
        result = execute_remote_winrm(
            command=command,
            executor_type=executor_type,
            target_host=target_host,
            credential=credential,
            timeout=timeout,
            dry_run=dry_run,
        )
    else:
        result = execute(
            command=command,
            executor_type=executor_type,
            timeout=timeout,
            dry_run=dry_run,
        )

    return jsonify({
        "success":     result.error is None,
        "exit_code":   result.exit_code,
        "stdout":      result.stdout,
        "stderr":      result.stderr,
        "duration_ms": result.duration_ms,
        "timed_out":   result.timed_out,
        "dry_run":     result.dry_run,
        "command":     result.command,
        "error":       result.error,
    })


# ── API: validate detection ───────────────────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
@_limiter.limit("30/minute")
def api_validate():
    """
    Validate a Sigma rule against events from a stored run.

    Body (JSON):
      {
        "run_id":     "uuid",           # optional — load events from run
        "sigma_rule": "title: ...\n...",
        "events":     [{ECS-lite}]      # optional — override run events
      }

    Returns:
      {
        "success": true,
        "detection_fired": true,
        "matched_events": [...],
        "gap_analysis": "narrative"
      }
    """
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}

    run_id     = body.get("run_id", "").strip() or None
    sigma_rule = body.get("sigma_rule", "").strip()
    events_raw = body.get("events")
    events     = events_raw if isinstance(events_raw, list) else None

    if not run_id and not events:
        return jsonify({
            "success": False,
            "error": "Provide run_id to load stored events, or pass events directly.",
        }), 400

    try:
        result = _engine.validate(
            run_id=run_id,
            sigma_rule=sigma_rule,
            events=events,
        )
        status = 200 if result.get("success") else 400
        return jsonify(result), status

    except Exception as exc:
        logger.error("Validate error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred."}), 500


# ── API: results list ─────────────────────────────────────────────────────────

@app.route("/api/results")
@_limiter.limit("60/minute")
def api_results():
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "page and per_page must be integers"}), 400
    search       = request.args.get("search", "")
    technique_id = request.args.get("technique_id", "")
    result       = _engine.get_results(
        page=page, per_page=per_page, search=search, technique_id=technique_id
    )
    return jsonify({"success": True, **result})


# ── API: single result ────────────────────────────────────────────────────────

@app.route("/api/result/<run_id>")
@_limiter.limit("60/minute")
def api_result(run_id: str):
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    if not _is_valid_run_id(run_id):
        return jsonify({"success": False, "error": "Invalid run_id format"}), 400
    run = _engine.get_result(run_id)
    if run is None:
        return jsonify({"success": False, "error": "Run not found"}), 404
    return jsonify({"success": True, "run": run})


@app.route("/api/result/<run_id>", methods=["DELETE"])
@_limiter.limit("20/minute")
def api_result_delete(run_id: str):
    if not _check_api_key():
        return jsonify({"error": "unauthorized"}), 401
    if not _is_valid_run_id(run_id):
        return jsonify({"success": False, "error": "Invalid run_id format"}), 400
    deleted = _engine.delete_result(run_id)
    if not deleted:
        return jsonify({"success": False, "error": "Run not found"}), 404
    return jsonify({"success": True, "deleted": run_id})


# ── API: export run ───────────────────────────────────────────────────────────

@app.route("/api/result/<run_id>/export")
@_limiter.limit("30/minute")
def api_export(run_id: str):
    if not _is_valid_run_id(run_id):
        return jsonify({"success": False, "error": "Invalid run_id format"}), 400
    fmt = request.args.get("format", "json").lower()
    run = _engine.get_result(run_id)
    if run is None:
        return jsonify({"success": False, "error": "Run not found"}), 404

    ts       = (run.get("executed_at") or "")[:10].replace("-", "")
    tid      = (run.get("technique_id") or "").replace(".", "_")
    filename = f"atomicloop_{tid}_{ts}"

    if fmt == "markdown":
        md_bytes = _engine.to_markdown(run).encode("utf-8")
        return send_file(
            io.BytesIO(md_bytes),
            mimetype="text/markdown",
            as_attachment=True,
            download_name=f"{filename}.md",
        )

    json_bytes = json.dumps(run, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{filename}.json",
    )


# ── CLI entry point ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AtomicLoop — Atomic Red Team Test Runner")
    p.add_argument("--config",    default="config.yaml")
    p.add_argument("--port",      type=int, default=None)
    p.add_argument("--host",      default="127.0.0.1",
                   help="Bind address (default 127.0.0.1). Use 0.0.0.0 for Docker/cross-VM.")
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5011))
    logger.info("AtomicLoop starting on http://%s:%d", args.host, port)
    app.run(debug=args.debug, host=args.host, port=port)


if __name__ == "__main__":
    main()
