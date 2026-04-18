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
import json
import logging
import os

import yaml
from flask import Flask, jsonify, render_template, request, send_file

from core.engine import AtomicEngine

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
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
_API_KEY: str          = os.environ.get("ATOMICLOOP_API_KEY", "")


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = AtomicEngine(_config)
    if not _API_KEY:
        logger.warning(
            "ATOMICLOOP_API_KEY is not set — /execute is unauthenticated. "
            "Set this env var to require an API key on that route."
        )
    return app


def _check_api_key() -> bool:
    """Return True if no API key is configured, or the request header matches."""
    if not _API_KEY:
        return True
    return request.headers.get("X-API-Key", "") == _API_KEY


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/run/<run_id>")
def run_page(run_id: str):
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
    body = request.get_json(silent=True) or {}

    technique_id    = str(body.get("technique_id", "")).strip().upper()
    test_number     = int(body.get("test_number", 1))
    confirm         = bool(body.get("confirm", False))
    dry_run         = bool(body.get("dry_run", False))
    capture_events  = bool(body.get("capture_events", True))
    normalize       = bool(body.get("normalize", True))
    input_arguments = body.get("input_arguments") or {}
    timeout_raw     = body.get("timeout")
    timeout         = int(timeout_raw) if timeout_raw is not None else None

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

    from core.executor import execute
    from core.remote_executor import execute_remote_winrm

    body = request.get_json(silent=True) or {}

    command       = str(body.get("command", "")).strip()
    executor_type = str(body.get("executor_type", "powershell")).strip().lower()
    target_host   = str(body.get("target_host", "")).strip()
    transport     = str(body.get("transport", "")).strip().lower()
    credential    = body.get("credential") or None
    timeout_raw   = body.get("timeout")
    timeout       = int(timeout_raw) if timeout_raw is not None else 30
    dry_run       = bool(body.get("dry_run", False))

    if not command:
        return jsonify({"success": False, "error": "command is required"}), 400

    if transport == "winrm":
        if not target_host:
            return jsonify({
                "success": False,
                "error": "target_host is required when transport is 'winrm'",
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
def api_results():
    page         = max(1, int(request.args.get("page", 1)))
    per_page     = max(1, min(200, int(request.args.get("per_page", 50))))
    search       = request.args.get("search", "")
    technique_id = request.args.get("technique_id", "")
    result       = _engine.get_results(
        page=page, per_page=per_page, search=search, technique_id=technique_id
    )
    return jsonify({"success": True, **result})


# ── API: single result ────────────────────────────────────────────────────────

@app.route("/api/result/<run_id>")
def api_result(run_id: str):
    run = _engine.get_result(run_id)
    if run is None:
        return jsonify({"success": False, "error": "Run not found"}), 404
    return jsonify({"success": True, "run": run})


@app.route("/api/result/<run_id>", methods=["DELETE"])
def api_result_delete(run_id: str):
    deleted = _engine.delete_result(run_id)
    if not deleted:
        return jsonify({"success": False, "error": "Run not found"}), 404
    return jsonify({"success": True, "deleted": run_id})


# ── API: export run ───────────────────────────────────────────────────────────

@app.route("/api/result/<run_id>/export")
def api_export(run_id: str):
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
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5011))
    logger.info("AtomicLoop starting on http://0.0.0.0:%d", port)
    app.run(debug=args.debug, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
