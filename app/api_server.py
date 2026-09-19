"""
Local API server for the BlueLine UI.

Binds to 127.0.0.1 only (never 0.0.0.0) — this is a local desktop tool,
not a network service. Scans run in a background thread per scan_id so
the UI can poll progress without blocking. This IS the offline-first
core: no request here ever leaves the machine.
"""

from __future__ import annotations

import threading
import uuid

from flask import Flask, jsonify, request, send_from_directory

from app.core import paths
from app.core.logging_setup import log_structured
from app.core.models import ScanConfig
from app.core.orchestrator import CancellationToken, ScanOrchestrator
from app.persistence.store import ScanStore
from app.reporting.csv_report import generate_csv_report
from app.reporting.html_report import generate_html_report
from app.reporting.json_report import generate_json_report, generate_sarif_report
from app.targets.discovery import TargetDiscovery

UI_DIR = paths.ui_dir()

app = Flask(__name__, static_folder=str(UI_DIR / "static"))
_store = ScanStore(paths.default_db_path())
_orchestrator = ScanOrchestrator()

# In-memory live state for scans currently running (progress log + cancel tokens).
_live_scans: dict[str, dict] = {}
_lock = threading.Lock()


@app.route("/")
def index():
    return send_from_directory(str(UI_DIR), "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory(str(UI_DIR / "static"), path)


@app.route("/api/target/discover", methods=["POST"])
def discover_target():
    data = request.get_json(force=True)
    target_path = data.get("target_path", "")
    discovery = TargetDiscovery()
    profile = discovery.discover(target_path)
    return jsonify(profile.as_dict())


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json(force=True)
    target_path = data.get("target_path")
    profile_name = data.get("profile", "standard")
    if not target_path:
        return jsonify({"error": "target_path is required"}), 400

    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    config = ScanConfig.for_profile(profile_name)
    token = CancellationToken()
    log_structured("app", "Scan requested via API", scan_id=scan_id, target=target_path, profile=profile_name)

    with _lock:
        _live_scans[scan_id] = {"log": [], "status": "running", "token": token, "result": None}

    def progress_cb(stage, status, detail):
        with _lock:
            _live_scans[scan_id]["log"].append({"stage": stage, "status": status, "detail": detail})

    def worker():
        result = _orchestrator.run_scan(scan_id, target_path, config, progress=progress_cb, cancel_token=token)
        _store.save(result)
        with _lock:
            _live_scans[scan_id]["status"] = result.status
            _live_scans[scan_id]["result"] = result.as_dict()

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id):
    with _lock:
        live = _live_scans.get(scan_id)
    if live is None:
        stored = _store.load(scan_id)
        if not stored:
            return jsonify({"error": "unknown scan_id"}), 404
        return jsonify({"status": stored["status"], "log": [], "result": stored})
    return jsonify({"status": live["status"], "log": live["log"], "result": live["result"]})


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    with _lock:
        live = _live_scans.get(scan_id)
        if live is None:
            return jsonify({"error": "unknown or already-finished scan_id"}), 404
        live["token"].cancel()
    return jsonify({"status": "cancel_requested"})


@app.route("/api/scan/<scan_id>/findings", methods=["GET"])
def scan_findings(scan_id):
    data = _store.load(scan_id)
    if not data:
        with _lock:
            live = _live_scans.get(scan_id)
        if live and live["result"]:
            data = live["result"]
        else:
            return jsonify({"error": "unknown scan_id"}), 404
    return jsonify(data["findings"])


@app.route("/api/scan/<scan_id>/report", methods=["GET"])
def scan_report(scan_id):
    fmt = request.args.get("format", "html")
    from app.cli import _scan_result_from_dict
    data = _store.load(scan_id)
    if not data:
        return jsonify({"error": "unknown scan_id"}), 404
    result = _scan_result_from_dict(data)

    if fmt == "pdf":
        from app.reporting.pdf_report import PdfGenerationError, generate_pdf_report
        try:
            pdf_bytes = generate_pdf_report(result)
        except PdfGenerationError as e:
            return jsonify({"error": str(e)}), 501
        return app.response_class(pdf_bytes, mimetype="application/pdf")

    generators = {
        "html": (generate_html_report, "text/html"),
        "json": (generate_json_report, "application/json"),
        "sarif": (generate_sarif_report, "application/json"),
        "csv": (generate_csv_report, "text/csv"),
    }
    gen, mimetype = generators.get(fmt, generators["html"])
    return app.response_class(gen(result), mimetype=mimetype)


@app.route("/api/history", methods=["GET", "DELETE"])
def history():
    target = request.args.get("target")
    if request.method == "DELETE":
        count = _store.delete_all(target_path=target)
        with _lock:
            if target is None:
                _live_scans.clear()
        return jsonify({"deleted_count": count})
    return jsonify(_store.list_history(target_path=target))


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    deleted = _store.delete(scan_id)
    with _lock:
        _live_scans.pop(scan_id, None)
    if not deleted:
        return jsonify({"error": "unknown scan_id"}), 404
    return jsonify({"deleted": True, "scan_id": scan_id})


@app.route("/api/compare", methods=["GET"])
def compare():
    a, b = request.args.get("a"), request.args.get("b")
    if not a or not b:
        return jsonify({"error": "a and b scan IDs are required"}), 400
    try:
        return jsonify(_store.compare(a, b))
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


def main():
    log_structured("app", "BlueLine API server starting", host="127.0.0.1", port=8642)
    app.run(host="127.0.0.1", port=8642, debug=False, threaded=True)


if __name__ == "__main__":
    main()
