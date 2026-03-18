#!/usr/bin/env python3
"""
ARGUS Web — Flask server for the ARGUS web interface.

Serves a single-page UI that replaces the CLI wizard with:
  - Afficher:  load pre-generated JSON files and display cartography
  - Importer:  upload nmap XML + BloodHound data, generate graphs server-side
  - Scanner:   launch scans (direct/pivot) with live log streaming

Usage:
    python3 argus_server.py                 # http://localhost:5000
    python3 argus_server.py --port 8080     # custom port
    sudo python3 argus_server.py            # required for scan mode (nmap needs root)
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path

from flask import Flask, request, jsonify, send_file, Response

SCRIPT_DIR = Path(__file__).parent.resolve()
RESULTS_DIR = SCRIPT_DIR / "results"

app = Flask(__name__)

# ── Job tracking ─────────────────────────────────────────────────────────────

jobs = {}  # job_id -> {process, output_dir, status, logs[], cmd}
jobs_lock = threading.Lock()


def _python():
    venv = SCRIPT_DIR / ".env" / "bin" / "python3"
    return str(venv) if venv.exists() else sys.executable


def _new_job(cmd, output_dir):
    """Start a subprocess job and track it."""
    job_id = uuid.uuid4().hex[:8]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with jobs_lock:
        jobs[job_id] = {
            "status": "running",
            "output_dir": str(output_dir),
            "logs": [],
            "cmd": cmd,
            "process": None,
        }

    t = threading.Thread(target=_run_job, args=(job_id, cmd, output_dir), daemon=True)
    t.start()
    return job_id


def _run_job(job_id, cmd, output_dir):
    """Execute subprocess, capture stdout/stderr line by line."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(SCRIPT_DIR),
        )
        with jobs_lock:
            jobs[job_id]["process"] = proc

        for line in proc.stdout:
            with jobs_lock:
                jobs[job_id]["logs"].append(line.rstrip("\n"))

        proc.wait()
        with jobs_lock:
            jobs[job_id]["status"] = "success" if proc.returncode == 0 else "failed"
    except Exception as e:
        with jobs_lock:
            jobs[job_id]["logs"].append(f"ERROR: {e}")
            jobs[job_id]["status"] = "failed"


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file(SCRIPT_DIR / "argus_web.html")


@app.route("/api/status/<job_id>")
def job_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify({"status": job["status"], "log_count": len(job["logs"])})


@app.route("/api/logs/<job_id>")
def stream_logs(job_id):
    """SSE endpoint — streams log lines in real-time."""
    def generate():
        sent = 0
        while True:
            with jobs_lock:
                job = jobs.get(job_id)
            if not job:
                yield f"data: {json.dumps({'type': 'error', 'text': 'unknown job'})}\n\n"
                return

            with jobs_lock:
                new_lines = job["logs"][sent:]
                status = job["status"]

            for line in new_lines:
                yield f"data: {json.dumps({'type': 'log', 'text': line})}\n\n"
                sent += 1

            if status != "running":
                yield f"data: {json.dumps({'type': 'done', 'status': status})}\n\n"
                return

            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/results/<job_id>")
def job_results(job_id):
    """Return generated JSON files after job completes."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404

    output_dir = Path(job["output_dir"])
    result = {}

    for name, filename in [
        ("network", "network_scan.json"),
        ("mapping", "hostname_mapping.json"),
        ("tier0", "graph_tier0.json"),
        ("tier1", "graph_tier1.json"),
        ("tier2", "graph_tier2.json"),
    ]:
        fpath = output_dir / filename
        if fpath.exists():
            try:
                result[name] = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception:
                pass

    return jsonify(result)


# ── Suggest start nodes with paths to Tier 0 ────────────────────────────────

@app.route("/api/suggest-starts", methods=["POST"])
def suggest_starts():
    """Analyze BH files and return objects with attack paths to Tier 0."""
    bh_files = request.files.getlist("bh_files")
    if not bh_files or not bh_files[0].filename:
        return jsonify({"error": "No BloodHound files"}), 400

    # Save BH files to a temp directory
    tmp = tempfile.mkdtemp(prefix="argus_suggest_")
    bh_dir = os.path.join(tmp, "bh")
    os.makedirs(bh_dir)
    for f in bh_files:
        fname = Path(f.filename).name
        if fname.endswith(".json"):
            f.save(os.path.join(bh_dir, fname))

    # Save certipy JSON if provided
    certipy_path = None
    certipy_file = request.files.get("certipy_json")
    if certipy_file and certipy_file.filename:
        certipy_path = os.path.join(tmp, "certipy.json")
        certipy_file.save(certipy_path)

    try:
        from argus_builder import find_tier0_objects
        results = find_tier0_objects(bh_dir, certipy_path)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


# ── Import endpoint ──────────────────────────────────────────────────────────

@app.route("/api/import", methods=["POST"])
def import_data():
    """Handle file uploads for import mode."""
    job_id = uuid.uuid4().hex[:8]
    save = request.form.get("save") == "true"
    custom_output = request.form.get("output_dir", "").strip() if save else ""
    if custom_output:
        output_dir = SCRIPT_DIR / custom_output
    elif save:
        output_dir = RESULTS_DIR / f"import_{job_id}"
    else:
        output_dir = RESULTS_DIR / f"_tmp_{job_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    uploads_dir = output_dir / "uploads"
    uploads_dir.mkdir(exist_ok=True)

    # Save nmap XML
    nmap_file = request.files.get("nmap_xml")
    nmap_path = None
    if nmap_file:
        nmap_path = uploads_dir / "scan.xml"
        nmap_file.save(str(nmap_path))

    # Save BloodHound files (directory upload sends multiple files)
    bh_dir = None
    bh_files = request.files.getlist("bh_files")
    if bh_files and bh_files[0].filename:
        bh_dir = uploads_dir / "bloodhound_data"
        bh_dir.mkdir(exist_ok=True)
        for f in bh_files:
            # webkitdirectory preserves relative paths — extract just the filename
            fname = Path(f.filename).name
            if fname.endswith(".json"):
                f.save(str(bh_dir / fname))

    # Save certipy JSON
    certipy_file = request.files.get("certipy_json")
    certipy_path = None
    if certipy_file and certipy_file.filename:
        certipy_path = uploads_dir / "certipy.json"
        certipy_file.save(str(certipy_path))

    # Form fields
    start = request.form.get("start", "").strip()
    dc_ip = request.form.get("dc_ip", "").strip()
    dns_tcp = request.form.get("dns_tcp") == "true"
    proxychains_conf = request.form.get("proxychains_conf", "").strip()
    import_type = request.form.get("import_type", "full")  # network, ad, full

    # Build command
    if import_type == "ad" and bh_dir:
        # AD only — use argus_graph.py
        cmd = [_python(), str(SCRIPT_DIR / "argus_graph.py"),
               "--data-dir", str(bh_dir), "--start", start,
               "--output-dir", str(output_dir)]
        if certipy_path:
            cmd += ["--certipy-json", str(certipy_path)]
    elif import_type == "network" and nmap_path:
        # Network only
        cmd = [_python(), str(SCRIPT_DIR / "argus_import.py"),
               "--nmap-xml", str(nmap_path), "--output-dir", str(output_dir)]
    else:
        # Full import
        cmd = [_python(), str(SCRIPT_DIR / "argus_import.py"),
               "--nmap-xml", str(nmap_path) if nmap_path else "",
               "--output-dir", str(output_dir)]
        if bh_dir:
            cmd += ["--bh-dir", str(bh_dir)]
        if start:
            cmd += ["--start", start]
        if certipy_path:
            cmd += ["--certipy-json", str(certipy_path)]
        if dc_ip:
            cmd += ["--dc-ip", dc_ip]
            if dns_tcp:
                cmd += ["--dns-tcp"]
            if proxychains_conf:
                cmd += ["--proxychains-conf", proxychains_conf]

    actual_job_id = _new_job(cmd, output_dir)
    return jsonify({"job_id": actual_job_id, "output_dir": str(output_dir)})


# ── Scan endpoint ────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan():
    """Handle scan mode — build command and run pipeline."""
    data = request.get_json() or {}
    mode = data.get("mode")  # direct or pivot
    submode = data.get("submode")
    save = data.get("save", False)
    custom_output = data.get("output_dir", "").strip() if save else ""
    scan_id = uuid.uuid4().hex[:8]
    if custom_output:
        output_dir = SCRIPT_DIR / custom_output
    elif save:
        output_dir = RESULTS_DIR / f"scan_{scan_id}"
    else:
        output_dir = RESULTS_DIR / f"_tmp_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    python = _python()
    pipeline = str(SCRIPT_DIR / "argus_pipeline.py")

    if mode == "direct":
        cmd = _build_direct_cmd(data, python, pipeline, str(output_dir))
    elif mode == "pivot":
        cmd = _build_pivot_cmd(data, python, pipeline, str(output_dir))
    else:
        return jsonify({"error": "invalid mode"}), 400

    job_id = _new_job(cmd, output_dir)
    return jsonify({"job_id": job_id, "output_dir": str(output_dir)})


def _build_direct_cmd(data, python, pipeline, output_dir):
    submode = data.get("submode", "full")
    dc_ip = data.get("dc_ip", "")
    domain = data.get("domain", "")
    user = data.get("user", "")
    start = data.get("start", "")
    ip_cidr = data.get("ip_cidr", "")
    gateway = data.get("gateway", "")
    dns = data.get("dns", "")
    port_scan = data.get("port_scan", False)

    # Auth
    auth_args = []
    if data.get("auth_type") == "hash":
        auth_args = ["-H", data.get("hash", "")]
    else:
        auth_args = ["--password", data.get("password", "")]

    if submode == "dc_only":
        cmd = ["sudo", python, pipeline,
               "--single-host",
               "--ip-cidr", dc_ip, "--gateway", dc_ip, "--dns", dc_ip,
               "--domain", domain, "--dc-ip", dc_ip,
               "--user", user, "--start", start] + auth_args
        if port_scan:
            cmd.append("--port-scan")
        cmd += ["--output-dir", output_dir]

    elif submode == "network":
        cmd = ["sudo", python, pipeline,
               "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
               "--domain", "x", "--dc-ip", "x", "--user", "x",
               "--password", "x", "--start", "x@x",
               "--skip-bloodhound", "--skip-certipy", "--skip-enrichment"]
        if port_scan:
            cmd.append("--port-scan")
        cmd += ["--output-dir", output_dir]

    elif submode == "ad_only":
        cmd = ["sudo", python, pipeline,
               "--skip-network",
               "--domain", domain, "--dc-ip", dc_ip,
               "--user", user, "--start", start] + auth_args
        cmd += ["--output-dir", output_dir]

    elif submode == "full_single":
        cmd = ["sudo", python, pipeline,
               "--single-host",
               "--ip-cidr", dc_ip, "--gateway", dc_ip, "--dns", dc_ip,
               "--domain", domain, "--dc-ip", dc_ip,
               "--user", user, "--start", start] + auth_args
        if port_scan:
            cmd.append("--port-scan")
        cmd += ["--output-dir", output_dir]

    elif submode == "full_network":
        cmd = ["sudo", python, pipeline,
               "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
               "--domain", domain, "--dc-ip", dc_ip,
               "--user", user, "--start", start] + auth_args
        if port_scan:
            cmd.append("--port-scan")
        cmd += ["--output-dir", output_dir]

    elif submode == "network_map":
        bh_dir = data.get("bh_dir", "")
        cmd = ["sudo", python, pipeline,
               "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
               "--domain", "x", "--dc-ip", "x", "--user", "x",
               "--password", "x", "--start", "x@x",
               "--skip-bloodhound", "--bh-dir", bh_dir,
               "--skip-certipy",
               "--output-dir", output_dir]
        if data.get("single_host"):
            cmd.append("--single-host")
        if port_scan:
            cmd.append("--port-scan")
    else:
        cmd = ["echo", "Unknown submode"]

    return cmd


def _build_pivot_cmd(data, python, pipeline, output_dir):
    submode = data.get("submode", "ad")
    proxychains_conf = data.get("proxychains_conf", "")
    domain = data.get("domain", "")
    dc_ip = data.get("dc_ip", "")
    dc_hostname = data.get("dc_hostname", "")
    user = data.get("user", "")
    start = data.get("start", "")
    targets = data.get("targets", "")

    auth_args = []
    if data.get("auth_type") == "hash":
        auth_args = ["-H", data.get("hash", "")]
    else:
        auth_args = ["--password", data.get("password", "")]

    if submode == "ad":
        cmd = ["proxychains4", "-f", proxychains_conf,
               python, pipeline,
               "--skip-network",
               "--domain", domain, "--dc-ip", dc_ip,
               "--user", user, "--start", start, "--dns-tcp"] + auth_args
        if dc_hostname:
            cmd += ["--dc-hostname", dc_hostname]
        cmd += ["--output-dir", output_dir]

    elif submode == "network":
        bh_dir = data.get("bh_dir", "")
        first_ip = targets.split(",")[0].strip() if targets else ""
        cmd = ["sudo", python, pipeline,
               "--ip-cidr", first_ip,
               "--domain", "x", "--dc-ip", "x", "--user", "x",
               "--password", "x", "--start", "x@x",
               "--proxychains-conf", proxychains_conf,
               "--targets", targets,
               "--skip-bloodhound", "--bh-dir", bh_dir,
               "--skip-certipy", "--skip-enrichment",
               "--output-dir", output_dir]
    else:
        cmd = ["echo", "Unknown submode"]

    return cmd


# ── Results / export endpoints ────────────────────────────────────────────────

@app.route("/api/files/<job_id>")
def list_result_files(job_id):
    """List generated JSON files for a job."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404

    output_dir = Path(job["output_dir"])
    if not output_dir.exists():
        return jsonify([])

    # Friendly labels
    labels = {
        "network_scan.json": "Scan reseau",
        "hostname_mapping.json": "Mapping hostname → IP",
        "graph_tier0.json": "Graphe Tier 0",
        "graph_tier1.json": "Graphe Tier 1",
        "graph_tier2.json": "Graphe Tier 2",
        "certipy_data.json": "Donnees Certipy (ADCS)",
    }
    files = []
    for f in sorted(output_dir.glob("*.json")):
        files.append({
            "filename": f.name,
            "label": labels.get(f.name, f.name),
            "size": f.stat().st_size,
        })
    return jsonify(files)


@app.route("/api/download/<job_id>/<filename>")
def download_file(job_id, filename):
    """Download a single result file."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404

    # Sanitize filename
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400

    fpath = Path(job["output_dir"]) / filename
    if not fpath.exists():
        return jsonify({"error": "not found"}), 404

    return send_file(fpath, as_attachment=True, download_name=filename)


@app.route("/api/export/<job_id>")
def export_zip(job_id):
    """ZIP all result files for a job."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404

    output_dir = Path(job["output_dir"])
    if not output_dir.exists():
        return jsonify({"error": "output directory not found"}), 404

    json_files = list(output_dir.glob("*.json"))
    if not json_files:
        return jsonify({"error": "no result files"}), 404

    zip_path = tempfile.NamedTemporaryFile(
        prefix=f"argus_{job_id}_", suffix=".zip", delete=False
    ).name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, f.name)

    return send_file(
        zip_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"argus_{job_id}.zip",
    )


# ── Demo files ───────────────────────────────────────────────────────────────

@app.route("/demo/list")
def list_demos():
    """List available demo datasets."""
    demo_dir = SCRIPT_DIR / "demo"
    if not demo_dir.exists():
        return jsonify([])
    demos = []
    for d in sorted(demo_dir.iterdir()):
        if d.is_dir() and not d.name.startswith("."):
            files = [f.name for f in d.iterdir() if f.suffix == ".json"]
            demos.append({"name": d.name, "files": files})
    return jsonify(demos)


@app.route("/demo/<name>/<filename>")
def serve_demo_file(name, filename):
    fpath = SCRIPT_DIR / "demo" / name / filename
    if not fpath.exists():
        return jsonify({"error": "not found"}), 404
    return send_file(fpath, mimetype="application/json")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARGUS Web Interface")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    is_root = os.geteuid() == 0

    print("=" * 60)
    print("  ARGUS — Web Interface")
    print("=" * 60)
    print(f"  URL:        http://{args.host}:{args.port}")
    print(f"  Root:       {'yes' if is_root else 'no (scan mode disabled)'}")
    print(f"  Script dir: {SCRIPT_DIR}")
    print("=" * 60)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
