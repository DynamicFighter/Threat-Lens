from flask import Flask, render_template, request, jsonify
import threading
import sys
import os
import sqlite3

# Add Port Scanner folder to Python path
scanner_folder = r"D:\Abdullah\TY Project\Port Scanner"

if scanner_folder not in sys.path:
    sys.path.insert(0, scanner_folder)

import Nmap_CVE

app = Flask(__name__)


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# SCAN PAGE
# --------------------------------------------------

@app.route("/scan")
def scan():
    return render_template("scan.html")

@app.route("/results")
def results():
    return render_template("results.html")

# --------------------------------------------------
# START SCAN
# --------------------------------------------------

@app.route("/api/start-scan", methods=["POST"])
def start_scan():

    data = request.get_json()

    target = data.get("target")
    start_port = data.get("start_port")
    end_port = data.get("end_port")

    # -----------------------------
    # VALIDATION
    # -----------------------------

    if not target:

        return jsonify({
            "success": False,
            "error": "Target is required."
        }), 400

    try:

        start_port = int(start_port)
        end_port = int(end_port)

    except (TypeError, ValueError):

        return jsonify({
            "success": False,
            "error": "Invalid port number."
        }), 400

    if start_port < 1 or end_port > 65535:

        return jsonify({
            "success": False,
            "error": "Port must be between 1 and 65535."
        }), 400

    if start_port > end_port:

        return jsonify({
            "success": False,
            "error": "Start port cannot be greater than end port."
        }), 400

    # -----------------------------
    # CHECK IF SCAN ALREADY RUNNING
    # -----------------------------

    current_status = Nmap_CVE.get_progress()

    if current_status["status"] == "scanning":

        return jsonify({
            "success": False,
            "error": "A scan is already running."
        }), 409

    # -----------------------------
    # START BACKGROUND SCAN
    # -----------------------------

    scan_thread = threading.Thread(
        target=Nmap_CVE.run_scan,
        args=(
            target,
            start_port,
            end_port
        ),
        daemon=True
    )

    scan_thread.start()

    return jsonify({
        "success": True,
        "message": "Security scan started."
    })


# --------------------------------------------------
# GET SCAN PROGRESS
# --------------------------------------------------

@app.route("/api/scan-status", methods=["GET"])
def scan_status():

    status = Nmap_CVE.get_progress()

    return jsonify(status)

@app.route("/api/latest-result", methods=["GET"])
def latest_result():

    database_path = os.path.join(
        scanner_folder,
        "security_scanner.db"
    )

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Get latest scan
    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    scan = cursor.fetchone()

    if not scan:
        connection.close()

        return jsonify({
            "success": False,
            "error": "No scan results found."
        }), 404

    scan_id = scan["id"]

    # Get scanned ports
    cursor.execute("""
        SELECT
            port,
            service,
            product,
            version
        FROM ports
        WHERE scan_id = ?
        ORDER BY port
    """, (scan_id,))

    ports = cursor.fetchall()

    # Get vulnerabilities
    cursor.execute("""
        SELECT
            port,
            cve_id,
            cvss_score,
            severity,
            description
        FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY cvss_score DESC
    """, (scan_id,))

    vulnerabilities = cursor.fetchall()

    connection.close()

    return jsonify({
        "success": True,

        "scan": {
            "id": scan["id"],
            "target": scan["target"],
            "scan_date": scan["scan_date"],
            "total_open_ports": scan["total_open_ports"],
            "total_cves": scan["total_cves"],
            "highest_cvss": scan["highest_cvss"],
            "overall_risk": scan["overall_risk"]
        },

        "ports": [
            {
                "port": row["port"],
                "service": row["service"],
                "product": row["product"],
                "version": row["version"]
            }
            for row in ports
        ],

        "vulnerabilities": [
            {
                "port": row["port"],
                "cve_id": row["cve_id"],
                "cvss_score": row["cvss_score"],
                "severity": row["severity"],
                "description": row["description"]
            }
            for row in vulnerabilities
        ]
    })

# --------------------------------------------------
# RUN FLASK
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        threaded=True
    )