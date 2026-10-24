
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from pymongo import MongoClient
from pathlib import Path
from werkzeug.utils import secure_filename
from datetime import datetime
import hashlib
import json
import os
import subprocess
import sys

# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOAD_DIR = BASE_DIR / "packet_capture"
RESULTS_DIR = BASE_DIR / "results"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# PDF GENERATOR
# --------------------------------------------------

sys.path.insert(0, str(BASE_DIR / "backend"))
from pdf_report import generate_pdf

# --------------------------------------------------
# FLASK APP
# --------------------------------------------------

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024

# --------------------------------------------------
# MONGODB CONNECTION
# --------------------------------------------------

MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb://localhost:27017/"
)

DB_NAME = os.environ.get(
    "MONGO_DB",
    "network_forensic_db"
)

mongo_client = None
db = None

try:
    mongo_client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=3000
    )
    mongo_client.admin.command("ping")
    db = mongo_client[DB_NAME]
    print("MongoDB connected successfully")

except Exception as error:
    print("MongoDB connection failed:", error)

# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def read_json_file(file_path):
    if not file_path.exists():
        return {}

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with file_path.open("rb") as evidence_file:
        for chunk in iter(
            lambda: evidence_file.read(1024 * 1024), b""
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


# --------------------------------------------------
# HOME / HEALTH CHECK
# --------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Network Forensic Tool API is running",
        "status": "running"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "mongodb_connected": db is not None
    })


# --------------------------------------------------
# UPLOAD AND ANALYZE PCAP
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze_pcap():

    if "file" not in request.files:
        return jsonify({
            "error": "Please select a PCAP file"
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({
            "error": "No file selected"
        }), 400

    safe_name = secure_filename(uploaded_file.filename)
    extension = Path(safe_name).suffix.lower()

    if extension not in {".pcap", ".pcapng"}:
        return jsonify({
            "error": "Only .pcap and .pcapng files are allowed"
        }), 400

    # Save uploaded PCAP
    upload_path = UPLOAD_DIR / "uploaded.pcap"
    uploaded_file.save(upload_path)

    # Calculate evidence hash
    evidence_hash = calculate_sha256(upload_path)

    # Pass uploaded file to analysis scripts
    env = os.environ.copy()
    env["PCAP_FILE"] = str(upload_path.resolve())

    commands = [
        [
            sys.executable,
            str(BASE_DIR / "detection_engine" / "attack_detector.py")
        ],
        [
            sys.executable,
            str(BASE_DIR / "forensic_module" / "forensic_analyzer.py")
        ],
        [
            sys.executable,
            str(BASE_DIR / "database" / "save_results.py")
        ]
    ]

    try:
        # Run detection, forensic analysis and database save
        for command in commands:

            result = subprocess.run(
                command,
                cwd=str(BASE_DIR),
                env=env,
                capture_output=True,
                text=True,
                timeout=300
            )

            print(
                f"\nRunning: {Path(command[1]).name}"
            )
            print(result.stdout)

            if result.returncode != 0:
                print(result.stderr)

                return jsonify({
                    "error": "Analysis step failed",
                    "step": Path(command[1]).name,
                    "details": result.stderr[-3000:]
                }), 500

        # Read generated JSON results
        report_path = RESULTS_DIR / "attack_report.json"
        timeline_path = RESULTS_DIR / "forensic_timeline.json"

        if not report_path.exists():
            return jsonify({
                "error": "attack_report.json was not generated"
            }), 500

        if not timeline_path.exists():
            return jsonify({
                "error": "forensic_timeline.json was not generated"
            }), 500

        report = read_json_file(report_path)
        timeline = read_json_file(timeline_path)

        # Generate PDF report
        generate_pdf()

        pdf_path = RESULTS_DIR / "network_forensic_report.pdf"

        if not pdf_path.exists():
            return jsonify({
                "error": "PDF generation did not create the report"
            }), 500

        # Analysis metadata
        analysis_time = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        analysis_info = {
            "last_analysis": analysis_time,
            "uploaded_file": safe_name,
            "evidence_sha256": evidence_hash
        }

        return jsonify({
            "message": "PCAP analysis completed successfully",
            "report": report,
            "forensics": timeline,
            "analysis_info": analysis_info,
            "pdf_generated": True,
            "pdf_download_url": "/api/download-pdf"
        }), 200

    except subprocess.TimeoutExpired:
        app.logger.exception("PCAP analysis timed out")

        return jsonify({
            "error": "Analysis timed out. Try again or increase the timeout."
        }), 500

    except Exception as error:
        app.logger.exception("PCAP analysis failed")

        return jsonify({
            "error": str(error)
        }), 500


# --------------------------------------------------
# GET ATTACK ALERTS FROM MONGODB
# --------------------------------------------------

@app.route("/api/attacks", methods=["GET"])
def get_attacks():

    if db is None:
        return jsonify({
            "error": "MongoDB is not connected"
        }), 503

    try:
        document = db["attack_alerts"].find_one(
            {},
            {"_id": 0},
            sort=[("saved_at", -1)]
        )

        report = document.get("report", {}) if document else {}
        alerts = report.get("alerts", [])

        return jsonify({
            "count": len(alerts),
            "attacks": alerts,
            "report": report
        })

    except Exception as error:
        return jsonify({
            "error": str(error)
        }), 500


# --------------------------------------------------
# GET FORENSIC EVIDENCE FROM MONGODB
# --------------------------------------------------

@app.route("/api/forensics", methods=["GET"])
def get_forensics():

    if db is None:
        return jsonify({
            "error": "MongoDB is not connected"
        }), 503

    try:
        document = db["packet_evidence"].find_one(
            {},
            {"_id": 0},
            sort=[("saved_at", -1)]
        )

        data = document.get("timeline", []) if document else []

        if isinstance(data, dict):
            data = data.get("timeline", [])

        timeline = data if isinstance(data, list) else []

        return jsonify({
            "count": len(timeline),
            "timeline": timeline,
            "evidence": timeline
        })

    except Exception as error:
        return jsonify({
            "error": str(error)
        }), 500


# --------------------------------------------------
# DOWNLOAD JSON REPORT
# --------------------------------------------------

@app.route("/api/download-report", methods=["GET"])
def download_json_report():

    report_path = RESULTS_DIR / "attack_report.json"

    if not report_path.exists():
        return jsonify({
            "error": "JSON report not found. Analyze a PCAP first."
        }), 404

    return send_file(
        report_path,
        as_attachment=True,
        download_name="network_forensic_report.json",
        mimetype="application/json"
    )


# --------------------------------------------------
# DOWNLOAD PDF REPORT
# --------------------------------------------------

@app.route("/api/download-pdf", methods=["GET"])
def download_pdf():

    pdf_path = RESULTS_DIR / "network_forensic_report.pdf"

    if not pdf_path.exists():
        return jsonify({
            "error": "PDF report not found. Analyze a PCAP first."
        }), 404

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="network_forensic_report.pdf",
        mimetype="application/pdf"
    )


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
