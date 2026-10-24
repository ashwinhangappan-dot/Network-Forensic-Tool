
import json
from pathlib import Path
from datetime import datetime, timezone
from pymongo import MongoClient

# Project folders
BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

ATTACK_FILE = RESULTS_DIR / "attack_report.json"
TIMELINE_FILE = RESULTS_DIR / "forensic_timeline.json"

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "network_forensic_db"


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def main():
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    try:
        client.admin.command("ping")
        db = client[DB_NAME]

        # Save attack detection report
        if ATTACK_FILE.exists():
            attack_data = load_json(ATTACK_FILE)
            db["attack_alerts"].insert_one({
                "saved_at": datetime.now(timezone.utc),
                "report": attack_data
            })
            print("Attack report saved to MongoDB.")

        # Save forensic timeline
        if TIMELINE_FILE.exists():
            timeline_data = load_json(TIMELINE_FILE)
            db["packet_evidence"].insert_one({
                "saved_at": datetime.now(timezone.utc),
                "timeline": timeline_data
            })
            print("Forensic timeline saved to MongoDB.")

        print("Database integration completed.")

    except Exception as error:
        print("Error:", error)

    finally:
        client.close()


if __name__ == "__main__":
    main()
