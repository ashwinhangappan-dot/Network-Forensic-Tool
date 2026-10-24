
from pymongo import MongoClient
from datetime import datetime, timezone

MONGO_URI = "mongodb://localhost:27017"

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

try:
    client.admin.command("ping")

    db = client["network_forensic_db"]
    packet_collection = db["packet_evidence"]
    alert_collection = db["attack_alerts"]

    print("MongoDB connected successfully!")
    print("Database:", db.name)
    print("Collections:", db.list_collection_names())

except Exception as error:
    print("MongoDB connection failed:", error)

finally:
    client.close()
