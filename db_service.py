"""
Central Shared Persistent Database Service for Distributed Group Chat
Runs on Sys1 (port 5001) to provide persistent, synchronized, deduplicated storage
for all backend server nodes (Sys2, Sys3, Sys4).
"""

import os
import sqlite3
import threading
import logging
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DB_SERVICE] %(message)s")
log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "central_chat.db"))
db_lock = threading.Lock()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

conn = get_db_connection()

with db_lock:
    # Messages table with UNIQUE message_id constraint to prevent duplicate insertions
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE,
            room_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(message_id);")
    
    # Public signing keys table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signing_keys (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL
        )
    """)
    conn.commit()


@app.route("/health", methods=["GET"])
def health():
    with db_lock:
        count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    return jsonify({"status": "ok", "total_messages": count}), 200


@app.route("/db/message", methods=["POST"])
def save_message():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"error": "Invalid payload"}), 400

    msg_id = str(data.get("message_id", "")).strip()
    room_id = str(data.get("room_id", "general")).strip()
    sender = str(data.get("sender", "")).strip()
    ciphertext = str(data.get("ciphertext", "")).strip()
    nonce = str(data.get("nonce", "")).strip()
    signature = str(data.get("signature", "")).strip()
    ts = str(data.get("timestamp", datetime.now().isoformat())).strip()

    if not (sender and ciphertext and nonce):
        return jsonify({"error": "Missing required fields"}), 400

    with db_lock:
        try:
            cursor = conn.cursor()
            # INSERT OR IGNORE enforces idempotency (no duplicate entries)
            cursor.execute("""
                INSERT OR IGNORE INTO messages (message_id, room_id, sender, ciphertext, nonce, signature, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (msg_id, room_id, sender, ciphertext, nonce, signature, ts))
            conn.commit()
            is_new = cursor.rowcount > 0
            return jsonify({"status": "ok", "is_new": is_new, "message_id": msg_id}), 200
        except Exception as e:
            log.error(f"Error inserting message: {e}")
            return jsonify({"error": str(e)}), 500


@app.route("/db/feed", methods=["GET"])
def get_feed():
    room_id = request.args.get("room_id", "general")
    with db_lock:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, message_id, room_id, sender, ciphertext, nonce, signature, timestamp
            FROM messages
            WHERE room_id = ?
            ORDER BY id ASC
        """, (room_id,))
        rows = cursor.fetchall()

    messages = []
    for r in rows:
        messages.append({
            "id": r[0],
            "message_id": r[1],
            "room_id": r[2],
            "sender": r[3],
            "ciphertext": r[4],
            "nonce": r[5],
            "signature": r[6],
            "timestamp": r[7]
        })
    return jsonify({"messages": messages}), 200


@app.route("/db/signing_key", methods=["POST"])
def save_signing_key():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    username = str(data.get("username", "")).strip()
    public_key = str(data.get("public_key", "")).strip()

    if not (username and public_key):
        return jsonify({"error": "Missing username or public_key"}), 400

    with db_lock:
        conn.execute("""
            INSERT OR REPLACE INTO signing_keys (username, public_key)
            VALUES (?, ?)
        """, (username, public_key))
        conn.commit()

    return jsonify({"status": "ok"}), 200


@app.route("/db/signing_key/<username>", methods=["GET"])
def get_signing_key(username: str):
    with db_lock:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM signing_keys WHERE username = ?", (username,))
        row = cursor.fetchone()

    if row:
        return jsonify({"username": username, "public_key": row[0]}), 200
    return jsonify({"error": "Key not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("DB_PORT", 5000))
    print(f"Starting Central DB Service on 0.0.0.0:{port}...")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
