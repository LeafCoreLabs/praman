import os
import uuid
import base64
import qrcode
import io
import hashlib
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from web3 import Web3
import easyocr
import numpy as np
import sqlite3
import json
import logging

# -------------------- Flask App --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)

# -------------------- Blockchain --------------------
WEB3_PROVIDER = "HTTP://127.0.0.1:7545"
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
CHAIN_ADDRESS = w3.eth.accounts[0] if w3.is_connected() else None

# -------------------- SQLite DB --------------------
DB_FILE = "praman.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Users table for all roles
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        details TEXT
    )
    """)

    # Certificates table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        cert_id TEXT PRIMARY KEY,
        issuer TEXT,
        file_hash TEXT,
        status TEXT,
        qr_code TEXT,
        tx_hash TEXT,
        issued_at TEXT
    )
    """)

    # Fraud logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fraud_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_id TEXT,
        tamper_score REAL,
        logged_at TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# -------------------- Utility --------------------
def hash_file(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

def generate_qr(cert_id: str, tx_hash: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(f"https://verify.example.com/{cert_id}?tx={tx_hash}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            try:
                token = request.headers["Authorization"].split(" ")[1]
            except IndexError:
                return jsonify({"error": "Token malformed"}), 401
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = get_user(data["username"])
            if not current_user:
                return jsonify({"error": "User not found"}), 401
        except Exception as e:
            return jsonify({"error": f"Token invalid: {str(e)}"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# -------------------- DB User Functions --------------------
def get_user(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_user(username, password, role, details=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role, details) VALUES (?,?,?,?)",
                   (username, password, role, json.dumps(details)))
    conn.commit()
    conn.close()

# -------------------- Auth Endpoints --------------------
@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        role_type = data.get("role_type")  # 'institute' or 'organisation'
        details = {
            "name": data.get("name"),
            "email": data.get("email"),
            "contact": data.get("contact"),
            "address": data.get("address"),
            "designation": data.get("designation")
        }

        if not username or not password or not role_type:
            return jsonify({"error": "Missing required fields"}), 400

        if get_user(username):
            return jsonify({"error": "Username already exists"}), 400

        add_user(username, password, role_type, details)
        return jsonify({"message": f"{role_type.capitalize()} account created successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user_type = data.get("user_type")  # from frontend

    user = get_user(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    role_map = {
        "Admin / Moderator": "admin",
        "Institute / Issuer": "institute",
        "Organisation / Verifier": "organisation"
    }
    expected_role = role_map.get(user_type)
    if expected_role != user["role"]:
        return jsonify({"error": f"This account is not allowed for {user_type} login"}), 403

    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    }, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"access_token": token, "role": user["role"]})

# -------------------- Certificate Endpoints --------------------
@app.route("/issue", methods=["POST"])
@token_required
def issue_cert(current_user):
    if current_user["role"] != "institute":
        return jsonify({"error": "Unauthorized"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    file_bytes = file.read()
    cert_id = str(uuid.uuid4())
    file_hash = hash_file(file_bytes)

    tx_hash = w3.eth.send_transaction({
        'from': CHAIN_ADDRESS,
        'to': CHAIN_ADDRESS,
        'value': w3.toWei(0, 'ether')
    }).hex() if CHAIN_ADDRESS else "demo_tx_hash"

    qr_b64 = generate_qr(cert_id, tx_hash)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO certificates (cert_id, issuer, file_hash, status, qr_code, tx_hash, issued_at)
        VALUES (?,?,?,?,?,?,?)""",
                   (cert_id, current_user["role"], file_hash, "valid", qr_b64, tx_hash,
                    datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    return jsonify({"cert_id": cert_id, "qr_code": qr_b64, "tx_hash": tx_hash, "status": "issued"})

@app.route("/verify", methods=["POST"])
def verify_cert():
    try:
        data = request.json
        cert_id = data.get("cert_id")
        file = request.files.get("file")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE cert_id=?", (cert_id,))
        cert = cursor.fetchone()
        if not cert:
            conn.close()
            return jsonify({"status": "not_found"}), 404
        cert = dict(cert)

        if file:
            file_hash = hash_file(file.read())
            if file_hash != cert["file_hash"]:
                cursor.execute("UPDATE certificates SET status=? WHERE cert_id=?", ("tampered", cert_id))
                cursor.execute("INSERT INTO fraud_logs (cert_id, tamper_score, logged_at) VALUES (?,?,?)",
                               (cert_id, 1.0, datetime.datetime.utcnow().isoformat()))
                conn.commit()
                cert["status"] = "tampered"

        conn.close()
        return jsonify({
            "status": cert["status"],
            "cert_id": cert_id,
            "issuer": cert["issuer"],
            "tx_hash": cert["tx_hash"],
            "issued_at": cert["issued_at"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------- OCR Endpoint --------------------
@app.route("/ocr", methods=["POST"])
@token_required
def ocr_cert(current_user):
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    reader = easyocr.Reader(['en'])
    result = reader.readtext(np.frombuffer(file.read(), np.uint8))
    ocr_text = " ".join([text for (_, text, _) in result])
    return jsonify({"ocr_text": ocr_text})

# -------------------- Fraud Logs --------------------
@app.route("/fraud_logs", methods=["GET"])
@token_required
def get_fraud_logs(current_user):
    if current_user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fraud_logs")
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

# -------------------- Health --------------------
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "pong", "message": "Pramān backend running"}), 200

# -------------------- Run --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
