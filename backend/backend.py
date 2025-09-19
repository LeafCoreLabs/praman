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
import logging

# -------------------- Flask App --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"  # replace with env var in production

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)

# -------------------- Blockchain --------------------
WEB3_PROVIDER = "HTTP://127.0.0.1:7545"  # Ganache or Polygon testnet
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
CHAIN_ADDRESS = w3.eth.accounts[0] if w3.is_connected() else None

# -------------------- In-Memory Users --------------------
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "inst1": {"password": "inst123", "role": "institute"},
    "user1": {"password": "user123", "role": "user"}
}

# -------------------- Certificates & Fraud Logs --------------------
certificates = {}  # cert_id -> {hash, issuer, status, qr_code, tx_hash}
fraud_logs = []    # tamper_score 0-1

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
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users.get(data["username"])
            if not current_user:
                return jsonify({"error": "User not found"}), 401
        except Exception as e:
            return jsonify({"error": f"Token invalid: {str(e)}"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# -------------------- Auth with User Type --------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user_type = data.get("user_type")  # NEW: front-end sends selected type

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if selected type matches user role
    role_map = {
        "Admin / Moderator": "admin",
        "Institute / Organization": "institute",
        "User / Student": "user"
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

# -------------------- Certificate Issue --------------------
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

    # Blockchain tx mock
    tx_hash = w3.eth.send_transaction({
        'from': CHAIN_ADDRESS,
        'to': CHAIN_ADDRESS,
        'value': w3.toWei(0, 'ether')
    }).hex() if CHAIN_ADDRESS else "demo_tx_hash"

    qr_b64 = generate_qr(cert_id, tx_hash)

    certificates[cert_id] = {
        "cert_id": cert_id,
        "issuer": current_user["role"],
        "hash": file_hash,
        "status": "valid",
        "qr_code": qr_b64,
        "tx_hash": tx_hash,
        "issued_at": datetime.datetime.utcnow().isoformat()
    }

    return jsonify({
        "cert_id": cert_id,
        "qr_code": qr_b64,
        "tx_hash": tx_hash,
        "status": "issued"
    })

# -------------------- Verification --------------------
@app.route("/verify", methods=["POST"])
def verify_cert():
    data = request.json
    cert_id = data.get("cert_id")
    file = request.files.get("file")  # optional
    cert = certificates.get(cert_id)
    if not cert:
        return jsonify({"status": "not_found"}), 404

    # recompute hash if file uploaded
    if file:
        file_hash = hash_file(file.read())
        if file_hash != cert["hash"]:
            cert["status"] = "tampered"
            fraud_logs.append({"cert_id": cert_id, "tamper_score": 1.0})

    return jsonify({
        "status": cert["status"],
        "cert_id": cert_id,
        "issuer": cert["issuer"],
        "tx_hash": cert["tx_hash"],
        "issued_at": cert["issued_at"]
    })

# -------------------- OCR --------------------
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
    return jsonify(fraud_logs)

# -------------------- Health --------------------
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "pong", "message": "Pramān backend running"}), 200

# -------------------- Run --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
