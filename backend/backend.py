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
import sqlite3
import json
import logging

# -------------------- Flask App --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)

# -------------------- Blockchain --------------------
WEB3_PROVIDER = "HTTP://127.0.0.1:8545"  # Anvil default RPC
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
CHAIN_ADDRESS = w3.eth.accounts[0] if w3.is_connected() else None

# Load smart contract
CONTRACT_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"  # Update on redeploy
with open("CertificateRegistryABI.json") as f:
    CONTRACT_ABI = json.load(f)
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# -------------------- SQLite DB --------------------
DB_FILE = "praman.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    # Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        details TEXT
    )
    """)
    # Certificates
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        cert_id TEXT PRIMARY KEY,
        issuer TEXT,
        student_name TEXT,
        roll_no TEXT,
        course TEXT,
        college TEXT,
        date_of_issue TEXT,
        file_hash TEXT,
        status TEXT,
        qr_code TEXT,
        tx_hash TEXT,
        issued_at TEXT,
        file_path TEXT
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

# -------------------- Utilities --------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def hash_file(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

def generate_qr(cert_id: str, tx_hash: str) -> str:
    qr = qrcode.QRCode(
        version=1, box_size=10, border=4,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(f"http://127.0.0.1:8501/verify?cert_id={cert_id}")
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

# -------------------- User Functions --------------------
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
    cursor.execute(
        "INSERT INTO users (username, password, role, details) VALUES (?,?,?,?)",
        (username, hash_password(password), role, json.dumps(details))
    )
    conn.commit()
    conn.close()

# -------------------- Default Admin --------------------
def create_default_admin():
    admin_username = "leafcorelabs"
    admin_password = "leaf5289@"
    if not get_user(admin_username):
        add_user(admin_username, admin_password, "admin", details={"name": "Admin"})
        logging.info(f"Default admin created: {admin_username}")
    else:
        logging.info("Default admin already exists")

create_default_admin()

# -------------------- Auth Endpoints --------------------
@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        role_type = data.get("role_type")
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
    user_type = data.get("user_type")

    user = get_user(username)
    if not user or user["password"] != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    role_map = {
        "Admin": "admin",
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

# -------------------- Certificate Issuance --------------------
@app.route("/issue", methods=["POST"])
@token_required
def issue_cert(current_user):
    if current_user["role"] != "institute":
        return jsonify({"error": "Only institutes can issue certificates"}), 403

    # Metadata
    student_name = request.form.get("student_name")
    roll_no = request.form.get("roll_no")
    course = request.form.get("course")
    college = request.form.get("college")
    date_of_issue = request.form.get("date_of_issue") or datetime.datetime.utcnow().date().isoformat()

    if not student_name or not roll_no or not course or not college:
        return jsonify({"error": "Missing required metadata"}), 400

    # File upload
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    cert_id = str(uuid.uuid4())

    # Save file in structured folder
    base_dir = "issued_certificates"
    student_folder = os.path.join(base_dir, student_name.replace(" ", "_"))
    os.makedirs(student_folder, exist_ok=True)
    ext = os.path.splitext(file.filename)[1] or ".pdf"
    file_path = os.path.join(student_folder, f"{cert_id}{ext}")
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    # Blockchain transaction
    try:
        tx_hash = contract.functions.issueCertificate(cert_id, file_hash, student_name, roll_no, course, college).transact({'from': CHAIN_ADDRESS})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        tx_hash_hex = receipt.transactionHash.hex()
    except Exception as e:
        return jsonify({"error": f"Blockchain transaction failed: {str(e)}"}), 500

    # Generate QR
    qr_b64 = generate_qr(cert_id, tx_hash_hex)

    # Save to DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO certificates (cert_id, issuer, student_name, roll_no, course, college, date_of_issue,
                                  file_hash, status, qr_code, tx_hash, issued_at, file_path)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (cert_id, current_user["role"], student_name, roll_no, course, college, date_of_issue,
          file_hash, "valid", qr_b64, tx_hash_hex, datetime.datetime.utcnow().isoformat(), file_path))
    conn.commit()
    conn.close()

    return jsonify({
        "cert_id": cert_id,
        "student_name": student_name,
        "roll_no": roll_no,
        "course": course,
        "college": college,
        "date_of_issue": date_of_issue,
        "qr_code": qr_b64,
        "tx_hash": tx_hash_hex,
        "status": "issued"
    })

# -------------------- Certificate Verification --------------------
@app.route("/verify", methods=["POST"])
def verify_cert():
    try:
        data = request.form
        cert_id = data.get("cert_id")
        student_name = data.get("student_name")
        roll_no = data.get("roll_no")
        course = data.get("course")
        college = data.get("college")
        file = request.files.get("file")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE cert_id=?", (cert_id,))
        cert = cursor.fetchone()
        if not cert:
            return jsonify({"status": "not_found"}), 404

        status = "valid"
        tamper_score = 0

        # File hash verification
        if file:
            file_hash = hashlib.sha256(file.read()).hexdigest()
            if file_hash != cert["file_hash"]:
                status = "tampered"
                tamper_score = 1.0
                cursor.execute(
                    "INSERT INTO fraud_logs (cert_id, tamper_score, logged_at) VALUES (?,?,?)",
                    (cert_id, tamper_score, datetime.datetime.utcnow().isoformat())
                )
                conn.commit()

        # Metadata verification
        if (student_name and student_name != cert["student_name"]) or \
           (roll_no and roll_no != cert["roll_no"]) or \
           (course and course != cert["course"]) or \
           (college and college != cert["college"]):
            status = "tampered"
            tamper_score = 1.0
            cursor.execute(
                "INSERT INTO fraud_logs (cert_id, tamper_score, logged_at) VALUES (?,?,?)",
                (cert_id, tamper_score, datetime.datetime.utcnow().isoformat())
            )
            conn.commit()

        conn.close()

        return jsonify({
            "status": status,
            "cert_id": cert["cert_id"],
            "student_name": cert["student_name"],
            "roll_no": cert["roll_no"],
            "course": cert["course"],
            "college": cert["college"],
            "date_of_issue": cert["date_of_issue"],
            "tx_hash": cert["tx_hash"],
            "file_verified": file is None or file_hash == cert["file_hash"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

# -------------------- Health Check --------------------
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "pong", "message": "Pramān backend running"}), 200

# -------------------- Run --------------------
if __name__ == "__main__":
    os.makedirs("issued_certificates", exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
