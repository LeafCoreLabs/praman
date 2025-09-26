import os
import uuid
import hashlib
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from web3 import Web3
import sqlite3
import json
import logging
from PIL import Image
import pytesseract
from pdf2image import convert_from_bytes

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
logging.basicConfig(level=logging.INFO)

# -------------------- Blockchain Setup --------------------
WEB3_PROVIDER = "HTTP://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
CHAIN_ADDRESS = w3.eth.accounts[0] if w3.is_connected() else None

CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
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
    # Updated: Added a 'reason' column to the fraud_logs table
    cursor.execute("DROP TABLE IF EXISTS fraud_logs")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        details TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        cert_id TEXT PRIMARY KEY,
        issuer TEXT,
        student_name TEXT,
        roll_no TEXT,
        dob TEXT,
        course TEXT,
        college TEXT,
        date_of_issue TEXT,
        metadata_hash TEXT,
        status TEXT,
        tx_hash TEXT,
        issued_at TEXT,
        file_path TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fraud_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_id TEXT,
        tamper_score REAL,
        reason TEXT,
        logged_at TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# -------------------- OCR Setup --------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
POPPLER_PATH = r"C:\poppler-25.07.0\Library\bin"

# -------------------- Utilities --------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def compute_metadata_hash(ocr_text: str) -> str:
    """Computes a SHA256 hash from the entire OCR text content."""
    return hashlib.sha256(ocr_text.encode()).hexdigest()

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

def create_default_admin():
    admin_username = "leafcorelabs"
    admin_password = "leaf5289@"
    if not get_user(admin_username):
        add_user(admin_username, admin_password, "admin", details={"name": "Admin"})
        logging.info(f"Default admin created: {admin_username}")
    else:
        logging.info("Default admin already exists")

create_default_admin()

# -------------------- OCR --------------------
def extract_text_from_file(file):
    ext = os.path.splitext(file.filename)[1].lower()
    images = []
    ocr_text = ""
    file.seek(0)
    if ext == ".pdf":
        images = convert_from_bytes(file.read(), poppler_path=POPPLER_PATH)
    else:
        images = [Image.open(file.stream)]
    for img in images:
        ocr_text += pytesseract.image_to_string(img) + "\n"
    return ocr_text

# The extract_fields_from_ocr function has been removed as requested.

# NEW: Helper function to log a fraud event with enhanced error handling
def log_fraud(cert_id, reason):
    """Logs a fraud event to the database with debug logging."""
    logging.info(f"Attempting to log fraud for cert_id: {cert_id}")
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO fraud_logs (cert_id, tamper_score, reason, logged_at)
            VALUES (?, ?, ?, ?)
        """, (cert_id, 1.0, reason, datetime.datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        logging.info(f"Fraud logged successfully. Reason: {reason}")
    except Exception as e:
        logging.error(f"Failed to log fraud event: {str(e)}")

# -------------------- Routes --------------------

@app.route("/")
def root():
    return jsonify({"message":"Pramān backend is running"}), 200

# ---------- Signup ----------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role_type = data.get("role_type") # 'institute' or 'organisation'
    details = {k:v for k,v in data.items() if k not in ["username","password","role_type"]}

    if not all([username, password, role_type]):
        return jsonify({"error":"Username, password, and role_type required"}), 400
    if get_user(username):
        return jsonify({"error":"Username already exists"}), 400
    add_user(username, password, role_type, details)
    return jsonify({"message":"User created successfully"}), 201

# ---------- Login ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user_type = data.get("user_type")

    if not all([username, password, user_type]):
        return jsonify({"error":"Username, password, and user_type required"}),400
    user = get_user(username)
    if not user or user["password"] != hash_password(password):
        return jsonify({"error":"Invalid credentials"}),401
    if user["role"] not in ["admin","institute","organisation"]:
        return jsonify({"error":"Invalid role"}),403
    access_token = jwt.encode({"username": username, "exp": datetime.datetime.utcnow()+datetime.timedelta(hours=8)}, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"access_token": access_token, "role": user["role"]}),200

# ---------- Issue Certificate ----------
@app.route("/issue", methods=["POST"])
@token_required
def issue_cert(current_user):
    if current_user["role"] != "institute":
        return jsonify({"error": "Only institutes can issue certificates"}), 403

    student_name = request.form.get("student_name")
    roll_no = request.form.get("roll_no")
    dob = request.form.get("dob")
    course = request.form.get("course")
    college = request.form.get("college")
    date_of_issue = request.form.get("date_of_issue") or datetime.datetime.utcnow().date().isoformat()
    if not all([student_name, roll_no, dob, course, college, date_of_issue]):
        return jsonify({"error":"All crucial fields required"}), 400

    if "file" not in request.files:
        return jsonify({"error":"Certificate file missing"}),400
    file = request.files["file"]

    # The file stream is consumed here for OCR and hashing.
    ocr_text = extract_text_from_file(file)
    metadata_hash = compute_metadata_hash(ocr_text)

    # NEW: Check for duplicate metadata before issuing
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT cert_id FROM certificates WHERE metadata_hash=?", (metadata_hash,))
    existing_cert = cursor.fetchone()
    conn.close()
    if existing_cert:
        log_fraud(existing_cert['cert_id'], "Duplicate Issuance Attempt: Document hash already exists.")
        return jsonify({"error": "A certificate with this exact content already exists."}), 409

    cert_id = str(uuid.uuid4())
    os.makedirs("issued_certificates", exist_ok=True)
    ext = os.path.splitext(file.filename)[1] or ".pdf"
    file_path = os.path.join("issued_certificates", f"{cert_id}{ext}")
    
    # FIX: Reset the file stream pointer to the beginning (0) so file.save() can read the content from the start.
    file.seek(0)
    
    file.save(file_path)

    try:
        tx_hash = contract.functions.issueCertificate(
            cert_id, metadata_hash,
            student_name, roll_no,
            course, college
        ).transact({'from': CHAIN_ADDRESS})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        tx_hash_hex = receipt.transactionHash.hex()
    except Exception as e:
        return jsonify({"error": f"Blockchain tx failed: {str(e)}"}),500

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO certificates (cert_id, issuer, student_name, roll_no, dob, course, college, date_of_issue,
                                 metadata_hash, status, tx_hash, issued_at, file_path)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (cert_id, current_user["role"], student_name, roll_no, dob, course, college, date_of_issue,
          metadata_hash, "valid", tx_hash_hex, datetime.datetime.utcnow().isoformat(), file_path))
    conn.commit()
    conn.close()

    return jsonify({
        "cert_id": cert_id,
        "status":"issued",
        "tx_hash": tx_hash_hex,
        "student_name": student_name,
        "roll_no": roll_no,
        "dob": dob,
        "course": course,
        "college": college,
        "date_of_issue": date_of_issue,
        "debug":{"ocr_text": ocr_text}
    })

# ---------- Verify Certificate ----------
@app.route("/verify", methods=["POST"])
def verify_cert():
    try:
        file = request.files.get("file")
        student_name = request.form.get("student_name","").strip().lower()
        roll_no = request.form.get("roll_no","").strip().lower()
        date_of_issue = request.form.get("date_of_issue","").strip()

        if not student_name or not file:
            return jsonify({"error":"Student name and certificate file mandatory"}),400
        if not roll_no and not date_of_issue:
            return jsonify({"error":"Provide either roll_no or date_of_issue"}),400

        # The file stream is consumed here for OCR and hashing.
        ocr_text = extract_text_from_file(file)
        metadata_hash = compute_metadata_hash(ocr_text)

        # DB Lookup
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE metadata_hash=?",(metadata_hash,))
        cert = cursor.fetchone()
        conn.close()

        if not cert:
            # Case 1: Document is wrong, hash is not in the database
            log_fraud(None, "Document Hash Not Found: The uploaded document's hash does not exist.")
            return jsonify({"status":"tampered or invalid","debug":{"ocr_text": ocr_text}}),404

        # Blockchain verification
        exists, cert_id = contract.functions.verifyMetadataHash(metadata_hash).call()
        if not exists:
            # Case 2: Hash found in DB, but not on the blockchain (highly suspicious)
            log_fraud(cert["cert_id"], "Blockchain Mismatch: Document hash found in DB but not on the blockchain.")
            return jsonify({"status":"tampered or invalid","debug":{"ocr_text": ocr_text}}),404

        # Check crucial fields
        name_match = cert["student_name"].lower() == student_name
        roll_match = roll_no and cert["roll_no"].lower() == roll_no
        date_match = date_of_issue and cert["date_of_issue"] == date_of_issue

        if name_match and (roll_match or date_match):
            return jsonify({
                "status":"valid",
                **{k: cert[k] for k in ["cert_id","student_name","roll_no","dob","course","college","date_of_issue","tx_hash"]},
                "debug":{"ocr_text":ocr_text}
            })
        else:
            # Case 3: Certificate matches on blockchain and DB, but provided fields don't match
            log_fraud(cert["cert_id"], "Data Mismatch: Provided user details do not match the certificate.")
            return jsonify({"status":"tampered or invalid","debug":{"ocr_text":ocr_text}}),404

    except Exception as e:
        return jsonify({"error": str(e)}),500

# ---------- Fraud Logs ----------
@app.route("/fraud_logs", methods=["GET"])
@token_required
def get_fraud_logs(current_user):
    if current_user["role"] != "admin":
        return jsonify({"error":"Unauthorized"}),403
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fraud_logs")
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

# -------------------- Main --------------------
if __name__ == "__main__":
    os.makedirs("issued_certificates", exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
