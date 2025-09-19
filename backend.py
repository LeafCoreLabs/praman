from flask import Flask, request, jsonify
import uuid, hashlib, base64, qrcode, io, datetime, jwt
from functools import wraps

# ======================
# Flask App
# ======================
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"

# ======================
# In-Memory Database
# ======================
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "institute1": {"password": "inst123", "role": "institute"},
}
certificates = {}
blacklist = []

# ======================
# Utils
# ======================
def generate_qr(cert_id):
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(f"verify://{cert_id}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def hash_file(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").split(" ")[-1]
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

# ======================
# Routes
# ======================
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data.get("username"), data.get("password")
    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"access_token": token, "role": user["role"]})

@app.route("/issue", methods=["POST"])
@token_required
def issue(current_user):
    if current_user["role"] != "institute":
        return jsonify({"error": "Unauthorized"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    file_bytes = file.read()
    cert_id = str(uuid.uuid4())
    file_hash = hash_file(file_bytes)
    qr_code = generate_qr(cert_id)
    certificates[cert_id] = {
        "cert_id": cert_id,
        "issuer": "Demo Institute",
        "hash": file_hash,
        "status": "valid",
        "qr_code": qr_code,
        "issued_at": datetime.datetime.utcnow().isoformat()
    }
    return jsonify({"cert_id": cert_id, "qr_code": qr_code, "status": "issued"})

@app.route("/verify", methods=["POST"])
def verify():
    cert_id = request.json.get("cert_id")
    cert = certificates.get(cert_id)
    if not cert:
        return jsonify({"status": "not_found"}), 404
    if cert_id in blacklist:
        return jsonify({"status": "tampered", "cert_id": cert_id}), 200
    return jsonify({"status": cert["status"], "cert_id": cert_id, "issuer": cert["issuer"], "issued_at": cert["issued_at"]})

@app.route("/blacklist", methods=["POST"])
@token_required
def blacklist_cert(current_user):
    if current_user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    cert_id = request.json.get("cert_id")
    if cert_id not in certificates:
        return jsonify({"error": "Certificate not found"}), 404
    blacklist.append(cert_id)
    certificates[cert_id]["status"] = "tampered"
    return jsonify({"message": f"Certificate {cert_id} blacklisted"})

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "pong", "message": "Backend running"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
