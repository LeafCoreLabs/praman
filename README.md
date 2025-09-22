<p align="center">
<img src="assets/logos/Praman - Copy.png" alt="Pramān Logo" width="300"/>
</p>

<p align="center"><i>"📜 Securing Credentials on the Blockchain"</i></p>

📌 About
Pramān (प्रमाण), meaning "proof" or "evidence" in Sanskrit, is a secure, blockchain-powered certificate issuance and verification platform. Developed by LeafCore Labs, its mission is to combat academic fraud and ensure the authenticity of educational and professional credentials. It provides a robust, end-to-end digital solution for institutions, organizations, and individuals.

🌟 Features
🔐 Role-Based Access
Admin: Full system monitoring, user management, and fraud log insights.

Institute / Issuer: Uploads and issues digital certificates to students.

Organization / Verifier: Verifies certificate authenticity with blockchain and OCR validation.

🛡️ Immutable Certificate Issuing
Institutes can issue new certificates by uploading a PDF or image.

The system generates a metadata hash and logs an immutable transaction on the blockchain.

Each certificate gets a unique ID and is stored securely in the database.

🔎 Tamper-Proof Verification
Users can verify a certificate by uploading the file and providing student details.

The system performs OCR extraction and hashes metadata to cross-check against blockchain and database records.

Flags tampered or invalid certificates automatically.

📝 Smart OCR Extraction
Uses Tesseract OCR (PDFs and images supported) to extract key details:

Student Name, Roll Number, Date of Birth, Course, College, Date of Issue.

Supports legacy and new digital certificates.

🔗 Blockchain Integration
Connects via Web3.py to a local Ganache testnet or any Ethereum-compatible network.

All issued certificates are recorded in a tamper-proof decentralized ledger.

✨ User-Friendly Interface
Interactive frontend built with Streamlit.

Role-based dashboard with intuitive navigation and forms.

Debugging panel for OCR text verification during issuance and verification.

📈 Fraud Monitoring
Admin dashboard displays real-time fraud logs and verification activity insights.

Helps detect anomalies, tampering trends, and unauthorized usage.

📐 Architecture
Layer

Technology

Frontend

Streamlit, streamlit-option-menu

Backend

Flask, JWT Authentication

Database

SQLite (praman.db) for users and certificates

Blockchain

Web3.py (Ganache / Polygon testnet)

OCR

Tesseract OCR (pdf2image for PDFs, PIL for images)

⚙️ Installation
1️⃣ Create a virtual environment & install dependencies:
```bash
python -m venv venv
# Activate environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
pip install -r requirements.txt
```

2️⃣ Run the backend:
```bash
python backend.py
```

3️⃣ Run the frontend:
```bash 
streamlit run frontend.py
```

🚀 Usage
Open the frontend in your browser (default: http://localhost:8501).

Select your user type: Admin, Institute, or Organization.

Sign Up for new users or Login for existing accounts.

Admin:

View fraud logs.

Monitor issued and verified certificates.

Institute:

Issue new certificates by uploading PDF/Image.

Debug panel shows OCR-extracted text.

Organization:

Verify certificates by uploading file and providing student details.

Debug panel helps inspect OCR extraction for verification.

🛠️ API Endpoints

Endpoint

Method

Description

/signup

POST

Register a new user with their role.

/login

POST

Authenticate a user and return a JWT token.

/issue

POST

Issue a new certificate (Institute only).

/verify

POST

Verify a certificate's authenticity (mandatory file upload).

/fraud_logs

GET

Retrieve fraud logs (Admin only).

/ping

GET

Health check endpoint.

📝 Database Schemas
users
username, password, role, details

certificates
cert_id, issuer, student_name, roll_no, dob, course, college, date_of_issue, metadata_hash, status, tx_hash, issued_at, file_path

fraud_logs
id, cert_id, tamper_score, logged_at

<p align="center"> <img src="assets/logos/Code_v.png" alt="Pramān Logo" width="200"/> </p>
<p align="center">Made with ❤️ by LeafCore Labs</p>