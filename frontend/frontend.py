import streamlit as st
import requests
import base64
from streamlit_option_menu import option_menu
import os

# ================= CONFIG =================
st.set_page_config(page_title="Pramān", page_icon="🪪", layout="centered")

BACKEND_URL = "http://127.0.0.1:5000"

# ================= STATE =================
for key in ["step", "token", "role", "user_type"]:
    if key not in st.session_state:
        st.session_state[key] = None
if st.session_state.step is None:
    st.session_state.step = "user_type"

# ================= CSS =================
st.markdown("""
<style>
body { background-color: #fafafa; font-family: 'Segoe UI', sans-serif; }
.stTextInput>div>div>input { border-radius: 3px; border: 1px solid #dbdbdb; background: #fafafa; }
.stButton>button { background: #0095f6; color: white !important; font-weight: 600; border-radius: 6px; padding: 8px; width: 100%; transition: all 0.3s ease-in-out; }
.stButton>button:hover { background: #0077cc; }
.footer { text-align: center; margin-top: 25px; font-size: 0.85rem; color: #8e8e8e; }
</style>
""", unsafe_allow_html=True)

# ================= CENTERED LOGO =================
st.image("assets/logos/praman.png", width=250)

# ---------- Step 1: User Type ----------
if st.session_state.step == "user_type":
    st.write("Select your user type:")
    user_type = st.radio("", ["Admin", "Institute / Issuer", "Organisation / Verifier"])
    if st.button("Continue"):
        st.session_state.user_type = user_type
        st.session_state.step = "login"

# ---------- Step 2: Login / Signup ----------
elif st.session_state.step in ["login", "signup"]:
    tab = st.radio("", ["Login", "Sign Up"], horizontal=True)

    # LOGIN
    if tab == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("← Back"):
                st.session_state.step = "user_type"
                st.rerun()
        with col2:
            if st.button("Sign In"):
                try:
                    r = requests.post(f"{BACKEND_URL}/login",
                                      json={"username": username,
                                            "password": password,
                                            "user_type": st.session_state.user_type})
                    if r.status_code == 200:
                        data = r.json()
                        st.session_state.token = data["access_token"]
                        st.session_state.role = data["role"]
                        st.session_state.step = "dashboard"
                        st.rerun()
                    else:
                        st.error(r.json().get("error", "Login failed"))
                except:
                    st.error("Backend not reachable")

    # SIGNUP
    elif tab == "Sign Up":
        with st.form("signup_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            name = st.text_input("Full Name / Organisation Name")
            email = st.text_input("Email")
            contact = st.text_input("Contact Number")
            address = st.text_area("Address")
            designation = st.text_input("Designation / Role")
            submitted = st.form_submit_button("Create Account")
            if submitted:
                try:
                    role_type = "institute" if st.session_state.user_type == "Institute / Issuer" else "organisation"
                    r = requests.post(f"{BACKEND_URL}/signup", json={
                        "username": username,
                        "password": password,
                        "role_type": role_type,
                        "name": name,
                        "email": email,
                        "contact": contact,
                        "address": address,
                        "designation": designation
                    })
                    if r.status_code in [200, 201]:
                        st.success("Account created! Please log in.")
                        st.session_state.step = "login"
                        st.rerun()
                    else:
                        st.error(r.json().get("error", "Signup failed"))
                except:
                    st.error("Backend not reachable")

# ---------- Step 3: Dashboard ----------
elif st.session_state.step == "dashboard" and st.session_state.token:
    if st.button("Logout"):
        st.session_state.step = "user_type"
        st.session_state.token = None
        st.session_state.role = None
        st.session_state.user_type = None
        st.rerun()

    selected = option_menu(
        menu_title=None,
        options=["Dashboard", "Issue Certificate", "Verify Certificate"],
        icons=["bar-chart-line", "file-earmark-plus", "search"],
        orientation="horizontal"
    )

    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # ---------- Dashboard ----------
    if selected == "Dashboard":
        st.subheader("Dashboard")
        if st.session_state.role == "admin":
            try:
                r = requests.get(f"{BACKEND_URL}/fraud_logs", headers=headers)
                if r.status_code == 200 and r.json():
                    logs = r.json()
                    st.table(logs)
                else:
                    st.info("No fraud logs yet.")
            except:
                st.error("Backend not reachable")
        else:
            st.info("Institute/Organisation dashboard coming soon...")

    # ---------- Issue Certificate ----------
    elif selected == "Issue Certificate" and st.session_state.role == "institute":
        st.subheader("Issue Certificate")
        with st.form("issue_form"):
            student_name = st.text_input("Student Name")
            roll_no = st.text_input("Roll Number / ID")
            course = st.text_input("Course / Degree")
            college = st.text_input("College / Institute")
            date_of_issue = st.date_input("Date of Issue")
            file = st.file_uploader("Supporting Document (PDF/Image)")
            submitted = st.form_submit_button("Issue Certificate")
            if submitted:
                if not student_name or not roll_no or not course or not college or not file:
                    st.error("All fields and file are required")
                else:
                    files = {"file": file}
                    data = {
                        "student_name": student_name,
                        "roll_no": roll_no,
                        "course": course,
                        "college": college,
                        "date_of_issue": str(date_of_issue)
                    }
                    try:
                        r = requests.post(f"{BACKEND_URL}/issue", files=files, data=data, headers=headers)
                        if r.status_code == 200:
                            cert = r.json()
                            st.success("Certificate Issued!")
                            st.write(f"Certificate ID: {cert['cert_id']}")
                            st.write(f"Student: {cert['student_name']}")
                            st.write(f"Roll No: {cert['roll_no']}")
                            st.write(f"Course: {cert['course']}")
                            st.write(f"College: {cert['college']}")
                            st.image(base64.b64decode(cert["qr_code"]), width=200)
                        else:
                            st.error(r.json().get("error", "Error issuing certificate"))
                    except:
                        st.error("Backend not reachable")

    # ---------- Verify Certificate ----------
    elif selected == "Verify Certificate":
        st.subheader("Verify Certificate")
        with st.form("verify_form"):
            cert_id = st.text_input("Certificate ID")
            student_name = st.text_input("Student Name (optional)")
            roll_no = st.text_input("Roll Number (optional)")
            course = st.text_input("Course (optional)")
            college = st.text_input("College (optional)")
            file = st.file_uploader("Upload Certificate File (optional)")
            submitted = st.form_submit_button("Verify Certificate")
            if submitted:
                data = {
                    "cert_id": cert_id,
                    "student_name": student_name,
                    "roll_no": roll_no,
                    "course": course,
                    "college": college
                }
                files = {"file": file} if file else None
                try:
                    r = requests.post(f"{BACKEND_URL}/verify", data=data, files=files)
                    if r.status_code == 200:
                        cert = r.json()
                        st.success("Verification Result")
                        st.write(cert)
                    else:
                        st.error("Certificate not found or invalid")
                except:
                    st.error("Backend not reachable")

# ================= FOOTER =================
st.markdown("<div class='footer'>Made with ❤️ by LeafCore Labs</div>", unsafe_allow_html=True)
