import streamlit as st
import requests
from streamlit_option_menu import option_menu
import os
import datetime
import re

# ================= CONFIG =================
st.set_page_config(page_title="Pramān", page_icon="🪪", layout="centered")
BACKEND_URL = "http://127.0.0.1:5000"

# ================= STATE =================
for key in ["step", "token", "role", "user_type", "confirm_logout"]:
    if key not in st.session_state:
        st.session_state[key] = None
if st.session_state.step is None:
    st.session_state.step = "user_type"

# ================= CSS =================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');

body { 
    background-color: #fafafa; 
    font-family: 'Poppins', sans-serif; 
}

.stTextInput>div>div>input, .stTextArea>div>div>textarea { 
    border-radius: 6px; 
    border: 1px solid #dbdbdb; 
    background: #fafafa; 
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    padding: 10px;
    font-size: 14px;
}

.stButton>button { 
    background: #0095f6; 
    color: white !important; 
    font-weight: 600; 
    border-radius: 6px; 
    padding: 10px; 
    width: 100%; 
    border: none;
    transition: all 0.2s ease-in-out; 
}
.stButton>button:hover { 
    background: #0077cc; 
    transform: translateY(-2px);
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}
.stButton>button:active {
    transform: translateY(0);
    box-shadow: none;
}
.footer { 
    text-align: center; 
    margin-top: 25px; 
    font-size: 0.85rem; 
    color: #8e8e8e; 
}
.main-container {
    background-color: white;
    padding: 2.5rem;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    margin: 2rem auto;
    animation: fadeIn 0.8s ease-in-out;
}

.logout-button {
    background: linear-gradient(45deg, #FF6B6B, #FF4B4B);
}

.logout-button:hover {
    background: linear-gradient(45deg, #FF4B4B, #FF6B6B);
}

.empty-state {
    text-align: center;
    padding: 40px 20px;
    color: #a0a0a0;
    font-size: 1.1rem;
    background-color: #f5f5f5;
    border-radius: 8px;
    border: 1px dashed #ccc;
    margin-top: 20px;
}
.empty-state-icon {
    font-size: 3rem;
    margin-bottom: 10px;
    color: #ccc;
}
.st-emotion-cache-1ky8201 {
    display: none;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 600px) {
    .main-container {
        padding: 1.5rem;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        font-size: 1rem;
    }
}

</style>
""", unsafe_allow_html=True)

# ================= CENTERED LOGO =================
st.image("assets/logos/praman.png", width=250)

# ---------- Step 1: User Type ----------
if st.session_state.step == "user_type":
    with st.container(border=True):
        st.subheader("Welcome to Pramān")
        st.write("Select your user type to proceed:")
        user_type = st.radio("", ["Admin", "Institute / Issuer", "Organisation / Verifier"])
        if st.button("Continue"):
            st.session_state.user_type = user_type
            st.session_state.step = "login"

# ---------- Step 2: Login / Signup ----------
elif st.session_state.step in ["login", "signup"]:
    tab = st.radio("", ["Login", "Sign Up"], horizontal=True)

    # Check for and display a success message from a previous signup
    if st.session_state.get("signup_success"):
        st.success("Account created successfully! Please log in.")
        del st.session_state["signup_success"]

    # Message placeholder for dynamic feedback
    message_placeholder = st.empty()

    if tab == "Login":
        with st.container(border=True):
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("← Back"):
                    st.session_state.step = "user_type"
                    st.rerun()
            with col2:
                if st.button("Sign In"):
                    if not username or not password:
                        message_placeholder.error("Please enter both username and password.")
                    else:
                        with st.spinner("Signing in..."):
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
                                    message_placeholder.success("Login successful!")
                                    st.rerun()
                                else:
                                    message_placeholder.error(r.json().get("error", "Login failed. Please check your credentials."))
                            except Exception as e:
                                message_placeholder.error(f"Backend not reachable: {str(e)}")
    elif tab == "Sign Up":
        with st.form("signup_form"):
            st.subheader("Create Your Account")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            st.markdown("Password must be at least 8 characters long and contain at least one uppercase letter, one number, and one special character.")
            name = st.text_input("Full Name / Organisation Name")
            email = st.text_input("Email :email:")
            contact = st.text_input("Contact Number")
            address = st.text_area("Address")
            designation = st.text_input("Designation / Role")
            submitted = st.form_submit_button("Create Account")
            if submitted:
                # Password validation check
                special_characters = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
                if len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif not any(char.isupper() for char in password):
                    st.error("Password must contain at least one capital letter.")
                elif not any(char.isdigit() for char in password):
                    st.error("Password must contain at least one number.")
                elif not special_characters.search(password):
                    st.error("Password must contain at least one special character.")
                elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    st.error("Please enter a valid email address.")
                else:
                    with st.spinner("Creating account..."):
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
                                st.session_state.signup_success = True
                                st.session_state.step = "login"
                                st.rerun()
                            else:
                                message_placeholder.error(r.json().get("error", "Signup failed."))
                        except Exception as e:
                            message_placeholder.error(f"Backend not reachable: {str(e)}")

# ---------- Step 3: Dashboard ----------
elif st.session_state.step == "dashboard" and st.session_state.token:
    # Logout confirmation logic
    if st.session_state.confirm_logout:
        st.warning("Are you sure you want to log out?")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Yes, Logout"):
                st.session_state.step = "user_type"
                st.session_state.token = None
                st.session_state.role = None
                st.session_state.user_type = None
                st.session_state.confirm_logout = None
                st.rerun()
        with col2:
            if st.button("Cancel"):
                st.session_state.confirm_logout = None
                st.rerun()
    else:
        if st.button("Logout", help="Click to log out", use_container_width=False):
            st.session_state.confirm_logout = True
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
        with st.container(border=True):
            st.subheader("Dashboard")
            if st.session_state.role == "admin":
                with st.spinner("Fetching fraud logs..."):
                    try:
                        r = requests.get(f"{BACKEND_URL}/fraud_logs", headers=headers)
                        if r.status_code == 200 and r.json():
                            st.table(r.json())
                        else:
                            st.markdown("""
                            <div class="empty-state">
                                <div class="empty-state-icon">📄</div>
                                No fraud logs to display at the moment.
                            </div>
                            """, unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"Backend not reachable: {str(e)}")
            else:
                st.info("Institute/Organisation dashboard coming soon...")

    # ---------- Issue Certificate ----------
    elif selected == "Issue Certificate" and st.session_state.role == "institute":
        with st.container(border=True):
            st.subheader("Issue Certificate")
            with st.form("issue_form"):
                student_name = st.text_input("Student Name")
                roll_no = st.text_input("Roll Number / ID")
                dob = st.date_input("Date of Birth", value=None, min_value=datetime.date(1900, 1, 1), max_value=datetime.date.today())
                course = st.text_input("Course / Degree")
                college = st.text_input("College / Institute")
                date_of_issue = st.date_input("Date of Issue", value=None, min_value=datetime.date(1900, 1, 1), max_value=datetime.date.today())
                file = st.file_uploader("Upload Certificate File (PDF/Image)")
                submitted = st.form_submit_button("Issue Certificate")
                if submitted:
                    with st.spinner("Issuing certificate..."):
                        if not all([student_name, roll_no, dob, course, college, file]):
                            st.error("All fields and certificate file are mandatory")
                        else:
                            data = {
                                "student_name": student_name.strip(),
                                "roll_no": roll_no.strip(),
                                "dob": str(dob),
                                "course": course.strip(),
                                "college": college.strip(),
                                "date_of_issue": str(date_of_issue)
                            }
                            files = {"file": file}
                            try:
                                r = requests.post(f"{BACKEND_URL}/issue", data=data, files=files, headers=headers)
                                if r.status_code == 200:
                                    cert = r.json()
                                    st.success("Certificate Issued!")
                                    st.json(cert)
                                    with st.expander("Debug Info (OCR Text)"):
                                        st.text_area("", cert.get("debug", {}).get("ocr_text", ""), height=250)
                                else:
                                    st.error(r.json().get("error", "Error issuing certificate"))
                            except Exception as e:
                                st.error(f"Backend not reachable: {str(e)}")

    # ---------- Verify Certificate ----------
    elif selected == "Verify Certificate":
        with st.container(border=True):
            st.subheader("Verify Certificate")
            with st.form("verify_form"):
                st.info("Student Name is mandatory. Provide either Roll Number OR Date of Issue. Certificate upload is required.")
                student_name = st.text_input("Student Name")
                roll_no = st.text_input("Roll Number")
                date_of_issue = st.date_input("Date of Issue", value=None, min_value=datetime.date(1900, 1, 1), max_value=datetime.date.today())
                file = st.file_uploader("Upload Certificate File (PDF/Image)")
                submitted = st.form_submit_button("Verify Certificate")
                if submitted:
                    with st.spinner("Verifying certificate..."):
                        if not student_name:
                            st.error("Student Name is mandatory")
                        elif not (roll_no or date_of_issue):
                            st.error("Either Roll Number or Date of Issue must be provided")
                        elif not file:
                            st.error("Certificate file is mandatory for verification")
                        else:
                            data = {
                                "student_name": student_name.strip(),
                                "roll_no": roll_no.strip(),
                                "date_of_issue": str(date_of_issue)
                            }
                            files = {"file": file}
                            try:
                                r = requests.post(f"{BACKEND_URL}/verify", data=data, files=files)
                                if r.status_code in [200, 404]:
                                    cert = r.json()
                                    if cert.get("status") == "valid":
                                        st.success("Certificate Verified Successfully!")
                                        st.json(cert)
                                    else:
                                        st.error("Certificate not valid or tampered.")
                                        st.json(cert)
                                    if "debug" in cert:
                                        with st.expander("Debug Info (OCR Text)"):
                                            st.text_area("", cert["debug"].get("ocr_text",""), height=250)
                                else:
                                    st.error(r.json().get("error","Verification failed"))
                            except Exception as e:
                                st.error(f"Backend not reachable: {str(e)}")

# ================= FOOTER =================
st.markdown("<div class='footer'>Made with ❤️ by LeafCore Labs</div>", unsafe_allow_html=True)
