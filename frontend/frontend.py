import streamlit as st
import requests
import base64
from datetime import datetime
from streamlit_option_menu import option_menu
import plotly.express as px

# ===================== Page Config =====================
st.set_page_config(page_title="Pramān Cert System", page_icon="🪪", layout="wide")

# ===================== Themes =====================
dark_theme = {"bg": "#0f1116","card": "#1e2128","text": "#e0e0e0","primary": "#4ade80","secondary": "#9ca3af","button_hover": "#22c55e"}
light_theme = {"bg": "#f0f2f6","card": "#ffffff","text": "#333333","primary": "#16a34a","secondary": "#4b5563","button_hover": "#22c55e"}

# ===================== Session State Defaults =====================
if "theme" not in st.session_state: st.session_state.theme = "dark"
theme = dark_theme if st.session_state.theme=="dark" else light_theme

for key in ["token","role","user_type","user_type_selected"]:
    if key not in st.session_state:
        st.session_state[key] = None

# ===================== Custom CSS =====================
st.markdown(f"""
<style>
body {{background-color: {theme['bg']}; color: {theme['text']};}}
.stButton>button {{
    background: linear-gradient(to right, {theme['primary']}, {theme['button_hover']});
    color: white; font-weight: bold; border-radius: 12px; padding: 10px 25px; transition: 0.3s;
}}
.stButton>button:hover {{transform: scale(1.05);}}
.card {{background-color: {theme['card']}; border-radius: 15px; padding: 20px; margin-bottom: 20px; box-shadow: 0px 4px 15px rgba(0,0,0,0.3);}}
.footer {{text-align:center; margin-top:50px; font-size:0.9rem; color:{theme['secondary']};}}
</style>
""", unsafe_allow_html=True)

# ===================== Header =====================
col1, col2 = st.columns([3,1])
with col1:
    st.markdown(f"<h1 style='color:{theme['primary']};'>🪪 Pramān Certificate System</h1>", unsafe_allow_html=True)
    st.markdown(f"<p style='color:{theme['secondary']};'>Secure Blockchain-based Certificate Issuing & Verification</p>", unsafe_allow_html=True)
with col2:
    toggle = st.checkbox("Dark Mode", value=(st.session_state.theme=="dark"))
    st.session_state.theme = "dark" if toggle else "light"
    theme = dark_theme if st.session_state.theme=="dark" else light_theme

# ===================== User Type Selection =====================
if not st.session_state.user_type_selected:
    st.subheader("Who are you?")
    user_type = st.radio("Select user type", ["Admin", "Institute / Issuer", "Organisation / Verifier"])
    if st.button("Continue"):
        st.session_state.user_type = user_type
        st.session_state.user_type_selected = True

# ===================== Login / Signup Tabs =====================
if st.session_state.user_type and not st.session_state.token:
    tab = st.radio("Choose Option", ["Login", "Sign Up"])
    if tab == "Login":
        st.subheader(f"{st.session_state.user_type} Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            r = requests.post("http://127.0.0.1:5000/login",
                              json={"username": username, "password": password, "user_type": st.session_state.user_type})
            if r.status_code == 200:
                data = r.json()
                st.session_state.token = data["access_token"]
                st.session_state.role = data["role"]
                st.success(f"Logged in as {st.session_state.role}")
            else:
                st.error(r.json().get("error","Login failed"))

    elif tab == "Sign Up":
        st.subheader(f"{st.session_state.user_type} Sign Up")
        with st.form("signup_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            name = st.text_input("Full Name / Organisation Name")
            email = st.text_input("Email")
            contact = st.text_input("Contact Number")
            address = st.text_area("Address")
            designation = st.text_input("Designation / Role")
            submitted = st.form_submit_button("Sign Up")
            if submitted:
                role_type = "institute" if st.session_state.user_type=="Institute / Issuer" else "organisation"
                r = requests.post("http://127.0.0.1:5000/signup", json={
                    "username": username, "password": password, "role_type": role_type,
                    "name": name, "email": email, "contact": contact, "address": address, "designation": designation
                })
                if r.status_code == 201:
                    st.success("Account created successfully! Please login.")
                else:
                    st.error(r.json().get("error","Signup failed"))

# ===================== Role-based Views =====================
if st.session_state.token:
    if st.button("Logout"):
        st.session_state.token = None
        st.session_state.role = None
        st.session_state.user_type = None
        st.session_state.user_type_selected = False
        st.experimental_rerun = lambda: None  # no-op for compatibility
        st.experimental_rerun()  # This will not break in new Streamlit versions

    selected = option_menu(
        menu_title=None,
        options=["Dashboard", "Issue Certificate", "Verify Certificate"],
        icons=["clipboard-data","file-earmark-plus","search"],
        orientation="horizontal",
        styles={
            "container": {"padding": "0!important", "background-color": theme['card']},
            "nav-link": {"font-size": "16px", "color": theme['text']},
            "nav-link-selected": {"background-color": theme['primary'], "color":"white"},
        }
    )
    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # -------------------- Dashboard --------------------
    if selected == "Dashboard":
        st.subheader(f"{st.session_state.role.capitalize()} Dashboard")
        if st.session_state.role == "admin":
            r = requests.get("http://127.0.0.1:5000/fraud_logs", headers=headers)
            if r.status_code == 200:
                logs = r.json()
                if logs:
                    st.markdown("<div class='card'><h3>Fraud Logs</h3></div>", unsafe_allow_html=True)
                    fig = px.bar(x=[l['cert_id'] for l in logs], y=[l['tamper_score'] for l in logs],
                                 color=[l['tamper_score'] for l in logs], color_continuous_scale="reds")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No fraud logs yet.")
        else:
            st.info("Institute/Organisation dashboard coming soon...")

    # -------------------- Issue Certificate --------------------
    elif selected == "Issue Certificate" and st.session_state.role=="institute":
        st.subheader("Issue Certificate")
        file = st.file_uploader("Upload Certificate PDF/Image")
        if st.button("Issue Certificate"):
            if file:
                r = requests.post("http://127.0.0.1:5000/issue", files={"file": file}, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    st.markdown("<div class='card'><h4>Certificate Issued Successfully!</h4></div>", unsafe_allow_html=True)
                    st.write(f"Certificate ID: {data['cert_id']}")
                    st.image(base64.b64decode(data["qr_code"]), width=180)
                else:
                    st.error("Error issuing certificate")
            else:
                st.warning("Upload a certificate file")

    # -------------------- Verify Certificate --------------------
    elif selected == "Verify Certificate":
        st.subheader("Verify Certificate")
        cert_id = st.text_input("Certificate ID")
        file = st.file_uploader("Optional: Upload Certificate File")
        if st.button("Verify Certificate"):
            files = {"file": file} if file else None
            r = requests.post("http://127.0.0.1:5000/verify", json={"cert_id": cert_id})
            if r.status_code == 200:
                data = r.json()
                st.markdown("<div class='card'><h4>Verification Result</h4></div>", unsafe_allow_html=True)
                st.write(f"Status: {data['status']}")
                st.write(f"Issuer: {data['issuer']}")
                st.write(f"TX Hash: {data['tx_hash']}")
            else:
                st.error("Certificate not found or error")

# ===================== Footer =====================
st.markdown(f"<div class='footer'>Made with ❤️ by Leaf Core Labs</div>", unsafe_allow_html=True)
