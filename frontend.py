import streamlit as st
import requests
import base64
from streamlit_option_menu import option_menu

# ======================
# Page Config
# ======================
st.set_page_config(page_title="Pramān", page_icon="🛡️", layout="wide")

# ======================
# Themes
# ======================
dark_theme = {
    "bg_main": "#0f1116", "bg_sec": "#181a1f",
    "text": "#e0e0e0", "primary": "#4ade80",
    "secondary": "#9ca3af", "border": "#4ade80",
    "card": "#1e2128", "card_border": "#6b7280"
}

light_theme = {
    "bg_main": "#f0f2f6", "bg_sec": "#ffffff",
    "text": "#333333", "primary": "#16a34a",
    "secondary": "#4b5563", "border": "#16a34a",
    "card": "#f9fafb", "card_border": "#d1d5db"
}

# ======================
# Session state
# ======================
if "token" not in st.session_state: st.session_state.token = None
if "role" not in st.session_state: st.session_state.role = None
if "theme" not in st.session_state: st.session_state.theme = "dark"

# ======================
# Theme switcher
# ======================
col1, col2 = st.columns([1,0.2])
with col2:
    is_dark = st.toggle("Dark Mode", value=(st.session_state.theme=="dark"))
st.session_state.theme = "dark" if is_dark else "light"
theme = dark_theme if st.session_state.theme=="dark" else light_theme

# ======================
# Logo & Branding
# ======================
logo_path = "assets/logos/Praman_dark.png" if st.session_state.theme=="dark" else "assets/logos/Praman_light.png"
st.image(logo_path, width=220)
st.markdown(f'<div style="text-align:center;color:{theme["primary"]};font-size:2.5rem;font-weight:bold;">🛡️ Pramān</div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;color:{theme["secondary"]};font-size:1.2rem;">Certificate Verification Platform</div>', unsafe_allow_html=True)

# ======================
# Inline CSS
# ======================
st.markdown(f"""
<style>
body {{ background-color:{theme['bg_main']}; color:{theme['text']}; }}
.stTextInput>div>div>input {{
    border-radius:10px; border:1px solid {theme['border']}; padding:10px; background-color:{theme['bg_sec']}; color:{theme['text']};
}}
.stFileUploader div {{ background-color:{theme['card']}; border:1px dashed {theme['border']}; border-radius:12px; padding:15px; text-align:center; }}
.stButton>button {{
    background:linear-gradient(to right,{theme['primary']},#22c55e); color:white; border-radius:10px; padding:10px 20px; font-size:1rem; font-weight:bold; border:none;
}}
.stButton>button:hover {{ background:linear-gradient(to right,#22c55e,{theme['primary']}); transform:scale(1.05); }}
.card {{ background-color:{theme['card']}; border:1px solid {theme['card_border']}; border-radius:12px; padding:20px; margin-top:15px; box-shadow:0px 4px 15px rgba(0,0,0,0.25); }}
</style>
""", unsafe_allow_html=True)

# ======================
# API URL
# ======================
API_URL = "http://127.0.0.1:5000"

# ======================
# Navigation
# ======================
selected = option_menu(None, ["Login","Institute","Verify","Admin"],
    icons=["box-arrow-in-right","building","check-circle","person-badge"],
    orientation="horizontal",
    styles={"container":{"padding":"0!important","background-color":theme['bg_sec'],"border-radius":"10px"},
            "icon":{"color":theme['primary']},
            "nav-link":{"color":theme['text']},
            "nav-link-selected":{"background-color":theme['primary']}})

# ======================
# Views
# ======================
# Login
if selected=="Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        res = requests.post(f"{API_URL}/login", json={"username":username,"password":password})
        if res.status_code==200:
            data=res.json()
            st.session_state.token = data["access_token"]
            st.session_state.role = data["role"]
            st.success(f"✅ Logged in as {data['role']}")
        else: st.error("❌ Invalid credentials")

# Institute Dashboard
elif selected=="Institute" and st.session_state.role=="institute":
    st.subheader("🏫 Institute Dashboard - Issue Certificate")
    uploaded_file = st.file_uploader("Upload Certificate File", type=["pdf","png","jpg"])
    if uploaded_file and st.button("📜 Issue Certificate"):
        files={"file":uploaded_file}
        headers={"Authorization":f"Bearer {st.session_state.token}"}
        res=requests.post(f"{API_URL}/issue", files=files, headers=headers)
        if res.status_code==200:
            data=res.json()
            st.markdown('<div class="card">',unsafe_allow_html=True)
            st.success(f"Certificate issued with ID: {data['cert_id']}")
            st.image(base64.b64decode(data["qr_code"]), width=200, caption="Scan to Verify")
            st.markdown('</div>',unsafe_allow_html=True)
        else: st.error("❌ Failed to issue certificate")

# Verify
elif selected=="Verify":
    st.subheader("✅ Verify Certificate")
    cert_id = st.text_input("Enter Certificate ID")
    if st.button("🔍 Verify"):
        res = requests.post(f"{API_URL}/verify", json={"cert_id":cert_id})
        if res.status_code==200:
            data=res.json()
            st.markdown('<div class="card">',unsafe_allow_html=True)
            if data["status"]=="valid": st.success(f"Certificate {data['cert_id']} is VALID ✅")
            elif data["status"]=="tampered": st.error("⚠️ Certificate has been TAMPERED")
            else: st.warning("❌ Certificate not found")
            st.json(data)
            st.markdown('</div>',unsafe_allow_html=True)
        else: st.error("Verification failed")

# Admin
elif selected=="Admin" and st.session_state.role=="admin":
    st.subheader("👨‍💼 Admin Dashboard")
    cert_id = st.text_input("Enter Certificate ID to Blacklist")
    if st.button("🚫 Blacklist Certificate"):
        headers={"Authorization":f"Bearer {st.session_state.token}"}
        res=requests.post(f"{API_URL}/blacklist", json={"cert_id":cert_id}, headers=headers)
        if res.status_code==200: st.success(f"Certificate {cert_id} blacklisted successfully")
        else: st.error("Failed to blacklist certificate")

# Footer Branding
venture_logo = "assets/logos/LeafCoreLabs_dark.png" if st.session_state.theme=="dark" else "assets/logos/LeafCoreLabs_light.png"
st.markdown(f'<div style="text-align:center;margin-top:40px;"><p style="color:{theme["secondary"]};font-size:1rem;">Powered by</p></div>', unsafe_allow_html=True)
st.image(venture_logo, width=160)
st.markdown(f'<footer style="text-align:center;margin-top:20px;font-size:0.9rem;color:{theme["secondary"]};">© 2025 Pramān by LeafCore Labs • All Rights Reserved</footer>', unsafe_allow_html=True)
