"""
login.py — Night's Watch
Run: streamlit run login.py
"""

import os
import streamlit as st

st.set_page_config(
    page_title="Night's Watch — Sign In",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# Hide sidebar and Streamlit chrome
st.markdown("""
<style>
[data-testid="stSidebar"]        { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }
#MainMenu, footer, header        { display: none !important; }

@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
    background: #04070f !important;
    color: #e2e8f0;
}

/* Animated grid */
body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
        linear-gradient(rgba(56,114,224,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56,114,224,0.05) 1px, transparent 1px);
    background-size: 44px 44px;
    animation: drift 24s linear infinite;
    pointer-events: none;
    z-index: 0;
}
@keyframes drift {
    from { background-position: 0 0; }
    to   { background-position: 44px 44px; }
}

/* Glow blobs */
body::after {
    content: '';
    position: fixed;
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(56,114,224,0.08) 0%, transparent 70%);
    top: -150px; left: -100px;
    pointer-events: none;
    z-index: 0;
    animation: pulse 8s ease-in-out infinite alternate;
}
@keyframes pulse {
    from { transform: scale(1);    opacity: 0.6; }
    to   { transform: scale(1.2);  opacity: 1;   }
}

/* Card */
.login-card {
    position: relative;
    z-index: 10;
    background: #0a0f1c;
    border: 1px solid #162033;
    border-radius: 22px;
    padding: 48px 42px 40px;
    box-shadow: 0 32px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(56,114,224,0.07);
    animation: rise 0.5s cubic-bezier(0.16,1,0.3,1) both;
    margin-top: 10vh;
}
@keyframes rise {
    from { opacity: 0; transform: translateY(20px); }
    to   { opacity: 1; transform: translateY(0);    }
}

.brand {
    font-family: 'Syne', sans-serif;
    font-size: 1.85rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #f1f5f9;
    margin-bottom: 4px;
}
.brand-sub {
    font-size: 0.82rem;
    color: #3d5280;
    margin-bottom: 36px;
    letter-spacing: 0.02em;
}

/* Inputs */
.stTextInput label {
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    color: #3d5280 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
}
.stTextInput > div > div > input {
    background: #060b18 !important;
    border: 1px solid #162033 !important;
    border-radius: 10px !important;
    color: #e2e8f0 !important;
    font-family: 'DM Sans', sans-serif !important;
    padding: 12px 14px !important;
    transition: border-color 0.2s !important;
}
.stTextInput > div > div > input:focus {
    border-color: #3872e0 !important;
    box-shadow: 0 0 0 3px rgba(56,114,224,0.12) !important;
}

/* Submit button */
.stFormSubmitButton > button {
    width: 100% !important;
    background: linear-gradient(135deg, #1e40af, #2563eb) !important;
    border: none !important;
    border-radius: 11px !important;
    color: #fff !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.92rem !important;
    font-weight: 600 !important;
    padding: 13px !important;
    margin-top: 8px !important;
    box-shadow: 0 4px 18px rgba(37,99,235,0.35) !important;
    transition: all 0.2s !important;
    letter-spacing: 0.01em !important;
}
.stFormSubmitButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 26px rgba(37,99,235,0.45) !important;
}

/* Google button */
.g-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    padding: 12px;
    background: #ffffff;
    border-radius: 11px;
    font-family: 'DM Sans', sans-serif;
    font-size: 0.9rem;
    font-weight: 600;
    color: #1f2937;
    cursor: pointer;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.25);
    transition: all 0.18s;
    border: none;
}
.g-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 18px rgba(0,0,0,0.3);
}

/* Divider */
.or-row {
    display: flex; align-items: center; gap: 10px;
    margin: 4px 0 20px;
}
.or-line { flex: 1; height: 1px; background: #162033; }
.or-text  { font-size: 0.72rem; color: #3d5280; letter-spacing: 0.06em; }

/* Footer */
.foot {
    text-align: center;
    font-size: 0.72rem;
    color: #1e2d4a;
    margin-top: 28px;
}
</style>
""", unsafe_allow_html=True)

# ── Session defaults ──────────────────────────────────────────────────────────
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user" not in st.session_state:
    st.session_state["user"] = None

# Already logged in → go straight to dashboard
if st.session_state["authenticated"]:
    st.switch_page("pages/dashboard.py")

# ── Google OAuth (optional) ───────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8501")

_oauth_ready = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
try:
    from streamlit_oauth import OAuth2Component
    _has_oauth = True
except ImportError:
    _has_oauth = False

# ── Layout ────────────────────────────────────────────────────────────────────
_, col, _ = st.columns([1, 1.15, 1])

with col:
    st.markdown("""
    <div class="login-card">
      <div class="brand">🛡️ Night's Watch</div>
      <div class="brand-sub">IoT Trust &amp; Drift Analytics · Eclipse Hackathon</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Google OAuth button ───────────────────────────────────────────────────
    if _oauth_ready and _has_oauth:
        oauth = OAuth2Component(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            refresh_token_endpoint="https://oauth2.googleapis.com/token",
            revoke_token_endpoint="https://oauth2.googleapis.com/revoke",
        )
        result = oauth.authorize_button(
            name="Continue with Google",
            redirect_uri=GOOGLE_REDIRECT_URI,
            scope="openid email profile",
            key="google_oauth",
            extras_params={"prompt": "select_account"},
            use_container_width=True,
            icon="https://www.google.com/favicon.ico",
        )
        if result and result.get("token"):
            import base64, json as _json
            try:
                id_token = result["token"].get("id_token", "")
                payload  = id_token.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                info     = _json.loads(base64.urlsafe_b64decode(payload))
                st.session_state["authenticated"] = True
                st.session_state["user"]          = info.get("email", "user")
                st.switch_page("pages/dashboard.py")
            except Exception:
                st.error("Google sign-in failed. Please use the form below.")

        st.markdown("""
        <div class="or-row">
          <div class="or-line"></div>
          <span class="or-text">OR</span>
          <div class="or-line"></div>
        </div>
        """, unsafe_allow_html=True)

    # ── Credentials form ──────────────────────────────────────────────────────
    with st.form("login_form"):
        username  = st.text_input("Username", placeholder="nightswatch")
        password  = st.text_input("Password", type="password", placeholder="••••••••")
        submitted = st.form_submit_button("Sign in →", use_container_width=True)

        if submitted:
            if username == "nightswatch" and password == "eclipse2024":
                st.session_state["authenticated"] = True
                st.session_state["user"]          = username
                st.switch_page("pages/dashboard.py")
            else:
                st.error("Incorrect username or password.")

    st.markdown("""
    <div class="foot">
        nightswatch &nbsp;/&nbsp; eclipse2024
    </div>
    """, unsafe_allow_html=True)