"""
login.py — Night's Watch
Run: streamlit run login.py
"""

import base64
import json as _json
import streamlit as st

st.set_page_config(
    page_title="Night's Watch — Sign In",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

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
    from { transform: scale(1);   opacity: 0.6; }
    to   { transform: scale(1.2); opacity: 1;   }
}
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
.foot {
    text-align: center;
    font-size: 0.72rem;
    color: #1e2d4a;
    margin-top: 28px;
}
.debug-box {
    background: #0d1424;
    border: 1px solid #1a3060;
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 0.78rem;
    color: #7a9cc4;
    margin-bottom: 12px;
    font-family: monospace;
}
</style>
""", unsafe_allow_html=True)

# ── Session defaults ──────────────────────────────────────────────────────────
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user" not in st.session_state:
    st.session_state["user"] = None

if st.session_state["authenticated"]:
    st.switch_page("pages/dashboard.py")

# ── Read credentials from secrets.toml ───────────────────────────────────────
try:
    GOOGLE_CLIENT_ID     = st.secrets["google"]["client_id"]
    GOOGLE_CLIENT_SECRET = st.secrets["google"]["client_secret"]
    GOOGLE_REDIRECT_URI  = st.secrets["google"]["redirect_uri"]
    _creds_ok = True
except Exception as e:
    _creds_ok = False
    _creds_error = str(e)

# ── OAuth library check ───────────────────────────────────────────────────────
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

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # ── Show credential error ─────────────────────────────────────────────────
    if not _creds_ok:
        st.error(f"❌ Could not read secrets.toml: `{_creds_error}`")
        st.markdown("""
        **Create the file** `.streamlit/secrets.toml` in your project folder:
        ```toml
        [google]
        client_id     = "YOUR_CLIENT_ID.apps.googleusercontent.com"
        client_secret = "GOCSPX-YOUR_SECRET"
        redirect_uri  = "http://localhost:8501"
        ```
        Then **restart** Streamlit (Ctrl+C and rerun).
        """)
        st.stop()

    if not _has_oauth:
        st.error("❌ `streamlit-oauth` not installed.")
        st.code('pip install streamlit-oauth', language="bash")
        st.stop()

    # ── Debug: confirm what was loaded (remove after testing) ─────────────────
    # st.markdown(
    #     f'<div class="debug-box">'
    #     f'✅ Loaded client_id: <b>{GOOGLE_CLIENT_ID[:30]}...</b><br>'
    #     f'✅ Secret length: <b>{len(GOOGLE_CLIENT_SECRET)} chars</b><br>'
    #     f'✅ Redirect URI: <b>{GOOGLE_REDIRECT_URI}</b>'
    #     f'</div>',
    #     unsafe_allow_html=True,
    # )

    # ── Real OAuth button ─────────────────────────────────────────────────────
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
        try:
            id_token = result["token"].get("id_token", "")
            payload  = id_token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            info = _json.loads(base64.urlsafe_b64decode(payload))

            st.session_state["authenticated"] = True
            st.session_state["user"]          = info.get("email", "user")
            st.session_state["user_info"]     = {
                "email":   info.get("email", ""),
                "name":    info.get("name", ""),
                "picture": info.get("picture", ""),
            }
            st.rerun()

        except Exception as ex:
            st.error(f"Token decode failed: {ex}")

    st.markdown("""
    <div class="foot">
        Sign in with any Google / Gmail account
    </div>
    """, unsafe_allow_html=True)