"""
dashboard.py — IoT Trust & Drift Analytics System
Merged: Bell notifications + IP Block panel + Live Replay tab.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import yaml


# ═══════════════════════════════════════════════════════════════════════
#  Page config
# ═══════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="IoT Trust & Drift Analytics Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stSidebarNav"] { display: none !important; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════

COLORS = {
    "normal": "#00B050", "warning": "#FFB81C",
    "high": "#FF6B35",   "critical": "#E74C3C",
    "bg_dark": "#0E1117","card_bg": "#1C1E26",
    "text": "#FAFAFA",   "text_muted": "#8B8D97",
    "accent": "#4A9EFF",
}

SEVERITY_CONFIG = {
    "NORMAL":   {"color": COLORS["normal"],   "icon": "✅", "range": "70–100"},
    "WARNING":  {"color": COLORS["warning"],  "icon": "⚠️",  "range": "50–70"},
    "HIGH":     {"color": COLORS["high"],     "icon": "🔶", "range": "30–50"},
    "CRITICAL": {"color": COLORS["critical"], "icon": "🔴", "range": "0–30"},
}

DEVICE_NAMES = {
    "10.0.1.1": "Smart Camera",      "10.0.1.2": "Front Doorbell",
    "10.0.1.3": "Living Room Hub",   "10.0.1.4": "Smart TV",
    "10.0.1.5": "Baby Monitor",      "10.0.2.1": "Kitchen Plug",
    "10.0.2.2": "Garage Door",       "10.0.2.3": "Garden Sensor",
    "10.0.2.4": "Solar Controller",  "10.0.2.5": "Pool Monitor",
    "10.0.3.1": "Bedroom Speaker",   "10.0.3.2": "Study Laptop",
    "10.0.3.3": "NAS Drive",         "10.0.3.4": "Print Server",
    "10.0.3.5": "Media Server",      "10.0.4.1": "Smart Lock",
    "10.0.4.2": "Motion Sensor",     "10.0.4.3": "HVAC Controller",
    "10.0.4.4": "Alarm Panel",       "10.0.4.5": "Irrigation System",
    "10.0.5.1": "IP Camera Alpha",   "10.0.5.2": "IP Camera Beta",
    "10.0.5.3": "IP Camera Gamma",   "10.0.5.4": "Smart Thermostat A",
    "10.0.5.5": "Smart Thermostat B","192.168.50.21": "Smart Thermostat C",
}

def get_device_name(device_id: str) -> str:
    return DEVICE_NAMES.get(device_id, device_id)


# ═══════════════════════════════════════════════════════════════════════
#  Session state init
# ═══════════════════════════════════════════════════════════════════════

def _init_session():
    defaults = {
        "notifications": [], "notif_panel_open": False, "notif_read_count": 0,
        "blocked_ips": {},          # {ip: {name, reason, blocked_at, trust_score}}
        "block_panel_open": False,
        "selected_device": None, "show_detail": False, "show_evidence": False,
        "notif_open": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_session()


# ═══════════════════════════════════════════════════════════════════════
#  IP Block helpers
# ═══════════════════════════════════════════════════════════════════════

def block_ip(device_id: str, name: str, reason: str, trust_score: float):
    st.session_state["blocked_ips"][device_id] = {
        "name":        name,
        "reason":      reason,
        "blocked_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "trust_score": trust_score,
    }

def unblock_ip(device_id: str):
    st.session_state["blocked_ips"].pop(device_id, None)

def is_blocked(device_id: str) -> bool:
    return device_id in st.session_state["blocked_ips"]

def generate_firewall_script(blocked: dict) -> str:
    """Generate iptables + Windows Firewall commands for all blocked IPs."""
    lines = [
        "#!/bin/bash",
        "# Night's Watch — Auto-generated IP Block Script",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "# Apply with: sudo bash block_ips.sh",
        "",
        "# ── Linux (iptables) ──────────────────────────────────────",
    ]
    for ip, info in blocked.items():
        lines.append(f"# {info['name']} | Score: {info['trust_score']} | {info['reason']}")
        lines.append(f"iptables -A INPUT  -s {ip} -j DROP")
        lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        lines.append("")

    lines += [
        "",
        "# ── Windows (PowerShell — run as Administrator) ───────────",
    ]
    for ip, info in blocked.items():
        lines.append(f"# {info['name']}")
        lines.append(
            f'New-NetFirewallRule -DisplayName "NW_Block_{ip}" '
            f'-Direction Inbound  -RemoteAddress {ip} -Action Block'
        )
        lines.append(
            f'New-NetFirewallRule -DisplayName "NW_Block_{ip}_out" '
            f'-Direction Outbound -RemoteAddress {ip} -Action Block'
        )
        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
#  Notification helpers
# ═══════════════════════════════════════════════════════════════════════

def get_drift_notifications(results: Optional[dict]) -> List[Dict[str, Any]]:
    if not results:
        return []
    notifications = []
    order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NORMAL": 3}
    for dev_id, dev_data in results.get("devices", {}).items():
        history = dev_data.get("history", [])
        if not history:
            continue
        last = history[-1]
        drift     = last.get("drift_confirmed", False)
        score     = last.get("trust_score", 100)
        severity  = last.get("severity", "NORMAL")

        # Include device if drift confirmed OR flatness detected
        flatness = last.get("flatness_drift", False)
        if not drift and not flatness and score >= 70:
            continue

        sigs = []
        if last.get("adwin_drift"):    sigs.append("ADWIN")
        if last.get("chi_drift"):      sigs.append("Chi²")
        if last.get("disagree_drift"): sigs.append("Disagree")
        if last.get("flatness_drift"): sigs.append("🧊 Frozen Sensor")

        notifications.append({
            "device_id": dev_id,
            "device_name": get_device_name(dev_id),
            "trust_score": score,
            "severity": severity,
            "drift_confirmed": drift,
            "signals_fired": sigs,
            "drift_factor": last.get("drift_factor", 1.0),
            "anomaly_score": last.get("anomaly_score", 0.0),
            "total_drift_windows": sum(1 for h in history if h.get("drift_confirmed")),
            "window": last.get("window", 0),
        })
    notifications.sort(key=lambda n: (order.get(n["severity"], 9), n["trust_score"]))
    return notifications


# ═══════════════════════════════════════════════════════════════════════
#  CSS
# ═══════════════════════════════════════════════════════════════════════

def inject_custom_css() -> None:
    st.markdown("""
    <style>
    .block-container { padding-top: 1.5rem; }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1C1E26 0%, #252830 100%);
        border-radius: 16px; padding: 1.4rem 1.6rem;
        border: 1px solid #2A2D37;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,0,0,0.35); }
    .metric-value { font-size: 2.4rem; font-weight: 800; line-height: 1.1;
                    margin-bottom: 0.3rem; letter-spacing: -0.5px; }
    .metric-label { font-size: 0.85rem; color: #8B8D97; text-transform: uppercase;
                    letter-spacing: 1px; font-weight: 600; }

    /* Severity badges */
    .severity-badge { display: inline-block; padding: 4px 14px; border-radius: 20px;
                      font-weight: 700; font-size: 0.75rem; letter-spacing: 0.8px;
                      text-transform: uppercase; }
    .badge-normal   { background:#00B05022; color:#00B050; border:1px solid #00B05044; }
    .badge-warning  { background:#FFB81C22; color:#FFB81C; border:1px solid #FFB81C44; }
    .badge-high     { background:#FF6B3522; color:#FF6B35; border:1px solid #FF6B3544; }
    .badge-critical { background:#E74C3C22; color:#E74C3C; border:1px solid #E74C3C44; }

    /* Signal indicators */
    .signal-active   { color:#00B050; font-weight:700; }
    .signal-inactive { color:#555; }

    /* Header */
    .dashboard-header {
        background: linear-gradient(135deg, #141620 0%, #1a1f30 100%);
        padding: 1.5rem 2rem; border-radius: 16px;
        border: 1px solid #2A2D37; margin-bottom: 1.5rem;
    }
    .dashboard-title {
        font-size: 1.8rem; font-weight: 800;
        background: linear-gradient(135deg, #4A9EFF, #7C5CFC);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0;
    }
    .dashboard-subtitle { font-size: 0.95rem; color: #8B8D97; margin: 0.3rem 0 0 0; }

    /* Expander */
    .stExpander { border:1px solid #2A2D37 !important; border-radius:12px !important; }
    .device-score { font-size:1.3rem; font-weight:800; }

    /* Bell + block notification styles */
    .bell-btn-active {
        position:relative; display:inline-flex; align-items:center; gap:8px;
        background:linear-gradient(135deg,#2a1a1a,#3a1f1f);
        border:1px solid #E74C3C66; border-radius:12px; padding:10px 16px;
        font-size:1.5rem; animation:bellPulse 1.6s ease-in-out infinite;
    }
    .bell-badge {
        position:absolute; top:-6px; right:-6px;
        background:#E74C3C; color:#fff; font-size:0.65rem; font-weight:800;
        min-width:20px; height:20px; border-radius:10px;
        display:flex; align-items:center; justify-content:center;
        padding:0 4px; border:2px solid #0E1117;
        animation:badgePop 0.4s cubic-bezier(0.34,1.56,0.64,1) both;
    }
    @keyframes bellPulse {
        0%,100%{box-shadow:0 0 0 0 rgba(231,76,60,0.0);}
        40%{box-shadow:0 0 0 8px rgba(231,76,60,0.25);}
        70%{box-shadow:0 0 0 14px rgba(231,76,60,0.08);}
    }
    @keyframes badgePop {
        0%{transform:scale(0);opacity:0;}
        100%{transform:scale(1);opacity:1;}
    }

    /* Block panel */
    .block-panel {
        background:linear-gradient(160deg,#0f1a10 0%,#121f14 100%);
        border:1px solid #2d6a3044; border-radius:16px;
        padding:1.2rem 1.4rem; margin-bottom:1.2rem;
        animation:slideDown 0.3s ease both;
    }
    .blocked-row {
        background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.2);
        border-left:3px solid #E74C3C; border-radius:8px;
        padding:10px 14px; margin-bottom:6px;
        display:flex; align-items:center; justify-content:space-between;
    }
    .blocked-tag {
        display:inline-block; padding:2px 8px; border-radius:4px;
        background:rgba(239,68,68,0.15); color:#E74C3C;
        font-size:0.65rem; font-weight:800; letter-spacing:0.06em;
    }

    /* Notif panel */
    .notif-panel {
        background:linear-gradient(160deg,#1a1d2a 0%,#1f2235 100%);
        border:1px solid #E74C3C44; border-radius:16px;
        padding:1.2rem 1.4rem; margin-bottom:1.2rem;
        animation:slideDown 0.3s ease both;
    }
    .notif-item {
        background:rgba(231,76,60,0.06); border:1px solid #E74C3C33;
        border-left:3px solid #E74C3C; border-radius:10px;
        padding:0.75rem 1rem; margin-bottom:0.6rem; transition:background 0.2s;
    }
    .notif-item:hover{background:rgba(231,76,60,0.12);}
    @keyframes slideDown {
        from{opacity:0;transform:translateY(-12px);}
        to{opacity:1;transform:translateY(0);}
    }
    </style>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
#  Header — bell + block button side by side
# ═══════════════════════════════════════════════════════════════════════

def render_header(notifications: List[Dict[str, Any]]) -> None:
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    n_alerts  = len(notifications)
    n_blocked = len(st.session_state["blocked_ips"])

    left_col, bell_col, block_col = st.columns([7, 1, 1])

    with left_col:
        st.markdown(f"""
        <div class="dashboard-header">
            <p class="dashboard-title">🔒 IoT Trust &amp; Drift Analytics</p>
            <p class="dashboard-subtitle">
                Real-Time Device Trustworthiness Monitoring &nbsp;·&nbsp; {now}
            </p>
        </div>
        """, unsafe_allow_html=True)

    # ── Bell button ──────────────────────────────────────────────
    with bell_col:
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        bell_label = f"🔔 {n_alerts}" if n_alerts > 0 else "🔔"
        bell_open  = st.session_state.get("notif_panel_open", False)
        if st.button(
            "✕ Alerts" if bell_open else bell_label,
            key="bell_btn",
            type="secondary" if bell_open else ("primary" if n_alerts > 0 else "secondary"),
            use_container_width=True,
            help=f"{n_alerts} drift alert{'s' if n_alerts != 1 else ''}",
        ):
            st.session_state["notif_panel_open"] = not bell_open
            st.session_state["block_panel_open"] = False
            st.rerun()

    # ── Block button ─────────────────────────────────────────────
    with block_col:
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        block_open = st.session_state.get("block_panel_open", False)
        block_label = f"🚫 {n_blocked}" if n_blocked > 0 else "🚫 Block"
        if st.button(
            "✕ Blocklist" if block_open else block_label,
            key="block_btn",
            type="secondary" if block_open else ("primary" if n_blocked > 0 else "secondary"),
            use_container_width=True,
            help=f"Manage blocked IPs ({n_blocked} blocked)",
        ):
            st.session_state["block_panel_open"] = not block_open
            st.session_state["notif_panel_open"] = False
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════
#  Notification panel
# ═══════════════════════════════════════════════════════════════════════

def render_notification_panel(notifications: List[Dict[str, Any]]) -> None:
    if not st.session_state.get("notif_panel_open", False):
        return

    sev_colors = {"CRITICAL":"#E74C3C","HIGH":"#FF6B35","WARNING":"#FFB81C","NORMAL":"#00B050"}
    bg_colors  = {"CRITICAL":"rgba(231,76,60,0.07)","HIGH":"rgba(255,107,53,0.07)",
                  "WARNING":"rgba(255,184,28,0.05)","NORMAL":"rgba(0,176,80,0.05)"}

    ts    = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    count = len(notifications)

    st.markdown(f"""
    <div style="display:flex;align-items:baseline;justify-content:space-between;
                margin-bottom:1rem;padding-bottom:0.6rem;
                border-bottom:1px solid rgba(255,255,255,0.07);">
        <span style="font-size:1.1rem;font-weight:800;color:#FAFAFA;">
            🔔 {count} Drift Alert{'s' if count != 1 else ''}
        </span>
        <span style="font-size:0.75rem;color:#555;">{ts}</span>
    </div>
    """, unsafe_allow_html=True)

    if not notifications:
        st.success("✅ All devices are behaving normally.")
        return

    for n in notifications:
        sev   = n["severity"]
        color = sev_colors.get(sev, "#E74C3C")
        bg    = bg_colors.get(sev, "rgba(231,76,60,0.07)")
        sigs  = " · ".join(f"<b>{s}</b>" for s in n["signals_fired"]) if n["signals_fired"] else "—"
        blocked_tag = (
            '<span style="color:#ef4444;font-size:0.68rem;background:rgba(239,68,68,0.15);'
            'padding:1px 7px;border-radius:4px;font-weight:700;">BLOCKED</span>'
            if is_blocked(n["device_id"]) else ""
        )

        c_info, c_action = st.columns([5, 1])
        with c_info:
            st.markdown(f"""
            <div style="background:{bg};border:1px solid {color}33;
                        border-left:3px solid {color};border-radius:10px;
                        padding:10px 14px;margin-bottom:4px;">
                <div style="font-weight:700;font-size:0.9rem;color:#FAFAFA;">
                    {n['device_name']} {blocked_tag}
                    <span style="font-size:0.7rem;color:#8B8D97;font-weight:400;
                                 font-family:monospace;"> {n['device_id']}</span>
                </div>
                <div style="font-size:0.76rem;color:#8B8D97;margin-top:3px;">
                    Signals: {sigs} · Factor: <b style="color:#ccc">{n['drift_factor']:.2f}x</b>
                    · Trust: <b style="color:{color}">{n['trust_score']:.0f}</b>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with c_action:
            st.markdown("<div style='margin-top:4px'></div>", unsafe_allow_html=True)
            if is_blocked(n["device_id"]):
                if st.button("Unblock", key=f"notif_unblock_{n['device_id']}",
                             use_container_width=True):
                    unblock_ip(n["device_id"])
                    st.rerun()
            else:
                if st.button("🚫 Block", key=f"notif_block_{n['device_id']}",
                             type="primary", use_container_width=True):
                    block_ip(
                        n["device_id"], n["device_name"],
                        f"Drift confirmed · Signals: {', '.join(n['signals_fired']) or 'multiple'}",
                        n["trust_score"],
                    )
                    st.rerun()


# ═══════════════════════════════════════════════════════════════════════
#  Block management panel
# ═══════════════════════════════════════════════════════════════════════

def render_block_panel(notifications: List[Dict[str, Any]]) -> None:
    if not st.session_state.get("block_panel_open", False):
        return

    blocked   = st.session_state["blocked_ips"]
    all_alert = {n["device_id"]: n for n in notifications}

    st.markdown("""
    <div style="font-size:1.1rem;font-weight:800;color:#FAFAFA;
                margin-bottom:4px;">🚫 IP Block Manager</div>
    <div style="font-size:0.8rem;color:#8B8D97;margin-bottom:16px;">
        Block flagged devices from the network. Download the generated firewall
        script and run it on your router / Linux host.
    </div>
    """, unsafe_allow_html=True)

    # ── Section 1: Currently blocked ────────────────────────────
    st.markdown("#### 🔴 Currently Blocked")
    if not blocked:
        st.info("No IPs blocked yet. Block flagged devices from the alerts panel or below.")
    else:
        for ip, info in list(blocked.items()):
            c1, c2, c3 = st.columns([3, 3, 1])
            with c1:
                st.markdown(f"""
                <div style="padding:6px 0;">
                    <span style="font-weight:700;color:#FAFAFA;">{info['name']}</span>
                    <span class="blocked-tag" style="margin-left:6px;">BLOCKED</span><br>
                    <code style="font-size:0.72rem;color:#8B8D97;">{ip}</code>
                </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
                <div style="padding:6px 0;font-size:0.78rem;color:#8B8D97;">
                    Trust: <b style="color:#E74C3C">{info['trust_score']:.0f}</b><br>
                    {info['reason']}<br>
                    <span style="font-size:0.68rem;">{info['blocked_at']}</span>
                </div>
                """, unsafe_allow_html=True)
            with c3:
                st.markdown("<div style='margin-top:6px'></div>", unsafe_allow_html=True)
                if st.button("Unblock", key=f"unblock_{ip}", use_container_width=True):
                    unblock_ip(ip)
                    st.rerun()

        st.markdown("")

        # Firewall script download
        script = generate_firewall_script(blocked)
        col_dl1, col_dl2, _ = st.columns([2, 2, 3])
        with col_dl1:
            st.download_button(
                label="⬇️ Download Linux Script (.sh)",
                data=script,
                file_name="block_ips.sh",
                mime="text/plain",
                key="dl_sh",
                use_container_width=True,
            )
        with col_dl2:
            st.download_button(
                label="⬇️ Download JSON Blocklist",
                data=json.dumps(blocked, indent=2),
                file_name="blocklist.json",
                mime="application/json",
                key="dl_json",
                use_container_width=True,
            )

        with st.expander("👁️ Preview firewall commands"):
            st.code(script, language="bash")

    st.markdown("---")

    # ── Section 2: Quick-block flagged devices ───────────────────
    st.markdown("#### ⚡ Quick Block — Flagged Devices")
    unblocked_alerts = [n for n in notifications if not is_blocked(n["device_id"])]

    if not unblocked_alerts:
        st.success("✅ All currently flagged devices are already blocked.")
    else:
        sev_c = {"CRITICAL":"#E74C3C","HIGH":"#FF6B35","WARNING":"#FFB81C"}

        if st.button(f"🚫 Block All {len(unblocked_alerts)} Flagged Devices",
                     type="primary", key="block_all"):
            for n in unblocked_alerts:
                block_ip(
                    n["device_id"], n["device_name"],
                    f"Drift confirmed · Signals: {', '.join(n['signals_fired']) or 'multiple'}",
                    n["trust_score"],
                )
            st.rerun()

        st.markdown("<div style='margin:8px 0'></div>", unsafe_allow_html=True)

        for n in unblocked_alerts:
            color = sev_c.get(n["severity"], "#FFB81C")
            sigs  = ", ".join(n["signals_fired"]) if n["signals_fired"] else "multiple signals"
            c1, c2 = st.columns([5, 1])
            with c1:
                st.markdown(f"""
                <div style="background:rgba(0,0,0,0.2);border:1px solid {color}33;
                            border-left:3px solid {color};border-radius:8px;
                            padding:8px 12px;margin-bottom:4px;">
                    <span style="font-weight:700;color:#FAFAFA;">{n['device_name']}</span>
                    <span style="font-size:0.7rem;color:#8B8D97;font-family:monospace;
                                 margin-left:8px;">{n['device_id']}</span><br>
                    <span style="font-size:0.75rem;color:#8B8D97;">
                        Trust: <b style="color:{color}">{n['trust_score']:.0f}</b>
                        &nbsp;·&nbsp; {sigs}
                    </span>
                </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown("<div style='margin-top:4px'></div>", unsafe_allow_html=True)
                if st.button("Block", key=f"qblock_{n['device_id']}",
                             type="primary", use_container_width=True):
                    block_ip(
                        n["device_id"], n["device_name"],
                        f"Drift confirmed · Signals: {sigs}",
                        n["trust_score"],
                    )
                    st.rerun()


# ═══════════════════════════════════════════════════════════════════════
#  Data loading
# ═══════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=0)
def load_results(path: str = "results.json") -> Optional[dict]:
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


@st.cache_data(ttl=60)
def load_config(path: str = "config.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError:
        return {}


def load_evidence_report(device_id: str, window_index: int) -> Optional[dict]:
    safe_id  = device_id.replace(".", "_").replace(":", "_")
    filename = f"results/{safe_id}_window_{window_index}.json"
    if not Path(filename).exists():
        return None
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def build_device_dataframe(results: dict) -> pd.DataFrame:
    devices = results.get("devices", {})
    if not devices:
        return pd.DataFrame()
    rows = []
    for dev_id, dev in devices.items():
        severity = dev.get("severity", "UNKNOWN")
        score    = dev.get("final_score", 0)
        rows.append({
            "Device":    get_device_name(dev_id),
            "Device IP": dev_id,
            "Score":     score,
            "Severity":  severity,
            "Blocked":   "🚫 Yes" if is_blocked(dev_id) else "—",
            "Min Score": dev.get("min_score", score),
            "Alerts":    dev.get("num_alerts", 0),
            "Windows":   dev.get("monitoring_windows", 0),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("Score", ascending=True).reset_index(drop=True)
    return df


def get_device_history(results: dict, device_id: str) -> List[dict]:
    return results.get("devices", {}).get(device_id, {}).get("history", [])


# ═══════════════════════════════════════════════════════════════════════
#  Metric cards
# ═══════════════════════════════════════════════════════════════════════

def render_metric_card(label, value, color=COLORS["accent"], suffix=""):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" style="color:{color};">{value}{suffix}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def render_metrics_row(summary: dict, device_df: pd.DataFrame) -> None:
    total     = summary.get("total_devices", 0)
    normal    = summary.get("normal", 0)
    warning   = summary.get("warning", 0)
    high_risk = summary.get("high_risk", 0)
    critical  = summary.get("critical", 0)
    avg_trust = summary.get("avg_trust", 0)
    n_blocked = len(st.session_state["blocked_ips"])

    if avg_trust >= 70:   avg_color = COLORS["normal"]
    elif avg_trust >= 50: avg_color = COLORS["warning"]
    elif avg_trust >= 30: avg_color = COLORS["high"]
    else:                 avg_color = COLORS["critical"]

    c1,c2,c3,c4,c5,c6,c7 = st.columns(7)
    with c1: render_metric_card("Total Devices",      total,                COLORS["accent"])
    with c2: render_metric_card("✅ Normal (≥70)",    normal,               COLORS["normal"])
    with c3: render_metric_card("⚠️ Warning (50-70)", warning,              COLORS["warning"])
    with c4: render_metric_card("🔶 High (30-50)",    high_risk,            COLORS["high"])
    with c5: render_metric_card("🔴 Critical (<30)",  critical,             COLORS["critical"])
    with c6: render_metric_card("Avg Trust Score",    f"{avg_trust:.1f}",   avg_color, "/100")
    with c7: render_metric_card("🚫 Blocked IPs",     n_blocked,            "#a855f7")


# ═══════════════════════════════════════════════════════════════════════
#  Trust timeline
# ═══════════════════════════════════════════════════════════════════════

def render_trust_timeline(results: dict, selected_devices: List[str]) -> None:
    fig = go.Figure()
    for y0,y1,c in [(70,100,COLORS["normal"]),(50,70,COLORS["warning"]),
                    (30,50,COLORS["high"]),(0,30,COLORS["critical"])]:
        fig.add_hrect(y0=y0,y1=y1,fillcolor=c,opacity=0.08,line_width=0,layer="below")
    for y,lbl in [(70,"Normal"),(50,"Warning"),(30,"Critical")]:
        fig.add_hline(y=y,line_dash="dot",line_color="#444",line_width=1,opacity=0.5,
                      annotation_text=lbl,annotation_position="right",
                      annotation_font_color="#666",annotation_font_size=10)

    palette      = px.colors.qualitative.Set2 + px.colors.qualitative.Pastel1
    devices_data = results.get("devices", {})
    for idx, dev_id in enumerate(selected_devices):
        history = devices_data.get(dev_id, {}).get("history", [])
        if not history:
            continue
        blocked_sfx = " 🚫" if is_blocked(dev_id) else ""
        fig.add_trace(go.Scatter(
            x=[h["window"] for h in history],
            y=[h["trust_score"] for h in history],
            mode="lines", name=get_device_name(dev_id) + blocked_sfx,
            line=dict(width=2.5, color=palette[idx % len(palette)],
                      dash="dot" if is_blocked(dev_id) else "solid"),
            hovertemplate=(f"<b>{dev_id}</b><br>Window: %{{x}}<br>"
                           f"Trust: %{{y:.1f}}<extra></extra>"),
        ))
    fig.update_layout(
        title=dict(text="Trust Score Timeline",font=dict(size=18)),
        xaxis_title="Window Index", yaxis_title="Trust Score",
        yaxis=dict(range=[0,105],dtick=10), template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=480,
        legend=dict(orientation="h",yanchor="bottom",y=1.02,
                    xanchor="right",x=1,font=dict(size=11)),
        margin=dict(l=50,r=30,t=60,b=50), hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════
#  Device table
# ═══════════════════════════════════════════════════════════════════════

def severity_badge(severity: str) -> str:
    cls  = f"badge-{severity.lower()}"
    icon = SEVERITY_CONFIG.get(severity,{}).get("icon","❓")
    return f'<span class="severity-badge {cls}">{icon} {severity}</span>'


def render_device_table(device_df: pd.DataFrame, notifications: List[Dict]) -> None:
    if device_df.empty:
        st.info("No device data available.")
        return
    st.markdown("### 📋 Device Status")
    notif_map = {n["device_id"]: n for n in notifications}

    for _, row in device_df.iterrows():
        dev_name = row["Device"]
        dev_id   = row["Device IP"]
        score    = row["Score"]
        severity = row["Severity"]
        sev_cfg  = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["CRITICAL"])
        blocked  = is_blocked(dev_id)

        blocked_tag = " 🚫 BLOCKED" if blocked else ""
        with st.expander(
            f"{sev_cfg['icon']}  **{dev_name}**{blocked_tag}  —  "
            f"Score: **{score:.0f}**  |  {severity}  |  Alerts: {row['Alerts']}",
            expanded=False,
        ):
            c1,c2,c3,c4,c5 = st.columns([2,1.5,1.5,1.5,1.5])
            with c1: st.markdown(f"**Device:** `{dev_id}`")
            with c2:
                st.markdown(
                    f"<span class='device-score' style='color:{sev_cfg['color']}'>"
                    f"{score:.1f}</span> / 100", unsafe_allow_html=True)
            with c3: st.markdown(severity_badge(severity), unsafe_allow_html=True)
            with c4: st.metric("Min Score", f"{row['Min Score']:.1f}")
            with c5: st.metric("Windows", row["Windows"])

            bc1,bc2,bc3 = st.columns(3)
            with bc1:
                if st.button("📊 View Details", key=f"detail_{dev_id}"):
                    st.session_state["selected_device"] = dev_id
                    st.session_state["show_detail"]     = True
            with bc2:
                if st.button("📄 View Evidence", key=f"evidence_{dev_id}"):
                    st.session_state["selected_device"] = dev_id
                    st.session_state["show_evidence"]   = True
            with bc3:
                if blocked:
                    if st.button("✅ Unblock", key=f"tbl_unblock_{dev_id}",
                                 use_container_width=True):
                        unblock_ip(dev_id)
                        st.rerun()
                elif dev_id in notif_map:
                    n = notif_map[dev_id]
                    if st.button("🚫 Block IP", key=f"tbl_block_{dev_id}",
                                 type="primary", use_container_width=True):
                        sigs = ", ".join(n["signals_fired"]) or "multiple signals"
                        block_ip(dev_id, dev_name,
                                 f"Drift confirmed · Signals: {sigs}", score)
                        st.rerun()


# ═══════════════════════════════════════════════════════════════════════
#  Device detail
# ═══════════════════════════════════════════════════════════════════════

def render_device_detail(results: dict, device_id: str) -> None:
    st.markdown(f"### 🔍 Device Detail: `{device_id}`")
    dev_data = results.get("devices",{}).get(device_id,{})
    if not dev_data:
        st.warning(f"No data for device {device_id}"); return
    history = dev_data.get("history",[])
    if not history:
        st.info("No monitoring history."); return

    final_score = dev_data.get("final_score",0)
    severity    = dev_data.get("severity","UNKNOWN")
    sev_cfg     = SEVERITY_CONFIG.get(severity,SEVERITY_CONFIG["CRITICAL"])

    mc1,mc2,mc3,mc4,mc5 = st.columns(5)
    with mc1: render_metric_card("Current Score",f"{final_score:.1f}",sev_cfg["color"],"/100")
    with mc2: render_metric_card("Severity",f"{sev_cfg['icon']} {severity}",sev_cfg["color"])
    with mc3:
        scores = [h["trust_score"] for h in history]
        trend  = scores[-1]-scores[0] if len(scores)>1 else 0
        arrow  = "↓" if trend<-5 else ("↑" if trend>5 else "→")
        render_metric_card("Trend",f"{arrow} {trend:+.1f}",sev_cfg["color"])
    with mc4: render_metric_card("Min Score",f"{dev_data.get('min_score',0):.1f}",COLORS["critical"])
    with mc5:
        action = {"NORMAL":"Monitor","WARNING":"Investigate","HIGH":"Isolate","CRITICAL":"Block"}.get(severity,"Monitor")
        render_metric_card("Action",action,sev_cfg["color"])

    if is_blocked(device_id):
        info = st.session_state["blocked_ips"][device_id]
        st.error(f"🚫 **This IP is blocked** — since {info['blocked_at']} · Reason: {info['reason']}")

    st.markdown("---")

    windows      = [h["window"]      for h in history]
    trust_scores = [h["trust_score"] for h in history]
    anomaly_sc   = [h.get("anomaly_score",0) for h in history]
    if_sc        = [h.get("if_score",0)      for h in history]
    hst_sc       = [h.get("hst_score",0)     for h in history]
    drift_facs   = [h.get("drift_factor",1.0) for h in history]

    # Trust timeline
    fig = go.Figure()
    for y0,y1,c in [(70,100,COLORS["normal"]),(50,70,COLORS["warning"]),
                    (30,50,COLORS["high"]),(0,30,COLORS["critical"])]:
        fig.add_hrect(y0=y0,y1=y1,fillcolor=c,opacity=0.07,line_width=0)
    fig.add_trace(go.Scatter(x=windows,y=trust_scores,mode="lines+markers",
        line=dict(width=3,color=COLORS["accent"]),marker=dict(size=4),
        name="Trust Score",fill="tozeroy",fillcolor="rgba(74,158,255,0.08)"))
    fig.update_layout(title="Trust Score Over Time",xaxis_title="Window",
        yaxis_title="Trust Score",yaxis=dict(range=[0,105]),
        template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",height=350,margin=dict(l=50,r=30,t=50,b=40))
    st.plotly_chart(fig, use_container_width=True)

    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(x=windows,y=anomaly_sc,mode="lines",name="Combined",
        line=dict(width=2.5,color="#FF6B6B")))
    fig2.add_trace(go.Scatter(x=windows,y=if_sc,mode="lines",name="Isolation Forest",
        line=dict(width=1.5,color="#4ECDC4",dash="dot")))
    fig2.add_trace(go.Scatter(x=windows,y=hst_sc,mode="lines",name="Half-Space Trees",
        line=dict(width=1.5,color="#FFE66D",dash="dot")))
    fig2.add_hline(y=0.15,line_dash="dash",line_color="#666",
        annotation_text="Threshold",annotation_font_color="#888")
    fig2.update_layout(title="Anomaly Scores",xaxis_title="Window",
        yaxis_title="Score (0–1)",yaxis=dict(autorange=True, rangemode="tozero"),
        template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",height=300,
        margin=dict(l=50,r=30,t=50,b=40),legend=dict(orientation="h",y=1.12))
    st.plotly_chart(fig2, use_container_width=True)

    drift_data = [h.get("drift_confirmed",False) for h in history]
    col_d1,col_d2 = st.columns(2)
    with col_d1:
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(x=windows,y=[1 if d else 0 for d in drift_data],
            mode="lines",line=dict(width=2,color="#FF6B35"),
            fill="tozeroy",fillcolor="rgba(255,107,53,0.15)"))
        fig3.update_layout(title="Drift Confirmation",
            yaxis=dict(tickvals=[0,1],ticktext=["No","Yes"]),
            template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",height=220,margin=dict(l=50,r=20,t=50,b=30))
        st.plotly_chart(fig3, use_container_width=True)
    with col_d2:
        fig4 = go.Figure()
        fig4.add_trace(go.Scatter(x=windows,y=drift_facs,mode="lines",
            line=dict(width=2,color="#7C5CFC"),
            fill="tozeroy",fillcolor="rgba(124,92,252,0.12)"))
        fig4.update_layout(title="Drift Factor",yaxis=dict(range=[0.9,2.1]),
            template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",height=220,margin=dict(l=50,r=20,t=50,b=30))
        st.plotly_chart(fig4, use_container_width=True)

    st.markdown("#### 🚦 Drift Signal Status (Latest Window)")
    last_h   = history[-1]
    sig_cols = st.columns(4)
    for col,(label,key) in zip(sig_cols,[("ADWIN","adwin_drift"),
                                          ("Chi-Squared","chi_drift"),
                                          ("Model Disagreement","disagree_drift"),
                                          ("Frozen Sensor","flatness_drift")]):
        active = last_h.get(key,False)
        cls    = "signal-active" if active else "signal-inactive"
        icon   = "🔴" if active else "🟢"
        with col:
            st.markdown(
                f"<div class='metric-card' style='text-align:center;'>"
                f"<span class='{cls}' style='font-size:1.3rem;'>{icon} {label}</span><br>"
                f"<span style='font-size:0.85rem;color:#8B8D97;'>"
                f"{'ACTIVE' if active else 'Inactive'}</span></div>",
                unsafe_allow_html=True)

    st.markdown("#### 🔀 Model Disagreement: IF vs HST Scores")
    fig_md = go.Figure()
    fig_md.add_trace(go.Scatter(x=windows,y=if_sc,mode="lines",
        name="Isolation Forest (frozen)",line=dict(width=2.5,color="#4ECDC4")))
    fig_md.add_trace(go.Scatter(x=windows,y=hst_sc,mode="lines",
        name="Half-Space Trees (adaptive)",line=dict(width=2.5,color="#FFE66D")))
    for w,dis in zip(windows,[h.get("disagree_drift",False) for h in history]):
        if dis:
            fig_md.add_vrect(x0=w-0.5,x1=w+0.5,
                fillcolor="rgba(255,107,53,0.15)",line_width=0,layer="below")
    fig_md.update_layout(xaxis_title="Window",yaxis_title="Score (0–1)",
        yaxis=dict(range=[0,1.05]),template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
        height=300,margin=dict(l=50,r=30,t=30,b=40),
        legend=dict(orientation="h",y=1.12))
    st.plotly_chart(fig_md, use_container_width=True)
    st.caption("Orange shaded = model disagreement windows.")

    all_violations: List[str] = []
    for h in history: all_violations.extend(h.get("policy_violations",[]))
    if all_violations:
        st.markdown("#### 🛡️ Policy Violations")
        vc: Dict[str,int] = {}
        for v in all_violations:
            k=v.split("(")[0].strip(); vc[k]=vc.get(k,0)+1
        v_df = pd.DataFrame([{"Rule":k,"Count":v}
                              for k,v in sorted(vc.items(),key=lambda x:-x[1])])
        fig_v = px.bar(v_df,x="Rule",y="Count",color="Count",
            color_continuous_scale=["#FFB81C","#E74C3C"])
        fig_v.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",height=260,
            margin=dict(l=50,r=20,t=30,b=60),showlegend=False)
        st.plotly_chart(fig_v, use_container_width=True)
    else:
        st.success("No policy violations for this device.")

    with st.expander("📊 Full Window History",expanded=False):
        hist_df = pd.DataFrame(history)
        if not hist_df.empty:
            disp_cols = [c for c in ["window","trust_score","severity","anomaly_score",
                "adwin_drift","chi_drift","disagree_drift","drift_confirmed",
                "drift_factor","policy_violations"] if c in hist_df.columns]
            st.dataframe(hist_df[disp_cols],use_container_width=True,height=400)


# ═══════════════════════════════════════════════════════════════════════
#  Evidence viewer
# ═══════════════════════════════════════════════════════════════════════

def render_evidence_viewer(results: dict, device_id: str) -> None:
    st.markdown(f"### 📄 Evidence Reports: `{device_id}`")
    dev_history   = get_device_history(results, device_id)
    alert_windows = [h["window"] for h in dev_history if h.get("trust_score",100)<70]
    if not alert_windows:
        st.info("No evidence reports — trust score never dropped below threshold.")
        return
    sel_win = st.selectbox("Select alert window:", alert_windows,
        format_func=lambda w: f"Window {w} (Score: "
            f"{next((h['trust_score'] for h in dev_history if h['window']==w),'?')})",
        key=f"ev_window_{device_id}")
    if sel_win is None: return
    evidence = load_evidence_report(device_id, sel_win)
    if evidence is None:
        st.warning(f"Evidence report for window {sel_win} not found. Run main.py first.")
        return
    summary  = evidence.get("summary",{})
    severity = summary.get("severity","UNKNOWN")
    sev_cfg  = SEVERITY_CONFIG.get(severity,SEVERITY_CONFIG["CRITICAL"])
    st.markdown(
        f"**Trust Score:** <span style='color:{sev_cfg['color']};font-size:1.4rem;"
        f"font-weight:800'>{summary.get('trust_score',0):.1f}</span> / 100 &nbsp; "
        f"{severity_badge(severity)} &nbsp; **Action:** {summary.get('action_recommended','Monitor')}",
        unsafe_allow_html=True)
    with st.expander("🔬 Anomaly Analysis",expanded=True):
        anomaly = evidence.get("anomaly_analysis",{})
        ac1,ac2 = st.columns(2)
        with ac1:
            st.metric("Anomaly Score",f"{anomaly.get('anomaly_score',0):.3f}")
            st.metric("Status",anomaly.get("status","Unknown"))
        with ac2:
            st.metric("Threshold",f"{anomaly.get('threshold',0.15):.2f}")
            st.markdown(f"_{anomaly.get('anomaly_interpretation','')}_")
    with st.expander("🌊 Drift Analysis",expanded=True):
        drift   = evidence.get("drift_analysis",{})
        signals = drift.get("signals",{})
        dc1,dc2,dc3 = st.columns(3)
        for col,key,label in [(dc1,"adwin","ADWIN"),(dc2,"chi_squared","Chi-Squared"),
                               (dc3,"model_disagreement","Model Disagreement")]:
            active = signals.get(key,False)
            cls    = "signal-active" if active else "signal-inactive"
            with col:
                st.markdown(f"<span class='{cls}'>{'✓' if active else '✗'} {label}</span>",
                            unsafe_allow_html=True)
        st.markdown(
            f"**Drift Confirmed:** {'✅ Yes' if drift.get('drift_confirmed') else '❌ No'}"
            f" &nbsp;|&nbsp; **Factor:** {drift.get('drift_factor',1.0):.2f}"
            f" &nbsp;|&nbsp; **Active:** {signals.get('signals_active_count',0)}/3")
        st.markdown(f"_{drift.get('drift_interpretation','')}_")
    with st.expander("📐 Feature Deviation Analysis",expanded=True):
        fa  = evidence.get("feature_deviation_analysis",{})
        tfs = fa.get("top_deviating_features",[])
        if tfs:
            feat_df = pd.DataFrame(tfs)
            disp    = [c for c in ["feature_name","current_value","baseline_mean",
                       "z_score","severity","deviation_interpretation"] if c in feat_df.columns]
            st.dataframe(feat_df[disp],use_container_width=True)
            if "z_score" in feat_df.columns and "feature_name" in feat_df.columns:
                z_fig = px.bar(feat_df,x="feature_name",y="z_score",color="z_score",
                    color_continuous_scale=["#4A9EFF","#FFB81C","#E74C3C"],
                    color_continuous_midpoint=3,
                    labels={"feature_name":"Feature","z_score":"Z-Score"})
                z_fig.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",height=280,
                    margin=dict(l=50,r=20,t=30,b=80),xaxis_tickangle=-35)
                st.plotly_chart(z_fig,use_container_width=True)
        else:
            st.success("All features within normal range.")
        st.markdown(f"**Features above threshold:** {fa.get('num_features_above_threshold',0)} / "
                    f"{fa.get('total_features_analyzed',22)}")
    with st.expander("🛡️ Policy Violations",expanded=False):
        policy = evidence.get("policy_violations",{})
        if policy.get("violations_detected"):
            for v in policy.get("violations",[]):
                st.markdown(f"- **{v.get('rule_name','Unknown')}**: "
                            f"{v.get('description','')} (penalty:{v.get('penalty',0)})")
            st.markdown(f"**Total penalty:** {policy.get('total_policy_penalty',0)}")
        else:
            st.success("No policy violations.")
    with st.expander("💡 Actionable Insights",expanded=True):
        insights = evidence.get("actionable_insights",[])
        if insights:
            for i,ins in enumerate(insights,1): st.markdown(f"**{i}.** {ins}")
        else:
            st.info("No insights generated.")
    with st.expander("📝 Detailed Explanation",expanded=False):
        narrative = evidence.get("detailed_explanation","")
        st.markdown(narrative) if narrative else st.info("No narrative available.")
    st.download_button(
        label="⬇️ Download Evidence Report (JSON)",
        data=json.dumps(evidence,indent=2,default=str),
        file_name=f"evidence_{device_id}_w{sel_win}.json",
        mime="application/json",
        key=f"dl_ev_{device_id}_{sel_win}")


# ═══════════════════════════════════════════════════════════════════════
#  Drift / policy overviews
# ═══════════════════════════════════════════════════════════════════════

def render_drift_overview(results: dict, selected_devices: List[str]) -> None:
    st.markdown("### 🌊 Drift Signal Status")
    devices = results.get("devices",{})
    rows    = []
    for dev_id in selected_devices:
        history = devices.get(dev_id,{}).get("history",[])
        if not history: continue
        last = history[-1]
        rows.append({
            "Device":          get_device_name(dev_id),
            "Blocked":         "🚫" if is_blocked(dev_id) else "—",
            "ADWIN":           "🔴" if last.get("adwin_drift")    else "🟢",
            "Chi²":            "🔴" if last.get("chi_drift")      else "🟢",
            "Disagree":        "🔴" if last.get("disagree_drift") else "🟢",
            "Frozen":          "🔴" if last.get("flatness_drift") else "🟢",
            "Drift Confirmed": "✅ Yes" if last.get("drift_confirmed") else "❌ No",
            "Drift Factor":    f"{last.get('drift_factor',1.0):.2f}",
            "Drift Windows":   f"{sum(1 for h in history if h.get('drift_confirmed'))}/{len(history)}",
        })
    if rows:
        st.dataframe(pd.DataFrame(rows),use_container_width=True,hide_index=True)
    else:
        st.info("No drift data available.")


def render_drift_events_timeline(results: dict, selected_devices: List[str]) -> None:
    st.markdown("### 📅 Drift Events Log")
    devices = results.get("devices",{})
    events  = []
    for dev_id in selected_devices:
        for h in devices.get(dev_id,{}).get("history",[]):
            if h.get("drift_confirmed",False) or h.get("flatness_drift",False):
                sigs = []
                if h.get("adwin_drift"):    sigs.append("ADWIN")
                if h.get("chi_drift"):      sigs.append("Chi²")
                if h.get("disagree_drift"): sigs.append("Disagree")
                if h.get("flatness_drift"): sigs.append("🧊 Frozen")
                events.append({"Device":get_device_name(dev_id),"Window":h["window"],
                    "Trust Score":f"{h.get('trust_score',0):.1f}",
                    "Signals Fired":", ".join(sigs) or "None",
                    "Drift Factor":f"{h.get('drift_factor',1.0):.2f}",
                    "Anomaly Score":f"{h.get('anomaly_score',0):.4f}"})
    if events:
        st.dataframe(pd.DataFrame(events),use_container_width=True,hide_index=True,
                     height=min(400,35*len(events)+38))
        st.caption(f"Showing {len(events)} drift event(s).")
    else:
        st.success("✅ No drift events detected.")


def render_policy_overview(results: dict, selected_devices: List[str]) -> None:
    st.markdown("### 🛡️ Policy Violations Overview")
    all_v: Dict[str,Dict] = {}
    for dev_id in selected_devices:
        for h in results.get("devices",{}).get(dev_id,{}).get("history",[]):
            for v in h.get("policy_violations",[]):
                k=v.split("(")[0].strip()
                if k not in all_v: all_v[k]={"count":0,"devices":set()}
                all_v[k]["count"]+=1; all_v[k]["devices"].add(dev_id)
    if not all_v:
        st.success("✅ No policy violations detected."); return
    v_df = pd.DataFrame([{"Rule":r,"Violations":i["count"],"Devices Affected":len(i["devices"])}
                          for r,i in sorted(all_v.items(),key=lambda x:-x[1]["count"])])
    fig = px.bar(v_df,x="Rule",y="Violations",color="Devices Affected",
        color_continuous_scale=["#4A9EFF","#E74C3C"],text="Violations")
    fig.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",height=300,
        margin=dict(l=50,r=20,t=20,b=70),xaxis_tickangle=-25)
    fig.update_traces(textposition="outside")
    st.plotly_chart(fig,use_container_width=True)


def render_feature_heatmap(results: dict, device_id: str) -> None:
    st.markdown(f"### 🗺️ Anomaly Heatmap: `{device_id}`")
    history = get_device_history(results,device_id)
    if not history: st.info("No history data."); return
    windows = [h["window"] for h in history]
    metrics = {"Anomaly":[h.get("anomaly_score",0) for h in history],
               "IF Score":[h.get("if_score",0) for h in history],
               "HST Score":[h.get("hst_score",0) for h in history],
               "Drift Factor":[h.get("drift_factor",1.0) for h in history]}
    z_data = np.array(list(metrics.values()))
    if len(windows)>150:
        step=len(windows)//150; indices=list(range(0,len(windows),step))
        z_data=z_data[:,indices]; windows=[windows[i] for i in indices]
    fig = go.Figure(data=go.Heatmap(z=z_data,x=[f"W{w}" for w in windows],
        y=list(metrics.keys()),colorscale="YlOrRd",
        hovertemplate="Window:%{x}<br>Metric:%{y}<br>Value:%{z:.3f}<extra></extra>"))
    fig.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",height=250,
        margin=dict(l=100,r=20,t=20,b=50),
        xaxis=dict(showticklabels=len(windows)<50))
    st.plotly_chart(fig,use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════
#  Sidebar
# ═══════════════════════════════════════════════════════════════════════

def render_sidebar(config: dict, results: Optional[dict]) -> dict:
    selections: Dict[str, Any] = {}
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        if config:
            models_cfg = config.get("models",{})
            if_w  = models_cfg.get("isolation_forest",{}).get("weight",0.6)
            hst_w = models_cfg.get("halfspacetrees",{}).get("weight",0.4)
            st.markdown(f"**Model Weights:** IF {if_w*100:.0f}% · HST {hst_w*100:.0f}%")
            drift_cfg = config.get("drift",{})
            sigs = [s for s in ["adwin","chi_squared","disagreement"]
                    if drift_cfg.get(s,{}).get("enabled")]
            st.markdown(f"**Drift Signals:** {', '.join(sigs) or 'None'}")
            policy_cfg = config.get("policy",{})
            rules = [k for k,v in policy_cfg.items() if isinstance(v,dict) and v.get("enabled")]
            st.markdown(f"**Policy Rules:** {len(rules)} active")
            with st.expander("Show all rules"):
                for r in rules:
                    st.markdown(f"- {r} (penalty:{policy_cfg[r].get('penalty','?')})")

        st.markdown("---")
        st.markdown("## 🎛️ Controls")
        all_devices = sorted(results.get("devices",{}).keys()) if results else []
        selected_devices = st.multiselect("Filter Devices",options=all_devices,default=all_devices)
        selections["devices"] = selected_devices
        severity_filter = st.multiselect("Severity Filter",
            options=["NORMAL","WARNING","HIGH","CRITICAL"],
            default=["NORMAL","WARNING","HIGH","CRITICAL"])
        selections["severity_filter"] = severity_filter

        # Blocklist summary in sidebar
        blocked = st.session_state["blocked_ips"]
        if blocked:
            st.markdown("---")
            st.markdown("## 🚫 Blocked IPs")
            for ip, info in blocked.items():
                st.markdown(f"- **{info['name']}** `{ip}`")
            if st.button("Clear all blocks", key="sidebar_clear_blocks"):
                st.session_state["blocked_ips"] = {}
                st.rerun()

        st.markdown("---")
        st.markdown("## 📥 Data")
        if results:
            st.download_button(label="⬇️ Download Results (JSON)",
                data=json.dumps(results,indent=2,default=str),
                file_name="iot_trust_results.json",mime="application/json")
        st.markdown("---")
        st.markdown("## ℹ️ Severity Guide")
        for sev,cfg in SEVERITY_CONFIG.items():
            st.markdown(f"<span style='color:{cfg['color']}'>{cfg['icon']} **{sev}** "
                        f"({cfg['range']})</span>",unsafe_allow_html=True)
        st.markdown("---")
        st.caption("IoT Trust & Drift Analytics v1.0 · Isolation Forest + Half-Space Trees")
    return selections


# ═══════════════════════════════════════════════════════════════════════
#  No-data fallback
# ═══════════════════════════════════════════════════════════════════════

def render_no_data_page() -> None:
    st.markdown("""
    <div class="dashboard-header">
        <p class="dashboard-title">🔒 IoT Trust &amp; Drift Analytics</p>
        <p class="dashboard-subtitle">No results data found</p>
    </div>
    """, unsafe_allow_html=True)
    st.warning("⚠️ No `results.json` found. Run `python main.py` first.")
    st.markdown("""
    ### Getting Started
    1. Ensure dataset CSV files are in the project directory
    2. Run: `python main.py`
    3. Then: `streamlit run dashboard.py`
    """)


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    inject_custom_css()
    config  = load_config()
    results = load_results()

    if results is None:
        render_sidebar(config, None)
        render_no_data_page()
        return

    notifications    = get_drift_notifications(results)
    selections       = render_sidebar(config, results)
    selected_devices = selections.get("devices", [])
    severity_filter  = selections.get("severity_filter", [])

    if severity_filter:
        devices_data     = results.get("devices", {})
        selected_devices = [d for d in selected_devices
                            if devices_data.get(d,{}).get("severity","UNKNOWN") in severity_filter]

    # Header with bell + block buttons
    render_header(notifications)

    # Panels (only one open at a time) — rendered BEFORE tabs
    # so they don't interfere with tab layout
    render_notification_panel(notifications)
    render_block_panel(notifications)

    # KPI row
    summary   = results.get("summary", {})
    device_df = build_device_dataframe(results)
    if selected_devices:
        device_df = device_df[device_df["Device IP"].isin(selected_devices)]

    render_metrics_row(summary, device_df)
    st.markdown("")

    # If a panel is open, skip tabs to avoid visual clutter
    if st.session_state.get("notif_panel_open") or st.session_state.get("block_panel_open"):
        return

    # ── Tabs ─────────────────────────────────────────────────────
    tab_overview, tab_devices, tab_evidence, tab_advanced, tab_live = st.tabs([
        "📈 Overview", "📋 Devices", "📄 Evidence Reports", "🔬 Advanced", "🔴 Live Replay",
    ])

    with tab_overview:
        if selected_devices:
            render_trust_timeline(results, selected_devices)
            col_l,col_r = st.columns(2)
            with col_l: render_drift_overview(results, selected_devices)
            with col_r: render_policy_overview(results, selected_devices)
            render_drift_events_timeline(results, selected_devices)
        else:
            st.info("Select at least one device from the sidebar.")

    with tab_devices:
        render_device_table(device_df, notifications)

    with tab_evidence:
        if selected_devices:
            ev_device = st.selectbox("Select device for evidence reports:",
                                     selected_devices, key="ev_device_select")
            if ev_device:
                render_evidence_viewer(results, ev_device)
        else:
            st.info("Select at least one device from the sidebar.")

    with tab_advanced:
        if selected_devices:
            hm_device = st.selectbox("Select device for heatmap:",
                                     selected_devices, key="hm_device_select")
            if hm_device:
                render_feature_heatmap(results, hm_device)
            st.markdown("### 📊 Trust Score Distribution")
            if not device_df.empty:
                fig_dist = px.histogram(device_df,x="Score",nbins=20,
                    color_discrete_sequence=[COLORS["accent"]],
                    labels={"Score":"Final Trust Score"})
                for x0,x1,c in [(0,30,COLORS["critical"]),(30,50,COLORS["high"]),
                                  (50,70,COLORS["warning"]),(70,100,COLORS["normal"])]:
                    fig_dist.add_vrect(x0=x0,x1=x1,fillcolor=c,opacity=0.08,line_width=0)
                fig_dist.update_layout(template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                    height=300,margin=dict(l=50,r=20,t=20,b=50))
                st.plotly_chart(fig_dist,use_container_width=True)
            with st.expander("⚙️ Full Configuration (YAML)",expanded=False):
                st.code(yaml.dump(config,default_flow_style=False),language="yaml")
        else:
            st.info("Select at least one device from the sidebar.")

    # ── Tab 5: Live Replay ───────────────────────────────────────
    with tab_live:
        st.markdown("### 🔴 Live Play Mode")
        st.markdown(
            "Plays `results.json` window-by-window with a configurable delay, "
            "simulating a live feed."
        )

        replay_delay = st.slider(
            "Delay per window (seconds)",
            min_value=0.1, max_value=2.0, value=0.3, step=0.1,
            key="replay_delay_slider",
        )

        all_live_devices = sorted(results.get("devices", {}).keys())
        live_device_filter = st.multiselect(
            "Devices to show",
            options=all_live_devices,
            default=all_live_devices[:6],
            format_func=get_device_name,
            key="live_device_filter",
        )

        if st.button("▶ Start Play", key="live_start_btn"):

            devices = results.get("devices", {})

            # Build unified timeline sorted by window index
            timeline = []
            for device_id, device_data in devices.items():
                if device_id in live_device_filter:
                    for window in device_data.get("history", []):
                        timeline.append((device_id, window))
            timeline.sort(key=lambda x: x[1]["window"])

            # Accumulators
            live_histories = {d: [] for d in live_device_filter}

            # Placeholders that update in place
            chart_placeholder   = st.empty()
            metrics_placeholder = st.empty()
            status_placeholder  = st.empty()

            palette = px.colors.qualitative.Set2 + px.colors.qualitative.Pastel1
            device_colors = {
                d: palette[i % len(palette)]
                for i, d in enumerate(live_device_filter)
            }

            for device_id, window in timeline:
                live_histories[device_id].append(window)

                # Rebuild chart
                fig_live = go.Figure()
                fig_live.add_hrect(y0=70,y1=100,fillcolor=COLORS["normal"], opacity=0.08,line_width=0,layer="below")
                fig_live.add_hrect(y0=50,y1=70, fillcolor=COLORS["warning"],opacity=0.08,line_width=0,layer="below")
                fig_live.add_hrect(y0=30,y1=50, fillcolor=COLORS["high"],   opacity=0.08,line_width=0,layer="below")
                fig_live.add_hrect(y0=0, y1=30, fillcolor=COLORS["critical"],opacity=0.08,line_width=0,layer="below")
                for y,label in [(70,"Normal"),(50,"Warning"),(30,"Critical")]:
                    fig_live.add_hline(
                        y=y,line_dash="dot",line_color="#444",line_width=1,opacity=0.5,
                        annotation_text=label,annotation_position="right",
                        annotation_font_color="#666",annotation_font_size=10,
                    )

                for dev_id in live_device_filter:
                    hist = live_histories[dev_id]
                    if not hist:
                        continue
                    blocked_sfx = " 🚫" if is_blocked(dev_id) else ""
                    fig_live.add_trace(go.Scatter(
                        x=[h["window"] for h in hist],
                        y=[h["trust_score"] for h in hist],
                        mode="lines",
                        name=get_device_name(dev_id) + blocked_sfx,
                        line=dict(
                            width=2.5,
                            color=device_colors[dev_id],
                            dash="dot" if is_blocked(dev_id) else "solid",
                        ),
                        hovertemplate=f"<b>{get_device_name(dev_id)}</b><br>Window: %{{x}}<br>Trust: %{{y:.1f}}<extra></extra>",
                    ))

                fig_live.update_layout(
                    title="Live Trust Score Feed",
                    xaxis_title="Window Index",
                    yaxis_title="Trust Score",
                    yaxis=dict(range=[0,105],dtick=10),
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=480,
                    legend=dict(orientation="h",yanchor="bottom",y=1.02,xanchor="right",x=1),
                    margin=dict(l=50,r=30,t=60,b=50),
                    hovermode="x unified",
                )

                with chart_placeholder.container():
                    st.plotly_chart(fig_live, use_container_width=True)

                # Update per-device score cards
                with metrics_placeholder.container():
                    mcols = st.columns(min(len(live_device_filter), 6))
                    for idx, dev_id in enumerate(live_device_filter):
                        hist = live_histories[dev_id]
                        if hist:
                            last    = hist[-1]
                            score   = last["trust_score"]
                            sev     = last["severity"]
                            sev_cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["CRITICAL"])
                            with mcols[idx]:
                                st.markdown(
                                    f"<div class='metric-card' style='text-align:center;padding:0.6rem;'>"
                                    f"<div style='color:{sev_cfg['color']};font-size:1.4rem;font-weight:800;'>{score:.0f}</div>"
                                    f"<div style='font-size:0.7rem;color:#8B8D97;'>{get_device_name(dev_id)}</div>"
                                    f"<div style='font-size:0.75rem;color:{sev_cfg['color']};'>{sev_cfg['icon']} {sev}</div>"
                                    f"</div>",
                                    unsafe_allow_html=True,
                                )

                status_placeholder.caption(
                    f"Window {window['window']} · Device {device_id} · "
                    f"Trust: {window['trust_score']:.1f}"
                )

                time.sleep(replay_delay)

            status_placeholder.success("✅ Replay complete.")

    # ── Detail / evidence views triggered from device table ──────
    sel_dev = st.session_state.get("selected_device")
    if st.session_state.get("show_detail") and sel_dev:
        st.markdown("---")
        render_device_detail(results, sel_dev)
        if st.button("Close Detail View", key="close_detail"):
            st.session_state["show_detail"] = False
            st.rerun()

    if st.session_state.get("show_evidence") and sel_dev:
        st.markdown("---")
        render_evidence_viewer(results, sel_dev)
        if st.button("Close Evidence View", key="close_evidence"):
            st.session_state["show_evidence"] = False
            st.rerun()


if __name__ == "__main__":
    main()