"""
dashboard.py — IoT Trust & Drift Analytics System

Streamlit-based interactive web dashboard for visualising device trust
scores, drift signals, policy violations, and evidence reports.

Run with::

    streamlit run dashboard.py

The dashboard reads pre-computed results from ``results.json`` (produced
by ``main.py``) and renders them as interactive charts, tables, and
drill-down detail views.
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


# ═════════════════════════════════════════════════════════════════════════════
#  Page config (MUST be first Streamlit call)
# ═════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="IoT Trust & Drift Analytics Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Hide sidebar nav links
st.markdown("""
<style>
[data-testid="stSidebarNav"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════════════════════
#  Constants & colour palette
# ═════════════════════════════════════════════════════════════════════════════

COLORS = {
    "normal": "#00B050",
    "warning": "#FFB81C",
    "high": "#FF6B35",
    "critical": "#E74C3C",
    "bg_dark": "#0E1117",
    "card_bg": "#1C1E26",
    "text": "#FAFAFA",
    "text_muted": "#8B8D97",
    "accent": "#4A9EFF",
}

SEVERITY_CONFIG = {
    "NORMAL":   {"color": COLORS["normal"],   "icon": "✅", "range": "70 – 100"},
    "WARNING":  {"color": COLORS["warning"],  "icon": "⚠️",  "range": "50 – 70"},
    "HIGH":     {"color": COLORS["high"],     "icon": "🔶", "range": "30 – 50"},
    "CRITICAL": {"color": COLORS["critical"], "icon": "🔴", "range": "0 – 30"},
}

DEVICE_NAMES = {
    "10.0.1.1": "Smart Camera",
    "10.0.1.2": "Front Doorbell",
    "10.0.1.3": "Living Room Hub",
    "10.0.1.4": "Smart TV",
    "10.0.1.5": "Baby Monitor",
    "10.0.2.1": "Kitchen Plug",
    "10.0.2.2": "Garage Door",
    "10.0.2.3": "Garden Sensor",
    "10.0.2.4": "Solar Controller",
    "10.0.2.5": "Pool Monitor",
    "10.0.3.1": "Bedroom Speaker",
    "10.0.3.2": "Study Laptop",
    "10.0.3.3": "NAS Drive",
    "10.0.3.4": "Print Server",
    "10.0.3.5": "Media Server",
    "10.0.4.1": "Smart Lock",
    "10.0.4.2": "Motion Sensor",
    "10.0.4.3": "HVAC Controller",
    "10.0.4.4": "Alarm Panel",
    "10.0.4.5": "Irrigation System",
    "10.0.5.1": "IP Camera Alpha",
    "10.0.5.2": "IP Camera Beta",
    "10.0.5.3": "IP Camera Gamma",
    "10.0.5.4": "Smart Thermostat A",
    "10.0.5.5": "Smart Thermostat B",
    "192.168.50.21": "Smart Thermostat C",
}

def get_device_name(device_id: str) -> str:
    """Return human-readable device name, falling back to IP if not mapped."""
    return DEVICE_NAMES.get(device_id, device_id)


# ═════════════════════════════════════════════════════════════════════════════
#  Custom CSS
# ═════════════════════════════════════════════════════════════════════════════

def inject_custom_css() -> None:
    """Inject custom styles for badges, cards, layout polish, and notifications."""
    st.markdown("""
    <style>
    /* ── Global ─────────────────────────────────────── */
    .block-container { padding-top: 1.5rem; }

    /* ── Metric cards ──────────────────────────────── */
    .metric-card {
        background: linear-gradient(135deg, #1C1E26 0%, #252830 100%);
        border-radius: 16px;
        padding: 1.4rem 1.6rem;
        border: 1px solid #2A2D37;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    }
    .metric-value {
        font-size: 2.4rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 0.3rem;
        letter-spacing: -0.5px;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8B8D97;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }

    /* ── Severity badges ───────────────────────────── */
    .severity-badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.75rem;
        letter-spacing: 0.8px;
        text-transform: uppercase;
    }
    .badge-normal   { background: #00B05022; color: #00B050; border: 1px solid #00B05044; }
    .badge-warning  { background: #FFB81C22; color: #FFB81C; border: 1px solid #FFB81C44; }
    .badge-high     { background: #FF6B3522; color: #FF6B35; border: 1px solid #FF6B3544; }
    .badge-critical { background: #E74C3C22; color: #E74C3C; border: 1px solid #E74C3C44; }

    /* ── Signal indicators ─────────────────────────── */
    .signal-active   { color: #00B050; font-weight: 700; }
    .signal-inactive { color: #555; }

    /* ── Header ────────────────────────────────────── */
    .dashboard-header {
        background: linear-gradient(135deg, #141620 0%, #1a1f30 100%);
        padding: 1.5rem 2rem;
        border-radius: 16px;
        border: 1px solid #2A2D37;
        margin-bottom: 1.5rem;
    }
    .dashboard-title {
        font-size: 1.8rem;
        font-weight: 800;
        background: linear-gradient(135deg, #4A9EFF, #7C5CFC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .dashboard-subtitle {
        font-size: 0.95rem;
        color: #8B8D97;
        margin: 0.3rem 0 0 0;
    }

    /* ── Expander sections ─────────────────────────── */
    .stExpander { border: 1px solid #2A2D37 !important; border-radius: 12px !important; }

    /* ── Tables ────────────────────────────────────── */
    .device-score {
        font-size: 1.3rem;
        font-weight: 800;
    }

    /* ── Notification bell wrapper ─────────────────── */
    .bell-wrapper {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        height: 100%;
    }
    .bell-btn-active {
        position: relative;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: linear-gradient(135deg, #2a1a1a, #3a1f1f);
        border: 1px solid #E74C3C66;
        border-radius: 12px;
        padding: 10px 16px;
        cursor: pointer;
        font-size: 1.5rem;
        animation: bellPulse 1.6s ease-in-out infinite;
    }
    .bell-btn-quiet {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: linear-gradient(135deg, #1C1E26, #252830);
        border: 1px solid #2A2D37;
        border-radius: 12px;
        padding: 10px 16px;
        font-size: 1.5rem;
        opacity: 0.6;
    }
    .bell-badge {
        position: absolute;
        top: -6px;
        right: -6px;
        background: #E74C3C;
        color: #fff;
        font-size: 0.65rem;
        font-weight: 800;
        min-width: 20px;
        height: 20px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0 4px;
        border: 2px solid #0E1117;
        animation: badgePop 0.4s cubic-bezier(0.34,1.56,0.64,1) both;
    }
    .bell-label-active {
        font-size: 0.8rem;
        font-weight: 700;
        color: #E74C3C;
        letter-spacing: 0.5px;
    }
    .bell-label-quiet {
        font-size: 0.8rem;
        color: #555;
        letter-spacing: 0.5px;
    }
    @keyframes bellPulse {
        0%,100% { box-shadow: 0 0 0 0 rgba(231,76,60,0.0); }
        40%      { box-shadow: 0 0 0 8px rgba(231,76,60,0.25); }
        70%      { box-shadow: 0 0 0 14px rgba(231,76,60,0.08); }
    }
    @keyframes badgePop {
        0%   { transform: scale(0); opacity: 0; }
        100% { transform: scale(1); opacity: 1; }
    }

    /* ── Notification panel ─────────────────────────── */
    .notif-panel {
        background: linear-gradient(160deg, #1a1d2a 0%, #1f2235 100%);
        border: 1px solid #E74C3C44;
        border-radius: 16px;
        padding: 1.2rem 1.4rem;
        margin-bottom: 1.2rem;
        animation: slideDown 0.3s ease both;
    }
    .notif-panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
    }
    .notif-panel-title {
        font-size: 1.05rem;
        font-weight: 800;
        color: #E74C3C;
        letter-spacing: 0.5px;
    }
    .notif-panel-sub {
        font-size: 0.78rem;
        color: #8B8D97;
        margin-top: 0.1rem;
    }
    .notif-item {
        background: rgba(231,76,60,0.06);
        border: 1px solid #E74C3C33;
        border-left: 3px solid #E74C3C;
        border-radius: 10px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.6rem;
        transition: background 0.2s;
    }
    .notif-item:hover { background: rgba(231,76,60,0.12); }
    .notif-item-critical {
        border-left-color: #E74C3C;
        background: rgba(231,76,60,0.08);
    }
    .notif-item-high {
        border-left-color: #FF6B35;
        border-color: #FF6B3533;
        background: rgba(255,107,53,0.06);
    }
    .notif-item-warning {
        border-left-color: #FFB81C;
        border-color: #FFB81C33;
        background: rgba(255,184,28,0.06);
    }
    .notif-device-name {
        font-weight: 700;
        font-size: 0.92rem;
        color: #FAFAFA;
    }
    .notif-device-ip {
        font-size: 0.72rem;
        color: #8B8D97;
        font-family: monospace;
    }
    .notif-signals {
        font-size: 0.78rem;
        color: #8B8D97;
        margin-top: 0.25rem;
    }
    .notif-score {
        font-size: 1.2rem;
        font-weight: 800;
    }
    .notif-empty {
        text-align: center;
        padding: 1.5rem;
        color: #00B050;
        font-size: 1rem;
    }
    @keyframes slideDown {
        from { opacity: 0; transform: translateY(-12px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    </style>
    """, unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
#  Notification helpers
# ═════════════════════════════════════════════════════════════════════════════

def get_drift_notifications(results: Optional[dict]) -> List[Dict[str, Any]]:
    """
    Scan the latest window of every device and return a list of notification
    dicts for any that currently have drift confirmed or a trust score < 70.
    Sorted by severity (critical first).
    """
    if not results:
        return []

    notifications = []
    devices = results.get("devices", {})

    severity_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NORMAL": 3}

    for dev_id, dev_data in devices.items():
        history = dev_data.get("history", [])
        if not history:
            continue
        last = history[-1]

        drift_confirmed = last.get("drift_confirmed", False)
        trust_score = last.get("trust_score", 100)
        severity = last.get("severity", "NORMAL")

        if not drift_confirmed and trust_score >= 70:
            continue  # device is clean

        # Build fired-signals list
        signals_fired = []
        if last.get("adwin_drift"):
            signals_fired.append("ADWIN")
        if last.get("chi_drift"):
            signals_fired.append("Chi²")
        if last.get("disagree_drift"):
            signals_fired.append("Disagree")

        # Count total drift windows across entire history
        total_drift_windows = sum(1 for h in history if h.get("drift_confirmed"))

        notifications.append({
            "device_id": dev_id,
            "device_name": get_device_name(dev_id),
            "trust_score": trust_score,
            "severity": severity,
            "drift_confirmed": drift_confirmed,
            "signals_fired": signals_fired,
            "drift_factor": last.get("drift_factor", 1.0),
            "anomaly_score": last.get("anomaly_score", 0.0),
            "total_drift_windows": total_drift_windows,
            "window": last.get("window", 0),
        })

    notifications.sort(key=lambda n: (severity_order.get(n["severity"], 9), n["trust_score"]))
    return notifications


def render_notification_bell(notifications: List[Dict[str, Any]]) -> None:
    """Animated pill bell. Click opens full alerts panel; click again closes it."""
    count = len(notifications)
    has_alerts = count > 0
    is_open = st.session_state.get("notif_open", False)

    if has_alerts:
        st.markdown(f"""
        <style>
        .nb-pill {{
            display:inline-flex;align-items:center;gap:6px;
            padding:6px 12px 6px 9px;
            background:rgba(231,76,60,0.10);
            border:1px solid rgba(231,76,60,0.40);
            border-radius:999px;pointer-events:none;margin-bottom:4px;
        }}
        .nb-dot {{
            width:6px;height:6px;border-radius:50%;background:#E74C3C;
            animation:nbPulse 1.4s ease-in-out infinite;
        }}
        .nb-bell {{ animation:nbSwing 3s ease-in-out infinite;transform-origin:50% 3px; }}
        @keyframes nbPulse{{0%,100%{{box-shadow:0 0 0 0 rgba(231,76,60,.5);}}60%{{box-shadow:0 0 0 5px rgba(231,76,60,0);}}}}
        @keyframes nbSwing{{0%,100%{{transform:rotate(0);}}6%{{transform:rotate(15deg);}}12%{{transform:rotate(-12deg);}}18%{{transform:rotate(8deg);}}24%{{transform:rotate(0);}}}}
        </style>
        <div class="nb-pill">
            <div class="nb-dot"></div>
            <svg class="nb-bell" width="15" height="15" viewBox="0 0 24 24" fill="none">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"
                      stroke="#E74C3C" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M13.73 21a2 2 0 0 1-3.46 0"
                      stroke="#E74C3C" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span style="font-size:.72rem;font-weight:800;color:#E74C3C;">
                {count} alert{'s' if count != 1 else ''}
            </span>
        </div>
        """, unsafe_allow_html=True)

        btn_label = "✕  Close Alerts" if is_open else f"🔔 {count} Drift Alerts"
        btn_type  = "secondary" if is_open else "primary"
        if st.button(btn_label, key="bell_toggle", type=btn_type, use_container_width=True):
            st.session_state["notif_open"] = not is_open
            st.rerun()
    else:
        st.markdown("""
        <div style="display:inline-flex;align-items:center;gap:6px;
                    padding:6px 12px;border-radius:999px;
                    border:1px solid rgba(255,255,255,0.07);opacity:.4;">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"
                      stroke="#666" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M13.73 21a2 2 0 0 1-3.46 0"
                      stroke="#666" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span style="font-size:.72rem;color:#555;font-weight:600;">all clear</span>
        </div>
        """, unsafe_allow_html=True)


def render_alerts_panel(notifications: List[Dict[str, Any]]) -> None:
    """
    Full-width alerts panel — shown instead of dashboard when notif_open=True.
    Each drifting device gets a clean card row.
    """
    sev_colors  = {"CRITICAL": "#E74C3C", "HIGH": "#FF6B35", "WARNING": "#FFB81C", "NORMAL": "#00B050"}
    bg_colors   = {"CRITICAL": "rgba(231,76,60,0.07)", "HIGH": "rgba(255,107,53,0.07)",
                   "WARNING": "rgba(255,184,28,0.05)", "NORMAL": "rgba(0,176,80,0.05)"}

    count = len(notifications)
    ts    = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    critical_count = sum(1 for n in notifications if n["severity"] == "CRITICAL")
    high_count     = sum(1 for n in notifications if n["severity"] == "HIGH")
    warning_count  = sum(1 for n in notifications if n["severity"] == "WARNING")

    summary_parts = []
    if critical_count:
        summary_parts.append(f'<span style="color:#E74C3C;font-weight:700;">{critical_count} critical</span>')
    if high_count:
        summary_parts.append(f'<span style="color:#FF6B35;font-weight:700;">{high_count} high</span>')
    if warning_count:
        summary_parts.append(f'<span style="color:#FFB81C;font-weight:700;">{warning_count} warning</span>')
    summary_html = " &nbsp;·&nbsp; ".join(summary_parts)

    # ── Header row ────────────────────────────────────────────────
    st.markdown(f"""
    <div style="display:flex;align-items:baseline;justify-content:space-between;
                margin-bottom:1rem;padding-bottom:0.6rem;
                border-bottom:1px solid rgba(255,255,255,0.07);">
        <div>
            <span style="font-size:1.25rem;font-weight:800;color:#FAFAFA;">
                🔔 {count} Drift Alert{'s' if count != 1 else ''}
            </span>
            &nbsp;&nbsp;
            <span style="font-size:0.82rem;color:#8B8D97;">{summary_html}</span>
        </div>
        <span style="font-size:0.75rem;color:#555;">{ts}</span>
    </div>
    """, unsafe_allow_html=True)

    # ── One card per device — each its own st.markdown call ───────
    for n in notifications:
        sev    = n["severity"]
        color  = sev_colors.get(sev, "#E74C3C")
        bg     = bg_colors.get(sev, "rgba(231,76,60,0.07)")

        signals_str = " · ".join(f"<b>{s}</b>" for s in n["signals_fired"]) if n["signals_fired"] else "—"
        drift_tag = (
            '<span style="color:#E74C3C;font-weight:700;font-size:0.7rem;'
            'background:rgba(231,76,60,0.15);padding:1px 7px;border-radius:4px;">● DRIFT</span>'
            if n["drift_confirmed"] else
            '<span style="color:#FFB81C;font-weight:700;font-size:0.7rem;'
            'background:rgba(255,184,28,0.15);padding:1px 7px;border-radius:4px;">⚠ LOW TRUST</span>'
        )

        st.markdown(f"""
        <div style="display:flex;align-items:center;justify-content:space-between;
                    background:{bg};
                    border:1px solid {color}33;border-left:3px solid {color};
                    border-radius:10px;padding:0.65rem 1rem;margin-bottom:0.4rem;">
            <div style="display:flex;align-items:center;gap:10px;flex:1.4;min-width:0;">
                <span style="width:8px;height:8px;border-radius:50%;flex-shrink:0;
                             background:{color};box-shadow:0 0 6px {color};
                             display:inline-block;"></span>
                <div>
                    <span style="font-weight:700;font-size:0.88rem;color:#FAFAFA;">
                        {n['device_name']}
                    </span>
                    &nbsp;{drift_tag}
                    <div style="font-size:0.68rem;color:#8B8D97;margin-top:1px;font-family:monospace;">
                        {n['device_id']} &nbsp;·&nbsp; Window {n['window']}
                    </div>
                </div>
            </div>
            <div style="flex:2;padding:0 1.2rem;font-size:0.74rem;color:#8B8D97;line-height:1.6;">
                Signals: {signals_str} &nbsp;·&nbsp;
                Factor: <b style="color:#ccc;">{n['drift_factor']:.2f}x</b> &nbsp;·&nbsp;
                Anomaly: <b style="color:#ccc;">{n['anomaly_score']:.3f}</b> &nbsp;·&nbsp;
                Drift windows: <b style="color:#ccc;">{n['total_drift_windows']}</b>
            </div>
            <div style="text-align:right;min-width:52px;">
                <div style="font-size:1.35rem;font-weight:800;color:{color};line-height:1;">
                    {n['trust_score']:.0f}
                </div>
                <div style="font-size:0.62rem;color:#8B8D97;">/ 100</div>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
#  Data loading (cached)
# ═════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=10)
def load_results(path: str = "results.json") -> Optional[dict]:
    """Load pre-computed pipeline results.  Returns None if missing."""
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
    """Load the system configuration for sidebar display."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError:
        return {}


def load_evidence_report(device_id: str, window_index: int) -> Optional[dict]:
    """Load a single evidence report for a specific device/window."""
    safe_id = device_id.replace(".", "_").replace(":", "_")
    filename = f"results/{safe_id}_window_{window_index}.json"
    if not Path(filename).exists():
        return None
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def build_device_dataframe(results: dict) -> pd.DataFrame:
    """Build a DataFrame of all devices from results for display."""
    devices = results.get("devices", {})
    if not devices:
        return pd.DataFrame()

    rows = []
    for dev_id, dev in devices.items():
        severity = dev.get("severity", "UNKNOWN")
        score = dev.get("final_score", 0)
        rows.append({
            "Device IP": get_device_name(dev_id),
            "Score": score,
            "Severity": severity,
            "Min Score": dev.get("min_score", score),
            "Max Score": dev.get("max_score", score),
            "Alerts": dev.get("num_alerts", 0),
            "Windows": dev.get("monitoring_windows", 0),
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("Score", ascending=True).reset_index(drop=True)
    return df


def get_device_history(results: dict, device_id: str) -> List[dict]:
    """Get the window-by-window history for a specific device."""
    return results.get("devices", {}).get(device_id, {}).get("history", [])


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Header
# ═════════════════════════════════════════════════════════════════════════════

def render_header(notifications: List[Dict[str, Any]]) -> None:
    """Render the dashboard header with title, timestamp, and notification bell."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    h_col_left, h_col_right = st.columns([5, 1])

    with h_col_left:
        st.markdown(f"""
        <div class="dashboard-header">
            <p class="dashboard-title">🔒 IoT Trust & Drift Analytics</p>
            <p class="dashboard-subtitle">
                Real-Time Device Trustworthiness Monitoring &nbsp;·&nbsp; {now}
            </p>
        </div>
        """, unsafe_allow_html=True)

    with h_col_right:
        st.markdown("<div style='height:1.1rem;'></div>", unsafe_allow_html=True)
        render_notification_bell(notifications)


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Metric cards
# ═════════════════════════════════════════════════════════════════════════════

def render_metric_card(
    label: str, value: Any, color: str = COLORS["accent"],
    suffix: str = "",
) -> None:
    """Render a single styled metric card."""
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" style="color:{color};">{value}{suffix}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def render_metrics_row(summary: dict, device_df: pd.DataFrame) -> None:
    """Top-level KPI cards row with mutually exclusive severity tiers."""
    total = summary.get("total_devices", 0)
    normal = summary.get("normal", 0)
    warning = summary.get("warning", 0)
    high_risk = summary.get("high_risk", 0)
    critical = summary.get("critical", 0)
    avg_trust = summary.get("avg_trust", 0)

    # Choose color for average trust
    if avg_trust >= 70:
        avg_color = COLORS["normal"]
    elif avg_trust >= 50:
        avg_color = COLORS["warning"]
    elif avg_trust >= 30:
        avg_color = COLORS["high"]
    else:
        avg_color = COLORS["critical"]

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        render_metric_card("Total Devices", total, COLORS["accent"])
    with c2:
        render_metric_card("✅ Normal (≥70)", normal, COLORS["normal"])
    with c3:
        render_metric_card("⚠️ Warning (50-70)", warning, COLORS["warning"])
    with c4:
        render_metric_card("🔶 High (30-50)", high_risk, COLORS["high"])
    with c5:
        render_metric_card("🔴 Critical (<30)", critical, COLORS["critical"])
    with c6:
        render_metric_card("Avg Trust Score", f"{avg_trust:.1f}", avg_color, suffix="/100")


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Trust score timeline
# ═════════════════════════════════════════════════════════════════════════════

def render_trust_timeline(
    results: dict, selected_devices: List[str],
) -> None:
    """Interactive Plotly line chart of trust scores over time."""
    fig = go.Figure()

    # Severity region bands
    fig.add_hrect(y0=70, y1=100, fillcolor=COLORS["normal"],
                  opacity=0.08, line_width=0, layer="below")
    fig.add_hrect(y0=50, y1=70, fillcolor=COLORS["warning"],
                  opacity=0.08, line_width=0, layer="below")
    fig.add_hrect(y0=30, y1=50, fillcolor=COLORS["high"],
                  opacity=0.08, line_width=0, layer="below")
    fig.add_hrect(y0=0, y1=30, fillcolor=COLORS["critical"],
                  opacity=0.08, line_width=0, layer="below")

    # Threshold lines
    for y, label in [(70, "Normal"), (50, "Warning"), (30, "Critical")]:
        fig.add_hline(y=y, line_dash="dot", line_color="#444",
                      line_width=1, opacity=0.5,
                      annotation_text=label,
                      annotation_position="right",
                      annotation_font_color="#666",
                      annotation_font_size=10)

    # Add colour palette
    palette = px.colors.qualitative.Set2 + px.colors.qualitative.Pastel1
    devices_data = results.get("devices", {})

    for idx, dev_id in enumerate(selected_devices):
        history = devices_data.get(dev_id, {}).get("history", [])
        if not history:
            continue

        windows = [h["window"] for h in history]
        scores = [h["trust_score"] for h in history]
        color = palette[idx % len(palette)]

        fig.add_trace(go.Scatter(
            x=windows, y=scores,
            mode="lines",
            name=get_device_name(dev_id),
            line=dict(width=2.5, color=color),
            hovertemplate=(
                f"<b>{dev_id}</b><br>"
                "Window: %{x}<br>"
                "Trust: %{y:.1f}<br>"
                "<extra></extra>"
            ),
        ))

    fig.update_layout(
        title=dict(text="Trust Score Timeline", font=dict(size=18)),
        xaxis_title="Window Index",
        yaxis_title="Trust Score",
        yaxis=dict(range=[0, 105], dtick=10),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=480,
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02,
            xanchor="right", x=1, font=dict(size=11),
        ),
        margin=dict(l=50, r=30, t=60, b=50),
        hovermode="x unified",
    )

    st.plotly_chart(fig, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Device status table
# ═════════════════════════════════════════════════════════════════════════════

def severity_badge(severity: str) -> str:
    """Return an HTML badge for the severity label."""
    cls = f"badge-{severity.lower()}"
    icon = SEVERITY_CONFIG.get(severity, {}).get("icon", "❓")
    return f'<span class="severity-badge {cls}">{icon} {severity}</span>'


def render_device_table(device_df: pd.DataFrame) -> None:
    """Render the interactive device status table."""
    if device_df.empty:
        st.info("No device data available.")
        return

    st.markdown("### 📋 Device Status")

    for _, row in device_df.iterrows():
        dev_id = row["Device IP"]
        score = row["Score"]
        severity = row["Severity"]
        sev_cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["CRITICAL"])

        with st.expander(
            f"{sev_cfg['icon']}  **{dev_id}**  —  "
            f"Score: **{score:.0f}**  |  {severity}  |  "
            f"Alerts: {row['Alerts']}",
            expanded=False,
        ):
            c1, c2, c3, c4, c5 = st.columns([2, 1.5, 1.5, 1.5, 1.5])
            with c1:
                st.markdown(f"**Device:** `{dev_id}`")
            with c2:
                st.markdown(
                    f"<span class='device-score' style='color:{sev_cfg['color']}'>"
                    f"{score:.1f}</span> / 100",
                    unsafe_allow_html=True,
                )
            with c3:
                st.markdown(severity_badge(severity), unsafe_allow_html=True)
            with c4:
                st.metric("Min Score", f"{row['Min Score']:.1f}")
            with c5:
                st.metric("Windows", row["Windows"])

            # Action buttons
            bc1, bc2 = st.columns(2)
            with bc1:
                if st.button(f"📊 View Details", key=f"detail_{dev_id}"):
                    st.session_state["selected_device"] = dev_id
                    st.session_state["show_detail"] = True
            with bc2:
                if st.button(f"📄 View Evidence", key=f"evidence_{dev_id}"):
                    st.session_state["selected_device"] = dev_id
                    st.session_state["show_evidence"] = True


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Device detail view
# ═════════════════════════════════════════════════════════════════════════════

def render_device_detail(results: dict, device_id: str) -> None:
    """Detailed view for a single device with charts and tables."""
    st.markdown(f"### 🔍 Device Detail: `{device_id}`")

    dev_data = results.get("devices", {}).get(device_id, {})
    if not dev_data:
        st.warning(f"No data available for device {device_id}")
        return

    history = dev_data.get("history", [])
    if not history:
        st.info("No monitoring history available.")
        return

    final_score = dev_data.get("final_score", 0)
    severity = dev_data.get("severity", "UNKNOWN")
    sev_cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["CRITICAL"])

    # ── Headline metrics ──────────────────────────────────────────
    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
    with mc1:
        render_metric_card("Current Score", f"{final_score:.1f}",
                           sev_cfg["color"], "/100")
    with mc2:
        render_metric_card("Severity", f"{sev_cfg['icon']} {severity}",
                           sev_cfg["color"])
    with mc3:
        scores = [h["trust_score"] for h in history]
        trend = scores[-1] - scores[0] if len(scores) > 1 else 0
        arrow = "↓" if trend < -5 else ("↑" if trend > 5 else "→")
        render_metric_card("Trend", f"{arrow} {trend:+.1f}", sev_cfg["color"])
    with mc4:
        render_metric_card("Min Score",
                           f"{dev_data.get('min_score', 0):.1f}",
                           COLORS["critical"])
    with mc5:
        action_map = {
            "NORMAL": "Monitor", "WARNING": "Investigate",
            "HIGH": "Isolate", "CRITICAL": "Block",
        }
        action = action_map.get(severity, "Monitor")
        render_metric_card("Action", action, sev_cfg["color"])

    st.markdown("---")

    # ── Mini trust timeline ───────────────────────────────────────
    fig = go.Figure()
    windows = [h["window"] for h in history]
    trust_scores = [h["trust_score"] for h in history]

    fig.add_hrect(y0=70, y1=100, fillcolor=COLORS["normal"],
                  opacity=0.07, line_width=0)
    fig.add_hrect(y0=50, y1=70, fillcolor=COLORS["warning"],
                  opacity=0.07, line_width=0)
    fig.add_hrect(y0=30, y1=50, fillcolor=COLORS["high"],
                  opacity=0.07, line_width=0)
    fig.add_hrect(y0=0, y1=30, fillcolor=COLORS["critical"],
                  opacity=0.07, line_width=0)

    fig.add_trace(go.Scatter(
        x=windows, y=trust_scores,
        mode="lines+markers",
        line=dict(width=3, color=COLORS["accent"]),
        marker=dict(size=4),
        name="Trust Score",
        fill="tozeroy",
        fillcolor="rgba(74,158,255,0.08)",
    ))

    fig.update_layout(
        title="Trust Score Over Time",
        xaxis_title="Window", yaxis_title="Trust Score",
        yaxis=dict(range=[0, 105]),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=350,
        margin=dict(l=50, r=30, t=50, b=40),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Anomaly scores ────────────────────────────────────────────
    anomaly_scores = [h.get("anomaly_score", 0) for h in history]
    if_scores = [h.get("if_score", 0) for h in history]
    hst_scores = [h.get("hst_score", 0) for h in history]

    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(
        x=windows, y=anomaly_scores,
        mode="lines", name="Combined",
        line=dict(width=2.5, color="#FF6B6B"),
    ))
    fig2.add_trace(go.Scatter(
        x=windows, y=if_scores,
        mode="lines", name="Isolation Forest",
        line=dict(width=1.5, color="#4ECDC4", dash="dot"),
    ))
    fig2.add_trace(go.Scatter(
        x=windows, y=hst_scores,
        mode="lines", name="Half-Space Trees",
        line=dict(width=1.5, color="#FFE66D", dash="dot"),
    ))
    fig2.add_hline(y=0.15, line_dash="dash", line_color="#666",
                   annotation_text="Threshold",
                   annotation_font_color="#888")
    fig2.update_layout(
        title="Anomaly Scores",
        xaxis_title="Window", yaxis_title="Score (0–1)",
        yaxis=dict(range=[0, 1.05]),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        margin=dict(l=50, r=30, t=50, b=40),
        legend=dict(orientation="h", y=1.12),
    )
    st.plotly_chart(fig2, use_container_width=True)

    # ── Drift signals timeline ────────────────────────────────────
    drift_data = [h.get("drift_confirmed", False) for h in history]
    drift_factors = [h.get("drift_factor", 1.0) for h in history]

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(
            x=windows, y=[1 if d else 0 for d in drift_data],
            mode="lines", name="Drift Confirmed",
            line=dict(width=2, color="#FF6B35"),
            fill="tozeroy", fillcolor="rgba(255,107,53,0.15)",
        ))
        fig3.update_layout(
            title="Drift Confirmation",
            yaxis=dict(tickvals=[0, 1], ticktext=["No", "Yes"]),
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=220,
            margin=dict(l=50, r=20, t=50, b=30),
        )
        st.plotly_chart(fig3, use_container_width=True)

    with col_d2:
        fig4 = go.Figure()
        fig4.add_trace(go.Scatter(
            x=windows, y=drift_factors,
            mode="lines", name="Drift Factor",
            line=dict(width=2, color="#7C5CFC"),
            fill="tozeroy", fillcolor="rgba(124,92,252,0.12)",
        ))
        fig4.update_layout(
            title="Drift Factor",
            yaxis=dict(range=[0.9, 2.1]),
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=220,
            margin=dict(l=50, r=20, t=50, b=30),
        )
        st.plotly_chart(fig4, use_container_width=True)

    # ── Active drift signal indicators ────────────────────────────
    st.markdown("#### 🚦 Drift Signal Status (Latest Window)")
    last_h = history[-1]
    sig_cols = st.columns(3)
    signal_names = [
        ("ADWIN", "adwin_drift"),
        ("Chi-Squared", "chi_drift"),
        ("Model Disagreement", "disagree_drift"),
    ]
    for col, (label, key) in zip(sig_cols, signal_names):
        active = last_h.get(key, False)
        cls = "signal-active" if active else "signal-inactive"
        icon = "🔴" if active else "🟢"
        status = "ACTIVE" if active else "Inactive"
        with col:
            st.markdown(
                f"<div class='metric-card' style='text-align:center;'>"
                f"<span class='{cls}' style='font-size:1.3rem;'>{icon} {label}</span><br>"
                f"<span style='font-size:0.85rem; color:#8B8D97;'>{status}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

    # ── IF vs HST score chart (Model Disagreement history) ────────
    st.markdown("#### 🔀 Model Disagreement: IF vs HST Scores")
    fig_md = go.Figure()
    fig_md.add_trace(go.Scatter(
        x=windows, y=if_scores,
        mode="lines", name="Isolation Forest (frozen)",
        line=dict(width=2.5, color="#4ECDC4"),
    ))
    fig_md.add_trace(go.Scatter(
        x=windows, y=hst_scores,
        mode="lines", name="Half-Space Trees (adaptive)",
        line=dict(width=2.5, color="#FFE66D"),
    ))
    # Highlight disagreement regions
    disagree_regions = [h.get("disagree_drift", False) for h in history]
    for i, (w, dis) in enumerate(zip(windows, disagree_regions)):
        if dis:
            fig_md.add_vrect(
                x0=w - 0.5, x1=w + 0.5,
                fillcolor="rgba(255,107,53,0.15)",
                line_width=0, layer="below",
            )
    fig_md.update_layout(
        xaxis_title="Window", yaxis_title="Score (0–1)",
        yaxis=dict(range=[0, 1.05]),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        margin=dict(l=50, r=30, t=30, b=40),
        legend=dict(orientation="h", y=1.12),
    )
    st.plotly_chart(fig_md, use_container_width=True)
    st.caption("Orange shaded regions indicate windows where model disagreement signal fired.")

    # ── Drift factor over time ────────────────────────────────────
    st.markdown("#### 📈 Drift Factor Over Time")
    fig_dft = go.Figure()
    fig_dft.add_trace(go.Scatter(
        x=windows, y=drift_factors,
        mode="lines+markers", name="Drift Factor",
        line=dict(width=2.5, color="#7C5CFC"),
        marker=dict(size=4),
        fill="tozeroy", fillcolor="rgba(124,92,252,0.08)",
    ))
    fig_dft.add_hline(y=1.0, line_dash="dot", line_color="#666",
                      annotation_text="Baseline",
                      annotation_font_color="#888")
    fig_dft.update_layout(
        xaxis_title="Window", yaxis_title="Drift Factor",
        yaxis=dict(range=[0.9, 2.1]),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=250,
        margin=dict(l=50, r=30, t=30, b=40),
    )
    st.plotly_chart(fig_dft, use_container_width=True)

    # ── Policy violations summary ─────────────────────────────────
    all_violations: List[str] = []
    for h in history:
        all_violations.extend(h.get("policy_violations", []))

    if all_violations:
        st.markdown("#### 🛡️ Policy Violations")
        violation_counts: Dict[str, int] = {}
        for v in all_violations:
            key = v.split("(")[0].strip()
            violation_counts[key] = violation_counts.get(key, 0) + 1

        v_df = pd.DataFrame([
            {"Rule": k, "Count": v}
            for k, v in sorted(violation_counts.items(), key=lambda x: -x[1])
        ])
        fig_v = px.bar(
            v_df, x="Rule", y="Count", color="Count",
            color_continuous_scale=["#FFB81C", "#E74C3C"],
        )
        fig_v.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=260,
            margin=dict(l=50, r=20, t=30, b=60),
            showlegend=False,
        )
        st.plotly_chart(fig_v, use_container_width=True)
    else:
        st.success("No policy violations detected for this device.")

    # ── Window-by-window history table ────────────────────────────
    with st.expander("📊 Full Window History", expanded=False):
        hist_df = pd.DataFrame(history)
        if not hist_df.empty:
            display_cols = [c for c in [
                "window", "trust_score", "severity", "anomaly_score",
                "adwin_drift", "chi_drift", "disagree_drift",
                "drift_confirmed", "drift_factor", "policy_violations",
            ] if c in hist_df.columns]
            st.dataframe(
                hist_df[display_cols],
                use_container_width=True,
                height=400,
            )


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Evidence report viewer
# ═════════════════════════════════════════════════════════════════════════════

def render_evidence_viewer(results: dict, device_id: str) -> None:
    """Show generated evidence reports for a device."""
    st.markdown(f"### 📄 Evidence Reports: `{device_id}`")

    evidence_files = results.get("evidence_reports", {}).get(device_id, [])
    dev_history = get_device_history(results, device_id)

    # Find alert windows for this device
    alert_windows = [
        h["window"] for h in dev_history
        if h.get("trust_score", 100) < 70
    ]

    if not alert_windows:
        st.info("No evidence reports generated — trust score never dropped below threshold.")
        return

    selected_window = st.selectbox(
        "Select alert window:",
        alert_windows,
        format_func=lambda w: f"Window {w} (Score: "
            f"{next((h['trust_score'] for h in dev_history if h['window'] == w), '?')})",
        key=f"ev_window_{device_id}",
    )

    if selected_window is None:
        return

    evidence = load_evidence_report(device_id, selected_window)

    if evidence is None:
        st.warning(
            f"Evidence report file for window {selected_window} not found. "
            "Run `python main.py` first to generate reports."
        )
        return

    # ── Render the evidence report ────────────────────────────────
    summary = evidence.get("summary", {})
    severity = summary.get("severity", "UNKNOWN")
    sev_cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["CRITICAL"])

    st.markdown(
        f"**Trust Score:** "
        f"<span style='color:{sev_cfg['color']}; font-size:1.4rem; font-weight:800'>"
        f"{summary.get('trust_score', 0):.1f}</span> / 100 &nbsp; "
        f"{severity_badge(severity)} &nbsp; "
        f"**Action:** {summary.get('action_recommended', 'Monitor')}",
        unsafe_allow_html=True,
    )

    # Anomaly analysis
    with st.expander("🔬 Anomaly Analysis", expanded=True):
        anomaly = evidence.get("anomaly_analysis", {})
        ac1, ac2 = st.columns(2)
        with ac1:
            st.metric("Anomaly Score", f"{anomaly.get('anomaly_score', 0):.3f}")
            st.metric("Status", anomaly.get("status", "Unknown"))
        with ac2:
            st.metric("Threshold", f"{anomaly.get('threshold', 0.15):.2f}")
            st.markdown(f"_{anomaly.get('anomaly_interpretation', '')}_")

    # Drift analysis
    with st.expander("🌊 Drift Analysis", expanded=True):
        drift = evidence.get("drift_analysis", {})
        signals = drift.get("signals", {})

        dc1, dc2, dc3 = st.columns(3)
        with dc1:
            active = signals.get("adwin", False)
            cls = "signal-active" if active else "signal-inactive"
            mark = "✓" if active else "✗"
            st.markdown(f"<span class='{cls}'>{mark} ADWIN</span>",
                        unsafe_allow_html=True)
        with dc2:
            active = signals.get("chi_squared", False)
            cls = "signal-active" if active else "signal-inactive"
            mark = "✓" if active else "✗"
            st.markdown(f"<span class='{cls}'>{mark} Chi-Squared</span>",
                        unsafe_allow_html=True)
        with dc3:
            active = signals.get("model_disagreement", False)
            cls = "signal-active" if active else "signal-inactive"
            mark = "✓" if active else "✗"
            st.markdown(f"<span class='{cls}'>{mark} Model Disagreement</span>",
                        unsafe_allow_html=True)

        st.markdown(
            f"**Drift Confirmed:** {'✅ Yes' if drift.get('drift_confirmed') else '❌ No'}"
            f" &nbsp;|&nbsp; **Drift Factor:** {drift.get('drift_factor', 1.0):.2f}"
            f" &nbsp;|&nbsp; **Active Signals:** {signals.get('signals_active_count', 0)}/3"
        )
        st.markdown(f"_{drift.get('drift_interpretation', '')}_")

    # Feature deviations
    with st.expander("📐 Feature Deviation Analysis", expanded=True):
        feat_analysis = evidence.get("feature_deviation_analysis", {})
        top_feats = feat_analysis.get("top_deviating_features", [])

        if top_feats:
            feat_df = pd.DataFrame(top_feats)
            display_cols = [c for c in [
                "feature_name", "current_value", "baseline_mean",
                "z_score", "severity", "deviation_interpretation"
            ] if c in feat_df.columns]
            st.dataframe(feat_df[display_cols], use_container_width=True)

            # Z-score bar chart
            if "z_score" in feat_df.columns and "feature_name" in feat_df.columns:
                z_fig = px.bar(
                    feat_df, x="feature_name", y="z_score",
                    color="z_score",
                    color_continuous_scale=["#4A9EFF", "#FFB81C", "#E74C3C"],
                    color_continuous_midpoint=3,
                    labels={"feature_name": "Feature", "z_score": "Z-Score"},
                )
                z_fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=280,
                    margin=dict(l=50, r=20, t=30, b=80),
                    xaxis_tickangle=-35,
                )
                st.plotly_chart(z_fig, use_container_width=True)
        else:
            st.success("All features within normal range.")

        st.markdown(
            f"**Features above threshold:** "
            f"{feat_analysis.get('num_features_above_threshold', 0)} / "
            f"{feat_analysis.get('total_features_analyzed', 22)}"
        )

    # Policy violations
    with st.expander("🛡️ Policy Violations", expanded=False):
        policy = evidence.get("policy_violations", {})
        if policy.get("violations_detected"):
            for v in policy.get("violations", []):
                st.markdown(
                    f"- **{v.get('rule_name', 'Unknown')}**: "
                    f"{v.get('description', '')} "
                    f"(penalty: {v.get('penalty', 0)})"
                )
            st.markdown(
                f"**Total policy penalty:** {policy.get('total_policy_penalty', 0)}"
            )
        else:
            st.success("No policy violations.")

    # Behavioral context
    with st.expander("🧠 Behavioral Context", expanded=False):
        ctx = evidence.get("behavioral_context", {})
        st.markdown(f"**Device Type:** {ctx.get('device_type_inference', 'Unknown')}")
        st.markdown(f"**Normal Pattern:** {ctx.get('normal_pattern_summary', 'N/A')}")
        st.markdown(f"**Current Pattern:** {ctx.get('current_pattern_summary', 'N/A')}")
        st.markdown(f"**Pattern Change:** {ctx.get('pattern_change', 'N/A')}")

    # Actionable insights
    with st.expander("💡 Actionable Insights", expanded=True):
        insights = evidence.get("actionable_insights", [])
        if insights:
            for idx, insight in enumerate(insights, 1):
                st.markdown(f"**{idx}.** {insight}")
        else:
            st.info("No specific insights generated.")

    # Detailed narrative
    with st.expander("📝 Detailed Explanation", expanded=False):
        narrative = evidence.get("detailed_explanation", "")
        if narrative:
            st.markdown(narrative)
        else:
            st.info("No narrative available.")

    # Download button
    st.download_button(
        label="⬇️ Download Evidence Report (JSON)",
        data=json.dumps(evidence, indent=2, default=str),
        file_name=f"evidence_{device_id}_w{selected_window}.json",
        mime="application/json",
        key=f"dl_ev_{device_id}_{selected_window}",
    )


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Drift signals overview
# ═════════════════════════════════════════════════════════════════════════════

def render_drift_overview(results: dict, selected_devices: List[str]) -> None:
    """Show drift signal summary across selected devices with individual signals."""
    st.markdown("### 🌊 Drift Signal Status")

    devices = results.get("devices", {})
    rows = []

    for dev_id in selected_devices:
        history = devices.get(dev_id, {}).get("history", [])
        if not history:
            continue
        last = history[-1]
        drift_windows = sum(1 for h in history if h.get("drift_confirmed", False))
        adwin_windows = sum(1 for h in history if h.get("adwin_drift", False))
        chi_windows = sum(1 for h in history if h.get("chi_drift", False))
        disagree_windows = sum(1 for h in history if h.get("disagree_drift", False))
        rows.append({
            "Device": get_device_name(dev_id),
            "ADWIN": "🔴" if last.get("adwin_drift") else "🟢",
            "Chi²": "🔴" if last.get("chi_drift") else "🟢",
            "Disagree": "🔴" if last.get("disagree_drift") else "🟢",
            "Drift Confirmed": "✅ Yes" if last.get("drift_confirmed") else "❌ No",
            "Drift Factor": f"{last.get('drift_factor', 1.0):.2f}",
            "Drift Windows": f"{drift_windows}/{len(history)}",
            "ADWIN Fires": adwin_windows,
            "Chi² Fires": chi_windows,
            "Disagree Fires": disagree_windows,
        })

    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No drift data available.")


def render_drift_events_timeline(results: dict, selected_devices: List[str]) -> None:
    """Show a table of drift events: when drift was detected and which signals fired."""
    st.markdown("### 📅 Drift Events Log")

    devices = results.get("devices", {})
    events = []

    for dev_id in selected_devices:
        history = devices.get(dev_id, {}).get("history", [])
        for h in history:
            if h.get("drift_confirmed", False):
                signals_fired = []
                if h.get("adwin_drift", False):
                    signals_fired.append("ADWIN")
                if h.get("chi_drift", False):
                    signals_fired.append("Chi²")
                if h.get("disagree_drift", False):
                    signals_fired.append("Disagree")
                events.append({
                    "Device": dev_id,
                    "Window": h["window"],
                    "Trust Score": f"{h.get('trust_score', 0):.1f}",
                    "Signals Fired": ", ".join(signals_fired) or "None",
                    "Drift Factor": f"{h.get('drift_factor', 1.0):.2f}",
                    "Anomaly Score": f"{h.get('anomaly_score', 0):.4f}",
                })

    if events:
        st.dataframe(
            pd.DataFrame(events),
            use_container_width=True,
            hide_index=True,
            height=min(400, 35 * len(events) + 38),
        )
        st.caption(f"Showing {len(events)} drift event(s) across {len(selected_devices)} device(s).")
    else:
        st.success("✅ No drift events detected across selected devices.")


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Policy violation overview
# ═════════════════════════════════════════════════════════════════════════════

def render_policy_overview(results: dict, selected_devices: List[str]) -> None:
    """Aggregate policy violation chart across selected devices."""
    st.markdown("### 🛡️ Policy Violations Overview")

    all_violations: Dict[str, Dict[str, int]] = {}
    devices = results.get("devices", {})

    for dev_id in selected_devices:
        history = devices.get(dev_id, {}).get("history", [])
        for h in history:
            for v in h.get("policy_violations", []):
                key = v.split("(")[0].strip()
                if key not in all_violations:
                    all_violations[key] = {"count": 0, "devices": set()}
                all_violations[key]["count"] += 1
                all_violations[key]["devices"].add(dev_id)

    if not all_violations:
        st.success("✅ No policy violations detected across selected devices.")
        return

    v_data = []
    for rule, info in sorted(all_violations.items(), key=lambda x: -x[1]["count"]):
        v_data.append({
            "Rule": rule,
            "Violations": info["count"],
            "Devices Affected": len(info["devices"]),
        })

    v_df = pd.DataFrame(v_data)
    fig = px.bar(
        v_df, x="Rule", y="Violations",
        color="Devices Affected",
        color_continuous_scale=["#4A9EFF", "#E74C3C"],
        text="Violations",
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        margin=dict(l=50, r=20, t=20, b=70),
        xaxis_tickangle=-25,
    )
    fig.update_traces(textposition="outside")
    st.plotly_chart(fig, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
#  UI Component: Feature heatmap
# ═════════════════════════════════════════════════════════════════════════════

def render_feature_heatmap(results: dict, device_id: str) -> None:
    """Heatmap of anomaly scores over time for a device (z-score proxy)."""
    st.markdown(f"### 🗺️ Anomaly Heatmap: `{device_id}`")

    history = get_device_history(results, device_id)
    if not history:
        st.info("No history data available.")
        return

    # We can show anomaly_score, drift_factor, trust across windows
    windows = [h["window"] for h in history]
    metrics = {
        "Anomaly": [h.get("anomaly_score", 0) for h in history],
        "IF Score": [h.get("if_score", 0) for h in history],
        "HST Score": [h.get("hst_score", 0) for h in history],
        "Drift Factor": [h.get("drift_factor", 1.0) for h in history],
    }

    z_data = np.array(list(metrics.values()))
    labels = list(metrics.keys())

    # Sample if too many windows
    max_cols = 150
    if len(windows) > max_cols:
        step = len(windows) // max_cols
        indices = list(range(0, len(windows), step))
        z_data = z_data[:, indices]
        windows = [windows[i] for i in indices]

    fig = go.Figure(data=go.Heatmap(
        z=z_data,
        x=[f"W{w}" for w in windows],
        y=labels,
        colorscale="YlOrRd",
        hovertemplate="Window: %{x}<br>Metric: %{y}<br>Value: %{z:.3f}<extra></extra>",
    ))
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=250,
        margin=dict(l=100, r=20, t=20, b=50),
        xaxis=dict(showticklabels=len(windows) < 50),
    )
    st.plotly_chart(fig, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
#  Sidebar
# ═════════════════════════════════════════════════════════════════════════════

def render_sidebar(config: dict, results: Optional[dict]) -> dict:
    """
    Render the sidebar with config summary and control panel.
    Returns a dict of user selections.
    """
    selections: Dict[str, Any] = {}

    with st.sidebar:
        st.markdown("## ⚙️ Configuration")

        # Config summary
        if config:
            models_cfg = config.get("models", {})
            if_w = models_cfg.get("isolation_forest", {}).get("weight", 0.6)
            hst_w = models_cfg.get("halfspacetrees", {}).get("weight", 0.4)
            st.markdown(
                f"**Model Weights:** IF {if_w*100:.0f}% · HST {hst_w*100:.0f}%"
            )

            drift_cfg = config.get("drift", {})
            signals = []
            if drift_cfg.get("adwin", {}).get("enabled"):
                signals.append("ADWIN")
            if drift_cfg.get("chi_squared", {}).get("enabled"):
                signals.append("Chi²")
            if drift_cfg.get("disagreement", {}).get("enabled"):
                signals.append("Disagree")
            st.markdown(f"**Drift Signals:** {', '.join(signals)}")

            policy_cfg = config.get("policy", {})
            rules = [k for k, v in policy_cfg.items()
                     if isinstance(v, dict) and v.get("enabled")]
            st.markdown(f"**Policy Rules:** {len(rules)} active")

            with st.expander("Show all rules"):
                for r in rules:
                    penalty = policy_cfg[r].get("penalty", "?")
                    st.markdown(f"- {r} (penalty: {penalty})")

        st.markdown("---")
        st.markdown("## 🎛️ Controls")

        # Device filter
        if results:
            all_devices = sorted(results.get("devices", {}).keys())
        else:
            all_devices = []

        selected_devices = st.multiselect(
            "Filter Devices",
            options=all_devices,
            default=all_devices,
            help="Select which devices to display in charts and tables.",
        )
        selections["devices"] = selected_devices

        # Severity filter
        severity_filter = st.multiselect(
            "Severity Filter",
            options=["NORMAL", "WARNING", "HIGH", "CRITICAL"],
            default=["NORMAL", "WARNING", "HIGH", "CRITICAL"],
        )
        selections["severity_filter"] = severity_filter

        st.markdown("---")
        st.markdown("## 📥 Data")

        # Download results
        if results:
            st.download_button(
                label="⬇️ Download Results (JSON)",
                data=json.dumps(results, indent=2, default=str),
                file_name="iot_trust_results.json",
                mime="application/json",
            )

        # Info
        st.markdown("---")
        st.markdown("## ℹ️ Severity Guide")
        for sev, cfg in SEVERITY_CONFIG.items():
            st.markdown(
                f"<span style='color:{cfg['color']}'>{cfg['icon']} **{sev}** "
                f"({cfg['range']})</span>",
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.caption(
            "IoT Trust & Drift Analytics v1.0 · "
            "Powered by Isolation Forest + Half-Space Trees"
        )

    return selections


# ═════════════════════════════════════════════════════════════════════════════
#  No-data fallback page
# ═════════════════════════════════════════════════════════════════════════════

def render_no_data_page() -> None:
    """Show instructions when no results.json is found."""
    st.markdown("""
    <div class="dashboard-header">
        <p class="dashboard-title">🔒 IoT Trust & Drift Analytics</p>
        <p class="dashboard-subtitle">No results data found</p>
    </div>
    """, unsafe_allow_html=True)

    st.warning("⚠️ No `results.json` file found. Run the analysis pipeline first.")

    st.markdown("""
    ### Getting Started

    1. **Ensure dataset files** are in the project directory (CSV files from CICIoT2023)

    2. **Run the pipeline:**
    ```bash
    python main.py
    ```

    3. **Then launch the dashboard:**
    ```bash
    streamlit run dashboard.py
    ```

    #### Optional arguments for `main.py`:
    | Flag | Description | Default |
    |------|-------------|---------|
    | `--config` | Config file path | `config.yaml` |
    | `--device` | Analyse specific device | All devices |
    | `--windows` | Max windows per device | All windows |
    | `--verbose` | Detailed per-window output | False |
    | `--output`  | Output JSON path | `results.json` |
    """)


# ═════════════════════════════════════════════════════════════════════════════
#  Main app entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Main Streamlit app."""
    inject_custom_css()

    # Load data
    config = load_config()
    results = load_results()

    # Initialise session state
    if "selected_device" not in st.session_state:
        st.session_state["selected_device"] = None
    if "show_detail" not in st.session_state:
        st.session_state["show_detail"] = False
    if "show_evidence" not in st.session_state:
        st.session_state["show_evidence"] = False
    if "notif_open" not in st.session_state:
        st.session_state["notif_open"] = False

    # ── No data fallback ─────────────────────────────────────────
    if results is None:
        render_sidebar(config, None)
        render_no_data_page()
        return

    # ── Build notifications early (needed for header) ────────────
    notifications = get_drift_notifications(results)

    # ── Sidebar ──────────────────────────────────────────────────
    selections = render_sidebar(config, results)
    selected_devices = selections.get("devices", [])
    severity_filter = selections.get("severity_filter", [])

    # Apply severity filter to device list
    if severity_filter:
        devices_data = results.get("devices", {})
        selected_devices = [
            d for d in selected_devices
            if devices_data.get(d, {}).get("severity", "UNKNOWN") in severity_filter
        ]

    # ── Header (with notification bell) ─────────────────────────
    render_header(notifications)

    # ── Metrics row ──────────────────────────────────────────────
    summary = results.get("summary", {})
    device_df = build_device_dataframe(results)

    # Filter the DataFrame to selected devices
    if selected_devices:
        device_df = device_df[device_df["Device IP"].isin(selected_devices)]

    render_metrics_row(summary, device_df)

    st.markdown("")  # spacer

    # ── If alerts panel is open, show it instead of tabs ─────────
    if st.session_state.get("notif_open", False):
        render_alerts_panel(notifications)
        return  # skip rendering the rest of the dashboard

    # ── Tabs for main content ────────────────────────────────────
    tab_overview, tab_devices, tab_evidence, tab_advanced, tab_live = st.tabs([
        "📈 Overview", "📋 Devices", "📄 Evidence Reports", "🔬 Advanced", "🔴 Live Replay",
    ])

    # ── Tab 1: Overview ──────────────────────────────────────────
    with tab_overview:
        if selected_devices:
            render_trust_timeline(results, selected_devices)

            col_l, col_r = st.columns(2)
            with col_l:
                render_drift_overview(results, selected_devices)
            with col_r:
                render_policy_overview(results, selected_devices)

            # Drift events log — shows exactly when and where drift was detected
            render_drift_events_timeline(results, selected_devices)
        else:
            st.info("Select at least one device from the sidebar to view charts.")

    # ── Tab 2: Devices ───────────────────────────────────────────
    with tab_devices:
        render_device_table(device_df)

    # ── Tab 3: Evidence ──────────────────────────────────────────
    with tab_evidence:
        if selected_devices:
            ev_device = st.selectbox(
                "Select device for evidence reports:",
                selected_devices,
                key="ev_device_select",
            )
            if ev_device:
                render_evidence_viewer(results, ev_device)
        else:
            st.info("Select at least one device from the sidebar.")

    # ── Tab 4: Advanced ──────────────────────────────────────────
    with tab_advanced:
        if selected_devices:
            hm_device = st.selectbox(
                "Select device for heatmap:",
                selected_devices,
                key="hm_device_select",
            )
            if hm_device:
                render_feature_heatmap(results, hm_device)

            # Score distribution
            st.markdown("### 📊 Trust Score Distribution")
            if not device_df.empty:
                fig_dist = px.histogram(
                    device_df, x="Score", nbins=20,
                    color_discrete_sequence=[COLORS["accent"]],
                    labels={"Score": "Final Trust Score"},
                )
                fig_dist.add_vrect(x0=0, x1=30, fillcolor=COLORS["critical"],
                                   opacity=0.08, line_width=0)
                fig_dist.add_vrect(x0=30, x1=50, fillcolor=COLORS["high"],
                                   opacity=0.08, line_width=0)
                fig_dist.add_vrect(x0=50, x1=70, fillcolor=COLORS["warning"],
                                   opacity=0.08, line_width=0)
                fig_dist.add_vrect(x0=70, x1=100, fillcolor=COLORS["normal"],
                                   opacity=0.08, line_width=0)
                fig_dist.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=300,
                    margin=dict(l=50, r=20, t=20, b=50),
                )
                st.plotly_chart(fig_dist, use_container_width=True)

            # Raw config viewer
            with st.expander("⚙️ Full Configuration (YAML)", expanded=False):
                st.code(yaml.dump(config, default_flow_style=False), language="yaml")
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
            chart_placeholder = st.empty()
            metrics_placeholder = st.empty()
            status_placeholder = st.empty()
            live_alert_placeholder = st.empty()
            
            palette = px.colors.qualitative.Set2 + px.colors.qualitative.Pastel1
            device_colors = {
                d: palette[i % len(palette)]
                for i, d in enumerate(live_device_filter)
            }

            for device_id, window in timeline:
                live_histories[device_id].append(window)
                
                live_alert_count = 0
                live_critical = 0
                live_high = 0
                live_warning = 0
                for d, hist in live_histories.items():
                    if not hist:
                        continue
                    last_w = hist[-1]
                    score = last_w.get("trust_score", 100)
                    sev = last_w.get("severity", "NORMAL")
                    if last_w.get("drift_confirmed") or score < 70:
                        live_alert_count += 1
                        if sev == "CRITICAL":   live_critical += 1
                        elif sev == "HIGH":     live_high += 1
                        elif sev == "WARNING":  live_warning += 1

                # Rebuild chart
                fig_live = go.Figure()
                fig_live.add_hrect(y0=70, y1=100, fillcolor=COLORS["normal"], opacity=0.08, line_width=0, layer="below")
                fig_live.add_hrect(y0=50, y1=70, fillcolor=COLORS["warning"], opacity=0.08, line_width=0, layer="below")
                fig_live.add_hrect(y0=30, y1=50, fillcolor=COLORS["high"],    opacity=0.08, line_width=0, layer="below")
                fig_live.add_hrect(y0=0,  y1=30, fillcolor=COLORS["critical"],opacity=0.08, line_width=0, layer="below")
                for y, label in [(70, "Normal"), (50, "Warning"), (30, "Critical")]:
                    fig_live.add_hline(
                        y=y, line_dash="dot", line_color="#444", line_width=1, opacity=0.5,
                        annotation_text=label, annotation_position="right",
                        annotation_font_color="#666", annotation_font_size=10,
                    )

                for dev_id in live_device_filter:
                    hist = live_histories[dev_id]
                    if not hist:
                        continue
                    fig_live.add_trace(go.Scatter(
                        x=[h["window"] for h in hist],
                        y=[h["trust_score"] for h in hist],
                        mode="lines",
                        name=get_device_name(dev_id),
                        line=dict(width=2.5, color=device_colors[dev_id]),
                        hovertemplate=f"<b>{get_device_name(dev_id)}</b><br>Window: %{{x}}<br>Trust: %{{y:.1f}}<extra></extra>",
                    ))

                fig_live.update_layout(
                    title="Live Trust Score Feed",
                    xaxis_title="Window Index",
                    yaxis_title="Trust Score",
                    yaxis=dict(range=[0, 105], dtick=10),
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=480,
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                    margin=dict(l=50, r=30, t=60, b=50),
                    hovermode="x unified",
                )

                with chart_placeholder.container():
                    st.plotly_chart(fig_live, use_container_width=True)
                
                with live_alert_placeholder.container():
                    if live_alert_count > 0:
                        parts = []
                        if live_critical:
                            parts.append(f'<span style="color:#E74C3C;font-weight:800;">'
                                        f'🔴 {live_critical} Critical</span>')
                        if live_high:
                            parts.append(f'<span style="color:#FF6B35;font-weight:800;">'
                                        f'🔶 {live_high} High</span>')
                        if live_warning:
                            parts.append(f'<span style="color:#FFB81C;font-weight:800;">'
                                        f'⚠️ {live_warning} Warning</span>')
                        summary = " &nbsp;·&nbsp; ".join(parts)
                        st.markdown(
                            f'<div style="background:rgba(231,76,60,0.08);border:1px solid '
                            f'rgba(231,76,60,0.35);border-radius:10px;padding:10px 16px;'
                            f'margin-bottom:8px;display:flex;align-items:center;gap:12px;">'
                            f'<span style="font-size:1.1rem;font-weight:800;color:#E74C3C;">'
                            f'🔔 {live_alert_count} Live Alert'
                            f'{"s" if live_alert_count != 1 else ""}</span>'
                            f'&nbsp;&nbsp;{summary}</div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            '<div style="background:rgba(0,176,80,0.07);border:1px solid '
                            'rgba(0,176,80,0.25);border-radius:10px;padding:10px 16px;'
                            'margin-bottom:8px;">'
                            '<span style="color:#00B050;font-weight:700;">✅ All devices normal</span>'
                            '</div>',
                            unsafe_allow_html=True,
                        )

                # Update per-device score cards
                with metrics_placeholder.container():
                    mcols = st.columns(min(len(live_device_filter), 6))
                    for idx, dev_id in enumerate(live_device_filter):
                        hist = live_histories[dev_id]
                        if hist:
                            last = hist[-1]
                            score = last["trust_score"]
                            sev = last["severity"]
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

    # ── Button-triggered detail / evidence views ─────────────────
    # Rendered OUTSIDE tabs so they appear regardless of which tab
    # is active when the user clicks a device button.
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


# ═════════════════════════════════════════════════════════════════════════════
#  Run
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    main()