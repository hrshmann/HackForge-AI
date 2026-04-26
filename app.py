"""
HackForge AI — Security Scanner
Integrated Hybrid Vulnerability Scanner
"""

import json
import time
import traceback
from datetime import datetime

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from scanner.scanner import run_scan as backend_run_scan
from scanner.report_generator import ReportGenerator

# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="HackForge AI",
    page_icon="assets/favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# STYLES
# =============================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Syne:wght@400;600;700;800&display=swap');

:root {
    --bg: #05060a;
    --surface: rgba(13,16,23,0.88);
    --surface2: rgba(9,12,18,0.95);
    --border: rgba(38,46,68,0.55);
    --border-hi: rgba(72,86,120,0.75);
    --green: #1aff8c;
    --green-dim: #0d8a4a;
    --red: #ff4545;
    --amber: #f5a623;
    --blue: #7ad9ff;
    --text: #c8cdd8;
    --text-dim: #5a6070;
    --text-hi: #eef0f5;
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'Syne', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 18% 20%, rgba(26,255,140,0.02), transparent 25%),
        radial-gradient(circle at 82% 10%, rgba(122,217,255,0.018), transparent 20%),
        linear-gradient(rgba(255,255,255,0.012) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.012) 1px, transparent 1px),
        var(--bg);
    background-size: auto, auto, 38px 38px, 38px 38px, auto;
    color: var(--text);
    overflow-x: hidden;
    animation: driftGrid 18s linear infinite;
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        to bottom,
        rgba(255,255,255,0.010),
        rgba(255,255,255,0.010) 1px,
        transparent 2px,
        transparent 4px
    );
    opacity: 0.14;
    pointer-events: none;
    z-index: 0;
}

.stApp::after {
    content: "THREAT VECTOR   •   PAYLOAD CORRELATION   •   ATTACK SURFACE";
    position: fixed;
    bottom: 6%;
    right: 3%;
    font-family: var(--mono);
    font-size: 2rem;
    letter-spacing: 6px;
    color: rgba(255,60,60,0.025);
    pointer-events: none;
    z-index: 0;
}

.stApp .main::before {
    content: "THREAT ANALYSIS GRID";
    position: fixed;
    top: 9%;
    left: 32%;
    font-family: var(--mono);
    font-size: 1.25rem;
    letter-spacing: 7px;
    color: rgba(122,217,255,0.025);
    pointer-events: none;
    z-index: 0;
}

.block-container {
    padding: 2rem 2.5rem 3rem;
    max-width: 1400px;
    position: relative;
    z-index: 2;
}

.block-container::before {
    content: "";
    position: fixed;
    top: 14%;
    right: 10%;
    width: 230px;
    height: 230px;
    border: 1px solid rgba(255,70,70,0.028);
    border-radius: 50%;
    box-shadow:
        0 0 0 28px rgba(255,70,70,0.008),
        0 0 0 56px rgba(255,70,70,0.004);
    pointer-events: none;
    z-index: 0;
}

.block-container::after {
    content: "";
    position: fixed;
    bottom: 10%;
    left: 24%;
    width: 180px;
    height: 180px;
    border: 1px solid rgba(122,217,255,0.03);
    transform: rotate(45deg);
    pointer-events: none;
    z-index: 0;
}

section[data-testid="stSidebar"] {
    background:
        radial-gradient(circle at top left, rgba(26,255,140,0.025), transparent 35%),
        var(--surface2);
    border-right: 1px solid var(--border);
    box-shadow: inset -1px 0 20px rgba(26,255,140,0.015);
}

section[data-testid="stSidebar"]::before {
    content: "";
    position: absolute;
    top: 0;
    right: 0;
    width: 2px;
    height: 100%;
    background: linear-gradient(to bottom, transparent, rgba(255,60,60,0.12), transparent);
    animation: pulseDot 3s infinite;
}

.hf-wordmark {
    font-family: var(--sans);
    font-weight: 800;
    font-size: 2rem;
    color: var(--text-hi);
    line-height: 1;
}
.hf-wordmark span { color: var(--green); }

.hf-sub {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--text-dim);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 0.2rem;
}

.hf-divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.4rem 0;
}

.section-label {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--text-dim);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
}

.section-title {
    font-family: var(--sans);
    font-size: 1.3rem;
    font-weight: 700;
    color: var(--text-hi);
    margin-bottom: 1rem;
}

.phase-row { display:flex; gap:0.6rem; margin:1rem 0; }

.phase {
    flex:1;
    background: var(--surface);
    border:1px solid var(--border);
    padding:0.6rem;
    text-align:center;
    font-family:var(--mono);
    font-size:0.72rem;
    color:var(--text-dim);
    backdrop-filter: blur(8px);
}
.phase.active {
    color:var(--blue);
    border-color:rgba(122,217,255,0.35);
}
.phase.done {
    color:var(--green);
    border-color:rgba(26,255,140,0.25);
}

.kpi-row { display:flex; gap:0.9rem; margin:1.2rem 0; }

.kpi {
    flex:1;
    background:var(--surface);
    border:1px solid var(--border);
    border-top:2px solid rgba(122,217,255,0.4);
    padding:1rem;
    backdrop-filter: blur(10px);
}
.kpi.red { border-top-color:rgba(255,69,69,0.5); }
.kpi.amber { border-top-color:rgba(245,166,35,0.5); }
.kpi.blue { border-top-color:rgba(122,217,255,0.5); }

.k-label {
    font-family:var(--mono);
    font-size:0.65rem;
    color:var(--text-dim);
    letter-spacing:2px;
    text-transform:uppercase;
}
.k-value {
    font-family:var(--sans);
    font-size:2rem;
    font-weight:700;
    color:var(--green);
}

.banner {
    padding:1rem 1.4rem;
    margin:0.8rem 0;
    backdrop-filter: blur(10px);
}
.banner.danger {
    background:rgba(255,61,61,0.04);
    border-left:3px solid var(--red);
}
.banner.safe {
    background:rgba(26,255,140,0.035);
    border-left:3px solid var(--green);
}

.stButton > button {
    background: rgba(122,217,255,0.015) !important;
    color: var(--blue) !important;
    border: 1px solid rgba(122,217,255,0.32) !important;
    border-radius: 6px !important;
    font-family: var(--mono) !important;
    transition: all 0.25s ease !important;
    height: 52px !important;
    min-height: 52px !important;
    margin-top: 0 !important;
}
.stButton > button:hover {
    box-shadow: 0 0 14px rgba(122,217,255,0.08) !important;
    transform: translateY(-1px);
}

.stTextInput input {
    background: var(--surface) !important;
    color: var(--text-hi) !important;
    border: 1px solid var(--border-hi) !important;
    border-radius: 6px !important;
    height: 52px !important;
    min-height: 52px !important;
}

.stSlider > div[data-baseweb="slider"] * {
    color: var(--green) !important;
}

.stProgress > div > div > div {
    background: linear-gradient(90deg, #1f8fff, #1aff8c) !important;
}

.hud-panel {
    position: relative;
    background: rgba(9,12,18,0.82);
    border: 1px solid rgba(55,70,95,0.45);
    padding: 1rem 1.2rem;
    margin-top: 1.2rem;
    overflow: hidden;
}

.hud-panel::before {
    content: "";
    position: absolute;
    top: 0;
    left: -100%;
    width: 60%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(122,217,255,0.05), transparent);
    animation: sweepLine 6s linear infinite;
}

.telemetry-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.9rem;
    position: relative;
    z-index: 2;
}

.telemetry-box {
    background: rgba(15,18,24,0.65);
    border: 1px solid rgba(42,52,76,0.4);
    padding: 0.8rem;
}

.telemetry-label {
    font-family: var(--mono);
    font-size: 0.62rem;
    color: #6f7f96;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.telemetry-value {
    font-family: var(--sans);
    font-size: 0.95rem;
    color: #d8e4f2;
    margin-top: 0.35rem;
}

.status-dot {
    display:inline-block;
    width:8px;
    height:8px;
    margin-right:6px;
    border-radius:50%;
    background:#7ad9ff;
    animation:pulseDot 2.2s infinite;
}

.tactical-separator {
    margin-top: 1rem;
    height: 16px;
    position: relative;
    opacity: 0.45;
}
.tactical-separator::before {
    content: "";
    position: absolute;
    top: 7px;
    left: 0;
    width: 100%;
    height: 1px;
    background: linear-gradient(to right, transparent, rgba(122,217,255,0.14), rgba(255,60,60,0.08), rgba(122,217,255,0.14), transparent);
}
.tactical-separator::after {
    content: "◈     ◈     ◈";
    position: absolute;
    top: -1px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.6rem;
    color: rgba(122,217,255,0.18);
    letter-spacing: 16px;
}

@keyframes sweepLine {
    0% { transform: translateX(-120%); opacity: 0; }
    20% { opacity: 0.18; }
    50% { opacity: 0.06; }
    100% { transform: translateX(220%); opacity: 0; }
}

@keyframes pulseDot {
    0% { opacity: 0.25; }
    50% { opacity: 1; }
    100% { opacity: 0.25; }
}

@keyframes driftGrid {
    0% { background-position: 0 0, 0 0, 0 0, 0 0, 0 0; }
    100% { background-position: 0 0, 0 0, 38px 38px, 38px 38px, 0 0; }
}
div[data-testid="stTextInput"] {
    margin-top: -18px !important;
    margin-bottom: 0px !important;
}

div[data-testid="stTextInput"] > div {
    margin-top: 0px !important;
    padding-top: 0px !important;
}
</style>
""", unsafe_allow_html=True)
# =============================================================================
# SESSION STATE
# =============================================================================

def init_state():
    defaults = {
        "scan_results": None,
        "scanning": False,
        "model_ready": True,
        "scan_triggered": False
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

PLOTLY_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#c8cdd8", family="Syne"),
    margin=dict(l=16, r=16, t=40, b=16),
)

# =============================================================================
# SCAN PIPELINE
# =============================================================================

def run_scan(target_url, max_depth, max_pages, enable_active):
    try:
        result = backend_run_scan(target_url, max_depth=max_depth, max_pages=max_pages)

        findings = result["final_findings"]

        risk = {
            "overall_score": result["risk_score"],
            "critical_count": sum(1 for x in findings if x["severity"] == "critical"),
            "high_count": sum(1 for x in findings if x["severity"] == "high"),
            "medium_count": sum(1 for x in findings if x["severity"] == "medium"),
            "low_count": sum(1 for x in findings if x["severity"] == "low"),
        }

        scan_data = {
            "scan_id": f"HF-{int(time.time())}",
            "target_url": result["target_url"],
            "duration": 0,
            "crawl_data": result["raw_crawl_data"],
            "ml_predictions": result["ml_predictions"],
            "validated_results": findings,
            "risk_assessment": risk,
        }

        report_gen = ReportGenerator(scan_data)
        scan_data["report"] = report_gen.generate()

        return scan_data

    except Exception:
        traceback.print_exc()
        st.error("Scan failed. See terminal for traceback.")
        return None
# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.markdown("""
    <div class="hf-wordmark">Hack<span>Forge</span></div>
    <div class="hf-sub">Tactical Vulnerability Console</div>
    <hr class="hf-divider">
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-label">Threat Modules</div>', unsafe_allow_html=True)

    modules = [
        ("SQL Injection", "ARMED"),
        ("Cross-Site Scripting", "ARMED"),
        ("Security Misconfiguration", "PASSIVE"),
        ("Broken Access Control", "PASSIVE"),
        ("Authentication Issues", "PASSIVE"),
        ("Insecure Components", "PASSIVE")
    ]

    for name, stat in modules:
        color = "#7ad9ff" if stat == "ARMED" else "#6f7f96"
        st.markdown(
            f'''
            <div style="
                border:1px solid rgba(42,52,76,0.35);
                padding:0.45rem 0.55rem;
                margin-bottom:0.35rem;
                font-family:var(--mono);
                font-size:0.68rem;
                display:flex;
                justify-content:space-between;
                background:rgba(10,14,20,0.55);
            ">
                <span style="color:var(--text);">{name}</span>
                <span style="color:{color};">{stat}</span>
            </div>
            ''',
            unsafe_allow_html=True
        )

    st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)
    st.markdown('<div class="section-label">Scan Controls</div>', unsafe_allow_html=True)

    max_depth = st.slider("Crawl depth", 1, 5, 3)
    max_pages = st.slider("Page limit", 10, 100, 50)
    enable_active = st.checkbox("Active testing", value=True)

    st.markdown(
        f'''
        <div style="
            margin-top:0.8rem;
            padding:0.7rem;
            border:1px solid rgba(42,52,76,0.35);
            background:rgba(10,14,20,0.45);
            font-family:var(--mono);
            font-size:0.65rem;
            color:#7ad9ff;
            line-height:1.8;
        ">
        Scan Profile: Hybrid Offensive Recon<br>
        Attack Depth: L{max_depth}<br>
        Target Budget: {max_pages} Nodes
        </div>
        ''',
        unsafe_allow_html=True
    )

    st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)
    st.markdown('<div class="section-label">System Telemetry</div>', unsafe_allow_html=True)

    st.markdown(
        f'''
        <div style="
            border:1px solid rgba(42,52,76,0.35);
            padding:0.7rem;
            background:rgba(10,14,20,0.45);
            font-family:var(--mono);
            font-size:0.65rem;
            color:#8a94a8;
            line-height:1.9;
        ">
        Backend Core ........ ONLINE<br>
        ML Heuristics ....... LOADED<br>
        Payload Matrix ...... 942<br>
        Signature Feed ...... SYNC<br>
        Threat Bus .......... LIVE<br>
        Console State ....... READY
        </div>
        ''',
        unsafe_allow_html=True
    )

# =============================================================================
# MAIN HEADER
# =============================================================================

col_h, col_meta = st.columns([3, 1])

with col_h:
    st.markdown("""
    <div class="hf-wordmark" style="font-size:2.6rem;">Hack<span>Forge</span> AI</div>
    <div class="hf-sub">AI-Powered Web Vulnerability Assessment</div>
    """, unsafe_allow_html=True)

with col_meta:
    if st.session_state.scan_results:
        r = st.session_state.scan_results
        st.markdown(
            f'<div style="font-family:var(--mono);font-size:0.7rem;color:var(--text-dim);'
            f'text-align:right;margin-top:0.5rem;">'
            f'Last scan&nbsp;&nbsp;{r["duration"]}s<br>'
            f'{r["scan_id"]}'
            f'</div>',
            unsafe_allow_html=True
        )

st.markdown("""
<div class="hud-panel">
    <div class="telemetry-grid">
        <div class="telemetry-box">
            <div class="telemetry-label">Subsystem</div>
            <div class="telemetry-value"><span class="status-dot"></span>Crawler Engine Online</div>
        </div>
        <div class="telemetry-box">
            <div class="telemetry-label">ML Core</div>
            <div class="telemetry-value"><span class="status-dot"></span>Model Loaded</div>
        </div>
        <div class="telemetry-box">
            <div class="telemetry-label">Payload Matrix</div>
            <div class="telemetry-value"><span class="status-dot"></span>Exploit Signatures Armed</div>
        </div>
        <div class="telemetry-box">
            <div class="telemetry-label">Threat Sync</div>
            <div class="telemetry-value"><span class="status-dot"></span>Live Diagnostic Channel</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)

# =============================================================================
# TABS
# =============================================================================

tab_scan, tab_results, tab_analytics, tab_kb = st.tabs(
    ["SCANNER", "RESULTS", "ANALYTICS", "REFERENCE"]
)

# =============================================================================
# TAB 1 SCANNER
# =============================================================================

with tab_scan:
    st.markdown("<div style='margin-top:0.1rem;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="margin-bottom:0.99rem;">Target</div>', unsafe_allow_html=True)

    col_input, col_btn = st.columns([6.4, 1.1], gap="small")

    with col_input:
        target_url = st.text_input(
            "Target URL",
            placeholder="https://target.example.com",
            label_visibility="collapsed",
        )

    with col_btn:
        run_btn = st.button("RUN SCAN", use_container_width=True)
        st.markdown("<div style='margin-bottom:0.6rem;'></div>", unsafe_allow_html=True)
    if run_btn and not st.session_state.scanning and not st.session_state.scan_triggered:
        if not target_url:
            st.error("Enter a target URL.")
        elif not target_url.startswith(("http://", "https://")):
            st.error("URL must start with http:// or https://")
        else:
            st.session_state.scan_triggered = True
            st.session_state.scanning = True

            status_text = st.empty()
            progress_bar = st.progress(0)

            st.markdown("<div style='margin-top:0.7rem;'></div>", unsafe_allow_html=True)

            diag1, diag2, diag3, diag4 = st.columns(4)
            box1 = diag1.empty()
            box2 = diag2.empty()
            box3 = diag3.empty()
            box4 = diag4.empty()

            phases = [
                ("Enumerating attack surface...", 18, [True, False, False, False]),
                ("Building dynamic route graph...", 36, [True, True, False, False]),
                ("Running supervised ML correlation...", 58, [True, True, True, False]),
                ("Deploying active payload matrix...", 78, [True, True, True, True]),
                ("Validating response anomalies...", 92, [True, True, True, True]),
                ("Correlating hybrid threat signals...", 100, [True, True, True, True]),
            ]

            for text, pct, active_map in phases:
                status_text.markdown(
                    f'<div style="font-family:var(--mono);font-size:0.9rem;color:#9cc9ff;margin-top:0.7rem;">{text}</div>',
                    unsafe_allow_html=True
                )

                progress_bar.progress(pct)

                labels = ["Crawling", "ML Analysis", "Active Testing", "Validation"]
                boxes = [box1, box2, box3, box4]

                for i in range(4):
                    color = "var(--green)" if active_map[i] else "var(--text-dim)"
                    border = "var(--green-dim)" if active_map[i] else "var(--border)"
                    glow = "0 0 12px rgba(26,255,140,0.05)" if active_map[i] else "none"

                    boxes[i].markdown(f'''
                        <div style="
                            background:var(--surface);
                            border:1px solid {border};
                            padding:0.8rem;
                            text-align:center;
                            font-family:var(--mono);
                            color:{color};
                            box-shadow:{glow};
                        ">
                            {labels[i]}
                        </div>
                    ''', unsafe_allow_html=True)

                time.sleep(0.55)

            result = run_scan(target_url, max_depth, max_pages, enable_active)

            st.session_state.scanning = False
            st.session_state.scan_triggered = False

            if result:
                st.session_state.scan_results = result
                st.success("Scan completed successfully.")

    if st.session_state.scan_results and not st.session_state.scanning:
        st.markdown(
            '<div style="font-family:var(--mono);font-size:0.8rem;color:var(--green-dim);margin-top:1rem;">'
            'Scan complete — view results in the RESULTS tab.'
            '</div>',
            unsafe_allow_html=True,
        )
# =============================================================================
# TAB 2 RESULTS
# =============================================================================

with tab_results:
    if not st.session_state.scan_results:
        st.markdown(
            '<div style="font-family:var(--mono);font-size:0.85rem;color:var(--text-dim);margin-top:2rem;">'
            'No scan data. Run a scan from the SCANNER tab.'
            '</div>',
            unsafe_allow_html=True,
        )
        st.stop()

    data = st.session_state.scan_results
    report = data["report"]
    risk = data["risk_assessment"]
    findings = report.get("findings", [])
    pages = data["crawl_data"].get("pages", [])
    ml_preds = data.get("ml_predictions", {})
    ml_vuln_count = len(ml_preds)

    if risk["critical_count"] > 0 or risk["high_count"] > 0:
        st.markdown(f"""
        <div class="banner danger">
            <div style="font-weight:700;font-size:1.05rem;color:#ff3d3d;">Vulnerabilities Detected</div>
            <div>
                {risk['critical_count']} critical / {risk['high_count']} high severity vulnerabilities identified.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="banner safe">
            <div style="font-weight:700;font-size:1.05rem;color:#1aff8c;">No Critical Issues Found</div>
            <div>Application passed baseline vulnerability checks.</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="kpi-row">
        <div class="kpi">
            <div class="k-label">Security Score</div>
            <div class="k-value">{risk['overall_score']}</div>
        </div>
        <div class="kpi red">
            <div class="k-label">Critical</div>
            <div class="k-value">{risk['critical_count']}</div>
        </div>
        <div class="kpi amber">
            <div class="k-label">High</div>
            <div class="k-value">{risk['high_count']}</div>
        </div>
        <div class="kpi blue">
            <div class="k-label">ML Flagged</div>
            <div class="k-value">{ml_vuln_count}</div>
        </div>
        <div class="kpi">
            <div class="k-label">Pages</div>
            <div class="k-value">{len(pages)}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)

    with st.expander(f"Hybrid ML Analysis — {len(ml_preds)} targets analysed"):
        if ml_preds:
            import pandas as pd
            rows = []
            for url, pred in ml_preds.items():
                for k, v in pred.items():
                    rows.append({
                        "URL": url,
                        "Vulnerability": k,
                        "Confidence": f"{round(v.get('confidence',0)*100,1)}%",
                        "Severity": v.get("severity","low")
                    })
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown(
        f'<div class="section-title">Findings <span style="font-size:1rem;color:var(--text-dim);">{len(findings)} total</span></div>',
        unsafe_allow_html=True,
    )

    if not findings:
        st.info("No vulnerabilities detected in this scan.")
    else:
        for f in findings:
            sev = f["severity"].lower()
            with st.expander(
                f"{f['severity'].upper()} — {f.get('title', f.get('vulnerability_type','Finding'))} — {f.get('url','')}",
                expanded=(sev == "critical")
            ):
                st.markdown(f"**Description:** {f.get('description', f.get('vulnerability_type','Security Issue Detected'))}")
                st.markdown(f"**Impact:** {f.get('impact', 'Potential security exploitation possible.')}")
                st.markdown(
                    f"**Confidence:** {round(f.get('confidence',0)*100 if f.get('confidence',0)<=1 else f.get('confidence',0),2)}% | "
                    f"**CVSS:** {f.get('cvss_score','N/A')} | "
                    f"**CWE:** {f.get('cwe','N/A')}"
                )

                rem = f.get("remediation")
                if rem and isinstance(rem, dict):
                    if rem.get("summary"):
                        st.info(rem["summary"])
                    if rem.get("steps"):
                        for step in rem["steps"]:
                            st.markdown(f"- {step}")

    st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)

    dl1, dl2, _ = st.columns([1,1,2])

    with dl1:
        st.download_button(
            "JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"hackforge_{data['scan_id']}.json",
            mime="application/json",
            use_container_width=True,
        )

    with dl2:
        rg = ReportGenerator(data)
        st.download_button(
            "Text Summary",
            data=rg.export_summary(),
            file_name=f"hackforge_{data['scan_id']}_summary.txt",
            mime="text/plain",
            use_container_width=True,
        )

# =============================================================================
# TAB 3 ANALYTICS
# =============================================================================

with tab_analytics:
    if not st.session_state.scan_results:
        st.info("Complete a scan to view analytics.")
        st.stop()

    data = st.session_state.scan_results
    risk = data["risk_assessment"]
    findings = data["report"].get("findings", [])
    ml_preds = data.get("ml_predictions", {})

    st.markdown('<div class="section-title">Analytics</div>', unsafe_allow_html=True)

    col_pie, col_bar = st.columns(2)

    with col_pie:
        labels = ["Critical", "High", "Medium", "Low"]
        values = [
            int(risk.get("critical_count", 0)),
            int(risk.get("high_count", 0)),
            int(risk.get("medium_count", 0)),
            int(risk.get("low_count", 0)),
        ]

        if sum(values) > 0:
            fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.55)])
            fig.update_layout(title="Findings by Severity", **PLOTLY_THEME)
            st.plotly_chart(fig, use_container_width=True)

    with col_bar:
        if sum(values) > 0:
            fig = go.Figure(data=[go.Bar(x=labels, y=values)])
            fig.update_layout(title="Severity Distribution", **PLOTLY_THEME)
            st.plotly_chart(fig, use_container_width=True)

    if ml_preds:
        import pandas as pd

        confs = []
        for url, pred in ml_preds.items():
            for k, v in pred.items():
                confs.append(round(v.get("confidence", 0) * 100, 2))

        if confs:
            fig = go.Figure(data=[go.Histogram(x=confs, nbinsx=10)])
            fig.update_layout(title="ML Confidence Distribution", **PLOTLY_THEME)
            st.plotly_chart(fig, use_container_width=True)

    if findings:
        vuln_types = {}
        for f in findings:
            title = f.get("title", f.get("vulnerability_type", "Unknown"))
            vuln_types[title] = vuln_types.get(title, 0) + 1

        fig = px.bar(
            x=list(vuln_types.keys()),
            y=list(vuln_types.values()),
            labels={"x": "Vulnerability Type", "y": "Count"},
        )
        fig.update_layout(title="Vulnerability Types", showlegend=False, **PLOTLY_THEME)
        st.plotly_chart(fig, use_container_width=True)

# =============================================================================
# TAB 4 REFERENCE
# =============================================================================

with tab_kb:
    st.markdown('<div class="section-title">Reference</div>', unsafe_allow_html=True)

    r1, r2 = st.columns(2)

    with r1:
        st.markdown("""
**Severity Levels**

| CVSS | Level | Response SLA |
|------|-------|-------------|
| 9.0–10.0 | Critical | Immediate |
| 7.0–8.9  | High     | < 7 days  |
| 4.0–6.9  | Medium   | < 30 days |
| 0.1–3.9  | Low      | Planned   |
""")

        st.markdown("""
**SQL Injection** — Unsanitised input reaches SQL interpreter.  
Fix: parameterised queries and prepared statements.

**Cross-Site Scripting** — Attacker-controlled script executes in victim browser.  
Fix: output encoding and CSP.

**Security Misconfiguration** — Missing headers or weak defaults.  
Fix: harden deployment baseline.
""")

    with r2:
        st.markdown("""
**Defensive Checklist**

1. Validate all input server-side.
2. Enforce MFA and strong credential policies.
3. Apply least privilege.
4. Enforce HTTPS.
5. Centralise logs.
6. Scan dependencies regularly.
7. Rotate secrets.
""")

        st.markdown("""
**Resources**

- OWASP Top 10
- CWE/SANS Top 25
- NIST Cybersecurity Framework
- PortSwigger Web Security Academy
""")

# =============================================================================
# FOOTER
# =============================================================================

st.markdown('<hr class="hf-divider">', unsafe_allow_html=True)

fc1, fc2, fc3 = st.columns(3)

fc1.markdown(
    '<div style="font-family:var(--mono);font-size:0.7rem;color:#5a6070;">HackForge AI v2.0.0</div>',
    unsafe_allow_html=True,
)

fc2.markdown(
    '<div style="font-family:var(--mono);font-size:0.7rem;color:#5a6070;text-align:center;">Hybrid Active Scanner + ML Intelligence</div>',
    unsafe_allow_html=True,
)

fc3.markdown(
    f'<div style="font-family:var(--mono);font-size:0.7rem;color:#5a6070;text-align:right;">{datetime.now().strftime("%Y-%m-%d")}</div>',
    unsafe_allow_html=True,
)
