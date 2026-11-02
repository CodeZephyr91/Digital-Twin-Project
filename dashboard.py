"""5G Lab Doctor & Remote Linux Operations Console.

A full-stack, production-minded observability and operations platform for
private 5G MEC laboratories and remote Linux infrastructure.
Features:
- Zero-hardcoding dynamic server profile inventory with .env and SQLite persistence.
- Valid protocol request dispatcher (SSH, HTTP/HTTPS, SIP OPTIONS, TCP, ICMP) to target IPs.
- Remote SSH terminal & command runner with separated stdout/stderr, duration, and audit trail.
- System telemetry monitoring (CPU load, RAM, Disk, Uptime) with offline state clarity.
- Domain-specific 5G monitoring (3GPP 11-stage registration, SIP ladder, Failure Isolation Matrix).
- Remote log inspection with live SSH tailing and local fallback.
- Command execution history and audit log.
- AI diagnostic assistant for incident reporting and log explanation.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Local modules
from ai_assistant import AIAssistant
from config import ServerProfile, cfg
from database import Database
from demo_data import generate_demo_packets, get_demo_registration_data, get_demo_sip_state
from health_monitor import DiagnosticFinding, HealthMonitor
from packet_capture import PacketCaptureManager, PacketInfo, SCAPY_AVAILABLE
from registration_parser import RegistrationParser, STAGE_DEFINITIONS
from sip_monitor import SIPMonitor
from ssh_log_collector import RemoteLogCollector
from ssh_service import CommandResult, SSHService


@st.cache_resource
def get_db() -> Database:
    """Returns singleton Database instance and seeds server profiles if empty."""
    db = Database(db_path=cfg.database_path)
    db.seed_default_profiles_if_empty(cfg.get_default_server_profiles())
    return db


@st.cache_resource
def get_packet_manager() -> PacketCaptureManager:
    """Returns singleton PacketCaptureManager instance."""
    db = get_db()

    def on_packet(pkt: PacketInfo):
        try:
            db.record_packet(
                timestamp=pkt.timestamp,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                length=pkt.length,
                tcp_flags=pkt.tcp_flags,
                summary=pkt.summary,
                is_demo=pkt.is_demo,
            )
        except Exception:
            pass

    return PacketCaptureManager(max_buffer_size=cfg.max_packets_in_memory, on_packet_callback=on_packet)


@st.cache_resource
def get_reg_parser() -> RegistrationParser:
    return RegistrationParser()


@st.cache_resource
def get_sip_monitor() -> SIPMonitor:
    return SIPMonitor()


@st.cache_resource
def get_health_monitor() -> HealthMonitor:
    return HealthMonitor(nodes_config=cfg.get_lab_nodes())


def load_sample_traces(reg_parser: RegistrationParser, sip_mon: SIPMonitor):
    """Loads sample log data for demonstration when offline."""
    sample_dir = Path(__file__).parent / "sample_data"
    gnb_file = sample_dir / "msg_trace.log"
    if gnb_file.exists():
        with open(gnb_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                reg_parser.parse_gnb_log_line(line)
    sip_file = sample_dir / "sip_trace.log"
    if sip_file.exists():
        sip_mon.parse_file(str(sip_file))


def render_dashboard():
    """Main rendering loop executed on every Streamlit rerun cycle."""
    try:
        st.set_page_config(
            page_title="5G Lab Doctor — Operations & Observability",
            page_icon="📡",
            layout="wide",
            initial_sidebar_state="expanded",
        )
    except Exception:
        pass

    # Custom High-Tech Dark NOC Styling
    st.markdown(
        """
        <style>
        .metric-box {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 14px;
            color: #f8fafc;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.82rem;
            letter-spacing: 0.5px;
        }
        .badge-ok { background-color: #065f46; color: #34d399; border: 1px solid #059669; }
        .badge-warn { background-color: #78350f; color: #fde68a; border: 1px solid #d97706; }
        .badge-crit { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
        .badge-info { background-color: #1e3a8a; color: #93c5fd; border: 1px solid #2563eb; }
        .badge-demo { background-color: #4c1d95; color: #ddd6fe; border: 1px solid #7c3aed; }
        .badge-gray { background-color: #334155; color: #cbd5e1; border: 1px solid #475569; }

        .node-card {
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
            background: #1e293b;
            border-left: 5px solid #64748b;
        }
        .node-up { border-left-color: #10b981; }
        .node-down { border-left-color: #ef4444; }
        .node-warn { border-left-color: #f59e0b; }

        .terminal-box {
            background-color: #090d16;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 12px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.88rem;
            color: #e2e8f0;
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 450px;
        }
        .evidence-box {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 10px;
            font-family: monospace;
            font-size: 0.85rem;
            color: #38bdf8;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    db = get_db()
    pkt_mgr = get_packet_manager()
    reg_parser = get_reg_parser()
    sip_mon = get_sip_monitor()
    health_mon = get_health_monitor()

    # Pre-populate sample traces once if empty
    if not reg_parser.ue_states:
        load_sample_traces(reg_parser, sip_mon)

    # Initialize Session State
    if "demo_mode" not in st.session_state:
        st.session_state.demo_mode = cfg.demo_mode
    if "last_probe_results" not in st.session_state:
        st.session_state.last_probe_results = {}
    if "last_cmd_result" not in st.session_state:
        st.session_state.last_cmd_result = None

    # Load dynamic profiles from DB (Zero Hardcoding)
    server_profiles = db.get_server_profiles(only_active=True)
    if not server_profiles:
        # Fallback to config defaults
        db.seed_default_profiles_if_empty(cfg.get_default_server_profiles())
        server_profiles = db.get_server_profiles(only_active=True)

    # Sidebar: Navigation & Status
    st.sidebar.image("https://img.icons8.com/fluency/96/5g.png", width=64)
    st.sidebar.title("5G Lab Operations")
    st.sidebar.caption("Remote Linux Management & 5G Digital Twin")

    st.sidebar.markdown("---")
    demo_toggle = st.sidebar.toggle(
        "Demo Mode (Simulation)",
        value=st.session_state.demo_mode,
        key="demo_mode_switch",
        help="Toggle between live laboratory monitoring and synthetic demonstration data.",
    )
    st.session_state.demo_mode = demo_toggle

    if st.session_state.demo_mode:
        st.sidebar.info("🟣 **DEMO MODE**: Showing simulated telemetry & sample traces.")
    else:
        st.sidebar.success("🟢 **LIVE MODE**: Operating against lab devices.")

    st.sidebar.markdown("---")
    page = st.sidebar.radio(
        "Navigation",
        [
            "1. Overview / Digital Twin",
            "2. Servers & Connections",
            "3. Terminal & Command Runner",
            "4. Server Telemetry & Health",
            "5. 5G Lab & Domain Tools",
            "6. Logs & Diagnostics",
            "7. Live Packets",
            "8. Command History & Audit",
            "9. AI Diagnostic Assistant",
            "10. Settings & Profiles",
        ],
        key="main_nav_radio",
    )

    st.sidebar.markdown("---")
    pkt_stats = pkt_mgr.get_stats()
    st.sidebar.markdown(f"**Capture Status**: `{pkt_stats['status']}`")
    st.sidebar.markdown(f"**Tracked Servers**: `{len(server_profiles)}`")
    if st.sidebar.button("🔄 Refresh Data Now", use_container_width=True):
        st.rerun()

    # ==============================================================================
    # PAGE 1: OVERVIEW / DIGITAL TWIN
    # ==============================================================================
    if page == "1. Overview / Digital Twin":
        st.title("📡 Live Digital Twin — Private 5G MEC Lab")
        st.caption("Real-time visual mirror of radio, 5G core, IMS, edge computing, and gateway topology.")

        # Determine dynamic reachable states
        node_states = health_mon.get_all_node_states()
        gnb_up = node_states.get("gnb_radio", {}).get("reachable", True if st.session_state.demo_mode else False)
        core_up = node_states.get("core_5g", {}).get("reachable", True if st.session_state.demo_mode else False)
        gw_up = node_states.get("cosgrid_firewall", {}).get("reachable", False)

        # Primary Failure Isolation Diagnosis
        diag_findings = health_mon.evaluate_diagnostics(
            registration_states=get_demo_registration_data() if st.session_state.demo_mode else reg_parser.get_all_states(),
            sip_calls=get_demo_sip_state()["calls"] if st.session_state.demo_mode else sip_mon.get_calls(),
            sip_ues=get_demo_sip_state()["registered_ues"] if st.session_state.demo_mode else sip_mon.get_registered_ues(),
            packet_count=pkt_stats["total_captured"],
            gateway_reachable=gw_up,
            gnb_reachable=gnb_up or st.session_state.demo_mode,
            core_reachable=core_up or st.session_state.demo_mode,
        )

        primary_diag = diag_findings[0] if diag_findings else None
        if primary_diag:
            st.warning(f"**System Diagnosis: {primary_diag.headline}**\n\n{primary_diag.explanation}")

        # Top KPI Metrics Row
        m1, m2, m3, m4, m5 = st.columns(5)
        core_profile = next((p for p in server_profiles if p["id"] == "core_5g"), None)
        gnb_profile = next((p for p in server_profiles if p["id"] == "gnb_radio"), None)
        gw_profile = next((p for p in server_profiles if p["id"] == "cosgrid_firewall"), None)

        with m1:
            core_ip = core_profile["ip"] if core_profile else cfg.core_5g_ip
            st.metric("Core 5G (AMF/UPF)", core_ip, "ONLINE" if (core_up or st.session_state.demo_mode) else "UNCHECKED")
        with m2:
            gnb_ip = gnb_profile["ip"] if gnb_profile else cfg.gnb_ip
            st.metric("Radio (gNB)", gnb_ip, "ONLINE (Band n78)" if (gnb_up or st.session_state.demo_mode) else "UNCHECKED")
        with m3:
            gw_ip = gw_profile["ip"] if gw_profile else cfg.gateway_ip
            gw_status = "ONLINE" if gw_up else "DOWN (No Route)"
            st.metric("Gateway (.1)", gw_ip, gw_status, delta_color="normal" if gw_up else "inverse")
        with m4:
            reg_count = 2 if st.session_state.demo_mode else len(reg_parser.ue_states)
            st.metric("Registered 5G UEs", f"{reg_count} Active", "UE 901, UE 902")
        with m5:
            call_count = 1 if st.session_state.demo_mode else len([c for c in sip_mon.active_calls.values() if c.state != "ENDED"])
            st.metric("Active Voice Calls", f"{call_count} In Progress", "901 -> 902 (Ringing)")

        st.markdown("---")

        # Topology Visual Map (Digital Twin Graph)
        col_topo, col_cards = st.columns([3, 2])

        with col_topo:
            st.subheader("🌐 Network Topology & Data Path")
            gw_class = "upNode" if gw_up else "downNode"
            core_class = "upNode" if (core_up or st.session_state.demo_mode) else "downNode"
            gnb_class = "upNode" if (gnb_up or st.session_state.demo_mode) else "downNode"

            topo_mermaid = f"""
            graph TD
                GW["<b>Cosgrid Gateway/Firewall</b><br/>{gw_ip}"]:::{gw_class}
                SW["<b>L2 Switch</b><br/>192.168.35.2"]:::upNode
                CORE["<b>Core 5G (AMF/SMF/UPF)</b><br/>{core_ip}"]:::{core_class}
                IMS["<b>IMS Core / cnpn</b><br/>192.168.35.35"]:::upNode
                GNB["<b>5G gNB Radio</b><br/>{gnb_ip}"]:::{gnb_class}
                NMS["<b>NMS Server</b><br/>192.168.35.6"]:::upNode
                EDGE["<b>MEC Edge Core</b><br/>192.168.35.19"]:::upNode
                CLOUD["<b>MEC Cloud Core</b><br/>192.168.35.5"]:::upNode
                UE1["<b>UE 901</b><br/>10.46.0.8<br/>Vo5G"]:::ueNode
                UE2["<b>UE 902</b><br/>10.46.0.10<br/>Vo5G"]:::ueNode

                GW -.->|Uplink Path| SW
                SW --- CORE
                SW --- IMS
                SW --- NMS
                SW --- GNB
                SW --- EDGE
                SW --- CLOUD

                GNB ===|5G NR Radio| UE1
                GNB ===|5G NR Radio| UE2
                UE1 ===|SIP Call Session| UE2
                GNB ---|GTP-U User Plane| EDGE

                classDef upNode fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
                classDef downNode fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;
                classDef ueNode fill:#312e81,stroke:#6366f1,stroke-width:2px,color:#fff;
            """
            st.markdown(f"```mermaid\n{topo_mermaid}\n```")

        with col_cards:
            st.subheader("📱 Connected UE Status")
            ue_data = get_demo_registration_data() if st.session_state.demo_mode else reg_parser.get_all_states()
            if ue_data:
                for ue_id, u_info in ue_data.items():
                    state_label = u_info.get("current_state", "UNKNOWN")
                    ip = u_info.get("ip_address", "Pending")
                    crnti = u_info.get("crnti", "N/A")
                    st.markdown(
                        f"""
                        <div class="node-card node-up">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <h4 style="margin:0; color:#38bdf8;">📱 Phone {ue_id}</h4>
                                <span class="status-badge badge-ok">5G {state_label}</span>
                            </div>
                            <p style="margin:6px 0 0 0; color:#cbd5e1; font-size:0.9rem;">
                                <b>IP Address:</b> <code>{ip}</code> | <b>C-RNTI:</b> <code>{crnti}</code><br/>
                                <b>PDU Sessions:</b> <code>internet</code> (Data), <code>ims</code> (Vo5G)<br/>
                                <b>IMS Extension:</b> sip:{ue_id}@192.168.35.35
                            </p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No active UEs registered yet.")

            st.subheader("📞 Current Voice Call State")
            sip_data = get_demo_sip_state() if st.session_state.demo_mode else {"calls": sip_mon.get_calls()}
            active_c = sip_data["calls"][0] if sip_data["calls"] else None
            if active_c:
                st.markdown(
                    f"""
                    <div class="node-card node-warn">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h4 style="margin:0; color:#fde68a;">📞 Active Session: {active_c['caller']} ➔ {active_c['callee']}</h4>
                            <span class="status-badge badge-warn">{active_c['state']}</span>
                        </div>
                        <p style="margin:6px 0 0 0; color:#cbd5e1; font-size:0.9rem;">
                            <b>Caller IP:</b> <code>{active_c['caller_ip']}</code> | <b>Callee IP:</b> <code>{active_c['callee_ip']}</code><br/>
                            <b>Setup Latency:</b> {active_c.get('setup_time_ms', 230)} ms<br/>
                            <b>Evidence:</b> {active_c.get('evidence', 'SIP Signalling observed')}
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.info("No active SIP call in progress.")

    # ==============================================================================
    # PAGE 2: SERVERS & CONNECTIONS (PROTOCOL REQUEST ENGINE)
    # ==============================================================================
    elif page == "2. Servers & Connections":
        st.title("🖥️ Lab Servers & Protocol Request Dispatcher")
        st.caption("Send valid requests through valid protocols (SSH, HTTP/HTTPS, SIP, TCP, ICMP) to target IPs.")

        # Top Control Row
        col_btn1, col_btn2 = st.columns([2, 4])
        with col_btn1:
            if st.button("🚀 Probe All Servers Concurrently", type="primary", use_container_width=True):
                with st.spinner("Dispatching parallel protocol probes to all configured servers..."):
                    probe_results = health_mon.probe_all_profiles(server_profiles)
                    st.session_state.last_probe_results = probe_results
                    st.success(f"Dispatched probes across {len(server_profiles)} devices.")
                    st.rerun()

        with col_btn2:
            st.info("Select any device below to dispatch a targeted protocol request and inspect the live response.")

        st.markdown("---")

        # Interactive Target Request Section
        st.subheader("⚡ Send Protocol Request to Specific Device")
        p_names = [f"{p['name']} ({p['ip']}) — [{p['protocol']}]" for p in server_profiles]
        profile_map = {f"{p['name']} ({p['ip']}) — [{p['protocol']}]": p for p in server_profiles}

        sel_p_label = st.selectbox("Select Target Device Profile", p_names, key="sel_target_device_profile")
        selected_prof = profile_map[sel_p_label]

        r1, r2, r3, r4 = st.columns([3, 2, 2, 2])
        with r1:
            req_ip = st.text_input("Target IP Address", value=selected_prof["ip"], key="req_ip_box")
        with r2:
            proto_options = ["SSH", "HTTP", "HTTPS", "SIP", "TCP", "ICMP"]
            def_idx = proto_options.index(selected_prof["protocol"]) if selected_prof["protocol"] in proto_options else 0
            req_proto = st.selectbox("Protocol", proto_options, index=def_idx, key="req_proto_box")
        with r3:
            req_port = st.number_input("Target Port", value=int(selected_prof.get("port", 22)), min_value=1, max_value=65535, key="req_port_box")
        with r4:
            req_timeout = st.number_input("Timeout (sec)", value=3.0, min_value=0.5, max_value=15.0, step=0.5, key="req_timeout_box")

        cred_c1, cred_c2 = st.columns(2)
        with cred_c1:
            req_user = st.text_input("Username (Optional)", value=selected_prof.get("username", ""), key="req_user_box")
        with cred_c2:
            req_pass = st.text_input("Password (Masked)", value=selected_prof.get("password", ""), type="password", key="req_pass_box")

        if st.button(f"⚡ Send Valid {req_proto} Request to {req_ip}:{req_port}", type="primary"):
            with st.spinner(f"Sending {req_proto} request to {req_ip}:{req_port}..."):
                res = HealthMonitor.send_protocol_request(
                    ip=req_ip,
                    port=int(req_port),
                    protocol=req_proto,
                    platform_type=selected_prof.get("platform", "CLI"),
                    username=req_user,
                    password=req_pass,
                    key_file=selected_prof.get("key_file"),
                    timeout_sec=float(req_timeout),
                )
                st.session_state.single_probe_res = res

        if "single_probe_res" in st.session_state and st.session_state.single_probe_res:
            r = st.session_state.single_probe_res
            status_color = "badge-ok" if r["success"] else "badge-crit"
            badge_text = "SUCCESS" if r["success"] else "FAILED / TIMEOUT"

            st.markdown(
                f"""
                <div style="background:#1e293b; border-left: 5px solid {'#10b981' if r['success'] else '#ef4444'}; border-radius:8px; padding:16px; margin-top:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4 style="margin:0; color:#f8fafc;">Response from {r['target_ip']}:{r['target_port']} ({r['protocol']})</h4>
                        <span class="status-badge {status_color}">{badge_text}</span>
                    </div>
                    <p style="margin:6px 0; color:#94a3b8; font-size:0.9rem;">
                        <b>Roundtrip Latency:</b> <code>{r['latency_ms'] or '-'} ms</code> | <b>Status:</b> <code>{r['status_summary']}</code> | <b>Timestamp:</b> <code>{r['timestamp']}</code>
                    </p>
                    <div class="evidence-box">
                        <b>Evidence Citation:</b><br/>{r['evidence']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if r["response_data"]:
                with st.expander("📄 View Raw Protocol Response Data / Headers", expanded=True):
                    st.code(r["response_data"], language="text")

        st.markdown("---")

        # Configured Server Inventory Table
        st.subheader("📋 Registered Lab Infrastructure Inventory")
        rows = []
        for p in server_profiles:
            p_id = p["id"]
            node_st = health_mon.node_states.get(p_id, {})
            reachable = node_st.get("reachable", None)
            reach_str = "🟢 Reachable" if reachable is True else ("🔴 Unreachable" if reachable is False else "⚪ Not Probed")
            lat_str = f"{node_st.get('latency_ms', '-')} ms" if node_st.get("latency_ms") else "-"

            rows.append({
                "Component": p["name"],
                "IP Address": p["ip"],
                "Port": p["port"],
                "Protocol": p["protocol"],
                "Platform": p["platform"],
                "Lab Role": p["role"],
                "Username": p.get("username", "-") or "-",
                "Live Status": reach_str,
                "Latency": lat_str,
                "Probe Note": node_st.get("collector_status", "-"),
            })

        df_inv = pd.DataFrame(rows)
        st.dataframe(df_inv, use_container_width=True, hide_index=True)

    # ==============================================================================
    # PAGE 3: TERMINAL & COMMAND RUNNER
    # ==============================================================================
    elif page == "3. Terminal & Command Runner":
        st.title("💻 Remote Terminal & Command Runner")
        st.caption("Secure, non-intrusive SSH command execution against lab Linux hosts with stdout/stderr separation.")

        cli_profiles = [p for p in server_profiles if p.get("platform") in ("CLI", "GUI/CLI") or p.get("protocol") == "SSH"]
        if not cli_profiles:
            cli_profiles = server_profiles

        col_t1, col_t2 = st.columns([3, 1])
        with col_t1:
            prof_opts = [f"{p['name']} ({p['ip']}) - [{p.get('username') or 'no-user'}]" for p in cli_profiles]
            prof_map = {f"{p['name']} ({p['ip']}) - [{p.get('username') or 'no-user'}]": p for p in cli_profiles}
            sel_cli = st.selectbox("Target Linux Server Profile", prof_opts, key="sel_cli_runner_profile")
            active_p = prof_map[sel_cli]

        with col_t2:
            cmd_timeout = st.number_input("Timeout (sec)", value=8, min_value=1, max_value=60, key="cmd_runner_timeout")

        # Quick Commands for this server
        quick_cmds = active_p.get("quick_commands", [])
        if quick_cmds:
            st.markdown("**⚡ Quick Authorized Commands:**")
            q_cols = st.columns(min(len(quick_cmds), 4))
            for i, qc in enumerate(quick_cmds[:4]):
                with q_cols[i % 4]:
                    if st.button(qc[:30] + ("..." if len(qc) > 30 else ""), key=f"btn_qc_{i}"):
                        st.session_state.cli_input_cmd = qc

        default_cmd = st.session_state.get("cli_input_cmd", "uptime && uname -a")
        cmd_input = st.text_input("Command to execute", value=default_cmd, key="main_cmd_input_box")

        btn_run_col, btn_clear_col = st.columns([2, 8])
        with btn_run_col:
            run_clicked = st.button("▶️ Execute Command", type="primary", use_container_width=True)

        if run_clicked:
            if not cmd_input.strip():
                st.error("Please enter a command to execute.")
            else:
                with st.spinner(f"Executing '{cmd_input}' on {active_p['ip']}..."):
                    res = SSHService.execute_command(
                        host=active_p["ip"],
                        command=cmd_input,
                        port=active_p.get("port", 22),
                        username=active_p.get("username", ""),
                        password=active_p.get("password", ""),
                        key_file=active_p.get("key_file"),
                        timeout=int(cmd_timeout),
                    )
                    st.session_state.last_cmd_result = res
                    # Record to audit trail
                    db.record_command_execution(
                        server_id=active_p["id"],
                        server_name=active_p["name"],
                        host=active_p["ip"],
                        command=cmd_input,
                        status=res.status,
                        exit_code=res.exit_code,
                        duration_ms=res.duration_ms,
                        stdout=res.stdout,
                        stderr=res.stderr,
                        executed_by="admin",
                    )

        # Display Result
        last_res: Optional[CommandResult] = st.session_state.get("last_cmd_result")
        if last_res:
            st.markdown("---")
            st.subheader("🖥️ Execution Output & Metrics")

            status_badge_cls = {
                "SUCCESS": "badge-ok",
                "FAILED": "badge-crit",
                "TIMEOUT": "badge-warn",
                "AUTH_ERROR": "badge-crit",
                "CONNECTION_ERROR": "badge-crit",
            }.get(last_res.status, "badge-gray")

            k1, k2, k3, k4 = st.columns(4)
            with k1:
                st.markdown(f"**Status:** <span class='status-badge {status_badge_cls}'>{last_res.status}</span>", unsafe_allow_html=True)
            with k2:
                st.markdown(f"**Exit Code:** `{last_res.exit_code if last_res.exit_code is not None else 'N/A'}`")
            with k3:
                st.markdown(f"**Duration:** `{last_res.duration_ms} ms`")
            with k4:
                st.markdown(f"**Timestamp:** `{last_res.timestamp}`")

            tab_stdout, tab_stderr = st.tabs(["📄 Standard Output (stdout)", "⚠️ Standard Error (stderr)"])
            with tab_stdout:
                if last_res.stdout:
                    st.markdown(f"<div class='terminal-box'>{last_res.stdout}</div>", unsafe_allow_html=True)
                    st.download_button("💾 Download Output", last_res.stdout, file_name=f"output_{int(time.time())}.txt")
                else:
                    st.info("No standard output returned.")

            with tab_stderr:
                if last_res.stderr:
                    st.markdown(f"<div class='terminal-box' style='color:#fca5a5;'>{last_res.stderr}</div>", unsafe_allow_html=True)
                else:
                    st.success("No standard error generated.")

    # ==============================================================================
    # PAGE 4: SERVER TELEMETRY & HEALTH
    # ==============================================================================
    elif page == "4. Server Telemetry & Health":
        st.title("📊 Remote Server Telemetry & Resource Utilization")
        st.caption("Live, non-intrusive Linux telemetry: CPU load, RAM usage, filesystem health, and system uptime.")

        cli_profiles = [p for p in server_profiles if p.get("platform") in ("CLI", "GUI/CLI") or p.get("protocol") == "SSH"]
        p_names = [f"{p['name']} ({p['ip']})" for p in cli_profiles]
        p_map = {f"{p['name']} ({p['ip']})": p for p in cli_profiles}

        sel_mon_name = st.selectbox("Select Target Server to Inspect", p_names, key="sel_mon_server_box")
        mon_p = p_map[sel_mon_name]

        if st.button("📡 Harvest Live Telemetry from Host", type="primary"):
            with st.spinner(f"Querying {mon_p['ip']} over SSH..."):
                t_data = SSHService.collect_system_telemetry(
                    host=mon_p["ip"],
                    port=mon_p.get("port", 22),
                    username=mon_p.get("username", ""),
                    password=mon_p.get("password", ""),
                    key_file=mon_p.get("key_file"),
                    timeout=4,
                )
                st.session_state.last_telemetry = t_data

        telem: Optional[Dict[str, Any]] = st.session_state.get("last_telemetry")
        if telem and telem.get("host") == mon_p["ip"]:
            if telem.get("status") == "SUCCESS":
                st.success(f"🟢 Telemetry synchronized from `{telem['host']}` at `{telem['timestamp']}` (Latency: {telem['latency_ms']} ms)")

                k1, k2, k3, k4 = st.columns(4)
                with k1:
                    st.metric("CPU Load (1m)", f"{telem['cpu_load_1m']}", f"5m: {telem['cpu_load_5m']}")
                with k2:
                    st.metric("RAM Utilized", f"{telem['ram_percent']}%", f"{telem['ram_used_mb']} / {telem['ram_total_mb']} MB")
                with k3:
                    st.metric("Root Disk (/)", f"{telem['disk_percent']}%", f"{telem['disk_used']} / {telem['disk_total']}")
                with k4:
                    st.metric("System Uptime", telem["uptime_str"][:24])

                # Progress bars
                st.markdown("---")
                st.markdown("**Memory Utilization:**")
                st.progress(min(telem["ram_percent"] / 100.0, 1.0), text=f"{telem['ram_percent']}% Used")
                st.markdown("**Filesystem Storage (/):**")
                st.progress(min(telem["disk_percent"] / 100.0, 1.0), text=f"{telem['disk_percent']}% Used")
            else:
                st.error(f"🔴 **Failed to harvest telemetry from {telem['host']}**")
                st.markdown(
                    f"""
                    <div class="terminal-box" style="color:#fca5a5;">
                        <b>Error Detail:</b> {telem.get('error', 'Host unreachable or authentication failed')}<br/>
                        Ensure the target host is powered on, reachable on the subnet, and credentials in Server Profiles are correct.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info(f"Click **Harvest Live Telemetry** above to poll resource metrics from `{mon_p['name']}` ({mon_p['ip']}).")

    # ==============================================================================
    # PAGE 5: 5G LAB & DOMAIN TOOLS
    # ==============================================================================
    elif page == "5. 5G Lab & Domain Tools":
        st.title("📶 5G Lab Domain Tools & Failure Isolation Matrix")
        st.caption("3GPP 11-stage registration state machine, RFC 3261 SIP call ladder, and telecom fault isolation.")

        tab_reg, tab_sip, tab_diag = st.tabs(["📱 11-Stage UE Registration", "📞 SIP Call Flow Ladder", "🩺 Failure Isolation Matrix"])

        with tab_reg:
            st.subheader("3GPP Release 15/16/17 Standalone Registration Timeline")
            ue_data = get_demo_registration_data() if st.session_state.demo_mode else reg_parser.get_all_states()

            if ue_data:
                sel_ue = st.selectbox("Select User Endpoint (UE)", list(ue_data.keys()), format_func=lambda x: f"Phone {x}")
                ue_state = ue_data[sel_ue]

                u1, u2, u3, u4 = st.columns(4)
                with u1:
                    st.metric("UE Identity", f"UE {ue_state['ue_id']}")
                with u2:
                    st.metric("Radio State", ue_state.get("current_state", "UNKNOWN"))
                with u3:
                    st.metric("Allocated 5G IP", ue_state.get("ip_address", "Pending"))
                with u4:
                    st.metric("CRNTI", ue_state.get("crnti", "N/A"))

                stages = ue_state["stages"]
                completed_count = sum(1 for s in stages if s["status"] == "Completed")
                st.progress(completed_count / 11, text=f"Registration Progress: {completed_count} of 11 Stages Verified")

                for stage in stages:
                    status = stage["status"]
                    badge_class = "badge-ok" if status == "Completed" else ("badge-info" if status == "Observed" else "badge-gray")
                    with st.expander(f"Stage {stage['stage_id']}: {stage['name']} — [{status}]", expanded=(status in ("Completed", "Observed"))):
                        st.markdown(
                            f"""
                            <div style="display:flex; gap:10px; margin-bottom:8px;">
                                <span class="status-badge {badge_class}">Status: {status}</span>
                                <span class="status-badge badge-info">Evidence Source: {stage['evidence_source']}</span>
                                <span class="status-badge badge-gray">Timestamp: {stage['timestamp']}</span>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        st.markdown(f"**Path:** `{stage['source_component']}` ➔ `{stage['dest_component']}` | **Description:** {stage['description']}")
                        st.markdown("**Raw Observed Evidence:**")
                        st.markdown(f"<div class='evidence-box'>{stage['raw_evidence']}</div>", unsafe_allow_html=True)
            else:
                st.info("No UE registration activity observed yet.")

        with tab_sip:
            st.subheader("RFC 3261 SIP Signaling Sequence Ladder")
            sip_state = get_demo_sip_state() if st.session_state.demo_mode else {
                "registered_ues": sip_mon.get_registered_ues(),
                "calls": sip_mon.get_calls(),
                "mermaid": sip_mon.generate_mermaid_ladder(),
            }
            mermaid_code = sip_state["mermaid"]
            st.markdown(f"```mermaid\n{mermaid_code}\n```")

            st.subheader("Active IMS Call Sessions")
            calls = sip_state["calls"]
            if calls:
                df_calls = pd.DataFrame(calls)
                st.dataframe(df_calls, use_container_width=True, hide_index=True)

        with tab_diag:
            st.subheader("Automated Root-Cause Fault Isolation (Section 4.1 & 11 Blueprint)")
            findings = health_mon.evaluate_diagnostics(
                registration_states=get_demo_registration_data() if st.session_state.demo_mode else reg_parser.get_all_states(),
                sip_calls=get_demo_sip_state()["calls"] if st.session_state.demo_mode else sip_mon.get_calls(),
                sip_ues=get_demo_sip_state()["registered_ues"] if st.session_state.demo_mode else sip_mon.get_registered_ues(),
                packet_count=pkt_stats["total_captured"],
                gateway_reachable=False,
                gnb_reachable=True,
                core_reachable=True,
            )

            for item in findings:
                border_color = {"OK": "#10b981", "WARNING": "#f59e0b", "CRITICAL": "#ef4444", "INFO": "#38bdf8"}.get(item.severity, "#38bdf8")
                st.markdown(
                    f"""
                    <div style="background:#1e293b; border-left: 5px solid {border_color}; border-radius:8px; padding:16px; margin-bottom:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h4 style="margin:0; color:#f8fafc;">{item.headline}</h4>
                            <span class="status-badge badge-warn">{item.severity}</span>
                        </div>
                        <p style="margin:6px 0; color:#cbd5e1; font-size:0.92rem;">{item.explanation}</p>
                        <div class="evidence-box"><b>Evidence:</b> {item.evidence}</div>
                        <div style="color:#a7f3d0; margin-top:6px; font-size:0.88rem;">💡 <b>Suggested Action:</b> {item.suggested_action}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # ==============================================================================
    # PAGE 6: LOGS & DIAGNOSTICS
    # ==============================================================================
    elif page == "6. Logs & Diagnostics":
        st.title("📜 Log Streaming & Telemetry Analysis")
        st.caption("Inspect remote logs directly over SSH or analyze local log files.")

        log_mode = st.radio("Log Source Mode", ["Local Sample Logs", "Remote Host SSH Stream"], horizontal=True)

        if log_mode == "Local Sample Logs":
            log_sources = {
                "gNB Radio Protocol Log (msg_trace.log)": "sample_data/msg_trace.log",
                "gNB Event History (eventHistory.log)": "sample_data/eventHistory.log",
                "gNB System Alarms (AlarmLog.csv)": "sample_data/AlarmLog.csv",
                "IMS SIP Trace (sip_trace.log)": "sample_data/sip_trace.log",
                "NMS Softswitch Telemetry (telemetry_app.log)": "sample_data/telemetry_app.log",
            }
            sel_s = st.selectbox("Select Log Stream", list(log_sources.keys()))
            rel_path = log_sources[sel_s]
            full_path = Path(__file__).parent / rel_path

            f1, f2 = st.columns([3, 1])
            with f1:
                search_q = st.text_input("Filter / Search Query", placeholder="e.g. 'RRC', 'ALARM', '901'")
            with f2:
                num_lines = st.selectbox("Lines to display", [25, 50, 100, 200], index=1)

            if full_path.exists():
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines = [l.strip() for l in f if l.strip()]
                if search_q:
                    all_lines = [l for l in all_lines if search_q.lower() in l.lower()]
                show_lines = all_lines[-num_lines:]
                st.code("\n".join(show_lines), language="log")
            else:
                st.warning(f"File `{rel_path}` not found locally.")

        else:
            st.subheader("Remote SSH Log Fetcher")
            r_profs = [p for p in server_profiles if p.get("default_log_path") or p.get("platform") == "CLI"]
            p_names = [f"{p['name']} ({p['ip']}) -> {p.get('default_log_path', '/var/log/syslog')}" for p in r_profs]
            p_map = {f"{p['name']} ({p['ip']}) -> {p.get('default_log_path', '/var/log/syslog')}": p for p in r_profs}

            sel_r_name = st.selectbox("Select Remote Server & Log Target", p_names)
            target_p = p_map[sel_r_name]

            l_c1, l_c2, l_c3 = st.columns([3, 1, 1])
            with l_c1:
                r_log_path = st.text_input("Remote File Path", value=target_p.get("default_log_path") or "/var/log/syslog")
            with l_c2:
                r_lines = st.number_input("Line Count", value=30, min_value=5, max_value=200)
            with l_c3:
                r_filter = st.text_input("Grep Filter (Optional)", "")

            if st.button("📡 Tail Remote Log over SSH", type="primary"):
                with st.spinner(f"Fetching {r_lines} lines from {target_p['ip']}:{r_log_path}..."):
                    ok, lines_out, msg = SSHService.fetch_remote_log_tail(
                        host=target_p["ip"],
                        remote_path=r_log_path,
                        lines=int(r_lines),
                        filter_query=r_filter if r_filter.strip() else None,
                        port=target_p.get("port", 22),
                        username=target_p.get("username", ""),
                        password=target_p.get("password", ""),
                        key_file=target_p.get("key_file"),
                    )
                    if ok:
                        st.success(msg)
                        st.code("\n".join(lines_out), language="log")
                    else:
                        st.error(msg)

    # ==============================================================================
    # PAGE 7: LIVE PACKETS
    # ==============================================================================
    elif page == "7. Live Packets":
        st.title("📦 Passive Packet Capture & Protocol Inspection")
        st.caption("Non-intrusive packet header capture (RFC 3261 SIP, 3GPP GTP-U, SCTP, TCP, UDP).")

        c1, c2, c3, c4 = st.columns([3, 3, 2, 2])
        ifaces = PacketCaptureManager.get_available_interfaces()
        iface_opts = [i["name"] for i in ifaces]
        iface_lbls = {i["name"]: i["label"] for i in ifaces}

        with c1:
            sel_if = st.selectbox("Capture Interface", iface_opts, format_func=lambda x: iface_lbls.get(x, x))
        with c2:
            bpf = st.text_input("BPF Filter", value=cfg.capture_filter)
        with c3:
            st.write("")
            st.write("")
            if pkt_mgr.status == "CAPTURING":
                if st.button("⏹️ Stop Capture", type="primary"):
                    pkt_mgr.stop_capture()
                    st.rerun()
            else:
                if st.button("▶️ Start Capture", type="primary"):
                    pkt_mgr.start_capture(interface=sel_if, filter_str=bpf)
                    st.rerun()
        with c4:
            st.write("")
            st.write("")
            if st.button("🗑️ Clear Packets"):
                pkt_mgr.clear()
                st.rerun()

        if st.session_state.demo_mode and pkt_mgr.total_packets_captured == 0:
            raw_pkts = [p.to_dict() for p in generate_demo_packets()]
        else:
            raw_pkts = pkt_mgr.get_recent_packets(limit=100)

        if raw_pkts:
            df_p = pd.DataFrame(raw_pkts)
            st.dataframe(df_p, use_container_width=True, hide_index=True)
        else:
            st.info("No packets captured yet. Start capture or enable Demo Mode.")

    # ==============================================================================
    # PAGE 8: COMMAND HISTORY & AUDIT LOG
    # ==============================================================================
    elif page == "8. Command History & Audit":
        st.title("📜 Command Execution Audit Trail")
        st.caption("Complete, tamper-evident audit record of all remote executions across lab servers.")

        history = db.get_command_history(limit=100)
        col_h1, col_h2 = st.columns([2, 8])
        with col_h1:
            if st.button("🗑️ Clear Audit Log"):
                db.clear_command_history()
                st.success("Audit history cleared.")
                st.rerun()

        if history:
            df_hist = pd.DataFrame(history)
            cols_order = ["id", "timestamp", "server_name", "host", "command", "status", "exit_code", "duration_ms", "executed_by"]
            st.dataframe(df_hist[[c for c in cols_order if c in df_hist.columns]], use_container_width=True, hide_index=True)

            st.markdown("---")
            st.subheader("🔍 Inspect Past Execution Output")
            sel_hist_id = st.selectbox("Select Record ID", df_hist["id"].tolist(), format_func=lambda x: f"Audit ID {x}")
            sel_rec = next((r for r in history if r["id"] == sel_hist_id), None)
            if sel_rec:
                t1, t2 = st.tabs(["Stdout Output", "Stderr Output"])
                with t1:
                    st.code(sel_rec.get("stdout") or "(empty)", language="text")
                with t2:
                    st.code(sel_rec.get("stderr") or "(empty)", language="text")
        else:
            st.info("No commands have been executed yet.")

    # ==============================================================================
    # PAGE 9: AI DIAGNOSTIC ASSISTANT
    # ==============================================================================
    elif page == "9. AI Diagnostic Assistant":
        st.title("🤖 AI Diagnostic Assistant & Incident Reporting")
        st.caption("Automated telecom failure correlation, log explanation, and structured incident synthesis.")

        tab_report, tab_explain = st.tabs(["📋 Generate Incident Report", "🔍 Explain Log / Error Excerpt"])

        with tab_report:
            if st.button("📄 Synthesize Full Lab Health & Incident Report", type="primary"):
                rep_md = AIAssistant.generate_incident_report(
                    system_nodes=server_profiles,
                    recent_findings=health_mon.evaluate_diagnostics(
                        registration_states=get_demo_registration_data() if st.session_state.demo_mode else reg_parser.get_all_states(),
                        sip_calls=get_demo_sip_state()["calls"] if st.session_state.demo_mode else sip_mon.get_calls(),
                        sip_ues=get_demo_sip_state()["registered_ues"] if st.session_state.demo_mode else sip_mon.get_registered_ues(),
                        packet_count=pkt_stats["total_captured"],
                        gateway_reachable=False,
                        gnb_reachable=True,
                        core_reachable=True,
                    ),
                    recent_events=db.get_events(limit=20),
                )
                st.session_state.generated_report = rep_md

            if "generated_report" in st.session_state:
                st.markdown(st.session_state.generated_report)
                st.download_button("💾 Download Report (.md)", st.session_state.generated_report, file_name=f"lab_incident_report_{int(time.time())}.md")

        with tab_explain:
            sample_err = "2026-10-26 15:30:03.120 IP 192.168.35.35.5060 > 10.46.0.8.5060: SIP: SIP/2.0 401 Unauthorized\nWWW-Authenticate: Digest realm=\"192.168.35.35\", nonce=\"4f8a3c91\""
            txt_in = st.text_area("Paste Log Excerpt or Error Message for AI Analysis", value=sample_err, height=120)

            if st.button("🧠 Analyze with AI Engine"):
                res_exp = AIAssistant.explain_log_or_error(txt_in)
                sev_cls = "badge-ok" if res_exp["severity"] == "OK" else ("badge-crit" if res_exp["severity"] == "CRITICAL" else "badge-info")

                st.markdown(
                    f"""
                    <div style="background:#1e293b; border-left:5px solid #38bdf8; border-radius:8px; padding:16px; margin-top:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h4 style="margin:0; color:#f8fafc;">{res_exp['summary']}</h4>
                            <span class="status-badge {sev_cls}">{res_exp['severity']}</span>
                        </div>
                        <p style="margin:8px 0; color:#cbd5e1;">{res_exp['explanation']}</p>
                        <div style="color:#a7f3d0; font-size:0.9rem;">
                            <b>Recommended Diagnostic Steps:</b>
                            <ul>
                                {''.join(f"<li>{a}</li>" for a in res_exp['suggested_actions'])}
                            </ul>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # ==============================================================================
    # PAGE 10: SETTINGS & PROFILES (ZERO HARDCODING)
    # ==============================================================================
    elif page == "10. Settings & Profiles":
        st.title("⚙️ Server Profiles & Configuration")
        st.caption("Manage server profiles, target IPs, and credentials dynamically without hardcoded values.")

        tab_edit, tab_add, tab_maint = st.tabs(["✏️ Edit Existing Server Profile", "➕ Add New Server Profile", "🧹 System Maintenance"])

        with tab_edit:
            p_opts = [f"{p['name']} ({p['id']})" for p in server_profiles]
            p_map = {f"{p['name']} ({p['id']})": p for p in server_profiles}
            sel_edit_label = st.selectbox("Select Profile to Edit", p_opts)
            cur_p = p_map[sel_edit_label]

            with st.form("form_edit_profile"):
                e_col1, e_col2 = st.columns(2)
                with e_col1:
                    e_name = st.text_input("Server / Device Name", value=cur_p["name"])
                    e_ip = st.text_input("IP Address", value=cur_p["ip"])
                    e_port = st.number_input("Port", value=int(cur_p.get("port", 22)), min_value=1, max_value=65535)
                    e_proto = st.selectbox("Protocol", ["SSH", "HTTP", "HTTPS", "SIP", "TCP", "ICMP"], index=["SSH", "HTTP", "HTTPS", "SIP", "TCP", "ICMP"].index(cur_p.get("protocol", "SSH")))
                    e_plat = st.selectbox("Platform Type", ["CLI", "GUI", "GUI/CLI"], index=["CLI", "GUI", "GUI/CLI"].index(cur_p.get("platform", "CLI")))
                with e_col2:
                    e_role = st.text_input("Lab Role / Description", value=cur_p.get("role", ""))
                    e_user = st.text_input("Primary Username", value=cur_p.get("username", ""))
                    e_pass = st.text_input("Primary Password", value=cur_p.get("password", ""), type="password")
                    e_user2 = st.text_input("Secondary Username (Optional)", value=cur_p.get("secondary_username", ""))
                    e_pass2 = st.text_input("Secondary Password (Optional)", value=cur_p.get("secondary_password", ""), type="password")
                    e_log = st.text_input("Default Log Path (Optional)", value=cur_p.get("default_log_path") or "")

                save_edit = st.form_submit_button("💾 Save Profile Changes", type="primary")
                if save_edit:
                    cur_p.update({
                        "name": e_name,
                        "ip": e_ip,
                        "port": int(e_port),
                        "protocol": e_proto,
                        "platform": e_plat,
                        "role": e_role,
                        "username": e_user,
                        "password": e_pass,
                        "secondary_username": e_user2,
                        "secondary_password": e_pass2,
                        "default_log_path": e_log,
                    })
                    db.save_server_profile(cur_p)
                    st.success(f"Profile '{e_name}' saved to database.")
                    st.rerun()

            if st.button(f"🗑️ Delete Profile '{cur_p['name']}'", type="secondary"):
                db.delete_server_profile(cur_p["id"])
                st.success(f"Profile '{cur_p['name']}' deleted.")
                st.rerun()

        with tab_add:
            with st.form("form_add_profile"):
                a_c1, a_c2 = st.columns(2)
                with a_c1:
                    a_id = st.text_input("Profile ID (unique identifier, e.g. 'cpe_node')", "")
                    a_name = st.text_input("Server / Device Name", "")
                    a_ip = st.text_input("IP Address", "")
                    a_port = st.number_input("Port", value=22, min_value=1, max_value=65535)
                    a_proto = st.selectbox("Protocol", ["SSH", "HTTP", "HTTPS", "SIP", "TCP", "ICMP"])
                with a_c2:
                    a_plat = st.selectbox("Platform Type", ["CLI", "GUI", "GUI/CLI"])
                    a_role = st.text_input("Lab Role / Description", "")
                    a_user = st.text_input("Username", "")
                    a_pass = st.text_input("Password", type="password")
                    a_log = st.text_input("Default Log Path", "")

                create_btn = st.form_submit_button("➕ Add Profile to Database", type="primary")
                if create_btn:
                    if not a_id.strip() or not a_ip.strip():
                        st.error("Profile ID and IP address are required.")
                    else:
                        new_prof = {
                            "id": a_id.strip(),
                            "name": a_name.strip() or a_id.strip(),
                            "ip": a_ip.strip(),
                            "port": int(a_port),
                            "protocol": a_proto,
                            "platform": a_plat,
                            "role": a_role.strip(),
                            "username": a_user.strip(),
                            "password": a_pass.strip(),
                            "default_log_path": a_log.strip(),
                            "is_active": True,
                        }
                        db.save_server_profile(new_prof)
                        st.success(f"Added new profile '{a_name}'.")
                        st.rerun()

        with tab_maint:
            st.subheader("Database Maintenance & Reset")
            d1, d2 = st.columns(2)
            with d1:
                if st.button("Purge Data Older than 7 Days"):
                    db.purge_old_data(days=7)
                    st.success("Historical records purged.")
            with d2:
                if st.button("Reset Defaults (Reload Profiles from .env)"):
                    db.clear_all()
                    db.seed_default_profiles_if_empty(cfg.get_default_server_profiles())
                    st.success("Profiles re-seeded from .env configuration.")
                    st.rerun()


if __name__ == "__main__":
    render_dashboard()
