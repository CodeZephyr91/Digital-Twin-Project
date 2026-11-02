"""AI-Assisted Operations & Telecom Diagnostic Engine.

Provides automated analysis, incident reporting, log explanation, and
troubleshooting recommendations for the 5G MEC Lab & Linux operations platform.
Operates deterministically using domain heuristics without mandatory external APIs,
with optional pluggable LLM support if API keys are configured.
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("5g_lab_doctor.ai_assistant")


class AIAssistant:
    """Intelligent operational diagnostics and log analysis."""

    @staticmethod
    def explain_log_or_error(log_text: str) -> Dict[str, Any]:
        """Analyzes telecom or system log text and explains root causes."""
        if not log_text or not log_text.strip():
            return {
                "summary": "No log text provided for analysis.",
                "severity": "INFO",
                "detected_patterns": [],
                "explanation": "Please provide log lines or an error message to analyze.",
                "suggested_actions": ["Select a log stream or run a command to produce output."],
            }

        patterns = []
        severity = "INFO"
        explanation = ""
        actions = []

        lower = log_text.lower()

        # Telecom-specific pattern matching
        if "rrcsetuprequest" in lower and "reject" in lower:
            patterns.append("RRC Connection Rejection")
            severity = "CRITICAL"
            explanation = "gNodeB rejected UE RRC setup request. Common causes include cell congestion, admission control limits, or TAC/PLMN mismatch."
            actions.append("Check gNB active cell state with 'cat /home/tetra/euGNB/logs/AlarmLog.csv'.")
            actions.append("Verify phone PLMN matches the configured SIM card.")

        elif "registration reject" in lower or "5gs registration reject" in lower:
            patterns.append("5GS NAS Registration Reject")
            severity = "CRITICAL"
            explanation = "The 5G Core AMF rejected the subscriber's NAS registration attempt (5GMM cause code). Likely authentication token failure or missing subscriber profile in UDR/UDM."
            actions.append("Inspect Core 5G subscriber database on 192.168.35.10.")
            actions.append("Verify SIM IMSI / SUPI matches 5G Core subscriber table.")

        elif "401 unauthorized" in lower and "www-authenticate" in lower:
            patterns.append("SIP 401 Digest Challenge (Normal)")
            severity = "OK"
            explanation = "RFC 3261 standard HTTP Digest authentication challenge from Core IMS. Subscriber must respond with Authorization MD5/SHA256 response."
            actions.append("Observe subsequent REGISTER packet with Authorization header.")

        elif "403 forbidden" in lower:
            patterns.append("SIP 403 Forbidden")
            severity = "WARNING"
            explanation = "Core IMS rejected subscriber credentials. Password or realm mismatch in SIP registrar."
            actions.append("Verify subscriber SIP extension and SIP password on 192.168.35.35.")

        elif "connection refused" in lower or "timed out" in lower:
            patterns.append("Network Connection Failure")
            severity = "WARNING"
            explanation = "Remote port refused TCP handshake or network path dropped packets."
            actions.append("Check reachability using 'ping' and port availability with 'ss -tulpn'.")
            actions.append("Ensure target daemon (sshd, nginx, coralswitch) is actively running.")

        elif "permission denied" in lower:
            patterns.append("Authentication / Authorization Failure")
            severity = "WARNING"
            explanation = "Incorrect username/password or insufficient sudo/POSIX file permissions."
            actions.append("Check credentials configured in Server Profiles.")
            actions.append("Verify file read permissions on target path.")

        else:
            patterns.append("General Telemetry")
            severity = "INFO"
            explanation = "Log lines show normal background processing or informative telemetry."
            actions.append("Filter log lines by specific keywords (e.g. 'RRC', 'SIP', 'FAIL').")

        return {
            "summary": f"Detected: {', '.join(patterns)}",
            "severity": severity,
            "detected_patterns": patterns,
            "explanation": explanation,
            "suggested_actions": actions,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def generate_incident_report(
        system_nodes: List[Dict[str, Any]],
        recent_findings: List[Any],
        recent_events: List[Dict[str, Any]],
    ) -> str:
        """Synthesizes an incident report in Markdown format."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        down_nodes = [n for n in system_nodes if not n.get("reachable")]
        up_nodes = [n for n in system_nodes if n.get("reachable")]

        report = f"""# 🚨 5G Lab Operations Incident & Health Report
**Generated At:** `{now}`  
**Environment:** Private 5G MEC Laboratory (`192.168.35.0/24`)

---

## 1. Executive Summary
- **Total Tracked Infrastructure Nodes:** `{len(system_nodes)}`
- **Reachable Nodes:** `{len(up_nodes)}`
- **Unreachable / Degraded Nodes:** `{len(down_nodes)}`
- **Primary Diagnosis:** {"⚠️ Active Anomalies Detected" if down_nodes else "✅ All Monitored Subsystems Nominal"}

---

## 2. Infrastructure Health Matrix

| Component | Target IP | Protocol | Status | Latency | Observation Note |
|---|---|---|---|---|---|
"""
        for n in system_nodes:
            status_icon = "🟢 UP" if n.get("reachable") else "🔴 DOWN"
            lat = f"{n.get('latency_ms', '-')} ms" if n.get("latency_ms") else "-"
            report += f"| **{n.get('name', 'Node')}** | `{n.get('ip')}` | `{n.get('protocol', 'TCP')}` | {status_icon} | {lat} | {n.get('collector_status', '-')} |\n"

        report += """
---

## 3. Failure Isolation & Diagnostic Findings
"""
        if recent_findings:
            for f in recent_findings:
                sev = getattr(f, "severity", "INFO")
                headline = getattr(f, "headline", "Diagnostic Item")
                exp = getattr(f, "explanation", "")
                ev = getattr(f, "evidence", "")
                action = getattr(f, "suggested_action", "")
                report += f"""
### [{sev}] {headline}
- **Root Cause Analysis:** {exp}
- **Observed Evidence:** `{ev}`
- **Recommended Remediation:** {action}
"""
        else:
            report += "\n*No critical diagnostic anomalies reported.*\n"

        report += f"""
---

## 4. Suggested Safe Operational Commands
```bash
# Verify gNodeB Radio link status:
ssh resonous@192.168.35.15 "tail -n 25 /home/tetra/euGNB/logs/msg_trace.log"

# Verify 5G Core service state:
ssh support@192.168.35.10 "ss -tulpn | grep -E '38412|80|22'"

# Verify IMS SIP daemon listening state:
ssh support@192.168.35.35 "netstat -ulpn | grep 5060"
```

*Report generated automatically by 5G Lab Doctor AI Operations Module.*
"""
        return report

    @staticmethod
    def suggest_commands_for_server(role: str, server_name: str) -> List[Dict[str, str]]:
        """Provides verified, non-destructive commands tailored to a specific server role."""
        role_lower = (role or "").lower()
        name_lower = (server_name or "").lower()
        if "radio" in role_lower or "gnb" in role_lower or "gnodeb" in role_lower or "gnb" in name_lower or "radio" in name_lower:
            return [
                {"name": "Check gNB Messages", "cmd": "tail -n 30 /home/tetra/euGNB/logs/msg_trace.log"},
                {"name": "Check gNB Events", "cmd": "tail -n 30 /home/tetra/euGNB/logs/eventHistory.log"},
                {"name": "Check Alarms", "cmd": "tail -n 15 /home/tetra/euGNB/logs/AlarmLog.csv"},
                {"name": "System Load & Uptime", "cmd": "uptime && free -m"},
            ]
        elif "core" in role_lower:
            return [
                {"name": "5G Ports & Sockets", "cmd": "ss -tulpn | grep -E '38412|80|5060|22'"},
                {"name": "System Resources", "cmd": "uptime && free -m && df -h"},
                {"name": "Network Interfaces", "cmd": "ip -br addr show"},
            ]
        elif "nms" in role_lower:
            return [
                {"name": "NMS Telemetry Log", "cmd": "tail -n 30 /var/log/coralswitch/softswitch/telemetry/app.log"},
                {"name": "NMS Service Log", "cmd": "tail -n 30 /var/log/coralswitch/softswitch/service-v2/app.log"},
                {"name": "System Uptime", "cmd": "uptime"},
            ]
        elif "hypervisor" in role_lower or "vm" in role_lower:
            return [
                {"name": "List All KVM VMs", "cmd": "virsh list --all"},
                {"name": "Hypervisor Memory", "cmd": "free -m"},
                {"name": "Disk Pools", "cmd": "df -h /var/lib/libvirt/images 2>/dev/null || df -h"},
            ]
        else:
            return [
                {"name": "System Uptime", "cmd": "uptime"},
                {"name": "Memory Usage", "cmd": "free -m"},
                {"name": "Disk Space", "cmd": "df -h"},
                {"name": "Network Addresses", "cmd": "ip -brief addr show"},
            ]
