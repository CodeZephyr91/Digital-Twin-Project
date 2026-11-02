"""Unit tests for AI Assistant module."""

import pytest
from ai_assistant import AIAssistant


def test_explain_log_rrc_reject():
    log_text = "2026-10-26 15:30:00 [RRC] Recv RRCSetupRequest reject cause: congestion"
    res = AIAssistant.explain_log_or_error(log_text)
    assert res["severity"] == "CRITICAL"
    assert "RRC Connection Rejection" in res["detected_patterns"]
    assert len(res["suggested_actions"]) > 0


def test_explain_log_sip_unauthorized():
    log_text = "SIP: SIP/2.0 401 Unauthorized\nWWW-Authenticate: Digest realm=\"192.168.35.35\""
    res = AIAssistant.explain_log_or_error(log_text)
    assert res["severity"] == "OK"
    assert "SIP 401 Digest Challenge (Normal)" in res["detected_patterns"]


def test_generate_incident_report():
    mock_nodes = [
        {"name": "Core 5G", "ip": "192.168.35.10", "protocol": "SSH", "reachable": True, "latency_ms": 35.0, "collector_status": "SSH Auth Success"},
        {"name": "Cosgrid Gateway", "ip": "192.168.35.1", "protocol": "HTTP", "reachable": False, "latency_ms": None, "collector_status": "No Route"},
    ]
    report = AIAssistant.generate_incident_report(
        system_nodes=mock_nodes,
        recent_findings=[],
        recent_events=[],
    )
    assert "5G Lab Operations Incident & Health Report" in report
    assert "192.168.35.10" in report
    assert "192.168.35.1" in report
    assert "Core 5G" in report


def test_suggest_commands_for_server():
    cmds_gnb = AIAssistant.suggest_commands_for_server(role="5G NR gNodeB", server_name="gNB Radio")
    assert any("msg_trace.log" in c["cmd"] for c in cmds_gnb)

    cmds_vm = AIAssistant.suggest_commands_for_server(role="KVM Hypervisor Host", server_name="Server 1 Host")
    assert any("virsh list --all" in c["cmd"] for c in cmds_vm)
