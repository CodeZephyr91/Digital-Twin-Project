"""Unit tests for Health Monitor and Failure Isolation Matrix."""

from health_monitor import HealthMonitor


def test_failure_isolation_rule_gateway_broken():
    """Equation 1 from Blueprint: State(gNB)=UP and State(Core)=UP and Ping(Gateway)=FAIL."""
    hm = HealthMonitor()
    findings = hm.evaluate_diagnostics(
        registration_states={"901": {"current_state": "PDU_ACTIVE"}},
        sip_calls=[{"state": "RINGING", "caller": "901", "callee": "902"}],
        sip_ues=[{"ue_id": "901"}],
        packet_count=100,
        gateway_reachable=False,
        gnb_reachable=True,
        core_reachable=True,
    )

    primary = findings[0]
    assert primary.severity == "WARNING"
    assert "Gateway Broken" in primary.headline
    assert "192.168.35.1" in primary.explanation
    assert "192.168.35.15" in primary.evidence
    assert "192.168.35.35" in primary.evidence


def test_reachability_probe_localhost():
    # Probing localhost / 127.0.0.1 should succeed
    reachable, latency, desc = HealthMonitor.check_reachability("127.0.0.1", timeout_sec=1.0)
    assert reachable is True
    assert latency is not None
