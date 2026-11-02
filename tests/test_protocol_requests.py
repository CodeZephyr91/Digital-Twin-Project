"""Unit tests for Protocol Request Engine across SSH, HTTP, SIP, and TCP."""

from unittest.mock import MagicMock, patch
import pytest
from health_monitor import HealthMonitor


def test_send_protocol_request_localhost_tcp():
    # Probing localhost via TCP should succeed or report socket state
    res = HealthMonitor.send_protocol_request(
        ip="127.0.0.1",
        port=80,
        protocol="TCP",
        platform_type="GUI",
        timeout_sec=0.5,
    )
    assert res["target_ip"] == "127.0.0.1"
    assert res["protocol"] == "TCP"
    assert "timestamp" in res


@patch("requests.get")
def test_send_protocol_request_http_mocked(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.reason = "OK"
    mock_resp.headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
    mock_get.return_value = mock_resp

    res = HealthMonitor.send_protocol_request(
        ip="192.168.35.6",
        port=80,
        protocol="HTTP",
        platform_type="GUI",
        username="admin",
        password="admin123",
    )

    assert res["success"] is True
    assert "HTTP 200 (OK)" in res["status_summary"]
    assert "nginx/1.18.0" in res["response_data"]
    assert "192.168.35.6" in res["evidence"]


@patch("ssh_service.SSHService.test_connection")
def test_send_protocol_request_ssh_mocked(mock_ssh):
    mock_ssh.return_value = (True, "Successfully authenticated as 'support'", 35.0)

    res = HealthMonitor.send_protocol_request(
        ip="192.168.35.10",
        port=22,
        protocol="SSH",
        platform_type="CLI",
        username="support",
        password="Support@817&&",
    )

    assert res["success"] is True
    assert res["latency_ms"] == 35.0
    assert "SSH Auth Success" in res["status_summary"]
    assert "192.168.35.10" in res["evidence"]


def test_concurrent_profile_probing():
    hm = HealthMonitor()
    mock_profiles = [
        {"id": "node_1", "name": "Node 1", "ip": "127.0.0.1", "port": 80, "protocol": "TCP", "platform": "GUI"},
        {"id": "node_2", "name": "Node 2", "ip": "127.0.0.1", "port": 22, "protocol": "SSH", "platform": "CLI"},
    ]
    results = hm.probe_all_profiles(mock_profiles)
    assert "node_1" in results
    assert "node_2" in results
    all_states = hm.get_all_node_states()
    assert "node_1" in all_states
    assert "node_2" in all_states
