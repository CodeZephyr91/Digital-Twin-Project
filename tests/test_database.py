"""Unit tests for database module."""

import gc
import os
import tempfile
import pytest
from database import Database


@pytest.fixture
def test_db():
    fd, temp_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database(db_path=temp_path)
    yield db
    db.close()
    del db
    gc.collect()
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except OSError:
        pass


def test_record_and_get_events(test_db):
    row_id = test_db.record_event(
        timestamp="2026-10-26 15:30:00",
        source="gNB",
        event_type="RRC_SETUP",
        ue_id="901",
        ip_address="10.46.0.8",
        severity="INFO",
        raw_message="Recv RRCSetupRequest",
        parsed_json={"crnti": "0x4a12"},
        is_demo=False,
    )
    assert row_id > 0

    events = test_db.get_events(limit=10)
    assert len(events) == 1
    assert events[0]["ue_id"] == "901"
    assert events[0]["event_type"] == "RRC_SETUP"
    assert events[0]["source"] == "gNB"
    assert events[0]["is_demo"] == 0

    # Test filtering
    assert len(test_db.get_events(ue_id="901")) == 1
    assert len(test_db.get_events(ue_id="902")) == 0
    assert len(test_db.get_events(source="gNB")) == 1
    assert len(test_db.get_events(source="IMS")) == 0


def test_record_and_update_call(test_db):
    cid = "call-12345"
    test_db.record_or_update_call(
        call_id=cid,
        caller="901",
        callee="902",
        state="INVITE_SENT",
        start_time="2026-10-26 15:35:00",
        caller_ip="10.46.0.8",
        callee_ip="10.46.0.10",
        evidence="INVITE sent",
    )

    calls = test_db.get_calls()
    assert len(calls) == 1
    assert calls[0]["state"] == "INVITE_SENT"
    assert calls[0]["caller"] == "901"

    # Update state to RINGING
    test_db.record_or_update_call(
        call_id=cid,
        caller="901",
        callee="902",
        state="RINGING",
        start_time="2026-10-26 15:35:00",
        setup_time_ms=230,
        evidence="180 Ringing received",
    )

    calls_updated = test_db.get_calls()
    assert len(calls_updated) == 1
    assert calls_updated[0]["state"] == "RINGING"
    assert calls_updated[0]["setup_time_ms"] == 230


def test_record_and_get_packets(test_db):
    test_db.record_packet(
        timestamp="2026-10-26 15:35:01",
        src_ip="10.46.0.8",
        dst_ip="192.168.35.35",
        src_port=5060,
        dst_port=5060,
        protocol="SIP/UDP",
        length=450,
        tcp_flags="",
        summary="SIP INVITE",
        is_demo=False,
    )
    test_db.record_packet(
        timestamp="2026-10-26 15:35:02",
        src_ip="192.168.35.15",
        dst_ip="192.168.35.19",
        src_port=2152,
        dst_port=2152,
        protocol="GTP-U",
        length=1200,
        summary="GTP-U tunnel",
        is_demo=False,
    )

    pkts = test_db.get_packets(limit=10)
    assert len(pkts) == 2

    counts = test_db.get_packet_counts()
    assert counts["TOTAL"] == 2
    assert counts["SIP/UDP"] == 1
    assert counts["GTP-U"] == 1

    # Filter
    sip_pkts = test_db.get_packets(protocol_filter="SIP/UDP")
    assert len(sip_pkts) == 1
    assert sip_pkts[0]["protocol"] == "SIP/UDP"


def test_node_health(test_db):
    test_db.update_node_health(
        node_id="gateway",
        name="Gateway",
        ip="192.168.35.1",
        reachable=False,
        service_status="DOWN",
        error_detail="Packet loss 100%",
    )

    nodes = test_db.get_node_health()
    assert len(nodes) == 1
    assert nodes[0]["node_id"] == "gateway"
    assert nodes[0]["reachable"] == 0
    assert nodes[0]["service_status"] == "DOWN"
