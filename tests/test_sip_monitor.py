"""Unit tests for SIP / IMS Monitor and Ladder Diagram Reconstruction."""

import pytest
from sip_monitor import SIPMonitor


@pytest.fixture
def sip_mon():
    return SIPMonitor()


def test_parse_sip_register_and_200ok(sip_mon):
    register_text = """2026-10-26 15:30:03.100 IP 10.46.0.8.5060 > 192.168.35.35.5060: SIP: REGISTER sip:192.168.35.35 SIP/2.0
Via: SIP/2.0/UDP 10.46.0.8:5060;branch=z9hG4bK-reg1
From: <sip:901@192.168.35.35>;tag=tag-901reg
To: <sip:901@192.168.35.35>
Call-ID: reg-call-901@10.46.0.8
CSeq: 1 REGISTER
"""
    msg1 = sip_mon.parse_sip_chunk(register_text)
    assert msg1 is not None
    assert msg1.method_or_status == "REGISTER"
    assert msg1.from_user == "901"
    sip_mon.process_sip_message(msg1)

    ok_text = """2026-10-26 15:30:03.170 IP 192.168.35.35.5060 > 10.46.0.8.5060: SIP: SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.46.0.8:5060;branch=z9hG4bK-reg1
From: <sip:901@192.168.35.35>;tag=tag-901reg
To: <sip:901@192.168.35.35>
Call-ID: reg-call-901@10.46.0.8
CSeq: 1 REGISTER
P-Associated-URI: <sip:901@192.168.35.35>
"""
    msg2 = sip_mon.parse_sip_chunk(ok_text)
    assert msg2 is not None
    assert msg2.status_code == 200
    sip_mon.process_sip_message(msg2)

    registered = sip_mon.get_registered_ues()
    assert len(registered) == 1
    assert registered[0]["ue_id"] == "901"
    assert registered[0]["status"] == "IMS_REGISTERED"


def test_call_flow_invite_ringing_bye(sip_mon):
    invite_text = """2026-10-26 15:35:00.100 IP 10.46.0.8.5060 > 192.168.35.35.5060: SIP: INVITE sip:902@192.168.35.35 SIP/2.0
From: <sip:901@192.168.35.35>;tag=calltag-901
To: <sip:902@192.168.35.35>
Call-ID: call-901-to-902-1234@10.46.0.8
CSeq: 100 INVITE
"""
    msg_inv = sip_mon.parse_sip_chunk(invite_text)
    sip_mon.process_sip_message(msg_inv)

    calls = sip_mon.get_calls()
    assert len(calls) == 1
    assert calls[0]["caller"] == "901"
    assert calls[0]["callee"] == "902"
    assert calls[0]["state"] == "INVITE_SENT"

    ringing_text = """2026-10-26 15:35:00.220 IP 192.168.35.35.5060 > 10.46.0.8.5060: SIP: SIP/2.0 180 Ringing
From: <sip:901@192.168.35.35>;tag=calltag-901
To: <sip:902@192.168.35.35>;tag=calltag-902
Call-ID: call-901-to-902-1234@10.46.0.8
CSeq: 100 INVITE
"""
    msg_ring = sip_mon.parse_sip_chunk(ringing_text)
    sip_mon.process_sip_message(msg_ring)

    calls2 = sip_mon.get_calls()
    assert calls2[0]["state"] == "RINGING"

    bye_text = """2026-10-26 15:35:20.100 IP 10.46.0.8.5060 > 192.168.35.35.5060: SIP: BYE sip:902@192.168.35.35 SIP/2.0
From: <sip:901@192.168.35.35>;tag=calltag-901
To: <sip:902@192.168.35.35>;tag=calltag-902
Call-ID: call-901-to-902-1234@10.46.0.8
CSeq: 101 BYE
"""
    msg_bye = sip_mon.parse_sip_chunk(bye_text)
    sip_mon.process_sip_message(msg_bye)

    calls3 = sip_mon.get_calls()
    assert calls3[0]["state"] == "ENDED"

    mermaid = sip_mon.generate_mermaid_ladder()
    assert "sequenceDiagram" in mermaid
    assert "INVITE" in mermaid
    assert "180 Ringing" in mermaid
