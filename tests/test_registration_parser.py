"""Unit tests for 5G UE Registration parser and state machine."""

import pytest
from registration_parser import RegistrationParser, STAGE_DEFINITIONS


@pytest.fixture
def parser():
    return RegistrationParser()


def test_no_fabrication_rule(parser):
    """Initial UE state must have all 11 stages marked as 'Not observed'."""
    ue = parser.get_or_create_ue("901")
    assert len(ue.stages) == 11
    for s_id, stage in ue.stages.items():
        assert stage.status == "Not observed"
        assert stage.evidence_source == "NONE"


def test_rrc_setup_flow(parser):
    line1 = "2026-10-26 15:30:01.120 [euGNB-RRC] INFO: [Cell 1] [CRNTI 0x4a12] Recv RRCSetupRequest (UE identity: 0x9b32fa)"
    ev1 = parser.parse_gnb_log_line(line1)
    assert ev1 is not None
    assert ev1["type"] == "RRC_SETUP_REQUEST"

    # RACH is marked Completed (INFERRED), RRC setup is Observed (GNB_LOG)
    ue = parser.get_or_create_ue("0x4a12")
    assert ue.stages[2].status == "Completed"
    assert ue.stages[2].evidence_source == "INFERRED"
    assert ue.stages[3].status == "Observed"
    assert ue.stages[3].evidence_source == "GNB_LOG"
    # Stage 4 onwards must still be 'Not observed'
    assert ue.stages[4].status == "Not observed"
    assert ue.stages[6].status == "Not observed"

    line2 = "2026-10-26 15:30:01.182 [euGNB-RRC] INFO: [Cell 1] [CRNTI 0x4a12] Recv RRCSetupComplete (SelectedPLMN-Identity: 001-01, NAS-PDU: 5GS-Registration-Request, UE 901)"
    ev2 = parser.parse_gnb_log_line(line2)
    assert ev2 is not None

    ue901 = parser.get_or_create_ue("901")
    assert ue901.stages[3].status == "Completed"
    assert ue901.stages[4].status == "Observed"


def test_full_registration_lifecycle(parser):
    lines = [
        "2026-10-26 15:30:01.182 [euGNB-RRC] Recv RRCSetupComplete (NAS-PDU: 5GS-Registration-Request, UE 901)",
        "2026-10-26 15:30:01.190 [euGNB-NGAP] Send InitialUEMessage_NG (UE 901)",
        "2026-10-26 15:30:01.215 [euGNB-NGAP] Recv DownlinkNASTransport (NAS: AuthenticationRequest, UE 901)",
        "2026-10-26 15:30:01.260 [euGNB-NGAP] Send UplinkNASTransport (NAS: AuthenticationResponse, UE 901)",
        "2026-10-26 15:30:01.285 [euGNB-NGAP] Recv DownlinkNASTransport (NAS: SecurityModeCommand, UE 901)",
        "2026-10-26 15:30:01.310 [euGNB-NGAP] Send UplinkNASTransport (NAS: SecurityModeComplete, UE 901)",
        "2026-10-26 15:30:01.340 [euGNB-NGAP] Recv InitialContextSetupRequest_NG (NAS: RegistrationAccept, UE 901)",
        "2026-10-26 15:30:01.415 [euGNB-RRC] Recv RRCReconfigurationComplete (NAS: RegistrationComplete, UE 901)",
        "2026-10-26 15:30:02.120 [euGNB-NGAP] Recv PDUSessionResourceSetupRequest (PDU Session ID: 2, DNN: ims, UE 901)",
        "2026-10-26 15:30:02.150 [euGNB-NGAP] Send PDUSessionResourceSetupResponse (PDU Session ID: 2, Allocated IP: 10.46.0.8, UE 901)",
    ]

    for line in lines:
        parser.parse_gnb_log_line(line)

    ue = parser.get_or_create_ue("901")
    assert ue.stages[4].status == "Completed"
    assert ue.stages[6].status == "Completed"
    assert ue.stages[7].status == "Completed"
    assert ue.stages[9].status == "Completed"
    assert ue.stages[10].status == "Completed"
    assert ue.stages[11].status == "Completed"
    assert ue.ip_address == "10.46.0.8"
    assert ue.current_state == "PDU_ACTIVE"

    # Stage 5 (Identity procedures) was not in the trace and must remain 'Not observed'
    assert ue.stages[5].status == "Not observed"
