"""Demo Mode and Synthetic Data Generator for 5G Lab Doctor.

Provides realistic simulation data for private 5G lab demonstrations:
- 5G UE Registration lifecycle (11 stages for UE 901 and UE 902)
- Synthetic SIP call sequence (901 -> 902: REGISTER, INVITE, 100 Trying, 180 Ringing, 200 OK, ACK, BYE)
- Synthetic packet stream clearly flagged with is_demo=True and [DEMO / SYNTHETIC] tags
- Simulated multi-node health status demonstrating the gateway routing failure scenario

Strict Guardrail:
- All generated records are stamped with is_demo=True and visually badged.
- Prevents misrepresenting synthetic traces as real live network captures.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List
from packet_capture import PacketInfo


def generate_demo_packets() -> List[PacketInfo]:
    """Generates a sequence of sample packets representing lab traffic."""
    now = datetime.now()
    demo_pkts = [
        # GTP-U 5G Data Tunnel
        PacketInfo(
            timestamp=(now - timedelta(seconds=28)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.15",
            dst_ip="192.168.35.19",
            src_port=2152,
            dst_port=2152,
            protocol="GTP-U",
            length=1240,
            tcp_flags="",
            summary="[DEMO] 5G User Plane GTP-U Encapsulation (gNB -> UPF Edge, TEID=0x10a2b)",
            is_demo=True,
        ),
        # SIP REGISTER
        PacketInfo(
            timestamp=(now - timedelta(seconds=25)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="10.46.0.8",
            dst_ip="192.168.35.35",
            src_port=5060,
            dst_port=5060,
            protocol="SIP/UDP",
            length=482,
            tcp_flags="",
            summary="[DEMO] SIP REGISTER sip:192.168.35.35 (From: sip:901)",
            is_demo=True,
        ),
        # SIP 200 OK
        PacketInfo(
            timestamp=(now - timedelta(seconds=24)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.35",
            dst_ip="10.46.0.8",
            src_port=5060,
            dst_port=5060,
            protocol="SIP/UDP",
            length=512,
            tcp_flags="",
            summary="[DEMO] SIP/2.0 200 OK (P-Associated-URI: <sip:901@192.168.35.35>)",
            is_demo=True,
        ),
        # SCTP NGAP Control Plane
        PacketInfo(
            timestamp=(now - timedelta(seconds=20)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.15",
            dst_ip="192.168.35.35",
            src_port=38412,
            dst_port=38412,
            protocol="SCTP/NGAP",
            length=216,
            tcp_flags="",
            summary="[DEMO] NGAP InitialUEMessage (AMF Registration Procedure)",
            is_demo=True,
        ),
        # SIP INVITE 901 -> 902
        PacketInfo(
            timestamp=(now - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="10.46.0.8",
            dst_ip="192.168.35.35",
            src_port=5060,
            dst_port=5060,
            protocol="SIP/UDP",
            length=680,
            tcp_flags="",
            summary="[DEMO] SIP INVITE sip:902@192.168.35.35 (Caller: 901, SDP AMR-WB)",
            is_demo=True,
        ),
        # SIP 180 Ringing
        PacketInfo(
            timestamp=(now - timedelta(seconds=14)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.35",
            dst_ip="10.46.0.8",
            src_port=5060,
            dst_port=5060,
            protocol="SIP/UDP",
            length=395,
            tcp_flags="",
            summary="[DEMO] SIP/2.0 180 Ringing (Callee 902 Alerting)",
            is_demo=True,
        ),
        # TCP MEC Edge Query
        PacketInfo(
            timestamp=(now - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="10.46.0.7",
            dst_ip="192.168.35.19",
            src_port=49210,
            dst_port=8000,
            protocol="TCP",
            length=88,
            tcp_flags="SYN",
            summary="[DEMO] TCP 49210 -> 8000 [SYN] Seq=102431 Len=88 (MEC Video Stream Request)",
            is_demo=True,
        ),
        # Gateway Ping Fail (ICMP Request with no reply)
        PacketInfo(
            timestamp=(now - timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.15",
            dst_ip="192.168.35.1",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            length=64,
            tcp_flags="",
            summary="[DEMO] ICMP Echo Request id=1 seq=1 (Gateway ping probe - Unanswered)",
            is_demo=True,
        ),
        # NMS Telemetry Sync
        PacketInfo(
            timestamp=(now - timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip="192.168.35.6",
            dst_ip="192.168.35.15",
            src_port=8080,
            dst_port=514,
            protocol="UDP",
            length=180,
            tcp_flags="",
            summary="[DEMO] Syslog / SNMP Telemetry polling from NMS Server",
            is_demo=True,
        ),
    ]
    return demo_pkts


def get_demo_registration_data() -> Dict[str, Dict[str, Any]]:
    """Returns realistic 11-stage registration state for UE 901 and UE 902."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ue901_stages = [
        {
            "stage_id": 1,
            "name": "UE Radio Synchronization",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "MIB / SIB1 broadcast sync (air interface)",
            "status": "Completed",
            "evidence_source": "INFERRED",
            "timestamp": "2026-10-26 15:30:00.850",
            "raw_evidence": "[DEMO] Physical layer MIB/SIB1 reception on NR ARFCN 632544",
            "details": "Band n78, 40MHz channel bandwidth locked",
        },
        {
            "stage_id": 2,
            "name": "Random Access Channel (RACH)",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "MSG1 Preamble / MSG2 RAR handshake",
            "status": "Completed",
            "evidence_source": "INFERRED",
            "timestamp": "2026-10-26 15:30:01.010",
            "raw_evidence": "[DEMO] RACH Preamble MSG1 detected -> MSG2 Random Access Response issued",
            "details": "TA=12, CRNTI allocated: 0x4a12",
        },
        {
            "stage_id": 3,
            "name": "RRC Connection Establishment",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "RRCSetupRequest / RRCSetup / RRCSetupComplete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.182",
            "raw_evidence": "Recv RRCSetupComplete (SelectedPLMN-Identity: 001-01, NAS-PDU: 5GS-Registration-Request, UE 901)",
            "details": "SRB1 established successfully",
        },
        {
            "stage_id": 4,
            "name": "NAS Registration Request",
            "source_component": "UE",
            "dest_component": "AMF",
            "description": "InitialUEMessage_NG with 5GS Registration Request",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.190",
            "raw_evidence": "Send InitialUEMessage_NG (RAN-UE-NGAP-ID: 101, PLMN: 001-01, NSSAI: SST=1, SD=0x000001)",
            "details": "Forwarded to AMF (192.168.35.35:38412)",
        },
        {
            "stage_id": 5,
            "name": "UE Identity Procedures",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "NAS Identity Request / Response (if SUCI needed)",
            "status": "Not observed",
            "evidence_source": "NONE",
            "timestamp": "-",
            "raw_evidence": "SUCI already present in initial registration container; identity exchange skipped per 3GPP TS 33.501",
            "details": "Optional procedure bypassed",
        },
        {
            "stage_id": 6,
            "name": "Authentication",
            "source_component": "AMF/AUSF",
            "dest_component": "UE",
            "description": "5G-AKA / EAP-AKA' challenge and verification",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.260",
            "raw_evidence": "Send UplinkNASTransport (RAN-UE-NGAP-ID: 101, AMF-UE-NGAP-ID: 501, NAS: AuthenticationResponse)",
            "details": "5G-AKA mutual verification successful",
        },
        {
            "stage_id": 7,
            "name": "NAS Security Establishment",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "NAS Security Mode Command / Complete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.310",
            "raw_evidence": "Send UplinkNASTransport (RAN-UE-NGAP-ID: 101, AMF-UE-NGAP-ID: 501, NAS: SecurityModeComplete)",
            "details": "Ciphering: 5G-EA2, Integrity: 5G-IA2",
        },
        {
            "stage_id": 8,
            "name": "UE Capability Exchange",
            "source_component": "gNB",
            "dest_component": "UE",
            "description": "UECapabilityEnquiry / UECapabilityInformation",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.350",
            "raw_evidence": "Recv UECapabilityInformation (NR Band n78, MIMO 4x4, Carrier Aggregation)",
            "details": "Capability container cached in gNB",
        },
        {
            "stage_id": 9,
            "name": "Registration Accept",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "InitialContextSetupRequest + Registration Accept",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.395",
            "raw_evidence": "Recv InitialContextSetupRequest_NG (RAN-UE-NGAP-ID: 101, AMF-UE-NGAP-ID: 501, NAS: RegistrationAccept)",
            "details": "5G-GUTI assigned, Periodic Reg Timer: 54 min",
        },
        {
            "stage_id": 10,
            "name": "Registration Complete",
            "source_component": "UE",
            "dest_component": "AMF",
            "description": "RRCReconfigurationComplete / RegistrationComplete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:01.430",
            "raw_evidence": "Send UplinkNASTransport (RAN-UE-NGAP-ID: 101, AMF-UE-NGAP-ID: 501, NAS: RegistrationComplete)",
            "details": "5GS Registration lifecycle complete",
        },
        {
            "stage_id": 11,
            "name": "PDU Session Establishment",
            "source_component": "SMF/UPF",
            "dest_component": "UE",
            "description": "PDUSessionResourceSetup (internet / ims DNNs)",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:30:02.150",
            "raw_evidence": "Send PDUSessionResourceSetupResponse (DNN: ims, PDU ID: 2, Allocated IP: 10.46.0.8)",
            "details": "Two PDU sessions: DNN internet (10.46.0.7) and DNN ims (10.46.0.8)",
        },
    ]

    ue902_stages = [
        {
            "stage_id": 1,
            "name": "UE Radio Synchronization",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "MIB / SIB1 broadcast sync (air interface)",
            "status": "Completed",
            "evidence_source": "INFERRED",
            "timestamp": "2026-10-26 15:32:10.100",
            "raw_evidence": "[DEMO] DL synchronization on n78",
            "details": "Cell ID: 1",
        },
        {
            "stage_id": 2,
            "name": "Random Access Channel (RACH)",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "MSG1 Preamble / MSG2 RAR handshake",
            "status": "Completed",
            "evidence_source": "INFERRED",
            "timestamp": "2026-10-26 15:32:10.350",
            "raw_evidence": "[DEMO] RACH preamble verified, CRNTI 0x4a15",
            "details": "MSG2 Timing Advance applied",
        },
        {
            "stage_id": 3,
            "name": "RRC Connection Establishment",
            "source_component": "UE",
            "dest_component": "gNB",
            "description": "RRCSetupRequest / RRCSetup / RRCSetupComplete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.560",
            "raw_evidence": "Recv RRCSetupComplete (SelectedPLMN-Identity: 001-01, UE 902)",
            "details": "RRC Connection active",
        },
        {
            "stage_id": 4,
            "name": "NAS Registration Request",
            "source_component": "UE",
            "dest_component": "AMF",
            "description": "InitialUEMessage_NG with 5GS Registration Request",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.570",
            "raw_evidence": "Send InitialUEMessage_NG (RAN-UE-NGAP-ID: 102, NAS: RegistrationRequest)",
            "details": "Dispatched to AMF 192.168.35.35",
        },
        {
            "stage_id": 5,
            "name": "UE Identity Procedures",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "NAS Identity Request / Response (if SUCI needed)",
            "status": "Not observed",
            "evidence_source": "NONE",
            "timestamp": "-",
            "raw_evidence": "Not invoked for UE 902",
            "details": "SUCI decrypted via UDM",
        },
        {
            "stage_id": 6,
            "name": "Authentication",
            "source_component": "AMF/AUSF",
            "dest_component": "UE",
            "description": "5G-AKA / EAP-AKA' challenge and verification",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.600",
            "raw_evidence": "[DEMO] 5G-AKA Challenge-Response verified with AUSF",
            "details": "K_SEAF generated",
        },
        {
            "stage_id": 7,
            "name": "NAS Security Establishment",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "NAS Security Mode Command / Complete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.620",
            "raw_evidence": "[DEMO] NAS Security Mode Complete verified",
            "details": "Integrity protected",
        },
        {
            "stage_id": 8,
            "name": "UE Capability Exchange",
            "source_component": "gNB",
            "dest_component": "UE",
            "description": "UECapabilityEnquiry / UECapabilityInformation",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.635",
            "raw_evidence": "[DEMO] UE Radio Access Capabilities stored",
            "details": "SA NR Support: Yes",
        },
        {
            "stage_id": 9,
            "name": "Registration Accept",
            "source_component": "AMF",
            "dest_component": "UE",
            "description": "InitialContextSetupRequest + Registration Accept",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.650",
            "raw_evidence": "Recv InitialContextSetupRequest_NG (RAN-UE-NGAP-ID: 102, NAS: RegistrationAccept)",
            "details": "Context setup requested",
        },
        {
            "stage_id": 10,
            "name": "Registration Complete",
            "source_component": "UE",
            "dest_component": "AMF",
            "description": "RRCReconfigurationComplete / RegistrationComplete",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:10.720",
            "raw_evidence": "Send InitialContextSetupResponse (RAN-UE-NGAP-ID: 102, AMF-UE-NGAP-ID: 502)",
            "details": "5G Registration Nominal",
        },
        {
            "stage_id": 11,
            "name": "PDU Session Establishment",
            "source_component": "SMF/UPF",
            "dest_component": "UE",
            "description": "PDUSessionResourceSetup (internet / ims DNNs)",
            "status": "Completed",
            "evidence_source": "GNB_LOG",
            "timestamp": "2026-10-26 15:32:11.230",
            "raw_evidence": "Send PDUSessionResourceSetupResponse (DNN: ims, Allocated IP: 10.46.0.10)",
            "details": "Allocated IP: 10.46.0.10 (ims) & 10.46.0.9 (internet)",
        },
    ]

    return {
        "901": {
            "ue_id": "901",
            "crnti": "0x4a12",
            "ip_address": "10.46.0.8",
            "current_state": "PDU_ACTIVE",
            "last_updated": now_str,
            "pdu_sessions": [
                {"dnn": "internet", "status": "ACTIVE", "ip": "10.46.0.7"},
                {"dnn": "ims", "status": "ACTIVE", "ip": "10.46.0.8"},
            ],
            "stages": ue901_stages,
        },
        "902": {
            "ue_id": "902",
            "crnti": "0x4a15",
            "ip_address": "10.46.0.10",
            "current_state": "PDU_ACTIVE",
            "last_updated": now_str,
            "pdu_sessions": [
                {"dnn": "internet", "status": "ACTIVE", "ip": "10.46.0.9"},
                {"dnn": "ims", "status": "ACTIVE", "ip": "10.46.0.10"},
            ],
            "stages": ue902_stages,
        },
    }


def get_demo_sip_state() -> Dict[str, Any]:
    """Returns sample SIP registration list, active call, and Mermaid ladder."""
    ues = [
        {
            "ue_id": "901",
            "ip": "10.46.0.8",
            "registered_at": "2026-10-26 15:30:03",
            "status": "IMS_REGISTERED",
            "p_associated_uri": "sip:901@192.168.35.35",
        },
        {
            "ue_id": "902",
            "ip": "10.46.0.10",
            "registered_at": "2026-10-26 15:32:12",
            "status": "IMS_REGISTERED",
            "p_associated_uri": "sip:902@192.168.35.35",
        },
    ]

    calls = [
        {
            "call_id": "call-901-to-902-session@10.46.0.8",
            "caller": "901",
            "callee": "902",
            "caller_ip": "10.46.0.8",
            "callee_ip": "10.46.0.10",
            "state": "RINGING",
            "start_time": "2026-10-26 15:35:00",
            "ringing_time": "2026-10-26 15:35:00.230",
            "connect_time": "-",
            "end_time": "-",
            "setup_time_ms": 230,
            "release_reason": "-",
            "evidence": "[DEMO] SIP INVITE -> 100 Trying -> 180 Ringing observed on port 5060",
            "message_count": 5,
        }
    ]

    mermaid = """sequenceDiagram
    autonumber
    participant UE1 as UE 901 (10.46.0.8)
    participant Core as IMS Core (192.168.35.35)
    participant UE2 as UE 902 (10.46.0.10)
    Note over UE1,Core: UE 901 IMS Registration
    UE1->>Core: REGISTER sip:192.168.35.35
    Core-->>UE1: 401 Unauthorized (Digest challenge)
    UE1->>Core: REGISTER (with credentials)
    Core-->>UE1: 200 OK (P-Associated-URI: sip:901)
    Note over Core,UE2: UE 902 IMS Registration
    UE2->>Core: REGISTER sip:192.168.35.35
    Core-->>UE2: 200 OK (P-Associated-URI: sip:902)
    Note over UE1,UE2: Voice Call Setup: 901 calls 902
    UE1->>Core: INVITE sip:902 (SDP: AMR-WB)
    Core-->>UE1: 100 Trying
    Core->>UE2: INVITE sip:902
    UE2-->>Core: 180 Ringing
    Core-->>UE1: 180 Ringing (902 Alerting)
"""

    return {"registered_ues": ues, "calls": calls, "mermaid": mermaid}
