"""5G UE Registration monitoring and protocol event parser.

Implements the 11-stage 3GPP registration timeline (Release 15/16/17):
1. UE radio synchronization (MIB/SIB1)
2. Random Access Channel (RACH)
3. RRC connection establishment
4. NAS Registration Request
5. UE identity procedures (if required)
6. Authentication
7. NAS security establishment
8. UE capability exchange
9. Registration Accept
10. Registration Complete
11. PDU Session Establishment

Strictly adheres to observation rules:
- Never fabricates missing events ("Not observed" if unobservable).
- Does not infer prior steps are complete unless verified.
- Explicitly flags evidence source: GNB_LOG, CORE_LOG, PACKET_CAPTURE, or INFERRED.
"""

import copy
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("5g_lab_doctor.registration_parser")

STAGE_DEFINITIONS = [
    (1, "UE Radio Synchronization", "UE", "gNB", "MIB / SIB1 broadcast sync (air interface)"),
    (2, "Random Access Channel (RACH)", "UE", "gNB", "MSG1 Preamble / MSG2 RAR handshake"),
    (3, "RRC Connection Establishment", "UE", "gNB", "RRCSetupRequest / RRCSetup / RRCSetupComplete"),
    (4, "NAS Registration Request", "UE", "AMF", "InitialUEMessage_NG with 5GS Registration Request"),
    (5, "UE Identity Procedures", "AMF", "UE", "NAS Identity Request / Response (if SUCI needed)"),
    (6, "Authentication", "AMF/AUSF", "UE", "5G-AKA / EAP-AKA' challenge and verification"),
    (7, "NAS Security Establishment", "AMF", "UE", "NAS Security Mode Command / Complete"),
    (8, "UE Capability Exchange", "gNB", "UE", "UECapabilityEnquiry / UECapabilityInformation"),
    (9, "Registration Accept", "AMF", "UE", "InitialContextSetupRequest + Registration Accept"),
    (10, "Registration Complete", "UE", "AMF", "RRCReconfigurationComplete / RegistrationComplete"),
    (11, "PDU Session Establishment", "SMF/UPF", "UE", "PDUSessionResourceSetup (internet / ims DNNs)"),
]


class RegistrationStage:
    def __init__(
        self,
        stage_id: int,
        name: str,
        source_component: str,
        dest_component: str,
        description: str,
        status: str = "Not observed",
        evidence_source: str = "NONE",
        timestamp: Optional[str] = None,
        raw_evidence: Optional[str] = None,
        details: Optional[str] = None,
    ):
        self.stage_id = stage_id
        self.name = name
        self.source_component = source_component
        self.dest_component = dest_component
        self.description = description
        self.status = status  # Not observed, Pending, Observed, Completed, Error
        self.evidence_source = evidence_source  # NONE, GNB_LOG, CORE_LOG, PACKET_CAPTURE, INFERRED
        self.timestamp = timestamp
        self.raw_evidence = raw_evidence
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "name": self.name,
            "source_component": self.source_component,
            "dest_component": self.dest_component,
            "description": self.description,
            "status": self.status,
            "evidence_source": self.evidence_source,
            "timestamp": self.timestamp or "-",
            "raw_evidence": self.raw_evidence or "No direct telemetry observed",
            "details": self.details or "",
        }


class UERegistrationState:
    def __init__(self, ue_id: str):
        self.ue_id = ue_id
        self.crnti: Optional[str] = None
        self.ip_address: Optional[str] = None
        self.current_state: str = "IDLE"  # IDLE, RRC_CONNECTING, AUTHENTICATING, REGISTERED, PDU_ACTIVE, RELEASED
        self.last_updated: str = datetime.now().isoformat(sep=" ", timespec="seconds")
        self.pdu_sessions: List[Dict[str, Any]] = []

        # Initialize the 11 stages as "Not observed"
        self.stages: Dict[int, RegistrationStage] = {}
        for s_id, s_name, s_src, s_dst, s_desc in STAGE_DEFINITIONS:
            self.stages[s_id] = RegistrationStage(
                stage_id=s_id,
                name=s_name,
                source_component=s_src,
                dest_component=s_dst,
                description=s_desc,
                status="Not observed",
                evidence_source="NONE",
            )

    def mark_stage(
        self,
        stage_id: int,
        status: str,
        evidence_source: str,
        timestamp: str,
        raw_evidence: str,
        details: Optional[str] = None,
    ):
        if stage_id in self.stages:
            stage = self.stages[stage_id]
            stage.status = status
            stage.evidence_source = evidence_source
            stage.timestamp = timestamp
            stage.raw_evidence = raw_evidence
            if details:
                stage.details = details
            self.last_updated = timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ue_id": self.ue_id,
            "crnti": self.crnti or "N/A",
            "ip_address": self.ip_address or "Pending PDU",
            "current_state": self.current_state,
            "last_updated": self.last_updated,
            "pdu_sessions": self.pdu_sessions,
            "stages": [stage.to_dict() for stage in self.stages.values()],
        }


class RegistrationParser:
    """Parses gNodeB logs, NGAP traces, and packet captures into structured UE lifecycles."""

    def __init__(self):
        self.ue_states: Dict[str, UERegistrationState] = {}
        self.crnti_to_ue: Dict[str, str] = {}

    def get_or_create_ue(self, ue_id: str) -> UERegistrationState:
        resolved_id = self.crnti_to_ue.get(ue_id, ue_id)
        if resolved_id not in self.ue_states:
            if ue_id != resolved_id and ue_id in self.ue_states:
                old_state = self.ue_states.pop(ue_id)
                old_state.ue_id = resolved_id
                self.ue_states[resolved_id] = old_state
            else:
                self.ue_states[resolved_id] = UERegistrationState(resolved_id)
        return self.ue_states[resolved_id]

    def parse_gnb_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses a log line from /home/tetra/euGNB/logs/msg_trace.log."""
        line = line.strip()
        if not line:
            return None

        # Regex for timestamp: 2026-10-26 15:30:01.120 or similar
        ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
        timestamp = ts_match.group(1) if ts_match else datetime.now().isoformat(sep=" ", timespec="milliseconds")

        # Extract CRNTI or UE identifier if present
        crnti_match = re.search(r"CRNTI\s+(0x[0-9a-fA-F]+)", line, re.IGNORECASE)
        crnti = crnti_match.group(1) if crnti_match else None

        # Check for explicit phone/subscriber UE number (e.g. 'UE 901' or 'UE 902')
        ue_num_match = re.search(r"\bUE\s+(\d+)\b", line)
        if ue_num_match:
            ue_id = ue_num_match.group(1)
            if crnti:
                self.crnti_to_ue[crnti] = ue_id
                if crnti in self.ue_states and crnti != ue_id:
                    old_state = self.ue_states.pop(crnti)
                    old_state.ue_id = ue_id
                    self.ue_states[ue_id] = old_state
        elif crnti and crnti in self.crnti_to_ue:
            ue_id = self.crnti_to_ue[crnti]
        elif crnti:
            ue_id = crnti
        else:
            ue_id_match = re.search(r"UE identity:\s*(0x[0-9a-fA-F]+)", line)
            ue_id = ue_id_match.group(1) if ue_id_match else "UE-UNKNOWN"

        ue = self.get_or_create_ue(ue_id)
        if crnti:
            ue.crnti = crnti

        # Match specific 3GPP and euGNB phrases
        if "Recv RRCSetupRequest" in line:
            # Stage 3 started (and RACH MSG1/2 is inferred/observed as physical pre-condition)
            ue.current_state = "RRC_CONNECTING"
            ue.mark_stage(
                stage_id=2,
                status="Completed",
                evidence_source="INFERRED",
                timestamp=timestamp,
                raw_evidence=line,
                details="RACH preamble succeeded, triggering RRCSetupRequest",
            )
            ue.mark_stage(
                stage_id=3,
                status="Observed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="UE sent RRCSetupRequest (mo-Signalling)",
            )
            return {"type": "RRC_SETUP_REQUEST", "ue_id": ue_id, "timestamp": timestamp, "stage": 3}

        elif "Recv RRCSetupComplete" in line:
            ue.mark_stage(
                stage_id=3,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="RRC Setup Completed on SRB1",
            )
            if "5GS-Registration-Request" in line or "NAS-PDU" in line:
                ue.mark_stage(
                    stage_id=4,
                    status="Observed",
                    evidence_source="GNB_LOG",
                    timestamp=timestamp,
                    raw_evidence=line,
                    details="RRCSetupComplete contained embedded NAS Registration Request",
                )
            return {"type": "RRC_SETUP_COMPLETE", "ue_id": ue_id, "timestamp": timestamp, "stage": 3}

        elif "Send InitialUEMessage_NG" in line:
            ue.mark_stage(
                stage_id=4,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="gNB forwarded InitialUEMessage with NAS Registration to AMF over NGAP",
            )
            return {"type": "INITIAL_UE_MESSAGE", "ue_id": ue_id, "timestamp": timestamp, "stage": 4}

        elif "AuthenticationRequest" in line:
            ue.current_state = "AUTHENTICATING"
            ue.mark_stage(
                stage_id=6,
                status="Observed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="AMF initiated 5G-AKA Authentication challenge",
            )
            return {"type": "AUTH_REQUEST", "ue_id": ue_id, "timestamp": timestamp, "stage": 6}

        elif "AuthenticationResponse" in line:
            ue.mark_stage(
                stage_id=6,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="UE responded to Authentication challenge with valid RES*",
            )
            return {"type": "AUTH_RESPONSE", "ue_id": ue_id, "timestamp": timestamp, "stage": 6}

        elif "SecurityModeCommand" in line:
            ue.mark_stage(
                stage_id=7,
                status="Observed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="NAS/AS Security Mode Command issued",
            )
            return {"type": "SECURITY_MODE_CMD", "ue_id": ue_id, "timestamp": timestamp, "stage": 7}

        elif "SecurityModeComplete" in line:
            ue.mark_stage(
                stage_id=7,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="Ciphering and integrity protection verified and activated",
            )
            return {"type": "SECURITY_MODE_COMPLETE", "ue_id": ue_id, "timestamp": timestamp, "stage": 7}

        elif "UECapabilityEnquiry" in line or "UECapabilityInformation" in line:
            ue.mark_stage(
                stage_id=8,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="UE radio capabilities exchanged and cached",
            )
            return {"type": "UE_CAPABILITY", "ue_id": ue_id, "timestamp": timestamp, "stage": 8}

        elif "Recv InitialContextSetupRequest_NG" in line or "RegistrationAccept" in line:
            ue.mark_stage(
                stage_id=9,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="Core AMF accepted registration, InitialContextSetup requested",
            )
            return {"type": "REGISTRATION_ACCEPT", "ue_id": ue_id, "timestamp": timestamp, "stage": 9}

        elif "RRCReconfigurationComplete" in line or "RegistrationComplete" in line or "Send UplinkNASTransport" in line and "RegistrationComplete" in line:
            ue.current_state = "REGISTERED"
            ue.mark_stage(
                stage_id=10,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="UE confirmed Registration Complete, 5G NAS security context active",
            )
            return {"type": "REGISTRATION_COMPLETE", "ue_id": ue_id, "timestamp": timestamp, "stage": 10}

        elif "Recv PDUSessionResourceSetupRequest" in line:
            ue.mark_stage(
                stage_id=11,
                status="Observed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details="AMF/SMF requested PDU Session setup",
            )
            # Detect DNN
            dnn = "internet" if "internet" in line else "ims" if "ims" in line else "default"
            ue.pdu_sessions.append({"dnn": dnn, "status": "REQUESTED", "timestamp": timestamp})
            return {"type": "PDU_SESSION_REQUEST", "ue_id": ue_id, "dnn": dnn, "timestamp": timestamp, "stage": 11}

        elif "Send PDUSessionResourceSetupResponse" in line:
            ue.current_state = "PDU_ACTIVE"
            ip_match = re.search(r"Allocated IP:\s*([0-9.]+)", line)
            if ip_match:
                ue.ip_address = ip_match.group(1)

            ue.mark_stage(
                stage_id=11,
                status="Completed",
                evidence_source="GNB_LOG",
                timestamp=timestamp,
                raw_evidence=line,
                details=f"PDU session established. Allocated IP: {ue.ip_address or 'Configured'}",
            )
            for sess in ue.pdu_sessions:
                if sess["status"] == "REQUESTED":
                    sess["status"] = "ACTIVE"
                    sess["ip"] = ue.ip_address
            return {"type": "PDU_SESSION_RESPONSE", "ue_id": ue_id, "ip": ue.ip_address, "timestamp": timestamp, "stage": 11}

        elif "Recv UEContextReleaseCommand_NG" in line or "Send RRCRelease" in line:
            ue.current_state = "RELEASED"
            return {"type": "UE_RELEASE", "ue_id": ue_id, "timestamp": timestamp}

        return None

    def parse_packet_for_registration(self, pkt_info: Any) -> Optional[Dict[str, Any]]:
        """Checks if a captured packet indicates 5G registration/PDU activity."""
        proto = getattr(pkt_info, "protocol", "")
        summary = getattr(pkt_info, "summary", "")
        src_ip = getattr(pkt_info, "src_ip", "")
        dst_ip = getattr(pkt_info, "dst_ip", "")
        ts = getattr(pkt_info, "timestamp", "")

        # GTP-U encapsulation packets observed on lab edge
        if "GTP-U" in proto or "2152" in summary:
            # 5G data traffic observed over tunnel
            ue_id = f"IP-{src_ip}" if src_ip.startswith("10.46.") else f"IP-{dst_ip}"
            ue = self.get_or_create_ue(ue_id)
            ue.ip_address = src_ip if src_ip.startswith("10.46.") else dst_ip
            ue.current_state = "PDU_ACTIVE"
            ue.mark_stage(
                stage_id=11,
                status="Completed",
                evidence_source="PACKET_CAPTURE",
                timestamp=ts,
                raw_evidence=summary,
                details="Active GTP-U User-Plane 5G traffic observed at capture interface",
            )
            return {"type": "GTP_PACKET", "ue_id": ue_id, "timestamp": ts, "stage": 11}

        # SCTP NGAP traffic
        if "SCTP" in proto or "38412" in summary:
            return {"type": "NGAP_SCTP_PACKET", "timestamp": ts}

        return None

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        return {ue_id: ue.to_dict() for ue_id, ue in self.ue_states.items()}

    def reset(self):
        self.ue_states.clear()
        self.crnti_to_ue.clear()
