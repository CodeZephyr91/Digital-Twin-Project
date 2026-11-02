"""SIP and IMS Monitoring module for 5G Lab Doctor.

Parses observable SIP signalling (RFC 3261) from live packet captures or tcpdump traces:
- REGISTER, 401/407 challenges, 200 OK (with P-Associated-URI extraction)
- INVITE, 100 Trying, 180 Ringing, 200 OK, ACK, BYE, and error responses
- Tracks call state machines (IDLE -> INVITE_SENT -> RINGING -> CONNECTED -> ENDED)
- Produces Mermaid sequence ladder diagrams for clear telecom visualization.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("5g_lab_doctor.sip_monitor")


@dataclass
class SIPMessage:
    raw_text: str
    timestamp: str
    method_or_status: str
    is_request: bool
    cseq_method: str
    call_id: str
    from_uri: str
    to_uri: str
    from_user: str
    to_user: str
    src_ip: str
    dst_ip: str
    contact_uri: Optional[str] = None
    p_associated_uri: Optional[str] = None
    status_code: Optional[int] = None


@dataclass
class SIPCallSession:
    call_id: str
    caller: str
    callee: str
    caller_ip: str
    callee_ip: str
    state: str = "IDLE"  # IDLE, INVITE_SENT, TRYING, RINGING, CONNECTED, ENDED, FAILED
    start_time: str = ""
    ringing_time: Optional[str] = None
    connect_time: Optional[str] = None
    end_time: Optional[str] = None
    setup_time_ms: Optional[int] = None
    release_reason: Optional[str] = None
    evidence: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_id": self.call_id,
            "caller": self.caller,
            "callee": self.callee,
            "caller_ip": self.caller_ip,
            "callee_ip": self.callee_ip,
            "state": self.state,
            "start_time": self.start_time,
            "ringing_time": self.ringing_time or "-",
            "connect_time": self.connect_time or "-",
            "end_time": self.end_time or "-",
            "setup_time_ms": self.setup_time_ms,
            "release_reason": self.release_reason or "-",
            "evidence": self.evidence,
            "message_count": len(self.messages),
        }


class SIPMonitor:
    """Reconstructs IMS SIP calls and registration states from packet captures or log streams."""

    def __init__(self):
        self.registered_ues: Dict[str, Dict[str, Any]] = {}
        self.active_calls: Dict[str, SIPCallSession] = {}
        self.call_history: List[SIPCallSession] = []
        self.ladder_events: List[Dict[str, Any]] = []

    @staticmethod
    def _extract_user(sip_uri: str) -> str:
        """Extracts user/extension number from a SIP URI like 'sip:901@192.168.35.35'."""
        match = re.search(r"sip:([0-9a-zA-Z_.-]+)@", sip_uri)
        if match:
            return match.group(1)
        # Direct string if no @
        match2 = re.search(r"sip:([0-9a-zA-Z_.-]+)", sip_uri)
        return match2.group(1) if match2 else sip_uri

    def parse_sip_chunk(self, text: str, default_ts: Optional[str] = None, default_src: str = "", default_dst: str = "") -> Optional[SIPMessage]:
        """Parses a single SIP message block from raw text or tcpdump snippet."""
        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        if not lines:
            return None

        # Look for SIP start line (Request or Response)
        start_line_idx = -1
        method_or_status = ""
        is_request = False
        status_code = None

        header_prefix_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+IP\s+([0-9.]+)(?:\.\d+)?\s*>\s*([0-9.]+)(?:\.\d+)?", text)
        ts = header_prefix_match.group(1) if header_prefix_match else (default_ts or datetime.now().isoformat(sep=" ", timespec="milliseconds"))
        src_ip = header_prefix_match.group(2) if header_prefix_match else default_src
        dst_ip = header_prefix_match.group(3) if header_prefix_match else default_dst

        for i, line in enumerate(lines):
            # Check SIP Request: e.g. REGISTER sip:..., INVITE sip:..., BYE sip:...
            req_match = re.search(r"\b(REGISTER|INVITE|ACK|BYE|CANCEL|OPTIONS|PRACK|UPDATE|SUBSCRIBE|NOTIFY)\s+(sip:[^\s]+)\s+SIP/2\.0", line)
            if req_match:
                start_line_idx = i
                method_or_status = req_match.group(1)
                is_request = True
                break

            # Check SIP Response: e.g. SIP/2.0 200 OK, SIP/2.0 180 Ringing, SIP/2.0 401 Unauthorized
            res_match = re.search(r"SIP/2\.0\s+(\d{3})\s+(.*)", line)
            if res_match:
                start_line_idx = i
                status_code = int(res_match.group(1))
                method_or_status = f"{status_code} {res_match.group(2).strip()}"
                is_request = False
                break

        if start_line_idx == -1:
            return None

        call_id = ""
        from_uri = ""
        to_uri = ""
        contact_uri = None
        p_associated_uri = None
        cseq_method = ""

        for line in lines[start_line_idx:]:
            if re.match(r"^Call-ID:\s*", line, re.IGNORECASE):
                call_id = re.sub(r"^Call-ID:\s*", "", line, flags=re.IGNORECASE).strip()
            elif re.match(r"^From:\s*", line, re.IGNORECASE):
                from_uri = re.sub(r"^From:\s*", "", line, flags=re.IGNORECASE).strip()
            elif re.match(r"^To:\s*", line, re.IGNORECASE):
                to_uri = re.sub(r"^To:\s*", "", line, flags=re.IGNORECASE).strip()
            elif re.match(r"^Contact:\s*", line, re.IGNORECASE):
                contact_uri = re.sub(r"^Contact:\s*", "", line, flags=re.IGNORECASE).strip()
            elif re.match(r"^P-Associated-URI:\s*", line, re.IGNORECASE):
                p_associated_uri = re.sub(r"^P-Associated-URI:\s*", "", line, flags=re.IGNORECASE).strip()
            elif re.match(r"^CSeq:\s*", line, re.IGNORECASE):
                cseq_parts = re.sub(r"^CSeq:\s*", "", line, flags=re.IGNORECASE).strip().split()
                if len(cseq_parts) > 1:
                    cseq_method = cseq_parts[1].upper()

        from_user = self._extract_user(from_uri)
        to_user = self._extract_user(to_uri)

        return SIPMessage(
            raw_text=text,
            timestamp=ts,
            method_or_status=method_or_status,
            is_request=is_request,
            cseq_method=cseq_method or (method_or_status if is_request else ""),
            call_id=call_id or f"cid-{ts}-{from_user}",
            from_uri=from_uri,
            to_uri=to_uri,
            from_user=from_user or "unknown",
            to_user=to_user or "unknown",
            src_ip=src_ip,
            dst_ip=dst_ip,
            contact_uri=contact_uri,
            p_associated_uri=p_associated_uri,
            status_code=status_code,
        )

    def process_sip_message(self, msg: SIPMessage) -> Dict[str, Any]:
        """Updates registration state, call sessions, and generates ladder events."""
        event_record: Dict[str, Any] = {
            "timestamp": msg.timestamp,
            "type": "SIP_EVENT",
            "method": msg.method_or_status,
            "from_user": msg.from_user,
            "to_user": msg.to_user,
            "src_ip": msg.src_ip,
            "dst_ip": msg.dst_ip,
            "call_id": msg.call_id,
        }

        # 1. Registration Tracking
        if "REGISTER" in msg.cseq_method or msg.method_or_status == "REGISTER":
            user = msg.from_user
            if msg.status_code == 200:
                # 200 OK for REGISTER
                extracted_user = user
                if msg.p_associated_uri:
                    extracted_user = self._extract_user(msg.p_associated_uri)
                self.registered_ues[extracted_user] = {
                    "ue_id": extracted_user,
                    "ip": msg.dst_ip or msg.src_ip,
                    "registered_at": msg.timestamp,
                    "status": "IMS_REGISTERED",
                    "p_associated_uri": msg.p_associated_uri or f"sip:{extracted_user}",
                }
                event_record["registration_status"] = "SUCCESS"
                event_record["registered_ue"] = extracted_user
            elif msg.status_code in (401, 407):
                event_record["registration_status"] = "CHALLENGED"

        # 2. Call State Tracking
        c_method = msg.cseq_method.upper() if msg.cseq_method else msg.method_or_status.upper()
        call_id = msg.call_id

        if call_id not in self.active_calls:
            self.active_calls[call_id] = SIPCallSession(
                call_id=call_id,
                caller=msg.from_user,
                callee=msg.to_user,
                caller_ip=msg.src_ip,
                callee_ip=msg.dst_ip,
                state="IDLE",
                start_time=msg.timestamp,
            )

        call = self.active_calls[call_id]
        call.messages.append({
            "timestamp": msg.timestamp,
            "direction": f"{msg.src_ip} -> {msg.dst_ip}",
            "msg": msg.method_or_status,
        })

        if msg.is_request:
            if msg.method_or_status == "INVITE":
                call.state = "INVITE_SENT"
                call.start_time = msg.timestamp
                call.evidence = f"SIP INVITE from sip:{msg.from_user} to sip:{msg.to_user} on port 5060"
            elif msg.method_or_status == "ACK":
                call.state = "CONNECTED"
                call.connect_time = msg.timestamp
                call.evidence = "SIP ACK received; two-way RTP bearer path established"
            elif msg.method_or_status == "BYE":
                call.state = "ENDED"
                call.end_time = msg.timestamp
                call.release_reason = f"Normal call release initiated by {msg.from_user}"
                call.evidence = f"SIP BYE from {msg.from_user}"
                # Move to history
                if call not in self.call_history:
                    self.call_history.append(call)
        else:
            # Responses
            if msg.status_code == 100:
                call.state = "TRYING"
                call.evidence = "Core softswitch processing routing (100 Trying)"
            elif msg.status_code == 180:
                call.state = "RINGING"
                call.ringing_time = msg.timestamp
                call.evidence = f"Called UE {call.callee} is alerting (180 Ringing)"
            elif msg.status_code == 200:
                if c_method == "INVITE":
                    call.state = "ANSWERED"
                    call.connect_time = msg.timestamp
                    call.evidence = f"Call answered by {call.callee} (200 OK)"
                elif c_method == "BYE":
                    call.state = "ENDED"
                    call.end_time = msg.timestamp
            elif msg.status_code and msg.status_code >= 400:
                call.state = "FAILED"
                call.end_time = msg.timestamp
                call.release_reason = f"SIP Error {msg.status_code}: {msg.method_or_status}"
                call.evidence = f"Failure response received: {msg.method_or_status}"

        # Ladder event record
        src_entity = self._resolve_entity_name(msg.src_ip, msg.from_user)
        dst_entity = self._resolve_entity_name(msg.dst_ip, msg.to_user)
        self.ladder_events.append({
            "timestamp": msg.timestamp,
            "src": src_entity,
            "dst": dst_entity,
            "label": msg.method_or_status,
            "raw": msg.raw_text,
        })

        return event_record

    def _resolve_entity_name(self, ip: str, user: str) -> str:
        """Translates an IP or username to a standardized ladder diagram entity."""
        if user in ("901", "UE-901", "UE 901"):
            return "UE 901"
        if user in ("902", "UE-902", "UE 902"):
            return "UE 902"
        if "35.35" in ip:
            return "IMS Core"
        if "10.46.0.8" in ip or "10.46.0.7" in ip:
            return "UE 901"
        if "10.46.0.10" in ip or "10.46.0.9" in ip:
            return "UE 902"
        return f"Node ({ip})" if ip else "IMS Core"

    def parse_file(self, file_path: str) -> int:
        """Parses a full or appended tcpdump SIP trace file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.error("Could not read SIP trace file %s: %s", file_path, e)
            return 0

        # Split on timestamp or empty lines
        chunks = re.split(r"\n(?=\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", content)
        count = 0
        for chunk in chunks:
            msg = self.parse_sip_chunk(chunk)
            if msg:
                self.process_sip_message(msg)
                count += 1
        return count

    def generate_mermaid_ladder(self, limit: int = 25) -> str:
        """Generates Mermaid.js sequence diagram code from recent SIP transactions."""
        events = self.ladder_events[-limit:]
        if not events:
            return "sequenceDiagram\n    Note over UE 901, IMS Core: No SIP transactions observed yet\n"

        lines = ["sequenceDiagram", "    autonumber"]
        # Declare participants in predictable order
        lines.append("    participant UE1 as UE 901")
        lines.append("    participant Core as IMS Core (192.168.35.35)")
        lines.append("    participant UE2 as UE 902")

        for ev in events:
            src = "UE1" if "901" in ev["src"] else "UE2" if "902" in ev["src"] else "Core"
            dst = "UE1" if "901" in ev["dst"] else "UE2" if "902" in ev["dst"] else "Core"
            label = ev["label"].replace('"', "'")
            # If response, use dashed line
            arrow = "-->>" if any(x in label for x in ("200", "180", "100", "401", "407", "404", "486")) else "->>"
            lines.append(f"    {src}{arrow}{dst}: {label}")

        return "\n".join(lines)

    def get_registered_ues(self) -> List[Dict[str, Any]]:
        return list(self.registered_ues.values())

    def get_calls(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in list(self.active_calls.values())]

    def reset(self):
        self.registered_ues.clear()
        self.active_calls.clear()
        self.call_history.clear()
        self.ladder_events.clear()
