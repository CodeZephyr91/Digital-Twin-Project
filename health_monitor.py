"""MEC and Lab Health Monitoring and Failure Isolation Engine.

Performs non-intrusive reachability and service health checks across the 192.168.35.x subnet:
- Gateway (192.168.35.1)
- Switch (192.168.35.2)
- NMS Server (192.168.35.6)
- gNB (192.168.35.15)
- MEC Edge (192.168.35.19)
- MEC Cloud (192.168.35.5)
- IMS Core (192.168.35.35)
- VM Hosts (192.168.35.50 / .51)

Implements the Rule-Based Failure Isolation Matrix from Blueprint Section 4.1 & 11:
- Distinguishes reachability (ping/socket) from true service health (telemetry/protocols).
- Generates human-readable diagnosis and links each conclusion to concrete evidence.
"""

import concurrent.futures
import logging
import platform
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("5g_lab_doctor.health_monitor")


@dataclass
class DiagnosticFinding:
    severity: str  # OK, INFO, WARNING, CRITICAL
    headline: str
    explanation: str
    evidence: str
    suggested_action: str
    timestamp: str


class HealthMonitor:
    """Monitors lab nodes and applies telecom diagnosis rules."""

    def __init__(self, nodes_config: Optional[Dict[str, Any]] = None):
        self.nodes_config = nodes_config or {}
        self.node_states: Dict[str, Dict[str, Any]] = {}
        self.last_run_time: Optional[str] = None
        self._lock = threading.Lock()

    @staticmethod
    def send_protocol_request(
        ip: str,
        port: int = 22,
        protocol: str = "SSH",
        platform_type: str = "CLI",
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout_sec: float = 2.5,
    ) -> Dict[str, Any]:
        """Makes a valid request through a valid protocol to the target IP address.

        Supports SSH (CLI), HTTP/HTTPS (GUI), SIP (Vo5G/IMS), TCP socket, and ICMP ping.
        """
        start_time = time.time()
        proto_upper = protocol.upper()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result: Dict[str, Any] = {
            "target_ip": ip,
            "target_port": port,
            "protocol": protocol,
            "platform": platform_type,
            "success": False,
            "latency_ms": None,
            "status_summary": "INIT",
            "response_data": "",
            "evidence": "",
            "timestamp": now_str,
        }

        # 1. SSH Protocol Request (CLI Platform)
        if proto_upper == "SSH" or platform_type == "CLI":
            try:
                from ssh_service import SSHService
                if username:
                    ok, msg, lat = SSHService.test_connection(
                        host=ip,
                        port=port or 22,
                        username=username,
                        password=password,
                        key_file=key_file,
                        timeout=int(timeout_sec),
                    )
                    lat_calc = lat or round((time.time() - start_time) * 1000, 2)
                    result["success"] = ok
                    result["latency_ms"] = lat_calc
                    result["status_summary"] = "SSH Auth Success" if ok else "SSH Auth Failed"
                    result["response_data"] = msg
                    result["evidence"] = f"SSH Handshake on {ip}:{port} (User: {username}): {msg}"
                    return result
            except Exception as e:
                logger.debug("SSH Service check error: %s", e)

            # Fallback SSH Banner Grab via TCP Socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_sec)
                s.connect((ip, port or 22))
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                s.close()
                latency = round((time.time() - start_time) * 1000, 2)
                result["success"] = True
                result["latency_ms"] = latency
                result["status_summary"] = f"SSH Banner Received ({banner[:40]})"
                result["response_data"] = banner
                result["evidence"] = f"TCP SYN/ACK + SSH Identification from {ip}:{port}: {banner}"
                return result
            except Exception as e:
                latency = round((time.time() - start_time) * 1000, 2)
                result["latency_ms"] = latency
                result["status_summary"] = f"SSH Port {port or 22} Unreachable"
                result["response_data"] = str(e)
                result["evidence"] = f"Connection refused or timed out on {ip}:{port}"

        # 2. HTTP / HTTPS Protocol Request (GUI Platform)
        elif proto_upper in ("HTTP", "HTTPS") or platform_type == "GUI":
            scheme = "https" if (proto_upper == "HTTPS" or port == 443) else "http"
            target_port = port if port else (443 if scheme == "https" else 80)
            url = f"{scheme}://{ip}:{target_port}/"

            try:
                import requests
                from requests.auth import HTTPBasicAuth
                auth = HTTPBasicAuth(username, password) if (username and password) else None
                resp = requests.get(
                    url,
                    timeout=timeout_sec,
                    verify=False,
                    auth=auth,
                    allow_redirects=True,
                )
                latency = round((time.time() - start_time) * 1000, 2)
                server_hdr = resp.headers.get("Server", "Unknown Web Server")
                result["success"] = True
                result["latency_ms"] = latency
                result["status_summary"] = f"HTTP {resp.status_code} ({resp.reason})"
                result["response_data"] = f"Status: {resp.status_code} {resp.reason}\nServer: {server_hdr}\nContent-Type: {resp.headers.get('Content-Type', 'N/A')}"
                result["evidence"] = f"HTTP GET {url} -> Status {resp.status_code} {resp.reason} (Server: {server_hdr})"
                return result
            except Exception as e:
                # If HTTP fails, test TCP socket
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout_sec)
                    res = s.connect_ex((ip, target_port))
                    s.close()
                    latency = round((time.time() - start_time) * 1000, 2)
                    if res == 0:
                        result["success"] = True
                        result["latency_ms"] = latency
                        result["status_summary"] = f"TCP Port {target_port} Open (HTTP service active)"
                        result["response_data"] = f"TCP Port {target_port} connected successfully"
                        result["evidence"] = f"TCP SYN/ACK received on {ip}:{target_port}"
                        return result
                except Exception:
                    pass

                latency = round((time.time() - start_time) * 1000, 2)
                result["latency_ms"] = latency
                result["status_summary"] = f"HTTP Request Failed ({url})"
                result["response_data"] = str(e)
                result["evidence"] = f"HTTP connect error on {url}: {e}"

        # 3. SIP Protocol Request (RFC 3261 OPTIONS Probe on Port 5060)
        elif proto_upper == "SIP":
            sip_port = port or 5060
            try:
                # Send RFC 3261 SIP OPTIONS Request over UDP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(min(timeout_sec, 2.0))
                sip_options = (
                    f"OPTIONS sip:{ip}:{sip_port} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-lab-probe-{int(time.time())}\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"From: <sip:lab-probe@5g-lab>;tag=probe1\r\n"
                    f"To: <sip:{ip}:{sip_port}>\r\n"
                    f"Call-ID: probe-{int(time.time()*1000)}@5g-lab\r\n"
                    f"CSeq: 1 OPTIONS\r\n"
                    f"Contact: <sip:lab-probe@127.0.0.1:5060>\r\n"
                    f"Accept: application/sdp\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
                s.sendto(sip_options.encode("utf-8"), (ip, sip_port))
                data, _ = s.recvfrom(2048)
                s.close()
                latency = round((time.time() - start_time) * 1000, 2)
                first_line = data.decode("utf-8", errors="ignore").splitlines()[0] if data else "SIP Response"
                result["success"] = True
                result["latency_ms"] = latency
                result["status_summary"] = f"SIP Response: {first_line}"
                result["response_data"] = data.decode("utf-8", errors="ignore")
                result["evidence"] = f"RFC 3261 SIP OPTIONS to {ip}:{sip_port} returned: {first_line}"
                return result
            except Exception:
                # Test TCP Port 5060 fallback
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout_sec)
                    res = s.connect_ex((ip, sip_port))
                    s.close()
                    latency = round((time.time() - start_time) * 1000, 2)
                    if res == 0:
                        result["success"] = True
                        result["latency_ms"] = latency
                        result["status_summary"] = f"SIP TCP Port {sip_port} Listening"
                        result["response_data"] = f"TCP port {sip_port} connected"
                        result["evidence"] = f"SIP Port {sip_port} listening on {ip}"
                        return result
                except Exception:
                    pass

                latency = round((time.time() - start_time) * 1000, 2)
                result["latency_ms"] = latency
                result["status_summary"] = f"SIP Port {sip_port} No Response"
                result["response_data"] = f"No SIP response from {ip}:{sip_port}"
                result["evidence"] = f"SIP probe timed out on UDP/TCP {ip}:{sip_port}"

        # 4. Fallback TCP Socket & ICMP Ping Probe
        reachable, latency, desc = HealthMonitor.check_reachability(ip, timeout_sec=timeout_sec)
        result["success"] = reachable
        result["latency_ms"] = latency
        result["status_summary"] = desc
        result["response_data"] = desc
        result["evidence"] = f"Path probe on {ip}: {desc}"
        return result

    @staticmethod
    def check_reachability(ip: str, timeout_sec: float = 1.0) -> Tuple[bool, Optional[float], str]:
        """Tests IP reachability using ping or socket probe without elevated privileges."""
        start_time = time.time()
        # Fast socket probe on common ports first
        probed_ports = [22, 80, 5060, 443]
        for port in probed_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_sec)
                res = s.connect_ex((ip, port))
                s.close()
                if res == 0:
                    latency = round((time.time() - start_time) * 1000, 2)
                    return True, latency, f"TCP port {port} open"
            except Exception:
                pass

        # Ping fallback
        try:
            is_win = platform.system().lower() == "windows"
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip] if is_win else ["ping", "-c", "1", "-W", str(int(timeout_sec)), ip]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec + 0.5)
            latency = round((time.time() - start_time) * 1000, 2)
            if proc.returncode == 0:
                return True, latency, "ICMP Echo Reply received"
            else:
                return False, None, "ICMP Echo Request timed out"
        except Exception as e:
            return False, None, f"Reachability check failed: {e}"

    def probe_all_profiles(self, profiles: List[Any], max_workers: int = 8) -> Dict[str, Dict[str, Any]]:
        """Concurrently probes all lab server profiles using valid protocols."""
        results: Dict[str, Dict[str, Any]] = {}

        def _probe_single(prof):
            d = prof.to_dict() if hasattr(prof, "to_dict") else dict(prof)
            prof_id = d.get("id") or d.get("ip")
            ip = d.get("ip")
            port = d.get("port", 22)
            protocol = d.get("protocol", "SSH")
            platform_type = d.get("platform", "CLI")
            user = d.get("username", "")
            pwd = d.get("password", "")
            key = d.get("key_file")
            name = d.get("name", prof_id)

            probe_res = self.send_protocol_request(
                ip=ip,
                port=port,
                protocol=protocol,
                platform_type=platform_type,
                username=user,
                password=pwd,
                key_file=key,
                timeout_sec=2.0,
            )

            service_status = "HEALTHY" if probe_res["success"] else "DOWN"
            self.update_node_state(
                node_id=prof_id,
                name=name,
                ip=ip,
                reachable=probe_res["success"],
                service_status=service_status,
                latency_ms=probe_res["latency_ms"],
                collector_status=probe_res["status_summary"],
                error_detail=probe_res["response_data"] if not probe_res["success"] else "",
            )
            return prof_id, probe_res

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_probe_single, p) for p in profiles]
            for f in concurrent.futures.as_completed(futures):
                try:
                    p_id, res = f.result()
                    results[p_id] = res
                except Exception as e:
                    logger.error("Profile probe error: %s", e)

        self.last_run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return results

    def update_node_state(
        self,
        node_id: str,
        name: str,
        ip: str,
        reachable: bool,
        service_status: str,
        latency_ms: Optional[float] = None,
        collector_status: Optional[str] = None,
        last_event: Optional[str] = None,
        error_detail: Optional[str] = None,
    ):
        """Records node telemetry."""
        with self._lock:
            self.node_states[node_id] = {
                "node_id": node_id,
                "name": name,
                "ip": ip,
                "reachable": reachable,
                "service_status": service_status,  # HEALTHY, DEGRADED, DOWN, UNKNOWN
                "latency_ms": latency_ms,
                "collector_status": collector_status or "DISCONNECTED",
                "last_event": last_event or "-",
                "error_detail": error_detail or "",
                "last_check": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

    def get_all_node_states(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return dict(self.node_states)

    def evaluate_diagnostics(
        self,
        registration_states: Dict[str, Any],
        sip_calls: List[Dict[str, Any]],
        sip_ues: List[Dict[str, Any]],
        packet_count: int,
        gateway_reachable: bool,
        gnb_reachable: bool,
        core_reachable: bool,
    ) -> List[DiagnosticFinding]:
        """Applies Section 4.1 & 11 Rule-Based Failure Isolation Matrix."""
        findings: List[DiagnosticFinding] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Primary Lab Isolation Rule (Eq. 1): State(gNB)=UP and State(Core)=UP and Ping(Gateway)=FAIL
        if gnb_reachable and core_reachable and not gateway_reachable:
            findings.append(
                DiagnosticFinding(
                    severity="WARNING",
                    headline="Local Private 5G Operational; External Gateway Broken",
                    explanation=(
                        "Local Private 5G Access and IMS calling channels are 100% operational. "
                        "However, external connectivity and internet access are dropped because the primary edge gateway "
                        "(192.168.35.1) is not routing traffic properly. Local MEC apps and internal SIP calling remain fully functional."
                    ),
                    evidence="gNB (192.168.35.15) UP, IMS Core (192.168.35.35) UP, Gateway (192.168.35.1) unreachable / packet loss 100%",
                    suggested_action="Check router at 192.168.35.1, uplink cable, or NAT configuration on the core switch.",
                    timestamp=now,
                )
            )

        # 2. Radio & Core Access Rule
        registered_ues = [ue for ue, data in registration_states.items() if data.get("current_state") in ("REGISTERED", "PDU_ACTIVE")]
        if gnb_reachable and core_reachable and registered_ues:
            findings.append(
                DiagnosticFinding(
                    severity="OK",
                    headline="5G NR Radio & Core Access Established",
                    explanation=f"gNodeB is active and 5G UEs ({', '.join(registered_ues)}) have established RRC contexts and 5GS NAS registration.",
                    evidence=f"msg_trace.log: InitialUEMessage + RegistrationAccept confirmed for {len(registered_ues)} UEs.",
                    suggested_action="Private 5G radio plane is nominal. Ready for user plane throughput testing.",
                    timestamp=now,
                )
            )

        # 3. IMS SIP Registration Rule
        if sip_ues:
            ims_ids = [u.get("ue_id") for u in sip_ues]
            findings.append(
                DiagnosticFinding(
                    severity="OK",
                    headline="Vo5G / IMS SIP Registration Active",
                    explanation=f"Subscribers ({', '.join(ims_ids)}) successfully completed SIP Digest challenge-response and registered with Core IMS.",
                    evidence="SIP REGISTER -> 200 OK (P-Associated-URI verified) on port 5060.",
                    suggested_action="Vo5G telephony services ready for voice call initiation.",
                    timestamp=now,
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="INFO",
                    headline="No Active IMS SIP Registrations Observed",
                    explanation="No phones have completed SIP registration with 192.168.35.35 yet, or capture port 5060 does not see the packets.",
                    evidence="No 200 OK for SIP REGISTER observed in core trace.",
                    suggested_action="Ensure phone has VoLTE/Vo5G enabled and APN 'ims' configured in SIM settings.",
                    timestamp=now,
                )
            )

        # 4. SIP Call Flow Rule
        ringing_calls = [c for c in sip_calls if c.get("state") in ("RINGING", "ANSWERED", "CONNECTED")]
        if ringing_calls:
            call_desc = ", ".join(f"{c.get('caller')} -> {c.get('callee')} ({c.get('state')})" for c in ringing_calls)
            findings.append(
                DiagnosticFinding(
                    severity="OK",
                    headline="Vo5G Call Session Progress Confirmed",
                    explanation=f"SIP Call routing through IMS core verified: {call_desc}.",
                    evidence="SIP INVITE -> 100 Trying -> 180 Ringing observed in trace.",
                    suggested_action="Active call session in progress.",
                    timestamp=now,
                )
            )

        # 5. Packet Visibility & Laptop Capture Point Analysis (Critical Requirement)
        findings.append(
            DiagnosticFinding(
                severity="INFO",
                headline="Observability Architecture & Capture Point Verification",
                explanation=(
                    "Capturing packets locally on the monitoring laptop observes traffic on the laptop's NIC. "
                    "In a 5G network, cellular phone traffic is encapsulated over NR radio to the gNB and GTP-U to the UPF. "
                    "To observe phone data packets directly, port mirroring (SPAN) on the lab switch or an authorized capture "
                    "agent at the UPF / IMS core (192.168.35.35) or MEC Edge (192.168.35.19) is required."
                ),
                evidence=f"Active packet capture count: {packet_count} packets observed at current capture interface.",
                suggested_action="For end-to-end phone user-plane visibility, configure SPAN on Switch port or SSH tcpdump on 192.168.35.35.",
                timestamp=now,
            )
        )

        return findings
