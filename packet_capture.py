"""Packet capture module for 5G Lab Doctor.

Provides passive packet monitoring using Scapy with robust fallbacks,
thread-safe queues, protocol statistics, and strict security guardrails
(no payload storage, non-elevated dashboard operation, graceful permission handling).
"""

import logging
import queue
import threading
import time
from collections import Counter, deque
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("5g_lab_doctor.packet_capture")

# Scapy import with graceful fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, conf, get_if_list, sniff
    # Optional SCTP support if scapy has it
    try:
        from scapy.layers.sctp import SCTP
    except Exception:
        SCTP = None
    SCAPY_AVAILABLE = True
except Exception as e:
    logger.warning("Scapy is not fully available or Npcap/libpcap missing: %s", e)
    IP = TCP = UDP = ICMP = conf = get_if_list = sniff = SCTP = None


class PacketInfo:
    """Structured representation of an observed packet metadata (no payload)."""

    def __init__(
        self,
        timestamp: str,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        length: int,
        tcp_flags: str = "",
        summary: str = "",
        is_demo: bool = False,
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.tcp_flags = tcp_flags
        self.summary = summary
        self.is_demo = is_demo

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "tcp_flags": self.tcp_flags,
            "summary": self.summary,
            "is_demo": self.is_demo,
        }


class PacketCaptureManager:
    """Manages passive packet capture on authorized network interfaces."""

    def __init__(self, max_buffer_size: int = 500, on_packet_callback: Optional[Callable[[PacketInfo], None]] = None):
        self.max_buffer_size = max_buffer_size
        self.on_packet_callback = on_packet_callback
        self.packet_buffer: deque[PacketInfo] = deque(maxlen=max_buffer_size)
        self.protocol_counts: Counter[str] = Counter()
        self.total_packets_captured = 0

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.status = "IDLE"  # IDLE, CAPTURING, STOPPED, ERROR
        self.last_error: Optional[str] = None
        self.current_interface: Optional[str] = None
        self.current_filter: Optional[str] = None

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, str]]:
        """Returns list of network interfaces available on the system."""
        interfaces: List[Dict[str, Any]] = []
        if SCAPY_AVAILABLE:
            try:
                # Scapy interface list
                if hasattr(conf, "ifaces"):
                    for iface_key, iface_data in conf.ifaces.items():
                        raw_name = str(getattr(iface_data, "name", iface_key))
                        desc = str(getattr(iface_data, "description", ""))
                        ip = str(getattr(iface_data, "ip", ""))

                        # Filter out internal WAN miniports that cannot sniff actual user traffic
                        if "WAN Miniport" in desc:
                            continue

                        # Clean friendly label
                        is_loopback = "loopback" in raw_name.lower() or "loopback" in desc.lower() or ip == "127.0.0.1"
                        has_real_ip = bool(ip and not ip.startswith("169.254.") and not is_loopback)

                        if has_real_ip:
                            label = f"[ACTIVE] {raw_name} - {desc} ({ip})"
                        elif is_loopback:
                            label = f"[LOOPBACK] {raw_name} ({ip or '127.0.0.1'})"
                        elif ip:
                            label = f"{raw_name} - {desc} ({ip})"
                        else:
                            label = f"{raw_name} - {desc}" if desc else raw_name

                        interfaces.append({
                            "name": str(iface_key),
                            "label": label,
                            "ip": str(ip),
                            "is_real_active": has_real_ip,
                            "is_loopback": is_loopback,
                        })

                    # Sort: active non-loopback first, then loopback, then inactive
                    interfaces.sort(key=lambda x: (not x.get("is_real_active", False), not x.get("is_loopback", False), x["label"]))
                else:
                    raw_list = get_if_list() or []
                    for name in raw_list:
                        interfaces.append({"name": str(name), "label": str(name), "ip": ""})
            except Exception as e:
                logger.error("Failed to list scapy interfaces: %s", e)

        if not interfaces:
            # Fallback placeholder to allow graceful UI interaction
            interfaces.append({"name": "any", "label": "Default / Any Interface", "ip": ""})
            interfaces.append({"name": "eth0", "label": "eth0 (Lab Linux Default)", "ip": "192.168.35.x"})
            interfaces.append({"name": "lo", "label": "Loopback (lo / 127.0.0.1)", "ip": "127.0.0.1"})

        return interfaces

    def start_capture(self, interface: Optional[str] = None, filter_str: Optional[str] = None) -> Tuple[bool, str]:
        """Starts asynchronous packet capture in a background daemon thread."""
        with self._lock:
            if self.status == "CAPTURING":
                return False, "Capture is already active."

            if not SCAPY_AVAILABLE:
                self.status = "ERROR"
                msg = (
                    "Scapy capture driver not available. On Windows, install Npcap with WinPcap API-compatible mode. "
                    "On Linux, ensure libpcap is installed."
                )
                self.last_error = msg
                return False, msg

            self._stop_event.clear()
            self.current_interface = interface
            self.current_filter = filter_str or ""
            self.last_error = None

            self._thread = threading.Thread(
                target=self._capture_worker,
                args=(interface, self.current_filter),
                daemon=True,
                name="PacketCaptureThread",
            )
            self.status = "CAPTURING"
            self._thread.start()
            return True, f"Capture started on {interface or 'default'}."

    def stop_capture(self) -> Tuple[bool, str]:
        """Signals background packet capture thread to stop."""
        with self._lock:
            if self.status != "CAPTURING":
                return False, "Capture is not running."

            self._stop_event.set()
            self.status = "STOPPED"
            return True, "Capture stopping requested."

    def add_packet(self, pkt_info: PacketInfo):
        """Thread-safely adds a packet to the buffer and updates statistics."""
        with self._lock:
            self.packet_buffer.appendleft(pkt_info)
            self.protocol_counts[pkt_info.protocol] += 1
            self.total_packets_captured += 1

        if self.on_packet_callback:
            try:
                self.on_packet_callback(pkt_info)
            except Exception as cb_err:
                logger.error("Packet callback error: %s", cb_err)

    def get_recent_packets(self, limit: int = 100, protocol_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns recent packets matching optional protocol filter."""
        with self._lock:
            packets = list(self.packet_buffer)

        if protocol_filter and protocol_filter.upper() != "ALL":
            p_upper = protocol_filter.upper()
            packets = [p for p in packets if p.protocol == p_upper]

        return [p.to_dict() for p in packets[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        """Returns capture statistics."""
        with self._lock:
            return {
                "status": self.status,
                "total_captured": self.total_packets_captured,
                "protocol_distribution": dict(self.protocol_counts),
                "interface": self.current_interface or "default",
                "filter": self.current_filter or "(none)",
                "last_error": self.last_error,
            }

    def clear(self):
        """Clears packet buffer and statistics."""
        with self._lock:
            self.packet_buffer.clear()
            self.protocol_counts.clear()
            self.total_packets_captured = 0

    def _capture_worker(self, iface: Optional[str], filter_str: str):
        """Worker executing scapy sniff with exception isolation."""
        try:
            kwargs: Dict[str, Any] = {
                "prn": self._process_scapy_packet,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }
            if iface and iface not in ("any", "Default / Any Interface"):
                kwargs["iface"] = iface
            if filter_str and filter_str.strip():
                kwargs["filter"] = filter_str.strip()

            # On Windows without Npcap/WinPcap, conf.use_pcap is False; attempt L3 socket if Admin
            if hasattr(conf, "use_pcap") and not conf.use_pcap:
                if hasattr(conf, "L3socket"):
                    try:
                        l3_sock = conf.L3socket()
                        kwargs["opened_socket"] = l3_sock
                    except Exception as l3_err:
                        raise RuntimeError(
                            "Npcap driver is not installed on Windows. Live packet capture on Windows requires Npcap. "
                            "Please download and install Npcap from https://npcap.com (select 'Install Npcap in WinPcap API-compatible Mode'), "
                            "or run PowerShell as Administrator."
                        ) from l3_err

            sniff(**kwargs)
            with self._lock:
                if self.status == "CAPTURING":
                    self.status = "STOPPED"

        except PermissionError as perm_err:
            with self._lock:
                self.status = "ERROR"
                self.last_error = (
                    f"Permission Denied: Raw packet capture requires elevated privileges (CAP_NET_RAW / sudo on Linux, "
                    f"Administrator / Npcap service on Windows). Detail: {perm_err}"
                )
            logger.error("Capture permission error: %s", self.last_error)
        except OSError as os_err:
            with self._lock:
                self.status = "ERROR"
                self.last_error = f"Socket/Interface error: {os_err}"
            logger.error("Capture OS error: %s", self.last_error)
        except Exception as e:
            err_str = str(e)
            with self._lock:
                self.status = "ERROR"
                if "winpcap is not installed" in err_str.lower() or "npcap" in err_str.lower() or "layer 2" in err_str.lower():
                    self.last_error = (
                        "Npcap Driver Missing: Windows requires the Npcap packet capture driver to capture live network interface traffic. "
                        "Please download and install Npcap from https://npcap.com (make sure to check 'Install Npcap in WinPcap API-compatible Mode' during installation), "
                        "or run PowerShell as Administrator."
                    )
                else:
                    self.last_error = f"Capture failure: {e}"
            logger.error("Capture worker error: %s", self.last_error)

    def _process_scapy_packet(self, packet: Any):
        """Extracts header metadata while intentionally ignoring raw payloads."""
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            pkt_len = len(packet)
            now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            protocol = "OTHER"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags = ""
            summary = ""

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                # Parse TCP flags
                flags = []
                f_val = str(tcp_layer.flags)
                if "S" in f_val:
                    flags.append("SYN")
                if "A" in f_val:
                    flags.append("ACK")
                if "F" in f_val:
                    flags.append("FIN")
                if "R" in f_val:
                    flags.append("RST")
                if "P" in f_val:
                    flags.append("PSH")
                if "U" in f_val:
                    flags.append("URG")
                tcp_flags = "/".join(flags) if flags else f_val
                summary = f"TCP {src_port} -> {dst_port} [{tcp_flags}] Seq={tcp_layer.seq} Ack={tcp_layer.ack} Len={pkt_len}"

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                if src_port == 5060 or dst_port == 5060:
                    protocol = "SIP/UDP"
                    summary = f"SIP Signalling {src_port} -> {dst_port} Len={pkt_len}"
                elif src_port == 2152 or dst_port == 2152:
                    protocol = "GTP-U"
                    summary = f"5G User Plane GTP-U Tunnel {src_port} -> {dst_port} Len={pkt_len}"
                elif src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                    summary = f"DNS Query/Response {src_port} -> {dst_port} Len={pkt_len}"
                else:
                    summary = f"UDP {src_port} -> {dst_port} Len={pkt_len}"

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                protocol = "ICMP"
                icmp_type = getattr(icmp_layer, "type", 0)
                type_desc = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type {icmp_type}"
                summary = f"ICMP {type_desc} id={getattr(icmp_layer, 'id', 0)} seq={getattr(icmp_layer, 'seq', 0)}"

            elif SCTP and packet.haslayer(SCTP):
                sctp_layer = packet[SCTP]
                protocol = "SCTP/NGAP"
                src_port = int(sctp_layer.sport)
                dst_port = int(sctp_layer.dport)
                summary = f"SCTP 5G-NGAP {src_port} -> {dst_port} Len={pkt_len}"

            else:
                protocol = f"IP-proto-{proto_num}"
                summary = f"IP Protocol {proto_num} Len={pkt_len}"

            info = PacketInfo(
                timestamp=now_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=pkt_len,
                tcp_flags=tcp_flags,
                summary=summary,
                is_demo=False,
            )
            self.add_packet(info)

        except Exception as proc_err:
            logger.debug("Error processing scapy packet: %s", proc_err)
