"""Configuration module for 5G Lab Doctor & Remote Linux Operations Platform.

Loads settings from environment variables and provides sensible defaults
for all lab infrastructure devices (Core 5G, gNB, NMS, MEC nodes, VM hosts,
gateways, cameras, iDRAC servers) without hardcoding credentials or IPs.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Attempt to load .env if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class ServerProfile:
    id: str
    name: str
    ip: str
    port: int = 22
    protocol: str = "SSH"  # SSH, HTTP, HTTPS, SIP, TCP, ICMP
    platform: str = "CLI"  # CLI, GUI, GUI/CLI
    role: str = ""
    username: str = ""
    password: str = ""
    secondary_username: str = ""
    secondary_password: str = ""
    key_file: Optional[str] = None
    timeout: int = 3
    default_log_path: Optional[str] = None
    expected_ports: List[int] = field(default_factory=list)
    quick_commands: List[str] = field(default_factory=list)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "platform": self.platform,
            "role": self.role,
            "username": self.username,
            "password": self.password,
            "secondary_username": self.secondary_username,
            "secondary_password": self.secondary_password,
            "key_file": self.key_file,
            "timeout": self.timeout,
            "default_log_path": self.default_log_path,
            "expected_ports": self.expected_ports,
            "quick_commands": self.quick_commands,
            "is_active": 1 if self.is_active else 0,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerProfile":
        expected_ports = data.get("expected_ports", [])
        if isinstance(expected_ports, str):
            import json
            try:
                expected_ports = json.loads(expected_ports)
            except Exception:
                expected_ports = []

        quick_commands = data.get("quick_commands", [])
        if isinstance(quick_commands, str):
            import json
            try:
                quick_commands = json.loads(quick_commands)
            except Exception:
                quick_commands = []

        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            ip=str(data.get("ip", "")),
            port=int(data.get("port", 22)),
            protocol=str(data.get("protocol", "SSH")),
            platform=str(data.get("platform", "CLI")),
            role=str(data.get("role", "")),
            username=str(data.get("username", "") or ""),
            password=str(data.get("password", "") or ""),
            secondary_username=str(data.get("secondary_username", "") or ""),
            secondary_password=str(data.get("secondary_password", "") or ""),
            key_file=data.get("key_file"),
            timeout=int(data.get("timeout", 3)),
            default_log_path=data.get("default_log_path"),
            expected_ports=list(expected_ports),
            quick_commands=list(quick_commands),
            is_active=bool(data.get("is_active", True)),
        )


@dataclass
class LabNode:
    name: str
    ip: str
    role: str
    default_log_path: Optional[str] = None
    expected_ports: List[int] = field(default_factory=list)


@dataclass
class Config:
    # Application & Display
    demo_mode: bool = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    refresh_interval: int = int(os.getenv("DASHBOARD_REFRESH_INTERVAL", "2"))
    database_path: str = os.getenv("DATABASE_PATH", "lab_state.db")
    event_retention_days: int = int(os.getenv("EVENT_RETENTION_DAYS", "7"))

    # Packet Capture
    capture_interface: Optional[str] = os.getenv("CAPTURE_INTERFACE", None) or None
    capture_filter: str = os.getenv("CAPTURE_FILTER", "ip or icmp or udp or tcp")
    promiscuous_mode: bool = os.getenv("PROMISCUOUS_MODE", "false").lower() in ("true", "1", "yes")
    save_payloads: bool = os.getenv("SAVE_PAYLOADS", "false").lower() in ("true", "1", "yes")
    max_packets_in_memory: int = int(os.getenv("MAX_PACKETS_IN_MEMORY", "500"))

    # Core Infrastructure IPs (Configurable from environment variables)
    core_5g_ip: str = os.getenv("CORE_5G_IP", "192.168.35.10")
    core_5g_user: str = os.getenv("CORE_5G_USER", "support")
    core_5g_pass: str = os.getenv("CORE_5G_PASS", "Support@817&&")
    core_5g_user2: str = os.getenv("CORE_5G_USER2", "su")
    core_5g_pass2: str = os.getenv("CORE_5G_PASS2", "TW0ULdCxH$6c;s")

    gnb_ip: str = os.getenv("GNB_IP", "192.168.35.15")
    gnb_user: str = os.getenv("GNB_USER", "resonous")
    gnb_pass: str = os.getenv("GNB_PASS", "resonous")

    nms_ip: str = os.getenv("NMS_IP", "192.168.35.6")
    nms_user: str = os.getenv("NMS_USER", "admin")
    nms_pass: str = os.getenv("NMS_PASS", "admin123")

    ims_ip: str = os.getenv("IMS_IP", "192.168.35.35")
    mec_edge_ip: str = os.getenv("MEC_EDGE_IP", "192.168.35.19")
    mec_edge_user: str = os.getenv("MEC_EDGE_USER", "support")
    mec_edge_pass: str = os.getenv("MEC_EDGE_PASS", "Support@817&&")

    mec_cloud_ip: str = os.getenv("MEC_CLOUD_IP", "192.168.35.5")
    mec_cloud_user: str = os.getenv("MEC_CLOUD_USER", "support")
    mec_cloud_pass: str = os.getenv("MEC_CLOUD_PASS", "Support@817&&")

    gateway_ip: str = os.getenv("GATEWAY_IP", "192.168.35.1")
    gateway_user: str = os.getenv("GATEWAY_USER", "root")
    gateway_pass: str = os.getenv("GATEWAY_PASS", "admin@321")

    switch_ip: str = os.getenv("SWITCH_IP", "192.168.35.2")
    switch_user: str = os.getenv("SWITCH_USER", "admin")
    switch_pass: str = os.getenv("SWITCH_PASS", "admin")

    vm_host_1_ip: str = os.getenv("VM_HOST_1_IP", "192.168.35.50")
    vm_host_1_user: str = os.getenv("VM_HOST_1_USER", "support")
    vm_host_1_pass: str = os.getenv("VM_HOST_1_PASS", "Support@817&&")

    vm_host_2_ip: str = os.getenv("VM_HOST_2_IP", "192.168.35.51")
    vm_host_2_user: str = os.getenv("VM_HOST_2_USER", "support")
    vm_host_2_pass: str = os.getenv("VM_HOST_2_PASS", "Support@817&&")

    iot_gateway_ip: str = os.getenv("IOT_GATEWAY_IP", "192.168.11.1")
    iot_gateway_user: str = os.getenv("IOT_GATEWAY_USER", "root")
    iot_gateway_pass: str = os.getenv("IOT_GATEWAY_PASS", "ecsd-edge@3682")

    gyan_ip: str = os.getenv("GYAN_IP", "192.168.11.35")
    gyan_user: str = os.getenv("GYAN_USER", "gyan")
    gyan_pass: str = os.getenv("GYAN_PASS", "CgYaN@817&&")

    cpe_ip: str = os.getenv("CPE_IP", "51.0.0.1")
    cpe_user: str = os.getenv("CPE_USER", "root")
    cpe_pass: str = os.getenv("CPE_PASS", "root")

    camera_ip: str = os.getenv("CAMERA_IP", "192.168.128.1")
    camera_user: str = os.getenv("CAMERA_USER", "admin")
    camera_pass: str = os.getenv("CAMERA_PASS", "admin123")

    idrac_1_ip: str = os.getenv("IDRAC_1_IP", "192.168.60.50")
    idrac_1_user: str = os.getenv("IDRAC_1_USER", "root")
    idrac_1_pass: str = os.getenv("IDRAC_1_PASS", "X4YW9N9FY94H")

    idrac_2_ip: str = os.getenv("IDRAC_2_IP", "192.168.60.51")
    idrac_2_user: str = os.getenv("IDRAC_2_USER", "root")
    idrac_2_pass: str = os.getenv("IDRAC_2_PASS", "NMX3XVXHP93V")

    # Global SSH Fallback Settings
    ssh_timeout: int = int(os.getenv("SSH_CONNECT_TIMEOUT", "3"))
    ssh_username: str = os.getenv("SSH_USERNAME", "")
    ssh_password: str = os.getenv("SSH_PASSWORD", "")
    ssh_key_file: Optional[str] = os.getenv("SSH_KEY_FILE", None) or None

    # Remote Log Paths
    gnb_log_path: str = os.getenv("GNB_LOG_PATH", "/home/tetra/euGNB/logs/msg_trace.log")
    gnb_event_history_path: str = os.getenv("GNB_EVENT_HISTORY_PATH", "/home/tetra/euGNB/logs/eventHistory.log")
    gnb_alarm_log_path: str = os.getenv("GNB_ALARM_LOG_PATH", "/home/tetra/euGNB/logs/AlarmLog.csv")
    ims_sip_trace_path: str = os.getenv("IMS_SIP_TRACE_PATH", "/tmp/sip_trace.log")
    nms_telemetry_path: str = os.getenv("NMS_TELEMETRY_LOG_PATH", "/var/log/coralswitch/softswitch/telemetry/app.log")
    nms_service_path: str = os.getenv("NMS_SERVICE_LOG_PATH", "/var/log/coralswitch/softswitch/service-v2/app.log")

    # SIP Monitor
    sip_port: int = int(os.getenv("SIP_PORT", "5060"))

    def get_lab_nodes(self) -> Dict[str, LabNode]:
        """Returns the dictionary of configured lab nodes for backward compatibility."""
        return {
            "core_5g": LabNode(name="Core 5G", ip=self.core_5g_ip, role="5G Core (AMF/SMF/UPF)", expected_ports=[22, 38412, 80]),
            "gateway": LabNode(name="Gateway / Firewall", ip=self.gateway_ip, role="L3 Default Gateway / Firewall", expected_ports=[53, 80, 443]),
            "switch": LabNode(name="Switch", ip=self.switch_ip, role="L2/Management Switch", expected_ports=[22, 80, 161]),
            "nms": LabNode(name="NMS Server", ip=self.nms_ip, role="Network Management & Telemetry", default_log_path=self.nms_telemetry_path, expected_ports=[22, 80, 8080]),
            "gnb": LabNode(name="gNB Radio", ip=self.gnb_ip, role="5G NR gNodeB (euGNB)", default_log_path=self.gnb_log_path, expected_ports=[22, 38412]),
            "ims": LabNode(name="Core IMS / cnpn", ip=self.ims_ip, role="IMS Core / SIP Registrar", default_log_path=self.ims_sip_trace_path, expected_ports=[22, self.sip_port]),
            "mec_edge": LabNode(name="MEC Edge", ip=self.mec_edge_ip, role="Local Multi-access Edge Computing", expected_ports=[22, 8000]),
            "mec_cloud": LabNode(name="MEC Cloud", ip=self.mec_cloud_ip, role="Centralized Cloud Node", expected_ports=[22, 8000]),
            "vm_host_1": LabNode(name="VM Host 1", ip=self.vm_host_1_ip, role="KVM Virtualization Host", expected_ports=[22]),
            "vm_host_2": LabNode(name="VM Host 2", ip=self.vm_host_2_ip, role="KVM Virtualization Host", expected_ports=[22]),
        }

    def get_default_server_profiles(self) -> List[ServerProfile]:
        """Generates server profiles loaded from environment settings matching 5G lab inventory."""
        return [
            ServerProfile(
                id="core_5g",
                name="Core 5G",
                ip=self.core_5g_ip,
                port=22,
                protocol="SSH",
                platform="CLI",
                role="5G Core Network (AMF/SMF/UPF)",
                username=self.core_5g_user,
                password=self.core_5g_pass,
                secondary_username=self.core_5g_user2,
                secondary_password=self.core_5g_pass2,
                expected_ports=[22, 38412],
                quick_commands=["uptime", "free -m", "df -h", "ip a", "ss -tulpn | grep -E '38412|80|22'"],
            ),
            ServerProfile(
                id="gnb_radio",
                name="gNB(Radio)",
                ip=self.gnb_ip,
                port=22,
                protocol="SSH",
                platform="CLI",
                role="5G NR gNodeB (euGNB)",
                username=self.gnb_user,
                password=self.gnb_pass,
                secondary_username="root",
                secondary_password="root",
                default_log_path=self.gnb_log_path,
                expected_ports=[22, 38412],
                quick_commands=[
                    "tail -n 25 /home/tetra/euGNB/logs/msg_trace.log",
                    "tail -n 25 /home/tetra/euGNB/logs/eventHistory.log",
                    "cat /home/tetra/euGNB/logs/AlarmLog.csv | tail -n 10",
                    "uptime",
                ],
            ),
            ServerProfile(
                id="ims_core",
                name="Core IMS / cnpn",
                ip=self.ims_ip,
                port=5060,
                protocol="SIP",
                platform="CLI",
                role="IMS Core / SIP Registrar / Vo5G",
                username=self.core_5g_user,
                password=self.core_5g_pass,
                default_log_path=self.ims_sip_trace_path,
                expected_ports=[22, 5060],
                quick_commands=["netstat -ulpn | grep 5060", "uptime", "free -m"],
            ),
            ServerProfile(
                id="nms_server",
                name="NMS Server",
                ip=self.nms_ip,
                port=80,
                protocol="HTTP",
                platform="GUI",
                role="Network Management System (NMS)",
                username=self.nms_user,
                password=self.nms_pass,
                secondary_username="student1",
                secondary_password="12345",
                default_log_path=self.nms_telemetry_path,
                expected_ports=[22, 80, 8080],
                quick_commands=["tail -n 25 /var/log/coralswitch/softswitch/telemetry/app.log", "uptime"],
            ),
            ServerProfile(
                id="mec_cloud",
                name="MEC-Cloud-Core",
                ip=self.mec_cloud_ip,
                port=22,
                protocol="SSH",
                platform="GUI/CLI",
                role="Centralized Cloud Core Node",
                username=self.mec_cloud_user,
                password=self.mec_cloud_pass,
                expected_ports=[22, 80, 8000],
                quick_commands=["uptime", "free -m", "df -h", "docker ps 2>/dev/null || podman ps 2>/dev/null || true"],
            ),
            ServerProfile(
                id="mec_edge",
                name="MEC-Edge-Core",
                ip=self.mec_edge_ip,
                port=22,
                protocol="SSH",
                platform="GUI/CLI",
                role="Local Edge UPF & Edge Applications",
                username=self.mec_edge_user,
                password=self.mec_edge_pass,
                expected_ports=[22, 80, 8000, 2152],
                quick_commands=["uptime", "free -m", "ip route", "ip link"],
            ),
            ServerProfile(
                id="cosgrid_gateway",
                name="Cosgrid IoT Gateway",
                ip=self.iot_gateway_ip,
                port=22,
                protocol="SSH",
                platform="GUI/CLI",
                role="IoT Gateway Node",
                username=self.iot_gateway_user,
                password=self.iot_gateway_pass,
                expected_ports=[22, 80],
                quick_commands=["uptime", "ip addr", "df -h"],
            ),
            ServerProfile(
                id="gyan",
                name="Gyan",
                ip=self.gyan_ip,
                port=22,
                protocol="SSH",
                platform="CLI",
                role="High Performance Processing Node",
                username=self.gyan_user,
                password=self.gyan_pass,
                expected_ports=[22],
                quick_commands=["uptime", "uname -a", "free -m"],
            ),
            ServerProfile(
                id="cpe",
                name="CPE (5G UE Router)",
                ip=self.cpe_ip,
                port=80,
                protocol="HTTP",
                platform="GUI",
                role="5G Customer Premises Equipment (UE)",
                username=self.cpe_user,
                password=self.cpe_pass,
                secondary_username="user",
                secondary_password="root",
                expected_ports=[80, 443],
                quick_commands=[],
            ),
            ServerProfile(
                id="sparsh_camera",
                name="Sparsh Camera",
                ip=self.camera_ip,
                port=80,
                protocol="HTTP",
                platform="GUI",
                role="5G Surveillance Camera Endpoint",
                username=self.camera_user,
                password=self.camera_pass,
                expected_ports=[80, 554],
                quick_commands=[],
            ),
            ServerProfile(
                id="idrac_1",
                name="Idrac Server 1",
                ip=self.idrac_1_ip,
                port=443,
                protocol="HTTPS",
                platform="GUI",
                role="Dell iDRAC Out-of-Band Controller 1",
                username=self.idrac_1_user,
                password=self.idrac_1_pass,
                expected_ports=[443, 80],
                quick_commands=[],
            ),
            ServerProfile(
                id="idrac_2",
                name="Idrac Server 2",
                ip=self.idrac_2_ip,
                port=443,
                protocol="HTTPS",
                platform="GUI",
                role="Dell iDRAC Out-of-Band Controller 2",
                username=self.idrac_2_user,
                password=self.idrac_2_pass,
                expected_ports=[443, 80],
                quick_commands=[],
            ),
            ServerProfile(
                id="vm_host_1",
                name="Server 1 Host",
                ip=self.vm_host_1_ip,
                port=22,
                protocol="SSH",
                platform="GUI/CLI",
                role="KVM Hypervisor Host 1",
                username=self.vm_host_1_user,
                password=self.vm_host_1_pass,
                expected_ports=[22],
                quick_commands=["virsh list --all", "uptime", "free -m"],
            ),
            ServerProfile(
                id="vm_host_2",
                name="Server 2 Host",
                ip=self.vm_host_2_ip,
                port=22,
                protocol="SSH",
                platform="GUI/CLI",
                role="KVM Hypervisor Host 2",
                username=self.vm_host_2_user,
                password=self.vm_host_2_pass,
                expected_ports=[22],
                quick_commands=["virsh list --all", "uptime", "free -m"],
            ),
            ServerProfile(
                id="l2_switch",
                name="L2 Switch",
                ip=self.switch_ip,
                port=80,
                protocol="HTTP",
                platform="GUI",
                role="L2 / Management Switch (10.90.90.90)",
                username=self.switch_user,
                password=self.switch_pass,
                expected_ports=[22, 80, 161],
                quick_commands=[],
            ),
            ServerProfile(
                id="cosgrid_firewall",
                name="Cosgrid Firewall",
                ip=self.gateway_ip,
                port=80,
                protocol="HTTP",
                platform="GUI",
                role="Firewall & L3 Gateway (BMC 192.168.12.1)",
                username=self.gateway_user,
                password=self.gateway_pass,
                secondary_username="root",
                secondary_password="admin123",
                expected_ports=[53, 80, 443],
                quick_commands=[],
            ),
        ]


# Global singleton instance
cfg = Config()

