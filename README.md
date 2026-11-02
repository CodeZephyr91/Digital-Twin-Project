# 5G Lab Doctor: Live Digital Twin & Full-Stack Observability Dashboard for a Private 5G MEC Lab

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Protocol](https://img.shields.io/badge/3GPP-Release%2015%2F16%2F17-orange.svg)](https://www.3gpp.org/)
[![License](https://img.shields.io/badge/Access-Read--Only%20Observability-success.svg)](#safety-and-guardrails)

A real-time digital twin and observability platform engineered for private 5G Multi-access Edge Computing (MEC) laboratories. The system transforms scattered raw gNodeB logs, 3GPP RRC/NGAP signalling, RFC 3261 SIP/IMS traces, and distributed node telemetry into a unified browser-based NOC (Network Operations Center) dashboard with automated root-cause fault isolation.

---

## 1. System Architecture

The application adopts a decoupled pipeline architecture mapping distributed physical infrastructure to real-time client visuals:

```
+-----------------------------------------------------------------------------------+
|                              Data Sources & Lab Hosts                             |
|  - gNB Radio (192.168.35.15)         : /home/tetra/euGNB/logs/msg_trace.log       |
|  - IMS Core (192.168.35.35)          : tcpdump port 5060 (/tmp/sip_trace.log)     |
|  - NMS Server (192.168.35.6)         : telemetry/app.log                          |
|  - MEC Edge & Cloud (35.19 & 35.5)   : UPF / Local Services                       |
|  - Gateway (192.168.35.1)            : ICMP Path Probe                            |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        Collector Layer (Strictly Read-Only)                       |
|  - Paramiko SSH Client (Non-blocking tail streams, zero intrusive daemons)        |
|  - Scapy / Socket Sniffer (Passive packet header monitoring, no payload storage)  |
|  - ICMP / TCP Socket Probes (Non-privileged path matrix reachability)             |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                       Parser & State Reconstruction Engine                        |
|  - 3GPP 11-Stage Registration Machine (RRC -> NAS -> Auth -> Security -> PDU)     |
|  - RFC 3261 SIP Dialog Engine (REGISTER, 401, 200 OK, INVITE, 180, ACK, BYE)     |
|  - Rule-Based Fault Isolation Matrix (Correlates multi-subsystem states)          |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                       Storage & Presentation (Fast & Local)                       |
|  - SQLite (lab_state.db): Events, Calls, Packets, Health status                   |
|  - Streamlit UI: Interactive Topology, Plotly Charts, Mermaid.js Call Ladders     |
+-----------------------------------------------------------------------------------+
```

---

## 2. Key Features

### Feature A: Live Packet Capture & Analysis
- **Passive Sniffing**: Uses Scapy with thread-safe queues and non-blocking workers.
- **Fields Observed**: Timestamp, Source IP, Destination IP, Source Port, Destination Port, Protocol (TCP, UDP, ICMP, SIP/UDP, GTP-U, SCTP/NGAP, DNS), Packet Length, TCP Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), and summary description.
- **Interactive Controls**: Dynamic interface selector, custom BPF filter input (e.g., `port 5060 or port 2152`), start/stop controls, and clear buffer.
- **Visual Analytics**: Interactive Plotly protocol distribution charts and packet size histograms.
- **Privacy & Security**: Raw payload inspection and persistence are disabled by default.

### Feature B: 11-Stage 5G UE Registration Timeline
Faithfully maps 3GPP Standalone (SA) registration procedures according to Release 15/16/17:
1. **UE Radio Synchronization** (MIB / SIB1 broadcast sync)
2. **Random Access Channel (RACH)** (MSG1 Preamble / MSG2 RAR)
3. **RRC Connection Establishment** (RRCSetupRequest / RRCSetup / RRCSetupComplete)
4. **NAS Registration Request** (InitialUEMessage_NG with 5GS Registration Request)
5. **UE Identity Procedures** (NAS Identity Request / Response, if required)
6. **Authentication** (5G-AKA / EAP-AKA' challenge & verification)
7. **NAS Security Establishment** (NAS Security Mode Command / Complete)
8. **UE Capability Exchange** (UECapabilityEnquiry / UECapabilityInformation)
9. **Registration Accept** (InitialContextSetupRequest + Registration Accept)
10. **Registration Complete** (RRCReconfigurationComplete / RegistrationComplete)
11. **PDU Session Establishment** (PDUSessionResourceSetup for `internet` and `ims` DNNs)

> **Observation Fidelity Guarantee**:
> Events are tagged with verified observation sources (`GNB_LOG`, `CORE_LOG`, `PACKET_CAPTURE`, or `INFERRED`). If an optional or unobservable stage has no evidence, it is displayed as **Not observed** rather than fabricated.

### Feature C: Read-Only Distributed Log Monitoring
- Ingests telemetry over Paramiko SSH from `192.168.35.15` (`msg_trace.log`, `eventHistory.log`, `AlarmLog.csv`), `192.168.35.35` (`sip_trace.log`), and `192.168.35.6` (`telemetry/app.log`).
- Incremental streaming using `tail -n 50 -f` to eliminate CPU/disk burden on the gNodeB.
- Seamless automatic failover to local sample traces in Demo Mode or when remote hosts are offline.

### Feature D: RFC 3261 SIP & IMS Calling Flow
- Decodes observable SIP transactions on port 5060.
- Tracks subscriber identities (`From`, `To`, `P-Associated-URI`, `Contact`).
- State machine tracks transitions: `IDLE` ➔ `INVITE_SENT` ➔ `TRYING` ➔ `RINGING` ➔ `CONNECTED` ➔ `ENDED`.
- Generates live Mermaid.js sequence ladder diagrams showing UE 901 ➔ IMS Core ➔ UE 902 handshakes.

### Feature E: MEC & Subnet Health with Fault Isolation Matrix
- Health matrix for all 8 lab nodes: Gateway (`.1`), Switch (`.2`), NMS (`.6`), gNB (`.15`), MEC Edge (`.19`), MEC Cloud (`.5`), Core IMS (`.35`), VM Hosts (`.50`, `.51`).
- Strictly separates reachability (ping/socket connect) from true service health.
- **Rule-Based Diagnosis**: Automatically isolates failures. For example:
  $$\text{State}(\text{gNB}) = \text{UP} \land \text{State}(\text{Core}) = \text{UP} \land \text{Ping}(\text{Gateway}) = \text{FAIL}$$
  Outputs in plain English: *"Local Private 5G Access and IMS calling channels are 100% operational. External connectivity is dropped because primary edge gateway (192.168.35.1) is not routing traffic properly."*

### Feature F: Demo Mode (Instant Simulation)
- Displays realistic synthetic registrations for UE 901 and UE 902, simulated SIP call progress, and sample packets.
- All simulated records are prominently stamped with `[DEMO / SYNTHETIC]` to avoid confusing simulation with real traffic.

---

## 3. Installation & Launch Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Windows 10/11 or Linux (Ubuntu 20.04/22.04/24.04, Debian, RHEL)

### Step 1: Clone Repository & Create Virtual Environment

**On Windows (PowerShell):**
```powershell
git clone <repo-url> "5g lab"
cd "5g lab"
python -m venv .venv
.\.venv\Scripts\activate
```

**On Linux / macOS (Bash):**
```bash
git clone <repo-url> 5g-lab
cd 5g-lab
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment (Optional)

Copy `.env.example` to `.env` to customize lab parameters:
```bash
cp .env.example .env       # Linux / macOS
copy .env.example .env     # Windows
```

Edit `.env` with non-secret defaults (e.g. `DEMO_MODE=false`, `GNB_IP=192.168.35.15`).

### Step 4: Launch Application

```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 4. Network Observability & Packet Capture Guide

### Why Phone Traffic May Not Appear on a Laptop Interface

A common point of confusion is running a packet sniffer on a laptop and expecting to see raw cellular phone packets:

```
[Phone: UE 901] 
       │ (Air Interface: 3GPP NR Band n78)
       ▼
[gNodeB: 192.168.35.15]
       │ (GTP-U Encapsulated Tunnel: UDP Port 2152)
       ▼
[Switch: 192.168.35.2] ──── (Point-to-point Ethernet) ────► [UPF / MEC: 192.168.35.19]
       │
   (Not routed to laptop unless mirrored!)
       │
[Laptop: 192.168.35.100]
```

1. **Air Interface Layering**: The phone communicates directly with the gNB radio head over licensed/private 3GPP NR air spectrum. This traffic is physically invisible to Wi-Fi/Ethernet cards.
2. **GTP-U Tunnel Encapsulation**: Once received by the gNB, user-plane data is wrapped in a GPRS Tunneling Protocol (GTP-U) wrapper and sent point-to-point to the User Plane Function (UPF) on `192.168.35.19`.
3. **Switch Forwarding**: Standard L2 switches forward unicast frames only between the ports involved (gNB ➔ UPF). A laptop on another port will never receive these frames by default.

### Authorized Lab Capture Points

To observe actual phone traffic:
1. **Switch SPAN / Port Mirroring**: Configure the lab switch to copy all traffic from the gNB port (or UPF port) to the laptop monitor port:
   ```text
   Switch(config)# monitor session 1 source interface gigabitEthernet 0/15
   Switch(config)# monitor session 1 destination interface gigabitEthernet 0/48
   ```
2. **Core / UPF Host Capture**: Run an authorized tcpdump collector on the IMS core or UPF:
   ```bash
   ssh support@192.168.35.35 "sudo tcpdump -i any -nn -s 0 port 5060 -w - | tee /tmp/sip_trace.log"
   ```

### Authorized Packet Capture Setup on Linux

Running raw socket packet capture without elevating the entire dashboard to `root`:

**Method A: Linux Capabilities (Recommended)**
Grant the Python executable capture capabilities without giving full `root` access:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

**Method B: Dedicated Wireshark/pcap Group**
```bash
sudo groupadd -f pcap
sudo usermod -aG pcap $USER
sudo chgrp pcap /usr/bin/dumpcap
sudo chmod 750 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

### Packet Capture Setup on Windows

On Windows, Scapy requires **Npcap**:
1. Download Npcap from [npcap.com](https://npcap.com/).
2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"** and **"Support raw 802.11 traffic"**.
3. If Npcap is absent, the dashboard detects it and operates in Demo/Log mode gracefully without crashing.

---

## 5. SSH Log Collection Configuration

The dashboard uses read-only Paramiko channels to observe remote lab logs:

### Generate Dedicated Read-Only Key
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_5glab_doctor -C "5g-lab-observability"
ssh-copy-id -i ~/.ssh/id_5glab_doctor.pub tetra@192.168.35.15
```

### Configure in `.env`
```ini
SSH_USERNAME=tetra
SSH_KEY_FILE=C:\Users\username\.ssh\id_5glab_doctor
SSH_CONNECT_TIMEOUT=3
```

---

## 6. Demonstration Checklist

Follow this script to demonstrate the platform in under 5 minutes:

| Step | Action | Expected Dashboard Output |
| :--- | :--- | :--- |
| **1** | Open `http://localhost:8501` | Overview page displays live digital twin topology, node status cards, and diagnostic alert. |
| **2** | Check Diagnostic Board | Highlights: *State(gNB)=UP & State(Core)=UP & Ping(Gateway)=FAIL* with suggested action. |
| **3** | Navigate to **3. 5G UE Registration** | Select **Phone 901**. See the 11-stage timeline with source tags (`GNB_LOG`, `INFERRED`, `Not observed`). |
| **4** | Toggle Airplane Mode on UE 901 | Observe RRCSetupRequest ➔ Authentication ➔ Registration Accept ➔ PDU Session allocated IP `10.46.0.8`. |
| **5** | Navigate to **4. SIP Call Flow** | View registered IMS phones (901 & 902). View Mermaid ladder diagram for call setup. |
| **6** | Dial 902 from 901 | Observe INVITE ➔ 100 Trying ➔ 180 Ringing in ladder and call session table. |
| **7** | Navigate to **2. Live Packets** | Select interface, click **Start Capture**, view live protocol distribution and packet table. |
| **8** | Toggle **Demo Mode** | Verify that simulation tags (`🟣 DEMO`) appear immediately without restarting the app. |

---

## 7. Demo Mode vs. Real Lab Verification Matrix

| Capability / Feature | Demo Mode (Simulated) | Real Lab (Hardware Verified) |
| :--- | :---: | :---: |
| **Digital Twin Topology Map** | Supported (Synthetic node state) | Supported (Real ping & socket checks) |
| **11-Stage 3GPP State Machine** | Supported (Pre-canned RRC sequence) | Supported (Parsed from `msg_trace.log`) |
| **No-Fabrication Telemetry Rule** | Verified (Stage 5 remains "Not observed") | Verified (Only observable steps marked) |
| **SIP Call-Flow Ladder Diagram** | Supported (901 ➔ 902 call progress) | Supported (Decoded from port 5060 tcpdump) |
| **Live Packet Table & Filters** | Supported (Synthetic tagged packets) | Supported (Live Scapy/Npcap/libpcap) |
| **Gateway Routing Fault Isolation** | Supported (Simulated Gateway timeout) | Supported (Probed against `192.168.35.1`) |
| **gNB Radio Log Streamer** | Local sample (`sample_data/`) | Remote SSH (`/home/tetra/euGNB/logs/`) |
| **SQLite Persistence & WAL Mode** | Supported (`lab_state.db`) | Supported (`lab_state.db`) |

---

## 8. Unit Testing

The test suite validates database transactions, packet queuing, strict 3GPP observation rules, RFC 3261 SIP parsing, the fault isolation matrix, dynamic server profiles, remote SSH execution, protocol request engine, command history, and AI assistant.

Run tests with:
```bash
pytest tests/ -v
```

### Verified Test Results
```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\windows\Desktop\5g lab
collected 31 items

tests/test_ai_assistant.py::test_explain_log_rrc_reject PASSED             [  3%]
tests/test_ai_assistant.py::test_explain_log_sip_unauthorized PASSED       [  6%]
tests/test_ai_assistant.py::test_generate_incident_report PASSED           [  9%]
tests/test_ai_assistant.py::test_suggest_commands_for_server PASSED        [ 12%]
tests/test_command_history.py::test_record_and_retrieve_command_history PASSED [ 16%]
tests/test_command_history.py::test_clear_command_history PASSED            [ 19%]
tests/test_database.py::test_record_and_get_events PASSED                 [ 22%]
tests/test_database.py::test_record_and_update_call PASSED                [ 25%]
tests/test_database.py::test_record_and_get_packets PASSED               [ 29%]
tests/test_database.py::test_node_health PASSED                          [ 32%]
tests/test_health_and_diagnosis.py::test_failure_isolation_rule_gateway_broken PASSED [ 35%]
tests/test_health_and_diagnosis.py::test_reachability_probe_localhost PASSED [ 38%]
tests/test_packet_capture.py::test_packet_info_model PASSED              [ 41%]
tests/test_packet_capture.py::test_capture_manager_buffer PASSED         [ 45%]
tests/test_packet_capture.py::test_get_available_interfaces PASSED       [ 48%]
tests/test_protocol_requests.py::test_send_protocol_request_localhost_tcp PASSED [ 51%]
tests/test_protocol_requests.py::test_send_protocol_request_http_mocked PASSED [ 54%]
tests/test_protocol_requests.py::test_send_protocol_request_ssh_mocked PASSED [ 58%]
tests/test_protocol_requests.py::test_concurrent_profile_probing PASSED  [ 61%]
tests/test_registration_parser.py::test_no_fabrication_rule PASSED       [ 64%]
tests/test_registration_parser.py::test_rrc_setup_flow PASSED            [ 67%]
tests/test_registration_parser.py::test_full_registration_lifecycle PASSED [ 70%]
tests/test_server_profiles.py::test_server_profile_dataclass PASSED       [ 74%]
tests/test_server_profiles.py::test_seed_and_query_profiles PASSED        [ 77%]
tests/test_server_profiles.py::test_custom_profile_crud PASSED             [ 80%]
tests/test_sip_monitor.py::test_parse_sip_register_and_200ok PASSED       [ 83%]
tests/test_sip_monitor.py::test_call_flow_invite_ringing_bye PASSED      [ 87%]
tests/test_ssh_service.py::test_command_result_to_dict PASSED            [ 90%]
tests/test_ssh_service.py::test_execute_command_success PASSED           [ 93%]
tests/test_ssh_service.py::test_execute_command_connection_failure PASSED [ 96%]
tests/test_ssh_service.py::test_collect_system_telemetry PASSED          [100%]

============================= 31 passed in 20.99s =============================
```

---

## 9. Safety and Guardrails

- **Strictly Read-Only by Default**: The dashboard executes non-destructive commands, checks telemetry, and streams log tails without modifying configs or rebooting devices.
- **Zero Host Contamination**: No intrusive agents, daemons, or background services need to be installed on target lab Linux nodes.
- **Zero Hardcoding**: All target IP addresses, credentials, ports, and protocols are loaded from `.env` and persisted dynamically in the SQLite database, with full interactive UI management.
- **Audit Logging**: Every executed command is preserved with timestamps, server targets, duration, stdout, and stderr in the `command_history` audit table.
- **Payload Privacy**: Raw packet payloads are never stored in SQLite or displayed in the UI.

