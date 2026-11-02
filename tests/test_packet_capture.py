"""Unit tests for packet capture module."""

from packet_capture import PacketCaptureManager, PacketInfo


def test_packet_info_model():
    pkt = PacketInfo(
        timestamp="2026-10-26 15:30:00",
        src_ip="10.46.0.8",
        dst_ip="192.168.35.35",
        src_port=5060,
        dst_port=5060,
        protocol="SIP/UDP",
        length=450,
        tcp_flags="",
        summary="SIP REGISTER",
        is_demo=True,
    )

    d = pkt.to_dict()
    assert d["src_ip"] == "10.46.0.8"
    assert d["dst_ip"] == "192.168.35.35"
    assert d["protocol"] == "SIP/UDP"
    assert d["is_demo"] is True


def test_capture_manager_buffer():
    mgr = PacketCaptureManager(max_buffer_size=5)

    for i in range(10):
        mgr.add_packet(
            PacketInfo(
                timestamp=f"2026-10-26 15:30:0{i}",
                src_ip="192.168.35.15",
                dst_ip="192.168.35.19",
                src_port=2152,
                dst_port=2152,
                protocol="GTP-U",
                length=1000 + i,
                is_demo=False,
            )
        )

    assert mgr.total_packets_captured == 10
    # Buffer should be capped at max_buffer_size = 5
    recent = mgr.get_recent_packets()
    assert len(recent) == 5

    stats = mgr.get_stats()
    assert stats["total_captured"] == 10
    assert stats["protocol_distribution"]["GTP-U"] == 10

    mgr.clear()
    assert mgr.total_packets_captured == 0
    assert len(mgr.get_recent_packets()) == 0


def test_get_available_interfaces():
    ifaces = PacketCaptureManager.get_available_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "name" in ifaces[0]
