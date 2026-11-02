"""Unit tests for Dynamic Server Profiles and Zero Hardcoding Guarantee."""

import gc
import os
import tempfile
import pytest
from config import ServerProfile, cfg
from database import Database


@pytest.fixture
def temp_db():
    fd, temp_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database(db_path=temp_path)
    yield db
    db.close()
    del db
    gc.collect()
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except OSError:
        pass


def test_server_profile_dataclass():
    sp = ServerProfile(
        id="core_5g",
        name="Core 5G",
        ip="192.168.35.10",
        port=22,
        protocol="SSH",
        platform="CLI",
        role="5G Core Network",
        username="support",
        password="Support@817&&",
        expected_ports=[22, 38412],
        quick_commands=["uptime", "free -m"],
    )
    d = sp.to_dict()
    assert d["id"] == "core_5g"
    assert d["ip"] == "192.168.35.10"
    assert d["username"] == "support"

    reconstructed = ServerProfile.from_dict(d)
    assert reconstructed.id == "core_5g"
    assert reconstructed.expected_ports == [22, 38412]
    assert reconstructed.quick_commands == ["uptime", "free -m"]


def test_seed_and_query_profiles(temp_db):
    defaults = cfg.get_default_server_profiles()
    assert len(defaults) >= 15

    temp_db.seed_default_profiles_if_empty(defaults)
    profiles = temp_db.get_server_profiles()
    assert len(profiles) >= 15

    # Check Core 5G profile from uploaded credentials sheet
    core_p = temp_db.get_server_profile("core_5g")
    assert core_p is not None
    assert core_p["ip"] == "192.168.35.10"
    assert core_p["username"] == "support"
    assert core_p["protocol"] == "SSH"

    # Check gNB profile
    gnb_p = temp_db.get_server_profile("gnb_radio")
    assert gnb_p is not None
    assert gnb_p["ip"] == "192.168.35.15"


def test_custom_profile_crud(temp_db):
    custom_profile = {
        "id": "custom_edge_node",
        "name": "Custom Edge Node",
        "ip": "192.168.35.99",
        "port": 8080,
        "protocol": "HTTP",
        "platform": "GUI",
        "role": "Custom Edge Testing Node",
        "username": "custom_user",
        "password": "custom_pass",
        "is_active": True,
    }

    # Save
    ok = temp_db.save_server_profile(custom_profile)
    assert ok is True

    # Retrieve
    retrieved = temp_db.get_server_profile("custom_edge_node")
    assert retrieved is not None
    assert retrieved["name"] == "Custom Edge Node"
    assert retrieved["ip"] == "192.168.35.99"
    assert retrieved["port"] == 8080

    # Update
    retrieved["ip"] = "192.168.35.100"
    temp_db.save_server_profile(retrieved)
    updated = temp_db.get_server_profile("custom_edge_node")
    assert updated["ip"] == "192.168.35.100"

    # Delete
    deleted = temp_db.delete_server_profile("custom_edge_node")
    assert deleted is True
    assert temp_db.get_server_profile("custom_edge_node") is None
