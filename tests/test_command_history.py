"""Unit tests for Command History and Audit Trail."""

import gc
import os
import tempfile
import pytest
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


def test_record_and_retrieve_command_history(temp_db):
    row_id = temp_db.record_command_execution(
        server_id="core_5g",
        server_name="Core 5G",
        host="192.168.35.10",
        command="uptime",
        status="SUCCESS",
        exit_code=0,
        duration_ms=42,
        stdout="up 10 days",
        stderr="",
        executed_by="admin",
    )
    assert row_id > 0

    history = temp_db.get_command_history(limit=10)
    assert len(history) == 1
    rec = history[0]
    assert rec["server_id"] == "core_5g"
    assert rec["command"] == "uptime"
    assert rec["status"] == "SUCCESS"
    assert rec["duration_ms"] == 42
    assert rec["stdout"] == "up 10 days"


def test_clear_command_history(temp_db):
    temp_db.record_command_execution(
        server_id="gnb_radio",
        server_name="gNB Radio",
        host="192.168.35.15",
        command="tail -n 10 /home/tetra/euGNB/logs/msg_trace.log",
        status="SUCCESS",
        exit_code=0,
        duration_ms=88,
        stdout="RRCSetupComplete",
        stderr="",
    )
    assert len(temp_db.get_command_history()) == 1

    temp_db.clear_command_history()
    assert len(temp_db.get_command_history()) == 0
