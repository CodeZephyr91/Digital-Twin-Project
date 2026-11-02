"""Unit tests for SSH Service module."""

from unittest.mock import MagicMock, patch
import pytest
from ssh_service import CommandResult, SSHService


def test_command_result_to_dict():
    cr = CommandResult(
        status="SUCCESS",
        exit_code=0,
        duration_ms=45,
        stdout="Linux 5.15.0",
        stderr="",
        timestamp="2026-10-26 15:30:00",
        command="uname -r",
        host="192.168.35.10",
    )
    d = cr.to_dict()
    assert d["status"] == "SUCCESS"
    assert d["exit_code"] == 0
    assert d["duration_ms"] == 45
    assert d["host"] == "192.168.35.10"


@patch("ssh_service.SSHService._create_client")
def test_execute_command_success(mock_create):
    mock_client = MagicMock()
    mock_channel = MagicMock()
    mock_channel.exit_status_ready.return_value = True
    mock_channel.recv_exit_status.return_value = 0

    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel
    mock_stdout.read.return_value = b"Linux gnb-radio 5.15.0-generic\n"

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""

    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)
    mock_create.return_value = (mock_client, None)

    res = SSHService.execute_command(
        host="192.168.35.15",
        command="uname -a",
        username="resonous",
        password="resonous",
    )

    assert res.status == "SUCCESS"
    assert res.exit_code == 0
    assert "Linux gnb-radio" in res.stdout
    assert res.stderr == ""


@patch("ssh_service.SSHService._create_client")
def test_execute_command_connection_failure(mock_create):
    mock_create.return_value = (None, "SSH Connection to 192.168.35.10:22 Failed: Connection refused")

    res = SSHService.execute_command(
        host="192.168.35.10",
        command="uptime",
        username="support",
    )

    assert res.status == "CONNECTION_ERROR"
    assert res.exit_code is None
    assert "Connection refused" in res.stderr


@patch("ssh_service.SSHService.execute_command")
def test_collect_system_telemetry(mock_exec):
    raw_mock_output = """---UPTIME---
 15:30:00 up 45 days,  2:15,  1 user,  load average: 0.25, 0.40, 0.35
---LOADAVG---
0.25 0.40 0.35
---MEMORY---
              total        used        free      shared  buff/cache   available
Mem:          16384        4096       12288         128        1024       11800
---DISK---
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        100G   25G   75G  25% /
"""
    mock_exec.return_value = CommandResult(
        status="SUCCESS",
        exit_code=0,
        duration_ms=50,
        stdout=raw_mock_output,
        stderr="",
        timestamp="2026-10-26 15:30:00",
        command="probe",
        host="192.168.35.10",
    )

    telem = SSHService.collect_system_telemetry(host="192.168.35.10")
    assert telem["status"] == "SUCCESS"
    assert telem["cpu_load_1m"] == 0.25
    assert telem["ram_total_mb"] == 16384
    assert telem["ram_used_mb"] == 4096
    assert telem["ram_percent"] == 25.0
    assert telem["disk_percent"] == 25.0
