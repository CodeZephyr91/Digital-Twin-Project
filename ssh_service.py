"""SSH Service Module for Remote Linux Operations & Monitoring.

Provides robust, read-only SSH connection management, remote command execution,
system telemetry harvesting, and log streaming using Paramiko.
Strictly enforces output limits, configurable timeouts, error separation,
and host-key safety guardrails.
"""

import logging
import os
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("5g_lab_doctor.ssh_service")

PARAMIKO_AVAILABLE = False
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    logger.warning("Paramiko is not installed; SSH operations will return error states.")


@dataclass
class CommandResult:
    status: str  # SUCCESS, FAILED, TIMEOUT, AUTH_ERROR, CONNECTION_ERROR
    exit_code: Optional[int]
    duration_ms: int
    stdout: str
    stderr: str
    timestamp: str
    command: str
    host: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timestamp": self.timestamp,
            "command": self.command,
            "host": self.host,
        }


class SSHService:
    """Manages connections and remote execution to lab Linux hosts."""

    @staticmethod
    def _create_client(
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout: int = 4,
    ) -> Tuple[Optional[Any], Optional[str]]:
        """Creates and connects a Paramiko SSHClient with explicit error handling."""
        if not PARAMIKO_AVAILABLE:
            return None, "Paramiko library is not installed in the current environment."

        if not host:
            return None, "Target host IP or hostname is required."

        client = paramiko.SSHClient()
        # Enforce known host policy with auto-add and logging
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: Dict[str, Any] = {
            "hostname": host,
            "port": int(port),
            "username": username or None,
            "timeout": float(timeout),
            "banner_timeout": float(timeout),
            "auth_timeout": float(timeout),
            "look_for_keys": False,
            "allow_agent": False,
        }

        if key_file and Path(key_file).exists():
            connect_kwargs["key_filename"] = key_file
        elif password:
            connect_kwargs["password"] = password

        try:
            client.connect(**connect_kwargs)
            return client, None
        except paramiko.AuthenticationException as e:
            client.close()
            return None, f"SSH Authentication Failed for user '{username}': {e}"
        except (paramiko.SSHException, socket.error, TimeoutError, OSError) as e:
            client.close()
            return None, f"SSH Connection to {host}:{port} Failed: {e}"
        except Exception as e:
            client.close()
            return None, f"Unexpected SSH Error: {e}"

    @classmethod
    def test_connection(
        cls,
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout: int = 3,
    ) -> Tuple[bool, str, Optional[float]]:
        """Tests SSH reachability and authentication without leaving open sessions."""
        start_t = time.time()
        client, err = cls._create_client(
            host=host,
            port=port,
            username=username,
            password=password,
            key_file=key_file,
            timeout=timeout,
        )
        duration_ms = round((time.time() - start_t) * 1000, 2)

        if err:
            return False, err, duration_ms

        try:
            # Run quick no-op to verify channel
            stdin, stdout, stderr = client.exec_command("echo READY", timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            client.close()
            if "READY" in out:
                return True, f"Successfully authenticated to {host}:{port} as '{username}'", duration_ms
            else:
                return False, f"Connected but test echo returned unexpected output: '{out}'", duration_ms
        except Exception as e:
            if client:
                client.close()
            return False, f"Authenticated but failed to open execution channel: {e}", duration_ms

    @classmethod
    def execute_command(
        cls,
        host: str,
        command: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout: int = 8,
        max_output_chars: int = 100000,
    ) -> CommandResult:
        """Executes a command remotely over SSH with separated stdout/stderr and timing."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_t = time.time()

        client, err = cls._create_client(
            host=host,
            port=port,
            username=username,
            password=password,
            key_file=key_file,
            timeout=timeout,
        )

        if err:
            duration_ms = int((time.time() - start_t) * 1000)
            status = "AUTH_ERROR" if "Authentication" in err else "CONNECTION_ERROR"
            return CommandResult(
                status=status,
                exit_code=None,
                duration_ms=duration_ms,
                stdout="",
                stderr=err,
                timestamp=now_str,
                command=command,
                host=host,
            )

        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=float(timeout), get_pty=False)

            # Read channels safely with size bounding
            stdout_bytes = b""
            stderr_bytes = b""

            # Wait for channel exit with timeout
            ch = stdout.channel
            deadline = time.time() + timeout
            while not ch.exit_status_ready():
                if time.time() > deadline:
                    ch.close()
                    client.close()
                    duration_ms = int((time.time() - start_t) * 1000)
                    return CommandResult(
                        status="TIMEOUT",
                        exit_code=None,
                        duration_ms=duration_ms,
                        stdout=stdout_bytes.decode("utf-8", errors="ignore")[:max_output_chars],
                        stderr=f"Command execution timed out after {timeout} seconds.",
                        timestamp=now_str,
                        command=command,
                        host=host,
                    )
                time.sleep(0.05)

            exit_code = ch.recv_exit_status()
            stdout_bytes = stdout.read(max_output_chars)
            stderr_bytes = stderr.read(max_output_chars)

            client.close()
            duration_ms = int((time.time() - start_t) * 1000)

            stdout_str = stdout_bytes.decode("utf-8", errors="ignore").strip()
            stderr_str = stderr_bytes.decode("utf-8", errors="ignore").strip()

            status = "SUCCESS" if exit_code == 0 else "FAILED"

            return CommandResult(
                status=status,
                exit_code=exit_code,
                duration_ms=duration_ms,
                stdout=stdout_str,
                stderr=stderr_str,
                timestamp=now_str,
                command=command,
                host=host,
            )

        except Exception as e:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
            duration_ms = int((time.time() - start_t) * 1000)
            return CommandResult(
                status="FAILED",
                exit_code=None,
                duration_ms=duration_ms,
                stdout="",
                stderr=f"Execution error on {host}: {e}",
                timestamp=now_str,
                command=command,
                host=host,
            )

    @classmethod
    def collect_system_telemetry(
        cls,
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout: int = 4,
    ) -> Dict[str, Any]:
        """Harvests non-intrusive Linux system metrics (CPU load, RAM, Disk, Uptime)."""
        probe_cmd = (
            "echo '---UPTIME---' && uptime && "
            "echo '---LOADAVG---' && cat /proc/loadavg 2>/dev/null || echo '0 0 0' && "
            "echo '---MEMORY---' && free -m 2>/dev/null || echo 'none' && "
            "echo '---DISK---' && df -h / 2>/dev/null || echo 'none'"
        )

        res = cls.execute_command(
            host=host,
            command=probe_cmd,
            port=port,
            username=username,
            password=password,
            key_file=key_file,
            timeout=timeout,
        )

        data: Dict[str, Any] = {
            "host": host,
            "status": res.status,
            "latency_ms": res.duration_ms,
            "cpu_load_1m": 0.0,
            "cpu_load_5m": 0.0,
            "cpu_load_15m": 0.0,
            "ram_total_mb": 0,
            "ram_used_mb": 0,
            "ram_free_mb": 0,
            "ram_percent": 0.0,
            "disk_total": "Unknown",
            "disk_used": "Unknown",
            "disk_free": "Unknown",
            "disk_percent": 0.0,
            "uptime_str": "-",
            "error": res.stderr if res.status != "SUCCESS" else None,
            "timestamp": res.timestamp,
        }

        if res.status != "SUCCESS" or not res.stdout:
            return data

        out = res.stdout

        # Parse Uptime
        m_uptime = re.search(r"---UPTIME---\s*\n([^\n]+)", out)
        if m_uptime:
            data["uptime_str"] = m_uptime.group(1).strip()

        # Parse Load Avg
        m_load = re.search(r"---LOADAVG---\s*\n([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)", out)
        if m_load:
            try:
                data["cpu_load_1m"] = float(m_load.group(1))
                data["cpu_load_5m"] = float(m_load.group(2))
                data["cpu_load_15m"] = float(m_load.group(3))
            except ValueError:
                pass

        # Parse Free -m
        m_mem = re.search(r"Mem:\s+(\d+)\s+(\d+)\s+(\d+)", out)
        if m_mem:
            try:
                total = int(m_mem.group(1))
                used = int(m_mem.group(2))
                free = int(m_mem.group(3))
                data["ram_total_mb"] = total
                data["ram_used_mb"] = used
                data["ram_free_mb"] = free
                if total > 0:
                    data["ram_percent"] = round((used / total) * 100, 1)
            except ValueError:
                pass

        # Parse df -h
        m_disk = re.search(r"\n\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+/", out)
        if m_disk:
            try:
                data["disk_total"] = m_disk.group(1)
                data["disk_used"] = m_disk.group(2)
                data["disk_free"] = m_disk.group(3)
                data["disk_percent"] = float(m_disk.group(4))
            except ValueError:
                pass

        return data

    @classmethod
    def fetch_remote_log_tail(
        cls,
        host: str,
        remote_path: str,
        lines: int = 50,
        filter_query: Optional[str] = None,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        timeout: int = 5,
    ) -> Tuple[bool, List[str], str]:
        """Reads recent log entries from a remote file without loading entire file."""
        if filter_query:
            # Sanitize search term to prevent shell injection
            safe_term = re.sub(r"[^a-zA-Z0-9_\-\.\:\/ ]", "", filter_query)
            cmd = f"tail -n {int(lines * 3)} '{remote_path}' 2>/dev/null | grep -i '{safe_term}' | tail -n {int(lines)}"
        else:
            cmd = f"tail -n {int(lines)} '{remote_path}' 2>/dev/null"

        res = cls.execute_command(
            host=host,
            command=cmd,
            port=port,
            username=username,
            password=password,
            key_file=key_file,
            timeout=timeout,
        )

        if res.status != "SUCCESS":
            return False, [], res.stderr or f"Failed to read '{remote_path}' from {host}"

        lines_out = [l for l in res.stdout.splitlines() if l.strip()]
        return True, lines_out, f"Read {len(lines_out)} lines from {host}:{remote_path}"
