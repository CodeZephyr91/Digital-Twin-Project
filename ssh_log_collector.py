"""SSH log collector module for 5G Lab Doctor.

Provides read-only, non-intrusive log collection from remote Linux lab hosts using Paramiko:
- gNB (192.168.35.15): msg_trace.log, eventHistory.log, AlarmLog.csv
- IMS Core (192.168.35.35): sip_trace.log
- NMS Server (192.168.35.6): telemetry/app.log
- VM Hosts (192.168.35.50/.51): virsh list --all (hypervisor VM telemetry)

Features:
- Incremental tail streaming without full-file reloads.
- Strict read-only safety guardrails (no writes, no reboots, non-intrusive).
- Seamless fallback to local sample logs when remote systems are offline or in demo mode.
- Non-blocking worker threads with thread-safe line queues.
"""

import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("5g_lab_doctor.ssh_collector")

PARAMIKO_AVAILABLE = False
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    logger.warning("Paramiko is not installed; SSH remote collection will use mock/fallback mode.")


class RemoteLogCollector:
    """Manages an incremental read-only log collector for a specific lab host."""

    def __init__(
        self,
        host: str,
        remote_path: str,
        username: str = "",
        password: str = "",
        key_file: Optional[str] = None,
        port: int = 22,
        timeout: int = 3,
        fallback_local_path: Optional[str] = None,
        line_callback: Optional[Callable[[str, str], None]] = None,
        node_id: str = "generic",
    ):
        self.host = host
        self.remote_path = remote_path
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.fallback_local_path = fallback_local_path
        self.line_callback = line_callback
        self.node_id = node_id

        self._ssh_client: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.status = "DISCONNECTED"  # DISCONNECTED, CONNECTED, STREAMING, FALLBACK_LOCAL, ERROR
        self.last_error: Optional[str] = None
        self.last_collected_time: Optional[str] = None
        self.collected_line_count = 0
        self.recent_lines: List[str] = []

    def start_collector(self, force_local: bool = False) -> Tuple[bool, str]:
        """Starts the log tail worker thread."""
        with self._lock:
            if self.status in ("STREAMING", "FALLBACK_LOCAL"):
                return True, f"Collector for {self.host} is already active."

            self._stop_event.clear()
            self.last_error = None

            if force_local or not PARAMIKO_AVAILABLE or not self.host or not self.username:
                # Use local sample log mode
                if self.fallback_local_path and Path(self.fallback_local_path).exists():
                    self.status = "FALLBACK_LOCAL"
                    self._thread = threading.Thread(
                        target=self._local_tail_worker,
                        args=(self.fallback_local_path,),
                        daemon=True,
                        name=f"LocalTail-{self.node_id}",
                    )
                    self._thread.start()
                    return True, f"Using local sample logs for {self.node_id} ({self.fallback_local_path})"
                else:
                    self.status = "ERROR"
                    self.last_error = f"No SSH credentials and local fallback file '{self.fallback_local_path}' not found."
                    return False, self.last_error

            # Launch remote SSH thread
            self._thread = threading.Thread(
                target=self._ssh_tail_worker,
                daemon=True,
                name=f"SSHTail-{self.node_id}",
            )
            self._thread.start()
            return True, f"Connecting to {self.host}:{self.port}..."

    def stop_collector(self):
        """Stops collector thread and closes SSH connection."""
        self._stop_event.set()
        with self._lock:
            if self._ssh_client:
                try:
                    self._ssh_client.close()
                except Exception:
                    pass
                self._ssh_client = None
            self.status = "DISCONNECTED"

    def _ssh_tail_worker(self):
        """Connects via Paramiko and streams 'tail -n 50 -f <file>'."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: Dict[str, Any] = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": self.timeout,
                "banner_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            if self.key_file and Path(self.key_file).exists():
                connect_kwargs["key_filename"] = self.key_file
            elif self.password:
                connect_kwargs["password"] = self.password

            client.connect(**connect_kwargs)
            with self._lock:
                self._ssh_client = client
                self.status = "STREAMING"

            cmd = f"tail -n 50 -f '{self.remote_path}'"
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=False)

            while not self._stop_event.is_set():
                line = stdout.readline()
                if not line:
                    if stdout.channel.exit_status_ready():
                        break
                    time.sleep(0.1)
                    continue

                line_clean = line.strip()
                if line_clean:
                    self._handle_new_line(line_clean)

        except Exception as e:
            with self._lock:
                self.status = "ERROR"
                self.last_error = f"SSH error on {self.host}: {e}"
            logger.warning("SSH collector error on %s: %s", self.host, e)

            # Auto-fallback to local sample log if configured
            if self.fallback_local_path and Path(self.fallback_local_path).exists():
                logger.info("Failing over to local sample log for %s", self.node_id)
                self.status = "FALLBACK_LOCAL"
                self._local_tail_worker(self.fallback_local_path)

    def _local_tail_worker(self, local_path: str):
        """Reads local sample file incrementally to simulate continuous telemetry."""
        try:
            with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                # Read initial lines
                lines = f.readlines()
                for line in lines:
                    line_clean = line.strip()
                    if line_clean:
                        self._handle_new_line(line_clean)

                # Keep watching for file appends
                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        line_clean = line.strip()
                        if line_clean:
                            self._handle_new_line(line_clean)
                    else:
                        time.sleep(1.0)
        except Exception as e:
            with self._lock:
                self.status = "ERROR"
                self.last_error = f"Local file read error: {e}"

    def _handle_new_line(self, line: str):
        with self._lock:
            self.collected_line_count += 1
            self.last_collected_time = time.strftime("%Y-%m-%d %H:%M:%S")
            self.recent_lines.append(line)
            if len(self.recent_lines) > 200:
                self.recent_lines.pop(0)

        if self.line_callback:
            try:
                self.line_callback(self.node_id, line)
            except Exception as cb_err:
                logger.error("Line callback error: %s", cb_err)

    def get_recent_lines(self, limit: int = 50) -> List[str]:
        with self._lock:
            return list(self.recent_lines[-limit:])

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "node_id": self.node_id,
                "host": self.host,
                "remote_path": self.remote_path,
                "status": self.status,
                "lines_collected": self.collected_line_count,
                "last_collected": self.last_collected_time or "-",
                "last_error": self.last_error,
            }
