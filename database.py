"""Database management module for 5G Lab Doctor.

Implements SQLite schema for events, calls, packets, and node health
with thread-safe execution, indexing, and data retention policies.
"""

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()


class Database:
    def __init__(self, db_path: str = "lab_state.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a connection configured with row factory and WAL mode."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # WAL mode for concurrent reading/writing
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        """Creates tables and indexes if they do not exist."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # 1. Events Table (as specified in 5G Lab Doctor blueprint Listing 1)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        ue_id TEXT,
                        ip_address TEXT,
                        severity TEXT,
                        raw_message TEXT,
                        parsed_json TEXT,
                        is_demo INTEGER DEFAULT 0
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ue ON events(ue_id);")

                # 2. Calls Table (Listing 1)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS calls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        call_id TEXT UNIQUE,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        caller TEXT NOT NULL,
                        callee TEXT NOT NULL,
                        caller_ip TEXT,
                        callee_ip TEXT,
                        state TEXT NOT NULL,
                        setup_time_ms INTEGER,
                        release_reason TEXT,
                        evidence TEXT,
                        is_demo INTEGER DEFAULT 0
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_calls_ts ON calls(start_time);")

                # 3. Packets Table (Feature A)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        length INTEGER,
                        tcp_flags TEXT,
                        summary TEXT,
                        is_demo INTEGER DEFAULT 0
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol);")

                # 4. Node Health Table (Feature E)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS node_health (
                        node_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        reachable INTEGER NOT NULL,
                        service_status TEXT NOT NULL,
                        latency_ms REAL,
                        last_check TEXT NOT NULL,
                        collector_status TEXT,
                        error_detail TEXT
                    );
                """)

                # 5. Dynamic Server Profiles Table (Zero Hardcoding)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS server_profiles (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        port INTEGER DEFAULT 22,
                        protocol TEXT DEFAULT 'SSH',
                        platform TEXT DEFAULT 'CLI',
                        role TEXT,
                        username TEXT,
                        password TEXT,
                        secondary_username TEXT,
                        secondary_password TEXT,
                        key_file TEXT,
                        timeout INTEGER DEFAULT 3,
                        default_log_path TEXT,
                        expected_ports TEXT,
                        quick_commands TEXT,
                        is_active INTEGER DEFAULT 1,
                        updated_at TEXT
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_server_ip ON server_profiles(ip);")

                # 6. Command Execution & Audit History (Feature B & F)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS command_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        server_id TEXT NOT NULL,
                        server_name TEXT,
                        host TEXT NOT NULL,
                        command TEXT NOT NULL,
                        status TEXT NOT NULL,
                        exit_code INTEGER,
                        duration_ms INTEGER,
                        stdout TEXT,
                        stderr TEXT,
                        executed_by TEXT DEFAULT 'admin'
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cmd_ts ON command_history(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cmd_server ON command_history(server_id);")

                conn.commit()

    def record_event(
        self,
        timestamp: str,
        source: str,
        event_type: str,
        ue_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        severity: str = "INFO",
        raw_message: str = "",
        parsed_json: Optional[Dict[str, Any]] = None,
        is_demo: bool = False,
    ) -> int:
        """Inserts a structured log or protocol event."""
        json_str = json.dumps(parsed_json) if parsed_json else None
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO events (timestamp, source, event_type, ue_id, ip_address, severity, raw_message, parsed_json, is_demo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, source, event_type, ue_id, ip_address, severity, raw_message, json_str, 1 if is_demo else 0),
                )
                conn.commit()
                return cursor.lastrowid

    def get_events(self, limit: int = 100, ue_id: Optional[str] = None, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves latest events with optional filters."""
        query = "SELECT * FROM events"
        params: List[Any] = []
        conditions = []

        if ue_id:
            conditions.append("ue_id = ?")
            params.append(ue_id)
        if source:
            conditions.append("source = ?")
            params.append(source)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def record_or_update_call(
        self,
        call_id: str,
        caller: str,
        callee: str,
        state: str,
        start_time: str,
        end_time: Optional[str] = None,
        caller_ip: Optional[str] = None,
        callee_ip: Optional[str] = None,
        setup_time_ms: Optional[int] = None,
        release_reason: Optional[str] = None,
        evidence: Optional[str] = None,
        is_demo: bool = False,
    ):
        """Inserts or updates an IMS SIP call session."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM calls WHERE call_id = ?", (call_id,))
                existing = cursor.fetchone()

                if existing:
                    cursor.execute(
                        """
                        UPDATE calls SET
                            state = ?,
                            end_time = COALESCE(?, end_time),
                            caller_ip = COALESCE(?, caller_ip),
                            callee_ip = COALESCE(?, callee_ip),
                            setup_time_ms = COALESCE(?, setup_time_ms),
                            release_reason = COALESCE(?, release_reason),
                            evidence = COALESCE(?, evidence)
                        WHERE call_id = ?
                        """,
                        (state, end_time, caller_ip, callee_ip, setup_time_ms, release_reason, evidence, call_id),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO calls (call_id, start_time, end_time, caller, callee, caller_ip, callee_ip, state, setup_time_ms, release_reason, evidence, is_demo)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (call_id, start_time, end_time, caller, callee, caller_ip, callee_ip, state, setup_time_ms, release_reason, evidence, 1 if is_demo else 0),
                    )
                conn.commit()

    def get_calls(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent calls."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM calls ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def record_packet(
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
        """Records an observed packet without saving full payload contents."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags, summary, is_demo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags, summary, 1 if is_demo else 0),
                )
                conn.commit()

    def get_packets(self, limit: int = 100, protocol_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves latest packets."""
        query = "SELECT * FROM packets"
        params: List[Any] = []
        if protocol_filter and protocol_filter.upper() != "ALL":
            query += " WHERE protocol = ?"
            params.append(protocol_filter.upper())
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_packet_counts(self) -> Dict[str, int]:
        """Returns protocol counts and total packets."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT protocol, COUNT(*) as cnt FROM packets GROUP BY protocol")
            counts = {row["protocol"]: row["cnt"] for row in cursor.fetchall()}
            cursor.execute("SELECT COUNT(*) as total FROM packets")
            total_row = cursor.fetchone()
            counts["TOTAL"] = total_row["total"] if total_row else 0
            return counts

    def update_node_health(
        self,
        node_id: str,
        name: str,
        ip: str,
        reachable: bool,
        service_status: str,
        latency_ms: Optional[float] = None,
        collector_status: Optional[str] = None,
        error_detail: Optional[str] = None,
    ):
        """Updates health status record for a node."""
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO node_health (node_id, name, ip, reachable, service_status, latency_ms, last_check, collector_status, error_detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id) DO UPDATE SET
                        reachable = excluded.reachable,
                        service_status = excluded.service_status,
                        latency_ms = excluded.latency_ms,
                        last_check = excluded.last_check,
                        collector_status = excluded.collector_status,
                        error_detail = excluded.error_detail
                    """,
                    (node_id, name, ip, 1 if reachable else 0, service_status, latency_ms, now, collector_status, error_detail),
                )
                conn.commit()

    def get_node_health(self) -> List[Dict[str, Any]]:
        """Returns health states for all nodes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM node_health ORDER BY node_id")
            return [dict(row) for row in cursor.fetchall()]

    # --------------------------------------------------------------------------
    # Server Profiles Methods (Zero Hardcoding & Full Dynamic Management)
    # --------------------------------------------------------------------------
    def seed_default_profiles_if_empty(self, profiles: List[Any]):
        """Populates server_profiles table with defaults if empty."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM server_profiles")
                count = cursor.fetchone()[0]
                if count > 0:
                    return

                now = datetime.now().isoformat(sep=" ", timespec="seconds")
                for p in profiles:
                    d = p.to_dict() if hasattr(p, "to_dict") else dict(p)
                    cursor.execute(
                        """
                        INSERT INTO server_profiles (
                            id, name, ip, port, protocol, platform, role, username, password,
                            secondary_username, secondary_password, key_file, timeout,
                            default_log_path, expected_ports, quick_commands, is_active, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            d.get("id"),
                            d.get("name"),
                            d.get("ip"),
                            d.get("port", 22),
                            d.get("protocol", "SSH"),
                            d.get("platform", "CLI"),
                            d.get("role", ""),
                            d.get("username", ""),
                            d.get("password", ""),
                            d.get("secondary_username", ""),
                            d.get("secondary_password", ""),
                            d.get("key_file"),
                            d.get("timeout", 3),
                            d.get("default_log_path"),
                            json.dumps(d.get("expected_ports", [])),
                            json.dumps(d.get("quick_commands", [])),
                            1 if d.get("is_active", True) else 0,
                            now,
                        ),
                    )
                conn.commit()

    def get_server_profiles(self, only_active: bool = False) -> List[Dict[str, Any]]:
        """Retrieves all registered server profiles."""
        query = "SELECT * FROM server_profiles"
        if only_active:
            query += " WHERE is_active = 1"
        query += " ORDER BY id"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                d = dict(row)
                try:
                    d["expected_ports"] = json.loads(d["expected_ports"]) if d["expected_ports"] else []
                except Exception:
                    d["expected_ports"] = []
                try:
                    d["quick_commands"] = json.loads(d["quick_commands"]) if d["quick_commands"] else []
                except Exception:
                    d["quick_commands"] = []
                results.append(d)
            return results

    def get_server_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single server profile by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM server_profiles WHERE id = ?", (profile_id,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["expected_ports"] = json.loads(d["expected_ports"]) if d["expected_ports"] else []
            except Exception:
                d["expected_ports"] = []
            try:
                d["quick_commands"] = json.loads(d["quick_commands"]) if d["quick_commands"] else []
            except Exception:
                d["quick_commands"] = []
            return d

    def save_server_profile(self, profile: Dict[str, Any]) -> bool:
        """Inserts or updates a server profile."""
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        expected_ports = profile.get("expected_ports", [])
        if not isinstance(expected_ports, str):
            expected_ports = json.dumps(expected_ports)

        quick_commands = profile.get("quick_commands", [])
        if not isinstance(quick_commands, str):
            quick_commands = json.dumps(quick_commands)

        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO server_profiles (
                        id, name, ip, port, protocol, platform, role, username, password,
                        secondary_username, secondary_password, key_file, timeout,
                        default_log_path, expected_ports, quick_commands, is_active, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        ip = excluded.ip,
                        port = excluded.port,
                        protocol = excluded.protocol,
                        platform = excluded.platform,
                        role = excluded.role,
                        username = excluded.username,
                        password = excluded.password,
                        secondary_username = excluded.secondary_username,
                        secondary_password = excluded.secondary_password,
                        key_file = excluded.key_file,
                        timeout = excluded.timeout,
                        default_log_path = excluded.default_log_path,
                        expected_ports = excluded.expected_ports,
                        quick_commands = excluded.quick_commands,
                        is_active = excluded.is_active,
                        updated_at = excluded.updated_at
                    """,
                    (
                        profile.get("id"),
                        profile.get("name"),
                        profile.get("ip"),
                        int(profile.get("port", 22)),
                        profile.get("protocol", "SSH"),
                        profile.get("platform", "CLI"),
                        profile.get("role", ""),
                        profile.get("username", ""),
                        profile.get("password", ""),
                        profile.get("secondary_username", ""),
                        profile.get("secondary_password", ""),
                        profile.get("key_file"),
                        int(profile.get("timeout", 3)),
                        profile.get("default_log_path"),
                        expected_ports,
                        quick_commands,
                        1 if profile.get("is_active", True) else 0,
                        now,
                    ),
                )
                conn.commit()
                return True

    def delete_server_profile(self, profile_id: str) -> bool:
        """Deletes a server profile by ID."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM server_profiles WHERE id = ?", (profile_id,))
                conn.commit()
                return cursor.rowcount > 0

    # --------------------------------------------------------------------------
    # Command Execution & Audit Methods
    # --------------------------------------------------------------------------
    def record_command_execution(
        self,
        server_id: str,
        server_name: str,
        host: str,
        command: str,
        status: str,
        exit_code: Optional[int],
        duration_ms: int,
        stdout: str,
        stderr: str,
        executed_by: str = "admin",
    ) -> int:
        """Records an SSH or remote command execution into audit history."""
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO command_history (
                        timestamp, server_id, server_name, host, command, status,
                        exit_code, duration_ms, stdout, stderr, executed_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (now, server_id, server_name, host, command, status, exit_code, duration_ms, stdout, stderr, executed_by),
                )
                conn.commit()
                return cursor.lastrowid

    def get_command_history(self, limit: int = 100, server_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves command execution audit history."""
        query = "SELECT * FROM command_history"
        params: List[Any] = []
        if server_id:
            query += " WHERE server_id = ?"
            params.append(server_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def clear_command_history(self) -> bool:
        """Clears command execution audit history."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM command_history;")
                conn.commit()
                return True

    def purge_old_data(self, days: int = 7):
        """Purges records older than specified retention days."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat(sep=" ", timespec="seconds")
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM calls WHERE start_time < ?", (cutoff,))
                cursor.execute("DELETE FROM command_history WHERE timestamp < ?", (cutoff,))
                conn.commit()

    def clear_all(self):
        """Clears all operational records (useful for test resets)."""
        with _LOCK:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM events;")
                cursor.execute("DELETE FROM calls;")
                cursor.execute("DELETE FROM packets;")
                cursor.execute("DELETE FROM node_health;")
                cursor.execute("DELETE FROM command_history;")
                cursor.execute("DELETE FROM server_profiles;")
                conn.commit()

    def close(self):
        """Checkpoints WAL and closes database handles."""
        try:
            with self._get_connection() as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception:
            pass

