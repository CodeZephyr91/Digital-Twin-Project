"""
Configuration loader and validator for the 5G MEC SSH Checker.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


@dataclass
class AppConfig:
    ssh_username: str
    ssh_password: str
    ssh_port: int
    ssh_timeout: float
    excel_file_path: Path
    known_hosts_path: Path
    command_timeout: float = 5.0

    def validate(self) -> list[str]:
        """Check for configuration anomalies before execution starts."""
        errors = []
        if not self.excel_file_path.exists():
            errors.append(f"Excel file does not exist: {self.excel_file_path}")
        if self.ssh_port <= 0 or self.ssh_port > 65535:
            errors.append(f"Invalid SSH port: {self.ssh_port}")
        if self.ssh_timeout <= 0:
            errors.append(f"Invalid SSH timeout: {self.ssh_timeout}")
        return errors


def load_config(env_file: Optional[str] = None) -> AppConfig:
    """Load settings from .env file and environment variables."""
    if env_file:
        load_dotenv(dotenv_path=env_file, override=True)
    else:
        load_dotenv(override=True)

    excel_path_raw = os.getenv("EXCEL_FILE_PATH", "iitbhu-5g.xlsx")
    known_hosts_raw = os.getenv("KNOWN_HOSTS_PATH", "~/.ssh/known_hosts")

    return AppConfig(
        ssh_username=os.getenv("SSH_USERNAME", "").strip(),
        ssh_password=os.getenv("SSH_PASSWORD", "").strip(),
        ssh_port=int(os.getenv("SSH_PORT", "22")),
        ssh_timeout=float(os.getenv("SSH_TIMEOUT", "15.0")),
        excel_file_path=Path(excel_path_raw).expanduser().resolve(),
        known_hosts_path=Path(known_hosts_raw).expanduser().resolve(),
        command_timeout=float(os.getenv("SSH_COMMAND_TIMEOUT", "5.0")),
    )
