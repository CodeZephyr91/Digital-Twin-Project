"""
Excel inventory parser and IP address validation module.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import pandas as pd


@dataclass
class ServerRecord:
    row_number: int
    name: str
    raw_ip: str
    is_valid_ip: bool
    validated_ip: Optional[str] = None
    validation_error: Optional[str] = None
    platform: Optional[str] = None


class ExcelReader:
    """Reads and parses server records from the MEC Lab inventory workbook."""

    def __init__(self, file_path: Path):
        self.file_path = file_path

    def read_servers(self) -> list[ServerRecord]:
        """Load sheet, detect table boundaries, and extract validated records."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Workbook not found at {self.file_path}")

        df = pd.read_excel(self.file_path, sheet_name=0, header=None)

        header_row_idx: Optional[int] = None
        for idx, row in df.iterrows():
            row_text = " ".join([str(val).lower() for val in row if pd.notna(val)])
            if "product" in row_text and "ip" in row_text:
                header_row_idx = idx
                break

        if header_row_idx is None:
            raise ValueError(
                f"Could not identify inventory table header in {self.file_path.name}"
            )

        records: list[ServerRecord] = []

        for idx in range(header_row_idx + 1, len(df)):
            row = df.iloc[idx]

            col1 = str(row[1]).strip() if pd.notna(row[1]) else ""
            col2 = str(row[2]).strip() if pd.notna(row[2]) else ""
            name = col1 if col1 else col2

            raw_ip = str(row[9]).strip() if pd.notna(row[9]) else ""
            platform = str(row[10]).strip() if pd.notna(row[10]) else ""

            if not name and not raw_ip:
                continue

            is_valid, validated_ip, error_msg = self._validate_ipv4(raw_ip)

            records.append(
                ServerRecord(
                    row_number=idx + 1,
                    name=name if name else "Unnamed Server",
                    raw_ip=raw_ip,
                    is_valid_ip=is_valid,
                    validated_ip=validated_ip,
                    validation_error=error_msg,
                    platform=platform,
                )
            )

        return records

    @staticmethod
    def _validate_ipv4(ip_str: str) -> tuple[bool, Optional[str], Optional[str]]:
        if not ip_str:
            return False, None, "Missing IP address in inventory"
        try:
            addr = ipaddress.IPv4Address(ip_str)
            return True, str(addr), None
        except ValueError:
            return False, None, f"Malformed IPv4 address syntax: '{ip_str}'"
