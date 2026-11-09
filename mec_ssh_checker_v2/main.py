#!/usr/bin/env python3
"""
MEC SSH Connectivity Checker
Entry point for checking SSH reachability and executing harmless read-only
Linux diagnostic commands across servers listed in the 5G MEC Lab inventory.
"""

from __future__ import annotations

import argparse
import sys
from config import load_config
from connection_manager import ConnectionManager
from excel_reader import ExcelReader
from ssh_client import SSHClient


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="5G MEC Lab Backend SSH Connectivity Checker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--excel",
        dest="excel_path",
        type=str,
        default=None,
        help="Path to Excel inventory file",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=None,
        help="SSH connection timeout in seconds",
    )
    parser.add_argument(
        "--env-file",
        dest="env_file",
        type=str,
        default=None,
        help="Path to custom .env file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    config = load_config(env_file=args.env_file)

    if args.excel_path:
        config.excel_file_path = config.excel_file_path.parent / args.excel_path
    if args.timeout is not None:
        config.ssh_timeout = args.timeout

    config_issues = config.validate()
    excel_issues = [
        issue
        for issue in config_issues
        if "Excel file" in issue or "EXCEL_FILE_PATH" in issue
    ]
    if excel_issues:
        for err in excel_issues:
            print(f"[!] Configuration Error: {err}", file=sys.stderr)
        return 1

    print("==================================================")
    print("       5G MEC LAB - SSH CONNECTIVITY CHECKER      ")
    print("==================================================")
    print(f"Inventory File : {config.excel_file_path}")
    print(f"SSH Username   : {config.ssh_username or '<not set>'}")
    print(f"SSH Port       : {config.ssh_port}")
    print(f"SSH Timeout    : {config.ssh_timeout}s")
    print("==================================================\n")

    try:
        reader = ExcelReader(file_path=config.excel_file_path)
        servers = reader.read_servers()
    except FileNotFoundError as e:
        print(f"[!] File Access Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] Failed to parse Excel inventory: {e}", file=sys.stderr)
        return 1

    ssh_client = SSHClient(
        port=config.ssh_port,
        timeout=config.ssh_timeout,
        command_timeout=config.command_timeout,
        known_hosts_path=config.known_hosts_path,
    )
    manager = ConnectionManager(config=config, ssh_client=ssh_client)

    manager.process_servers(servers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
