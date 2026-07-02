#!/usr/bin/env python3
"""
Test script for pyzk WL10 fork.
Lists users and attendance records from ZK fingerprint devices.

Usage:
  python3 test_wl10.py <ip> [options]

Options:
  --wl10         Force WL10 mode
  --password N   Device password (default: 0)
  --tcp          Use TCP (default)
  --udp          Use UDP
  --verbose      Verbose output
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zk import ZK
import argparse
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description='ZK Device Tester')
    parser.add_argument('ip', help='Device IP address')
    parser.add_argument('--wl10', action='store_true', help='Force WL10 mode')
    parser.add_argument('--password', type=int, default=0, help='Device password')
    parser.add_argument('--udp', action='store_true', help='Use UDP instead of TCP')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--port', type=int, default=4370, help='Port (default: 4370)')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds')
    args = parser.parse_args()

    zk = ZK(
        args.ip,
        port=args.port,
        timeout=args.timeout,
        password=args.password,
        force_udp=args.udp,
        ommit_ping=True,
        verbose=args.verbose,
        wl10=args.wl10
    )

    try:
        conn = zk.connect()
        print(f"Connected: {conn}")
        dev_name = zk.get_device_name()
        platform = zk.get_platform()
        print(f"Device: {dev_name} ({platform})")
        print(f"Firmware: {zk.get_firmware_version()}")
        print(f"Serial: {zk.get_serialnumber()}")
        print(f"MAC: {zk.get_mac()}")
        print(f"WL10 mode: {zk.wl10}")

        if args.wl10 or zk.wl10:
            users = zk.wl10_get_users()
            print(f"\n=== USERS ({len(users)}) ===")
            for u in users:
                print(f"  UID:{u.uid:>4} | Badge:{u.user_id:>6} | {u.name}")

            attendance = zk.wl10_get_attendance()
            print(f"\n=== ATTENDANCE ({len(attendance)}) ===")
            print(f"{'Badge':>8} | {'Nombre':<30} | {'Fecha/Hora':<22} | {'Status':<6} | {'Punch':<5}")
            print("-" * 80)
            for a in attendance:
                ts = a.timestamp.strftime('%Y-%m-%d %H:%M:%S') if a.timestamp else 'N/A'
                print(f"{a.badge:>8} | {a.name:<30} | {ts:<22} | {a.status:<6} | {a.punch:<5}")
        else:
            zk.read_sizes()
            print(f"\n=== USERS: {zk.users}/{zk.users_cap} ===")
            users = zk.get_users()
            for u in users[:10]:
                print(f"  {u}")
            if len(users) > 10:
                print(f"  ... and {len(users) - 10} more")

            print(f"\n=== ATTENDANCE: {zk.records}/{zk.rec_cap} ===")
            attendance = zk.get_attendance()
            print(f"{'Badge':>8} | {'Nombre':<30} | {'Fecha/Hora':<22} | {'Status':<6} | {'Punch':<5}")
            print("-" * 80)
            for a in attendance[:20]:
                ts = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                print(f"{a.badge:>8} | {a.name:<30} | {ts:<22} | {a.status:<6} | {a.punch:<5}")
            if len(attendance) > 20:
                print(f"  ... and {len(attendance) - 20} more")

        zk.disconnect()
        print("\nDone.")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()