#!/usr/bin/env python3
"""List attendance records from ZK fingerprint device (WL10 compatible)."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))
from zk import ZK
import argparse
from datetime import datetime, date


def main():
    parser = argparse.ArgumentParser(description='Listar marcaciones desde dispositivo ZK')
    parser.add_argument('ip', help='Dirección IP del dispositivo')
    parser.add_argument('--password', type=int, default=0, help='Contraseña del dispositivo')
    parser.add_argument('--port', type=int, default=4370)
    parser.add_argument('--timeout', type=int, default=15)
    parser.add_argument('--no-wl10', action='store_true', help='Forzar modo estándar (no WL10)')
    parser.add_argument('--csv', action='store_true', help='Salida en formato CSV')
    parser.add_argument('--since', help='Filtrar desde fecha (YYYY-MM-DD)')
    parser.add_argument('--until', help='Filtrar hasta fecha (YYYY-MM-DD)')
    args = parser.parse_args()

    since_date = datetime.strptime(args.since, '%Y-%m-%d').date() if args.since else None
    until_date = datetime.strptime(args.until, '%Y-%m-%d').date() if args.until else None
    max_year = date.today().year  # filter out future dates

    zk = ZK(args.ip, port=args.port, timeout=args.timeout,
            password=args.password, ommit_ping=True, force_udp=False,
            wl10=not args.no_wl10)
    conn = zk.connect()

    dev_name = zk.get_device_name() or ''
    use_wl10 = args.no_wl10 is False and ('WL10' in dev_name or zk.wl10)

    if use_wl10:
        users = zk.wl10_get_users()
        attendance = zk.wl10_get_attendance()
    else:
        zk.read_sizes()
        users = zk.get_users()
        attendance = zk.get_attendance()

    if args.csv:
        print("Badge,Nombre,Fecha,Hora,Status,Punch")
    else:
        print(f"{'Badge':>8} | {'Nombre':<30} | {'Fecha/Hora':<22} | {'Status':<6} | {'Punch':<5}")
        print("-" * 80)

    for a in attendance:
        if a.timestamp:
            rec_date = a.timestamp.date()
            if since_date and rec_date < since_date:
                continue
            if until_date and rec_date > until_date:
                continue
            if a.timestamp.year > max_year:
                continue
            
            ts = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            if args.csv:
                print(f"{a.badge},{a.name},{a.timestamp.strftime('%Y-%m-%d')},{a.timestamp.strftime('%H:%M:%S')},{a.status},{a.punch}")
            else:
                print(f"{a.badge:>8} | {a.name:<30} | {ts:<22} | {a.status:<6} | {a.punch:<5}")

    zk.disconnect()


if __name__ == '__main__':
    main()