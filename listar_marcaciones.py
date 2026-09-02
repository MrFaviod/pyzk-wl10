#!/usr/bin/env python3
"""List attendance records from ZK fingerprint device (WL10 compatible)."""
import os
import sys
from contextlib import suppress

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))

import argparse
from datetime import date, datetime

from zk import ZK

# Traducción al español del label canónico del estado (ver Attendance.status_label)
STATUS_ES = {
    'Check-In': 'Entrada',
    'Check-Out': 'Salida',
    'Break-Out': 'Salida-Pausa',
    'Break-In': 'Entrada-Pausa',
    'Overtime-In': 'Entrada-Extra',
    'Overtime-Out': 'Salida-Extra',
}


def status_display(a):
    label = a.status_label if hasattr(a, 'status_label') else ''
    return STATUS_ES.get(label, str(a.status))


def _parse_date(value):
    """argparse type para fechas YYYY-MM-DD (convierte errores en un usage error)."""
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        raise argparse.ArgumentTypeError(f"fecha inválida '{value}' (use YYYY-MM-DD)")


def main():  # noqa: PLR0912, PLR0915  # intentional: attendance dump CLI with many flags/steps
    parser = argparse.ArgumentParser(description='Listar marcaciones desde dispositivo ZK')
    parser.add_argument('ip', help='Dirección IP del dispositivo')
    parser.add_argument('--password', type=int, default=0, help='Contraseña del dispositivo')
    parser.add_argument('--port', type=int, default=4370, help='Puerto del dispositivo (default 4370)')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout de conexión en segundos')
    parser.add_argument('--no-wl10', action='store_true', help='Forzar modo estándar (no WL10)')
    parser.add_argument('--csv', action='store_true', help='Salida en formato CSV')
    parser.add_argument('--since', type=_parse_date, metavar='YYYY-MM-DD', help='Filtrar desde fecha (YYYY-MM-DD)')
    parser.add_argument('--until', type=_parse_date, metavar='YYYY-MM-DD', help='Filtrar hasta fecha (YYYY-MM-DD)')
    parser.add_argument('--tcp-maxseg', type=int, default=None,
                        help='TCP_MAXSEG to set before connect (e.g. 1200 for VPN/PMTUD blackhole routes)')
    parser.add_argument('--gap-timeout', type=int, default=None,
                        help='Inter-chunk drain grace in seconds (default 1; VPN profile for 110.152 uses 3)')
    args = parser.parse_args()

    since_date = args.since
    until_date = args.until
    max_year = date.today().year  # filter out future dates

    zk = ZK(args.ip, port=args.port, timeout=args.timeout,
            password=args.password, ommit_ping=True, force_udp=False,
            wl10=not args.no_wl10, tcp_maxseg=args.tcp_maxseg,
            gap_timeout=args.gap_timeout)
    try:
        zk.connect()

        dev_name = zk.get_device_name() or ''
        use_wl10 = args.no_wl10 is False and ('WL10' in dev_name or zk.wl10)

        if use_wl10:
            zk.wl10_get_users()
            attendance = zk.wl10_get_attendance()
        else:
            zk.read_sizes()
            zk.get_users()
            attendance = zk.get_attendance()
    except Exception as e:  # noqa: BLE001  # intentional: friendly CLI error instead of a traceback
        print(f'ERROR: {type(e).__name__}: {e}', file=sys.stderr)
        print('Verifique la IP, que el dispositivo esté encendido y que el puerto 4370 esté accesible.',
              file=sys.stderr)
        return 1
    finally:
        with suppress(Exception):
            zk.disconnect()

    records = []
    for a in attendance:
        if not a.timestamp:
            continue
        rec_date = a.timestamp.date()
        if since_date and rec_date < since_date:
            continue
        if until_date and rec_date > until_date:
            continue
        if a.timestamp.year > max_year:
            continue
        records.append(a)
    records.sort(key=lambda a: a.timestamp)

    if args.csv:
        print("Badge,Nombre,Fecha,Hora,Status,Punch")
        for a in records:
            print(f"{a.badge},{a.name},{a.timestamp.strftime('%Y-%m-%d')},{a.timestamp.strftime('%H:%M:%S')},{status_display(a)},{a.punch}")
    else:
        print(f"{'Badge':>8} | {'Nombre':<30} | {'Fecha/Hora':<22} | {'Status':<13} | {'Punch':<5}")
        print("-" * 88)
        for a in records:
            ts = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            print(f"{a.badge:>8} | {a.name:<30} | {ts:<22} | {status_display(a):<13} | {a.punch:<5}")

    # El resumen va a stderr para no contaminar stdout (CSV o pipes)
    if records:
        print(f'Total: {len(records)} marcaciones', file=sys.stderr)
    else:
        print('No se encontraron marcaciones para el filtro solicitado.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
