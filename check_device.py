#!/usr/bin/env python3
"""check_device.py — utilidad read-only para diagnosticar dispositivos ZK WL10.

NO escribe ni borra nada en el dispositivo: solo conecta, lee informacion,
lista usuarios y muestra las ultimas N marcaciones con su estado traducido
(Entrada/Salida/Pausa/Extra).

Uso (Windows, sin instalar nada):
    python check_device.py 192.168.1.100
    python check_device.py 192.168.1.100 --limit 30
    python check_device.py 192.168.1.100 --csv salida.csv

Depende solo de la biblioteca estandar de Python 3.8+ y de la carpeta
pyzk_wl10/ que viaja junto a este script.
"""
import argparse
import os
import sys
from contextlib import suppress

# Funciona desde cualquier directorio: la carpeta pyzk_wl10/ esta junto a este script
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))

from zk import ZK, const

STATUS_ES = {
    'Check-In': 'Entrada',
    'Check-Out': 'Salida',
    'Break-Out': 'Salida-Pausa',
    'Break-In': 'Entrada-Pausa',
    'Overtime-In': 'Entrada-Extra',
    'Overtime-Out': 'Salida-Extra',
}


def status_display(att):
    """Traduce el estado de una marcacion a espanol; fallback al label o numero."""
    label = getattr(att, 'status_label', None)
    if label:
        return STATUS_ES.get(label, label)
    return str(att.status)


def main():  # noqa: PLR0912, PLR0915  # intentional: diagnostic CLI with many branches/steps
    # Consola Windows: acepta caracteres UTF-8 (nombres con acentos)
    with suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    ap = argparse.ArgumentParser(description='Diagnostico read-only de dispositivo ZK WL10')
    ap.add_argument('ip', help='Direccion IP del dispositivo')
    ap.add_argument('--port', type=int, default=4370)
    ap.add_argument('--timeout', type=int, default=20, help='Timeout de conexion en segundos')
    ap.add_argument('--password', type=int, default=0, help='Contrasena del dispositivo')
    ap.add_argument('--limit', type=int, default=20, help='Cuantas ultimas marcaciones mostrar')
    ap.add_argument('--no-wl10', action='store_true', help='Forzar modo estandar (no WL10)')
    ap.add_argument('--csv', metavar='ARCHIVO', help='Guardar TODAS las marcaciones en CSV')
    args = ap.parse_args()

    print(f'Conectando a {args.ip}:{args.port} ...')
    zk = ZK(args.ip, port=args.port, timeout=args.timeout, password=args.password,
            ommit_ping=True, force_udp=False, wl10=not args.no_wl10, verbose=False)
    try:
        zk.connect()
    except Exception as e:  # noqa: BLE001  # intentional: report connect failure
        print(f'ERROR de conexion: {type(e).__name__}: {e}')
        print('Verifique que la IP sea correcta, que el dispositivo este encendido')
        print('y que el puerto 4370 este abierto en el firewall.')
        return 1

    try:
        # Informacion del dispositivo
        dev_name = zk.get_device_name() or '(desconocido)'
        platform = zk.get_platform() or ''
        fw = zk.get_firmware_version() or ''
        print(f'Dispositivo : {dev_name} {platform} {fw}'.strip())
        print(f'Modo        : {"WL10" if zk.wl10 else "estandar"}')

        if zk.wl10:
            try:
                users = zk.wl10_get_users()
            except Exception as e:  # noqa: BLE001  # intentional: report read failure
                print(f'ERROR leyendo usuarios: {type(e).__name__}: {e}')
                return 1
            print(f'Usuarios    : {len(users)}')
            print(f'{"UID":>5} | {"Nombre":<24} | {"UserID":>8} | {"Priv":>5}')
            print('-' * 50)
            for u in sorted(users, key=lambda x: x.uid):
                priv = 'ADMIN' if u.privilege == const.USER_ADMIN else str(u.privilege)
                print(f'{u.uid:>5} | {u.name:<24} | {u.user_id:>8} | {priv:>5}')

            try:
                att = zk.wl10_get_attendance()
            except Exception as e:  # noqa: BLE001  # intentional: report read failure
                print(f'\nERROR leyendo marcaciones: {type(e).__name__}: {e}')
                print('El dispositivo no entrego el registro completo (posible estado')
                print('transitorio o conexion inestable). Reintente en unos minutos.')
                return 1
        else:
            try:
                zk.read_sizes()
                users = zk.get_users()
            except Exception as e:  # noqa: BLE001  # intentional: report read failure
                print(f'ERROR leyendo usuarios: {type(e).__name__}: {e}')
                return 1
            print(f'Usuarios    : {len(users)}')
            for u in sorted(users, key=lambda x: x.uid):
                priv = 'ADMIN' if u.privilege == const.USER_ADMIN else str(u.privilege)
                print(f'{u.uid:>5} | {u.name:<24} | {u.user_id:>8} | {priv:>5}')
            try:
                att = zk.get_attendance()
            except Exception as e:  # noqa: BLE001  # intentional: report read failure
                print(f'\nERROR leyendo marcaciones: {type(e).__name__}: {e}')
                return 1

        by_uid = {u.uid: u for u in users}
        total = len(att)
        print(f'\nMarcaciones : {total}')
        if total == 0:
            print('(el dispositivo no tiene marcaciones registradas)')
        else:
            print(f'\nUltimas {min(args.limit, total)} marcaciones:')
            print(f'{"Fecha y hora":<20} | {"Nombre":<24} | {"UserID":>8} | {"Estado":<14}')
            print('-' * 75)
            for a in sorted(att, key=lambda x: x.timestamp)[-args.limit:]:
                u = by_uid.get(a.uid)
                name = u.name if u else '?'
                print(f'{a.timestamp:%Y-%m-%d %H:%M:%S} | {name:<24} | {a.user_id:>8} | {status_display(a):<14}')

        if args.csv:
            with open(args.csv, 'w', encoding='utf-8', newline='') as f:
                f.write('Badge,Nombre,Fecha,Hora,Status,Punch\n')
                for a in sorted(att, key=lambda x: x.timestamp):
                    u = by_uid.get(a.uid)
                    name = u.name if u else ''
                    print(f'{a.badge},{name},{a.timestamp:%Y-%m-%d},{a.timestamp:%H:%M:%S},'
                          f'{status_display(a)},{a.punch}', file=f)
            print(f'\nCSV guardado en: {args.csv}')
    finally:
        with suppress(Exception):
            zk.disconnect()
    return 0


if __name__ == '__main__':
    sys.exit(main())
