#!/usr/bin/env python3
"""Probar comandos alternativos para obtener log de asistencia real"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Probar CMD_PREPARE_DATA (1500) + CMD_DATA_WRRQ (1503) con FCT_ATTLOG
print("=== Probando CMD_PREPARE_DATA ===")
cmd_data = pack('II', const.FCT_ATTLOG, 0)
resp = zk._ZK__send_command(const.CMD_PREPARE_DATA, cmd_data, 4096)
print(f"PREPARE_DATA: status={resp.get('status')}, code={resp.get('code')}")
if resp.get('status'):
    print(f"  Data: {zk._ZK__data[:100].hex()}")

# Si PREPARE_DATA funciona, probar DATA_WRRQ
if resp.get('status'):
    print("\n=== Probando CMD_DATA_WRRQ después de PREPARE_DATA ===")
    resp2 = zk._ZK__send_command(const.CMD_DATA_WRRQ, cmd_data, 4096)
    print(f"DATA_WRRQ: status={resp2.get('status')}, code={resp2.get('code')}")
    if resp2.get('status'):
        print(f"  Data: {zk._ZK__data[:100].hex()}")
        all_data = zk._ZK__data
        for i in range(20):
            try:
                chunk = zk._ZK__recieve_chunk()
                if chunk:
                    all_data += chunk
                else:
                    break
            except:
                break
        print(f"  Total: {len(all_data)} bytes")

# Probar con tabla=13 (CMD_ATTLOG_RRQ)
print("\n=== Probando tabla=13 (CMD_ATTLOG_RRQ) ===")
cmd_data2 = pack('II', 13, 0)
resp3 = zk._ZK__send_command(const.CMD_PREPARE_DATA, cmd_data2, 4096)
print(f"PREPARE_DATA tabla=13: status={resp3.get('status')}, code={resp3.get('code')}")

# Probar ULG_RRQ (log de operaciones)
print("\n=== Probando CMD_ULG_RRQ (29) ===")
resp4 = zk._ZK__send_command(const.CMD_ULG_RRQ, b'', 4096)
print(f"ULG_RRQ: status={resp4.get('status')}, code={resp4.get('code')}")

zk.disconnect()