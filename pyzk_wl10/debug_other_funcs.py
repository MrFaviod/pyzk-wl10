#!/usr/bin/env python3
"""Probar otros códigos de función para obtener log completo"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('<DEVICE_IP>', timeout=30, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Probar varias combinaciones
tests = [
    (const.CMD_DB_RRQ, const.FCT_ATTLOG, 0, "DB_RRQ FCT_ATTLOG"),
    (const.CMD_DB_RRQ, const.FCT_OPLOG, 0, "DB_RRQ FCT_OPLOG"),
    (const.CMD_DB_RRQ, 8, 0, "DB_RRQ FCT_WORKCODE=8"),
    (const.CMD_DB_RRQ, 9, 0, "DB_RRQ FCT_?=9"),
    (const.CMD_DB_RRQ, 10, 0, "DB_RRQ FCT_?=10"),
    (const.CMD_DB_RRQ, 13, 0, "DB_RRQ table=13 (ATTLOG_RRQ)"),
    (const.CMD_DB_RRQ, 15, 0, "DB_RRQ table=15 (CLEAR_ATTLOG)"),
    (const.CMD_DB_RRQ, 20, 0, "DB_RRQ table=20"),
    (const.CMD_ATTLOG_RRQ, 0, 0, "ATTLOG_RRQ legacy"),
]

for cmd, func, param, desc in tests:
    cmd_data = pack('II', func, param)
    resp = zk._ZK__send_command(cmd, cmd_data, 4096)
    
    all_data = zk._ZK__data
    for i in range(50):
        try:
            chunk = zk._ZK__recieve_chunk()
            if chunk:
                all_data += chunk
            else:
                break
        except:
            break
    
    status = resp.get('status')
    code = resp.get('code')
    print(f"{desc}: status={status}, code={code}, total={len(all_data)} bytes")
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        print(f"  Header total={total}, data={len(all_data)-4}")

zk.disconnect()