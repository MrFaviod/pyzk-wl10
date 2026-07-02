#!/usr/bin/env python3
"""Probar offset rápido"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('<DEVICE_IP>', timeout=10, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Probar parámetros clave
for param in [0, 414, 500, 1000]:
    cmd_data = pack('II', const.FCT_ATTLOG, param)
    resp = zk._ZK__send_command(const.CMD_DB_RRQ, cmd_data, 4096)
    all_data = zk._ZK__data
    for i in range(5):
        try:
            chunk = zk._ZK__recieve_chunk()
            if chunk:
                all_data += chunk
            else:
                break
        except:
            break
    
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        data = all_data[4:]
        cnt = len(data) // 28
        print(f"param={param}: records={cnt}, bytes={len(data)}")
    else:
        print(f"param={param}: NO DATA")

zk.disconnect()