#!/usr/bin/env python3
"""Probar offset/parámetro en CMD_DB_RRQ"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('192.168.180.201', timeout=30, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Probar diferentes valores de parámetro (offset/count)
for param in [0, 1, 100, 414, 500, 1000, 4000]:
    cmd_data = pack('II', const.FCT_ATTLOG, param)
    resp = zk._ZK__send_command(const.CMD_DB_RRQ, cmd_data, 4096)
    
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
    
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        data = all_data[4:]
        cnt = len(data) // 28
        print(f"param={param:4d}: status={resp.get('status')}, code={resp.get('code')}, data={len(data)} bytes, records={cnt}")
    else:
        print(f"param={param:4d}: status={resp.get('status')}, code={resp.get('code')}, NO DATA")

zk.disconnect()