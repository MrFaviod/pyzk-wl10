#!/usr/bin/env python3
"""Inspeccionar OPLOG (FCT_OPLOG=4)"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack
from datetime import datetime

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# CMD_DB_RRQ con FCT_OPLOG
cmd_data = pack('II', const.FCT_OPLOG, 0)
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
    print(f"OPLOG: total={total}, data={len(data)} bytes")
    
    # Intentar 24, 28, 32, 40 bytes
    for size in [24, 28, 32, 40]:
        cnt = len(data) // size
        if cnt > 0:
            print(f"  {size}-byte: {cnt} records")
            # Parsear algunos
            for ri in range(min(3, cnt)):
                rec = data[ri*size:(ri+1)*size]
                print(f"    Rec {ri}: {rec.hex()}")

zk.disconnect()