#!/usr/bin/env python3
"""Inspeccionar timestamp WL10 real vs Unix"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK
from struct import unpack
from datetime import datetime

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

raw = zk._wl10_read_bulk_data(13)
data = raw[4:]
REC_SIZE = 28

# Convertir 2026-07-01 y 2026-07-02 a varios formatos
for dt_str in ['2026-07-01', '2026-07-02']:
    dt = datetime.strptime(dt_str, '%Y-%m-%d')
    unix = int(dt.timestamp())
    zk_fmt = ((dt.year % 100) * 12 * 31 + ((dt.month - 1) * 31) + dt.day - 1) * (24 * 60 * 60)
    print(f"{dt_str}: Unix={unix} (0x{unix:08x}), ZK_fmt={zk_fmt} (0x{zk_fmt:08x})")

print("\nBuscando timestamps cercanos en los registros...")
# Buscar todos los ts_val y comparar
for ri in range(len(data) // REC_SIZE):
    rec = data[ri*REC_SIZE:(ri+1)*REC_SIZE]
    uid = unpack('<I', rec[0:4])[0]
    ts_val = unpack('<I', rec[4:8])[0]
    status = rec[8]
    punch = rec[9]
    user_id_att = rec[10:16].split(b'\x00')[0].decode('utf-8', errors='ignore')
    
    # Intentar Unix timestamp
    unix_dt = None
    try:
        unix_dt = datetime.fromtimestamp(ts_val)
    except:
        pass
    
    # Intentar ZK format
    zk_dt = None
    val = ts_val
    second = val % 60
    t = val // 60
    minute = t % 60
    t //= 60
    hour = t % 24
    t //= 24
    day = t % 31 + 1
    t //= 31
    month = t % 12 + 1
    t //= 12
    year = t + 2000
    try:
        zk_dt = datetime(year, month, day, hour, minute, second)
    except:
        pass
    
    # Mostrar solo si Unix cae en 2026-06 a 2026-07 o ZK en 2026-07
    if (unix_dt and 2026 <= unix_dt.year <= 2026 and 6 <= unix_dt.month <= 7) or \
       (zk_dt and zk_dt.year == 2026 and zk_dt.month == 7):
        print(f"[{ri:3d}] uid={uid:<8} ts_val={ts_val:<12} (0x{ts_val:08x}) Unix={unix_dt} ZK={zk_dt} status={status} punch={punch} user_id='{user_id_att}'")

zk.disconnect()