#!/usr/bin/env python3
"""Buscar timestamps Unix (2026-07-01/02) en datos CMD_ATTLOG_RRQ"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK
from struct import unpack

zk = ZK('<DEVICE_IP>', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

raw = zk._wl10_read_bulk_data(13)
data = raw[4:]

# Buscar Unix timestamps de julio 2026
targets = [1782874800, 1782961200, 1782874800 + 86400]  # 2026-07-01, 2026-07-02, etc.

print("Buscando timestamps Unix en datos crudos...")
for i, b in enumerate(data):
    if i + 4 <= len(data):
        val = unpack('<I', data[i:i+4])[0]
        if val in targets:
            print(f"  Offset {i}: Unix timestamp {val} = {val}")

# También buscar en little-endian bytes de 4 en 4
for i in range(0, len(data) - 3, 4):
    val = unpack('<I', data[i:i+4])[0]
    if 1782000000 <= val <= 1785000000:  # rango julio 2026
        print(f"  Offset {i}: Unix {val} = {val}")

# Buscar ZK format para julio 2026
# 2026-07-01 -> year=26, month=6, day=0
# t = 26*12+6=318, *31+0=9858, *24=236592, *60=14195520, *60=851731200
# 2026-07-02 -> 851817600
zk_targets = [851731200, 851817600]
for i in range(0, len(data) - 3, 4):
    val = unpack('<I', data[i:i+4])[0]
    if val in zk_targets:
        print(f"  Offset {i}: ZK format {val} = {val}")

# Dump first few records bytes 4-8 (timestamp field)
print("\nPrimeros 10 registros - bytes 4-8:")
for ri in range(10):
    rec = data[ri*28:(ri+1)*28]
    if len(rec) >= 8:
        ts = unpack('<I', rec[4:8])[0]
        print(f"  Rec {ri}: ts={ts} (0x{ts:08x})")

zk.disconnect()