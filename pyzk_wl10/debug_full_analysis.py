#!/usr/bin/env python3
"""Análisis completo de registros 28 bytes - buscar fecha real"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK
from struct import unpack
from datetime import datetime

zk = ZK('<DEVICE_IP>', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

raw = zk._wl10_read_bulk_data(13)
data = raw[4:]
REC_SIZE = 28

print("Análisis completo de registros - buscando timestamp real julio 2026")
print("=" * 80)

# Fechas objetivo en varios formatos
jul1_unix = 1782874800
jul2_unix = 1782961200
jul1_zk = 851731200
jul2_zk = 851817600

print(f"Objetivos: Unix={jul1_unix}(0x{jul1_unix:08x})/{jul2_unix}(0x{jul2_unix:08x}), ZK={jul1_zk}(0x{jul1_zk:08x})/{jul2_zk}(0x{jul2_zk:08x})")

for ri in range(len(data) // REC_SIZE):
    rec = data[ri*REC_SIZE:(ri+1)*REC_SIZE]
    if len(rec) < REC_SIZE:
        continue
    
    # Extraer todos los uint32 del registro
    u32s = []
    for j in range(0, REC_SIZE, 4):
        if j+4 <= REC_SIZE:
            u32s.append(unpack('<I', rec[j:j+4])[0])
    
    # Verificar cada uint32 contra targets
    for j, val in enumerate(u32s):
        if val in [jul1_unix, jul2_unix, jul1_zk, jul2_zk]:
            print(f"  REC {ri:3d} offset {j*4:2d}: ENCONTRADO {val} (0x{val:08x})")
            print(f"    Registro completo: {rec.hex()}")
    
    # También buscar valores cercanos (±1 día)
    for j, val in enumerate(u32s):
        if abs(val - jul1_unix) < 86400 or abs(val - jul2_unix) < 86400:
            print(f"  REC {ri:3d} offset {j*4:2d}: CERCANO Unix {val} (diff={val-jul1_unix})")
        if abs(val - jul1_zk) < 86400 or abs(val - jul2_zk) < 86400:
            print(f"  REC {ri:3d} offset {j*4:2d}: CERCANO ZK {val} (diff={val-jul1_zk})")

print("\n" + "=" * 80)
print("Dump completo de primeros 5 registros (hex + posibles timestamps):")
for ri in range(5):
    rec = data[ri*REC_SIZE:(ri+1)*REC_SIZE]
    print(f"\nRec {ri}: {rec.hex()}")
    for j in range(0, 28, 4):
        val = unpack('<I', rec[j:j+4])[0]
        # Intentar decodificar como Unix
        try:
            dt_unix = datetime.fromtimestamp(val)
        except:
            dt_unix = None
        # ZK format
        v = val
        second = v % 60; t = v // 60
        minute = t % 60; t //= 60
        hour = t % 24; t //= 24
        day = t % 31 + 1; t //= 31
        month = t % 12 + 1; t //= 12
        year = t + 2000
        try:
            dt_zk = datetime(year, month, day, hour, minute, second)
        except:
            dt_zk = None
        print(f"  [{j:2d}-{j+3:2d}]: {val:>12} (0x{val:08x}) Unix={dt_unix} ZK={dt_zk}")

zk.disconnect()