#!/usr/bin/env python3
"""Parsear todos los datos de CMD_DB_RRQ y buscar julio 2026"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack
from datetime import datetime

zk = ZK('<DEVICE_IP>', timeout=30, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# CMD_DB_RRQ con FCT_ATTLOG
cmd_data = pack('II', const.FCT_ATTLOG, 0)
resp = zk._ZK__send_command(const.CMD_DB_RRQ, cmd_data, 4096)

all_data = zk._ZK__data
print(f"Datos iniciales: {len(all_data)} bytes")

# Recibir todos los chunks
for i in range(200):
    try:
        chunk = zk._ZK__recieve_chunk()
        if chunk:
            all_data += chunk
        else:
            break
    except:
        break

print(f"Total datos: {len(all_data)} bytes")

if len(all_data) >= 4:
    total = unpack('I', all_data[:4])[0]
    data = all_data[4:]
    print(f"Header: {total}, Datos: {len(data)} bytes")
    
    REC_SIZE = 28
    count = len(data) // REC_SIZE
    print(f"Registros de {REC_SIZE} bytes: {count}")
    
    # Decodificar todos y buscar julio 2026
    july_records = []
    for ri in range(count):
        rec = data[ri*REC_SIZE:(ri+1)*REC_SIZE]
        uid = unpack('<I', rec[0:4])[0]
        ts = unpack('<I', rec[4:8])[0]
        status = rec[8]
        punch = rec[9]
        user_id = rec[10:16].split(b'\x00')[0].decode('utf-8', errors='ignore')
        
        # Decodificar ZK
        v = ts
        second = v % 60; t = v // 60
        minute = t % 60; t //= 60
        hour = t % 24; t //= 24
        day = t % 31 + 1; t //= 31
        month = t % 12 + 1; t //= 12
        year = t + 2000
        
        try:
            dt = datetime(year, month, day, hour, minute, second)
        except:
            dt = None
        
        # Buscar julio 2026
        if dt and dt.year == 2026 and dt.month == 7:
            july_records.append((ri, uid, dt, status, punch, user_id))
    
    print(f"\nRegistros en JULIO 2026: {len(july_records)}")
    for ri, uid, dt, status, punch, user_id in july_records:
        print(f"  Rec {ri}: uid={uid} dt={dt} status={status} punch={punch} user_id='{user_id}'")
    
    # También mostrar rango de fechas
    dates = []
    for ri in range(count):
        rec = data[ri*REC_SIZE:(ri+1)*REC_SIZE]
        ts = unpack('<I', rec[4:8])[0]
        v = ts
        second = v % 60; t = v // 60
        minute = t % 60; t //= 60
        hour = t % 24; t //= 24
        day = t % 31 + 1; t //= 31
        month = t % 12 + 1; t //= 12
        year = t + 2000
        try:
            dt = datetime(year, month, day, hour, minute, second)
            dates.append(dt)
        except:
            pass
    
    if dates:
        print(f"\nRango de fechas: {min(dates)} a {max(dates)}")
        # Contar por mes
        from collections import Counter
        month_counts = Counter((d.year, d.month) for d in dates)
        for (y, m), c in sorted(month_counts.items()):
            print(f"  {y}-{m:02d}: {c} registros")

zk.disconnect()