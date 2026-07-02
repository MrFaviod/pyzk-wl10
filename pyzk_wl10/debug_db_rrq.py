#!/usr/bin/env python3
"""Probar CMD_DB_RRQ con FCT_ATTLOG para asistencia completa"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# CMD_DB_RRQ (7) con FCT_ATTLOG (1) - según test Lua
print("Enviando CMD_DB_RRQ (7) con FCT_ATTLOG (1)...")
cmd_data = pack('II', const.FCT_ATTLOG, 0)  # table=1, param=0
resp = zk._ZK__send_command(const.CMD_DB_RRQ, cmd_data, 4096)
print(f"Respuesta: {resp}")

if resp.get('status'):
    print(f"Código: {resp['code']} (0x{resp['code']:x})")
    print(f"Data recibida: {len(zk._ZK__data)} bytes")
    if len(zk._ZK__data) > 0:
        print(f"Primeros 100 bytes: {zk._ZK__data[:100].hex()}")
    
    # Recibir chunks
    print("\nRecibiendo chunks...")
    all_data = zk._ZK__data
    for i in range(100):
        try:
            chunk = zk._ZK__recieve_chunk()
            if chunk:
                all_data += chunk
                print(f"  Chunk {i}: {len(chunk)} bytes (total: {len(all_data)})")
            else:
                print(f"  Chunk {i}: vacío")
                break
        except Exception as e:
            print(f"  Chunk {i}: error {e}")
            break
    
    print(f"\nTotal datos: {len(all_data)} bytes")
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        print(f"Header total: {total}")
        data = all_data[4:]
        print(f"Datos: {len(data)} bytes")
        for size in [24, 28, 32, 40, 72]:
            cnt = len(data) // size
            if cnt > 0:
                print(f"  {size}-byte records: {cnt} (rem {len(data) % size})")
        
        # Parsear algunos
        for ri in range(min(5, len(data) // 28)):
            rec = data[ri*28:(ri+1)*28]
            uid = unpack('<I', rec[0:4])[0]
            ts = unpack('<I', rec[4:8])[0] if len(rec) >= 8 else 0
            status = rec[8] if len(rec) > 8 else 0
            punch = rec[9] if len(rec) > 9 else 0
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
                from datetime import datetime
                dt = datetime(year, month, day, hour, minute, second)
            except:
                dt = None
            print(f"  Rec {ri}: uid={uid} ts={ts} (0x{ts:08x}) -> {dt} status={status} punch={punch} user_id='{user_id}'")

zk.disconnect()