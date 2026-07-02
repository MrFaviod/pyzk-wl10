#!/usr/bin/env python3
"""Probar CMD_PREPARE_DATA + CMD_DATA para obtener TODAS las asistencias"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Intentar CMD_PREPARE_DATA con tabla FCT_ATTLOG (1)
print("Enviando CMD_PREPARE_DATA (1500) con FCT_ATTLOG...")
cmd_data = pack('I', const.FCT_ATTLOG)  # tabla = 1
resp = zk._ZK__send_command(const.CMD_PREPARE_DATA, cmd_data, 4096)
print(f"Respuesta: {resp}")

if resp.get('status'):
    print(f"Código: {resp['code']} (0x{resp['code']:x})")
    print(f"Data recibida: {len(zk._ZK__data)} bytes")
    if len(zk._ZK__data) > 0:
        print(f"Primeros 100 bytes: {zk._ZK__data[:100].hex()}")
    
    # Recibir chunks CMD_DATA (1501)
    print("\nRecibiendo chunks CMD_DATA...")
    all_data = zk._ZK__data
    for i in range(50):
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
    
    # Liberar
    zk._ZK__send_command(const.CMD_FREE_DATA, b'')
    print("CMD_FREE_DATA enviado")
else:
    print("CMD_PREPARE_DATA falló")

zk.disconnect()