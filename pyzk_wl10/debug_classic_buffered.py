#!/usr/bin/env python3
"""Protocolo bufferizado clásico: PREPARE_DATA → CMD_DATA (1501)"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import pack, unpack

zk = ZK('<DEVICE_IP>', timeout=30, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# 1. CMD_PREPARE_DATA (1500) con FCT_ATTLOG
print("1. Enviando CMD_PREPARE_DATA (1500) con FCT_ATTLOG...")
cmd_data = pack('I', const.FCT_ATTLOG)
resp = zk._ZK__send_command(const.CMD_PREPARE_DATA, cmd_data, 4096)
print(f"   Respuesta: {resp}")

if resp.get('status'):
    print(f"   Código: {resp['code']} (0x{resp['code']:x})")
    print(f"   Data inicial: {len(zk._ZK__data)} bytes")
    
    # 2. Recibir chunks CMD_DATA (1501)
    print("\n2. Enviando CMD_DATA (1501) para recibir chunks...")
    all_data = zk._ZK__data
    for i in range(200):
        # Enviar CMD_DATA vacío para solicitar siguiente chunk
        chunk_resp = zk._ZK__send_command(const.CMD_DATA, b'', 4096)
        if not chunk_resp.get('status'):
            print(f"   Chunk {i}: falló - {chunk_resp}")
            break
        
        if chunk_resp['code'] == const.CMD_DATA:
            chunk = zk._ZK__data
            if chunk:
                all_data += chunk
                print(f"   Chunk {i}: {len(chunk)} bytes (total: {len(all_data)})")
            else:
                print(f"   Chunk {i}: vacío - fin")
                break
        elif chunk_resp['code'] == const.CMD_ACK_OK:
            print(f"   Chunk {i}: ACK_OK - fin de datos")
            break
        else:
            print(f"   Chunk {i}: código inesperado {chunk_resp['code']}")
            break
    else:
        # Si el bucle for termina sin break, intentar recibir sin enviar
        for i in range(50):
            try:
                chunk = zk._ZK__recieve_chunk()
                if chunk:
                    all_data += chunk
                    print(f"   Auto-chunk {i}: {len(chunk)} bytes (total: {len(all_data)})")
                else:
                    break
            except:
                break
    
    print(f"\nTotal datos: {len(all_data)} bytes")
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        data = all_data[4:]
        print(f"Header: {total}, Datos: {len(data)} bytes")
        for size in [24, 28, 32, 40, 72]:
            cnt = len(data) // size
            if cnt > 0:
                print(f"  {size}-byte: {cnt} records")
    
    # 3. CMD_FREE_DATA (1502)
    print("\n3. Liberando buffer CMD_FREE_DATA...")
    zk._ZK__send_command(const.CMD_FREE_DATA, b'')

else:
    print("PREPARE_DATA falló")

zk.disconnect()