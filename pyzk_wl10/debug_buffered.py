#!/usr/bin/env python3
"""Debug buffered attendance read"""
import sys
sys.path.insert(0, '/home/informatica/zk2/pyzk_wl10')
from zk import ZK, const
from struct import unpack

zk = ZK('192.168.180.201', timeout=15, ommit_ping=True, force_udp=False, wl10=True)
conn = zk.connect()

# Try CMD_DATA_WRRQ
cmd_data = b'\x01\x00\x00\x00\x00\x00\x00\x00'  # FCT_ATTLOG=1, param=0
print("Sending CMD_DATA_WRRQ...")
cmd_response = zk._ZK__send_command(const.CMD_DATA_WRRQ, cmd_data, 4096)
print(f"Response: {cmd_response}")

if cmd_response.get('status'):
    print(f"Code: {cmd_response['code']} (0x{cmd_response['code']:x})")
    print(f"Data len: {len(zk._ZK__data)}")
    print(f"First 100 bytes: {zk._ZK__data[:100].hex()}")
    
    # Receive more chunks
    all_data = zk._ZK__data
    for i in range(20):
        try:
            chunk = zk._ZK__recieve_chunk()
            if chunk:
                all_data += chunk
                print(f"Chunk {i}: {len(chunk)} bytes")
            else:
                print(f"Chunk {i}: empty")
                break
        except Exception as e:
            print(f"Chunk {i}: error {e}")
            break
    
    print(f"Total data: {len(all_data)} bytes")
    if len(all_data) > 0:
        print(f"First 200 bytes: {all_data[:200].hex()}")
        
    # Try to parse
    if len(all_data) >= 4:
        total = unpack('I', all_data[:4])[0]
        print(f"Total header: {total}")
        data = all_data[4:]
        print(f"Data bytes: {len(data)}")
        
        # Try different record sizes
        for size in [24, 28, 32, 40, 72]:
            count = len(data) // size
            if count > 0:
                print(f"  {size}-byte records: {count} (remainder {len(data) % size})")

zk._ZK__send_command(const.CMD_FREE_DATA, b'')
zk.disconnect()