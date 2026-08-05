#!/usr/bin/env python3
"""
wl10_probe_write.py — Probe script for AK3750/WL10 set_user + delete_user protocol.

WHAT THIS SCRIPT DOES:
    1. Connects to the device, reads the baseline user list (via CMD=9 no payload).
    2. Writes a test user with USER privilege (priv=0) via CMD=8 + 72B payload.
    3. Reads back and verifies persistence.
    4. Writes a test user with ADMIN privilege (priv=14) via the same path.
    5. Reads back and verifies privilege level.
    6. Deletes the test users via CMD=18 + pack('<h', uid).
    7. Reads back and verifies deletion.
    8. Prints a structured report.

Confirmed protocol against AK3750WIFI_TFT "Ver 6.60 May 19 2023"
(firmware at <DEVICE_IP>):

    WRITE user:  CMD=8 (CMD_USER_WRQ)   payload=72B (HB8s24s4sx7sx24s)
                 response: CMD_ACK_OK=2000
    READ users:  CMD=9 (CMD_USERTEMP_RRQ)  NO payload
                 response: CMD_PREPARE_DATA=1500 + 12B header + N*72B records
    DELETE user: CMD=18 (CMD_DELETE_USER)  payload=pack('<h', uid)
                 response: CMD_ACK_OK=2000
    HOUSEKEEPING: CMD=1013 (REFRESHDATA) between operations.
                  CMD=1502 (FREE_DATA) after bulk reads.

Usage:
    python3 wl10_probe_write.py <DEVICE_IP> [--port 4370] [--password 0] [--verbose]
"""

import os
import socket
import sys
from struct import pack, unpack

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))
from zk import const

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USHRT_MAX = 65535
M1 = const.MACHINE_PREPARE_DATA_1   # 20560
M2 = const.MACHINE_PREPARE_DATA_2   # 32130

CMD_CONNECT       = const.CMD_CONNECT        # 1000
CMD_REFRESHDATA   = const.CMD_REFRESHDATA    # 1013
CMD_USER_WRQ      = const.CMD_USER_WRQ       # 8
CMD_USERTEMP_RRQ  = const.CMD_USERTEMP_RRQ   # 9
CMD_FREE_DATA     = const.CMD_FREE_DATA     # 1502
CMD_DELETE_USER   = const.CMD_DELETE_USER    # 18

CMD_ACK_OK        = const.CMD_ACK_OK         # 2000
CMD_ACK_ERROR     = const.CMD_ACK_ERROR      # 2001
CMD_PREPARE_DATA  = const.CMD_PREPARE_DATA   # 1500


# ---------------------------------------------------------------------------
# Helpers (replicate ZK.__create_header without touching instance state)
# ---------------------------------------------------------------------------

def create_checksum(buf):
    length = len(buf)
    checksum = 0
    while length > 1:
        checksum += unpack('H', pack('BB', buf[0], buf[1]))[0]
        buf = buf[2:]
        if checksum > USHRT_MAX:
            checksum -= USHRT_MAX
        length -= 2
    if length:
        checksum += buf[-1]
    while checksum > USHRT_MAX:
        checksum -= USHRT_MAX
    checksum = ~checksum
    while checksum < 0:
        checksum += USHRT_MAX
    return checksum & 0xFFFF


def make_header(cmd, command_string, session_id, reply_id):
    """Build a ZK wire packet. Does NOT mutate any caller state."""
    buf = pack('<4H', cmd, 0, session_id, reply_id) + command_string
    bs = unpack('8B' + f'{len(command_string)}B', buf)
    checksum = create_checksum(bs)
    reply_id += 1
    if reply_id >= USHRT_MAX:
        reply_id -= USHRT_MAX
    return pack('<4H', cmd, checksum, session_id, reply_id) + command_string


def tcp_top(packet):
    return pack('<HHI', M1, M2, len(packet)) + packet


def raw_send_recv(sock, cmd, payload, sid, rid, timeout=10, idle_wait=1):
    """Send command to the device and gather all TCP-framed responses.

    Returns ``(payloads, raw_bytes, new_sid, new_rid)``.

    The ZK protocol keeps ``session_id`` constant for the whole TCP session
    (it is assigned by the device during CMD_CONNECT). Only ``reply_id``
    advances by one per command and is echoed back in the ACK response.

    For bulk reads (CMD=9, CMD=13) the device replies with three ZK packets:
      - [0] CMD_PREPARE_DATA (1500):  ZK header sid/rid are valid.
      - [1] CMD_DATA (1501):         ZK header bytes 4-7 are part of the bulk
                                     data checksum, NOT a real sid/rid — both
                                     appear as small integers (sid=0, rid=2)
                                     and must NOT be used to update state.
      - [2] CMD_ACK_OK (2000):       ZK header sid/rid are valid (final ack).
    Therefore we must update sid/rid ONLY from a payload whose ``cmd`` field
    is CMD_ACK_OK (2000) or CMD_ACK_ERROR (2001), never from CMD_DATA (1501)
    or even CMD_PREPARE_DATA (its rid is the seq-of-this-command, not yet
    echoed).  We use the FIRST ACK found in the burst.
    """
    sock.send(tcp_top(make_header(cmd, payload, sid, rid)))
    sock.settimeout(timeout)
    all_data = b''
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            all_data += chunk
            sock.settimeout(idle_wait)
    except socket.timeout:
        pass
    # Parse TCP framing and extract ZK payloads
    payloads = []
    pos = 0
    while pos + 8 <= len(all_data):
        m1, m2, dsize = unpack('<HHI', all_data[pos:pos+8])
        if m1 == M1 and m2 == M2 and dsize > 0 and pos + 8 + dsize <= len(all_data):
            payloads.append(all_data[pos+8:pos+8+dsize])
            pos += 8 + dsize
        else:
            pos += 1
    # Update reply_id only: the session_id stays constant across the whole session
    # (assigned by the device during CMD_CONNECT).  The ACK payloads after a bulk
    # read have garbled session_id fields (134 bytes of checksum/auth data) so we
    # MUST NOT read session_id from them.
    new_sid, new_rid = sid, rid
    for p in payloads:
        if len(p) >= 8:
            pcmd, _, _, ack_rid = unpack('<4H', p[:8])
            if pcmd in (CMD_ACK_OK, CMD_ACK_ERROR):
                new_sid = sid   # preserve caller's sid, never use the wire value
                new_rid = ack_rid
                break
    return payloads, all_data, new_sid, new_rid


def make_user_payload_72(uid, privilege, user_id, name='TEST',
                         password='', group_id='1', card=0):
    """72-byte user record (standard pyzk layout)."""
    name_b = name.encode('utf-8', errors='ignore').ljust(24, b'\x00')[:24]
    pw_b = password.encode('utf-8', errors='ignore').ljust(8, b'\x00')[:8]
    gid_b = group_id.encode('utf-8', errors='ignore').ljust(7, b'\x00')[:7]
    uid_str_b = str(user_id).encode('utf-8', errors='ignore').ljust(24, b'\x00')[:24]
    card_b = pack('<I', int(card))[:4]
    return pack('<HB8s24s4sx7sx24s',
                uid, privilege, pw_b, name_b, card_b, gid_b, uid_str_b)


def parse_users(payloads):
    """Concatenate all payload bodies, strip the 12B section header, slice 72B records."""
    if not payloads:
        return []
    cmd = unpack('<H', payloads[0][:2])[0]
    if cmd != CMD_PREPARE_DATA:
        return []
    all_bodies = b''
    for p in payloads:
        all_bodies += p[8:]
    if len(all_bodies) < 12:
        return []
    records = all_bodies[12:]
    users = []
    for i in range(len(records) // 72):
        rec = records[i*72:(i+1)*72]
        uid, priv = unpack('<HB', rec[:3])
        name = rec[11:35].split(b'\x00')[0].decode('utf-8', errors='ignore')
        card = unpack('<I', rec[35:39])[0]
        uid_field = rec[48:72].split(b'\x00')[0].decode('ascii', errors='ignore')
        users.append({'uid': uid, 'priv': priv, 'name': name, 'card': card, 'user_id': uid_field})
    return users


# ---------------------------------------------------------------------------
# Wire operations
# ---------------------------------------------------------------------------

def op_connect(sock):
    payloads, _, _, rid = raw_send_recv(sock, CMD_CONNECT, b'', 0, USHRT_MAX-1, timeout=5)
    if not payloads or unpack('<H', payloads[0][:2])[0] != CMD_ACK_OK:
        raise RuntimeError(f'CONNECT failed: {payloads}')
    _, _, sid, rid = unpack('<4H', payloads[0][:8])
    return sid, rid


def op_refresh(sock, sid, rid):
    payloads, _, sid2, rid2 = raw_send_recv(sock, CMD_REFRESHDATA, b'', sid, rid, timeout=5)
    if not payloads or unpack('<H', payloads[0][:2])[0] != CMD_ACK_OK:
        raise RuntimeError('REFRESH failed')
    return sid2, rid2


def op_free_data(sock, sid, rid):
    _, _, sid2, rid2 = raw_send_recv(sock, CMD_FREE_DATA, b'', sid, rid, timeout=5)
    return sid2, rid2


def op_write_user(sock, sid, rid, uid, privilege, badge, name='TEST'):
    payload = make_user_payload_72(uid, privilege, badge, name=name)
    payloads, _, sid2, rid2 = raw_send_recv(sock, CMD_USER_WRQ, payload, sid, rid, timeout=10)
    if not payloads:
        return False, 'no response', sid2, rid2
    cmd = unpack('<H', payloads[0][:2])[0]
    ok = (cmd == CMD_ACK_OK)
    return ok, f'cmd={cmd}', sid2, rid2


def op_read_users(sock, sid, rid):
    payloads, _, sid2, rid2 = raw_send_recv(sock, CMD_USERTEMP_RRQ, b'', sid, rid, timeout=15, idle_wait=2)
    users = parse_users(payloads)
    return users, sid2, rid2


def op_delete_user(sock, sid, rid, uid):
    payloads, _, sid2, rid2 = raw_send_recv(sock, CMD_DELETE_USER, pack('<h', uid), sid, rid, timeout=5)
    if not payloads:
        return False, 'no response', sid2, rid2
    cmd = unpack('<H', payloads[0][:2])[0]
    ok = (cmd == CMD_ACK_OK)
    return ok, f'cmd={cmd}', sid2, rid2


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse  # noqa: PLC0415  # lazy: script entry point, avoids import cost in helpers
    parser = argparse.ArgumentParser(description='Probe WL10 set_user + delete_user protocol')
    parser.add_argument('ip', help='Device IP')
    parser.add_argument('--port', type=int, default=4370)
    parser.add_argument('--timeout', type=int, default=15)
    parser.add_argument('--verbose', action='store_true', help='Print hex dumps')
    args = parser.parse_args()

    # UIDs and badges for probe
    USER_UID = 1000
    USER_BADGE = '999950'
    ADMIN_UID = 1001
    ADMIN_BADGE = '999951'

    print(f'=== WL10 probe_write against {args.ip}:{args.port} ===')
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((args.ip, args.port))
    except Exception as e:  # noqa: BLE001  # intentional: report connect failure and exit
        print(f'CONNECT socket error: {e}')
        return 1
    print('  TCP connected')

    sid, rid = op_connect(s)
    print(f'  ZK connected: sid={sid} rid={rid}')

    # --- Baseline ---
    print()
    print('=== Step 1: Read baseline users (CMD=9 no payload) ===')
    sid, rid = op_refresh(s, sid, rid)
    users, sid, rid = op_read_users(s, sid, rid)
    print(f'  Found {len(users)} users')

    # If test users from a previous probe run are still present, delete them first
    for u in users:
        if u['user_id'] in (USER_BADGE, ADMIN_BADGE):
            print(f'  WARN: leftover test user {u["user_id"]!r} uid={u["uid"]} found, deleting...')
            ok_del, note_del, sid, rid = op_delete_user(s, sid, rid, u['uid'])
            print(f'    delete: {"OK" if ok_del else "FAIL"} ({note_del})')

    if args.verbose:
        for u in users:
            print(f'    uid={u["uid"]:>3} priv={u["priv"]:>2} name={u["name"]!r} badge={u["user_id"]!r}')

    # --- WRITE USER with REFRESH in between ---
    print()
    print(f'=== Step 2: WRITE user uid={USER_UID} badge={USER_BADGE} priv=0 (USER_DEFAULT) ===')
    sid, rid = op_refresh(s, sid, rid)  # settle device state before write
    ok, note, sid, rid = op_write_user(s, sid, rid, USER_UID, const.USER_DEFAULT, USER_BADGE, name='TEST_USER')
    print(f'  Result: {"OK" if ok else "FAIL"} ({note})')

    # --- WRITE ADMIN ---
    print()
    print(f'=== Step 3: WRITE admin uid={ADMIN_UID} badge={ADMIN_BADGE} priv=14 (USER_ADMIN) ===')
    sid, rid = op_refresh(s, sid, rid)  # settle device state before write
    ok2, note2, sid, rid = op_write_user(s, sid, rid, ADMIN_UID, const.USER_ADMIN, ADMIN_BADGE, name='TEST_ADMIN')
    print(f'  Result: {"OK" if ok2 else "FAIL"} ({note2})')

    # --- READBACK ---
    print()
    print('=== Step 4: READ users to verify persistence ===')
    sid, rid = op_refresh(s, sid, rid)
    users_after, sid, rid = op_read_users(s, sid, rid)
    print(f'  Found {len(users_after)} users (was {len(users)})')

    user_rec = [u for u in users_after if u['user_id'] == USER_BADGE]
    admin_rec = [u for u in users_after if u['user_id'] == ADMIN_BADGE]

    print()
    if user_rec:
        u = user_rec[0]
        u_ok = (u['priv'] == const.USER_DEFAULT)
        print(f'  USER badge {USER_BADGE}: FOUND  uid={u["uid"]} priv={u["priv"]} name={u["name"]!r}  '
              f'privilege={"OK" if u_ok else "WRONG (expected 0)"}')
    else:
        print(f'  USER badge {USER_BADGE}: NOT FOUND  -> WRITE failed despite ACK')

    if admin_rec:
        u = admin_rec[0]
        a_ok = (u['priv'] == const.USER_ADMIN)
        print(f'  ADMIN badge {ADMIN_BADGE}: FOUND  uid={u["uid"]} priv={u["priv"]} name={u["name"]!r}  '
              f'privilege={"OK" if a_ok else "WRONG (expected 14)"}')
    else:
        print(f'  ADMIN badge {ADMIN_BADGE}: NOT FOUND  -> WRITE failed despite ACK')

    # --- DELETE ---
    print()
    print(f'=== Step 5: DELETE user uid={USER_UID} (CMD=18 pack(\'h\', uid)) ===')
    ok_del, note_del, sid, rid = op_delete_user(s, sid, rid, USER_UID)
    print(f'  Result: {"OK" if ok_del else "FAIL"} ({note_del})')

    print(f'=== Step 6: DELETE admin uid={ADMIN_UID} ===')
    ok_del2, note_del2, sid, rid = op_delete_user(s, sid, rid, ADMIN_UID)
    print(f'  Result: {"OK" if ok_del2 else "FAIL"} ({note_del2})')

    # --- VERIFY DELETE ---
    print()
    print('=== Step 7: READ users to verify deletion ===')
    sid, rid = op_refresh(s, sid, rid)
    users_final, sid, rid = op_read_users(s, sid, rid)
    print(f'  Found {len(users_final)} users (was {len(users)} baseline, {len(users_after)} before delete)')

    user_gone = not any(u['user_id'] == USER_BADGE for u in users_final)
    admin_gone = not any(u['user_id'] == ADMIN_BADGE for u in users_final)
    print()
    print(f'  USER  badge {USER_BADGE}: {"GONE (delete worked)" if user_gone else "STILL PRESENT (delete failed)"}')
    print(f'  ADMIN badge {ADMIN_BADGE}: {"GONE (delete worked)" if admin_gone else "STILL PRESENT (delete failed)"}')

    if not user_gone:
        for u in users_final:
            if u['user_id'] == USER_BADGE:
                print(f'    uid={u["uid"]} priv={u["priv"]} name={u["name"]!r}')
                break

    # --- SUMMARY ---
    print()
    print('=== SUMMARY ===')
    print(f'  Write USER  : {"PASS" if user_rec else "FAIL"}')
    print(f'  Write ADMIN : {"PASS" if admin_rec else "FAIL"}')
    print(f'  Delete USER : {"PASS" if user_gone else "FAIL"}')
    print(f'  Delete ADMIN: {"PASS" if admin_gone else "FAIL"}')
    if user_rec and admin_rec and user_gone and admin_gone:
        print()
        print('  ALL TESTS PASSED — wl10_set_user / wl10_delete_user confirmed working.')

    s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
