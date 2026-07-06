"""Shared helpers for building binary WL10 fixtures deterministically.

This module contains functions to pack user/attendance records and
frame bulk responses using the same on-wire layout the parsers expect.
It is NOT a pytest conftest — it is a regular module that test files
import directly.
"""
import os
import struct


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
WL10_ROOT = os.path.join(ROOT, 'pyzk_wl10')
import sys
for p in (WL10_ROOT, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from zk import const


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def pack_user_record(uid, privilege=0, password=b'', name=b'', card=0,
                     group_id=b'', user_id=b''):
    """Pack a single 72-byte pyzk/WL10 user record."""
    password = password.ljust(8, b'\x00')[:8]
    name = name.ljust(24, b'\x00')[:24]
    group_id = group_id.ljust(7, b'\x00')[:7]
    user_id = user_id.ljust(24, b'\x00')[:24]
    return struct.pack('<HB8s24sIx7sx24s',
                       uid, privilege, password, name, card,
                       group_id, user_id)


def pack_attendance_record(uid, user_id, flag=1, timestamp=0, status=0):
    """Pack a single 22-byte WL10 attendance record."""
    uid_bytes = user_id.ljust(6, b'\x00')[:6] if isinstance(user_id, bytes) \
        else user_id.encode('ascii', errors='ignore').ljust(6, b'\x00')[:6]
    return struct.pack('<H6s4sBIB4s',
                       uid, uid_bytes, b'\x00' * 4, flag,
                       int(timestamp), int(status), b'\x00' * 4)


def pack_bulk_response(records_bytes, record_size):
    """Frame ``records_bytes`` with the WL10 12-byte bulk header."""
    outer = 4 + len(records_bytes)
    device = 0x00009fb0
    section = len(records_bytes)
    assert section % record_size == 0, \
        'records section must be a multiple of record_size'
    return struct.pack('<III', outer, device, section) + records_bytes


def encode_zk_time(dt):
    """Encode a :class:`datetime` into the ZK 4-byte timestamp."""
    year_part = dt.year % 100
    month_part = dt.month - 1
    day_part = dt.day - 1
    value = (((year_part * 12 + month_part) * 31 + day_part) * 86400
             + dt.hour * 3600 + dt.minute * 60 + dt.second)
    return value
