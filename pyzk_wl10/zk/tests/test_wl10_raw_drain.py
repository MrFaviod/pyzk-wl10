"""Tests for _wl10_read_raw_command multi-chunk draining.

Covers the 110.152 failure mode: the device delivers its bulk ATTLOG
response in several TCP chunks (first recv returns ~1200 bytes, the
rest arrives up to ~300 ms later). The drain loop must keep reading
until the socket goes silent or the response is truncated and the
bulk read returns 0 records.
"""
import socket
import struct
from unittest.mock import MagicMock

from zk import const
from zk.base import ZK

MAGIC1 = const.MACHINE_PREPARE_DATA_1  # 20560
MAGIC2 = const.MACHINE_PREPARE_DATA_2  # 32130


def _build_zk(recv_chunks):
    """Build a ZK with a fake socket returning the given recv chunks.

    ``recv_chunks`` is a list of (bytes, timeout_after_recv_seconds).
    After the last chunk the fake raises socket.timeout to end the drain.
    """
    inst = object.__new__(ZK)
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.tcp = True
    inst.is_connect = True
    inst._ZK__session_id = 12345
    inst._ZK__reply_id = 6789
    inst._ZK__timeout = 5
    inst._ZK__sock = MagicMock()

    calls = iter(recv_chunks)

    def fake_recv(_size):
        try:
            data, _delay = next(calls)
        except StopIteration:
            raise socket.timeout('drain complete')
        return data

    inst._ZK__sock.recv.side_effect = fake_recv
    return inst


class TestWl10RawDrain:
    """Multi-chunk draining in _wl10_read_raw_command."""

    def test_single_chunk_with_records(self):
        """A single chunk with a full PREPARE_DATA payload is returned."""
        payload = (
            b'\x00\x00\x00\x00'          # outer len placeholder (12-byte header)
            + b'\xb0\x9f\x00\x00'        # device magic
            + b'\x2c\x00\x00\x00'        # section byte count = 44 (2 records)
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
            + b'\x02\x00' + b'270' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\x12\x07\xe9\x32' + b'\x01' + b'\x00' * 4
        )
        # build raw TCP frame: top (8B) + ZK header (8B) + payload
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        zk = _build_zk([(raw, 0.0)])
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload

    def test_multi_chunk_concatenates_all_chunks(self):
        """Chunks arriving after the first one are drained until silence."""
        payload_head = (
            b'\x00\x00\x00\x00'
            + b'\xb0\x9f\x00\x00'
            + b'\x2c\x00\x00\x00'
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
        )
        payload_tail = (
            b'\x02\x00' + b'270' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\x12\x07\xe9\x32' + b'\x01' + b'\x00' * 4
        )
        full = payload_head + payload_tail
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(full))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + full)
        # first recv returns only the first 1200 bytes worth, second returns rest
        split = 16 + len(payload_head)
        zk = _build_zk([(raw[:split], 0.0), (raw[split:], 0.0)])
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == full
