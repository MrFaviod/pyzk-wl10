"""Tests for _wl10_read_raw_command multi-chunk draining.

Covers the WL10 device's segmented bulk response: the device delivers its
bulk ATTLOG/USER response in several TCP chunks. The resilient drain
loop keeps reading until a complete terminal ACK (CMD_ACK_OK /
CMD_ACK_ERROR) frame is present in the accumulated stream, or until the
adaptive silence fallback ends the current attempt; three attempts with
a growing gap (gap_timeout, 2x, 4x, clamped by __timeout) cover the
no-ACK case.
"""
import socket
import struct
from unittest.mock import MagicMock, call

from helpers import pack_attendance_record, pack_bulk_response
from zk import const
from zk.base import ZK

MAGIC1 = const.MACHINE_PREPARE_DATA_1  # 20560
MAGIC2 = const.MACHINE_PREPARE_DATA_2  # 32130


def _pack_ack_frame(pcmd, rid, sid=12345, checksum=0):
    """Pack a bare 16-byte terminal ACK frame (dsize=8, no payload)."""
    return (struct.pack('<HHI', MAGIC1, MAGIC2, 8)
            + struct.pack('<4H', pcmd, checksum, sid, rid))


def _pack_prepare_frame(payload, sid=12345, rid=3, checksum=0):
    """Pack a CMD_PREPARE_DATA frame carrying ``payload``."""
    return (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
            + struct.pack('<4H', const.CMD_PREPARE_DATA, checksum, sid, rid)
            + payload)


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
    inst.gap_timeout = 1
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


def _build_zk_retry(recv_seq):
    """Build a ZK whose recv yields a scripted sequence per attempt.

    ``recv_seq`` is a flat list whose items are either ``bytes`` (returned
    by recv) or the sentinel ``TIMEOUT`` (raise ``socket.timeout``). This
    lets a test script exactly one chunk followed by a timeout *within a
    single inner loop* so each retry attempt consumes one chunk then
    ends — unlike :func:`_build_zk` whose generator runs the whole inner
    loop to exhaustion across attempts.
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
    inst.gap_timeout = 1
    inst._ZK__sock = MagicMock()

    calls = iter(recv_seq)

    def fake_recv(_size):
        item = next(calls)
        if item is TIMEOUT:
            raise socket.timeout('drain complete')
        return item

    inst._ZK__sock.recv.side_effect = fake_recv
    return inst


TIMEOUT = object()


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

    def test_lan_default_path_keeps_1s_gap(self):
        """gap_timeout=1 (default) keeps a 1s silence fallback on the
        first chunk.

        The adaptive drain computes ``silence_gap = min(gap_timeout *
        2**attempt, __timeout)`` regardless of ``tcp_maxseg``; with the
        default gap_timeout=1 the first-attempt silence gap is exactly
        1s — matching historical LAN behaviour.
        """
        payload = b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4 + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        # Fake recv delivers exactly one chunk, then the socket goes
        # silent (socket.timeout) — the drain must end after chunk 1,
        # never waiting for a chunk2 that would arrive >1s later.
        zk = _build_zk([(raw, 0.0)])
        zk.tcp_maxseg = None      # LAN default path
        zk.gap_timeout = 1        # default: silence fallback bounded to 1s
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),  # first recv: min(timeout, 10)
            call(1),                          # silence_gap: min(1*2**0, timeout)=1
            call(zk._ZK__timeout),            # finally: restore
        ]

    def test_gap_widens_to_3s_when_maxseg_set(self):
        """VPN profile (tcp_maxseg=1200, gap_timeout=3) widens the
        post-first-chunk drain gap to min(3, timeout)=3.

        RED vs current base.py: the drain loop hard-codes 1s after the
        first chunk, so the middle settimeout call is 1 — a device that
        pauses >1s between chunks (vpn-device over Fortinet VPN) gets
        truncated. After the fix the middle call must be
        ``min(gap_timeout, timeout)`` = 3.
        """
        payload = (
            b'\x00\x00\x00\x00'
            + b'\xb0\x9f\x00\x00'
            + b'\x2c\x00\x00\x00'
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
            + b'\x02\x00' + b'270' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\x12\x07\xe9\x32' + b'\x01' + b'\x00' * 4
        )
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        # First chunk arrives; the fake then goes silent (socket.timeout),
        # mirroring a >1s inter-chunk pause on the VPN link.
        zk = _build_zk([(raw, 0.0)])
        zk.tcp_maxseg = 1200     # vpn-device VPN profile
        zk.gap_timeout = 3
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),  # first recv
            call(3),                          # widened gap: min(gap_timeout, timeout)
            call(zk._ZK__timeout),            # finally: restore
        ]

    def test_gap_clamped_by_timeout(self):
        """The widened gap is clamped by the connection timeout.

        gap_timeout=3 with _ZK__timeout=2 must yield min(3, 2)=2, never
        exceeding the connection timeout. Fails today (hard-coded 1).
        """
        payload = (
            b'\x00\x00\x00\x00'
            + b'\xb0\x9f\x00\x00'
            + b'\x2c\x00\x00\x00'
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
        )
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        zk = _build_zk([(raw, 0.0)])
        zk.tcp_maxseg = 1200
        zk.gap_timeout = 3
        zk._ZK__timeout = 2
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(2, 10)),
            call(2),   # min(gap_timeout=3, timeout=2)
            call(2),   # finally: restore to timeout
        ]

    def test_default_gap_stays_1s_when_no_maxseg(self):
        """LAN devices (no profile) keep the 1s drain gap.

        gap_timeout stays at its default 1 for LAN, so the middle
        settimeout call remains exactly 1 — identical to
        test_lan_default_path_keeps_1s_gap. This guards the LAN path
        against accidental widening (a 3s gap would stall LAN drains
        waiting for chunks that never come).
        """
        payload = (
            b'\x00\x00\x00\x00'
            + b'\xb0\x9f\x00\x00'
            + b'\x2c\x00\x00\x00'
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
        )
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        zk = _build_zk([(raw, 0.0)])
        zk.tcp_maxseg = None      # LAN default path
        zk.gap_timeout = 1        # default: no widening
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),
            call(1),               # unchanged LAN gap
            call(zk._ZK__timeout),
        ]

    def test_gap_timeout_none_normalized_to_default(self):
        """CLI passes gap_timeout=None explicitly (argparse default).

        The drain must treat None as the 1s default instead of crashing
        with ``min(None * 2**attempt, timeout)`` TypeError — the sentinel
        bug that made the CLI fail with 'got 0 bytes after 3 attempts'
        while a direct probe (which omitted the kwarg) succeeded.
        """
        payload = (
            b'\x00\x00\x00\x00'
            + b'\xb0\x9f\x00\x00'
            + b'\x2c\x00\x00\x00'
            + b'\x01\x00' + b'181' + b'\x00' * 3 + b'\x00' * 4
            + b'\x01' + b'\xe4\xe8\x32\x01' + b'\x00' + b'\x00' * 4
        )
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(payload))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + payload)
        zk = _build_zk([(raw, 0.0)])
        zk.gap_timeout = None     # argparse default reaches the constructor
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == payload
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),
            call(1),               # None normalized to the 1s default
            call(zk._ZK__timeout),
        ]

    def test_multichunk_ack_ends_drain_early(self):
        """Multi-chunk bulk: chunk1 carries the PREPARE_DATA header +
        half the records; chunk2 carries the remaining records and the
        trailing CMD_ACK_OK. The drain scans after each recv: chunk1 has
        no terminal ACK yet so it applies the adaptive silence_gap
        (gap_timeout=3) before the next recv; chunk2 completes the ACK
        and the inner loop breaks — three settimeout calls total.
        """
        rec1 = pack_attendance_record(1, '181', flag=1, timestamp=0x0132e8e4)
        rec2 = pack_attendance_record(2, '270', flag=1, timestamp=0x32e90712)
        rec3 = pack_attendance_record(3, '333', flag=1, timestamp=0x33e90a13)
        records = rec1 + rec2 + rec3
        section = pack_bulk_response(records, const.WL10_ATT_RECORD_SIZE)
        ack = (struct.pack('<HHI', MAGIC1, MAGIC2, 8)
               + struct.pack('<4H', const.CMD_ACK_OK, 0, 12345, 6789))
        raw = (struct.pack('<HHI', MAGIC1, MAGIC2, 8 + len(section))
               + struct.pack('<4H', const.CMD_PREPARE_DATA, 0, 12345, 3)
               + section
               + ack)
        split = 16 + len(section) // 2
        chunk1, chunk2 = raw[:split], raw[split:]
        zk = _build_zk([(chunk1, 0.0), (chunk2, 0.0)])
        zk.gap_timeout = 3
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == section
        assert zk._wl10_bulk_is_complete(out, const.WL10_ATT_RECORD_SIZE)
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),   # first recv: min(timeout, 10)
            call(3),                          # silence_gap before chunk2
            call(zk._ZK__timeout),            # finally: restore
        ]


class TestAckTermination:
    """Terminal-ACK termination behaviour of _wl10_read_raw_command."""

    def test_terminal_ack_breaks_drain_early(self):
        """A single chunk holding PREPARE_DATA immediately followed by the
        terminal CMD_ACK_OK frame must break the inner drain loop on the
        first recv scan — so the ``settimeout(silence_gap)`` line is
        never reached and only two settimeout calls occur:
        ``call(min(__timeout, 10))`` before the recv and
        ``call(__timeout)`` in the finally block.
        """
        section = pack_bulk_response(
            pack_attendance_record(1, '181', flag=1, timestamp=0x0132e8e4)
            + pack_attendance_record(2, '270', flag=1, timestamp=0x32e90712),
            const.WL10_ATT_RECORD_SIZE)
        rid = 6789
        raw = _pack_prepare_frame(section, rid=3) + _pack_ack_frame(const.CMD_ACK_OK, rid)
        zk = _build_zk([(raw, 0.0)])
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == section
        assert zk._wl10_last_ack == (const.CMD_ACK_OK, rid)
        assert zk._ZK__sock.settimeout.call_args_list == [
            call(min(zk._ZK__timeout, 10)),
            call(zk._ZK__timeout),
        ]

    def test_split_ack_assembled_across_chunks(self):
        """ACK frame split across two chunks: chunk1 carries the PREPARE_DATA
        frame plus the first 4 bytes of the ACK (the magic+dsize header);
        chunk2 carries the remaining 12 bytes of the ACK (the 4H pcmd/ck/
        sid/rid). Scanning after chunk1 sees an incomplete frame (no),
        so silence_gap is applied; scanning after chunk2 sees the full ACK
        and the drain breaks. The returned payload is the section and the
        last_ack records the assembled ACK.
        """
        section = pack_bulk_response(
            pack_attendance_record(1, '181'), const.WL10_ATT_RECORD_SIZE)
        rid = 4242
        prepare = _pack_prepare_frame(section, rid=3)
        ack = _pack_ack_frame(const.CMD_ACK_OK, rid, sid=12345)
        split_point = len(prepare) + 4  # 4 bytes of the ACK header in chunk1
        chunk1 = prepare + ack[:split_point - len(prepare)]
        chunk2 = ack[split_point - len(prepare):]
        assert chunk1 + chunk2 == prepare + ack
        zk = _build_zk([(chunk1, 0.0), (chunk2, 0.0)])
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == section
        assert zk._wl10_last_ack == (const.CMD_ACK_OK, rid)

    def test_ack_error_terminates_and_updates_reply_id(self):
        """A CMD_ACK_ERROR (2001) terminal frame with a fresh rid must
        terminate draining, update ``__reply_id`` (ERROR still advances
        the device's rid), and still return whatever section was drained
        before the error ACK arrived.
        """
        section = pack_bulk_response(
            pack_attendance_record(1, '181'), const.WL10_ATT_RECORD_SIZE)
        error_rid = 4242
        assert error_rid != 6789  # different from the harness initial rid
        raw = _pack_prepare_frame(section, rid=3) + _pack_ack_frame(
            const.CMD_ACK_ERROR, error_rid)
        zk = _build_zk([(raw, 0.0)])
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == section
        assert zk._wl10_last_ack == (const.CMD_ACK_ERROR, error_rid)
        assert zk._ZK__reply_id == error_rid

    def test_no_ack_silence_fallback_returns_payload(self):
        """A bulk response delivered across chunks with NO terminal ACK
        relies on the silence fallback: after the socket goes quiet the
        drain accepts the accumulated payload via the
        ``len(payload) >= 8`` branch. ``_wl10_last_ack`` stays None and
        ``__reply_id`` is unchanged (no ACK to sync from).
        """
        section = pack_bulk_response(
            pack_attendance_record(1, '181', flag=1, timestamp=0x0132e8e4)
            + pack_attendance_record(2, '270', flag=1, timestamp=0x32e90712),
            const.WL10_ATT_RECORD_SIZE)
        raw = _pack_prepare_frame(section, rid=3)
        split = 16 + len(section) // 2
        chunk1, chunk2 = raw[:split], raw[split:]
        initial_rid = 6789
        zk = _build_zk([(chunk1, 0.0), (chunk2, 0.0)])
        zk.gap_timeout = 1
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == section
        assert zk._wl10_last_ack is None
        assert zk._ZK__reply_id == initial_rid

    def test_adaptive_gaps_grow_across_attempts(self):
        """When no ACK and no payload >= 8 ever arrives, each of the three
        attempts times out after one short recv. The silence_gap grows
        per attempt — ``gap_timeout * 2**attempt`` — so with
        ``gap_timeout=1`` the silence settimeout call inside each attempt
        is ``call(1)``, ``call(2)``, then ``call(4)``. The retry harness
        feeds one chunk then a timeout *within a single inner loop*, so
        each attempt consumes exactly one chunk then ends; after three
        attempts the drain returns ``b''``.
        """
        zk = _build_zk_retry(
            [b'AAAA', TIMEOUT, b'BBBB', TIMEOUT, b'CCCC', TIMEOUT])
        zk.gap_timeout = 1
        zk._ZK__timeout = 8
        zk._ZK__sock.settimeout.reset_mock()
        out = zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert out == b''
        call_list = zk._ZK__sock.settimeout.call_args_list
        silence_calls = [c.args[0] for c in call_list
                         if c.args and c.args[0] in (1, 2, 4)]
        assert silence_calls == [1, 2, 4]

