"""Offline contract tests for the WL10 fingerprint-template read path.

The standard pyzk path reads templates by sending ``CMD_DATA_WRRQ`` (1503)
with ``pack('<bhii', 1, CMD_DB_RRQ, FCT_FINGERTMP, 0)``. WL10 firmware
needs the raw TCP drain instead, so ``wl10_get_templates`` sends that same
request through ``_wl10_read_raw_command`` and parses the same table format:

    uint32 total_size, then entries of
    size:uint16, uid:uint16, fid:int8, valid:int8, template[size-6]
"""
import socket
import struct
from unittest.mock import MagicMock, call as mock_call

import pytest
from helpers import pack_template_table

from zk import const
from zk.base import ZK
from zk.exception import ZKErrorResponse
from zk.finger import Finger
from zk.user import User


TEMPLATE_A = bytes(range(1, 33))
TEMPLATE_B = bytes(range(33, 73))
ENTRIES = [(7, 0, 1, TEMPLATE_A), (7, 1, 1, TEMPLATE_B), (11, 0, 0, TEMPLATE_A[:16])]

# The wire request the standard pyzk reader builds for a fingerprint-template
# table read. Direct CMD_DB_RRQ (7) with an empty body is NOT it: live probes on
# all three authorized WL10s answered that with a bare terminal ACK_OK and zero
# payload.
TEMPLATE_REQUEST = struct.pack('<bhii', 1, const.CMD_DB_RRQ, const.FCT_FINGERTMP, 0)

# Live read-only probes on all three authorized WL10s answered that wrapped
# request with a stable 13-byte announcement instead of the table: a zero
# prefix byte, two identical uint32 sizes, and a 4-byte opaque trailer.
LIVE_ANNOUNCEMENTS = (
    ('target A', bytes.fromhex('00c6470000c64700007a343d00'), 18374),
    ('target B', bytes.fromhex('004c4e00004c4e00003cf4ad00'), 20044),
    ('target C', bytes.fromhex('00585b0000585b00009683d300'), 23384),
)
MAX_ANNOUNCED_SIZE = 64 * 1024 * 1024

# The standard reader releases the device's single bulk buffer after its
# chunk loop. This firmware will not service template reads until that
# buffer is released, so every announced fetch ends with this command.
RELEASE = (const.CMD_FREE_DATA, b'')


def _announcement(size, trailer=b'\x00\x00\x00\x00'):
    """Build the observed 13-byte prepare/read announcement."""
    return b'\x00' + struct.pack('<II', size, size) + trailer


def _chunk_frame(command, payload, rid):
    """Frame one raw response packet for the fake socket."""
    return (struct.pack('<HHI', const.MACHINE_PREPARE_DATA_1,
                        const.MACHINE_PREPARE_DATA_2, 8 + len(payload))
            + struct.pack('<4H', command, 0, 12345, rid)
            + payload)


def _prepare_frame(size, rid):
    """Frame a command-88 ``CMD_PREPARE_DATA`` announcement.

    The measured live shape is an 8-byte payload carrying the announced
    size twice and no data of its own.
    """
    return _chunk_frame(const.CMD_PREPARE_DATA, struct.pack('<II', size, size), rid)


def _template_frame(template, rid):
    """Frame a command-88 ``CMD_DATA`` template response.

    Mirrors the real shape the standard reader consumes: the template,
    six zero padding bytes, then the single terminator byte it strips
    before building the ``Finger``.
    """
    return _chunk_frame(const.CMD_DATA, template + (b'\x00' * 6) + b'\x00', rid)


def _decode_sent(frame):
    """Return ``[(command, command_string)]`` for a framed TCP send."""
    return struct.unpack('<4H', frame[8:16])[0], frame[16:]


def _sent_rid(frame):
    """Return the reply_id the request carried when it went on the wire."""
    return struct.unpack('<4H', frame[8:16])[3]


def _zk_with_fake_socket(frames, sent):
    """Build a WL10 ZK whose socket records sends and replays ``frames``.

    A ``_TIMEOUT`` item in ``frames`` makes the next ``recv`` raise
    ``socket.timeout``, which ends the current drain without ending the
    test — that is how one response is separated from the next.
    """
    inst = object.__new__(ZK)
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.tcp = True
    inst.is_connect = True
    inst.tcp_maxseg = None
    inst.gap_timeout = 1
    inst._ZK__session_id = 12345
    inst._ZK__reply_id = 6789
    inst._ZK__timeout = 1
    inst._ZK__sock = MagicMock()
    inst._ZK__sock.send.side_effect = sent.append
    remaining = iter(list(frames))

    def fake_recv(_size):
        try:
            item = next(remaining)
        except StopIteration:
            raise socket.timeout('drain complete')
        if item is _TIMEOUT:
            raise socket.timeout('drain complete')
        return item

    inst._ZK__sock.recv.side_effect = fake_recv
    return inst


_TIMEOUT = object()


def _bulk_frame(payload, pcmd=const.CMD_PREPARE_DATA, rid=3):
    """Frame ``payload`` as a WL10 TCP packet."""
    return (struct.pack('<HHI', const.MACHINE_PREPARE_DATA_1,
                        const.MACHINE_PREPARE_DATA_2, 8 + len(payload))
            + struct.pack('<4H', pcmd, 0, 12345, rid)
            + payload)


class TestTemplateFixtures:
    """The builders must produce the documented on-wire table format."""

    def test_table_starts_with_matching_uint32_total_size(self):
        table = pack_template_table(ENTRIES)
        declared = int.from_bytes(table[:4], 'little')
        assert declared == len(table) - 4
        assert declared == sum(6 + len(t) for *_head, t in ENTRIES)
        assert table[4:10] == b'\x26\x00\x07\x00\x00\x01'

    def test_empty_table_is_just_the_zero_total(self):
        assert pack_template_table([]) == b'\x00\x00\x00\x00'


class TestParseTemplates:
    """_wl10_parse_templates must build standard-compatible Finger objects."""

    def test_bare_table_parses_into_fingers(self, zk_instance):
        table = pack_template_table(ENTRIES)
        parsed = zk_instance._wl10_parse_templates(table)
        assert parsed == [
            Finger(7, 0, 1, TEMPLATE_A),
            Finger(7, 1, 1, TEMPLATE_B),
            Finger(11, 0, 0, TEMPLATE_A[:16]),
        ]
        assert [f.size for f in parsed] == [len(TEMPLATE_A), len(TEMPLATE_B), 16]

    def test_framed_table_parses_into_fingers(self, zk_instance):
        table = pack_template_table(ENTRIES)
        framed = (
            (4 + len(table)).to_bytes(4, 'little')
            + (0x9FB0).to_bytes(4, 'little')
            + len(table).to_bytes(4, 'little')
            + table
        )
        parsed = zk_instance._wl10_parse_templates(
            zk_instance._wl10_template_body(framed))
        assert parsed == [
            Finger(7, 0, 1, TEMPLATE_A),
            Finger(7, 1, 1, TEMPLATE_B),
            Finger(11, 0, 0, TEMPLATE_A[:16]),
        ]

    def test_empty_table_returns_no_templates(self, zk_instance):
        assert zk_instance._wl10_parse_templates(pack_template_table([])) == []

    def test_missing_total_size_fails_closed(self, zk_instance):
        with pytest.raises(ZKErrorResponse, match='[Tt]runcated'):
            zk_instance._wl10_parse_templates(b'\x01\x02')

    def test_truncated_body_fails_closed(self, zk_instance):
        table = pack_template_table(ENTRIES)
        with pytest.raises(ZKErrorResponse, match='[Tt]runcated'):
            zk_instance._wl10_parse_templates(table[:-4])

    def test_overlong_declared_total_fails_closed(self, zk_instance):
        table = bytearray(pack_template_table(ENTRIES))
        table[0:4] = (len(table) + 32).to_bytes(4, 'little')
        with pytest.raises(ZKErrorResponse, match='[Tt]runcated'):
            zk_instance._wl10_parse_templates(bytes(table))

    def test_corrupt_entry_size_below_header_fails_closed(self, zk_instance):
        table = bytearray(pack_template_table(ENTRIES))
        table[4:6] = (2).to_bytes(2, 'little')
        with pytest.raises(ZKErrorResponse, match='size'):
            zk_instance._wl10_parse_templates(bytes(table))

    def test_entry_size_overrunning_table_fails_closed(self, zk_instance):
        table = bytearray(pack_template_table(ENTRIES))
        table[4:6] = (len(table)).to_bytes(2, 'little')
        with pytest.raises(ZKErrorResponse, match='size'):
            zk_instance._wl10_parse_templates(bytes(table))

    def test_trailing_partial_header_fails_closed(self, zk_instance):
        table = pack_template_table([ENTRIES[0]])
        corrupt = table + b'\x08\x00\x07\x00'
        corrupt = bytearray(corrupt)
        corrupt[0:4] = (len(corrupt) - 4).to_bytes(4, 'little')
        with pytest.raises(ZKErrorResponse, match='[Tt]runcated'):
            zk_instance._wl10_parse_templates(bytes(corrupt))


class TestWl10GetTemplates:
    """The read path must use raw CMD 7 and never the buffered reader."""

    def test_reads_through_the_data_wrrq_wrapper(self, zk_instance):
        table = pack_template_table(ENTRIES)
        zk_instance._wl10_read_raw_command = MagicMock(return_value=table)
        zk_instance.read_with_buffer = MagicMock(
            side_effect=AssertionError('buffered reader must not be used'))

        templates = zk_instance.wl10_get_templates()

        zk_instance._wl10_read_raw_command.assert_called_once_with(
            const.CMD_DATA_WRRQ, TEMPLATE_REQUEST)
        assert [f.uid for f in templates] == [7, 7, 11]

    def test_builds_the_exact_wire_request(self):
        """The drain must send CMD_DATA_WRRQ + pack('<bhii', 1, 7, 2, 0)."""
        payload = pack_template_table(ENTRIES)
        framed = (len(payload).to_bytes(4, 'little')
                  + (0x9FB0).to_bytes(4, 'little')
                  + len(payload).to_bytes(4, 'little') + payload)
        sent = []
        zk = _zk_with_fake_socket([_bulk_frame(framed)], sent)

        templates = zk.wl10_get_templates()

        assert [f.uid for f in templates] == [7, 7, 11]
        assert len(sent) == 1, 'the template read must issue exactly one request'
        command, command_string = _decode_sent(sent[0])
        assert command == const.CMD_DATA_WRRQ == 1503
        assert command_string == struct.pack('<bhii', 1, 7, 2, 0)

    def test_user_and_attendance_raw_commands_stay_bare(self):
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_read_raw_command(const.CMD_USERTEMP_RRQ)
        assert {_decode_sent(frame) for frame in sent} == {(const.CMD_USERTEMP_RRQ, b'')}

        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_read_raw_command(const.CMD_ATTLOG_RRQ)
        assert {_decode_sent(frame) for frame in sent} == {(const.CMD_ATTLOG_RRQ, b'')}

    def test_empty_response_fails_closed(self, zk_instance):
        zk_instance._wl10_read_raw_command = MagicMock(return_value=b'')
        with pytest.raises(ZKErrorResponse):
            zk_instance.wl10_get_templates()

    def test_announcement_then_valid_table_returns_fingers(self):
        """The announcement is followed by one synchronous 1504 chunk read."""
        table = pack_template_table(ENTRIES)
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_OK, _announcement(len(table)), 10),
             _chunk_frame(const.CMD_DATA, table, 11)],
            sent)

        templates = zk.wl10_get_templates()

        assert [f.uid for f in templates] == [7, 7, 11]
        assert [_decode_sent(f) for f in sent] == [
            (const.CMD_DATA_WRRQ, TEMPLATE_REQUEST),
            (1504, struct.pack('<ii', 0, len(table))),
            RELEASE,
        ]

    def test_large_table_is_read_in_max_chunk_slices(self):
        """No chunk may exceed the standard 0xFFC0 chunk size."""
        announced = 0xFFC0 + 1000
        sent = []
        # _wl10_read_announced_body only issues the chunk reads; the
        # announcement itself is already parsed by this point.
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'A' * 0xFFC0, 11),
             _chunk_frame(const.CMD_DATA, b'B' * 1000, 12)],
            sent)

        data = zk._wl10_read_announced_body(announced)

        assert data == b'A' * 0xFFC0 + b'B' * 1000
        assert [_decode_sent(f) for f in sent] == [
            (1504, struct.pack('<ii', 0, 0xFFC0)),
            (1504, struct.pack('<ii', 0xFFC0, 1000)),
        ]

    def test_zero_prefix_announcement_still_fetches_the_whole_table(self):
        """A total=0 prefix must not shorten the fetch the announcement asked for.

        Live on all three devices the read requested only 4 bytes, the
        device answered 4 bytes, and the table prefix then read as
        total=0, so templates were reported as a complete count of 0
        while 18-23 KB of announced bytes stayed unread. The announced
        total is the byte count of the whole buffered response, so every
        announced byte is fetched before anything is parsed.
        """
        table = pack_template_table([(1, 0, 1, b'\x00' * 16)])
        announced = len(table)
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_ACK_OK, _announcement(announced), 10),
            _chunk_frame(const.CMD_DATA, table, 11),
        ], sent)

        templates = zk.wl10_get_templates()

        assert [f.uid for f in templates] == [1]
        assert [_decode_sent(f) for f in sent] == [
            (const.CMD_DATA_WRRQ, TEMPLATE_REQUEST),
            (1504, struct.pack('<ii', 0, announced)),
            RELEASE,
        ]

    def test_zero_total_prefix_in_a_large_announcement_fails_closed(self):
        """Announcement > 4 with a total=0 body is a contradiction, not 0 templates."""
        announced = 512
        zero_prefix = b'\x00' * announced
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_ACK_OK, _announcement(announced), 10),
            _chunk_frame(const.CMD_DATA, zero_prefix, 11),
        ], sent)

        with pytest.raises(ZKErrorResponse):
            zk.wl10_get_templates()
        # The whole announced body was still fetched before parsing, and
        # the device buffer is released even on failure.
        assert [_decode_sent(f) for f in sent] == [
            (const.CMD_DATA_WRRQ, TEMPLATE_REQUEST),
            (1504, struct.pack('<ii', 0, announced)),
            RELEASE,
        ]

    def test_announced_table_is_fully_covered_without_gaps(self):
        """Chunk requests must cover exactly ``[0, announced)`` with no gaps."""
        announced = 0xFFC0 + 1000
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_DATA, b'A' * 0xFFC0, 11),
            _chunk_frame(const.CMD_DATA, b'B' * 1000, 12),
        ], sent)

        data = zk._wl10_read_announced_body(announced)

        assert len(data) == announced
        requests = [_decode_sent(frame) for frame in sent]
        assert [command for command, _body in requests] == [1504, 1504]
        cursor = 0
        for _command, body in requests:
            start, size = struct.unpack('<ii', body)
            assert start == cursor, 'chunks must be contiguous with no gaps'
            cursor += size
        assert cursor == announced, 'the announced bytes must be consumed exactly'

    def test_requires_wl10_mode(self, zk_instance):
        zk_instance.wl10 = False
        zk_instance._wl10_read_raw_command = MagicMock()
        with pytest.raises(ZKErrorResponse, match='WL10'):
            zk_instance.wl10_get_templates()
        zk_instance._wl10_read_raw_command.assert_not_called()


class TestAnnouncement:
    """Only the observed 13-byte prepare/read announcement is accepted."""

    def test_live_announcement_shapes_parse(self, zk_instance):
        for name, raw, size in LIVE_ANNOUNCEMENTS:
            assert zk_instance._wl10_parse_announcement(raw) == size, name

    @pytest.mark.parametrize('label, raw', [
        ('wrong length', _announcement(4096)[:-1]),
        ('longer than 13', _announcement(4096) + b'\x00'),
        ('nonzero prefix', b'\x01' + _announcement(4096)[1:]),
        ('unequal sizes', b'\x00' + struct.pack('<II', 4096, 4097) + b'\x00' * 4),
        ('zero size', _announcement(0)),
        ('above the maximum', _announcement(MAX_ANNOUNCED_SIZE + 1)),
    ])
    def test_malformed_announcement_fails_closed(self, zk_instance, label, raw):
        with pytest.raises(ZKErrorResponse):
            zk_instance._wl10_parse_announcement(raw)

    def test_announcement_size_limit_is_explicit(self, zk_instance):
        assert zk_instance._wl10_parse_announcement(
            _announcement(MAX_ANNOUNCED_SIZE)) == MAX_ANNOUNCED_SIZE
        with pytest.raises(ZKErrorResponse, match='size'):
            zk_instance._wl10_parse_announcement(
                _announcement(MAX_ANNOUNCED_SIZE + 1))

    def test_base_max_chunk(self):
        assert ZK.WL10_MAX_CHUNK == 0xFFC0

    def test_chunk_uses_the_synchronous_cmd_data_shape(self):
        """1504 answers with CMD_DATA in the first recv, like the standard reader."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 4, 11)], sent)

        assert zk._wl10_read_announced_chunk(0, 4) == b'X' * 4
        assert [_decode_sent(f) for f in sent] == [(1504, struct.pack('<ii', 0, 4))]

    def test_chunk_read_does_not_use_the_bulk_drain(self):
        """The ACK/silence drain is the wrong transport for a chunk response."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 4, 11)], sent)
        zk._wl10_read_raw_command = MagicMock(side_effect=AssertionError(
            'the chunk read must not use the ACK-terminated bulk drain'))

        assert zk._wl10_read_announced_chunk(0, 4) == b'X' * 4

    def test_prepare_framed_chunk_response_fails_closed(self):
        """The prepare/announcement bulk shape is not a chunk response."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_PREPARE_DATA, struct.pack('<I', 4) + b'ABCD', 11)],
            sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 4)

    def test_ack_only_chunk_response_fails_closed(self):
        """A bare ACK with no CMD_DATA payload is not a chunk response."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_OK, b'', 10)], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 4)

    def test_trailing_bytes_after_a_full_chunk_fail_closed(self):
        """Bytes beyond the requested size are a desync, not extra data.

        Appending them to the payload is how a later bulk frame gets
        swallowed into the table.
        """
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 12, 11)], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 4)

    def test_chunk_read_does_not_swallow_trailing_bulk_traffic(self):
        """A chunk read consumes its own response only."""
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_DATA, b'X' * 4, 11),
            _chunk_frame(const.CMD_ACK_OK, _announcement(4096), 10),
        ], sent)

        assert zk._wl10_read_announced_chunk(0, 4) == b'X' * 4
        # The trailing bulk frame is still available to the next consumer.
        assert zk._wl10_parse_announcement(
            zk._wl10_read_raw_command(const.CMD_USERTEMP_RRQ)) == 4096

    def test_chunk_request_carries_the_next_reply_id(self):
        """The chunk request advances the reply_id exactly once."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 4, 2000)], sent)
        before = zk._ZK__reply_id

        zk._wl10_read_announced_chunk(0, 4)

        assert _sent_rid(sent[0]) == before + 1

    def test_chunk_response_reply_id_is_authoritative(self):
        """The CMD_DATA response rid wins and is not advanced twice."""
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_DATA, b'X' * 4, 2000),
            _chunk_frame(const.CMD_DATA, b'Y' * 4, 2001),
        ], sent)

        assert zk._wl10_read_announced_chunk(0, 4) == b'X' * 4
        assert zk._ZK__reply_id == 2000
        assert zk._wl10_read_announced_chunk(4, 4) == b'Y' * 4

        _first_rid, second_rid = (_sent_rid(frame) for frame in sent)
        assert second_rid == 2000 + 1, 'the next request must build on the response rid'
        assert zk._ZK__reply_id == 2001

    def test_a_subsequent_bulk_read_uses_the_committed_reply_id(self):
        """After a template read, a raw cmd 9 read stays in sync."""
        sent = []
        zk = _zk_with_fake_socket([
            _chunk_frame(const.CMD_DATA, b'X' * 4, 2000),
            _bulk_frame(b'\x00' * 72, rid=2001),
        ], sent)

        zk._wl10_read_announced_chunk(0, 4)
        assert zk._wl10_read_raw_command(const.CMD_USERTEMP_RRQ) == b'\x00' * 72

        assert [_decode_sent(frame)[0] for frame in sent] == [1504, const.CMD_USERTEMP_RRQ]
        assert _sent_rid(sent[1]) == 2000 + 1, 'the user read must build on the chunk rid'

    def test_stream_starts_safe(self):
        assert ZK.__new__(ZK)._wl10_stream_safe is True

    def test_chunk_failure_marks_the_stream_unsafe(self):
        """A failed chunk read leaves unread bytes, so the stream is unsafe."""
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(const.CMD_ACK_OK, b'', 10)], sent)
        assert zk._wl10_stream_safe is True

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_body(64)

        assert zk._wl10_stream_safe is False
        # The isolated template read must not go on to touch user/attendance.
        assert [struct.unpack('<4H', frame[8:16])[0] for frame in sent] == [1504]

    def test_rejected_chunk_range_leaves_the_stream_safe(self):
        """A range rejected before any send cannot desync the stream."""
        sent = []
        zk = _zk_with_fake_socket([], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 0)
        assert zk._wl10_stream_safe is True

    def test_overlong_chunk_response_fails_closed(self):
        """More bytes than requested is a desync, not extra data."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 64, 11)], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 4)

    def test_chunk_reads_must_be_nonnegative_and_bounded(self):
        sent = []
        zk = _zk_with_fake_socket([], sent)
        for start, size in ((-1, 16), (0, -16), (0, 0)):
            with pytest.raises(ZKErrorResponse):
                zk._wl10_read_announced_chunk(start, size)
        assert sent == [], 'no socket send may happen for a rejected chunk'

    def test_short_chunk_data_fails_closed(self):
        announced = 512
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'X' * 100, 11)], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_body(announced)

    def test_terminal_ack_error_fails_closed(self):
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(const.CMD_ACK_ERROR, b'', 10)], sent)
        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_announced_chunk(0, 64)

    def test_announced_but_invalid_table_fails_closed_once(self):
        """A structurally valid announcement followed by garbage must not retry 1503."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_OK, _announcement(64), 10),
             _chunk_frame(const.CMD_DATA, b'\xaa' * 64, 11)],
            sent)
        with pytest.raises(ZKErrorResponse):
            zk.wl10_get_templates()
        assert [_decode_sent(f) for f in sent] == [
            (const.CMD_DATA_WRRQ, TEMPLATE_REQUEST),
            (1504, struct.pack('<ii', 0, 64)),
            RELEASE,
        ]

    def test_announcement_with_wrong_length_payload_fails_closed(self):
        """A truncated fetch after a valid announcement still fails closed."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_OK, _announcement(512), 10),
             _chunk_frame(const.CMD_DATA, b'X' * 200, 11)],
            sent)
        with pytest.raises(ZKErrorResponse):
            zk.wl10_get_templates()
        assert [command for command, _body in map(_decode_sent, sent)] == [
            const.CMD_DATA_WRRQ, 1504, const.CMD_FREE_DATA]


class TestCmd88UserTemplate:
    """Per-user/per-finger template read over command 88.

    The standard reader sends ``pack('hb', uid, temp_id)`` to command 88
    and treats the response as a ``CMD_DATA`` chunk, dropping the final
    byte and any trailing six zero bytes. WL10 firmware is the same
    command, but every ambiguous or truncated outcome must fail closed
    instead of being retried or padded.
    """

    @pytest.mark.parametrize('fid', list(range(10)))
    def test_wire_bytes_cover_every_fid(self, fid):
        sent = []
        zk = _zk_with_fake_socket(
            [_template_frame(TEMPLATE_A, 11)], sent)

        finger = zk._wl10_read_user_template(7, fid)

        assert finger.fid == fid
        assert [_decode_sent(frame) for frame in sent] == [
            (88, struct.pack('<hb', 7, fid))]

    def test_present_template_returns_a_finger(self):
        sent = []
        zk = _zk_with_fake_socket([_template_frame(TEMPLATE_A, 11)], sent)

        finger = zk._wl10_read_user_template(7, 0)

        assert isinstance(finger, Finger)
        assert (finger.uid, finger.fid, finger.valid) == (7, 0, 1)
        assert bytes(finger.template) == TEMPLATE_A

    def test_template_bytes_ending_in_zeros_are_preserved(self):
        """Only the pad is stripped; template bytes that are zero survive."""
        template = TEMPLATE_A + b'\x00' * 6
        sent = []
        zk = _zk_with_fake_socket([_template_frame(template, 11)], sent)

        assert bytes(zk._wl10_read_user_template(7, 0).template) == template

    def test_explicit_absence_returns_none(self):
        """A bare ACK with no payload is the device saying "no template"."""
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(const.CMD_ACK_OK, b'', 11)], sent)

        assert zk._wl10_read_user_template(7, 0) is None

    def test_ack_error_is_explicit_absence(self):
        """A complete ACK_ERROR is the firmware saying "no template here".

        Live read-only runs returned a fully parsed ACK_ERROR on the very
        first bounded command-88 query on all three devices, deterministically,
        while users, attendance and the standard table read stayed complete.
        That makes ACK_ERROR this firmware's absence answer for a uid/fid, not
        an ambiguous transport failure — so it is not an error and it leaves
        the session safe.
        """
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(const.CMD_ACK_ERROR, b'', 11)], sent)

        assert zk._wl10_read_user_template(7, 0) is None
        assert zk._wl10_stream_safe is True
        assert [command for command, _body in map(_decode_sent, sent)] == [88]

    def test_ack_error_syncs_the_authoritative_reply_id(self):
        """Absence still commits the response rid, so the next send is in sync."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_ERROR, b'', 2000),
             _template_frame(TEMPLATE_A, 2001)], sent)

        assert zk._wl10_read_user_template(7, 0) is None
        assert zk._ZK__reply_id == 2000

        finger = zk._wl10_read_user_template(7, 1)

        assert bytes(finger.template) == TEMPLATE_A
        # The header carries the pre-increment rid: 6789 -> 6790 on the wire,
        # then the absence answer's rid 2000 -> 2001 on the next request.
        assert [_sent_rid(frame) for frame in sent] == [6790, 2001]
        assert zk._ZK__reply_id == 2001

    def test_truncated_response_fails_closed(self):
        """A frame that declares more payload than it carries is a desync."""
        sent = []
        frame = _chunk_frame(const.CMD_DATA, TEMPLATE_A, 11)
        # Declare a longer section than the frame actually carries.
        lying = frame[:4] + struct.pack('<I', len(frame) - 8 + 64) + frame[8:]
        zk = _zk_with_fake_socket([lying], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, 0)

        assert zk._wl10_stream_safe is False

    def test_unknown_status_fails_closed(self):
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(0x4242, TEMPLATE_A, 11)], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, 0)

    def test_prepare_data_status_records_its_shape(self):
        """CMD_PREPARE_DATA is recorded before its body is read.

        The status, the frame's declared length and the payload length are
        the facts needed to choose a transport, and none of them is
        biometric.
        """
        body = TEMPLATE_A + b'\x00' * 6 + b'\x01'
        sent = []
        zk = _zk_with_fake_socket([
            _prepare_frame(len(body), 10),
            _chunk_frame(const.CMD_DATA, body, 11),
            _chunk_frame(const.CMD_ACK_OK, b'', 12),
            _TIMEOUT,
        ], sent)

        zk._wl10_read_user_template(7, 0)

        assert zk._wl10_last_data_response == {
            'status': const.CMD_PREPARE_DATA, 'declared': 16, 'payload_len': 8,
            'rid': 10}

    def test_prepare_data_pushes_the_body_after_the_announcement(self):
        """The announcement promises a size; the device then pushes the body.

        Live on a fingerprint-bearing target the announce frame carried an
        8-byte payload (the size twice) and no data at all, and the template
        arrived in the frames that followed, ended by the terminal ACK. The
        pushed body keeps the standard reader's shape: the template, six
        zero padding bytes and a terminator byte.
        """
        body = TEMPLATE_A + b'\x00' * 6 + b'\x01'
        sent = []
        zk = _zk_with_fake_socket([
            _prepare_frame(len(body), 10),
            _chunk_frame(const.CMD_DATA, body, 11),
            _chunk_frame(const.CMD_ACK_OK, b'', 12),
            _TIMEOUT,
        ], sent)

        finger = zk._wl10_read_user_template(7, 0)

        assert isinstance(finger, Finger)
        assert (finger.uid, finger.fid, finger.valid) == (7, 0, 1)
        assert bytes(finger.template) == TEMPLATE_A
        assert [command for command, _body in map(_decode_sent, sent)] == [88]
        assert zk._ZK__reply_id == 12, 'the terminal ACK is authoritative'
        assert zk._wl10_stream_safe is True

    def test_pushed_body_shorter_than_announced_fails_closed(self):
        """A short push is a desync, never a shorter template."""
        body = TEMPLATE_A + b'\x00' * 6 + b'\x01'
        sent = []
        zk = _zk_with_fake_socket([
            _prepare_frame(len(body) + 64, 10),
            _chunk_frame(const.CMD_DATA, body, 11),
            _chunk_frame(const.CMD_ACK_OK, b'', 12),
            _TIMEOUT,
        ], sent)

        with pytest.raises(ZKErrorResponse, match='pushed template body'):
            zk._wl10_read_user_template(7, 0)

        assert zk._wl10_stream_safe is False

    def test_pushed_body_longer_than_announced_fails_closed(self):
        """Bytes beyond the announced size are a desync, not extra data."""
        body = TEMPLATE_A + b'\x00' * 6 + b'\x01'
        sent = []
        zk = _zk_with_fake_socket([
            _prepare_frame(len(body) - 2, 10),
            _chunk_frame(const.CMD_DATA, body, 11),
            _chunk_frame(const.CMD_ACK_OK, b'', 12),
            _TIMEOUT,
        ], sent)

        with pytest.raises(ZKErrorResponse, match='pushed template body'):
            zk._wl10_read_user_template(7, 0)

    def test_push_without_a_terminal_ack_fails_closed(self):
        """Every bulk-shaped read on this firmware ends with a terminal ACK.

        Without it the reply_id cannot be committed, so the session cannot
        be reused for the next uid.
        """
        body = TEMPLATE_A + b'\x00' * 6 + b'\x01'
        sent = []
        zk = _zk_with_fake_socket([
            _prepare_frame(len(body), 10),
            _chunk_frame(const.CMD_DATA, body, 11),
            _TIMEOUT,
        ], sent)

        with pytest.raises(ZKErrorResponse, match='terminal ACK'):
            zk._wl10_read_user_template(7, 0)

        assert zk._wl10_stream_safe is False

    @pytest.mark.parametrize('announced', [0, MAX_ANNOUNCED_SIZE + 1])
    def test_implausible_announced_size_fails_closed_before_any_push_read(self, announced):
        """An announcement drives a read loop, so its size is validated."""
        sent = []
        zk = _zk_with_fake_socket([_prepare_frame(announced, 10)], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, 0)

        assert [command for command, _body in map(_decode_sent, sent)] == [88]

    def test_absence_records_no_shape(self):
        """The recorded shape reflects the last classified response only."""
        sent = []
        zk = _zk_with_fake_socket([_chunk_frame(const.CMD_ACK_ERROR, b'', 11)], sent)

        assert zk._wl10_read_user_template(7, 0) is None
        assert zk._wl10_last_data_response == {
            'status': const.CMD_ACK_ERROR, 'declared': 8, 'payload_len': 0,
            'rid': 11}

    def test_empty_after_padding_is_absence_not_a_zero_length_finger(self):
        """A payload of only padding carries no template data."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_DATA, b'\x00' * 7, 11)], sent)

        assert zk._wl10_read_user_template(7, 0) is None

    def test_a_desynced_session_refuses_the_next_read(self):
        """After a failed template read the session has unread bytes.

        Command 88 starts a transfer the device finishes on its own.
        Abandoning one is the confirmed trigger for the state in which the
        firmware answers every later template read with ACK_ERROR, and
        enough of them make it refuse sessions entirely until it is
        restarted. Poking a desynced session again is what compounds a bad
        read into that state, so the next read is refused instead.
        """
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_UNAUTH, b'', 11)], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, 0)
        assert zk._wl10_stream_safe is False

        with pytest.raises(ZKErrorResponse, match='out of sync'):
            zk._wl10_read_user_template(7, 1)

        assert [command for command, _body in map(_decode_sent, sent)] == [88], \
            'no request may follow a desynchronized read'

    @pytest.mark.parametrize('fid', [-1, 10, 11, 255])
    def test_fid_outside_zero_to_nine_is_refused_before_any_send(self, fid):
        sent = []
        zk = _zk_with_fake_socket([], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, fid)

        assert sent == [], 'no request may be sent for a rejected fid'

    def test_ambiguous_response_is_never_retried(self):
        """One logical attempt: a sent request leaves the session uncertain."""
        sent = []
        zk = _zk_with_fake_socket(
            [_chunk_frame(const.CMD_ACK_UNAUTH, b'', 11)], sent)

        with pytest.raises(ZKErrorResponse):
            zk._wl10_read_user_template(7, 0)

        assert [command for command, _body in map(_decode_sent, sent)] == [88]
        assert zk._wl10_stream_safe is False

    def test_scan_continues_through_every_fid_when_all_are_absent(self):
        """Absence is normal data: the scan covers every fid and stays safe."""
        sent = []
        frames = [_chunk_frame(const.CMD_ACK_ERROR, b'', 1000 + fid)
                  for fid in range(10)]
        zk = _zk_with_fake_socket(frames, sent)
        zk._wl10_template_uids = set()

        result = zk.wl10_scan_user_templates([7])

        assert result == {7: []}
        assert [_decode_sent(frame) for frame in sent] == [
            (88, struct.pack('<hb', 7, fid)) for fid in range(10)]
        assert zk._wl10_stream_safe is True
        assert zk._ZK__reply_id == 1009


class TestScanUserTemplates:
    """Bulk scan over provided real UIDs and fid 0..9."""

    def test_scan_covers_every_fid_for_every_uid(self):
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(return_value=None)

        zk.wl10_scan_user_templates([7, 11])

        assert zk._wl10_read_user_template.call_args_list == [
            mock_call(uid, fid) for uid in (7, 11) for fid in range(10)]

    def test_scan_never_probes_reserved_template_slots(self):
        """Interleaved template slots are not users and must not be read."""
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_template_uids = {11}
        zk._wl10_read_user_template = MagicMock(return_value=None)

        zk.wl10_scan_user_templates([7, 11, 3])

        probed = {call.args[0] for call in zk._wl10_read_user_template.call_args_list}
        assert probed == {7, 3}, 'the reserved slot uid must never be probed'

    def test_scan_returns_present_templates_per_uid(self):
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_template_uids = set()
        templates = {0: Finger(7, 0, 1, TEMPLATE_A), 3: Finger(7, 3, 1, TEMPLATE_B)}
        zk._wl10_read_user_template = MagicMock(
            side_effect=lambda uid, fid: templates.get(fid))

        result = zk.wl10_scan_user_templates([7])

        assert [finger.fid for finger in result[7]] == [0, 3]

    def test_scan_counts_absences_without_inventing_templates(self):
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(return_value=None)

        result = zk.wl10_scan_user_templates([7, 11])

        assert result == {7: [], 11: []}

    def test_scan_fails_closed_on_a_read_error(self):
        """A failed read must not be reported as "this user has no template"."""
        sent = []
        zk = _zk_with_fake_socket([], sent)
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(
            side_effect=ZKErrorResponse('template read failed'))

        with pytest.raises(ZKErrorResponse):
            zk.wl10_scan_user_templates([7])

    def test_scan_refuses_when_not_in_wl10_mode(self, zk_instance):
        zk_instance.wl10 = False
        with pytest.raises(ZKErrorResponse, match='WL10'):
            zk_instance.wl10_scan_user_templates([7])


class TestUserFingerprints:
    """The per-user yes/no view: who has a fingerprint enrolled."""

    def test_reports_presence_and_absence_as_booleans(self):
        """Only presence is reported: the fid a template answers on is not
        stable across sessions on this firmware, so it is not something a
        caller can branch on.
        """
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        present = {(7, 2), (11, 0)}
        zk._wl10_read_user_template = MagicMock(
            side_effect=lambda uid, fid: Finger(uid, fid, 1, TEMPLATE_A)
            if (uid, fid) in present else None)

        assert zk.wl10_user_fingerprints([7, 11, 13]) == {7: True, 11: True, 13: False}

    def test_a_present_fid_ends_that_user_s_scan(self):
        """A user with a fingerprint costs one exchange per finger until it is found."""
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(return_value=None)

        assert zk.wl10_user_fingerprints(
            [7], require_certified=False) == {7: False}
        assert zk._wl10_read_user_template.call_args_list == [
            mock_call(7, fid) for fid in range(10)]

        zk._wl10_read_user_template.reset_mock()
        zk._wl10_read_user_template.side_effect = (
            lambda uid, fid: Finger(uid, fid, 1, TEMPLATE_A) if fid == 2 else None)

        assert zk.wl10_user_fingerprints([7]) == {7: True}
        assert zk._wl10_read_user_template.call_args_list == [
            mock_call(7, fid) for fid in range(3)]

    def test_reads_the_user_table_when_no_users_are_given(self):
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk.wl10_get_users = MagicMock(return_value=[
            User(7, 'a', 0, user_id='1'), User(11, 'b', 0, user_id='2')])
        zk._wl10_read_user_template = MagicMock(return_value=None)

        assert zk.wl10_user_fingerprints(require_certified=False) == {
            7: False, 11: False}
        zk.wl10_get_users.assert_called_once_with()

    def test_reserved_template_slots_are_never_probed(self):
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = {11}
        zk._wl10_read_user_template = MagicMock(return_value=None)

        assert zk.wl10_user_fingerprints(
            [7, 11], require_certified=False) == {7: False}

    def test_a_failed_read_raises_instead_of_reporting_absence(self):
        """A false "no fingerprint" is the one error this must not make."""
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(
            side_effect=ZKErrorResponse('read failed'))

        with pytest.raises(ZKErrorResponse):
            zk.wl10_user_fingerprints([7])

    def test_a_scan_that_finds_nothing_is_not_certified(self):
        """A device refusing every template read looks exactly like a device
        with no fingerprints. Only a found template proves the device is
        answering command 88, so an all-absent scan must not be reported as
        "nobody has a fingerprint" without the caller saying so.
        """
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(return_value=None)

        with pytest.raises(ZKErrorResponse, match='restart'):
            zk.wl10_user_fingerprints([7, 11])

        assert zk.wl10_user_fingerprints(
            [7, 11], require_certified=False) == {7: False, 11: False}

    def test_a_found_template_certifies_the_rest_of_the_scan(self):
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk._wl10_read_user_template = MagicMock(
            side_effect=lambda uid, fid: Finger(uid, fid, 1, TEMPLATE_A)
            if uid == 11 else None)

        assert zk.wl10_user_fingerprints([7, 11]) == {7: False, 11: True}

    def test_an_empty_user_table_is_not_a_failure(self):
        """No users at all is not the same as a device that answered nothing."""
        zk = _zk_with_fake_socket([], [])
        zk._wl10_template_uids = set()
        zk.wl10_get_users = MagicMock(return_value=[])
        zk._wl10_read_user_template = MagicMock(return_value=None)

        assert zk.wl10_user_fingerprints() == {}

    def test_wl10_user_fingerprints_requires_wl10_mode(self, zk_instance):
        zk_instance.wl10 = False
        with pytest.raises(ZKErrorResponse, match='WL10'):
            zk_instance.wl10_user_fingerprints([7])


class TestGetTemplatesDispatch:
    """Native get_templates must prefer the WL10 path in WL10 mode."""

    def test_dispatch_to_wl10(self, zk_instance):
        expected = [Finger(7, 0, 1, TEMPLATE_A)]
        zk_instance.wl10_get_templates = MagicMock(return_value=expected)
        zk_instance.read_sizes = MagicMock()
        zk_instance.read_with_buffer = MagicMock()
        assert zk_instance.get_templates() == expected
        zk_instance.wl10_get_templates.assert_called_once_with()
        zk_instance.read_with_buffer.assert_not_called()

    def test_non_wl10_path_unchanged(self, zk_instance):
        zk_instance.wl10 = False
        zk_instance.fingers = 0
        zk_instance.read_sizes = MagicMock()
        zk_instance.wl10_get_templates = MagicMock(
            side_effect=AssertionError('must not use WL10 path'))
        assert zk_instance.get_templates() == []
        zk_instance.wl10_get_templates.assert_not_called()
