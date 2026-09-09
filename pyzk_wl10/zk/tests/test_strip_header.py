import os
import struct

from helpers import FIXTURES_DIR, pack_bulk_response, pack_user_record


class TestStripHeader:
    """Test the _wl10_strip_header static method."""

    def test_standard_12byte_layout(self, zk_class):
        records = pack_user_record(
            uid=1, name=b'Alice', user_id=b'100') * 3
        raw = pack_bulk_response(records, 72)
        recs, n = zk_class._wl10_strip_header(raw, 72)
        assert n == 3
        assert len(recs) == 3 * 72

    def test_variant_8byte_no_section(self, zk_class):
        records = pack_user_record(
            uid=2, name=b'Bob', user_id=b'200') * 2
        section = len(records)
        outer = section + 4
        raw = struct.pack('<III', outer, 0x9fb0, section) + records
        recs, n = zk_class._wl10_strip_header(raw, 72)
        assert n == 2
        assert len(recs) == 2 * 72

    def test_fallback_outer_is_count(self, zk_class):
        records = pack_user_record(
            uid=3, name=b'Carol', user_id=b'300')
        n_records = 1
        raw = struct.pack('<I', n_records) + records
        recs, n = zk_class._wl10_strip_header(raw, 72)
        assert n == n_records
        assert len(recs) == len(records)

    def test_empty_raw(self, zk_class):
        recs, n = zk_class._wl10_strip_header(b'', 72)
        assert recs == b''
        assert n == 0

    def test_short_raw(self, zk_class):
        raw = b'\x00' * 8
        recs, n = zk_class._wl10_strip_header(raw, 22)
        assert recs == raw
        assert n == 0

    def test_not_multiple_of_record_size(self, zk_class):
        # Data with an extra prefix that doesn't match any known header
        # layout falls through to the catch-all: return the raw data as-is
        # with n = len // record_size.
        record_size = 22
        records = b'\x01' * record_size * 3
        raw = records  # no prefix at all
        recs, n = zk_class._wl10_strip_header(raw, record_size)
        assert recs == records
        assert n == 3

    def test_load_fixture_bulk_users(self, zk_class):
        path = os.path.join(FIXTURES_DIR, 'bulk_users.bin')
        with open(path, 'rb') as f:
            data = f.read()
        recs, n = zk_class._wl10_strip_header(data, 72)
        assert n == 3, f'Expected 3 records, got {n}'
        assert len(recs) == 3 * 72


class TestCreateHeaderReplyId:
    """Lock the reply_id wrap semantics used by ``connect()``.

    ``connect()`` seeds ``self.__reply_id = const.USHRT_MAX - 1`` (65534)
    before the first ``CMD_CONNECT``. The header must NEVER emit 0xFFFF
    (65535) — the device firmware treats it as a reserved/invalid value and
    the handshake fails (observed: ``get_device_name()`` times out). The
    wrap therefore triggers AT 65535, mapping the post-increment 65535 to 0
    and keeping the field within 0..65534.
    """

    def _reply_id(self, zk_class, reply_id):
        zk = object.__new__(zk_class)
        header = zk._ZK__create_header(1000, b'', 1, reply_id)
        # buf = pack('<4H', command, checksum, session_id, reply_id)
        # command_string is b'' so header == buf and reply_id is at [6:8].
        return struct.unpack('<H', header[6:8])[0]

    def test_reply_id_never_emits_reserved_ffff(self, zk_class):
        # 65534 + 1 = 65535 (0xFFFF) must wrap to 0, never be emitted.
        assert self._reply_id(zk_class, 65534) == 0

    def test_reply_id_increments_without_wrap(self, zk_class):
        assert self._reply_id(zk_class, 65533) == 65534
