"""Tests for WL10 bulk-read resilience on unstable links.

Bella Vista (110.152) intermittently delivers truncated bulk responses:
the framing header announces more records than actually arrive. The old
code accepted the partial payload silently, dropping users/attendance
mid-way through the table. These tests lock the new contract: a
truncated response is retried (free_data + short backoff) and raises
ZKErrorResponse once retries are exhausted — never a silent partial
table.
"""
from datetime import datetime
from struct import pack, unpack
from unittest.mock import MagicMock, patch

import pytest
from helpers import encode_zk_time, pack_attendance_record, pack_bulk_response, pack_user_record

from zk import const
from zk.base import ZK
from zk.exception import ZKErrorResponse
from zk.user import User


def _build_wl10_zk():
    """Build a mock-backed ZK instance for WL10 read tests."""
    inst = object.__new__(ZK)
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.tcp = True
    inst.is_connect = True
    inst._ZK__session_id = 12345
    inst._ZK__reply_id = 6789
    inst._ZK__timeout = 5
    inst.next_uid = 1
    inst.next_user_id = '1'
    inst._ZK__sock = MagicMock()
    inst.free_data = MagicMock()
    return inst


def _two_user_records():
    return (pack_user_record(uid=5, name=b'Alice', user_id=b'259')
            + pack_user_record(uid=6, name=b'Bob', user_id=b'260'))


def _one_attendance_record():
    return pack_attendance_record(
        uid=26, user_id=b'26', flag=1,
        timestamp=encode_zk_time(datetime(2026, 7, 1, 14, 5, 38)),
        status=0)


def _truncated_bulk(records_bytes, record_size):
    """Frame a bulk whose header announces one record MORE than present."""
    full = pack_bulk_response(records_bytes, record_size)
    outer, device, section = unpack('<III', full[:12])
    return (pack('<III', outer + record_size, device, section + record_size)
            + records_bytes)


class TestWl10BulkIsComplete:
    """Truncation detection over the 12-byte bulk framing."""

    def test_complete_standard_layout(self):
        inst = _build_wl10_zk()
        raw = pack_bulk_response(_two_user_records(), const.WL10_USER_RECORD_SIZE)
        assert inst._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE) is True

    def test_complete_empty_bulk(self):
        inst = _build_wl10_zk()
        raw = pack_bulk_response(b'', const.WL10_USER_RECORD_SIZE)
        assert inst._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE) is True

    def test_truncated_announced_more_than_received(self):
        inst = _build_wl10_zk()
        raw = _truncated_bulk(_two_user_records(), const.WL10_USER_RECORD_SIZE)
        assert inst._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE) is False

    def test_short_prepare_ack_is_not_complete(self):
        inst = _build_wl10_zk()
        # Real capture from 110.152: PREPARE_DATA announce, zero records.
        raw = b'\x96\x0a\x00\x00\xb0\x9f\x00\x00'
        assert inst._wl10_bulk_is_complete(raw, const.WL10_ATT_RECORD_SIZE) is False

    def test_empty_is_not_complete(self):
        inst = _build_wl10_zk()
        assert inst._wl10_bulk_is_complete(b'', const.WL10_USER_RECORD_SIZE) is False

    def test_variant_section_at_offset_4(self):
        inst = _build_wl10_zk()
        records = _two_user_records()
        # 8-byte header form: outer + section header at offset 4.
        raw = pack('<II', 4 + len(records), len(records)) + records
        assert inst._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE) is True


class TestWl10GetUsersRetry:
    """get_users must retry truncated reads, never return a partial table."""

    def test_complete_first_try_returns_users(self):
        inst = _build_wl10_zk()
        inst._wl10_read_bulk_data = MagicMock(
            return_value=pack_bulk_response(_two_user_records(),
                                            const.WL10_USER_RECORD_SIZE))
        users = inst._wl10_get_users()
        assert len(users) == 2
        assert inst.free_data.call_count == 0, \
            'First attempt must not free_data (keeps current behavior)'

    def test_retry_after_truncation_succeeds(self):
        inst = _build_wl10_zk()
        truncated = _truncated_bulk(_two_user_records(), const.WL10_USER_RECORD_SIZE)
        complete = pack_bulk_response(_two_user_records(),
                                      const.WL10_USER_RECORD_SIZE)
        inst._wl10_read_bulk_data = MagicMock(side_effect=[truncated, complete])
        with patch('zk.base.time.sleep') as sleep:
            users = inst._wl10_get_users()
        assert len(users) == 2
        assert inst.free_data.call_count == 1, \
            'Retry must free_data first to settle the device'
        sleep.assert_called_once()

    def test_truncated_every_time_raises(self):
        inst = _build_wl10_zk()
        truncated = _truncated_bulk(_two_user_records(), const.WL10_USER_RECORD_SIZE)
        inst._wl10_read_bulk_data = MagicMock(return_value=truncated)
        with pytest.raises(ZKErrorResponse, match='complete user table'), patch('zk.base.time.sleep'):
            inst._wl10_get_users()

    def test_all_empty_raises(self):
        inst = _build_wl10_zk()
        inst._wl10_read_bulk_data = MagicMock(return_value=b'')
        with pytest.raises(ZKErrorResponse, match='complete user table'), patch('zk.base.time.sleep'):
            inst._wl10_get_users()


class TestWl10GetAttendanceTruncation:
    """Attendance must share the completeness gate."""

    def _inst_with_attendance_flow(self, bulk_value):
        inst = _build_wl10_zk()
        inst._wl10_get_users = MagicMock(
            return_value=[User(uid=26, name='Alice', privilege=0, user_id='26')])
        inst._wl10_read_bulk_data = MagicMock(return_value=bulk_value)
        return inst

    def test_complete_returns_attendance(self):
        raw = pack_bulk_response(_one_attendance_record(),
                                 const.WL10_ATT_RECORD_SIZE)
        inst = self._inst_with_attendance_flow(raw)
        att = inst._wl10_get_attendance()
        assert len(att) == 1

    def test_truncated_raises(self):
        raw = _truncated_bulk(_one_attendance_record(),
                              const.WL10_ATT_RECORD_SIZE)
        inst = self._inst_with_attendance_flow(raw)
        with pytest.raises(ZKErrorResponse, match='complete attendance log'), patch('zk.base.time.sleep'):
            inst._wl10_get_attendance()


class TestWl10AttendanceDedup:
    """110.152 firmware emits every attendance record twice (exact dupes).

    Dedup is by (user_id, timestamp, status) — identical punch events are
    collapsed, distinct punches (e.g. different status) are kept.
    """

    def _parse(self, records_bytes):
        raw = pack_bulk_response(records_bytes, const.WL10_ATT_RECORD_SIZE)
        inst = _build_wl10_zk()
        return inst._wl10_parse_attendance(raw, users_map=None)

    def _dup_pair(self):
        one = _one_attendance_record()
        return one + one

    def test_duplicate_exact_pair_collapses(self):
        att = self._parse(self._dup_pair())
        assert len(att) == 1, 'Two identical records must collapse to one'

    def test_non_consecutive_duplicates_also_collapse(self):
        one = _one_attendance_record()
        other = pack_attendance_record(
            uid=27, user_id=b'27', flag=1,
            timestamp=encode_zk_time(datetime(2026, 7, 2, 9, 0, 0)), status=1)
        att = self._parse(one + other + one)
        assert len(att) == 2, 'Interleaved duplicate must still collapse'

    def test_same_uid_timestamp_different_status_kept(self):
        one = _one_attendance_record()
        flip = pack_attendance_record(
            uid=26, user_id=b'26', flag=1,
            timestamp=encode_zk_time(datetime(2026, 7, 1, 14, 5, 38)), status=1)
        att = self._parse(one + flip)
        assert len(att) == 2, 'Same event with different status is NOT a duplicate'

    def test_all_duplicates_produce_unique_count(self):
        one = _one_attendance_record()
        att = self._parse(one * 6)
        assert len(att) == 1, 'Six copies of the same event must collapse to one'

    def test_empty_bulk_returns_empty_list(self):
        att = self._parse(b'')
        assert att == []


class TestWl10AttendanceMissingUser:
    """Bella Vista can deliver a user table missing a badge that
    attendance records still reference. The parser must fall back to the
    raw badge instead of crashing with KeyError.
    """

    def test_missing_badge_in_users_map_does_not_crash(self):
        raw = pack_bulk_response(_one_attendance_record(),
                                 const.WL10_ATT_RECORD_SIZE)
        inst = _build_wl10_zk()
        # users_map is non-empty but lacks the badge the record references
        # (Bella Vista delivered a partial user table) — must fall back to
        # the raw user_id, not raise KeyError.
        att = inst._wl10_parse_attendance(raw, users_map={'999': {'name': 'X', 'badge': '999', 'uid': 999}})
        assert len(att) == 1
        assert att[0].badge == '26', 'Badge falls back to the raw user_id'

    def test_partial_users_map_falls_back_gracefully(self):
        one = _one_attendance_record()
        other = pack_attendance_record(
            uid=27, user_id=b'999', flag=1,
            timestamp=encode_zk_time(datetime(2026, 7, 2, 9, 0, 0)), status=1)
        raw = pack_bulk_response(one + other, const.WL10_ATT_RECORD_SIZE)
        inst = _build_wl10_zk()
        # users_map knows uid 26 only — the b'999' record must not crash
        att = inst._wl10_parse_attendance(raw, users_map={'26': {'name': 'Alice', 'badge': '26', 'uid': 26}})
        assert len(att) == 2
        by_badge = {a.badge: a for a in att}
        assert by_badge['999'].status == 1, 'Record with missing user still parsed'
