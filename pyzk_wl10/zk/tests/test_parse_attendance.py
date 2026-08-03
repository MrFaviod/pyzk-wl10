from datetime import datetime
from helpers import (
    FIXTURES_DIR, pack_attendance_record, pack_bulk_response,
    encode_zk_time
)
from zk.const import WL10_ATT_RECORD_SIZE


class TestParseAttendance:
    """Test _wl10_parse_attendance and related logic."""

    def test_parse_valid(self, zk_instance):
        ts = encode_zk_time(datetime(2026, 7, 1, 14, 5, 38))
        rec = pack_attendance_record(
            uid=138, user_id=b'138', flag=1,
            timestamp=ts, status=1)
        raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
        atts = zk_instance._wl10_parse_attendance(raw)
        assert len(atts) == 1
        a = atts[0]
        assert a.uid == 138
        assert a.badge == '138'
        assert a.timestamp == datetime(2026, 7, 1, 14, 5, 38)
        assert a.status == 1

    def test_parse_with_users_map(self, zk_instance):
        ts = encode_zk_time(datetime(2026, 7, 1, 9, 0, 0))
        rec = pack_attendance_record(
            uid=5, user_id=b'138', flag=1,
            timestamp=ts, status=0)
        raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
        users_map = {
            '138': {'name': 'Rivarola Enciso, Juan A', 'badge': '138', 'uid': 5}
        }
        atts = zk_instance._wl10_parse_attendance(raw, users_map)
        assert len(atts) == 1
        a = atts[0]
        assert a.name == 'Rivarola Enciso, Juan A'
        assert a.badge == '138'

    def test_parse_skips_zero_ts(self, zk_instance):
        rec = pack_attendance_record(
            uid=999, user_id=b'', flag=1, timestamp=0, status=0)
        raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
        atts = zk_instance._wl10_parse_attendance(raw)
        assert len(atts) == 0, 'Should skip zero timestamp'

    def test_parse_skips_old_year(self, zk_instance):
        ts = encode_zk_time(datetime(1999, 12, 31, 23, 59, 59))
        rec = pack_attendance_record(
            uid=200, user_id=b'200', flag=1, timestamp=ts, status=0)
        raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
        atts = zk_instance._wl10_parse_attendance(raw)
        assert len(atts) == 0, 'Should skip 1999-timestamp records'

    def test_parse_empty_user_id_falls_back_to_uid(self, zk_instance):
        ts = encode_zk_time(datetime(2026, 7, 1, 14, 5, 38))
        rec = pack_attendance_record(
            uid=42, user_id=b'', flag=1, timestamp=ts, status=0)
        raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
        atts = zk_instance._wl10_parse_attendance(raw)
        assert len(atts) == 1
        assert atts[0].badge == '42'

    def test_parse_bulk_partial_valid(self, zk_instance):
        ts_valid = encode_zk_time(datetime(2026, 7, 1, 14, 5, 38))
        rec_valid = pack_attendance_record(
            uid=138, user_id=b'138', flag=1, timestamp=ts_valid, status=1)
        rec_zero = pack_attendance_record(
            uid=999, user_id=b'', flag=1, timestamp=0, status=0)
        raw = pack_bulk_response(rec_valid + rec_zero, WL10_ATT_RECORD_SIZE)
        atts = zk_instance._wl10_parse_attendance(raw)
        assert len(atts) == 1, 'Only the valid record should survive'
        assert atts[0].uid == 138

    def test_parse_status_label_maps_numbers(self, zk_instance):
        """status byte is a numeric punch state; label must map to a name."""
        ts = encode_zk_time(datetime(2026, 7, 1, 14, 5, 38))
        cases = [
            (0, 'Check-In'),      # entrada
            (1, 'Check-Out'),     # salida
            (2, 'Break-Out'),
            (3, 'Break-In'),
            (4, 'Overtime-In'),   # observado en 192.168.170.40
            (5, 'Overtime-Out'),
            (99, 'Unknown'),
        ]
        for status, expected in cases:
            rec = pack_attendance_record(
                uid=26, user_id=b'26', flag=1, timestamp=ts, status=status)
            raw = pack_bulk_response(rec, WL10_ATT_RECORD_SIZE)
            atts = zk_instance._wl10_parse_attendance(raw)
            assert len(atts) == 1
            a = atts[0]
            assert a.status == status, 'raw numeric status must be preserved'
            assert a.status_label == expected, (
                f'status {status} should map to {expected!r}, got {a.status_label!r}'
            )
