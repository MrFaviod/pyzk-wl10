from datetime import datetime
from helpers import encode_zk_time


class TestDecodeZkTime:
    def test_decode_valid(self, zk_class):
        dt = datetime(2026, 7, 3, 9, 30, 45)
        ts = encode_zk_time(dt)
        result = zk_class._decode_zk_time(ts)
        assert result == dt, f'Expected {dt}, got {result}'

    def test_decode_zero(self, zk_class):
        """Value 0 is defined to return None (not the ZK epoch)."""
        assert zk_class._decode_zk_time(0) is None

    def test_decode_negative(self, zk_class):
        """0xFFFFFFFF decodes to year 2133, which is within range."""
        result = zk_class._decode_zk_time(0xFFFFFFFF)
        assert result is not None
        assert result.year >= 2000

    def test_decode_min_positive(self, zk_class):
        """Smallest positive value = 2000-01-01 00:00:01."""
        result = zk_class._decode_zk_time(1)
        assert result is not None
        assert result == datetime(2000, 1, 1, 0, 0, 1)

    def test_decode_bisextile(self, zk_class):
        dt = datetime(2024, 2, 29, 23, 59, 59)
        ts = encode_zk_time(dt)
        result = zk_class._decode_zk_time(ts)
        assert result == dt

    def test_decode_beyond_2099(self, zk_class):
        dt = datetime(2100, 1, 1, 0, 0, 0)
        ts = encode_zk_time(dt)
        result = zk_class._decode_zk_time(ts)
        # The year calculation `year = t + 2000` gives year 2100.
        assert result is None or result.year >= 2100

    def test_roundtrip(self, zk_class):
        dt = datetime(2026, 12, 25, 18, 0, 0)
        ts = encode_zk_time(dt)
        result = zk_class._decode_zk_time(ts)
        assert result == dt