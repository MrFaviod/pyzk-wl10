class TestScanUserId:
    """Test _wl10_scan_user_id static method."""

    def test_digits_start(self, zk_class):
        rec = b'138\x00' + b'\x00' * 68
        assert zk_class._wl10_scan_user_id(rec) == '138'

    def test_digits_in_middle(self, zk_class):
        rec = b'\x00' * 10 + b'99999\x00' + b'\x00' * 57
        assert zk_class._wl10_scan_user_id(rec) == '99999'

    def test_digits_at_end(self, zk_class):
        rec = b'\x00' * 67 + b'209\x00'
        assert zk_class._wl10_scan_user_id(rec) == '209'

    def test_too_short(self, zk_class):
        rec = b'\x00' * 10 + b'99\x00' + b'\x00' * 59
        assert zk_class._wl10_scan_user_id(rec) == ''

    def test_too_long(self, zk_class):
        rec = b'\x00' * 10 + b'123456\x00' + b'\x00' * 55
        result = zk_class._wl10_scan_user_id(rec)
        assert len(result) <= 5
        assert result.isdigit()

    def test_no_digits(self, zk_class):
        rec = b'\x00' * 72
        assert zk_class._wl10_scan_user_id(rec) == ''

    def test_boundary_digit_after(self, zk_class):
        rec = b'\x00' * 5 + b'9876 ' + b'\x00' * 62
        assert zk_class._wl10_scan_user_id(rec) == '9876'

    def test_boundary_digit_no_fence(self, zk_class):
        rec = b'\x00' * 69 + b'123\x00'
        assert zk_class._wl10_scan_user_id(rec) == '123'
