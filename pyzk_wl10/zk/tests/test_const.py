import os
import sys

# Ensure the library path is set
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
WL10_ROOT = os.path.join(ROOT, 'pyzk_wl10')
for p in (WL10_ROOT, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from zk import const
from zk.base import ZK


class TestConst:
    def test_wl10_record_sizes(self):
        assert const.WL10_USER_RECORD_SIZE == 72
        assert const.WL10_ATT_RECORD_SIZE == 22

    def test_ushrt_max(self):
        assert const.USHRT_MAX == 65535

    def test_user_privilege_constants(self):
        assert const.USER_DEFAULT == 0
        assert const.USER_ADMIN == 14

    def test_wl10_methods_exist(self):
        inst = object.__new__(ZK)
        assert hasattr(inst, 'wl10_get_users')
        assert hasattr(inst, 'wl10_get_attendance')
        assert hasattr(inst, 'wl10_set_user')
        assert hasattr(inst, 'wl10_delete_user')
