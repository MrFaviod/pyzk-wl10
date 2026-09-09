"""Tests that native ZK methods dispatch to their WL10 counterparts.

RISK-1: the native ``set_user`` / ``delete_user`` / ``refresh_data``
methods were not aware of WL10 mode, so calling them on a WL10
connection fell through to the UDP/``__send_command`` path and failed
(the raw-TCP bulk path requires ``wl10_*`` helpers instead).
"""
from struct import pack
from unittest.mock import MagicMock

from zk import const
from zk.user import User


class TestNativeDispatchToWl10:
    """Native methods must delegate to wl10_* when ``self.wl10`` is True."""

    def test_refresh_data_dispatches_to_wl10(self, zk_instance):
        zk_instance._wl10_refresh_data = MagicMock(return_value=True)
        result = zk_instance.refresh_data()
        zk_instance._wl10_refresh_data.assert_called_once()
        assert result is True

    def test_set_user_dispatches_to_wl10(self, zk_instance):
        zk_instance.wl10_set_user = MagicMock(return_value=True)
        result = zk_instance.set_user(
            uid=100, name='Alice', privilege=0, password='',
            group_id='', user_id='999950', card=0)
        zk_instance.wl10_set_user.assert_called_once_with(
            uid=100, name='Alice', privilege=0, password='',
            group_id='', user_id='999950', card=0)
        assert result is True

    def test_delete_user_dispatches_to_wl10(self, zk_instance):
        zk_instance.wl10_delete_user = MagicMock(return_value=True)
        result = zk_instance.delete_user(uid=100)
        zk_instance.wl10_delete_user.assert_called_once_with(
            uid=100, user_id='')
        assert result is True

    def test_get_users_dispatches_to_wl10(self, zk_instance):
        users = [User(5, 'Alice', 0, '', '1', '259', 0),
                 User(6, 'Bob', 0, '', '1', '260', 0)]
        zk_instance._wl10_get_users = MagicMock(return_value=users)
        zk_instance.wl10_get_users = MagicMock(
            side_effect=zk_instance.wl10_get_users)
        zk_instance._ZK__send_command = MagicMock()
        zk_instance.users = 0
        zk_instance.next_uid = 1
        zk_instance.next_user_id = '1'
        result = zk_instance.get_users()
        zk_instance.wl10_get_users.assert_called_once_with()
        zk_instance._ZK__send_command.assert_not_called()
        assert result == users
        assert zk_instance.users == 2
        assert zk_instance.next_uid == 7
        assert zk_instance.next_user_id == '7'

    def test_restart_dispatches_to_wl10(self, zk_instance):
        zk_instance.wl10_reboot = MagicMock(return_value=True)
        zk_instance._ZK__send_command = MagicMock()
        result = zk_instance.restart()
        zk_instance.wl10_reboot.assert_called_once_with()
        zk_instance._ZK__send_command.assert_not_called()
        assert result is True


class TestNativeDeleteUserLargeUid:
    """M3: the native delete_user path must pack uid as unsigned short."""

    def test_large_uid_no_struct_error(self, zk_instance):
        # uid > 32767 overflowed the signed pack('h', uid) and raised
        # struct.error before the command could be sent.
        zk_instance.wl10 = False
        zk_instance.next_uid = 50000
        zk_instance._ZK__send_command = MagicMock(return_value={'status': True})
        zk_instance.refresh_data = MagicMock(return_value=True)

        zk_instance.delete_user(uid=40000)

        zk_instance._ZK__send_command.assert_called_once()
        command, command_string = zk_instance._ZK__send_command.call_args[0]
        assert command == const.CMD_DELETE_USER
        assert command_string == pack('<H', 40000)
