"""Offline contract tests for the read-only WL10 capture probe."""
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from unittest.mock import MagicMock

from zk.finger import Finger

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "wl10_probe_read.py"


def _load_probe():
    spec = importlib.util.spec_from_file_location("wl10_probe_read", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_class(calls, *, failures=(), scan=None):
    failures = set(failures)

    class FakeZK:
        def __init__(self, *args, **kwargs):
            self.calls = calls
            self._wl10_template_uids = {7, 11}
            self._wl10_sidecar_uids = {7, 11}
            self._parser_counts = {}
            self.users = 2
            self.fingers = 3
            self.records = 3
            self.cards = 0
            self.fingers_cap = 10
            self.users_cap = 100
            self.rec_cap = 1000
            self.fingers_av = 7
            self.users_av = 98
            self.rec_av = 997
            self.faces = 0
            self.faces_cap = 0

        def connect(self):
            self.calls.append("connect")
            if "connect" in failures:
                raise RuntimeError("connect failed")
            return self

        def disconnect(self):
            self.calls.append("disconnect")
            if "disconnect" in failures:
                raise RuntimeError("disconnect failed")
            return True

        def _read(self, name, value=None):
            self.calls.append(name)
            if name in failures:
                raise RuntimeError(f"{name} failed")
            return value

        def get_device_name(self):
            return self._read("get_device_name", "WL10")

        def get_platform(self):
            return self._read("get_platform", "AK3750")

        def get_firmware_version(self):
            return self._read("get_firmware_version", "6.60")

        def get_serialnumber(self):
            return self._read("get_serialnumber", "SERIAL")

        def get_mac(self):
            return self._read("get_mac", "MAC")

        def get_face_version(self):
            return self._read("get_face_version", 1)

        def get_fp_version(self):
            return self._read("get_fp_version", 1)

        def get_extend_fmt(self):
            return self._read("get_extend_fmt", 1)

        def get_user_extend_fmt(self):
            return self._read("get_user_extend_fmt", 1)

        def get_face_fun_on(self):
            return self._read("get_face_fun_on", 1)

        def get_compat_old_firmware(self):
            return self._read("get_compat_old_firmware", 0)

        def get_network_params(self):
            return self._read("get_network_params", {"ip": "10.0.0.2"})

        def get_pin_width(self):
            return self._read("get_pin_width", 9)

        def get_time(self):
            return self._read("get_time", "now")

        def read_sizes(self):
            return self._read("read_sizes", True)

        def wl10_get_users(self):
            self._read("wl10_get_users")
            if "wl10_get_users" in failures:
                raise RuntimeError("incomplete users")
            users = [SimpleNamespace(uid=7), SimpleNamespace(uid=11)]
            self._parser_counts["users"] = {"declared": 4, "candidate": 3}
            return users

        def wl10_get_attendance(self):
            self._read("wl10_get_attendance")
            if "wl10_get_attendance" in failures:
                raise RuntimeError("incomplete attendance")
            attendance = [SimpleNamespace(uid=7), SimpleNamespace(uid=11), SimpleNamespace(uid=7)]
            self._parser_counts["attendance"] = {"declared": 8, "candidate": 3}
            return attendance

        def wl10_get_templates(self):
            self._read("wl10_get_templates")
            if "wl10_get_templates" in failures:
                raise RuntimeError("incomplete templates")
            return [Finger(7, 0, 1, TEMPLATE_A),
                    Finger(7, 1, 1, TEMPLATE_B),
                    Finger(11, 0, 0, TEMPLATE_A[:16])]

        def wl10_scan_user_templates(self, uids):
            self._read("wl10_scan_user_templates", ())
            if "wl10_scan_user_templates" in failures:
                raise RuntimeError("incomplete user templates")
            if scan is not None:
                return scan(self, uids)
            return {7: [Finger(7, 0, 1, TEMPLATE_A), Finger(7, 3, 1, TEMPLATE_B)], 11: []}

    return FakeZK


TEMPLATE_A = bytes(range(1, 33))
TEMPLATE_B = bytes(range(33, 73))


def test_skip_template_table_keeps_the_fragile_read_out(monkeypatch, tmp_path):
    """The standard table fetch can wedge a device; this flag avoids it.

    Live, the standard table announced 68474 bytes and the first 1504 chunk
    timed out, and every later template read on that device answered
    ACK_ERROR. A production sweep that only needs "who has a fingerprint"
    must be able to leave that read out entirely.
    """
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))
    out = tmp_path / "capture"

    assert mod.main(["10.0.0.2", "--skip-template-table",
                     "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())

    assert summary["templates"] == {
        "status": "skipped", "complete": None, "count": None}
    assert "wl10_get_templates" not in calls
    assert "wl10_scan_user_templates" in calls
    assert summary["outcome"] == "ok"
    assert summary["user_templates"]["status"] == "ok"


def test_nameless_sidecars_are_reported_without_becoming_users(monkeypatch, tmp_path):
    """Ghost records are visible in the summary, never in the user list."""
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))
    out = tmp_path / "capture"

    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())

    assert summary["users"]["sidecars"] == [7, 11]
    assert summary["users"]["count"] == 2


def test_read_order_is_allowlisted_and_read_only(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))

    assert mod.main(["10.0.0.2", "--output-dir", str(tmp_path / "capture")]) == 0
    assert calls == [
        "connect", "get_device_name", "get_platform", "get_firmware_version", "get_serialnumber",
        "get_mac", "get_face_version", "get_fp_version", "get_extend_fmt", "get_user_extend_fmt",
        "get_face_fun_on", "get_compat_old_firmware", "get_network_params", "get_pin_width", "get_time",
        "read_sizes", "wl10_get_users", "wl10_get_attendance", "wl10_scan_user_templates",
        "wl10_get_templates", "disconnect",
    ]
    assert not {"set_user", "delete_user", "clear_data", "restart", "poweroff", "set_time", "unlock", "enable_device", "disable_device"} & set(calls)


def test_required_output_dir_and_collision(monkeypatch, tmp_path):
    mod = _load_probe()
    monkeypatch.setattr(mod, "CapturingZK", _fake_class([]))

    with pytest.raises(SystemExit):
        mod.main(["10.0.0.2"])

    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "marker.txt"
    marker.write_text("keep")
    assert mod.main(["10.0.0.2", "--output-dir", str(existing)]) != 0
    assert marker.read_text() == "keep"


def test_operation_error_is_recorded_and_later_reads_continue(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls, failures={"get_mac"}))

    assert mod.main(["10.0.0.2", "--output-dir", str(tmp_path / "capture")]) != 0
    assert "get_face_version" in calls
    assert "wl10_get_users" in calls
    summary = json.loads((tmp_path / "capture" / "summary.json").read_text())
    assert summary["operations"]["get_mac"] == {
        "status": "error", "type": "RuntimeError", "message": "get_mac failed",
    }


def test_connect_failure_and_incomplete_bulk_are_nonzero(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls, failures={"connect"}))
    out = tmp_path / "connect-failure"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) != 0
    assert calls == ["connect", "disconnect"]

    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls, failures={"wl10_get_users", "wl10_get_attendance"}))
    out = tmp_path / "incomplete"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) != 0
    assert "wl10_get_attendance" in calls
    summary = json.loads((out / "summary.json").read_text())
    assert summary["users"]["status"] == "error"
    assert summary["attendance"]["status"] == "error"


def test_capture_files_are_stable_and_hashable(monkeypatch, tmp_path):
    mod = _load_probe()
    payloads = {9: b"users", 13: b"attendance"}
    monkeypatch.setattr(mod.ZK, "_wl10_read_raw_command",
                        lambda self, code, command_string=b'': payloads[code])
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 41)

    assert zk._wl10_read_raw_command(9) == b"users"
    zk._wl10_last_ack = (2001, 42)
    assert zk._wl10_read_raw_command(13) == b"attendance"
    with pytest.raises(Exception, match="not allowed"):
        zk._wl10_read_raw_command(8)

    assert (tmp_path / "cmd_09_001.bin").read_bytes() == b"users"
    assert (tmp_path / "cmd_13_001.bin").read_bytes() == b"attendance"
    assert [(c["command"], c["filename"], c["bytes"], c["sha256"], c["ack"]) for c in zk._captures] == [
        (9, "cmd_09_001.bin", 5, hashlib.sha256(b"users").hexdigest(), {"command": 2000, "reply_id": 41}),
        (13, "cmd_13_001.bin", 10, hashlib.sha256(b"attendance").hexdigest(), {"command": 2001, "reply_id": 42}),
    ]


def test_help_is_offline_and_succeeds():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "--output-dir" in proc.stdout
    assert "--tcp-maxseg" in proc.stdout
    assert "--gap-timeout" in proc.stdout


def test_invalid_ip_rejected_before_construction(monkeypatch, tmp_path):
    mod = _load_probe()

    class ExplodingZK:
        def __init__(self, *args, **kwargs):
            raise AssertionError("constructor must not run for invalid IP")

    monkeypatch.setattr(mod, "CapturingZK", ExplodingZK)
    out = tmp_path / "capture"
    assert mod.main(["127.0.0.1;echo pwned", "--output-dir", str(out)]) != 0
    assert not out.exists()


def test_real_capturing_client_allows_read_housekeeping(monkeypatch, tmp_path):
    mod = _load_probe()
    zk = mod.CapturingZK("127.0.0.1", wl10=True, ommit_ping=True, capture_dir=tmp_path)
    sent = []

    def fake_send(self, command, command_string=b"", response_size=8):
        sent.append(command)
        return {"status": True, "code": mod.const.CMD_ACK_OK}

    monkeypatch.setattr(mod.ZK, "_ZK__send_command", fake_send)
    assert zk.free_data() is True
    zk._clear_error()
    assert sent == [
        mod.const.CMD_FREE_DATA,
        mod.const.CMD_ACK_ERROR,
        mod.const.CMD_ACK_UNKNOWN,
        mod.const.CMD_ACK_UNKNOWN,
        mod.const.CMD_ACK_UNKNOWN,
    ]


def test_real_capturing_client_fails_closed_on_mutation_helpers(monkeypatch, tmp_path):
    mod = _load_probe()
    zk = mod.CapturingZK("127.0.0.1", wl10=False, ommit_ping=True, capture_dir=tmp_path)
    sent = []

    def fake_send(self, command, command_string=b"", response_size=8):
        sent.append(command)
        return {"status": True, "code": mod.const.CMD_ACK_OK}

    monkeypatch.setattr(mod.ZK, "_ZK__send_command", fake_send)
    for invoke in (
        lambda: zk.set_user(uid=1, user_id="1"),
        lambda: zk.delete_user(uid=1),
        zk.clear_data,
        zk.restart,
    ):
        with pytest.raises(Exception, match="not allowed"):
            invoke()
    assert sent == []


def test_real_wl10_capturing_client_blocks_raw_mutations_before_socket_send(monkeypatch, tmp_path):
    mod = _load_probe()
    zk = mod.CapturingZK("127.0.0.1", wl10=True, ommit_ping=True, capture_dir=tmp_path)
    sent = []
    sock = MagicMock()
    sock.send.side_effect = lambda payload: sent.append(payload)
    sock.recv.return_value = b""
    monkeypatch.setattr(zk, "_ZK__sock", sock)

    for invoke in (
        lambda: zk.wl10_set_user(uid=1, user_id="1"),
        lambda: zk.wl10_delete_user(uid=1),
        zk.wl10_reboot,
        lambda: zk.set_user(uid=1, user_id="1"),
        lambda: zk.delete_user(uid=1),
        zk.restart,
        zk._wl10_refresh_data,
        zk._wl10_read_ack,
        zk.refresh_data,
    ):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            invoke()

    assert sent == []

def test_symlinked_output_and_evidence_targets_are_not_overwritten(monkeypatch, tmp_path):
    mod = _load_probe()
    target = tmp_path / "target"
    target.write_text("keep")
    out = tmp_path / "capture"
    out.symlink_to(target)
    monkeypatch.setattr(mod, "CapturingZK", _fake_class([]))
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) != 0
    assert target.read_text() == "keep"

    capture_target = tmp_path / "capture-target"
    capture_target.write_bytes(b"keep")
    capture_dir = tmp_path / "capture-dir"
    capture_dir.mkdir()
    (capture_dir / "cmd_09_001.bin").symlink_to(capture_target)
    with pytest.raises(FileExistsError):
        mod._write_exclusive(capture_dir / "cmd_09_001.bin", b"overwrite")
    assert capture_target.read_bytes() == b"keep"

    summary_target = tmp_path / "summary-target"
    summary_target.write_text("keep")
    (capture_dir / "summary.json").symlink_to(summary_target)
    with pytest.raises(FileExistsError):
        mod._write_exclusive(capture_dir / "summary.json", b"overwrite")
    assert summary_target.read_text() == "keep"


def test_stdout_and_summary_redact_uid_bounds_and_password(monkeypatch, tmp_path, capsys):
    mod = _load_probe()
    monkeypatch.setattr(mod, "CapturingZK", _fake_class([]))
    out = tmp_path / "capture"
    assert mod.main(["10.0.0.2", "--password", "1234", "--output-dir", str(out)]) == 0
    stdout = capsys.readouterr().out
    assert "min_uid" not in stdout
    assert "max_uid" not in stdout
    summary = json.loads((out / "summary.json").read_text())
    assert summary["constructor"]["password_configured"] is True
    assert "password" not in summary["constructor"]
    assert summary["users"]["min_uid"] == 7
    assert summary["users"]["parser_counts"]["accepted"] == 2


def test_real_connect_suppresses_hidden_metadata_reads(monkeypatch):
    mod = _load_probe()
    zk = mod.CapturingZK("127.0.0.1", wl10=True, ommit_ping=True)
    commands = []

    monkeypatch.setattr(zk.helper, "test_tcp", lambda: 1)
    monkeypatch.setattr(zk, "_ZK__create_socket", lambda: None)

    def fake_send(self, command, command_string=b"", response_size=8):
        commands.append(command)
        self._ZK__header = (command, 0, 123, 1)
        return {"status": True, "code": mod.const.CMD_ACK_OK}

    monkeypatch.setattr(mod.ZK, "_ZK__send_command", fake_send)
    zk.connect()
    assert commands == [mod.const.CMD_CONNECT]


def test_summary_contains_real_parser_counts(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))
    out = tmp_path / "capture"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["users"]["parser_counts"] == {"declared": 4, "candidate": 3, "accepted": 2}
    assert summary["attendance"]["parser_counts"] == {"declared": 8, "candidate": 3, "accepted": 3}
def test_capture_writes_remain_bound_to_original_directory_after_replacement(tmp_path):
    mod = _load_probe()
    original = tmp_path / 'capture'
    original.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    fd = os.open(original, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    moved = tmp_path / 'moved'
    original.rename(moved)
    original.symlink_to(outside, target_is_directory=True)
    try:
        mod._write_exclusive(fd, 'capture.bin', b'keep-local')
    finally:
        os.close(fd)
    assert (moved / 'capture.bin').read_bytes() == b'keep-local'
    assert not (outside / 'capture.bin').exists()


def test_probe_summary_writes_new_directory(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, 'CapturingZK', _fake_class(calls))
    out = tmp_path / 'capture'
    assert mod.main(['10.0.0.2', '--output-dir', str(out)]) == 0
    assert (out / 'summary.json').exists()


def test_summary_records_stream_safety(monkeypatch, tmp_path):
    """Stream safety is reported, so an unsafe session is never read as clean."""
    mod = _load_probe()
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 51)

    assert mod._stream_summary(zk) == {"safe": True}
    zk._wl10_stream_safe = False
    assert mod._stream_summary(zk) == {"safe": False}


def test_template_summary_errors_are_never_ok_with_count_zero(monkeypatch, tmp_path):
    """An error summary must not present itself as a complete empty table."""
    mod = _load_probe()
    summary = mod._template_summary([])
    assert summary["status"] == "ok"
    assert summary["count"] == 0
    error = mod._bulk_error(mod.ZKErrorResponse("table fetch failed"))
    assert error["status"] == "error"
    assert error.get("complete") is False


def test_user_template_summary_is_privacy_safe(monkeypatch, tmp_path):
    """Per-user template evidence carries no names, badges or raw bytes."""
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))
    out = tmp_path / "capture"

    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())

    user_templates = summary["user_templates"]
    assert user_templates["status"] == "ok"
    assert user_templates["count"] == 2
    assert user_templates["per_uid"] == {
        "7": {"count": 2, "present_fids": [0, 3]},
        "11": {"count": 0, "present_fids": []},
    }
    assert user_templates["entries"] == [
        {"uid": 7, "fid": 0, "valid": 1, "size": len(TEMPLATE_A),
         "sha256": hashlib.sha256(TEMPLATE_A).hexdigest()},
        {"uid": 7, "fid": 3, "valid": 1, "size": len(TEMPLATE_B),
         "sha256": hashlib.sha256(TEMPLATE_B).hexdigest()},
    ]
    serialized = json.dumps(user_templates)
    for leaked in (TEMPLATE_A.hex(), TEMPLATE_B.hex(), "mark", "badge", "name"):
        assert leaked not in serialized, leaked
    assert "template" not in json.dumps(user_templates["entries"][0])


def test_user_template_scan_runs_after_users_and_before_standard_table(monkeypatch, tmp_path):
    """The per-user scan needs the parsed user table and is independent of it."""
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))

    assert mod.main(["10.0.0.2", "--output-dir", str(tmp_path / "capture")]) == 0

    assert calls.index("wl10_get_users") < calls.index("wl10_scan_user_templates")
    assert calls.index("wl10_scan_user_templates") < calls.index("wl10_get_templates")


def test_user_template_errors_fail_closed_without_leaking_bytes(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(
        mod, "CapturingZK", _fake_class(calls, failures={"wl10_scan_user_templates"}))
    out = tmp_path / "capture"

    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) != 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["user_templates"]["status"] == "error"
    assert summary["user_templates"]["complete"] is False
    assert summary["outcome"] == "error"


def test_cmd_88_is_reachable_only_through_the_bounded_method(monkeypatch, tmp_path):
    """No generic command API: only uid+fid 0..9 inside the scan is permitted."""
    mod = _load_probe()
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {88: 0, 7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 51)
    zk.wl10 = True
    zk._known_user_uids = {7, 11}
    zk._wl10_template_uids = {11}

    monkeypatch.setattr(mod.ZK, "_wl10_read_user_template",
                        lambda self, uid, fid: None)

    # A real, non-reserved uid with a valid fid is allowed.
    assert zk._wl10_read_user_template(7, 3) is None
    # A reserved template slot is never a user.
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_user_template(11, 0)
    # An unknown uid is refused.
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_user_template(99, 0)
    # fids outside 0..9 are refused.
    for fid in (-1, 10, 40):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_user_template(7, fid)


def test_cmd_88_writes_no_raw_biometric_file(monkeypatch, tmp_path):
    """A present template is a biometric identifier and never reaches disk."""
    mod = _load_probe()
    monkeypatch.setattr(mod.ZK, "_wl10_read_user_template",
                        lambda self, uid, fid: Finger(uid, fid, 1, TEMPLATE_A))
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk.wl10 = True
    zk._known_user_uids = {7}
    zk._wl10_template_uids = set()
    zk._wl10_last_ack = (2000, 51)
    zk._ZK__reply_id = 6789

    assert zk._wl10_read_user_template(7, 3) is not None

    assert list(tmp_path.iterdir()) == []
    assert zk._captures == [{
        "command": 88, "wire_command": 88, "uid": 7, "fid": 3,
        "status": "present", "size": len(TEMPLATE_A),
        "sha256": hashlib.sha256(TEMPLATE_A).hexdigest(),
        "request_rid": 6789, "rid": None,
    }]
    serialized = json.dumps(zk._captures)
    for leaked in (TEMPLATE_A.hex(), "mark", "name", "badge", "template"):
        assert leaked not in serialized


def test_scan_writes_no_raw_biometric_files(monkeypatch, tmp_path):
    """The whole bounded scan, present and absent fids, persists no bytes."""
    mod = _load_probe()
    monkeypatch.setattr(
        mod.ZK, "_wl10_read_user_template",
        lambda self, uid, fid: Finger(uid, fid, 1, TEMPLATE_A) if fid == 0 else None)
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk.wl10 = True
    zk._known_user_uids = {7, 11}
    zk._wl10_template_uids = {11}
    zk._wl10_last_ack = (2000, 51)

    result = zk.wl10_scan_user_templates([7, 11])

    assert [finger.fid for finger in result[7]] == [0]
    # A reserved slot is skipped entirely, not reported as an empty user.
    assert 11 not in result
    assert list(tmp_path.iterdir()) == []
    assert sorted(
        (capture["uid"], capture["fid"]) for capture in zk._captures) == [
            (7, fid) for fid in range(10)]
    assert sorted({capture["status"] for capture in zk._captures}) == ["absent", "present"]
    serialized = json.dumps(zk._captures)
    for leaked in (TEMPLATE_A.hex(), "mark", "name", "badge", "template"):
        assert leaked not in serialized


def test_unclassified_cmd_88_status_is_recorded_without_bytes(monkeypatch, tmp_path):
    """A prepare-data answer is evidence, and longitudes are not biometric.

    Live read-only runs returned CMD_PREPARE_DATA (1500) for a uid/fid that
    holds a template. Recording the status and both lengths is what makes
    the next transport choice measurable; no payload byte is ever stored.
    """
    mod = _load_probe()

    def fake(self, uid, fid):
        self._wl10_last_data_response = {
            "status": 1500, "declared": 21, "payload_len": 13, "rid": 4242}
        raise mod.ZKErrorResponse("template response status 1500 is not CMD_DATA")

    monkeypatch.setattr(mod.ZK, "_wl10_read_user_template", fake)
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk.wl10 = True
    zk._known_user_uids = {7}
    zk._wl10_template_uids = set()
    zk._ZK__reply_id = 6789

    with pytest.raises(mod.ZKErrorResponse):
        zk._wl10_read_user_template(7, 0)

    assert list(tmp_path.iterdir()) == []
    assert zk._captures == [{
        "command": 88, "wire_command": 88, "uid": 7, "fid": 0,
        "status": "error", "wire_status": 1500, "payload_len": 13,
        "request_rid": 6789, "rid": 4242,
    }]


def test_absent_fids_are_recorded_as_metadata_only(monkeypatch, tmp_path):
    """Every explicit absence is recorded, and still nothing is written."""
    mod = _load_probe()
    monkeypatch.setattr(mod.ZK, "_wl10_read_user_template",
                        lambda self, uid, fid: None)
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk.wl10 = True
    zk._known_user_uids = {7}
    zk._wl10_template_uids = set()
    zk._wl10_last_ack = (2000, 51)

    assert zk.wl10_scan_user_templates([7]) == {7: []}

    assert list(tmp_path.iterdir()) == []
    assert [(capture["uid"], capture["fid"], capture["status"])
            for capture in zk._captures] == [
                (7, fid, "absent") for fid in range(10)]
    assert {capture["size"] for capture in zk._captures} == {0}
    assert zk._wl10_stream_safe is True


def test_users_are_recorded_for_the_bounded_cmd_88_guard(monkeypatch, tmp_path):
    """The scan guard needs the successfully parsed real-user uid set."""
    mod = _load_probe()
    seen = {}

    def capture_scan(self, uids):
        seen["known"] = set(getattr(self, "_known_user_uids", ()))
        seen["uids"] = list(uids)
        return {}

    monkeypatch.setattr(mod, "CapturingZK", _fake_class([], scan=capture_scan))

    assert mod.main(["10.0.0.2", "--output-dir", str(tmp_path / "capture")]) == 0
    assert seen["known"] == {7, 11}
    assert seen["uids"] == [7, 11]


def test_announcement_bounds_the_chunk_flow(monkeypatch, tmp_path):
    """A validated announcement is what unlocks bounded 1504 chunk reads."""
    mod = _load_probe()
    monkeypatch.setattr(mod.ZK, "_wl10_read_announced_chunk",
                        lambda self, start, size: b"chunk")
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 51)

    assert not hasattr(zk, "_wl10_announced_total")
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_announced_chunk(0, 16)

    announced = bytes.fromhex("00c6470000c64700007a343d00")
    assert zk._wl10_parse_announcement(announced) == 18374
    assert zk._wl10_announced_total == 18374
    # A chunk inside the announced table is allowed; the table fits one chunk.
    assert zk._wl10_read_announced_chunk(0, 16) == b"chunk"
    assert zk._wl10_read_announced_chunk(0, 18374) == b"chunk"
    # Past the announced end, or past one max chunk, is refused.
    for start, size in ((18374, 16), (0, 18374 + 1)):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_announced_chunk(start, size)



def test_template_wrapper_is_allowed_and_direct_cmd_7_still_blocked(monkeypatch, tmp_path):
    mod = _load_probe()
    payloads = {9: b"users", 13: b"attendance", 1503: b"templates"}
    monkeypatch.setattr(mod.ZK, "_wl10_read_raw_command",
                        lambda self, code, command_string=b'': payloads[code])
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 41)
    request = struct.pack("<bhii", 1, mod.const.CMD_DB_RRQ, mod.const.FCT_FINGERTMP, 0)
    assert request == struct.pack("<bhii", 1, 7, 2, 0)
    assert zk._wl10_read_raw_command(mod.const.CMD_DATA_WRRQ, request) == b"templates"
    assert (tmp_path / "cmd_1503_001.bin").read_bytes() == b"templates"
    assert zk._captures == [{
        "command": mod.const.CMD_DB_RRQ, "wire_command": mod.const.CMD_DATA_WRRQ,
        "filename": "cmd_1503_001.bin", "bytes": 9,
        "sha256": hashlib.sha256(b"templates").hexdigest(),
        "ack": {"command": 2000, "reply_id": 41},
    }]
    # The defective direct request from the first increment stays blocked.
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_raw_command(mod.const.CMD_DB_RRQ)
    # So does any other payload on the allowed wire command.
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_raw_command(mod.const.CMD_DATA_WRRQ, struct.pack("<bhii", 1, 9, 0, 0))
    for blocked in (8, 10, 14, 15, 18, 19, 50):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_raw_command(blocked)


def test_template_chunk_command_is_bounded_and_not_generic(monkeypatch, tmp_path):
    """Command 1504 is reachable only through the bounded internal flow."""
    mod = _load_probe()
    calls = []

    def fake_chunk(self, start, size):
        calls.append((start, size))
        return b"chunk"

    monkeypatch.setattr(mod.ZK, "_wl10_read_announced_chunk", fake_chunk)
    zk = mod.CapturingZK.__new__(mod.CapturingZK)
    zk._capture_dir = tmp_path
    zk._capture_seq = {7: 0, 1503: 0, 1504: 0, 9: 0, 13: 0}
    zk._captures = []
    zk._wl10_last_ack = (2000, 51)
    zk._wl10_announced_total = 2 * 0xFFC0

    body = struct.pack("<ii", 0, 0xFFC0)
    assert zk._wl10_read_announced_chunk(0, 0xFFC0) == b"chunk"
    # Only the non-sensitive range metadata is recorded for the capture.
    assert calls == [(0, 0xFFC0)]
    assert zk._captures == [{
        "command": 1504, "wire_command": 1504, "filename": "cmd_1504_001.bin",
        "bytes": 5, "sha256": hashlib.sha256(b"chunk").hexdigest(),
        "ack": {"command": 2000, "reply_id": 51},
        "read": {"start": 0, "size": 0xFFC0},
    }]
    assert (tmp_path / "cmd_1504_001.bin").read_bytes() == b"chunk"

    # No generic arbitrary read: only non-negative sizes within one max chunk.
    for start, size in ((0, 0xFFC0 + 1), (0, 0), (0, -1), (-1, 16)):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_announced_chunk(start, size)
    # A chunk must also stay inside the range the device announced.
    for start, size in ((2 * 0xFFC0, 16), (0xFFC0, 0xFFC0 + 1)):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_announced_chunk(start, size)
    # With no validated announcement, no chunk read is permitted at all.
    zk._wl10_announced_total = None
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_announced_chunk(0, 16)
    zk._wl10_announced_total = 2 * 0xFFC0
    # Other bodies and other commands stay blocked.
    for code, bad_body in ((1504, b""), (1504, struct.pack("<iiii", 0, 0, 0, 0)),
                           (1502, struct.pack("<ii", 0, 16))):
        with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
            zk._wl10_read_raw_command(code, bad_body)
    # A request body on the bare raw reads is still rejected.
    with pytest.raises(mod.ZKErrorResponse, match="not allowed"):
        zk._wl10_read_raw_command(9, struct.pack("<ii", 0, 16))


def test_template_summary_is_privacy_safe_and_complete(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))
    out = tmp_path / "capture"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    templates = summary["templates"]
    assert templates["status"] == "ok"
    assert templates["count"] == 3
    assert templates["total_bytes"] == len(TEMPLATE_A) + len(TEMPLATE_B) + 16
    assert templates["per_uid"] == {"7": 2, "11": 1}
    assert templates["entries"] == [
        {"uid": 7, "fid": 0, "valid": 1, "size": len(TEMPLATE_A),
         "sha256": hashlib.sha256(TEMPLATE_A).hexdigest()},
        {"uid": 7, "fid": 1, "valid": 1, "size": len(TEMPLATE_B),
         "sha256": hashlib.sha256(TEMPLATE_B).hexdigest()},
        {"uid": 11, "fid": 0, "valid": 0, "size": 16,
         "sha256": hashlib.sha256(TEMPLATE_A[:16]).hexdigest()},
    ]
    assert templates["size_histogram"] == {"32": 1, "40": 1, "16": 1}
    blob = json.dumps(summary)
    assert TEMPLATE_A.hex() not in blob
    assert TEMPLATE_B.hex() not in blob
    assert "template" not in json.dumps(templates["entries"][0])
    assert "mark" not in blob
    assert summary["template_uids"] == [7, 11]


def test_template_errors_fail_closed_without_leaking_bytes(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls, failures={"wl10_get_templates"}))
    out = tmp_path / "capture"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) != 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["templates"]["status"] == "error"
    assert summary["templates"]["complete"] is False
    assert summary["outcome"] == "error"


def test_read_sizes_summary_preserves_analysis_counters(monkeypatch, tmp_path):
    mod = _load_probe()
    monkeypatch.setattr(mod, "CapturingZK", _fake_class([]))
    out = tmp_path / "capture"
    assert mod.main(["10.0.0.2", "--output-dir", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    sizes = summary["sizes"]
    assert sizes["users"] == 2
    assert sizes["fingers"] == 3
    assert sizes["records"] == 3
    assert sizes["users_cap"] == 100
    assert sizes["users_av"] == 98
    assert sizes["fingers_cap"] == 10
    assert sizes["fingers_av"] == 7
    assert sizes["rec_cap"] == 1000
    assert sizes["rec_av"] == 997
    assert sizes["faces"] == 0
    assert sizes["faces_cap"] == 0
    assert "password" not in json.dumps(sizes)
