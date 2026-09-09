"""Offline contract tests for the read-only WL10 capture probe."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "wl10_probe_read.py"


def _load_probe():
    spec = importlib.util.spec_from_file_location("wl10_probe_read", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_class(calls, *, failures=()):
    failures = set(failures)

    class FakeZK:
        def __init__(self, *args, **kwargs):
            self.calls = calls
            self._wl10_template_uids = {7, 11}
            self._parser_counts = {}

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

    return FakeZK


def test_read_order_is_allowlisted_and_read_only(monkeypatch, tmp_path):
    mod = _load_probe()
    calls = []
    monkeypatch.setattr(mod, "CapturingZK", _fake_class(calls))

    assert mod.main(["10.0.0.2", "--output-dir", str(tmp_path / "capture")]) == 0
    assert calls == [
        "connect", "get_device_name", "get_platform", "get_firmware_version", "get_serialnumber",
        "get_mac", "get_face_version", "get_fp_version", "get_extend_fmt", "get_user_extend_fmt",
        "get_face_fun_on", "get_compat_old_firmware", "get_network_params", "get_pin_width", "get_time",
        "read_sizes", "wl10_get_users", "wl10_get_attendance", "disconnect",
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
    monkeypatch.setattr(mod.ZK, "_wl10_read_raw_command", lambda self, code: payloads[code])
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


def test_real_capturing_client_fails_closed_on_forbidden_command(monkeypatch, tmp_path):
    mod = _load_probe()
    zk = mod.CapturingZK("127.0.0.1", wl10=True, ommit_ping=True, capture_dir=tmp_path)
    sent = []

    def fake_send(self, command, command_string=b"", response_size=8):
        sent.append(command)
        return {"status": True, "code": mod.const.CMD_ACK_OK}

    monkeypatch.setattr(mod.ZK, "_ZK__send_command", fake_send)
    with pytest.raises(Exception, match="not allowed"):
        zk.free_data()
    assert sent == []
    assert zk._ZK__send_command(mod.const.CMD_OPTIONS_RRQ)["status"] is True
    assert sent == [mod.const.CMD_OPTIONS_RRQ]


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
