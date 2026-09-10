"""Offline safety contract tests for the WL10 live runner."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "test_runner_wl10.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("test_runner_wl10", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _user(uid, badge, name="Alice", privilege=0, card=0):
    return SimpleNamespace(uid=uid, user_id=badge, badge=badge, name=name,
                           privilege=privilege, card=card)


def _fake_zk(calls, baselines, *, write_error=None, readback=None):
    class FakeZK:
        def __init__(self, *args, **kwargs):
            calls.append(("construct", args, kwargs))
            self._wl10_template_uids = {7}
            self._baselines = iter(baselines)
            self.write_error = write_error
            self.readback = readback

        def connect(self):
            calls.append("connect")

        def disconnect(self):
            calls.append("disconnect")

        def wl10_get_users(self):
            calls.append("read")
            return list(next(self._baselines))

        def wl10_set_user(self, **kwargs):
            calls.append(("write", kwargs))
            if self.write_error:
                raise self.write_error
            if self.readback is not None:
                self._baselines = iter([self.readback])
            return True

    return FakeZK


def _writes(calls):
    return [c for c in calls if isinstance(c, tuple) and c[0] == "write"]


def test_default_reads_baseline_and_never_writes(monkeypatch, capsys):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[_user(1, "123456")]]))

    assert mod.main(["10.0.0.2"]) == 0
    assert not _writes(calls)
    assert calls == [calls[0], "connect", "read", "disconnect"]
    out = capsys.readouterr().out
    assert "uid=8" in out and "badge=999950" in out
    assert "Alice" not in out and "123456" not in out


def test_missing_write_args_fails_before_connection(monkeypatch):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))

    assert mod.main(["10.0.0.2", "--write-one"]) != 0
    assert calls == []


@pytest.mark.parametrize(
    "extra",
    [["--write-one", "--uid", "6", "--user-id", "999950", "--evidence-json", "x.json"],
     ["--write-one", "--uid", "8", "--user-id", "999949", "--evidence-json", "x.json"],
     ["--write-one", "--uid", "8", "--user-id", "1000000", "--evidence-json", "x.json"]],
)
def test_invalid_explicit_values_fail_before_connection(monkeypatch, extra):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    assert mod.main(["10.0.0.2", *extra]) != 0
    assert calls == []


def test_occupied_or_template_uid_rejects_without_write(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[_user(8, "123456")]]))
    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) != 0
    assert not _writes(calls)

    calls.clear()
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    assert mod.main(["10.0.0.2", "--write-one", "--uid", "7",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) != 0
    assert not _writes(calls)


def test_valid_write_is_singular_regular_user_and_reads_back(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    written = _user(8, "999950", name="RE110-8")
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[], []], readback=[written]))
    evidence = tmp_path / "evidence.json"

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) == 0
    writes = _writes(calls)
    assert len(writes) == 1
    assert writes[0][1] == {"uid": 8, "user_id": "999950", "name": "RE110-8",
                            "privilege": mod.const.USER_DEFAULT, "card": 0}
    assert calls.count("read") == 3
    data = json.loads(evidence.read_text())
    assert data["outcome"] == "success"
    assert data["candidate"] == {"uid": 8, "user_id": "999950"}
    assert "Alice" not in evidence.read_text()


def test_failed_write_does_not_retry_or_cleanup(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[], []], write_error=RuntimeError("ACK_ERROR")))
    evidence = tmp_path / "failed.json"

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) != 0
    assert len(_writes(calls)) == 1
    assert not any(c in {"delete", "reboot", "refresh"} for c in calls if isinstance(c, str))
    assert json.loads(evidence.read_text())["stage"] == "write"


def test_readback_mismatch_does_not_retry_or_cleanup(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    wrong = _user(8, "999950", name="WRONG", privilege=mod.const.USER_DEFAULT)
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[], []], readback=[wrong]))
    evidence = tmp_path / "mismatch.json"

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) != 0
    assert len(_writes(calls)) == 1
    assert not any(c in {"delete", "reboot", "refresh"} for c in calls if isinstance(c, str))
    assert json.loads(evidence.read_text())["stage"] == "readback"


def test_evidence_collision_is_rejected_without_connection(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    evidence = tmp_path / "existing.json"
    evidence.write_text("keep")

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) != 0
    assert calls == []
    assert evidence.read_text() == "keep"

def test_write_one_rejects_multiple_ips_before_connection(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    evidence = tmp_path / "multi.json"

    assert mod.main(["10.0.0.2", "10.0.0.3", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) == 2
    assert calls == []


def test_default_evidence_path_rejects_before_connection(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    evidence = tmp_path / "default.json"

    assert mod.main(["10.0.0.2", "--evidence-json", str(evidence)]) == 2
    assert calls == []
    assert not evidence.exists()


def test_dangling_symlink_evidence_rejects_before_connection(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    target = tmp_path / "missing-target.json"
    evidence = tmp_path / "dangling.json"
    evidence.symlink_to(target)

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) == 2
    assert calls == []
    assert not target.exists()
    assert evidence.is_symlink()


def test_missing_parent_evidence_rejects_before_connection(monkeypatch, tmp_path):
    mod = _load_runner()
    calls = []
    monkeypatch.setattr(mod, "ZK", _fake_zk(calls, [[]]))
    evidence = tmp_path / "missing-parent" / "evidence.json"

    assert mod.main(["10.0.0.2", "--write-one", "--uid", "8",
                     "--user-id", "999950", "--evidence-json", str(evidence)]) == 2
    assert calls == []
    assert not evidence.parent.exists()

def test_evidence_replacement_survives_failed_atomic_write(tmp_path):
    mod = _load_runner()
    evidence = tmp_path / "replacement.json"

    mod._preflight_evidence(evidence)
    evidence.write_text("attacker")

    with pytest.raises(FileExistsError):
        mod._write_evidence(evidence, {"outcome": "success"})
    assert evidence.read_text() == "attacker"

def test_help_documents_safe_contract(capsys):
    mod = _load_runner()
    assert mod.main(["--help"]) == 0
    help_text = capsys.readouterr().out
    for term in ("read-only", "--write-one", "--uid", "--user-id", "--evidence-json", "residue"):
        assert term in help_text
