"""Tests for the CLI surface of ``listar_marcaciones.py``.

The script's argparse parser is built inside ``main()`` (guarded by
``if __name__ == '__main__'``), so it cannot be imported and inspected
directly without running ``main()``.  These tests therefore:

1. run ``listar_marcaciones.py --help`` via subprocess and assert the
   new flags appear (no device involved — ``--help`` exits before any
   network I/O),
2. import the module and call ``main()`` with a stubbed-out ``ZK`` class
   that captures the constructor kwargs and raises before any network
   call, asserting the flags default to ``None`` and pass through to
   ``ZK(...)`` unchanged, and
3. stub ``ZK`` with fakes that exercise the error/sorting paths without
   touching a real device.
"""
import importlib.util
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / 'listar_marcaciones.py'

# Sentinel: marks "the flag is absent from the ZK(...) call" — distinct from
# "present with value None".
_MISSING = object()


def _import_listar():
    """Import listar_marcaciones.py from the repo root by absolute path."""
    spec = importlib.util.spec_from_file_location('listar_marcaciones', SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load {SCRIPT}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _CapturedArgs(Exception):
    """Raised by the fake ZK once the constructor kwargs are captured."""


class _FakeZK:
    """Stand-in for ``ZK`` that captures constructor kwargs, never connects."""

    def __init__(self, *args, **kwargs):
        raise _CapturedArgs(kwargs)


@pytest.fixture
def run_main():
    """Run ``main()`` with fake ``ZK``; return the kwargs ZK would receive.

    ``_FakeZK.__init__`` raises immediately, so ``main()`` aborts at
    construction time — before ``zk.connect()`` — and no device is touched.
    """

    def _run(*argv):
        mod = _import_listar()
        mod.ZK = _FakeZK  # type: ignore[attr-defined]  # stubbing module attr
        with mock.patch.object(sys, 'argv', ['listar_marcaciones.py', *argv]), pytest.raises(_CapturedArgs) as exc_info:
            mod.main()
        return exc_info.value.args[0]

    return _run


def _run_subprocess(*argv):
    return subprocess.run(  # noqa: S603  # fixed interpreter + fixed repo script, no user input
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )


def test_help_lists_flags():
    """--help output advertises --tcp-maxseg and --gap-timeout."""
    proc = _run_subprocess('--help')
    assert proc.returncode == 0
    assert '--tcp-maxseg' in proc.stdout
    assert '--gap-timeout' in proc.stdout


def test_defaults_none(run_main):
    """Both flags default to None and are explicitly forwarded to ZK."""
    kwargs = run_main('192.168.1.1')
    assert kwargs.get('tcp_maxseg', _MISSING) is None
    assert kwargs.get('gap_timeout', _MISSING) is None


def test_flags_passed_through(run_main):
    """Explicit flag values reach ZK(...) unchanged."""
    kwargs = run_main('192.168.1.1', '--tcp-maxseg', '1200', '--gap-timeout', '3')
    assert kwargs['tcp_maxseg'] == 1200
    assert kwargs['gap_timeout'] == 3


class _FakeZKDrop:
    """ZK that records calls, fails on connect and still supports disconnect."""

    def __init__(self, *args, **kwargs):
        self.wl10 = True
        self.calls = []

    def connect(self):
        self.calls.append('connect')
        raise ConnectionRefusedError('conexión rechazada')

    def disconnect(self):
        self.calls.append('disconnect')


def test_connect_failure_is_friendly(capsys):
    """A failed connect reports a friendly error, exits 1 and never shows a traceback."""
    mod = _import_listar()
    fake = _FakeZKDrop()
    mod.ZK = lambda *a, **k: fake  # type: ignore[attr-defined]  # stubbing module attr
    with mock.patch.object(sys, 'argv', ['listar_marcaciones.py', '192.168.1.1']):
        rc = mod.main()
    out = capsys.readouterr()
    assert rc == 1
    assert 'ERROR' in out.err
    assert 'Traceback' not in out.err
    # The session is torn down (guarded) even when the connect itself failed.
    assert fake.calls == ['connect', 'disconnect']


def test_invalid_date_is_usage_error():
    """An invalid --since value is an argparse usage error, not a Python traceback."""
    proc = _run_subprocess('192.168.1.1', '--since', 'not-a-date')
    assert proc.returncode == 2
    assert 'fecha inválida' in proc.stderr
    assert 'Traceback' not in proc.stderr


class _FakeZKOK:
    """ZK that serves users + attendance out of chronological order."""

    def __init__(self, *args, **kwargs):
        self.wl10 = True

    def connect(self):
        pass

    def get_device_name(self):
        return ''

    def wl10_get_users(self):
        return []

    def wl10_get_attendance(self):
        return [
            SimpleNamespace(timestamp=datetime(2026, 7, 1, 8, 0, 0), badge='102', name='Alice',
                            status_label='Check-In', status=0, punch=0),
            SimpleNamespace(timestamp=datetime(2026, 7, 2, 12, 0, 0), badge='103', name='Bob',
                            status_label='Check-Out', status=1, punch=1),
            SimpleNamespace(timestamp=datetime(2026, 6, 30, 17, 30, 0), badge='101', name='Carol',
                            status_label='Check-In', status=0, punch=0),
        ]

    def disconnect(self):
        pass


def test_output_chronological_with_summary(capsys):
    """Records print oldest-first regardless of device order, with a count on stderr."""
    mod = _import_listar()
    mod.ZK = _FakeZKOK  # type: ignore[attr-defined]  # stubbing module attr
    with mock.patch.object(sys, 'argv', ['listar_marcaciones.py', '192.168.1.1']):
        rc = mod.main()
    out = capsys.readouterr()
    assert rc == 0
    assert out.out.index('2026-06-30') < out.out.index('2026-07-01') < out.out.index('2026-07-02')
    assert 'Total: 3 marcaciones' in out.err


def test_csv_output_stays_machine_readable(capsys):
    """CSV mode keeps stdout pure data; the summary goes to stderr only."""
    mod = _import_listar()
    mod.ZK = _FakeZKOK  # type: ignore[attr-defined]  # stubbing module attr
    with mock.patch.object(sys, 'argv', ['listar_marcaciones.py', '192.168.1.1', '--csv']):
        rc = mod.main()
    out = capsys.readouterr()
    assert rc == 0
    lines = out.out.strip().splitlines()
    assert lines[0] == 'Badge,Nombre,Fecha,Hora,Status,Punch'
    assert len(lines) == 1 + 3
    # CSV rows are chronological too
    dates = [line.split(',')[2] for line in lines[1:]]
    assert dates == ['2026-06-30', '2026-07-01', '2026-07-02']
    assert 'Total: 3 marcaciones' in out.err
