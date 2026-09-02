"""Tests for the CLI surface of ``check_device.py``.

The parser is built inside ``main()``, so these tests exercise argparse
via subprocess only: ``--help`` exits before any network I/O, and an
invalid ``--limit`` exits with a usage error before any device is
touched. No device is ever contacted.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / 'check_device.py'


def _run_subprocess(*argv):
    return subprocess.run(  # noqa: S603  # fixed interpreter + fixed repo script, no user input
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )


def test_limit_rejects_zero():
    """--limit 0 is a usage error, not a silent "show everything"."""
    proc = _run_subprocess('192.168.1.1', '--limit', '0')
    assert proc.returncode == 2
    assert 'debe ser un entero positivo' in proc.stderr
    assert 'Traceback' not in proc.stderr


def test_limit_rejects_negative():
    """A negative --limit is rejected instead of reversing the display order."""
    proc = _run_subprocess('192.168.1.1', '--limit', '-5')
    assert proc.returncode == 2
    assert 'debe ser un entero positivo' in proc.stderr


def test_help_exits_zero():
    """--help works without any device."""
    proc = _run_subprocess('--help')
    assert proc.returncode == 0
    assert '--limit' in proc.stdout
