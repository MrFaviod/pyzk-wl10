"""Tests for the CLI surface of ``listar_marcaciones.py``.

The script's argparse parser is built inside ``main()`` (guarded by
``if __name__ == '__main__'``), so it cannot be imported and inspected
directly without running ``main()``.  These tests therefore:

1. run ``listar_marcaciones.py --help`` via subprocess and assert the
   new flags appear (no device involved — ``--help`` exits before any
   network I/O), and
2. import the module and call ``main()`` with a stubbed-out ``ZK`` class
   that captures the constructor kwargs and raises before any network
   call, asserting the flags default to ``None`` and pass through to
   ``ZK(...)`` unchanged.

All three tests FAIL on the current code: the ``--tcp-maxseg`` and
``--gap-timeout`` flags do not exist yet.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path
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
        with mock.patch.object(sys, 'argv', ['listar_marcaciones.py', *argv]):
            with pytest.raises(_CapturedArgs) as exc_info:
                mod.main()
        return exc_info.value.args[0]

    return _run


def test_help_lists_flags():
    """--help output advertises --tcp-maxseg and --gap-timeout."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), '--help'],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
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
