"""Pytest fixtures for the WL10 parser tests.

Shared helper functions live in ``helpers.py`` — import that module directly.
"""
import os
import sys

import pytest

TESTS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(TESTS_DIR, '..', '..', '..'))
WL10_ROOT = os.path.join(ROOT, 'pyzk_wl10')

# Make both the library and the tests directory available for imports
for p in (TESTS_DIR, WL10_ROOT, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from zk import const
from zk.base import ZK


@pytest.fixture
def zk_class():
    """Return the :class:`ZK` class itself (no instance, no socket)."""
    return ZK


@pytest.fixture
def zk_instance(zk_class):
    """Return a bare ZK instance with no socket (safe for parser tests).

    Parser methods need ``self.encoding`` (used in string decoding) and
    ``self.verbose`` (controls debug output).  The socket is never
    touched.
    """
    inst = object.__new__(zk_class)
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    return inst


@pytest.fixture
def const_module():
    return const
