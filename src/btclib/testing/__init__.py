# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.testing: fixtures for the tests of btclib and its callers.

`blocks` holds mainnet blocks as bytes. `strategies` holds hypothesis
strategies for transactions, scripts and blocks, and needs the `testing`
extra (`pip install "btclib[testing]"`), which installs hypothesis.

`strategies` is imported on demand, by `__getattr__` below, so that `import
btclib.testing` and `from btclib import *` work without hypothesis.
tests/imports_test.py holds that.
"""

from importlib import import_module
from types import ModuleType

from btclib.testing import blocks

__all__ = [
    "blocks",
    "strategies",
]


def __getattr__(published: str) -> ModuleType:
    """Import `strategies` the first time it is asked for.

    PEP 562, as `btclib/__init__.py` does it.
    """
    if published == "strategies":
        return import_module(f"{__name__}.strategies")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with `strategies` beside what the package already has."""
    return sorted({*__all__, *globals()})
