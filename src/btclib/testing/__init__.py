# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.testing: fixtures for the tests of btclib and its callers.

`blocks` holds mainnet blocks as bytes. `strategies` holds hypothesis
strategies for transactions, scripts and blocks.

`strategies` is imported by name, as in `from btclib.testing import
strategies`. It is not in `__all__`, so that `from btclib.testing import *`
works without hypothesis. tests/imports_test.py holds that.
"""

from btclib.testing import blocks

__all__ = ["blocks"]
