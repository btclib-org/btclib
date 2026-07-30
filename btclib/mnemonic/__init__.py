#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Module btclib.mnemonic.

bip39 and electrum are the two mnemonic schemes this package is for, and
neither was exported: `import btclib.mnemonic` followed by
`btclib.mnemonic.bip39.mnemonic_from_entropy(...)` raised AttributeError
until something else in the process happened to import the submodule.
"""

from btclib.mnemonic import bip39, electrum
from btclib.mnemonic.entropy import (
    BinStr,
    Entropy,
    bin_str_entropy_from_bytes,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_int,
    bin_str_entropy_from_random,
    bin_str_entropy_from_rolls,
    bin_str_entropy_from_str,
    bin_str_entropy_from_wordlist_indexes,
    bytes_entropy_from_str,
    collect_rolls,
    wordlist_indexes_from_bin_str_entropy,
)
from btclib.mnemonic.mnemonic import (
    WORDLISTS,
    Mnemonic,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)

__all__ = [
    "WORDLISTS",
    "BinStr",
    "Entropy",
    "Mnemonic",
    "bin_str_entropy_from_bytes",
    "bin_str_entropy_from_entropy",
    "bin_str_entropy_from_int",
    "bin_str_entropy_from_random",
    "bin_str_entropy_from_rolls",
    "bin_str_entropy_from_str",
    "bin_str_entropy_from_wordlist_indexes",
    "bip39",
    "bytes_entropy_from_str",
    "collect_rolls",
    "electrum",
    "indexes_from_mnemonic",
    "mnemonic_from_indexes",
    "wordlist_indexes_from_bin_str_entropy",
]
