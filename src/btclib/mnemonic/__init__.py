# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.mnemonic.

bip39, electrum and slip39 are the three mnemonic schemes this package
is for, and none is exported by importing the package alone: `import
btclib.mnemonic` followed by
`btclib.mnemonic.bip39.mnemonic_from_entropy(...)` raises
AttributeError until something else in the process happens to import
the submodule, which is why all three are named here.
dispatch is exported beside them: it is the entry point that answers
which scheme a sentence belongs to, and it is of no use to anyone who
has to import it by name after already knowing.

entropy and mnemonic are named too, being the two modules the three
schemes are built on rather than schemes themselves: the first turns
dice rolls, bytes, an int or a bit string into the entropy a sentence
encodes, the second is the word list and the index codec over it. Their
functions are also re-exported flat below, so naming the modules adds one
thing -- what is *not* flat, WordLists and data_file among it, is reached
as btclib.mnemonic.mnemonic, a module spelled like the package that holds
it and easy to assume is the package.
"""

from btclib.mnemonic import bip39, dispatch, electrum, entropy, mnemonic, slip39
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
    normalize_mnemonic,
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
    "dispatch",
    "electrum",
    "entropy",
    "indexes_from_mnemonic",
    "mnemonic",
    "mnemonic_from_indexes",
    "normalize_mnemonic",
    "slip39",
    "wordlist_indexes_from_bin_str_entropy",
]
