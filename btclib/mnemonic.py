#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Functions for entropy conversion from/to mnemonic sentence.

Entropy must be represented as binary 0/1 string.

Warning: these functions are not meant for end-users which are
better served by the bip39 and electrum module functions.
"""

import math
from hashlib import pbkdf2_hmac
from typing import List

from .entropy import BinStr
from .wordlists import _wordlists

Mnemonic = str


def _indexes_from_entropy(entropy: BinStr, lang: str) -> List[int]:
    """Return the word-list indexes for a given binary 0/1 string entropy.

    Return the list of integer indexes into a language word-list
    for a given entropy.

    Entropy must be represented as binary 0/1 string; leading zeros
    are not considered redundant padding.
    """

    bits = len(entropy)
    int_entropy = int(entropy, 2)
    n = _wordlists.language_length(lang)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, n)
        indexes.append(index)

    # do not lose leading zeros entropy
    bpw = _wordlists.bits_per_word(lang)
    nwords = math.ceil(bits / bpw)
    while len(indexes) < nwords:
        indexes.append(0)

    return list(reversed(indexes))


def _mnemonic_from_indexes(indexes: List[int], lang: str) -> Mnemonic:
    """Return the mnemonic from a list of word-list indexes.

    Return the mnemonic from a list of integer indexes into
    a given language word-list.
    """

    words = []
    wordlist = _wordlists.wordlist(lang)
    for index in indexes:
        word = wordlist[index]
        words.append(word)
    return ' '.join(words)


def _indexes_from_mnemonic(mnemonic: Mnemonic, lang: str) -> List[int]:
    """Return the word-list indexes for a given mnemonic.

    Return the list of integer indexes into a language word-list
    for a given mnemonic.
    """

    words = mnemonic.split()
    wordlist = _wordlists.wordlist(lang)
    indexes = [wordlist.index(w) for w in words]
    return indexes


def _entropy_from_indexes(indexes: List[int], lang: str) -> BinStr:
    """Return the entropy from a list of word-list indexes.

    Return the entropy from a list of integer indexes into
    a given language word-list.
    """

    n = _wordlists.language_length(lang)
    entropy = 0
    for index in indexes:
        entropy = entropy * n + index

    binentropy = bin(entropy)[2:]    # remove '0b'

    # do not lose leading zeros entropy
    bpw = _wordlists.bits_per_word(lang)
    bits = len(indexes) * bpw
    binentropy = binentropy.zfill(bits)

    return binentropy
