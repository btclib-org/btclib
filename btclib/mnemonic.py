#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Class for converting entropy from/to mnemonic sentence.

*Entropy* must be represented as binary 0/1 string.
"""

import math
from hashlib import pbkdf2_hmac
from typing import List

from .entropy import Entropy
from .wordlists import _wordlists

Mnemonic = str

def indexes_from_entropy(entropy: Entropy, lang: str) -> List[int]:
    """Return the word-list indexes for a given entropy.
    
    Return the list of integer indexes into a language word-list
    for a given entropy.

    Entropy must be represented as binary 0/1 string; leading zeros
    are not considered redundant padding.
    """

    if type(entropy) != str:
        m = "entropy must be binary string, "
        m += f"not '{type(entropy).__name__}'"
        raise TypeError(m)

    bits = len(entropy)
    int_entropy = int(entropy, 2)
    n = _wordlists.language_length(lang)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, n)
        indexes.append(index)

    # do not lose leading zeros entropy
    bpw = _wordlists.bits_per_word(lang)
    nwords = math.ceil(bits/bpw)
    while len(indexes) < nwords:
        indexes.append(0)

    return list(reversed(indexes))

def mnemonic_from_indexes(indexes: List[int], lang: str) -> Mnemonic:
    """Return the mnemonic from a list of word-list indexes.
    
    Return the mnemonic from a list of integer indexes into
    a given language word-list.
    """

    words = []
    wordlist = _wordlists.wordlist(lang)
    for i in indexes:
        word = wordlist[i]
        words.append(word)
    return ' '.join(words)

def indexes_from_mnemonic(mnemonic: Mnemonic, lang: str) -> List[int]:
    """Return the word-list indexes for a given mnemonic.
    
    Return the list of integer indexes into a language word-list
    for a given mnemonic.
    """

    words = mnemonic.split()
    wordlist = _wordlists.wordlist(lang)
    indexes = [wordlist.index(w) for w in words]
    return indexes

def entropy_from_indexes(indexes: List[int], lang: str) -> Entropy:
    """Return the entropy from a list of word-list indexes.
    
    Return the entropy from a list of integer indexes into
    a given language word-list.
    """

    n = _wordlists.language_length(lang)
    entropy = 0
    for i in indexes:
        entropy = entropy*n + i

    binentropy = bin(entropy)[2:]    # remove '0b'

    # do not lose leading zeros entropy
    bpw = _wordlists.bits_per_word(lang)
    bits = len(indexes)*bpw
    binentropy = binentropy.zfill(bits)

    return binentropy

def _seed_from_mnemonic(mnemonic: Mnemonic,
                        passphrase: str, prefix: str) -> bytes:
    hf_name = 'sha512'
    password = mnemonic.encode()
    salt = (prefix + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hf_name, password, salt, iterations, dksize)
