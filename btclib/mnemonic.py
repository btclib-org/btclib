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
import os
from typing import Union, List

from btclib.entropy import Entropy

WordList = List[str]

class Mnemonic:
    """Class for converting entropy from/to mnemonic sentence.
    
    Provide word-list based conversions between entropy, word indexes,
    and mnemonic phrase.

    Word-list dictionaries are from:

    * https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    * https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
    """

    def __init__(self) -> None:

        path = os.path.join(os.path.dirname(__file__), "dictdata")
        self.language_files = {
            'en': os.path.join(path, 'english.txt'),
            'it': os.path.join(path, 'italian.txt')
        }
        self.languages = list(self.language_files)

        # create dictionaries where each language has None word-list
        values = len(self.languages)*[None]
        self._dictionary = dict(zip(self.languages, values))
        self._bits_per_word = dict(zip(self.languages, values))
        self._language_length = dict(zip(self.languages, values))

    def _load_lang(self, lang: str, filename: str = None) -> None:
        """Load the language worlidst if it has not been loaded yet."""

        if lang not in self.languages:
            if filename is None:
                raise ValueError(f"unknown language '{lang}'")
            else:
                self.languages.append(lang)
                self.language_files[lang] = filename
                self._dictionary[lang] = None
                self._bits_per_word[lang] = None
                self._language_length[lang] = None

        # language has not been loaded yet
        if self._dictionary[lang] == None:
            with open(self.language_files[lang], 'r') as f:
                lines = f.readlines()
            f.closed

            nwords = len(lines)
            # http://www.graphics.stanford.edu/~seander/bithacks.html
            # Determining if an integer is a power of 2
            if nwords & (nwords - 1) != 0:
                errMsg = f"dictionary length ({nwords}) must be a power of two"
                raise ValueError(errMsg)

            self._bits_per_word[lang] = int(math.log(nwords, 2))
            self._language_length[lang] = nwords
            # clean up and normalization are missing, but removal of \n
            self._dictionary[lang] = [line[:-1] for line in lines]

    def bits_per_word(self, lang: str) -> int:
        """Return the number of bits per word.

        Return the number of bits per word for the given language.
        """
        self._load_lang(lang)
        return self._bits_per_word[lang]

    def word_list(self, lang: str) -> WordList:
        """Return the language word-list."""

        self._load_lang(lang)
        return self._dictionary[lang]

    def language_length(self, lang: str) -> int:
        """Return the language word-list length."""

        self._load_lang(lang)
        return self._language_length[lang]

    def indexes_from_entropy(self, entropy: Entropy, lang: str) -> List[int]:
        """Return the list of integer indexes for a given entropy.
        
        Return the list of integer indexes into a language word-list
        for a given entropy.

        Entropy must be represented as binary 0/1 string; leading zeros
        are not considered redundant padding.
        """

        self._load_lang(lang)

        if type(entropy) != str:
            m = "entropy must be binary string, "
            m += f"not '{type(entropy).__name__}'"
            raise TypeError(m)

        bits = len(entropy)
        int_entropy = int(entropy, 2)
        n = self._language_length[lang]
        indexes = []
        while int_entropy:
            int_entropy, index = divmod(int_entropy, n)
            indexes.append(index)

        # do not lose leading zeros entropy
        bpw = self._bits_per_word[lang]
        nwords = math.ceil(bits/bpw)
        while len(indexes) < nwords:
            indexes.append(0)

        return list(reversed(indexes))

    def mnemonic_from_indexes(self, indexes: List[int], lang: str) -> str:
        """Return the mnemonic from a list of integer indexes.
        
        Return the mnemonic for a given language from a list of
        integer indexes.
        """

        self._load_lang(lang)

        words = []
        dictionary = self._dictionary[lang]
        for i in indexes:
            word = dictionary[i]
            words.append(word)
        return ' '.join(words)

    def indexes_from_mnemonic(self, mnemonic: str, lang: str) -> List[int]:
        """Return the list of integer indexes from a mnemonic.
        
        Return the list of integer indexes from a mnemonic
        in a given language.
        """
        self._load_lang(lang)

        words = mnemonic.split()
        dictionary = self._dictionary[lang]
        indexes = [dictionary.index(w) for w in words]
        return indexes

    def entropy_from_indexes(self, indexes: List[int], lang: str) -> Entropy:
        """Return the entropy from a list of integer indexes.
        
        Return the entropy from a list of integer indexes for
        a given language word-list.
        """

        self._load_lang(lang)

        n = self._language_length[lang]
        entropy = 0
        for i in indexes:
            entropy = entropy*n + i

        binentropy = bin(entropy)[2:]    # remove '0b'

        # do not lose leading zeros entropy
        bpw = self._bits_per_word[lang]
        bits = len(indexes)*bpw
        binentropy = binentropy.zfill(bits)

        return binentropy

# singleton
mnemonic_dict = Mnemonic()
