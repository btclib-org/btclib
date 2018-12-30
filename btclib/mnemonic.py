#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Mnemonic class for converting entropy into a mnemonic sentence
"""

import math
import os
from typing import Union, List

from btclib.entropy import Entropy

WordList = List[str]


class Mnemonic:
    """Word-list based conversions between entropy, word indexes, and mnemonic phrase.

       Entropy is treated bitwise: (leading) zeros are not
       considered redundant padding. 
    """

    def __init__(self) -> None:
        # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
        # https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
        self.language_files = {
            'en': 'english.txt',
            'it': 'italian.txt'
        }
        self.languages = self.language_files.keys()

        # create dictionaries where each languaga has None wordlist
        values = len(self.languages)*[None]
        self._dictionary = dict(zip(self.languages, values))
        self._bits_per_word = dict(zip(self.languages, values))
        self._language_length = dict(zip(self.languages, values))

    def _load_language_if_not_available(self, lang: str) -> None:
        """ Load the language worlidst if it has not been loaded yet """
        assert lang in self.languages, "unknown language" + lang

        if self._dictionary[lang] == None:
            filename = self.language_files[lang]
            path_to_filename = os.path.join(os.path.dirname(__file__),
                                            "../data/",
                                            filename)
            with open(path_to_filename, 'r') as f:
                lines = f.readlines()
            f.closed

            nwords = len(lines)
            # http://www.graphics.stanford.edu/~seander/bithacks.html
            # Determining if an integer is a power of 2
            assert nwords & (nwords - 1) == 0, \
                "dictionary length must be a power of two"
            self._bits_per_word[lang] = int(math.log(nwords, 2))
            self._language_length[lang] = nwords
            # clean up and normalization are missing, but removal of \n
            self._dictionary[lang] = [line[:-1] for line in lines]

    def bits_per_word(self, lang: str) -> int:
        self._load_language_if_not_available(lang)
        return self._bits_per_word[lang]

    def word_list(self, lang: str) -> WordList:
        self._load_language_if_not_available(lang)
        return self._dictionary[lang]

    def language_length(self, lang: str) -> int:
        self._load_language_if_not_available(lang)
        return self._language_length[lang]

    # input entropy can be expresses as binary string or int
    def indexes_from_entropy(self, entropy: Entropy, lang: str) -> List[int]:
        self._load_language_if_not_available(lang)

        if type(entropy) != str:
            raise TypeError("entropy must be binary string, ",
                            "not '%s'" % type(entropy).__name__)

        bits = len(entropy)
        entropy = int(entropy, 2)
        n = self._language_length[lang]
        indexes = []
        while entropy:
            indexes.append(entropy % n)
            entropy = entropy // n

        # do not lose leading zeros entropy
        bpw = self._bits_per_word[lang]
        nwords = math.ceil(bits/bpw)
        while len(indexes) < nwords:
            indexes.append(0)

        return list(reversed(indexes))

    def mnemonic_from_indexes(self, indexes: List[int], lang: str) -> str:
        self._load_language_if_not_available(lang)

        words = []
        dictionary = self._dictionary[lang]
        for i in indexes:
            word = dictionary[i]
            words.append(word)
        return ' '.join(words)

    def indexes_from_mnemonic(self, mnemonic: str, lang: str) -> List[int]:
        self._load_language_if_not_available(lang)

        words = mnemonic.split()
        dictionary = self._dictionary[lang]
        indexes = [dictionary.index(w) for w in words]
        return indexes

    def entropy_from_indexes(self, indexes: List[int], lang: str) -> Entropy:
        self._load_language_if_not_available(lang)

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


mnemonic_dict = Mnemonic()
