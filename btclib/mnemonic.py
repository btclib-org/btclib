#!/usr/bin/env python3

"""
MnemonicDictionaries class for converting entropy into a mnemonic sentence
"""

import math
import os
from typing import Union, List

Entropy = str # binary 0/1 string
GenericEntropy = Union[Entropy, bytes, bytearray, int]
WordList = List[str]

class MnemonicDictionaries:
    """Dictionary based conversions between entropy, word indexes, and mnemonic phrase.

       Entropy is treated bitwise: (leading) zeros are not
       considered redundant padding. 
    """

    def __init__(self) -> None:
        # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
        # https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
        self.language_files = {
            'en':'english.txt',
            'it':'italian.txt'
        }
        self.languages = self.language_files.keys()

        # create empty dictionaries
        values = len(self.languages)*[None]
        self._dictionary = dict(zip(self.languages, values))
        self._bits_per_word = dict(zip(self.languages, values))
        self._language_length = dict(zip(self.languages, values))

    def _load_language_if_not_available(self, lang: str) -> None:
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
            assert nwords & (nwords - 1) == 0, "dictionary length must be a power of two"
            self._bits_per_word[lang] = int(math.log(nwords, 2))
            self._language_length[lang] = nwords
            # clean up and normalization are missing, but removal of \n
            self._dictionary[lang] = [line[:-1] for line in lines]

    def bits_per_word(self, lang: str) -> int:
        self._load_language_if_not_available(lang)
        return self._bits_per_word[lang]

    def dictionary(self, lang: str) -> WordList:
        self._load_language_if_not_available(lang)
        return self._dictionary[lang]

    def language_length(self, lang: str) -> int:
        self._load_language_if_not_available(lang)
        return self._language_length[lang]

    # input entropy can be expresses as binary string, bytes-like, or int
    def indexes_from_entropy(self, entropy: GenericEntropy, lang: str) -> List[int]:
        self._load_language_if_not_available(lang)

        if type(entropy) == str: # binary string
            bits = len(entropy)
            entropy = int(entropy, 2)
        elif isinstance(entropy, (bytes, bytearray)):
            bits = len(entropy)*8
            entropy = int.from_bytes(entropy, 'big')
        elif type(entropy) == int:
            assert entropy >= 0, "negative entropy"
            bits = entropy.bit_length()
        else:
            raise TypeError("entropy must be bynary string,",
                            "bytes-like object, or int;",
                            "not '%s'" % type(entropy).__name__)

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

    # output entropy is returned as binary string
    def entropy_from_indexes(self, indexes: List[int], lang: str) -> Entropy:
        self._load_language_if_not_available(lang)

        n = self._language_length[lang]
        entropy = 0
        for i in indexes:
            entropy = entropy*n + i

        binentropy = bin(entropy)[2:]

        # do not lose leading zeros entropy
        bpw = self._bits_per_word[lang]
        bits = len(indexes)*bpw
        binentropy = binentropy.zfill(bits)

        return binentropy

mnemonic_dict = MnemonicDictionaries()
