#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""MnemonicDictionaries class definition and associated tests"""

import math
import os


class MnemonicDictionaries:
    """Manage dictionary based conversions between entropy, 
       word indexes, and mnemonic phrase.

       Entropy is treated bitwise, as (leading) zeros are not
       considered redundant padding. 
    """

    def __init__(self):
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

    def _load_language_if_not_available(self, lang):
        assert lang in self.languages, "unknown language" + lang

        if self._dictionary[lang] == None:
            filename = self.language_files[lang]
            path_to_filename = os.path.join(os.path.dirname(__file__),
                                            # folder,
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

    def bits_per_word(self, lang):
        self._load_language_if_not_available(lang)
        return self._bits_per_word[lang]

    def dictionary(self, lang):
        self._load_language_if_not_available(lang)
        return self._dictionary[lang]

    def language_length(self, lang):
        self._load_language_if_not_available(lang)
        return self._language_length[lang]

    # input entropy can be expresses as binary string, bytes-like, or int
    def indexes_from_entropy(self, entropy, lang):
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

    def mnemonic_from_indexes(self, indexes, lang):
        self._load_language_if_not_available(lang)

        words = []
        dictionary = self._dictionary[lang]
        for i in indexes:
            word = dictionary[i]
            words.append(word)
        return ' '.join(words)

    def indexes_from_mnemonic(self, mnemonic, lang):
        self._load_language_if_not_available(lang)

        words = mnemonic.split()
        dictionary = self._dictionary[lang]
        indexes = [dictionary.index(w) for w in words]
        return indexes

    # output entropy is returned as binary string
    def entropy_from_indexes(self, indexes, lang):
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


def main():
    lang = "en"
    length = mnemonic_dict.language_length(lang)
    if length != 2048:
        raise ValueError("\n" + length + "\n" + 2048)
    bpw = mnemonic_dict.bits_per_word(lang)
    if bpw != 11:
        raise ValueError("\n" + bpw + "\n" + 11)

    test_mnemonic = "ozone drill grab fiber curtain grace " \
                    "pudding thank cruise elder eight picnic"
    test_indexes = [1268,  535,  810,  685,  433,  811,
                    1385, 1790,  421,  570,  567, 1313]
    indexes = mnemonic_dict.indexes_from_mnemonic(test_mnemonic, lang)
    if indexes != test_indexes:
        raise ValueError("\n" + str(indexes) + "\n" + str(test_indexes))
    mnemonic = mnemonic_dict.mnemonic_from_indexes(test_indexes, lang)
    if mnemonic != test_mnemonic:
        raise ValueError("\n" + mnemonic + "\n" + test_mnemonic)


    entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    if indexes != test_indexes:
        raise ValueError("\n" + str(indexes) + "\n" + str(test_indexes))

    test_indexes = [   0,    0, 2047, 2047, 2047, 2047,
                    2047, 2047, 2047, 2047, 2047,    0]
    entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    if indexes != test_indexes:
        raise ValueError("\n" + str(indexes) + "\n" + str(test_indexes))


if __name__ == "__main__":
    # execute only if run as a script
    main()
