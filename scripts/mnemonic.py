#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""MnemonicDictionaries class definition and associated tests"""

import math
import os

class MnemonicDictionaries:
    """Manage dictionary based conversions between entropy, 
    word indexes, and mnemonic phrase
    """

    def __init__(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
        # https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
        self.language_files = {
            'en':'english.txt',
            'it':'italian.txt'
        }
        languages = self.language_files.keys()
        # empy dictionaries
        self.dictionaries = dict(zip(languages, [None]*len(languages)))
        self.bpw = dict(zip(languages, [None]*len(languages)))

    def load_language_if_not_available(self, lang):
        assert lang in self.dictionaries.keys(), "unknown language" + lang

        if self.dictionaries[lang] == None:
            filename = self.language_files[lang]
            path = os.path.join(os.path.dirname(__file__),
                                # folder,
                                filename)
            lines = open(path, 'r').readlines()
            # no enforcing of 2048 lines...
            words = len(lines)
            assert words % 2 == 0, "dictionary with an odd number of words"
            self.bpw[lang] = int(math.log(words, 2))
            # clean up and normalization are missing, but removal of \n
            self.dictionaries[lang] = [line[:-1] for line in lines]

    def bit_per_word(self, lang):
        self.load_language_if_not_available(lang)
        return self.bpw[lang]

    def indexes_from_entropy(self, entropy, lang):
        self.load_language_if_not_available(lang)
        assert int(entropy, 2) >= 0, "entropy must be a binary string"

        words = len(entropy)//self.bpw[lang]
        # to be revised:
        # left-most bits are used, any traling extra are unused
        indexes = [int(entropy[i*self.bpw[lang]:(i+1)*self.bpw[lang]], 2) for i in range(0, words)]
        return indexes

    def mnemonic_from_indexes(self, indexes, lang):
        self.load_language_if_not_available(lang)

        words = []
        for i in indexes:
            word = self.dictionaries[lang][i]
            words.append(word)
        return ' '.join(words)

    def indexes_from_mnemonic(self, mnemonic, lang):
        self.load_language_if_not_available(lang)

        words = mnemonic.split()
        indexes = [self.dictionaries[lang].index(word) for word in words]
        return indexes

    def entropy_from_indexes(self, indexes, lang):
        self.load_language_if_not_available(lang)

        entropy = ''
        for i in indexes:
            word_bits = bin(i)
            word_bits = word_bits[2:]
            word_bits = word_bits.zfill(self.bpw[lang])
            entropy += word_bits
        return entropy

mnemonic_dict = MnemonicDictionaries()

def main():
    lang = "en"
    assert mnemonic_dict.bit_per_word(lang) == 11
    mnemonic = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    test_vector = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    assert test_vector == [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313]
    assert mnemonic == mnemonic_dict.mnemonic_from_indexes(test_vector, lang)

    entropy = mnemonic_dict.entropy_from_indexes(test_vector, lang)
    assert mnemonic_dict.indexes_from_entropy(entropy, lang) == test_vector

    test_vector = [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0, 0]
    entropy = mnemonic_dict.entropy_from_indexes(test_vector, lang)
    assert entropy[:22] =="0"*22
    assert entropy[22:-22] =="1"*88
    assert entropy[-22:]=="0"*22
    assert mnemonic_dict.indexes_from_entropy(entropy, lang) == test_vector


if __name__ == "__main__":
    # execute only if run as a script
    main()
