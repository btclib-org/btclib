#!/usr/bin/env python3

import unittest
from btclib.mnemonic import mnemonic_dict

class TestMnemonicDictionaries(unittest.TestCase):
    def test_1(self):
        lang = "en"

        length = mnemonic_dict.language_length(lang)
        self.assertEqual(length, 2048)

        bpw = mnemonic_dict.bits_per_word(lang)
        self.assertEqual(bpw, 11)

        test_mnemonic = "ozone drill grab fiber curtain grace " \
                        "pudding thank cruise elder eight picnic"
        test_indexes = [1268,  535,  810,  685,  433,  811,
                        1385, 1790,  421,  570,  567, 1313]
        indexes = mnemonic_dict.indexes_from_mnemonic(test_mnemonic, lang)
        self.assertEqual(indexes, test_indexes)

        mnemonic = mnemonic_dict.mnemonic_from_indexes(test_indexes, lang)
        self.assertEqual(mnemonic, test_mnemonic)

        entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
        indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)

    def test_2(self):
        lang = "en"
        test_indexes = [   0,    0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047,    0]
        entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
        indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
