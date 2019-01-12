#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
import os

from btclib.mnemonic import mnemonic_dict


class TestMnemonicDictionaries(unittest.TestCase):
    def test_1(self):
        lang = "en"

        d = mnemonic_dict.word_list(lang)
        self.assertIsInstance(d, list)
        self.assertEqual(len(d), 2048)

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

        # entropy must be binary string or int
        entropy = b'123456789abcdef0'
        self.assertRaises(
            TypeError, mnemonic_dict.indexes_from_entropy, entropy, lang)

    def test_2(self):
        lang = "en"
        test_indexes = [0,    0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047,    0]
        entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
        indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)

        lang = "fakeng"
        # unknown language 'fakeng''
        self.assertRaises(ValueError, mnemonic_dict._load_lang, lang)
        #mnemonic_dict._load_lang(lang)

        # dictionary length (must be a power of two
        filename = os.path.join(os.path.dirname(__file__),
                                "data",
                                "fakeenglish.txt")
        self.assertRaises(ValueError, mnemonic_dict._load_lang, lang, filename)
        #mnemonic_dict._load_lang(lang, filename)

        lang = "eng"
        filename = os.path.join(os.path.dirname(__file__),
                                "data",
                                "english.txt")
        mnemonic_dict._load_lang(lang, filename)
        test_indexes = [0,    0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047,    0]
        entropy = mnemonic_dict.entropy_from_indexes(test_indexes, lang)
        indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
