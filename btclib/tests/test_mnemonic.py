#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from os import path

from btclib.mnemonic import (_indexes_from_mnemonic, _mnemonic_from_indexes,
                             _wordlists)


class TestMnemonic(unittest.TestCase):

    def test_mnemonic(self):
        lang = "en"

        test_mnemonic = "ozone drill grab fiber curtain grace " \
                        "pudding thank cruise elder eight picnic"
        test_indexes = [1268, 535, 810, 685, 433, 811,
                        1385, 1790, 421, 570, 567, 1313]
        indexes = _indexes_from_mnemonic(test_mnemonic, lang)
        self.assertEqual(indexes, test_indexes)

        mnemonic = _mnemonic_from_indexes(test_indexes, lang)
        self.assertEqual(mnemonic, test_mnemonic)

    def test_wordlist_1(self):
        lang = "en"

        d = _wordlists.wordlist(lang)
        self.assertIsInstance(d, list)
        self.assertEqual(len(d), 2048)

        length = _wordlists.language_length(lang)
        self.assertEqual(length, 2048)

    def test_wordlist_2(self):
        lang = "fakeen"
        # missing file for language 'fakeen''
        self.assertRaises(ValueError, _wordlists.load_lang, lang)
        # _wordlists.load_lang(lang)

        # dictionary length (must be a power of two
        filename = path.join(path.dirname(__file__),
                             "data", "fakeenglish.txt")
        self.assertRaises(ValueError, _wordlists.load_lang, lang, filename)
        # _wordlists.load_lang(lang, filename)

        # dinamically add a new language
        lang = "en2"
        filename = path.join(path.dirname(__file__),
                             "data", "english.txt")
        _wordlists.load_lang(lang, filename)
        length = _wordlists.language_length(lang)
        self.assertEqual(length, 2048)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
