#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.mnemonic import (_entropy_from_indexes, _indexes_from_entropy,
                             _indexes_from_mnemonic, _mnemonic_from_indexes)


class TestMnemonic(unittest.TestCase):
    def test_1(self):
        lang = "en"

        test_mnemonic = "ozone drill grab fiber curtain grace " \
                        "pudding thank cruise elder eight picnic"
        test_indexes = [1268,  535,  810,  685,  433,  811,
                        1385, 1790,  421,  570,  567, 1313]
        indexes = _indexes_from_mnemonic(test_mnemonic, lang)
        self.assertEqual(indexes, test_indexes)

        mnemonic = _mnemonic_from_indexes(test_indexes, lang)
        self.assertEqual(mnemonic, test_mnemonic)

        entropy = _entropy_from_indexes(test_indexes, lang)
        indexes = _indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)

        test_indexes = [0,    0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047,    0]
        entropy = _entropy_from_indexes(test_indexes, lang)
        indexes = _indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)

        test_indexes = [0,    0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047,    0]
        entropy = _entropy_from_indexes(test_indexes, lang)
        indexes = _indexes_from_entropy(entropy, lang)
        self.assertEqual(indexes, test_indexes)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
