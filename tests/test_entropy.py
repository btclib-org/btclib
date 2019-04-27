#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from secrets import randbits
from btclib.entropy import Entropy, GenericEntropy, \
    bytes_from_entropy, str_from_entropy, \
    int_from_entropy


class TestEntropy(unittest.TestCase):
    def test_conversions(self):
        entropy = '10101011' * 32

        str_entropy = str_from_entropy(entropy)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(entropy)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(entropy)
        self.assertEqual(int_entropy.bit_length(), 256)

        str_entropy = str_from_entropy(bytes_entropy)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(bytes_entropy)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(bytes_entropy)
        self.assertEqual(int_entropy.bit_length(), 256)

        str_entropy = str_from_entropy(int_entropy)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(int_entropy)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(int_entropy)
        self.assertEqual(int_entropy.bit_length(), 256)

    def test_leading_zeros(self):
        entropy = '00101010' * 32

        str_entropy = str_from_entropy(entropy)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(entropy)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(entropy)
        self.assertEqual(int_entropy.bit_length(), 254)

        str_entropy = str_from_entropy(bytes_entropy)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(bytes_entropy)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(bytes_entropy)
        self.assertEqual(int_entropy.bit_length(), 254)

        str_entropy = str_from_entropy(int_entropy, 254)
        self.assertEqual(len(str_entropy), 254)
        self.assertEqual(str_entropy, entropy[2:])
        bytes_entropy = bytes_from_entropy(int_entropy, 254)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(int_entropy)
        self.assertEqual(int_entropy.bit_length(), 254)

        # the 32 bytes integer has its leftmost bit set to 0
        entropy = randbits(255)
        self.assertEqual(len(str_from_entropy(entropy)), 256)

    def test_exceptions(self):
        entropy = '00101010' * 31
        entropy = entropy[2:]  # 246 bits
        str_entropy = str_from_entropy(entropy, 246)
        bytes_entropy = bytes_from_entropy(entropy, 246)
        int_entropy = int_from_entropy(entropy, 246)
        invalid_entropy = tuple()

        self.assertRaises(ValueError, str_from_entropy, str_entropy)
        self.assertRaises(ValueError, str_from_entropy, bytes_entropy)
        self.assertRaises(ValueError, str_from_entropy, -1*int_entropy)
        self.assertEqual(len(str_from_entropy(int_entropy)), 256)
        self.assertRaises(TypeError, str_from_entropy, invalid_entropy)

        self.assertRaises(ValueError, int_from_entropy, str_entropy)
        self.assertRaises(ValueError, int_from_entropy, bytes_entropy)
        self.assertRaises(ValueError, int_from_entropy, -1*int_entropy)
        self.assertEqual(int_from_entropy(int_entropy), int_entropy)
        self.assertRaises(TypeError, int_from_entropy, invalid_entropy)

        self.assertRaises(ValueError, bytes_from_entropy, str_entropy)
        self.assertRaises(ValueError, bytes_from_entropy, bytes_entropy)
        self.assertRaises(ValueError, bytes_from_entropy, -1*int_entropy)
        self.assertEqual(len(bytes_from_entropy(int_entropy)), 32)
        self.assertRaises(TypeError, bytes_from_entropy, invalid_entropy)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
