#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
import unittest

from btclib.entropy import Entropy, binstr_from_entropy

random.seed(42)


class TestEntropy(unittest.TestCase):
    def test_conversions(self):
        binstr_entropy = '10101011' * 32
        entropy = binstr_from_entropy(binstr_entropy)
        self.assertEqual(entropy, binstr_entropy)

        int_entropy = int(binstr_entropy, 2)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(entropy, binstr_entropy)

        bytes_entropy = int_entropy.to_bytes(32, byteorder='big')
        entropy = binstr_from_entropy(bytes_entropy)
        self.assertEqual(entropy, binstr_entropy)

        binstr_entropy = '00101011' * 32
        entropy = binstr_from_entropy(binstr_entropy)
        self.assertEqual(entropy, binstr_entropy)

        int_entropy = int(binstr_entropy, 2)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(entropy, binstr_entropy)

        bytes_entropy = int_entropy.to_bytes(32, byteorder='big')
        entropy = binstr_from_entropy(bytes_entropy)
        self.assertEqual(entropy, binstr_entropy)

        binstr_entropy = '00000000' + '10101011' * 31
        entropy = binstr_from_entropy(binstr_entropy)
        self.assertEqual(entropy, binstr_entropy)

        int_entropy = int(binstr_entropy, 2)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(entropy, binstr_entropy)

        bytes_entropy = int_entropy.to_bytes(32, byteorder='big')
        entropy = binstr_from_entropy(bytes_entropy)
        self.assertEqual(entropy, binstr_entropy)

        # the 32 bytes integer has its leftmost bit set to 0
        int_entropy = random.getrandbits(255)
        binstr_entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(len(binstr_entropy), 256)

        # 257 bits
        int_entropy = 1 << 256
        binstr_entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(len(binstr_entropy), 256)

        exp_int_entropy = int_entropy >> 1
        int_entropy = int(binstr_entropy, 2)
        self.assertEqual(int_entropy, exp_int_entropy)

    def test_exceptions(self):
        binstr_entropy1 = '00011010' * 27  # 216 bits
        binstr_entropy = binstr_entropy1[2:]  # 214 bits

        entropy = binstr_from_entropy(binstr_entropy, 214)
        self.assertEqual(entropy, binstr_entropy)
        self.assertRaises(ValueError, binstr_from_entropy, binstr_entropy)
        # binstr_from_entropy(binstr_entropy)
        self.assertRaises(ValueError, binstr_from_entropy, binstr_entropy, 216)
        #binstr_from_entropy(binstr_entropy, 216)

        int_entropy = int(binstr_entropy, 2)  # 213 bits
        entropy = binstr_from_entropy(int_entropy, 214)
        self.assertEqual(entropy, binstr_entropy)
        entropy = binstr_from_entropy(int_entropy, 256)
        self.assertEqual(len(entropy), 256)
        self.assertEqual(int(entropy, 2), int_entropy)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(len(entropy), 224)
        self.assertEqual(int(entropy, 2), int_entropy)
        self.assertRaises(ValueError, binstr_from_entropy, -1*int_entropy)
        # binstr_from_entropy(-1*int_entropy)

        bytes_entropy = int_entropy.to_bytes(27, byteorder='big')
        self.assertRaises(ValueError, binstr_from_entropy, bytes_entropy, 214)
        #binstr_from_entropy(bytes_entropy, 214)
        entropy = binstr_from_entropy(bytes_entropy, 216)
        self.assertEqual(entropy, binstr_entropy1)
        self.assertRaises(ValueError, binstr_from_entropy, bytes_entropy, 224)
        #binstr_from_entropy(bytes_entropy, 224)

        invalid_entropy = tuple()
        self.assertRaises(TypeError, binstr_from_entropy, invalid_entropy)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
