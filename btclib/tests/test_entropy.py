#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import math
import secrets
import unittest

from btclib.entropy import (_entropy_from_indexes, _indexes_from_entropy,
                            binstr_from_entropy, randbinstr)


class TestEntropy(unittest.TestCase):
    def test_indexes(self):
        entropy = '0'
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, [0])
        entropy = '00000000000'
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, [0])
        entropy = '000000000000'
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, [0, 0])

        test_indexes = [1268, 535, 810, 685, 433, 811,
                        1385, 1790, 421, 570, 567, 1313]

        entropy = _entropy_from_indexes(test_indexes, 2048)
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, test_indexes)

        test_indexes = [0, 0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047, 0]
        entropy = _entropy_from_indexes(test_indexes, 2048)
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, test_indexes)

        test_indexes = [0, 0, 2047, 2047, 2047, 2047,
                        2047, 2047, 2047, 2047, 2047, 0]
        entropy = _entropy_from_indexes(test_indexes, 2048)
        indexes = _indexes_from_entropy(entropy, 2048)
        self.assertEqual(indexes, test_indexes)

    def test_conversions(self):
        binstr_entropy = '10101011' * 32
        entropy = binstr_from_entropy(binstr_entropy)
        self.assertEqual(entropy, binstr_entropy)

        int_entropy = int(binstr_entropy, 2)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(entropy, binstr_entropy)

        entropy = binstr_from_entropy(bin(int_entropy))
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
        int_entropy = secrets.randbits(255)
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
        # binstr_from_entropy(binstr_entropy, 216)

        int_entropy = int(binstr_entropy, 2)  # 213 bits
        entropy = binstr_from_entropy(int_entropy, 214)
        self.assertEqual(entropy, binstr_entropy)
        entropy = binstr_from_entropy(int_entropy, 256)
        self.assertEqual(len(entropy), 256)
        self.assertEqual(int(entropy, 2), int_entropy)
        entropy = binstr_from_entropy(int_entropy)
        self.assertEqual(len(entropy), 224)
        self.assertEqual(int(entropy, 2), int_entropy)
        self.assertRaises(ValueError, binstr_from_entropy, -1 * int_entropy)
        # binstr_from_entropy(-1*int_entropy)

        bytes_entropy = int_entropy.to_bytes(27, byteorder='big')
        self.assertRaises(ValueError, binstr_from_entropy, bytes_entropy, 214)
        # binstr_from_entropy(bytes_entropy, 214)
        entropy = binstr_from_entropy(bytes_entropy, 216)
        self.assertEqual(entropy, binstr_entropy1)
        self.assertRaises(ValueError, binstr_from_entropy, bytes_entropy, 224)
        # binstr_from_entropy(bytes_entropy, 224)

        invalid_entropy = tuple()
        self.assertRaises(TypeError, binstr_from_entropy, invalid_entropy)

    def test_randbinstr(self):
        bits = 256
        dice_base = 20
        bits_per_roll = math.floor(math.log2(dice_base))
        base = 2 ** bits_per_roll
        roll_number = math.ceil(bits / bits_per_roll)

        rolls = [base for _ in range(roll_number)]
        binstr = randbinstr(bits, dice_base, rolls, False, False, False)
        self.assertEqual(binstr, '1' * 256)

        rolls = [base for _ in range(2 * roll_number)]
        binstr = randbinstr(bits, dice_base, rolls, False, False, False)
        self.assertEqual(binstr, '1' * 256)

        rolls = [1 for _ in range(roll_number)]
        binstr = randbinstr(bits, dice_base, rolls, False, False, False)
        self.assertEqual(binstr, '0' * 256)

        rolls = [1 for _ in range(2 * roll_number)]
        binstr = randbinstr(bits, dice_base, rolls, False, False, False)
        self.assertEqual(binstr, '0' * 256)

        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
        binstr = randbinstr(bits, dice_base, rolls)
        self.assertEqual(len(binstr), 256)
        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
        binstr2 = randbinstr(bits, dice_base, rolls)
        self.assertEqual(len(binstr2), 256)
        self.assertNotEqual(binstr, binstr2)

        binstr = randbinstr(bits)
        self.assertEqual(len(binstr), 256)
        binstr2 = randbinstr(bits)
        self.assertEqual(len(binstr2), 256)
        self.assertNotEqual(binstr, binstr2)

        # goes through bit lenght reduction before hashing
        rolls = [base for _ in range(roll_number + 1)]
        binstr = randbinstr(bits, dice_base, rolls)

        # Number of bits (255) must be in (128, 160, 192, 224, 256)
        self.assertRaises(ValueError, randbinstr,
                          bits - 1, dice_base, rolls)
        # randbinstr(bits-1, dice_base, rolls)

        # too few usable [1-16] rolls, missing 2
        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number - 2)]
        self.assertRaises(ValueError, randbinstr, bits, dice_base, rolls)
        # randbinstr(bits, dice_base, rolls)

        # too few usable [1-16] rolls, missing 1
        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
        rolls[1] = base + 1
        self.assertRaises(ValueError, randbinstr, bits, dice_base, rolls)
        # randbinstr(bits, dice_base, rolls)

        # invalid (21) roll, not in [1-20]
        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
        rolls[1] = dice_base + 1
        self.assertRaises(ValueError, randbinstr, bits, dice_base, rolls)
        # randbinstr(bits, dice_base, rolls)

        # Invalid dice base (1): must be >= 2
        rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
        self.assertRaises(ValueError, randbinstr, bits, 1, rolls)
        # randbinstr(bits, 1, rolls)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
