#!/usr/bin/env python3

import unittest
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

        str_entropy = str_from_entropy(entropy, 256)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(entropy, 256)
        self.assertEqual(len(bytes_entropy), 32)
        int_entropy = int_from_entropy(entropy)
        self.assertEqual(int_entropy.bit_length(), 254)

        str_entropy = str_from_entropy(bytes_entropy, 256)
        self.assertEqual(len(str_entropy), 256)
        self.assertEqual(str_entropy, entropy)
        bytes_entropy = bytes_from_entropy(bytes_entropy, 256)
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

    def test_exceptionss(self):
        entropy = '00101010' * 31
        entropy = entropy[2:] # 246 bits
        str_entropy = str_from_entropy(entropy)
        bytes_entropy = bytes_from_entropy(entropy)
        int_entropy = int_from_entropy(bytes_entropy)
        invalid_entropy = tuple()

        self.assertRaises(ValueError, str_from_entropy, str_entropy, 256)
        self.assertRaises(ValueError, str_from_entropy, bytes_entropy, 256)
        self.assertRaises(ValueError, str_from_entropy, -int_entropy, 256)
        self.assertRaises(ValueError, str_from_entropy, int_entropy, 256)
        self.assertRaises(TypeError, str_from_entropy, invalid_entropy, 256)

        self.assertRaises(ValueError, int_from_entropy, -int_entropy)
        self.assertRaises(TypeError, int_from_entropy, invalid_entropy)

        self.assertRaises(ValueError, bytes_from_entropy, str_entropy, 256)
        self.assertRaises(ValueError, bytes_from_entropy, bytes_entropy, 256)
        self.assertRaises(ValueError, bytes_from_entropy, -int_entropy, 256)
        self.assertRaises(ValueError, bytes_from_entropy, int_entropy, 256)
        self.assertRaises(TypeError, bytes_from_entropy, invalid_entropy, 256)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
