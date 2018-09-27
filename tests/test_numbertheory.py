#!/usr/bin/env python3

import unittest
from btclib.numbertheory import mod_inv, mod_sqrt

class TestNumberTheory(unittest.TestCase):
    def test_mod_sqrt(self):
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29]:
            hasRoot = set()
            hasRoot.add(1)
            for i in range(2, p):
                hasRoot.add(i*i % p)
            for i in range(1, p):
                if i in hasRoot:
                    root = mod_sqrt(i, p)
                    self.assertEqual(i, (root*root) % p)
                    root = p - root
                    self.assertEqual(i, (root*root) % p)
                else:
                    self.assertRaises(ValueError, mod_sqrt, i, p)

    def test_mod_inv(self):
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29]:
            for i in range(1, p):
                inv = mod_inv(i, p)
                self.assertEqual((i* inv) % p, 1)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
