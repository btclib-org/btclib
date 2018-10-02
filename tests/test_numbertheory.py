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

# Test that checks whether p - 1 (i.e. - 1 (mod p))
    # is a quadratic residue (should be so in case p = 1 (mod 4)) or not
    # (this should be the case if p = 3 (mod 4))
    def test_minus_one_quadr_res(self):
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29]:
            hasRoot = set()
            hasRoot.add(1)
            for i in range(2, p):
                hasRoot.add(i * i % p)
            if (p % 4) == 3:
                self.assertNotIn(p - 1, hasRoot)
                self.assertRaises(ValueError, mod_sqrt, p - 1, p)
            else:
                assert p % 4 == 1
                self.assertIn(p - 1, hasRoot)
                root = mod_sqrt(p - 1, p)
                self.assertEqual(p - 1, root * root % p)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
