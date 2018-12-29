#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from btclib.numbertheory import mod_inv, mod_sqrt


class TestNumberTheory(unittest.TestCase):
    def test_mod_sqrt(self):
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29]:
            hasRoot = set()
            hasRoot.add(0)
            hasRoot.add(1)
            for i in range(2, p):
                hasRoot.add(i*i % p)
            for i in range(0, p):
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
                self.assertEqual((i * inv) % p, 1)

    def test_minus_one_quadr_res(self):
        """Ensure that if p = 3 (mod 4) then p - 1 is a quadratic residue"""
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29]:
            hasRoot = set()
            hasRoot.add(1)
            for i in range(2, p):
                hasRoot.add(i * i % p)
            if (p % 4) == 3:
                self.assertNotIn(p - 1, hasRoot)
                self.assertRaises(ValueError, mod_sqrt, p - 1, p)
            else:
                assert p % 4 == 1, "something is badly broken"
                self.assertIn(p - 1, hasRoot)
                root = mod_sqrt(p - 1, p)
                self.assertEqual(p - 1, root * root % p)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
