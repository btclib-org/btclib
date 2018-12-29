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

primes = [2,    3,   5,   7,  11,  13,   17,  19,  23, 29,
          31,  37,  41,  43,  47,  53,   59,  61,  67, 71,
          73,  79,  83,  89,  97, 101,  103, 107, 109, 113,
          2**160 - 2**31 - 1,
          2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1,
          2**192 - 2**64 - 1,
          2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1,
          2**224 - 2**96 + 1,
          2**256 - 2**32 - 977,
          2**256 - 2**224 + 2**192 + 2**96 - 1,
          2**384 - 2**128 - 2**96 + 2**32 - 1,
          2**521 - 1]

class TestNumberTheory(unittest.TestCase):
    def test_mod_inv_prime(self):
        for p in primes:
            # zero has no inverse
            self.assertRaises(ValueError, mod_inv, 0, p)
            for a in range(1, min(p, 500)):  # exhausted only for small p
                inv = mod_inv(a, p)
                self.assertEqual(a*inv % p, 1)
                inv = mod_inv(a+p, p)
                self.assertEqual(a*inv % p, 1)

    def test_mod_inv(self):
        max_m = 100
        for m in range(2, max_m):
            nums = list(range(m))
            for a in nums:
                mult = [a*i % m for i in nums]
                if 1 in mult:
                    inv = mod_inv(a, m)
                    self.assertEqual(a*inv % m, 1)
                    inv = mod_inv(a+m, m)
                    self.assertEqual(a*inv % m, 1)
                else:
                    self.assertRaises(ValueError, mod_inv, a, m)

    def test_mod_sqrt(self):
        for p in primes[:30]:  # exhaustable only for small p
            hasRoot = set()
            hasRoot.add(0)
            hasRoot.add(1)
            for i in range(2, p):
                hasRoot.add(i*i % p)
            for i in range(p):
                if i in hasRoot:
                    root = mod_sqrt(i, p)
                    self.assertEqual(i, (root*root) % p)
                    root = p - root
                    self.assertEqual(i, (root*root) % p)
                    root = mod_sqrt(i+p, p)
                    self.assertEqual(i, (root*root) % p)
                else:
                    self.assertRaises(ValueError, mod_sqrt, i, p)

    def test_minus_one_quadr_res(self):
        """Ensure that if p = 3 (mod 4) then p - 1 is not a quadratic residue"""
        for p in primes:
            if (p % 4) == 3:
                self.assertRaises(ValueError, mod_sqrt, p - 1, p)
            else:
                assert p == 2 or p % 4 == 1, "something is badly broken"
                root = mod_sqrt(p - 1, p)
                self.assertEqual(p - 1, root * root % p)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
