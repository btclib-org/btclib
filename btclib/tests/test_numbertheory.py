#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.numbertheory` module."

import pytest

from btclib.numbertheory import mod_inv, mod_sqrt

primes = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    2 ** 160 - 2 ** 31 - 1,
    2 ** 192 - 2 ** 32 - 2 ** 12 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 3 - 1,
    2 ** 192 - 2 ** 64 - 1,
    2 ** 224 - 2 ** 32 - 2 ** 12 - 2 ** 11 - 2 ** 9 - 2 ** 7 - 2 ** 4 - 2 - 1,
    2 ** 224 - 2 ** 96 + 1,
    2 ** 256 - 2 ** 32 - 977,
    2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
    2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
    2 ** 521 - 1,
]


def test_mod_inv_prime():
    for p in primes:
        err_msg = "No inverse for 0x0 mod "
        with pytest.raises(ValueError, match=err_msg):
            mod_inv(0, p)
        for a in range(1, min(p, 500)):  # exhausted only for small p
            inv = mod_inv(a, p)
            assert a * inv % p == 1
            inv = mod_inv(a + p, p)
            assert a * inv % p == 1


def test_mod_inv():
    max_m = 100
    for m in range(2, max_m):
        nums = list(range(m))
        for a in nums:
            mult = [a * i % m for i in nums]
            if 1 in mult:
                inv = mod_inv(a, m)
                assert a * inv % m == 1
                inv = mod_inv(a + m, m)
                assert a * inv % m == 1
            else:
                err_msg = "No inverse for "
                with pytest.raises(ValueError, match=err_msg):
                    mod_inv(a, m)


def test_mod_sqrt():
    for p in primes[:30]:  # exhaustable only for small p
        hasRoot = set()
        hasRoot.add(0)
        hasRoot.add(1)
        for i in range(2, p):
            hasRoot.add(i * i % p)
        for i in range(p):
            if i in hasRoot:
                root = mod_sqrt(i, p)
                assert i == (root * root) % p
                root = p - root
                assert i == (root * root) % p
                root = mod_sqrt(i + p, p)
                assert i == (root * root) % p
            else:
                err_msg = "No root for "
                with pytest.raises(ValueError, match=err_msg):
                    mod_sqrt(i, p)


def test_minus_one_quadr_res():
    "Ensure that if p = 3 (mod 4) then p - 1 is not a quadratic residue"
    for p in primes:
        if (p % 4) == 3:
            err_msg = "No root for "
            with pytest.raises(ValueError, match=err_msg):
                mod_sqrt(p - 1, p)
        else:
            assert p == 2 or p % 4 == 1, "something is badly broken"
            root = mod_sqrt(p - 1, p)
            assert p - 1 == root * root % p
