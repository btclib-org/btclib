#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
import random
from typing import List

from btclib.curvemult import Curve, Point, _jac_from_aff
from btclib.curvemult import _mult_jac, double_mult, mult, multi_mult
from btclib.curves import (all_curves, ec23_31, low_card_curves, secp112r1,
                           secp160r1, secp256k1, secp256r1, secp384r1)

random.seed(42)

Inf = Point()  # Infinity point in affine coordinates
InfJ = 1, 1, 0  # Infinity point in jacobian coordinates


class TestEllipticCurve(unittest.TestCase):
    def test_mult(self):
        for ec in low_card_curves:
            for q in range(ec.n):
                Q = ec._mult_aff(q, ec.G)
                Qjac = _mult_jac(q, ec.GJ, ec)
                Q2 = ec._aff_from_jac(Qjac)
                self.assertEqual(Q, Q2)
        # with last curve
        self.assertEqual(Inf, ec._mult_aff(3, Inf))
        self.assertEqual(InfJ, _mult_jac(3, InfJ, ec))

    def test_shamir(self):
        ec = ec23_31
        for k1 in range(ec.n):
            for k2 in range(ec.n):
                shamir = double_mult(k1, ec.G, k2, ec.G, ec)
                std = ec.add(mult(k1, ec.G, ec), mult(k2, ec.G, ec))
                self.assertEqual(shamir, std)
                shamir = double_mult(k1, Inf, k2, ec.G, ec)
                std = ec.add(mult(k1, Inf, ec), mult(k2, ec.G, ec))
                self.assertEqual(shamir, std)
                shamir = double_mult(k1, ec.G, k2, Inf, ec)
                std = ec.add(mult(k1, ec.G, ec), mult(k2, Inf, ec))
                self.assertEqual(shamir, std)

    def test_boscoster(self):
        ec = secp256k1

        k: List[int] = list()
        ksum = 0
        for i in range(11):
            k.append(random.getrandbits(ec.nlen) % ec.n)
            ksum += k[i]

        P = [ec.G] * len(k)
        boscoster = multi_mult(k, P, ec)
        self.assertEqual(boscoster, mult(ksum, ec.G, ec))

        # mismatch between scalar length and Points length
        P = [ec.G] * (len(k)-1)
        self.assertRaises(ValueError, multi_mult, k, P, ec)
        #multi_mult(k, P, ec)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
