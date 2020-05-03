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
from typing import List

from btclib.alias import INF, INFJ
from btclib.curve import _mult_aff, _mult_jac
from btclib.curvemult import double_mult, mult, multi_mult
from btclib.curves import ec23_31, low_card_curves, secp256k1

random.seed(42)


class TestEllipticCurve(unittest.TestCase):
    def test_mult(self):
        for ec in low_card_curves:
            for q in range(ec.n):
                Q = _mult_aff(q, ec.G, ec)
                QJ = _mult_jac(q, ec.GJ, ec)
                Q2 = ec._aff_from_jac(QJ)
                self.assertEqual(Q, Q2)
        # with last curve
        self.assertEqual(INF, _mult_aff(3, INF, ec))
        self.assertEqual(INFJ, _mult_jac(3, INFJ, ec))

    def test_shamir(self):
        ec = ec23_31
        for k1 in range(ec.n):
            for k2 in range(ec.n):
                shamir = double_mult(k1, ec.G, k2, ec.G, ec)
                std = ec.add(mult(k1, ec.G, ec), mult(k2, ec.G, ec))
                self.assertEqual(shamir, std)
                shamir = double_mult(k1, INF, k2, ec.G, ec)
                std = ec.add(mult(k1, INF, ec), mult(k2, ec.G, ec))
                self.assertEqual(shamir, std)
                shamir = double_mult(k1, ec.G, k2, INF, ec)
                std = ec.add(mult(k1, ec.G, ec), mult(k2, INF, ec))
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
        P = [ec.G] * (len(k) - 1)
        self.assertRaises(ValueError, multi_mult, k, P, ec)
        # multi_mult(k, P, ec)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
