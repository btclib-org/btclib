#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from btclib.ellipticcurves import secp256k1, sha256
from btclib.pedersen_commitment import pedersen_commit, pedersen_open


class TestPedersenCommitment(unittest.TestCase):
    def test_pedersen_commitment(self):
        r = 0x1
        v = 0x2
        C = pedersen_commit(r, v, secp256k1, sha256)
        self.assertTrue(pedersen_open(r, v, C, secp256k1, sha256))

    def test_pedersen_commitment_sum(self):
        r1 = 0x1
        r2 = 0x2
        r_sum = 0x3
        v1 = 0x4
        v2 = 0x5
        v_sum = 0x9
        C_sum = pedersen_commit(r_sum, v_sum, secp256k1, sha256)
        self.assertTrue(pedersen_open(
            r1 + r2, v1 + v2, C_sum, secp256k1, sha256))

    def test_pedersen_commitment_oddeven(self):
        r = 0x0
        v = 0x5
        C_1 = pedersen_commit(r, v, secp256k1, sha256)
        C_2 = pedersen_commit(r, -v, secp256k1, sha256)
        self.assertTrue(C_1[0] == C_2[0])
        self.assertTrue(C_1[1] == secp256k1.yOdd(C_2[0], True)
                        or C_1[1] == secp256k1.yOdd(C_2[0], False))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
