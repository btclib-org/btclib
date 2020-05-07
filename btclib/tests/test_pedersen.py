#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256, sha384

from btclib import pedersen
from btclib.curves import secp256k1, secp256r1, secp384r1


class TestSecondGenerator(unittest.TestCase):
    def test_second_generator(self):
        """
        important remarks on secp256-zkp prefix for
        compressed encoding of the second generator:
        https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
        """

        H = (0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,
             0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904)
        self.assertEqual(H, pedersen.second_generator(secp256k1, sha256))

        H = pedersen.second_generator(secp256r1, sha256)
        H = pedersen.second_generator(secp384r1, sha384)


class TestPedersenCommitment(unittest.TestCase):
    def test_commitment(self):

        ec = secp256k1
        hf = sha256

        r1 = 0x1
        v1 = 0x2
        # r1*G + v1*H
        C1 = pedersen.commit(r1, v1, ec, hf)
        self.assertTrue(pedersen.open(r1, v1, C1, ec, hf))

        r2 = 0x3
        v2 = 0x4
        # r2*G + v2*H
        C2 = pedersen.commit(r2, v2, ec, hf)
        self.assertTrue(pedersen.open(r2, v2, C2, ec, hf))

        # Pedersen Commitment is additively homomorphic
        # Commit(r1, v1) + Commit(r2, v2) = Commit(r1+r2, v1+r2)
        R = pedersen.commit(r1 + r2, v1 + v2, ec, hf)
        self.assertTrue(ec.add(C1, C2), R)

        # commit does not open (with catched exception)
        self.assertFalse(pedersen.open((r1, r1), v1, C2, ec, hf))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
