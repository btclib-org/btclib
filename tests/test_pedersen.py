#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256, sha384

from btclib.ec import pointMult, DblScalarMult
from btclib.curves import secp256k1, secp256r1, secp384r1
from btclib.utils import octets2point
from btclib import pedersen


class TestSecondGenerator(unittest.TestCase):
    def test_second_generator(self):
        """
        important remark on secp256-zkp prefix for compressed encoding of the second generator:
        https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
        """

        ec = secp256k1
        hf = sha256

        H = pedersen.secondGenerator(ec, hf)
        self.assertEqual(H, octets2point(ec, '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'))

        # 0*G + 1*H
        T = DblScalarMult(ec, 0, ec.G, 1, H)
        self.assertEqual(T, octets2point(ec, '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'))

        # 0*G + 2*H
        T = DblScalarMult(ec, 0, ec.G, 2, H)
        self.assertEqual(T, octets2point(ec, '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a'))
        T = pointMult(ec, 2, H)
        self.assertEqual(T, octets2point(ec, '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a'))

        # 0*G + 3*H
        T = DblScalarMult(ec, 0, ec.G, 3, H)
        self.assertEqual(T, octets2point(ec, '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa'))
        T = pointMult(ec, 3, H)
        self.assertEqual(T, octets2point(ec, '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa'))

        # 1*G+0*H
        T = DblScalarMult(ec, 1, ec.G, 0, H)
        self.assertEqual(T, octets2point(ec, '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))
        T = pointMult(ec, 1, ec.G)
        self.assertEqual(T, octets2point(ec, '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))

        # 2*G+0*H
        T = DblScalarMult(ec, 2, ec.G, 0, H)
        self.assertEqual(T, octets2point(ec, '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'))
        T = pointMult(ec, 2, ec.G)
        self.assertEqual(T, octets2point(ec, '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'))

        # 3*G+0*H
        T = DblScalarMult(ec, 3, ec.G, 0, H)
        self.assertEqual(T, octets2point(ec, '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'))
        T = pointMult(ec, 3, ec.G)
        self.assertEqual(T, octets2point(ec, '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'))

        # 0*G+5*H
        T = DblScalarMult(ec, 0, ec.G, 5, H)
        self.assertEqual(T, octets2point(ec, '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e'))
        T = pointMult(ec, 5, H)
        self.assertEqual(T, octets2point(ec, '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e'))

        # 0*G-5*H
        T = DblScalarMult(ec, 0, ec.G, -5, H)
        self.assertEqual(T, octets2point(ec, '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e'))
        T = pointMult(ec, -5, H)
        self.assertEqual(T, octets2point(ec, '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e'))

        # 1*G-5*H
        U = DblScalarMult(ec, 1, ec.G, -5, H)
        self.assertEqual(U, octets2point(ec, '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a'))
        U = ec.add(ec.G, T)  # reusing previous T value
        self.assertEqual(U, octets2point(ec, '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a'))

        H = pedersen.secondGenerator(secp256r1, hf)
        H = pedersen.secondGenerator(secp384r1, sha384)

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
        R = pedersen.commit(r1+r2, v1+v2, ec, hf)
        self.assertTrue(ec.add(C1, C2), R)

        # commit does not open (with catched exception)
        self.assertFalse(pedersen.open((r1, r1), v1, C2, ec, hf))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
