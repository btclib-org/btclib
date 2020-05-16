#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.dsa` module."

import unittest
from hashlib import sha1
from hashlib import sha256 as hf

from btclib import dsa
from btclib.alias import INF
from btclib.curvemult import _mult_jac, double_mult, mult
from btclib.curves import CURVES, secp256k1
from btclib.numbertheory import mod_inv
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.tests.test_curves import low_card_curves

secp112r2 = CURVES["secp112r2"]
secp160r1 = CURVES["secp160r1"]


class TestDSA(unittest.TestCase):
    def test_signature(self):

        ec = secp256k1
        q, Q = dsa.gen_keys(0x1)
        msg = "Satoshi Nakamoto"
        sig = dsa.sign(msg, q)
        self.assertEqual(sig, dsa.deserialize(sig))
        # https://bitcointalk.org/index.php?topic=285142.40
        # Deterministic Usage of DSA and ECDSA (RFC 6979)
        exp_sig = (
            0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
            0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5,
        )
        r, s = sig
        self.assertEqual(sig[0], exp_sig[0])
        self.assertIn(sig[1], (exp_sig[1], secp256k1.n - exp_sig[1]))

        self.assertTrue(dsa.verify(msg, Q, sig))

        # malleability
        malleated_sig = (r, secp256k1.n - s)
        self.assertTrue(dsa.verify(msg, Q, malleated_sig))

        keys = dsa.recover_pubkeys(msg, sig)
        self.assertTrue(len(keys) == 2)
        self.assertIn(Q, keys)

        fmsg = "Craig Wright"
        self.assertFalse(dsa.verify(fmsg, Q, sig))

        fdsasig = (sig[0], sig[1], sig[1])
        self.assertFalse(dsa.verify(msg, Q, fdsasig))
        self.assertRaises(ValueError, dsa._verify, msg, Q, fdsasig, ec, hf)

        _, fQ = dsa.gen_keys()
        self.assertFalse(dsa.verify(msg, fQ, sig))

        # r not in [1, n-1]
        invalid_dassig = 0, sig[1]
        self.assertFalse(dsa.verify(msg, Q, invalid_dassig))

        # s not in [1, n-1]
        invalid_dassig = sig[0], 0
        self.assertFalse(dsa.verify(msg, Q, invalid_dassig))

        # pubkey = INF
        self.assertRaises(ValueError, dsa._verify, msg, INF, sig, ec, hf)
        # dsa._verify(msg, INF, sig, ec, hf)

        # private key not in [1, n-1]
        self.assertRaises(ValueError, dsa.sign, msg, 0)
        # dsa.sign(msg, 0)

        # ephemeral key not in [1, n-1]
        self.assertRaises(ValueError, dsa.sign, msg, 1, 0)
        # dsa.sign(msg, 1, 0)

    def test_gec(self):
        """GEC 2: Test Vectors for SEC 1, section 2

            http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
        """
        # 2.1.1 Scheme setup
        ec = secp160r1
        hf = sha1

        # 2.1.2 Key Deployment for U
        dU = 971761939728640320549601132085879836204587084162
        self.assertEqual(
            format(dU, str(ec.nsize) + "x"), "aa374ffc3ce144e6b073307972cb6d57b2a4e982"
        )
        QU = mult(dU, ec.G, ec)
        self.assertEqual(
            QU,
            (
                466448783855397898016055842232266600516272889280,
                1110706324081757720403272427311003102474457754220,
            ),
        )
        self.assertEqual(
            bytes_from_point(QU, ec).hex(), "0251b4496fecc406ed0e75a24a3c03206251419dc0"
        )

        # 2.1.3 Signing Operation for U
        msg = b"abc"
        k = 702232148019446860144825009548118511996283736794
        exp_sig = (
            0xCE2873E5BE449563391FEB47DDCBA2DC16379191,
            0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54,
        )
        sig = dsa.sign(msg, dU, k, ec, hf)
        r, s = sig
        self.assertEqual(r, exp_sig[0])
        self.assertIn(s, (exp_sig[1], ec.n - exp_sig[1]))

        # 2.1.4 Verifying Operation for V
        self.assertTrue(dsa.verify(msg, QU, sig, ec, hf))

    def test_low_cardinality(self):
        """test low-cardinality curves for all msg/key pairs."""

        # ec.n has to be prime to sign
        prime = [11, 13, 17, 19]

        # only low card or it would take forever
        for ec in low_card_curves.values():
            if ec.p in prime:  # only few curves or it would take too long
                for q in range(1, ec.n):  # all possible private keys
                    PJ = _mult_jac(q, ec.GJ, ec)  # public key
                    for e in range(ec.n):  # all possible int from hash
                        for k in range(1, ec.n):  # all possible ephemeral keys
                            RJ = _mult_jac(k, ec.GJ, ec)
                            Rx = (RJ[0] * mod_inv(RJ[2] * RJ[2], ec.p)) % ec.p
                            r = Rx % ec.n
                            s = mod_inv(k, ec.n) * (e + q * r) % ec.n
                            # bitcoin canonical 'low-s' encoding for ECDSA
                            if s > ec.n / 2:
                                s = ec.n - s
                            if r == 0 or s == 0:
                                self.assertRaises(ValueError, dsa._sign, e, q, k, ec)
                                continue

                            sig = dsa._sign(e, q, k, ec)
                            self.assertEqual((r, s), sig)
                            # valid signature must pass verification
                            self.assertIsNone(dsa._verhlp(e, PJ, r, s, ec))

                            JacobianKeys = dsa._recover_pubkeys(e, r, s, ec)
                            Qs = [ec._aff_from_jac(key) for key in JacobianKeys]
                            self.assertIn(ec._aff_from_jac(PJ), Qs)

    def test_pubkey_recovery(self):
        ec = secp112r2
        q = 0x10
        Q = mult(q, ec.G, ec)
        msg = "Satoshi Nakamoto"
        k = None
        sig = dsa.sign(msg, q, k, ec)
        self.assertTrue(dsa.verify(msg, Q, sig, ec))
        dersig = dsa.serialize(*sig, ec)
        self.assertTrue(dsa.verify(msg, Q, dersig, ec))
        r, s = dsa.deserialize(dersig)
        self.assertEqual((r, s), sig)

        keys = dsa.recover_pubkeys(msg, sig, ec)
        self.assertEqual(len(keys), 4)
        self.assertIn(Q, keys)
        for Q in keys:
            self.assertTrue(dsa.verify(msg, Q, sig, ec))

    def test_crack_prvkey(self):
        ec = secp256k1

        q = 0xDEADBEEF6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
        k = 1010101010101010101

        msg1 = "Paolo is afraid of ephemeral random numbers"
        sig1 = dsa.sign(msg1, q, k)
        # print(f'\nr1: {hex(sig1[0]).upper()}')
        # print(f's1: {hex(sig1[1]).upper()}')

        msg2 = "and Paolo is right to be afraid"
        sig2 = dsa.sign(msg2, q, k)
        # print(f'\nr2: {hex(sig2[0]).upper()}')
        # print(f's2: {hex(sig2[1]).upper()}')

        qc, kc = dsa.crack_prvkey(msg1, sig1, msg2, sig2)
        self.assertEqual(q, qc)
        self.assertIn(k, (kc, ec.n - kc))

        self.assertRaises(ValueError, dsa.crack_prvkey, msg1, sig1, msg2, (16, sig1[1]))
        self.assertRaises(ValueError, dsa.crack_prvkey, msg1, sig1, msg1, sig1)


def test_forge_hash_sig():
    """forging valid hash signatures"""

    ec = secp256k1

    # see https://twitter.com/pwuille/status/1063582706288586752
    # Satoshi's key
    key = "03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    P = point_from_octets(key, ec)

    # pick u1 and u2 at will
    u1 = 1
    u2 = 2
    R = double_mult(u2, P, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    e = s * u1 % ec.n
    dsa._verhlp(e, (P[0], P[1], 1), r, s, ec)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult(u2, P, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    e = s * u1 % ec.n
    dsa._verhlp(e, (P[0], P[1], 1), r, s, ec)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
