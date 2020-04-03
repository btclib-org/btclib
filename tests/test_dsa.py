#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha1, sha256

from btclib import der, dsa
from btclib.curvemult import _mult_jac, double_mult, mult
from btclib.curves import low_card_curves, secp112r2, secp160r1, secp256k1
from btclib.numbertheory import mod_inv
from btclib.utils import octets_from_point, point_from_octets


class TestDSA(unittest.TestCase):
    def test_signature(self):
        q = 0x1
        Q = mult(q)
        msg = 'Satoshi Nakamoto'
        sig = dsa.sign(msg, q)
        # https://bitcointalk.org/index.php?topic=285142.40
        # Deterministic Usage of DSA and ECDSA (RFC 6979)
        exp_sig = (
            0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
            0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
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

        fmsg = 'Craig Wright'
        self.assertFalse(dsa.verify(fmsg, Q, sig))

        fdsasig = (sig[0], sig[1], sig[1])
        self.assertFalse(dsa.verify(msg, Q, fdsasig))
        self.assertRaises(ValueError, dsa._verify, msg, Q, fdsasig)

        fq = 0x4
        fQ = mult(fq)
        self.assertFalse(dsa.verify(msg, fQ, sig))

        # r not in [1, n-1]
        invalid_dassig = 0, sig[1]
        self.assertFalse(dsa.verify(msg, Q, invalid_dassig))

        # s not in [1, n-1]
        invalid_dassig = sig[0], 0
        self.assertFalse(dsa.verify(msg, Q, invalid_dassig))

        # pubkey = Inf
        self.assertRaises(ValueError, dsa._verify, msg, (1, 0), sig)
        #dsa._verify(msg, (1, 0), sig)

        # private key not in [1, n-1]
        self.assertRaises(ValueError, dsa.sign, msg, 0)
        #dsa.sign(msg, 0)

        # ephemeral key not in [1, n-1]
        self.assertRaises(ValueError, dsa.sign, msg, 1, 0)
        #dsa.sign(msg, 1, 0)

    def test_gec(self):
        """GEC 2: Test Vectors for SEC 1, section 2

            http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
        """
        # 2.1.1 Scheme setup
        ec = secp160r1
        hf = sha1

        # 2.1.2 Key Deployment for U
        dU = 971761939728640320549601132085879836204587084162
        self.assertEqual(format(dU, str(ec.psize)+'x'),
                         'aa374ffc3ce144e6b073307972cb6d57b2a4e982')
        QU = mult(dU, ec.G, ec)
        self.assertEqual(QU,
                         (466448783855397898016055842232266600516272889280,
                          1110706324081757720403272427311003102474457754220))
        self.assertEqual(octets_from_point(QU, True, ec).hex(),
                         '0251b4496fecc406ed0e75a24a3c03206251419dc0')

        # 2.1.3 Signing Operation for U
        msg = b'abc'
        k = 702232148019446860144825009548118511996283736794
        exp_sig = (0xCE2873E5BE449563391FEB47DDCBA2DC16379191,
                   0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54)
        sig = dsa.sign(msg, dU, k, ec, hf)
        r, s = sig
        self.assertEqual(r, exp_sig[0])
        self.assertIn(s, (exp_sig[1], ec.n - exp_sig[1]))

        # 2.1.4 Verifying Operation for V
        self.assertTrue(dsa.verify(msg, QU, sig, ec, hf))

    def test_forge_hash_sig(self):
        """forging valid hash signatures"""

        ec = secp256k1
        # see https://twitter.com/pwuille/status/1063582706288586752
        # Satoshi's key
        P = point_from_octets("03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c", ec)

        u1 = 1
        u2 = 2  # pick them at will
        R = double_mult(u2, P, u1, ec.G, ec)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        sig = r, s
        e = s * u1 % ec.n
        dsa._verhlp(e, (P[0], P[1], 1), r, s, ec)

        u1 = 1234567890
        u2 = 987654321  # pick them at will
        R = double_mult(u2, P, u1, ec.G, ec)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        sig = r, s
        e = s * u1 % ec.n
        dsa._verhlp(e, (P[0], P[1], 1), r, s, ec)

    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [11,  13,  17,  19]

        for ec in low_card_curves:  # only low card or it would take forever
            if ec._p in prime:  # only few curves or it would take too long
                for d in range(1, ec.n):  # all possible private keys
                    PJ = _mult_jac(d, ec.GJ, ec)  # public key
                    for e in range(ec.n):  # all possible int from hash
                        for k in range(1, ec.n):  # all possible ephemeral keys
                            RJ = _mult_jac(k, ec.GJ, ec)
                            Rx = (RJ[0]*mod_inv(RJ[2]*RJ[2], ec._p)) % ec._p
                            r = Rx % ec.n
                            if r == 0:
                                self.assertRaises(ValueError,
                                                  dsa._sign, e, d, k, ec)
                                continue

                            s = mod_inv(k, ec.n) * (e + d * r) % ec.n
                            if s == 0:
                                self.assertRaises(ValueError,
                                                  dsa._sign, e, d, k, ec)
                                continue

                            # bitcoin canonical 'low-s' encoding for ECDSA
                            if s > ec.n / 2:
                                s = ec.n - s

                            # valid signature
                            sig = dsa._sign(e, d, k, ec)
                            self.assertEqual((r, s), sig)
                            # valid signature must validate
                            self.assertIsNone(dsa._verhlp(e, PJ, r, s, ec))

                            keys = dsa._recover_pubkeys(e, r, s, ec)
                            Qs = [ec._aff_from_jac(key) for key in keys]
                            self.assertIn(ec._aff_from_jac(PJ), Qs)

    def test_pubkey_recovery(self):
        ec = secp112r2
        q = 0x10
        Q = mult(q, ec.G, ec)
        msg = 'Satoshi Nakamoto'
        k = sighash = None
        sig = dsa.sign(msg, q, k, ec)
        self.assertTrue(dsa.verify(msg, Q, sig, ec))
        dersig = der.serialize(*sig, sighash, ec)
        self.assertTrue(dsa.verify(msg, Q, dersig, ec))
        r, s, _ = der.deserialize(dersig)
        self.assertEqual((r, s), sig)


        keys = dsa.recover_pubkeys(msg, dersig, ec)
        self.assertEqual(len(keys), 4)
        self.assertIn(Q, keys)
        for Q in keys:
            self.assertTrue(dsa.verify(msg, Q, sig, ec))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
