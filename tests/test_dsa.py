#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256, sha1

from btclib.numbertheory import mod_inv
from btclib.ec import pointMult, DblScalarMult
from btclib.curves import secp256k1, secp112r2, secp160r1, low_card_curves
from btclib.utils import octets2point, point2octets
from btclib.dsa import ecdsa_sign, _ecdsa_sign, ecdsa_verify, \
    _ecdsa_verify, _ecdsa_verhlp, ecdsa_pubkey_recovery, _ecdsa_pubkey_recovery


class TestEcdsa(unittest.TestCase):
    def test_ecdsa(self):
        ec = secp256k1
        hf = sha256
        q = 0x1
        Q = pointMult(ec, q, ec.G)
        msg = 'Satoshi Nakamoto'.encode()
        sig = ecdsa_sign(ec, hf, msg, q)
        # https://bitcointalk.org/index.php?topic=285142.40
        # Deterministic Usage of DSA and ECDSA (RFC 6979)
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
        r, s = sig
        self.assertEqual(sig[0], exp_sig[0])
        self.assertIn(sig[1], (exp_sig[1], ec.n - exp_sig[1]))

        self.assertTrue(ecdsa_verify(ec, hf, msg, Q, sig))
        self.assertTrue(_ecdsa_verify(ec, hf, msg, Q, sig))

        # malleability
        malleated_sig = (r, ec.n - s)
        self.assertTrue(ecdsa_verify(ec, hf, msg, Q, malleated_sig))
        self.assertTrue(_ecdsa_verify(ec, hf, msg, Q, malleated_sig))

        keys = ecdsa_pubkey_recovery(ec, hf, msg, sig)
        self.assertTrue(len(keys)==2)
        self.assertIn(Q, keys)

        fmsg = 'Craig Wright'.encode()
        self.assertFalse(ecdsa_verify(ec, hf, fmsg, Q, sig))
        self.assertFalse(_ecdsa_verify(ec, hf, fmsg, Q, sig))

        fdsasig = (sig[0], sig[1], sig[1])
        self.assertFalse(ecdsa_verify(ec, hf, msg, Q, fdsasig))
        self.assertRaises(TypeError, _ecdsa_verify, ec, hf, msg, Q, fdsasig)

        fq = 0x4
        fQ = pointMult(ec, fq, ec.G)
        self.assertFalse(ecdsa_verify(ec, hf, msg, fQ, sig))
        self.assertFalse(_ecdsa_verify(ec, hf, msg, fQ, sig))

        # r not in [1, n-1]
        invalid_dassig = 0, sig[1]
        self.assertFalse(ecdsa_verify(ec, hf, msg, Q, invalid_dassig))

        # s not in [1, n-1]
        invalid_dassig = sig[0], 0
        self.assertFalse(ecdsa_verify(ec, hf, msg, Q, invalid_dassig))

        # pubkey = Inf
        self.assertRaises(ValueError, _ecdsa_verify, ec, hf, msg, (1, 0), sig)
        #_ecdsa_verify(ec, hf, msg, (1, 0), sig)

    def test_ecdsa_gec(self):
        """ GEC 2: Test Vectors for SEC 1, section 2

            http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
        """
        # 2.1.1 Scheme setup
        ec = secp160r1
        hf = sha1

        # 2.1.2 Key Deployment for U
        dU = 971761939728640320549601132085879836204587084162
        self.assertEqual(format(dU, str(ec.psize)+'x'),
                         'aa374ffc3ce144e6b073307972cb6d57b2a4e982')
        QU = pointMult(ec, dU, ec.G)
        self.assertEqual(QU, (466448783855397898016055842232266600516272889280, 1110706324081757720403272427311003102474457754220))
        self.assertEqual(point2octets(ec, QU, True).hex(),
                         '0251b4496fecc406ed0e75a24a3c03206251419dc0')

        # 2.1.3 Signing Operation for U
        msg = 'abc'.encode()
        k =  702232148019446860144825009548118511996283736794
        exp_sig = (0xCE2873E5BE449563391FEB47DDCBA2DC16379191,
                   0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54)
        sig = ecdsa_sign(ec, hf, msg, dU, k)
        r, s = sig
        self.assertEqual(r, exp_sig[0])
        self.assertIn(s, (exp_sig[1], ec.n - exp_sig[1]))

        # 2.1.4 Verifying Operation for V
        self.assertTrue(ecdsa_verify(ec, hf, msg, QU, sig))
        self.assertTrue(_ecdsa_verify(ec, hf, msg, QU, sig))


    def test_forge_hash_sig(self):
        """forging valid signatures for hash (DSA signs message, not hash)"""

        ec = secp256k1
        # see https://twitter.com/pwuille/status/1063582706288586752
        # Satoshi's key
        P = octets2point(secp256k1, "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c")

        u1 = 1
        u2 = 2  # pick them at will
        R = DblScalarMult(ec, u1, ec.G, u2, P)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        sig = r, s
        e = s * u1 % ec.n
        _ecdsa_verhlp(ec, e, P, sig)

        u1 = 1234567890
        u2 = 987654321  # pick them at will
        R = DblScalarMult(ec, u1, ec.G, u2, P)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        sig = r, s
        e = s * u1 % ec.n
        _ecdsa_verhlp(ec, e, P, sig)

    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [11,  13,  17,  19]

        for ec in low_card_curves:  # only low card curves or it would take forever
            if ec._p in prime:  # only few curves or it would take too long
                for d in range(ec.n):  # all possible private keys
                    if d == 0:  # invalid prvkey=0
                        self.assertRaises(ValueError, _ecdsa_sign, ec, 1, d, 1)
                        continue
                    P = pointMult(ec, d, ec.G)  # public key
                    for e in range(ec.n):  # all possible int from hash
                        for k in range(ec.n):  # all possible ephemeral keys

                            if k == 0:
                                self.assertRaises(ValueError, _ecdsa_sign, ec, e, d, k)
                                continue
                            R = pointMult(ec, k, ec.G)

                            r = R[0] % ec.n
                            if r == 0:
                                self.assertRaises(ValueError, _ecdsa_sign, ec, e, d, k)
                                continue

                            s = mod_inv(k, ec.n) * (e + d * r) % ec.n
                            if s == 0:
                                self.assertRaises(ValueError, _ecdsa_sign, ec, e, d, k)
                                continue

                            # bitcoin canonical 'low-s' encoding for ECDSA signatures
                            if s > ec.n / 2:
                                s = ec.n - s

                            # valid signature
                            sig = _ecdsa_sign(ec, e, d, k)
                            self.assertEqual((r, s), sig)
                            # valid signature must validate
                            self.assertTrue(_ecdsa_verhlp(ec, e, P, sig))

                            keys = _ecdsa_pubkey_recovery(ec, e, sig)
                            self.assertIn(P, keys)
                            for Q in keys:
                                self.assertTrue(_ecdsa_verhlp(ec, e, Q, sig))

    def test_pubkey_recovery(self):
        ec = secp112r2
        hf = sha256
        q = 0x1
        Q = pointMult(ec, q, ec.G)
        msg = 'Satoshi Nakamoto'.encode()
        sig = ecdsa_sign(ec, hf, msg, q)

        self.assertTrue(ecdsa_verify(ec, hf, msg, Q, sig))
        self.assertTrue(_ecdsa_verify(ec, hf, msg, Q, sig))

        keys = ecdsa_pubkey_recovery(ec, hf, msg, sig)
        self.assertIn(Q, keys)
        for Q in keys:
            self.assertTrue(ecdsa_verify(ec, hf, msg, Q, sig))
            self.assertTrue(_ecdsa_verify(ec, hf, msg, Q, sig))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
