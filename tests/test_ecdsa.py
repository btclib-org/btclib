#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256

from btclib.numbertheory import mod_inv
from btclib.ec import secp256k1, octets2point, _jac_from_aff, pointMult, \
    DblScalarMult
from btclib.ecdsa import rfc6979, bits2int, to_dsasig, \
    ecdsa_sign, _ecdsa_sign, ecdsa_verify, _ecdsa_verify, _ecdsa_verhlp, \
    ecdsa_pubkey_recovery, _ecdsa_pubkey_recovery

from tests.test_ec import low_card_curves


class TestEcdsa(unittest.TestCase):
    def test_ecdsa(self):
        ec = secp256k1
        q = 0x1
        Q = pointMult(ec, q, ec.G)
        msg = 'Satoshi Nakamoto'.encode()
        dsasig = ecdsa_sign(msg, q)
        # https://bitcointalk.org/index.php?topic=285142.40
        # Deterministic Usage of DSA and ECDSA (RFC 6979)
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
        r, s = to_dsasig(dsasig, ec)
        self.assertEqual(r, exp_sig[0])
        self.assertIn(s, (exp_sig[1], ec.n - exp_sig[1]))

        self.assertTrue(ecdsa_verify(dsasig, msg, Q))
        self.assertTrue(_ecdsa_verify(dsasig, msg, Q, ec, sha256))

        # malleability
        malleated_sig = (r, ec.n - s)
        self.assertTrue(ecdsa_verify(malleated_sig, msg, Q))
        self.assertTrue(_ecdsa_verify(malleated_sig, msg, Q, ec, sha256))

        keys = ecdsa_pubkey_recovery(dsasig, msg)
        self.assertIn(Q, keys)

        fmsg = 'Craig Wright'.encode()
        self.assertFalse(ecdsa_verify(dsasig, fmsg, Q))
        self.assertFalse(_ecdsa_verify(dsasig, fmsg, Q, ec, sha256))

        fdsasig = (dsasig[0], dsasig[1], dsasig[1])
        self.assertFalse(ecdsa_verify(fdsasig, msg, Q))
        self.assertRaises(TypeError, _ecdsa_verify, fdsasig, msg, Q, ec, sha256)

        fq = 0x4
        fQ = pointMult(ec, fq, ec.G)
        self.assertFalse(ecdsa_verify(dsasig, msg, fQ))
        self.assertFalse(_ecdsa_verify(dsasig, msg, fQ, ec, sha256))

        # r not in [1, n-1]
        invalid_dassig = 0, dsasig[1]
        self.assertRaises(ValueError, to_dsasig, invalid_dassig, ec)
        # s not in [1, n-1]
        invalid_dassig = dsasig[0], 0
        self.assertRaises(ValueError, to_dsasig, invalid_dassig, ec)

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
        dsasig = r, s
        e = s * u1 % ec.n
        _ecdsa_verhlp(dsasig, e, P, ec)

        u1 = 1234567890
        u2 = 987654321  # pick them at will
        R = DblScalarMult(ec, u1, ec.G, u2, P)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        dsasig = r, s
        e = s * u1 % ec.n
        _ecdsa_verhlp(dsasig, e, P, ec)

    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [11,  13,  17,  19]

        for ec in low_card_curves:  # only low card curves or it would take forever
            e_max = ec.n * 2
            if ec._p in prime:  # only few curves or it would take too long
                for d in range(ec.n):  # all possible private keys
                    if d == 0:  # invalid prvkey=0
                        self.assertRaises(ValueError, _ecdsa_sign, 1, d, 1, ec)
                        continue
                    P = pointMult(ec, d, ec.G)  # public key
                    for e in range(e_max):  # all possible int from hash
                        for k in range(ec.n):  # all possible ephemeral keys

                            if k == 0:
                                self.assertRaises(
                                    ValueError, _ecdsa_sign, e, d, k, ec)
                                continue
                            R = pointMult(ec, k, ec.G)

                            r = R[0] % ec.n
                            if r == 0:
                                self.assertRaises(
                                    ValueError, _ecdsa_sign, e, d, k, ec)
                                continue

                            s = mod_inv(k, ec.n) * (e + d * r) % ec.n
                            if s == 0:
                                self.assertRaises(
                                    ValueError, _ecdsa_sign, e, d, k, ec)
                                continue

                            # valid signature
                            sig = _ecdsa_sign(e, d, k, ec)
                            self.assertEqual((r, s), sig)
                            # valid signature must validate
                            self.assertTrue(_ecdsa_verhlp(sig, e, P, ec))
                            # malleated signature must validate
                            #malleated_sig = (sig[0], ec.n - sig[1])
                            #self.assertTrue(_ecdsa_verhlp(malleated_sig, e, P, ec))
                            # key recovery
                            #keys = _ecdsa_pubkey_recovery(sig, e, ec)
                            #self.assertIn(P, keys)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
