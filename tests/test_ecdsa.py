#!/usr/bin/env python3

import unittest
from btclib.ecdsa import ecdsa_sign, ecdsa_verify, ecdsa_pubkey_recovery
from btclib.ellipticcurves import pointMultiply, secp256k1 as ec
from tests.test_ellipticcurves import lowcard
from btclib.rfc6979 import rfc6979
from hashlib import sha256 as hasher
from btclib.ecsignutils import int_from_hash
from btclib.ellipticcurves import mod_inv

class TestEcdsa(unittest.TestCase):
    def test_ecdsa(self):
        q = 0x1
        Q = ec.pointMultiply(q, ec.G)
        msg = 'Satoshi Nakamoto'

        dsasig = ecdsa_sign(ec, msg, q)
        self.assertTrue(ecdsa_verify(ec, msg, dsasig, Q))
        # malleability
        malleated_sig = (dsasig[0], ec.n - dsasig[1])
        self.assertTrue(ecdsa_verify(ec, msg, malleated_sig, Q))

        keys = ecdsa_pubkey_recovery(ec, msg, dsasig)
        self.assertIn(Q, keys)

        # source: https://bitcointalk.org/index.php?topic=285142.40
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
        r, s = dsasig
        self.assertEqual(r, exp_sig[0])
        sigs = (exp_sig[1], ec.n - exp_sig[1])
        self.assertIn(s, sigs)

    # test all msg/key pairs on low cardinality curves
    def test_low_cardinality(self):
        # curve.n has to be prime to sign
        prime = [2,	3, 5, 7, 11, 13, 17, 19, 23, 29,
                 31, 37, 41, 43, 47, 53, 59, 61, 67, 
                 71, 73, 79, 83, 89, 97, 101, 103, 107,
             	 109, 113, 127,	131, 137, 139, 149,	151,
            	 157, 163, 167,	173, 179, 181, 191, 193,
                 197, 199, 211,	223, 227, 229, 233, 239,
                 241, 251, 257, 263, 269, 271, 277,	281,
                 283, 293, 307,	311, 313, 317, 331, 337]
        for curve in lowcard:
            if curve.n in prime:
                for m in range(0, curve.n):
                    # message in bytes
                    m = m.to_bytes(curve.bytesize, 'big')
                    for q in range(1, curve.n):
                        Q = pointMultiply(curve, q, curve.G)
                        # looking if the signature fails
                        k = rfc6979(q, m, hasher)
                        K = pointMultiply(curve, k, curve.G)

                        if K == None:
                            self.assertRaises(AssertionError, ecdsa_sign, curve, m, q)
                        else:
                            r = K[0] % curve.n
                            e = int_from_hash(m, curve.n)
                            s = mod_inv(k, curve.n) * (e + q * r) % curve.n
                            if r == 0 or s == 0:
                                self.assertRaises(AssertionError, ecdsa_sign, curve, m, q)
                            else:
                                # valid signature, must validate
                                self.assertTrue(K != None and r != 0 and s != 0)
                                dsasig = ecdsa_sign(curve, m, q)
                                self.assertTrue(ecdsa_verify(curve, m, dsasig, Q))
                                # malleability
                                malleated_sig = (dsasig[0], curve.n - dsasig[1])
                                self.assertTrue(ecdsa_verify(curve, m, malleated_sig, Q))

                                # key recovery
                                keys = ecdsa_pubkey_recovery(curve, m, dsasig)
                                self.assertIn(Q, keys)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
