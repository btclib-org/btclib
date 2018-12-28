#!/usr/bin/env python3

import unittest
from hashlib import sha256

from btclib.numbertheory import mod_inv
from btclib.ellipticcurves import secp256k1, _jac_from_affine, to_Point, \
                                  pointMultiply, DoubleScalarMultiplication
from btclib.ecdsa import rfc6979, int_from_hash, \
                         _ecdsa_sign, ecdsa_sign, to_dsasig, \
                         _ecdsa_verify, ecdsa_verify, \
                         _ecdsa_pubkey_recovery, ecdsa_pubkey_recovery

from tests.test_ellipticcurves import low_card_curves

class TestEcdsa(unittest.TestCase):
    def test_ecdsa(self):
        q = 0x1
        Q = pointMultiply(secp256k1, q, secp256k1.G)
        msg = 'Satoshi Nakamoto'.encode()
        H = sha256(msg).digest()
        dsasig = ecdsa_sign(msg, q)
        # https://bitcointalk.org/index.php?topic=285142.40
        # Deterministic Usage of DSA and ECDSA (RFC 6979)
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
        r, s = to_dsasig(dsasig, secp256k1)
        self.assertEqual(r, exp_sig[0])
        self.assertIn(s, (exp_sig[1], secp256k1.n - exp_sig[1]))

        self.assertTrue(ecdsa_verify(dsasig, msg, Q))
        self.assertTrue(_ecdsa_verify(dsasig, H, Q))

        # malleability
        malleated_sig = (r, secp256k1.n - s)
        self.assertTrue(ecdsa_verify(malleated_sig, msg, Q))
        self.assertTrue(_ecdsa_verify(malleated_sig, H, Q))

        keys = ecdsa_pubkey_recovery(dsasig, msg)
        self.assertIn(Q, keys)

        # message instead of message digest
        self.assertRaises(ValueError, _ecdsa_verify, dsasig, msg, Q)

        fmsg = 'Craig Wright'.encode()
        fH = sha256(fmsg).digest()
        self.assertFalse(ecdsa_verify(dsasig, fmsg, Q))
        self.assertFalse(_ecdsa_verify(dsasig, fH, Q))

        fdsasig = (dsasig[0], dsasig[1], dsasig[1])
        self.assertFalse(ecdsa_verify(fdsasig, msg, Q))
        self.assertRaises(TypeError, _ecdsa_verify, fdsasig, H, Q)

        fq = 0x4
        fQ = pointMultiply(secp256k1, fq, secp256k1.G)
        self.assertFalse(ecdsa_verify(dsasig, msg, fQ))
        self.assertFalse(_ecdsa_verify(dsasig, H, fQ))

    def test_forge_hash_sig(self):
        """forging valid signatures for hash (DSA signs message, not hash)"""

        ec = secp256k1
        # see https://twitter.com/pwuille/status/1063582706288586752
        # Satoshi's key
        P = to_Point(secp256k1, "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c")

        u1 = 1; u2 = 2 # pick them at will
        R = DoubleScalarMultiplication(ec, u1, ec.G, u2, P)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        dsasig = r , s
        e = s * u1 % ec.n
        hash_digest = e.to_bytes(32, 'big')
        _ecdsa_verify(dsasig, hash_digest, P, ec)

        u1 = 1234567890; u2 = 987654321 # pick them at will
        R = DoubleScalarMultiplication(ec, u1, ec.G, u2, P)
        r = R[0] % ec.n
        u2inv = mod_inv(u2, ec.n)
        s = r * u2inv % ec.n
        dsasig = r , s
        e = s * u1 % ec.n
        hash_digest = e.to_bytes(32, 'big')
        _ecdsa_verify(dsasig, hash_digest, P, ec)




    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [
              3,   5,   7,  11,  13,  17,  19,  23,  29,  31,
             37,  41,  43,  47,  53,  59,  61,  67,  71,  73#,
            # 79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
            #131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            #181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            #239, 241, 251, 257, 263, 269, 271, 277, 281, 283
            ]

        # all possible hashed messages
        hlen = 32
        H = [i.to_bytes(hlen, 'big') for i in range(0, max(prime))]

        for ec in low_card_curves: # only low card curves or it would take forever
            if ec.n in prime: # only few curves or it would take too long
                # all possible private keys (invalid 0 included)
                for q in range(0, ec.n):
                    if q == 0:
                        self.assertRaises(ValueError, _ecdsa_sign, H[0], q, None, ec)
                        continue
                    Q = pointMultiply(ec, q, ec.G) # public key
                    for m in range(0, ec.n): # all possible hashed messages

                        k = rfc6979(q, H[m], ec, sha256) # ephemeral key
                        K = pointMultiply(ec, k, ec.G)
                        if K[1] == 0:
                            self.assertRaises(ValueError, _ecdsa_sign, H[m], q, k, ec)
                            continue

                        r = K[0] % ec.n
                        if r == 0:
                            self.assertRaises(ValueError, _ecdsa_sign, H[m], q, k, ec)
                            continue

                        e = int_from_hash(H[m], ec, sha256)
                        s = mod_inv(k, ec.n) * (e + q * r) % ec.n
                        if s == 0:
                            print("it does not enter here")
                            self.assertRaises(ValueError, _ecdsa_sign, H[m], q, k, ec)
                            continue

                        # valid signature
                        sig = _ecdsa_sign(H[m], q, k, ec)
                        self.assertEqual((r, s), sig)
                        # valid signature must validate
                        self.assertTrue(_ecdsa_verify(sig, H[m], Q, ec))
                        # malleated signature must validate
                        malleated_sig = (sig[0], ec.n - sig[1])
                        self.assertTrue(_ecdsa_verify(malleated_sig, H[m], Q, ec))
                        # key recovery
                        keys = _ecdsa_pubkey_recovery(sig, H[m], ec)
                        self.assertIn(Q, keys)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
