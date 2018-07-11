#!/usr/bin/env python3

import unittest
from hashlib import sha256
from btclib.ellipticcurves import bytes_from_Point
from btclib.ecssa import ec, ecssa_sign, ecssa_verify, ecssa_pubkey_recovery


class TestEcssa(unittest.TestCase):
    def test_ecssa(self):
        prv = 0x1
        pub = ec.pointMultiply(prv, ec.G)
        msg = 'Satoshi Nakamoto'

        ssasig = ecssa_sign(msg, prv)
        self.assertTrue(ecssa_verify(msg, ssasig, pub))
        # malleability
        malleated_sig = (ssasig[0], ec.order - ssasig[1])
        self.assertFalse(ecssa_verify(msg, malleated_sig, pub))

        e = sha256(ssasig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   sha256(msg.encode()).digest()).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, ssasig), pub)

    def test_ecssa_bip(self):
        prv = 0x1
        pub = ec.pointMultiply(prv, ec.G)
        msg = b'\x00' * 32
        expected_sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
                        0x7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = ecssa_sign(msg, prv, eph_prv)
        self.assertTrue(ecssa_verify(msg, sig, pub))
        # malleability
        malleated_sig = (sig[0], ec.order - sig[1])
        self.assertFalse(ecssa_verify(msg, malleated_sig, pub))

        self.assertEqual(sig, expected_sig)

        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig), pub)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
