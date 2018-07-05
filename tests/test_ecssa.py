#!/usr/bin/env python3

import unittest
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

        self.assertEqual(ecssa_pubkey_recovery(msg, ssasig), pub)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
