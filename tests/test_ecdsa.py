#!/usr/bin/env python3

import unittest
from btclib.ecdsa import ec, ecdsa_sign, ecdsa_verify, ecdsa_pubkey_recovery

class TestEcdsa(unittest.TestCase):
    def test_ecdsa(self):
        prv = 0x1
        pub = ec.pointMultiply(prv, ec.G)
        msg = 'Satoshi Nakamoto'

        dsasig = ecdsa_sign(msg, prv)
        self.assertTrue(ecdsa_verify(msg, dsasig, pub))
        # malleability
        malleated_sig = (dsasig[0], ec.n - dsasig[1])
        self.assertTrue(ecdsa_verify(msg, malleated_sig, pub))

        keys = (ecdsa_pubkey_recovery(msg, dsasig, 0),
                ecdsa_pubkey_recovery(msg, dsasig, 1))
        self.assertIn(pub, keys)

        # source: https://bitcointalk.org/index.php?topic=285142.40
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
        r, s = dsasig
        self.assertEqual(r, exp_sig[0])
        sigs = (exp_sig[1], ec.n - exp_sig[1])
        self.assertIn(s, sigs)



if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
