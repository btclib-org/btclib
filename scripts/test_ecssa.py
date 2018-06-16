#!/usr/bin/env python3

import unittest
from ecssa import ec, ecssa_sign, ecssa_verify, ecssa_pubkey_recovery

class TestEcssa(unittest.TestCase):
    def test_ecssa(self):
        prv = 0x1
        pub = ec.pointMultiply(prv)
        msg = 'Satoshi Nakamoto'
        exp_sig = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                   0x5c0eed7fda3782b5e439e100834390459828ef7089dbd375e48949224b6f82c0)
        # FIXME: the above sig was generated with this code,
        #        it would be better to use a sig
        #        genearated by other code to test against
        ssasig = ecssa_sign(msg, prv)
        r, s = ecssa_sign(msg, prv)
        self.assertEqual(r, exp_sig[0])
        # ?????
        sigs = (exp_sig[1], ec.order - exp_sig[1])
        self.assertIn(s, sigs)

        self.assertTrue(ecssa_verify(msg, ssasig, pub))

        self.assertEqual(ecssa_pubkey_recovery(msg, ssasig), pub)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
