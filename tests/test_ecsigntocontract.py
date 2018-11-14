#!/usr/bin/env python3

import unittest
from btclib.ecsigntocontract import ec, sha256, \
                                    ecdsa_verify, ecssa_verify, \
                                    ecdsa_commit_and_sign, ecssa_commit_and_sign, \
                                    verify_commit

class TestSignToContract(unittest.TestCase):
    def test_digntocontract(self):
        prv = 0x1
        pub = ec.pointMultiply(prv, ec.G)
        m = "to be signed"
        c = "to be committed"

        sig_ecdsa, receipt_ecdsa = ecdsa_commit_and_sign(m, prv, c)
        self.assertTrue(ecdsa_verify(ec, m, sig_ecdsa, pub))
        self.assertTrue(verify_commit(receipt_ecdsa, c))

        sig_ecssa, receipt_ecssa = ecssa_commit_and_sign(m, prv, c)
        self.assertTrue(ecssa_verify(ec, m, sig_ecssa, pub))
        self.assertTrue(verify_commit(receipt_ecssa, c))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
