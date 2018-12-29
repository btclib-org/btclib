#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.ellipticcurves import secp256k1, sha256, pointMultiply
from btclib.ecdsa import ecdsa_verify
from btclib.ecssa import ecssa_verify
from btclib.ecsigntocontract import ecdsa_commit_and_sign, \
    ecssa_commit_and_sign, verify_commit


class TestSignToContract(unittest.TestCase):
    def test_signtocontract(self):
        prv = 0x1
        pub = pointMultiply(secp256k1, prv, secp256k1.G)
        m = "to be signed".encode()
        c = "to be committed".encode()

        sig_ecdsa, receipt_ecdsa = ecdsa_commit_and_sign(
            m, prv, c, None, secp256k1, sha256)
        self.assertTrue(ecdsa_verify(sig_ecdsa, m, pub, secp256k1))
        self.assertTrue(verify_commit(receipt_ecdsa, c, secp256k1, sha256))

        # 32 bytes message for ECSSA
        m = sha256(m).digest()
        sig_ecssa, receipt_ecssa = ecssa_commit_and_sign(
            m, prv, c, None, secp256k1, sha256)
        self.assertTrue(ecssa_verify(sig_ecssa, m, pub, secp256k1))
        self.assertTrue(verify_commit(receipt_ecssa, c, secp256k1, sha256))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
