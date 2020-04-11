#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256

from btclib import dsa, ssa
from btclib.curvemult import mult
from btclib.signtocontract import (ecdsa_commit_sign, ecssa_commit_sign,
                                   verify_commit)
from btclib.curves import secp256k1 as ec


class TestSignToContract(unittest.TestCase):
    def test_signtocontract(self):
        prv = 0x1
        pub = mult(prv)
        m = b"to be signed"
        c = b"to be committed"

        dsa_sig, dsa_receipt = ecdsa_commit_sign(c, m, prv, None)
        self.assertIsNone(dsa._verify(m, pub, dsa_sig, ec, sha256))
        self.assertTrue(verify_commit(c, dsa_receipt))

        # 32 bytes message for ECSSA
        m = sha256(m).digest()
        ssa_sig, ssa_receipt = ecssa_commit_sign(c, m, prv, None)
        self.assertIsNone(ssa._verify(m, pub, ssa_sig, ec, sha256))
        self.assertTrue(verify_commit(c, ssa_receipt))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
