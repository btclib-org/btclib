#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256 as hf

from btclib.ec import pointMult
from btclib.curves import secp256k1 as ec
from btclib import dsa
from btclib.ssa import ecssa_verify
from btclib.signtocontract import ecdsa_commit_sign, ecssa_commit_sign, \
    verify_commit


class TestSignToContract(unittest.TestCase):
    def test_signtocontract(self):
        prv = 0x1
        pub = pointMult(ec, prv, ec.G)
        m = "to be signed".encode()
        c = "to be committed".encode()

        dsa_sig, dsa_receipt = ecdsa_commit_sign(c, ec, hf, m, prv, None)
        self.assertTrue(dsa.verify(ec, hf, m, pub, dsa_sig))
        self.assertTrue(verify_commit(c, ec, hf, dsa_receipt))

        # 32 bytes message for ECSSA
        m = hf(m).digest()
        ssa_sig, ssa_receipt = ecssa_commit_sign(c, ec, hf, m, prv, None)
        self.assertTrue(ecssa_verify(ec, hf, m, pub, ssa_sig))
        self.assertTrue(verify_commit(c, ec, hf, ssa_receipt))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
