#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.signtocontract` module."

import secrets
from hashlib import sha256

from btclib import dsa, ssa
from btclib.curves import secp256k1 as ec
from btclib.signtocontract import (
    ecdsa_commit_sign,
    ecssa_commit_sign,
    verify_commit,
)


def test_signtocontract() -> None:
    m = sha256(b"to be signed").digest()
    c = sha256(b"to be committed").digest()

    prv, Pub = dsa.gen_keys()
    dsa_sig, dsa_receipt = ecdsa_commit_sign(c, m, prv)
    dsa._assert_as_valid(m, Pub, dsa_sig, ec, sha256)
    assert verify_commit(c, dsa_receipt)

    k = 1 + secrets.randbelow(ec.n - 1)
    dsa_sig, dsa_receipt = ecdsa_commit_sign(c, m, prv, k)
    dsa._assert_as_valid(m, Pub, dsa_sig, ec, sha256)
    assert verify_commit(c, dsa_receipt)

    prv, pub = ssa.gen_keys()
    ssa_sig, ssa_receipt = ecssa_commit_sign(c, m, prv)
    ssa._assert_as_valid(m, pub, ssa_sig, ec, sha256)
    assert verify_commit(c, ssa_receipt)

    k = 1 + secrets.randbelow(ec.n - 1)
    ssa_sig, ssa_receipt = ecssa_commit_sign(c, m, prv, k)
    ssa._assert_as_valid(m, pub, ssa_sig, ec, sha256)
    assert verify_commit(c, ssa_receipt)
