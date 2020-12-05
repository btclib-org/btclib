#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.sign_to_contract` module."

import secrets
from hashlib import sha256

from btclib import dsa, ssa
from btclib.curve import secp256k1
from btclib.sign_to_contract import (
    ecdsa_commit_sign,
    ecssa_commit_sign,
    verify_commit,
)

ec = secp256k1


def test_sign_to_contract_dsa() -> None:
    m = sha256(b"to be signed").digest()
    c = sha256(b"to be committed").digest()

    prv_key, pub_key = dsa.gen_keys()
    dsa_sig, dsa_receipt = ecdsa_commit_sign(c, m, prv_key)
    dsa._assert_as_valid(m, pub_key, dsa_sig, sha256)
    assert verify_commit(c, dsa_receipt)

    k = 1 + secrets.randbelow(ec.n - 1)
    dsa_sig, dsa_receipt = ecdsa_commit_sign(c, m, prv_key, k)
    dsa._assert_as_valid(m, pub_key, dsa_sig, sha256)
    assert verify_commit(c, dsa_receipt)


def test_sign_to_contract_ssa() -> None:
    m = sha256(b"to be signed").digest()
    c = sha256(b"to be committed").digest()

    prv_key, pub = ssa.gen_keys()
    ssa_sig, ssa_receipt = ecssa_commit_sign(c, m, prv_key)
    ssa._assert_as_valid(m, pub, ssa_sig, sha256)
    assert verify_commit(c, ssa_receipt)

    k = 1 + secrets.randbelow(ec.n - 1)
    ssa_sig, ssa_receipt = ecssa_commit_sign(c, m, prv_key, k)
    ssa._assert_as_valid(m, pub, ssa_sig, sha256)
    assert verify_commit(c, ssa_receipt)
