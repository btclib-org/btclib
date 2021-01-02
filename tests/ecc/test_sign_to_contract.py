#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.sign_to_contract` module."

import secrets
from hashlib import sha1, sha256

from btclib.ecc import dsa, ssa
from btclib.ecc.curve import CURVES, secp256k1
from btclib.ecc.sign_to_contract import (
    dsa_commit_sign,
    dsa_verify_commit,
    ssa_commit_sign,
    ssa_verify_commit,
)


def test_sign_to_contract_dsa() -> None:
    commit_msg = "to be committed".encode()
    msg = "to be signed".encode()

    lower_s = True
    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            prv_key, pub_key = dsa.gen_keys(ec=ec)
            nonce = None
            dsa_sig, receipt = dsa_commit_sign(commit_msg, msg, prv_key, nonce, ec, hf)
            dsa.assert_as_valid(msg, pub_key, dsa_sig, lower_s, hf)
            assert dsa_verify_commit(
                commit_msg, receipt, msg, pub_key, dsa_sig, lower_s, hf
            )

            nonce = 1 + secrets.randbelow(ec.n - 1)
            dsa_sig, R = dsa_commit_sign(commit_msg, msg, prv_key, nonce, ec, hf)
            dsa.assert_as_valid(msg, pub_key, dsa_sig, lower_s, hf)
            assert dsa_verify_commit(commit_msg, R, msg, pub_key, dsa_sig, lower_s, hf)


def test_sign_to_contract_ssa() -> None:
    commit_msg = "to be committed".encode()
    msg = "to be signed".encode()

    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            prv_key, pub_key = ssa.gen_keys(ec=ec)
            ssa_sig, receipt = ssa_commit_sign(commit_msg, msg, prv_key, None, ec, hf)
            ssa.assert_as_valid(msg, pub_key, ssa_sig, hf)
            assert ssa_verify_commit(commit_msg, receipt, msg, pub_key, ssa_sig, hf)

            random_nonce = 1 + secrets.randbelow(ec.n - 1)
            ssa_sig, R = ssa_commit_sign(commit_msg, msg, prv_key, random_nonce, ec, hf)
            ssa.assert_as_valid(msg, pub_key, ssa_sig, hf)
            assert ssa_verify_commit(commit_msg, R, msg, pub_key, ssa_sig, hf)
