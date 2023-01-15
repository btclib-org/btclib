#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.sign_to_contract` module."""

import random
from hashlib import sha1, sha256

from btclib.ec import secp256k1
from btclib.ec.curve import CURVES
from btclib.ecc import dsa
from btclib.ecc.sign_to_contract import dsa_commit_sign, dsa_verify_commit

random.seed(42)


def test_sign_to_contract_dsa() -> None:
    commit_msg = b"to be committed"
    msg = b"to be signed"

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

            nonce = 1 + random.randrange(ec.n - 1)
            dsa_sig, R = dsa_commit_sign(commit_msg, msg, prv_key, nonce, ec, hf)
            dsa.assert_as_valid(msg, pub_key, dsa_sig, lower_s, hf)
            assert dsa_verify_commit(commit_msg, R, msg, pub_key, dsa_sig, lower_s, hf)
