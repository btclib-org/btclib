#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.rfc6979` module."

import hashlib
import json
from os import path

import pytest

from btclib.ecc import dsa
from btclib.ecc.curve import CURVES, mult
from btclib.ecc.rfc6979 import rfc6979_
from btclib.hashes import reduce_to_hlen


def test_rfc6979() -> None:
    # source: https://bitcointalk.org/index.php?topic=285142.40
    msg = "Satoshi Nakamoto".encode()
    msg_hash = hashlib.sha256(msg).digest()
    x = 0x1
    k = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
    k2 = rfc6979_(msg_hash, x, hf=hashlib.sha256)
    assert k == k2


def test_rfc6979_example() -> None:
    class _helper:  # pylint: disable=too-few-public-methods
        def __init__(self, n: int) -> None:
            self.n = n
            self.nlen = n.bit_length()
            self.n_size = (self.nlen + 7) // 8

    # source: https://tools.ietf.org/html/rfc6979 section A.1
    fake_ec = _helper(0x4000000000000000000020108A2E0CC0D99F8A5EF)
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    msg = "sample".encode()
    msg_hash = hashlib.sha256(msg).digest()
    k = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
    assert k == rfc6979_(msg_hash, x, fake_ec)  # type: ignore


@pytest.mark.second
def test_rfc6979_tv() -> None:

    fname = "rfc6979.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        test_dict = json.load(file_)

    lower_s = False
    for ec_name in test_dict:
        ec = CURVES[ec_name]
        test_vectors = test_dict[ec_name]
        for x, x_U, y_U, hf, msg, k, r, s in test_vectors:
            x = int(x, 16)
            msg = msg.encode()
            m = reduce_to_hlen(msg, hf=getattr(hashlib, hf))
            # test RFC6979 implementation
            k2 = rfc6979_(m, x, ec, getattr(hashlib, hf))
            assert int(k, 16) == k2
            # test RFC6979 usage in DSA
            sig = dsa.sign_(m, x, k2, lower_s, ec=ec, hf=getattr(hashlib, hf))
            assert int(r, 16) == sig.r
            assert int(s, 16) == sig.s
            # test that RFC6979 is the default nonce for DSA
            sig = dsa.sign_(m, x, None, lower_s, ec=ec, hf=getattr(hashlib, hf))
            assert int(r, 16) == sig.r
            assert int(s, 16) == sig.s
            # test key-pair coherence
            U = mult(x, ec.G, ec)
            assert int(x_U, 16), int(y_U, 16) == U
            # test signature validity
            dsa.assert_as_valid(msg, U, sig, lower_s, getattr(hashlib, hf))
