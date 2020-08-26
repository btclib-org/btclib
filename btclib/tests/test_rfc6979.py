#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.rfc6979` module."

import hashlib
import json
from os import path

import pytest

from btclib import dsa
from btclib.curvemult import mult
from btclib.curves import CURVES
from btclib.rfc6979 import rfc6979


def test_rfc6979() -> None:
    # source: https://bitcointalk.org/index.php?topic=285142.40
    msg = "Satoshi Nakamoto"
    x = 0x1
    k = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
    k2 = rfc6979(msg, x, hf=hashlib.sha256)
    assert k == k2


def test_rfc6979_example() -> None:
    class _helper:
        def __init__(self, n: int) -> None:
            self.n = n
            self.nlen = n.bit_length()
            self.nsize = (self.nlen + 7) // 8

    # source: https://tools.ietf.org/html/rfc6979 section A.1
    fake_ec = _helper(0x4000000000000000000020108A2E0CC0D99F8A5EF)
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    msg = "sample"
    k = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
    assert k == rfc6979(msg, x, fake_ec)  # type: ignore


@pytest.mark.second
def test_rfc6979_tv() -> None:

    fname = "rfc6979.json"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "r") as f:
        test_dict = json.load(f)

    for ec_name in test_dict:
        ec = CURVES[ec_name]
        test_vectors = test_dict[ec_name]
        for x, x_U, y_U, hf, msg, k, r, s in test_vectors:
            x = int(x, 16)
            # test RFC6979 implementation
            k2 = rfc6979(msg, x, ec, eval("hashlib." + hf))
            assert k == hex(k2)
            # test RFC6979 usage in DSA
            sig = dsa.sign(msg, x, k2, False, ec, eval("hashlib." + hf))
            assert r == hex(sig[0])
            assert s == hex(sig[1])
            # test that RFC6979 is the default nonce for DSA
            sig = dsa.sign(msg, x, k=None, low_s=False, ec=ec, hf=eval("hashlib." + hf))
            assert r == hex(sig[0])
            assert s == hex(sig[1])
            # test key-pair coherence
            U = mult(x, ec.G, ec)
            assert (int(x_U, 16), int(y_U, 16)) == U
            # test signature validity
            dsa.assert_as_valid(msg, U, sig, ec, hf=eval("hashlib." + hf))
