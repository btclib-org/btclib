#!/usr/bin/env python3

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Copyright (C) 2019-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.bech32` module.

These tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

- splitted the original tests.py file in test_bech32.py
  and test_b32.py
- checked for raised exceptions instead of assertIsNone
"""

import pytest

from btclib.bech32 import _BECH32_1_CONST, _BECH32_M_CONST, decode, encode
from btclib.exceptions import BTClibValueError


def test_bech32() -> None:
    "Test bech32 checksum."

    valid_checksum = [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
        # the next one would have been invalid with the 90 char limit
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    ]

    for test in valid_checksum:
        decoded = decode(test, _BECH32_1_CONST)
        assert decoded == decode(test.encode("ascii"), _BECH32_1_CONST)
        assert encode(*decoded, _BECH32_1_CONST).decode() == test.lower()
        pos = test.rfind("1")
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]
        with pytest.raises(BTClibValueError):
            decode(test, _BECH32_1_CONST)

    invalid_checksum = [
        ["\x20" + " 1nwldj5", r"HRP character out of range: *"],
        ["\x7F" + "1axkwrx", r"HRP character out of range: *"],
        ["\x80" + "1eym55h", r"HRP character out of range: *"],
        ["pzry9x0s0muk", r"no separator character: *"],
        ["1pzry9x0s0muk", r"empty HRP: *"],
        ["x1b4n0q5v", r"invalid data character: *"],
        ["li1dgmt3", r"too short checksum: *"],
        # Invalid character in checksum
        ["de1lg7wt\xff", r"invalid character in checksum: *"],
        # checksum calculated with uppercase form of HRP
        ["A1G7SGD8", r"invalid checksum: *"],
        ["10a06t8", r"empty HRP: *"],
        ["1qzzfhee", r"empty HRP: *"],
    ]

    for addr, err_msg in invalid_checksum:
        with pytest.raises(BTClibValueError, match=err_msg):
            decode(addr, _BECH32_1_CONST)


def test_bech32_insertion_issue() -> None:
    """Test documented bech32 insertion issue.

    https://github.com/sipa/bech32/issues/51
    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-November/017443.html
    https://gist.github.com/sipa/a9845b37c1b298a7301c33a04090b2eb
    https://gist.github.com/sipa/a9845b37c1b298a7301c33a04090b2eb
    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-October/018236.html
    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-December/018292.html
    https://gist.github.com/sipa/14c248c288c3880a3b191f978a34508e

    """
    strings = ("ii2134hk2xmat79tp", "eyg5bsz1l2mrq5ypl40hp")
    for string in strings:
        for i in range(20):
            decode(string[:-1] + i * "q" + string[-1:], _BECH32_1_CONST)


def test_bech32m() -> None:

    valid_checksum = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
        # the next one would have been invalid with the 90 char limit
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    ]
    for test in valid_checksum:
        decoded = decode(test, _BECH32_M_CONST)
        assert decoded == decode(test.encode("ascii"), _BECH32_M_CONST)
        assert encode(*decoded, _BECH32_M_CONST).decode() == test.lower()
        pos = test.rfind("1")
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]
        with pytest.raises(BTClibValueError):
            decode(test, _BECH32_M_CONST)

    invalid_checksum = [
        ["\x20" + "1xj0phk", r"HRP character out of range: *"],
        ["\x7F" + "1g6xzxy", r"HRP character out of range: *"],
        ["\x80" + "1vctc34", r"HRP character out of range: *"],
        ["qyrz8wqd2c9m", r"no separator character: *"],
        ["1qyrz8wqd2c9m", r"empty HRP: *"],
        ["y1b0jsk6g", r"invalid data character: *"],
        ["lt1igcx5c0", r"invalid data character: *"],
        ["in1muywd", r"too short checksum: *"],
        ["mm1crxm3i", r"invalid character in checksum: *"],
        ["au1s5cgom", r"invalid character in checksum: *"],
        ["M1VUXWEZ", r"invalid checksum: *"],
        ["16plkw9", r"empty HRP: *"],
        ["1p2gdwpf", r"empty HRP: *"],
    ]

    for addr, err_msg in invalid_checksum:
        with pytest.raises(BTClibValueError, match=err_msg):
            decode(addr, _BECH32_M_CONST)
