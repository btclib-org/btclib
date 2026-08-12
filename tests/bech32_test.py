# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
"""Tests for the `btclib.bech32` module.

These tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

- split the original tests.py file in bech32_test.py
  and b32_test.py
- checked for raised exceptions instead of assertIsNone
"""

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.bech32 import (
    _ALPHABET,
    _BECH32_1_CONST,
    _BECH32_M_CONST,
    _GENERATOR,
    _TAPS,
    decode,
    encode,
)
from btclib.exceptions import BTClibValueError


def test_the_tap_table_holds_the_taps_it_replaces() -> None:
    """Each entry is the XOR of the generator constants its bits select.

    What `_polymod` reads from `_TAPS` once per character, the reference
    computes with the five conditional XORs written out below. `chk >> 25`
    is five bits wide, so the 32 entries are the whole domain: this is
    exhaustive rather than a sample, which is what a table of constants no
    reader can check by eye asks for.
    """
    assert len(_TAPS) == 32
    for top in range(32):
        taps = 0
        for i in range(5):
            taps ^= _GENERATOR[i] if ((top >> i) & 1) else 0
        assert _TAPS[top] == taps


def test_bech32() -> None:
    """Test bech32 checksum."""
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
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]  # noqa: PLW2901
        with pytest.raises(BTClibValueError):  # assorted error messages
            decode(test, _BECH32_1_CONST)

    # a byte outside ascii is not a str decode() ever receives from the
    # loop above, which only ever encodes an already-valid bech32 string:
    # nothing else exercises the UnicodeDecodeError catch this raises
    # instead of letting fly past a caller written to catch BTClibValueError
    with pytest.raises(BTClibValueError, match="non-ascii character in bech32 string"):
        decode(
            b"\xff1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
        )

    invalid_checksum = [
        ["\x20" + " 1nwldj5", r"HRP character out of range: *"],
        ["\x7f" + "1axkwrx", r"HRP character out of range: *"],
        ["\x80" + "1eym55h", r"HRP character out of range: *"],
        # the boundary itself, not \x20/\x7f/\x80 (all far outside it):
        # `47 < ord(x) < 123` weakened at either end to `<=` still
        # refuses those three and would accept "/" (47) or "{" (123)
        ["/1nwldj5", r"HRP character out of range: *"],
        ["{1axkwrx", r"HRP character out of range: *"],
        # mixed case where lowering it does not sort below the original:
        # `bech.lower() != bech` weakened to `< bech` is false here (the
        # raised "u" sorts above the "U" it replaces), and the `and`
        # after it only raises if the upper-casing check also does
        ["a12UEL5L", r"mixed case: *"],
        ["pzry9x0s0muk", r"no separator character: *"],
        ["1pzry9x0s0muk", r"empty HRP: *"],
        ["x1b4n0q5v", r"invalid data character: *"],
        ["li1dgmt3", r"too short checksum: *"],
        # Invalid character in checksum
        ["de1lg7wt\xff", r"invalid character in checksum: *"],
        # the same, at the far end of the checksum rather than the near
        # one: `bech[-6:]` weakened to `bech[-5:]` still catches the
        # vector above (its invalid byte is the very last character) and
        # misses this one, six characters from the end and not five
        ["de1\xffqpzry", r"invalid character in checksum: *"],
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

    - https://github.com/sipa/bech32/issues/51
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-November/017443.html
    - https://gist.github.com/sipa/a9845b37c1b298a7301c33a04090b2eb
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-October/018236.html
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-December/018292.html
    - https://gist.github.com/sipa/14c248c288c3880a3b191f978a34508e
    """
    strings = ("ii2134hk2xmat79tp", "eyg5bsz1l2mrq5ypl40hp")
    for string, i in itertools.product(strings, range(20)):
        decode(string[:-1] + i * "q" + string[-1:], _BECH32_1_CONST)


def test_bech32m() -> None:
    """Reproduce the reference bech32m checksum vectors, valid and invalid."""
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
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]  # noqa: PLW2901
        with pytest.raises(BTClibValueError):
            decode(test, _BECH32_M_CONST)

    invalid_checksum = [
        ["\x20" + "1xj0phk", r"HRP character out of range: *"],
        ["\x7f" + "1g6xzxy", r"HRP character out of range: *"],
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


# lowercase only: encode writes the data part in lowercase, and a
# string mixing the two cases is rejected outright. "1" is left in on
# purpose -- it is the separator, and the hrp is delimited by the *last*
# one, which is the only thing that makes an hrp containing it work
HRP = st.text(alphabet="0123456789abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10)
# non-empty: the constant to checksum with is chosen by the first value,
# which is the witness version when the payload is an address
DATA = st.lists(st.integers(min_value=0, max_value=31), min_size=1, max_size=80)


@given(hrp=HRP, data=DATA)
def test_round_trip(hrp: str, data: list[int]) -> None:
    """A bech32 string decodes to the hrp and data it was built from."""
    assert decode(encode(hrp, data)) == (hrp, data)


@given(hrp=HRP, data=DATA, position=st.integers(min_value=0), value=st.integers(0, 31))
def test_a_changed_character_fails_the_checksum(
    hrp: str, data: list[int], position: int, value: int
) -> None:
    """What the checksum is for, over the whole space rather than a vector."""
    encoded = encode(hrp, data).decode("ascii")
    # only the data part: changing the hrp is a different address, not a
    # corrupted one, and the separator would move
    body = encoded[len(hrp) + 1 :]
    i = position % len(body)
    mutated = body[:i] + _ALPHABET[value] + body[i + 1 :]
    if mutated == body:
        return
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        decode(f"{hrp}1{mutated}")
