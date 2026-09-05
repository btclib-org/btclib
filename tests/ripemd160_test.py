# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib._ripemd160` module.

The vectors are the ones the authors of RIPEMD-160 publish at
https://homes.esat.kuleuven.be/~bosselae/ripemd160.html, as the vendored
upstream carries them in its own unittest -- Bitcoin Core's
test/functional/test_framework/crypto/ripemd160.py, whose revision
`TF2.md` pins.

Eight of that upstream's nine. The ninth is 10^6 times "a", and in pure
Python it takes 1.5 s, which would make it the slowest test in this suite
(the slowest today is 1.47 s) for the one property it has over the others,
that the input spans many blocks. `test_matches_hashlib` covers that
property over 138 lengths, 4096 bytes among them, in some 5 ms.
"""

from __future__ import annotations

import hashlib

import pytest

from btclib._ripemd160 import fi, ripemd160
from btclib.exceptions import BTClibValueError
from btclib.hashes import _RIPEMD160_IN_HASHLIB

TEST_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
)


@pytest.mark.parametrize("msg, digest", TEST_VECTORS)
def test_ripemd160(msg: bytes, digest: str) -> None:
    """Reproduce the designers' published RIPEMD-160 vectors."""
    assert ripemd160(msg).hex() == digest


@pytest.mark.skipif(
    not _RIPEMD160_IN_HASHLIB,
    reason="hashlib has no ripemd160 to compare against",
)
def test_matches_hashlib() -> None:
    """Match hashlib over lengths spanning padding and block boundaries."""
    # every length up to 135 covers the two padding boundaries, 55/56 and
    # 119/120, and the block boundaries at 64 and 128; 4096 covers the
    # many-block loop, which the upstream vector left out above is what
    # otherwise exercises
    for length in [*range(136), 1000, 4096]:
        # a fixed pattern rather than random bytes: a failure here must be
        # reproducible from the length alone
        data = bytes((7 * i + 13) & 0xFF for i in range(length))
        assert ripemd160(data) == hashlib.new("ripemd160", data).digest()


def test_invalid_round_number() -> None:
    """`fi` is called with 0 to 4 and says so.

    Upstream ends the chain with `assert False`; this is the same
    unreachable line, reached on purpose. Nothing in the compression
    function can produce a sixth round: it passes `j >> 4` and `4 - (j >>
    4)` for j in range(80).
    """
    for i in (5, -1):
        with pytest.raises(BTClibValueError, match=f"invalid round number: {i}"):
            fi(0, 0, 0, i)
