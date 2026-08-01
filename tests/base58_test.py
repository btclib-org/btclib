#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.base58` module."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.base58 import (
    MAX_LENGTH,
    _b58decode,
    _b58decode_to_int,
    _b58encode,
    _b58encode_from_int,
    b58decode,
    b58encode,
)
from btclib.exceptions import BTClibValueError


def test_empty() -> None:
    assert _b58encode(b"") == b""
    assert _b58decode(_b58encode(b"")) == b""

    assert b58decode(b58encode(b""), 0) == b""


def test_hello_world() -> None:
    assert _b58encode(b"hello world") == b"StV1DL6CwTryKyV"
    assert _b58decode(b"StV1DL6CwTryKyV") == b"hello world"
    assert _b58decode(_b58encode(b"hello world")) == b"hello world"
    assert _b58encode(_b58decode(b"StV1DL6CwTryKyV")) == b"StV1DL6CwTryKyV"

    assert b58decode(b58encode(b"hello world"), 11) == b"hello world"


def test_trailing_zeros() -> None:
    assert _b58encode(b"\x00\x00hello world") == b"11StV1DL6CwTryKyV"
    assert _b58decode(b"11StV1DL6CwTryKyV") == b"\x00\x00hello world"
    assert _b58decode(_b58encode(b"\x00\x00hello world")) == b"\x00\x00hello world"
    assert _b58encode(_b58decode(b"11StV1DL6CwTryKyV")) == b"11StV1DL6CwTryKyV"

    assert b58decode(b58encode(b"\x00\x00hello world"), 13) == b"\x00\x00hello world"


def test_exceptions() -> None:
    encoded = b58encode(b"hello world")
    b58decode(encoded, 11)

    wrong_length = len(encoded) - 1
    with pytest.raises(BTClibValueError, match="invalid decoded size: "):
        b58decode(encoded, wrong_length)

    invalid_checksum = encoded[:-4] + b"1111"
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        b58decode(invalid_checksum, 4)

    # a character outside ascii is an invalid base58 character like any
    # other, and used to come back as a UnicodeEncodeError instead
    err_msg = "non-ascii character in base58 string: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b58decode("hèllo world")

    err_msg = "not enough bytes for checksum, invalid base58 decoded size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b58decode(_b58encode(b"123"))


def test_wif() -> None:
    # https://en.bitcoin.it/wiki/Wallet_import_format
    prv = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    uncompressed_key = b"\x80" + prv.to_bytes(32, byteorder="big", signed=False)
    uncompressed_wif = b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    wif = b58encode(uncompressed_key)
    assert wif == uncompressed_wif
    key = b58decode(uncompressed_wif)
    assert key == uncompressed_key

    compressed_key = b"\x80" + prv.to_bytes(32, byteorder="big", signed=False) + b"\x01"
    compressed_wif = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    wif = b58encode(compressed_key)
    assert wif == compressed_wif
    key = b58decode(compressed_wif)
    assert key == compressed_key

    # string
    compressed_wif = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    key = b58decode(compressed_wif)
    assert key == compressed_key


def test_integers() -> None:
    digits = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for i in range(len(digits)):
        char = digits[i : i + 1]
        assert _b58decode_to_int(char) == i
        assert _b58encode_from_int(i) == char
    number = (
        "0111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e4"
        "8fd66a835e252ada93ff480d6dd43dc62a641155a5"
    )
    n = int(number, 16)
    assert _b58decode_to_int(digits) == n
    assert _b58encode_from_int(n) == digits[1:]


def test_max_length() -> None:
    """Decoding is quadratic, so the input is bounded first.

    Measured 13 ms at 10k characters, 198 ms at 40k and 3312 ms at 160k,
    four times the cost per doubling -- and the checksum that rejects
    the string is verified only once the decoding has been paid for.
    """
    # the longest thing btclib encodes: a 78-byte BIP32 extended key,
    # here the one whose 112 characters no payload can exceed
    longest = b58encode(b"\xff" * 78)
    assert len(longest) == MAX_LENGTH
    assert b58decode(longest, 78) == b"\xff" * 78

    err_msg = f"too many base58 characters: {MAX_LENGTH + 1}, max is {MAX_LENGTH}"
    with pytest.raises(BTClibValueError, match=err_msg):
        b58decode(b"1" * (MAX_LENGTH + 1))
    # str and bytes take the same path
    with pytest.raises(BTClibValueError, match=err_msg):
        b58decode("1" * (MAX_LENGTH + 1))


@given(payload=st.binary(max_size=78))
def test_round_trip(payload: bytes) -> None:
    """Whatever goes in comes back, checksum and leading zeros included.

    78 bytes is the largest payload MAX_LENGTH leaves room for, a BIP32
    extended key; the leading zero bytes the strategy produces are the
    case the encoding writes as leading '1' characters rather than
    carrying through the base conversion, and has to count back.
    """
    encoded = b58encode(payload)
    assert len(encoded) <= MAX_LENGTH
    assert b58decode(encoded) == payload
    assert b58decode(encoded, len(payload)) == payload
    # str and bytes are the same string to the decoder
    assert b58decode(encoded.decode("ascii")) == payload
