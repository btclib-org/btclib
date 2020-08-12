#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.base58` module."

import pytest

from btclib.base58 import (
    _b58decode,
    _b58decode_to_int,
    _b58encode,
    _b58encode_from_int,
    b58decode,
    b58encode,
)


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

    with pytest.raises(TypeError, match="object supporting the buffer API required"):
        b58encode(3)  # type: ignore

    encoded = b58encode(b"hello world")
    b58decode(encoded, 11)

    wrong_length = len(encoded) - 1
    with pytest.raises(ValueError, match="invalid decoded size: "):
        b58decode(encoded, wrong_length)

    invalidChecksum = encoded[:-4] + b"1111"
    with pytest.raises(ValueError, match="invalid checksum: "):
        b58decode(invalidChecksum, 4)

    with pytest.raises(ValueError, match="'ascii' codec can't encode character "):
        b58decode("hèllo world")

    err_msg = "not enough bytes for checksum, invalid base58 decoded size: "
    with pytest.raises(ValueError, match=err_msg):
        b58decode(_b58encode(b"123"))


def test_wif() -> None:
    # https://en.bitcoin.it/wiki/Wallet_import_format
    prv = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    uncompressedKey = b"\x80" + prv.to_bytes(32, byteorder="big")
    uncomprWIF = b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    wif = b58encode(uncompressedKey)
    assert wif == uncomprWIF
    key = b58decode(uncomprWIF)
    assert key == uncompressedKey

    compressedKey = b"\x80" + prv.to_bytes(32, byteorder="big") + b"\x01"
    compressedWIF = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    wif = b58encode(compressedKey)
    assert wif == compressedWIF
    key = b58decode(compressedWIF)
    assert key == compressedKey

    # string
    compressedWIF = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    key = b58decode(compressedWIF)
    assert key == compressedKey


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
