# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
    decode,
    encode,
)
from btclib.exceptions import BTClibValueError
from tests import load, vector_id

# Bitcoin Core's `src/test/data/base58_encode_decode.json`, entire and
# byte for byte; tests/_data/README.md pins the revision. A row is [hex,
# base58], and the pair is Core's `EncodeBase58`/`DecodeBase58` -- the
# codec with no checksum on it, which is `_b58encode`/`_b58decode` here
# and not the `encode`/`decode` the rest of this module exercises
CODEC_VECTORS = [
    pytest.param(hexed, encoded, id=vector_id(index, hexed[:16]))
    for index, (hexed, encoded) in enumerate(load("_data", "base58_encode_decode.json"))
]


def test_empty() -> None:
    """Round-trip the empty payload, checksummed or not."""
    assert _b58encode(b"") == b""
    assert _b58decode(_b58encode(b"")) == b""

    assert decode(encode(b""), 0) == b""


def test_hello_world() -> None:
    """Check the 'hello world' known answer, in both directions."""
    assert _b58encode(b"hello world") == b"StV1DL6CwTryKyV"
    assert _b58decode(b"StV1DL6CwTryKyV") == b"hello world"
    assert _b58decode(_b58encode(b"hello world")) == b"hello world"
    assert _b58encode(_b58decode(b"StV1DL6CwTryKyV")) == b"StV1DL6CwTryKyV"

    assert decode(encode(b"hello world"), 11) == b"hello world"


def test_trailing_zeros() -> None:
    """Verify leading zero bytes become leading '1' characters, and back."""
    assert _b58encode(b"\x00\x00hello world") == b"11StV1DL6CwTryKyV"
    assert _b58decode(b"11StV1DL6CwTryKyV") == b"\x00\x00hello world"
    assert _b58decode(_b58encode(b"\x00\x00hello world")) == b"\x00\x00hello world"
    assert _b58encode(_b58decode(b"11StV1DL6CwTryKyV")) == b"11StV1DL6CwTryKyV"

    assert decode(encode(b"\x00\x00hello world"), 13) == b"\x00\x00hello world"


@pytest.mark.parametrize("hexed, encoded", CODEC_VECTORS)
def test_core_codec_vectors(hexed: str, encoded: str) -> None:
    """Both directions of Core's codec vectors, over the raw functions.

    The set is small and reaches what the tests above reach by hand:
    the empty string, leading zero bytes as leading '1' characters, the
    whole alphabet in order, the transitions at powers of 58, and a
    256-byte payload. That last one is 348 base58 characters, which
    `decode` would refuse on MAX_LENGTH before looking at it -- the
    cap is on the checked decoder, the codec under it being uncapped.
    What the set adds is that the answer is Core's, not btclib's.
    """
    raw = bytes.fromhex(hexed)
    assert _b58encode(raw) == encoded.encode("ascii")
    assert _b58decode(encoded.encode("ascii")) == raw


def test_exceptions() -> None:
    """Check the message of each way decode refuses an input."""
    encoded = encode(b"hello world")
    decode(encoded, 11)

    wrong_length = len(encoded) - 1
    with pytest.raises(BTClibValueError, match="invalid decoded size: "):
        decode(encoded, wrong_length)

    # a requested size smaller than what decoded, not larger: the vector
    # above asks for more than the 11 decoded bytes, which `== out_size`
    # weakened to `>= out_size` also refuses (11 is not >= 19); asking
    # for fewer is what tells them apart, 11 being >= 5
    with pytest.raises(BTClibValueError, match="invalid decoded size: "):
        decode(encoded, 5)

    invalid_checksum = encoded[:-4] + b"1111"
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        decode(invalid_checksum, 4)

    # a character outside ascii is an invalid base58 character like any
    # other, not a UnicodeEncodeError
    err_msg = "non-ascii character in base58 string: "
    with pytest.raises(BTClibValueError, match=err_msg):
        decode("hèllo world")

    err_msg = "not enough bytes for checksum, invalid base58 decoded size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        decode(_b58encode(b"123"))


def test_wif() -> None:
    """Reproduce the Bitcoin wiki's WIF vectors, compressed and not."""
    # https://en.bitcoin.it/wiki/Wallet_import_format
    prv = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    uncompressed_key = b"\x80" + prv.to_bytes(32, byteorder="big", signed=False)
    uncompressed_wif = b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    wif = encode(uncompressed_key)
    assert wif == uncompressed_wif
    key = decode(uncompressed_wif)
    assert key == uncompressed_key

    compressed_key = b"\x80" + prv.to_bytes(32, byteorder="big", signed=False) + b"\x01"
    compressed_wif = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    wif = encode(compressed_key)
    assert wif == compressed_wif
    key = decode(compressed_wif)
    assert key == compressed_key

    # string
    compressed_wif = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    key = decode(compressed_wif)
    assert key == compressed_key


def test_encode_octets_spellings() -> None:
    """`encode` takes every `Octets` spelling, memoryview included.

    A memoryview has no `__add__`, and `bytes_from_octets` hands one
    back unchanged: `encode` copies it to `bytes` right at the
    concatenation `_b58encode`'s payload needs, which is the one place
    a memoryview payload would otherwise fail (issue #1255).
    """
    payload = b"hello world"
    known_answer = b"3vQB7B6MrGQZaxCuFg4oh"
    for spelling in (payload, bytearray(payload), memoryview(payload)):
        assert encode(spelling) == known_answer


def test_integers() -> None:
    """Verify the integer codec over each digit and the full alphabet."""
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
    longest = encode(b"\xff" * 78)
    assert len(longest) == MAX_LENGTH
    assert decode(longest, 78) == b"\xff" * 78

    err_msg = f"too many base58 characters: {MAX_LENGTH + 1}, max is {MAX_LENGTH}"
    with pytest.raises(BTClibValueError, match=err_msg):
        decode(b"1" * (MAX_LENGTH + 1))
    # str and bytes take the same path
    with pytest.raises(BTClibValueError, match=err_msg):
        decode("1" * (MAX_LENGTH + 1))


@given(payload=st.binary(max_size=78))
def test_round_trip(payload: bytes) -> None:
    """Whatever goes in comes back, checksum and leading zeros included.

    78 bytes is the largest payload MAX_LENGTH leaves room for, a BIP32
    extended key; the leading zero bytes the strategy produces are the
    case the encoding writes as leading '1' characters rather than
    carrying through the base conversion, and has to count back.
    """
    encoded = encode(payload)
    assert len(encoded) <= MAX_LENGTH
    assert decode(encoded) == payload
    assert decode(encoded, len(payload)) == payload
    # str and bytes are the same string to the decoder
    assert decode(encoded.decode("ascii")) == payload
