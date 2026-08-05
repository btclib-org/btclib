#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.utils` module."""

import random
from io import BytesIO

import pytest

from btclib.exceptions import BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    decode_num,
    encode_num,
    hex_string,
    int_from_integer,
    read_exactly,
)

random.seed(42)


def test_read_exactly() -> None:
    """The size asked for is the size returned, or it is an error."""
    stream = BytesIO(b"12345")
    assert read_exactly(stream, 2, "first field") == b"12"
    assert read_exactly(stream, 3, "second field") == b"345"
    # nothing left, and asking for nothing is not asking
    assert read_exactly(stream, 0, "no field") == b""


def test_read_exactly_names_the_field_it_could_not_fill() -> None:
    """A short read is refused, and the message says which field it was.

    BytesIO.read hands back what is left rather than raising, so an
    unchecked read is not a missing check but a wrong value: the field
    would be as long as the buffer happened to be.
    """
    err_msg = "not enough data for the sequence: 3 bytes instead of 4"
    with pytest.raises(BTClibValueError, match=err_msg):
        read_exactly(BytesIO(b"123"), 4, "sequence")

    err_msg = "not enough data for the tx_id: 0 bytes instead of 32"
    with pytest.raises(BTClibValueError, match=err_msg):
        read_exactly(BytesIO(b""), 32, "tx_id")


def test_assert_no_trailing() -> None:
    """Octets are one whole object; a caller's stream is the caller's."""
    # what a parser hands over: the argument as it came, and the stream
    # it made of it, read up to the end of the object
    consumed = BytesIO(b"12")
    consumed.read(2)
    assert_no_trailing(b"12", consumed, "thing")

    consumed = BytesIO(b"12")
    consumed.read(2)
    assert_no_trailing("3132", consumed, "thing")

    stream = BytesIO(b"12junk")
    stream.read(2)
    with pytest.raises(BTClibValueError, match="4 bytes after the thing"):
        assert_no_trailing(b"12junk", stream, "thing")

    # the same four bytes in a stream the caller owns are the caller's,
    # and they are still there to be read
    stream = BytesIO(b"12junk")
    stream.read(2)
    assert_no_trailing(stream, stream, "thing")
    assert stream.read() == b"junk"


def test_int_from_integer() -> None:
    """Round-trip integers through int, hex-string, and bytes forms."""
    for i in (
        random.getrandbits(256 - 8),
        0x0B6CA75B7D3076C561958CCED813797F6D2275C7F42F3856D007D587769A90,
    ):
        assert i == int_from_integer(i)
        assert i == int_from_integer(f" {hex(i).upper()}")
        assert -i == int_from_integer(f"{hex(-i).upper()} ")
        assert i == int_from_integer(hex_string(i))
        assert i == int_from_integer(i.to_bytes(32, byteorder="big", signed=False))


def test_int_from_integer_reads_a_str_as_hex() -> None:
    """Check "1234" reads as 0x1234, and an odd digit count is refused."""
    # a decimal-looking str is a hex-string like any other, which the
    # docstring says out loud: 0x1234, not one thousand two hundred
    # and thirty-four
    assert int_from_integer("1234") == 4660
    assert int_from_integer("1234") == int_from_integer("0x1234")
    assert int_from_integer(1234) == 1234

    # and an odd number of digits is not a one-digit decimal either
    # (Python 3.14 rephrased the message bytes.fromhex raises)
    with pytest.raises(ValueError, match="fromhex"):
        int_from_integer("9")


def test_hex_string() -> None:
    """Format int, str and bytes as spaced hex; refuse odd or negative."""
    int_ = 34492435054806958080
    assert hex_string(int_) == "01 DEADBEEF 00000000"
    assert hex_string(hex(int_).lower()) == "01 DEADBEEF 00000000"

    a_str = "01de adbeef00000000"
    assert hex_string(a_str) == "01 DEADBEEF 00000000"
    a_bytes = bytes.fromhex(a_str)
    assert hex_string(a_bytes) == "01 DEADBEEF 00000000"

    # invalid hex-string: odd number of hex digits
    # (Python 3.14 rephrased the message bytes.fromhex raises)
    a_str = "1deadbeef00000000"
    with pytest.raises(ValueError, match="fromhex"):
        hex_string(a_str)

    int_ = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        hex_string(int_)


def test_encode_num() -> None:
    """Round-trip script numbers across sign, zero and length boundaries."""
    with pytest.raises(BTClibValueError, match="empty byte string"):
        decode_num(b"")

    # different representations of zero
    assert decode_num(b"\x00") == 0  # "positive" zero
    assert decode_num(b"\x80") == 0  # "negative" zero

    for i in range(-255, 256):
        assert decode_num(encode_num(i)) == i

    for i in [
        0x80FF,
        0xFFFF,
        0x80FFFF,
        0xFFFFFF,
        0x80FFFFFF,
        0xFFFFFFFF,
        0x80FFFFFFFF,
        0xFFFFFFFFFF,
    ]:
        assert decode_num(encode_num(i - 1)) == i - 1
        assert decode_num(encode_num(i)) == i
        assert decode_num(encode_num(i + 1)) == i + 1

        assert decode_num(encode_num(-i - 1)) == -i - 1
        assert decode_num(encode_num(-i)) == -i
        assert decode_num(encode_num(-i + 1)) == -i + 1

    # 7 bits + sign bit = 8 bits = 1 byte (plus 1 byte for length)
    i = 0b01111111
    assert len(encode_num(i)) == 1
    # 8 bits + sign bit = 9 bits = 2 byte (plus 1 byte for length)
    i = 0b11111111
    assert len(encode_num(i)) == 2
    # 15 bits + sign bit = 16 bits = 2 byte (plus 1 byte for length)
    i = 0b0111111111111111
    assert len(encode_num(i)) == 2
    # 16 bits + sign bit = 17 bits = 3 byte (plus 1 byte for length)
    i = 0b1111111111111111
    assert len(encode_num(i)) == 3


def test_encode_num_is_bounded_by_the_int64_of_a_script_number() -> None:
    """A script number is an int64, so both ends of int64 are the bound.

    Core takes a number into a script through
    `CScript::operator<<(int64_t)` and has no wider parameter, so an
    integer past either end is one no script can carry (issue #406).
    Both extremes are in range, and the most negative one takes nine
    octets rather than eight, its magnitude not fitting beside a sign
    bit -- which is what Core's `CScriptNum::serialize` writes for it
    too.
    """
    assert encode_num(2**63 - 1) == bytes.fromhex("ffffffffffffff7f")
    assert encode_num(-(2**63)) == bytes.fromhex("000000000000008080")

    with pytest.raises(BTClibValueError, match="script number out of range: "):
        encode_num(2**63)
    with pytest.raises(BTClibValueError, match="script number out of range: "):
        encode_num(-(2**63) - 1)

    # the reader is not bounded to match: it answers for a coinbase push
    # of any width, which is what Block.height reads
    assert decode_num(encode_num(2**63 - 1)) == 2**63 - 1
    assert decode_num(encode_num(-(2**63))) == -(2**63)
    assert decode_num(bytes.fromhex("00000000000000000010")) == 2**76
