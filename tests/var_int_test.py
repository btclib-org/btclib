# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.var_int` module."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import var_int
from btclib.exceptions import BTClibTypeError, BTClibValueError


def test_var_int_conversion() -> None:
    """Round-trip each length boundary; refuse negatives and 2**64."""
    int_ = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        var_int.serialize(int_)

    int_ = 0x00
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ = 0xFC
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 3
    assert var_int.parse(bytes_) == int_

    int_ = 0xFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 3
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 5
    assert var_int.parse(bytes_) == int_

    int_ = 0xFFFFFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 5
    # above MAX_SIZE, so parsing it back takes an explicit max_size
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ = 0xFFFFFFFFFFFFFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ += 1
    with pytest.raises(
        BTClibValueError, match="integer too big for var_int encoding: "
    ):
        var_int.serialize(int_)

    assert var_int.parse("6a") == 106
    assert var_int.parse("fd2602") == 550
    assert var_int.parse("fe703a0f00") == 998000


def test_max_size_is_bitcoin_cores() -> None:
    """MAX_SIZE is serialize.h's number, and the number is the whole of it.

    Every check around the cap -- that MAX_SIZE parses and one more does
    not -- holds for whatever value the constant happens to have, so the
    value is what has to be written down: it is a limit btclib shares with
    Core rather than one it chooses.
    """
    assert var_int.MAX_SIZE == 0x02000000


def test_var_int_max_size() -> None:
    """The MAX_SIZE range check of Bitcoin Core's ReadCompactSize."""
    assert var_int.parse(var_int.serialize(var_int.MAX_SIZE)) == var_int.MAX_SIZE

    with pytest.raises(BTClibValueError, match="var_int too big: "):
        var_int.parse(var_int.serialize(var_int.MAX_SIZE + 1))

    # the cap is what keeps a count from driving an allocation: nine bytes
    # would otherwise ask for 2^64-1 elements
    with pytest.raises(BTClibValueError, match="var_int too big: "):
        var_int.parse(b"\xff" + b"\xff" * 8)

    # a caller can still raise it for a var_int that is neither a length
    # nor a count
    assert var_int.parse("fe00000004", max_size=0xFFFFFFFF) == 0x04000000


def test_a_bool_is_neither_a_count_nor_a_cap() -> None:
    """CompactSize is an integer field, and `is_integer` is the policy.

    The cap is the case a caller cannot see failing: `max_size=True` is a
    limit of one, so every count above one comes back as `var_int too
    big` -- a range refusal for what is a type error, and `true` is what a
    json configuration decodes to. Both entry points are in
    tests/integer_policy_test.py's inventory too, with every other integer
    field of the library.
    """
    for value in (True, False):
        with pytest.raises(BTClibTypeError, match="non-integer var_int"):
            var_int.serialize(value)
        with pytest.raises(BTClibTypeError, match="non-integer max_size"):
            var_int.parse(b"\x01", max_size=value)

    # what the refusal must not take with it: the numbers those two are
    # not, at the boundary of the one-byte encoding
    assert var_int.serialize(0) == b"\x00"
    assert var_int.serialize(1) == b"\x01"
    assert var_int.parse(b"\x01", max_size=1) == 1


def test_var_int_non_canonical() -> None:
    """Only the shortest encoding is valid, as in Bitcoin Core."""
    # 1 fits in one byte, 0xfd in two, 0x10000 in four. fdfc00 and
    # feffff0000 are the boundary from below -- the largest number the
    # shorter form holds, written in the longer one -- and each is the
    # case a minimum one short of the right value would accept
    for encoding in (
        "fd0100",
        "fd0000",
        "fdfc00",
        "fe01000000",
        "fefdff0000",
        "fefeff0000",
        "feffff0000",
    ):
        with pytest.raises(BTClibValueError, match="non-canonical var_int: "):
            var_int.parse(encoding)
    with pytest.raises(BTClibValueError, match="non-canonical var_int: "):
        var_int.parse(b"\xff" + (0xFFFFFFFF).to_bytes(8, "little"))

    # the diagnosis names the number and the width it was written in,
    # which is what tells a longer encoding from a number out of range:
    # both refusals are about the same octets
    err_msg = "non-canonical var_int: 252 encoded in 3 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        var_int.parse("fdfc00")

    # the boundary values are the shortest encoding of themselves
    assert var_int.parse("fcfd") == 0xFC  # 0xfc is a one byte integer
    assert var_int.parse("fdfd00") == 0xFD
    assert var_int.parse("fe00000100") == 0x0001_0000
    int_ = 0x1_0000_0000
    assert var_int.parse(b"\xff" + int_.to_bytes(8, "little"), max_size=int_) == int_


def test_var_int_truncated() -> None:
    """A read that comes up short is an error, not a zero."""
    # stream.read returns b"" past the end of the stream without raising,
    # and int.from_bytes(b"") is 0: without the length check, `fd` parses
    # as 0 and `fd01` as 1
    for encoding in (b"", b"\xfd", b"\xfd\x01", b"\xfe\x01\x00", b"\xff\x01"):
        with pytest.raises(
            BTClibValueError, match="not enough binary data for var_int"
        ):
            var_int.parse(encoding)


@given(i=st.integers(min_value=0, max_value=var_int.MAX_SIZE))
def test_round_trip(i: int) -> None:
    """Every length and count a parser can meet survives the encoding."""
    assert var_int.parse(var_int.serialize(i)) == i


@given(i=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF))
def test_round_trip_past_max_size(i: int) -> None:
    """The cap is a range check on parse, not a limit of the encoding."""
    encoded = var_int.serialize(i)
    assert len(encoded) in {1, 3, 5, 9}
    assert var_int.parse(encoded, max_size=0xFFFFFFFFFFFFFFFF) == i


@given(i=st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_non_canonical_encoding_is_rejected(i: int) -> None:
    """A number has one encoding, which is the shortest one.

    Were a longer one accepted the same transaction would have two
    serializations, hence two txids; Bitcoin Core calls it a
    "non-canonical ReadCompactSize()".
    """
    canonical = var_int.serialize(i)
    for prefix, size in ((b"\xfd", 2), (b"\xfe", 4), (b"\xff", 8)):
        if i.bit_length() > 8 * size or 1 + size <= len(canonical):
            continue
        longer = prefix + i.to_bytes(size, byteorder="little", signed=False)
        with pytest.raises(BTClibValueError, match="non-canonical var_int: "):
            var_int.parse(longer)


@given(i=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF))
def test_truncated_encoding_is_rejected(i: int) -> None:
    """A prefix announcing more bytes than follow is not a smaller number."""
    encoded = var_int.serialize(i)
    if len(encoded) == 1:
        return
    for length in range(1, len(encoded)):
        err_msg = "not enough binary data for var_int"
        with pytest.raises(BTClibValueError, match=err_msg):
            var_int.parse(encoded[:length], max_size=0xFFFFFFFFFFFFFFFF)


@given(i=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF))
def test_the_size_and_the_encoding_agree(i: int) -> None:
    """`_size` answers what `serialize` would have written."""
    assert var_int._size(i) == len(var_int.serialize(i))


def test_the_size_agrees_at_every_width_boundary() -> None:
    """Both sides of each threshold, which is where an off-by-one lands."""
    for i in (
        0,
        1,
        0xFC,
        0xFD,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
        0xFFFFFFFFFFFFFFFF,
    ):
        assert var_int._size(i) == len(var_int.serialize(i))
