# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.utils` module."""

import random
from io import BytesIO

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    decode_num,
    encode_num,
    hex_string,
    int_from_bits,
    int_from_integer,
    int_from_json_number,
    is_octets,
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
    # (the message is bytes.fromhex's own, which Python 3.14 rephrased,
    # inside the class this library promises)
    with pytest.raises(BTClibValueError, match="invalid hex string: "):
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
    with pytest.raises(BTClibValueError, match="invalid hex string: "):
        hex_string(a_str)

    int_ = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        hex_string(int_)

    # zero is not negative: `< 0` weakened to `<= 0` would refuse it
    assert hex_string(0) == "00"

    # a hex length that is an exact multiple of 8 (here 16, unlike the
    # 18-digit vector above): the index loop's stop bound at 0 is what
    # keeps the top group from being an empty one -- read as -1 instead,
    # 0 itself joins the indexes and a leading space appears before "DE"
    assert hex_string(0xDEADBEEF00000000) == "DEADBEEF 00000000"


def test_int_from_bits() -> None:
    """Discard bits on the right down to nlen, or none if there are fewer.

    Every caller in this codebase hashes into exactly `ec.nlen` bits, so
    `blen == nlen` is the only case they exercise; `blen > nlen` is the
    truncation the docstring is about, and `blen < nlen` -- fewer bits
    than asked for -- is `n` weakened from `blen - nlen` to a negative
    shift count away from `i >> n` raising instead of returning `i`
    unchanged.
    """
    assert int_from_bits(b"\xff", 4) == 0b1111
    assert int_from_bits(b"\xff\x00", 4) == 0b1111
    assert int_from_bits(b"\xff", 16) == 0xFF


def test_encode_num() -> None:
    """Round-trip script numbers across sign, zero and length boundaries."""
    # zero is the empty vector, as Core's CScriptNum::serialize writes it
    # and its set_vch reads it back, and the only spelling the
    # interpreter accepts as a number: the engine's `_to_num` refuses the
    # other two under MINIMALDATA, which is where that rule belongs
    assert encode_num(0) == b""
    assert decode_num(b"") == 0
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


def test_a_json_number_is_a_whole_one_or_it_is_an_error() -> None:
    """1.0 is the json spelling of 1; 1.5 is the spelling of nothing.

    `from_dict` coerces because a whole number may arrive as a float,
    which is what json does to 1 -- but `int(1.5)` is 1, so a fractional
    version, depth or index became a number the caller never wrote and
    nothing said so. `nan` and `inf` are floats and no more whole than
    1.5 is.
    """
    assert int_from_json_number(1, "version") == 1
    assert int_from_json_number(1.0, "version") == 1
    assert int_from_json_number(-1.0, "version") == -1
    assert int_from_json_number("1", "version") == 1

    for fractional in (1.5, -0.5, float("nan"), float("inf")):
        with pytest.raises(BTClibValueError, match="invalid version: "):
            int_from_json_number(fractional, "version")

    # a bool decodes out of json's `true` and `int(True)` is 1
    for value in (True, False):
        with pytest.raises(BTClibTypeError, match="invalid version type: bool"):
            int_from_json_number(value, "version")

    # and what is no number at all, this taking Any: neither error was
    # btclib's, and one of them was not even a ValueError
    with pytest.raises(BTClibValueError, match="invalid version: "):
        int_from_json_number("not a number", "version")
    for not_a_number in (None, object(), [1]):
        with pytest.raises(BTClibTypeError, match="invalid version type: "):
            int_from_json_number(not_a_number, "version")


def test_octets_are_bytes_or_the_hex_string_of_bytes_and_nothing_else() -> None:
    """A tuple went through untouched, to be measured as if it were octets.

    `bytes_from_octets` returned anything that was not a `str`
    unchanged, so `len` of a tuple of 33 ints was 33 and
    `taproot.assert_valid_control_block` accepted it as a control block
    size. Every buffer is still taken, and returned as it came: a read
    must not rewrite the field it reads, which is what `bytes()` here
    would do to a bytearray a caller built.
    """
    assert bytes_from_octets(b"\x00\x01") == b"\x00\x01"
    assert bytes_from_octets("0001") == b"\x00\x01"
    # every buffer `Octets` names, and what reaches this is whatever a
    # field was built from rather than only what a caller writes
    assert bytes_from_octets(bytearray(b"\x00\x01")) == b"\x00\x01"
    assert bytes_from_octets(memoryview(b"\x00\x01")) == b"\x00\x01"
    # unchanged, and not merely equal
    buffer: object = bytes_from_octets(bytearray(b"\x00"))
    assert isinstance(buffer, bytearray)

    for not_octets in (tuple(range(33)), [1, 2], None, 1.5):
        with pytest.raises(BTClibTypeError, match="invalid octets type: "):
            bytes_from_octets(not_octets)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid octets type: "):
            int_from_integer(not_octets)  # type: ignore[arg-type]
    # an int is an `Integer` and no `Octets`, so the two differ on it
    assert int_from_integer(1) == 1
    with pytest.raises(BTClibTypeError, match="invalid octets type: int"):
        bytes_from_octets(1)  # type: ignore[arg-type]

    # the hex string that is not one, in both, with the message
    # `bytes.fromhex` gives: a position, and never the string itself
    for not_hex in ("9", "zz", "not hex at all"):
        with pytest.raises(BTClibValueError, match="invalid hex string: "):
            bytes_from_octets(not_hex)
        with pytest.raises(BTClibValueError, match="invalid hex string: "):
            int_from_integer(not_hex)
    with pytest.raises(BTClibValueError, match="invalid hex integer: "):
        int_from_integer("0xzz")


def test_a_non_contiguous_memoryview_is_refused_at_the_coercion() -> None:
    """A strided slice is `Octets` to the annotation, `BufferError` underneath.

    `mv[::2]` is not C-contiguous, and `bytes_from_octets` used to hand it
    back untouched, so the failure reached whichever consumer used the
    buffer next -- `hash160` with a bare `BufferError`, a public entry
    point rather than this module. The refusal is raised here instead,
    once, at the coercion every `Octets` parameter passes (issue #1260).
    """
    raw = bytes(range(64))
    strided = memoryview(raw)[::2]
    assert not strided.c_contiguous

    with pytest.raises(BTClibValueError, match="invalid octets: non-contiguous"):
        bytes_from_octets(strided)
    with pytest.raises(BTClibValueError, match="invalid octets: non-contiguous"):
        hash160(strided)

    # a contiguous slice is untouched, same as any other buffer
    contiguous = memoryview(raw)[:32]
    assert bytes_from_octets(contiguous) == raw[:32]
    assert hash160(contiguous) == hash160(raw[:32])


def test_is_octets_answers_one_octets_not_a_sequence_of_them() -> None:
    """The question `bytes_from_octets` embeds, and two other callers ask.

    Every `Octets` spelling is itself iterable, which is what makes a
    single one hard to tell from a sequence of them by shape alone; a
    `list` or a `tuple` of `Octets` is not one itself.
    """
    for one in (b"\x00\x01", "0001", bytearray(b"\x00\x01"), memoryview(b"\x00\x01")):
        assert is_octets(one)
    for many in ([b"\x00"], (b"\x00", b"\x01"), []):
        assert not is_octets(many)
