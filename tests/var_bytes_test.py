# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.var_bytes` module."""

from collections.abc import Callable
from io import BytesIO

import pytest

# private on purpose: two copies' agreement is the subject (issue #2282, Rule 3)
from btclib_ecc.ecc.dsa import _parse_der_value
from hypothesis import given
from hypothesis import strategies as st

from btclib import var_bytes
from btclib.exceptions import BTClibRuntimeError, BTClibValueError


@given(octets=st.binary(max_size=512))
def test_round_trip(octets: bytes) -> None:
    """The octets come back, and nothing of the length prefix with them."""
    assert var_bytes.parse(var_bytes.serialize(octets)) == octets
    # hex is the other spelling the whole library accepts
    assert var_bytes.parse(var_bytes.serialize(octets.hex())) == octets


@given(octets=st.binary(max_size=64), tail=st.binary(max_size=16))
def test_parse_stops_at_the_announced_length(octets: bytes, tail: bytes) -> None:
    """What follows a var_bytes belongs to whoever reads next.

    This is the property the container parsers rest on: a Tx is a
    sequence of these, so a parse that ran past its length would read
    the next field as part of this one.
    """
    stream = BytesIO(var_bytes.serialize(octets) + tail)
    assert var_bytes.parse(stream) == octets
    assert stream.read() == tail


@given(octets=st.binary(min_size=1, max_size=64))
def test_truncated_is_rejected(octets: bytes) -> None:
    """A length announcing more than follows is not a shorter value.

    BytesIO.read returns what is left rather than what was asked for, so
    without the check the truncation would be silent and two distinct
    inputs would parse to one value.
    """
    serialized = var_bytes.serialize(octets)
    with pytest.raises(BTClibRuntimeError, match="not enough binary data"):
        var_bytes.parse(serialized[:-1])


@given(octets=st.binary(max_size=32))
def test_forbid_zero_size(octets: bytes) -> None:
    """An empty value is legal unless the caller says it is not."""
    serialized = var_bytes.serialize(octets)
    if octets:
        assert var_bytes.parse(serialized, forbid_zero_size=True) == octets
    else:
        with pytest.raises(BTClibRuntimeError, match="zero size"):
            var_bytes.parse(serialized, forbid_zero_size=True)


def test_the_size_and_the_serialization_agree() -> None:
    """`_size` is what `serialize` writes, the hex spelling included.

    The string case is the one a length cannot be read off: `len` of
    "deadbeef" is eight and the codec writes four bytes and a prefix.
    """
    for octets in (b"", b"\x00", b"\xff" * 0xFC, b"\xff" * 0xFD, "deadbeef"):
        assert var_bytes._size(octets) == len(var_bytes.serialize(octets))


def _outcome(read: Callable[[BytesIO], bytes], data: bytes) -> tuple[str, bytes | str]:
    """Return what one reader answers, or the family and message it raises.

    The family and not the class: the two readers are two packages', and
    each raises its own `ValueError`.
    """
    try:
        return "value", read(BytesIO(data))
    except ValueError as e:
        return "ValueError", str(e)


def _var_bytes_as_dsa_reports_it(stream: BytesIO) -> bytes:
    """Return what `var_bytes` reads, erring in the words `Sig.parse` uses."""
    try:
        return var_bytes.parse(stream, forbid_zero_size=True)
    except BTClibRuntimeError as e:
        raise BTClibValueError(f"invalid DER length: {e}") from e


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="nothing"),
        pytest.param(b"\x00", id="zero size"),
        pytest.param(b"\x02ab", id="one octet"),
        pytest.param(b"\x03ab", id="overrun"),
        pytest.param(b"\x80" + bytes(0x80), id="0x80 as a size"),
        pytest.param(b"\xfc" + bytes(0xFC), id="0xfc as a size"),
        pytest.param(b"\xfd\xfd\x00" + bytes(0xFD), id="two octets"),
        pytest.param(b"\xfd\xfd", id="two octets cut short"),
        pytest.param(b"\xfd\xfc\x00", id="two octets non-canonical"),
        pytest.param(b"\xfe\x00\x00\x01\x00", id="four octets non-canonical"),
        pytest.param(b"\xfe\x01\x00\x00\x02", id="four octets past the cap"),
        pytest.param(b"\xff" + bytes(8), id="eight octets non-canonical"),
    ],
)
def test_dsa_reads_a_der_size_as_var_bytes_does(data: bytes) -> None:
    """The DER size reader of `ecc.dsa` answers as `var_bytes` does.

    btclib_ecc does not import btclib, so `Sig.parse` cannot call
    `var_bytes` and reads a DER element's size itself. This is the one
    place both are in reach, and every branch of either reader is a row
    here: the value, or the refusal and its message.
    """
    expected = _outcome(_var_bytes_as_dsa_reports_it, data)
    assert _outcome(_parse_der_value, data) == expected
