# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.var_bytes` module."""

from io import BytesIO

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import var_bytes
from btclib.exceptions import BTClibRuntimeError


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
