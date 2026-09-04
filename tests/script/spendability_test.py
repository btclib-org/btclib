# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.spendability` module."""

from __future__ import annotations

import pytest

from btclib.script import is_nulldata, is_unspendable, serialize
from btclib.script.limits import MAX_SCRIPT_SIZE


@pytest.mark.parametrize(
    "script_pub_key",
    [
        pytest.param(serialize(["OP_RETURN", b"\xde\xad\xbe\xef"]), id="nulldata"),
        pytest.param(b"\x6a", id="bare OP_RETURN"),
        pytest.param(b"\x6a\x51", id="OP_RETURN OP_1"),
        pytest.param(b"\x6a" + bytes(MAX_SCRIPT_SIZE), id="huge OP_RETURN"),
        pytest.param(b"\x51" * (MAX_SCRIPT_SIZE + 1), id="over MAX_SCRIPT_SIZE"),
    ],
)
def test_an_unspendable_script(script_pub_key: bytes) -> None:
    """Verify each shape Core's IsUnspendable answers True for."""
    assert is_unspendable(script_pub_key)


@pytest.mark.parametrize(
    "script_pub_key",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x51" * MAX_SCRIPT_SIZE, id="at MAX_SCRIPT_SIZE"),
        pytest.param(b"\x6b\x01\x00", id="OP_RESERVED, one past OP_RETURN"),
    ],
)
def test_a_spendable_script(script_pub_key: bytes) -> None:
    """Verify the boundary on either side of both conditions.

    The empty script has no leading op code to read, the comparison on
    the length is `>` so the bound itself passes, and the byte above
    OP_RETURN is a different op code -- weakened to an inequality, the
    first condition would answer True for every one of these.
    """
    assert not is_unspendable(script_pub_key)


def test_unspendable_is_wider_than_the_nulldata_classifier() -> None:
    """`is_nulldata` answers a narrower question, on purpose (issue #211).

    A bare OP_RETURN and an OP_RETURN followed by several pushes are not
    the standard nulldata shape, and a node will never let either be
    spent: reading spendability off the classifier would call both
    spendable.
    """
    assert not is_nulldata(b"\x6a")
    assert not is_nulldata(b"\x6a\x51")
    assert is_unspendable(b"\x6a")
    assert is_unspendable(b"\x6a\x51")


def test_a_hex_string_is_read_as_octets() -> None:
    """An Octets parameter takes hex, as every other one here does."""
    assert is_unspendable("6a0100")
    assert not is_unspendable("0014" + "00" * 20)
