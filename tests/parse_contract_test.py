#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the parse contract every `parse` in btclib owes its caller.

One file rather than a case per module, because the rule is one and
`btclib/utils.py` states it: a field is as long as its encoding says, a
complete octet string is one whole object, and a caller's stream is the
caller's. What the tests hold every parser to is that none of the three
depends on `check_validity`, which is an opinion about what the bytes
mean and not about where they end.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from os import path
from typing import Any

import pytest

from btclib.bip32 import BIP32KeyData
from btclib.block import Block, BlockHeader
from btclib.ecc import bms, ssa
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# what btclib promises to raise, and the whole of it: a truncated buffer
# has to be refused as one of these three, and never as an IndexError or a
# struct error from underneath the library
_CONTRACT_EXCEPTIONS = (BTClibValueError, BTClibRuntimeError, BTClibTypeError)

_TX_ID = "01" * 32
_XPRV = (
    "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFo"
    "CMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
)


def _block_1() -> bytes:
    """Return the consensus bytes of the block after genesis."""
    filename = path.join(path.dirname(__file__), "block", "_data", "block_1.bin")
    with open(filename, "rb") as file_:
        return file_.read()


def _tx() -> Tx:
    return Tx(
        1,
        0x12345678,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


# every object with a fixed-width field in it or a length of its own,
# with the parser to read it back: (name, parse, serialization)
_CASES: list[tuple[str, Callable[..., Any], bytes]] = [
    ("outpoint", OutPoint.parse, OutPoint(_TX_ID, 0).serialize()),
    ("tx_in", TxIn.parse, TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF).serialize()),
    ("tx_out", TxOut.parse, TxOut(1, b"").serialize()),
    ("tx", Tx.parse, _tx().serialize(include_witness=True)),
    ("block_header", BlockHeader.parse, _block_1()[:80]),
    ("block", Block.parse, _block_1()),
    ("bip32_key", BIP32KeyData.parse, BIP32KeyData.b58decode(_XPRV).serialize()),
    ("ssa_sig", ssa.Sig.parse, ssa.sign(b"parse contract", 1).serialize()),
    ("bms_sig", bms.Sig.parse, bms.sign(b"parse contract", 1).serialize()),
]

_IDS = [case[0] for case in _CASES]
_PARSE_AND_BYTES = [(case[1], case[2]) for case in _CASES]


@pytest.mark.parametrize(("parse", "serialization"), _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_no_prefix_of_an_encoding_is_an_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Every truncation is refused, at every offset and either way.

    `BytesIO.read` answers with what is left rather than raising, and
    `int.from_bytes` takes a short answer, so an unchecked parser turns
    each of these prefixes into an object that serializes back longer
    than the buffer it came from: distinct buffers, including malformed
    ones, mapping to one canonical object.
    """
    for size in range(len(serialization)):
        with pytest.raises(_CONTRACT_EXCEPTIONS):
            parse(serialization[:size], check_validity=check_validity)


@pytest.mark.parametrize(("parse", "serialization"), _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_octets_are_one_whole_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Bytes after the object are refused, hex-string included."""
    assert parse(serialization, check_validity=check_validity)

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse(serialization + trailing, check_validity=check_validity)
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse((serialization + trailing).hex(), check_validity=check_validity)


@pytest.mark.parametrize(("parse", "serialization"), _PARSE_AND_BYTES, ids=_IDS)
def test_a_stream_is_the_callers(
    parse: Callable[..., Any], serialization: bytes
) -> None:
    """A stream may carry more, and is left on the byte after the object.

    This is the half of the contract that makes the other half safe to
    enforce: a transaction is read out of the very stream its block is
    read from, so what follows the object in a stream is not the parser's
    to complain about -- or to consume.
    """
    stream = BytesIO(serialization + b"junk")
    assert parse(stream)
    assert stream.read() == b"junk"


def test_a_truncated_field_names_itself() -> None:
    """The diagnosis is the truncation, not whatever the short read meant.

    Without the length check the missing bytes are reported by whichever
    field they happen to fall in, or not at all: three bytes off a lock
    time read as a lock time three bytes smaller, which is a valid one.
    """
    tx_bytes = _tx().serialize(include_witness=True)
    out_point_bytes = OutPoint(_TX_ID, 0).serialize()

    with pytest.raises(
        BTClibValueError, match="not enough data for the outpoint tx_id"
    ):
        OutPoint.parse(out_point_bytes[:20])
    with pytest.raises(BTClibValueError, match="not enough data for the outpoint vout"):
        OutPoint.parse(out_point_bytes[:34])
    with pytest.raises(
        BTClibValueError, match="not enough data for the transaction version"
    ):
        Tx.parse(tx_bytes[:3])
    with pytest.raises(BTClibValueError, match="not enough data for the lock time"):
        Tx.parse(tx_bytes[:-1])
    with pytest.raises(BTClibValueError, match="not enough data for the sequence"):
        TxIn.parse(TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF).serialize()[:-1])
    with pytest.raises(BTClibValueError, match="not enough data for the output value"):
        TxOut.parse(TxOut(1, b"").serialize()[:4])


def test_a_fixed_size_object_reports_its_own_length() -> None:
    """A buffer that is the object reports the buffer, not a field of it.

    The three fixed-size encodings agree on the message -- and on saying
    it whatever `check_validity` says, which is what a semantic check
    would have gated.
    """
    header_bytes = _block_1()[:80]
    key_bytes = BIP32KeyData.b58decode(_XPRV).serialize()

    err_msg = "invalid decoded length: 70 instead of 80"
    with pytest.raises(BTClibValueError, match=err_msg):
        BlockHeader.parse(header_bytes[:70], check_validity=False)

    err_msg = "invalid decoded length: 70 instead of 78"
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyData.parse(key_bytes[:70], check_validity=False)


def test_a_truncation_does_not_round_trip() -> None:
    """The property behind the contract, on the case issue 322 reported.

    A transaction one to three bytes short of its lock time used to parse
    into a transaction whose serialization is longer than what was
    parsed: two buffers, one object, and only one of them written back.
    """
    tx = _tx()
    tx_bytes = tx.serialize(include_witness=True)

    for cut in (1, 2, 3):
        with pytest.raises(BTClibValueError, match="not enough data for the lock time"):
            Tx.parse(tx_bytes[:-cut])

    assert Tx.parse(tx_bytes) == tx
    with pytest.raises(BTClibValueError, match="4 bytes after the transaction"):
        Tx.parse(tx_bytes + b"junk")
