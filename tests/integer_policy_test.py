# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on integer fields: a bool is not a number.

One file rather than a case per module, because the decision is one and
`btclib.utils.is_integer` states it. What makes it worth a refusal is the
json boundary: `true` decodes to `True`, and a schema mistake used to
become one satoshi, one virtual byte, one index or a one-sat/kvB fee rate
instead of failing beside the input that caused it.

"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

import pytest

from btclib import base58, bech32, var_int
from btclib.alias import TaprootScriptTree
from btclib.amount import valid_sats_amount
from btclib.b58 import wif_from_prv_key
from btclib.block import BlockHeader
from btclib.block.block import bip34_commitment
from btclib.block.block_context import BlockContext
from btclib.block.mining import mine
from btclib.block.proof_of_work import hash_rate, retarget_first_height
from btclib.exceptions import BTClibEccTypeError, BTClibTypeError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.hashes import merkle_root_from_branch, sha256
from btclib.key import PrvKeyData
from btclib.script import input_script_sig, sig_hash
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import (
    bytes_from_octets,
    encode_num,
    hex_string,
    int_from_integer,
    is_integer,
)

_TX_ID = "01" * 32
_RATE = FeeRate(sats_per_kvbyte=1000)
_NOW = datetime(2026, 8, 4, tzinfo=UTC)
# a one-leaf tree and the prevout of the one input `_tx` builds: what the
# two index parameters below have to be handed something valid to index
_SCRIPT_TREE: TaprootScriptTree = [(0xC0, ["OP_1"])]
_PREVOUTS = [TxOut(1, b"")]


def _tx(version: Any = 1, lock_time: Any = 0) -> Tx:
    return Tx(
        version,
        lock_time,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


def _header(version: Any = 1, nonce: Any = 1) -> BlockHeader:
    return BlockHeader(
        version,
        "00" * 32,
        "11" * 32,
        datetime(2009, 1, 9, tzinfo=UTC),
        "1d00ffff",
        nonce,
    )


# every field whose contract is an integer quantity, with the shortest
# call that reaches its validator
_CASES: list[tuple[str, Callable[[Any], object]]] = [
    ("satoshi amount", valid_sats_amount),
    ("fee rate", lambda v: FeeRate(sats_per_kvbyte=v)),
    ("virtual size", lambda v: fee_from_vsize(v, _RATE)),
    ("output value", lambda v: TxOut(v, b"")),
    ("outpoint vout", lambda v: OutPoint(_TX_ID, v)),
    (
        "outpoint vout from a dict",
        lambda v: OutPoint.from_dict({"txid": _TX_ID, "vout": v}),
    ),
    ("input sequence", lambda v: TxIn(OutPoint(_TX_ID, 0), b"", v)),
    ("transaction version", _tx),
    ("transaction lock time", lambda v: _tx(lock_time=v)),
    ("header version", _header),
    ("header nonce", lambda v: _header(nonce=v)),
    ("block height", lambda v: BlockContext(v, _NOW)),
    ("bip34 height", lambda v: BlockContext(1, _NOW, v)),
    ("private key scalar", PrvKeyData),
    ("dust threshold", lambda v: valid_sats_amount(1, dust=v)),
    ("output size", lambda v: bytes_from_octets(b"x", v)),
    ("output size in an iterable", lambda v: bytes_from_octets(b"x", [v])),
    ("base58 output size", lambda v: base58.decode(base58.encode(b"x"), v)),
    ("var_int", var_int.serialize),
    ("var_int max_size", lambda v: var_int.parse(b"\x01", max_size=v)),
    ("bech32 5-bit value", lambda v: bech32.encode("bc", [v])),
    ("taproot leaf index", lambda v: input_script_sig(None, _SCRIPT_TREE, v)),
    (
        "sig_hash input index",
        lambda v: sig_hash.taproot(_tx(), v, _PREVOUTS, 1, 0, b"", b""),
    ),
    ("script number", encode_num),
    (
        "merkle leaf index",
        lambda v: merkle_root_from_branch(b"\x00" * 32, [], v, sha256),
    ),
    ("bip34 commitment height", bip34_commitment),
    ("retarget height", retarget_first_height),
    ("mining max tries", lambda v: mine(_header(), v)),
    ("hash rate difficulty", lambda v: hash_rate(v, 600.0)),
    ("hash rate timespan", lambda v: hash_rate(1.0, v)),
    ("hash rate block count", lambda v: hash_rate(1.0, 600.0, v)),
    # the key path, which this census did not reach until issue #1206.
    # One line stands behind all of it, `int_from_integer`: `wif_from_prv_key`
    # reaches it through btclib_ecc's copy, which is that package's to
    # test. These cases are here for the reach of the policy and not as a
    # test apiece. The address builders are not among
    # them: they take a `PubKeyData`, so a bool is refused by
    # `bytes_from_octets` on the same terms as any other wrong type, and
    # `bms.sign` likewise takes a `PrvKeyData` and refuses one through
    # `assert_type` (issue #1188) -- refusals `key_test.py` holds, not
    # this census
    ("integer coercion", int_from_integer),
    ("hex string", hex_string),
    ("WIF private key", wif_from_prv_key),
]

_IDS = [case[0] for case in _CASES]
_CALLS = [case[1] for case in _CASES]


@pytest.mark.parametrize("call", _CALLS, ids=_IDS)
@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_bool_is_not_an_integer_field(
    call: Callable[[Any], object], *, value: bool
) -> None:
    """Every integer field refuses a boolean, and refuses it as a type.

    `isinstance(True, int)` is what let each of these through as one or
    zero, and `int(True) == True` is what let the satoshi amount through a
    conversion-and-equality check on top of that.

    btclib_ecc's class where that package reads the field -- the WIF's
    key, through its `scalar_from_prv_key` -- and btclib's elsewhere.
    """
    with pytest.raises((BTClibTypeError, BTClibEccTypeError)):
        call(value)


# the sentence each of these gives back, CHANGELOG.md and
# RELEASE_NOTES.md naming which entry points give which. Whichever
# control reaches the value first writes it, so
# an entry point moves between these families by gaining or losing a
# check above it and never by choosing a wording -- which is why the
# notes tell a caller to match on the class. Three families, and no
# census of what a bool can draw: these are the sentences this change
# writes, `_CASES` above is the wider list and pins the class rather
# than the text, and a refusal older than this one belongs to whatever
# raises it and not to the key surface -- `PrvKeyData`'s is its own and
# `key_test.py` has it, where `PubKeyData` gives back
# `bytes_from_octets`', the sentence every `Octets` parameter shares
_WORDINGS = [
    ("integer coercion", int_from_integer, "non-integer: True"),
    ("hex string", hex_string, "non-integer: True"),
    ("WIF private key", wif_from_prv_key, "non-integer: True"),
]


@pytest.mark.parametrize(
    "call, message",
    [(case[1], case[2]) for case in _WORDINGS],
    ids=[case[0] for case in _WORDINGS],
)
def test_which_check_refuses_the_bool_decides_the_sentence(
    call: Callable[[Any], object], message: str
) -> None:
    """The wordings the release notes promise, held to what is raised."""
    with pytest.raises((BTClibTypeError, BTClibEccTypeError), match=message):
        call(True)


def test_the_integers_a_bool_refusal_must_not_take_with_it() -> None:
    """The same calls with a number, which is what the refusal is around.

    A test that only checks refusals passes just as well when the field
    refuses everything.
    """
    assert valid_sats_amount(1) == 1
    assert FeeRate(sats_per_kvbyte=1).sats_per_kvbyte == 1
    assert fee_from_vsize(1, _RATE) == 1
    assert TxOut(1, b"").value == 1
    assert OutPoint(_TX_ID, 1).vout == 1
    assert OutPoint.from_dict({"txid": _TX_ID, "vout": 1}).vout == 1
    assert TxIn(OutPoint(_TX_ID, 0), b"", 1).sequence == 1
    assert _tx(version=1, lock_time=1).lock_time == 1
    assert _header(nonce=1).nonce == 1
    assert BlockContext(1, _NOW).height == 1
    assert valid_sats_amount(1, dust=1) == 1
    assert int_from_integer(1) == 1
    assert hex_string(1) == "01"
    assert wif_from_prv_key(1).startswith("Kw")
    assert bytes_from_octets(b"x", 1) == b"x"
    assert bytes_from_octets(b"xx", [1, 2]) == b"xx"
    assert base58.decode(base58.encode(b"x"), 1) == b"x"
    assert var_int.serialize(1) == b"\x01"
    assert var_int.parse(b"\x01", max_size=1) == 1
    assert bech32.encode("bc", [1]) == b"bc1pdg93mv"
    assert input_script_sig(None, _SCRIPT_TREE, 0)[0] == ["OP_1"]
    assert len(sig_hash.taproot(_tx(), 0, _PREVOUTS, 1, 0, b"", b"")) == 32
    assert encode_num(1) == b"\x01"
    assert merkle_root_from_branch(b"\x00" * 32, [], 0, sha256) == b"\x00" * 32
    assert bip34_commitment(1) == b"Q"
    assert retarget_first_height(2015) == 0
    assert mine(_header(), 1) is None
    assert hash_rate(1.0, 600.0, 1) == 2**32 / 600.0
    # an integer difficulty and an integer timespan are numbers too: the
    # bool refusal must not take the int with it where a float is annotated
    assert hash_rate(1, 600) == hash_rate(1.0, 600.0)


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    These boundaries used to convert what they were handed -- a dust
    threshold through a comparison -- or to
    complain about the wrong thing: an output size that is neither a number
    nor an iterable of them met `tuple()` and answered "not iterable", from
    underneath the library rather than through its exception contract.
    """
    with pytest.raises(BTClibTypeError, match="non-integer satoshi dust"):
        valid_sats_amount(1, dust=1.0)  # type: ignore[arg-type]

    for out_size in (1.5, object(), "1"):
        with pytest.raises(BTClibTypeError, match="invalid output size type"):
            bytes_from_octets(b"x", out_size)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid output size type"):
        bytes_from_octets(b"x", [1.5])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid output size type"):
        base58.decode(base58.encode(b"x"), 1.0)  # type: ignore[arg-type]

    for not_a_count in (1.5, "1", object()):
        with pytest.raises(BTClibTypeError, match="non-integer var_int"):
            var_int.serialize(not_a_count)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="non-integer max_size"):
            var_int.parse(b"\x01", max_size=not_a_count)  # type: ignore[arg-type]


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    Issue #273 asks whether the sighash types should become an `IntEnum`;
    `type(value) is int` would have answered it in advance, and with a no.
    """

    class Sighash(IntEnum):
        ALL = 1

    assert is_integer(Sighash.ALL)
    assert valid_sats_amount(Sighash.ALL) == 1
    assert FeeRate(sats_per_kvbyte=Sighash.ALL).sats_per_kvbyte == 1
    assert bytes_from_octets(b"x", Sighash.ALL) == b"x"
    assert base58.decode(base58.encode(b"x"), Sighash.ALL) == b"x"
    assert var_int.serialize(Sighash.ALL) == b"\x01"
    assert var_int.parse(b"\x01", max_size=Sighash.ALL) == 1

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
    assert not is_integer(None)
