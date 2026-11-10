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
from decimal import Decimal
from enum import IntEnum
from io import BytesIO
from typing import Any

import pytest
from ecc.exceptions import EccTypeError

from btclib import bms, var_int
from btclib.alias import TaprootScriptTree
from btclib.amount import valid_sats_amount
from btclib.b32 import address_from_witness, power_of_2_base_conversion
from btclib.b58 import wif_from_prv_key
from btclib.block import BlockHeader
from btclib.block.block import bip34_commitment
from btclib.block.block_context import BlockContext
from btclib.block.build import build_coinbase
from btclib.block.mining import mine
from btclib.block.proof_of_work import hash_rate, retarget_first_height
from btclib.exceptions import BTClibTypeError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.hashes import merkle_root_from_branch, sha256
from btclib.key import PrvKeyData
from btclib.script import ScriptPubKey, input_script_sig, sig_hash
from btclib.script.engine import NO_FLAGS
from btclib.script.engine.script import (
    assert_pub_key_num,
    assert_signature_num,
    script_op_count,
)
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.script import op_int, push_int, read_op_code, serialize
from btclib.script.taproot import tree_helper
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
# the ECDSA half of a BMS signature, r and s of 1, which the recovery flag
# below is paired with
_DSA_SIG = bms.Sig.parse(
    bytes([27]) + 2 * (1).to_bytes(32, "big"), check_validity=False
).dsa_sig


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


# the integer parameters whose type is checked before an operator or a
# lookup meets them, the shortest call that reaches each check, and the
# start of its refusal (issues #3008 and #3023)
_NON_INTEGER_CASES: list[tuple[str, Callable[[Any], object], str]] = [
    ("OP_INT", op_int, "invalid OP_INT type"),
    ("pushed number", push_int, "non-integer script number"),
    (
        "legacy sig_hash type",
        lambda v: sig_hash.legacy(b"", _tx(), 0, v),
        "invalid hash_type type",
    ),
    (
        "segwit_v0 sig_hash type",
        lambda v: sig_hash.segwit_v0(b"", _tx(), 0, v, 1),
        "invalid hash_type type",
    ),
    (
        "taproot sig_hash type",
        lambda v: sig_hash.taproot(_tx(), 0, _PREVOUTS, v, 0, b"", b""),
        "invalid hash_type type",
    ),
    (
        "from_tx sig_hash type",
        lambda v: sig_hash.from_tx(_PREVOUTS, _tx(), 0, v),
        "invalid hash_type type",
    ),
    (
        "OP_CODESEPARATOR index",
        lambda v: sig_hash.from_tx(_PREVOUTS, _tx(), 0, 1, codesep_index=v),
        "invalid OP_CODESEPARATOR index type",
    ),
    (
        "bms recovery flag",
        lambda v: bms.Sig(v, _DSA_SIG),
        "invalid recovery flag type",
    ),
    ("coinbase fees", lambda v: build_coinbase(1, b"", fees=v), "invalid fees type"),
    ("public key count", assert_pub_key_num, "invalid public key count type"),
    (
        "signature count",
        lambda v: assert_signature_num(v, 3),
        "invalid signature count type",
    ),
    (
        "signature count's public key count",
        lambda v: assert_signature_num(1, v),
        "invalid public key count type",
    ),
    ("op code count", lambda v: script_op_count(v, 1), "invalid op code count type"),
    (
        "op code count increment",
        lambda v: script_op_count(1, v),
        "invalid op code count increment type",
    ),
    (
        "pushdata op code",
        lambda v: read_push_data(
            v, BytesIO(b"\x01\x02"), [], False, NO_FLAGS, serialize
        ),
        "invalid op code type",
    ),
    (
        "op code start",
        lambda v: read_op_code(b"\x00\x01\x02", v),
        "invalid start offset type",
    ),
]

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
    ("private key scalar", PrvKeyData),
    ("dust threshold", lambda v: valid_sats_amount(1, dust=v)),
    ("output size", lambda v: bytes_from_octets(b"x", v)),
    ("output size in an iterable", lambda v: bytes_from_octets(b"x", [v])),
    ("var_int", var_int.serialize),
    ("var_int max_size", lambda v: var_int.parse(b"\x01", max_size=v)),
    ("witness version", lambda v: address_from_witness(v, b"\x00" * 20)),
    ("base conversion value", lambda v: power_of_2_base_conversion([v], 1, 8)),
    ("base conversion from_bits", lambda v: power_of_2_base_conversion([1], v, 8)),
    ("base conversion to_bits", lambda v: power_of_2_base_conversion([1], 8, v)),
    ("taproot leaf index", lambda v: input_script_sig(None, _SCRIPT_TREE, v)),
    ("taproot leaf version", lambda v: tree_helper([(v, ["OP_1"])])),
    ("multisig threshold", lambda v: ScriptPubKey.p2ms(v, [PrvKeyData(1).pub])),
    (
        "sig_hash input index",
        lambda v: sig_hash.taproot(_tx(), v, _PREVOUTS, 1, 0, b"", b""),
    ),
    (
        "sig_hash aggregation mode",
        lambda v: sig_hash.taproot(_tx(), 0, _PREVOUTS, 1, 0, b"", b"", agg_mode=v),
    ),
    ("script number", encode_num),
    *((name, call) for name, call, _ in _NON_INTEGER_CASES),
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
    # reaches it through ecc's copy, which is that package's to
    # test. These cases are here for the reach of the policy and not as a
    # test apiece. The address builders are not among
    # them: they take a `PubKeyData` and refuse a bool through
    # `assert_type`, as any other wrong type, and `bms.sign` likewise
    # takes a `PrvKeyData` or a WIF `str` and refuses one through
    # `assert_type` (issue #1188) -- refusals `built_object_contract_test.py`,
    # `key_test.py` and `schemes/bms_test.py` hold, not this census
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

    ecc's class where that package reads the field -- the WIF's
    key, through its `scalar_from_prv_key` -- and btclib's elsewhere.
    """
    with pytest.raises((BTClibTypeError, EccTypeError)):
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
    with pytest.raises((BTClibTypeError, EccTypeError), match=message):
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
    assert var_int.serialize(1) == b"\x01"
    assert var_int.parse(b"\x01", max_size=1) == 1
    assert address_from_witness(1, b"\x00" * 20) == (
        "bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmmente"
    )
    assert power_of_2_base_conversion([1], 1, 8) == [128]
    assert power_of_2_base_conversion([1], 8, 1) == [0, 0, 0, 0, 0, 0, 0, 1]
    assert input_script_sig(None, _SCRIPT_TREE, 0)[0] == ["OP_1"]
    assert tree_helper([(0xC0, ["OP_1"])])[0][0][0] == (0xC0, ["OP_1"])
    assert len(sig_hash.taproot(_tx(), 0, _PREVOUTS, 1, 0, b"", b"")) == 32
    assert (
        len(sig_hash.taproot(_tx(), 0, _PREVOUTS, 1, 0, b"", b"", agg_mode=0xBC)) == 32
    )
    assert encode_num(1) == b"\x01"
    assert merkle_root_from_branch(b"\x00" * 32, [], 0, sha256) == b"\x00" * 32
    assert bip34_commitment(1) == b"Q"
    assert retarget_first_height(2015) == 0
    assert mine(_header(), 1) is None
    assert hash_rate(1.0, 600.0, 1) == 2**32 / 600.0
    # an integer difficulty and an integer timespan are numbers too: the
    # bool refusal must not take the int with it where a float is annotated
    assert hash_rate(1, 600) == hash_rate(1.0, 600.0)
    assert op_int(1) == "OP_1"
    assert push_int(1) == "OP_1"
    assert len(sig_hash.legacy(b"", _tx(), 0, 1)) == 32
    assert len(sig_hash.segwit_v0(b"", _tx(), 0, 1, 1)) == 32
    assert len(sig_hash.from_tx(_PREVOUTS, _tx(), 0, 1, codesep_index=0)) == 32
    assert bms.Sig(27, _DSA_SIG).rf == 27
    assert build_coinbase(1, b"", fees=1).vout[0].value == 50 * 10**8 + 1


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

    for not_a_count in (1.5, "1", object()):
        with pytest.raises(BTClibTypeError, match="non-integer var_int"):
            var_int.serialize(not_a_count)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="non-integer max_size"):
            var_int.parse(b"\x01", max_size=not_a_count)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "call, err_msg",
    [(case[1], case[2]) for case in _NON_INTEGER_CASES],
    ids=[case[0] for case in _NON_INTEGER_CASES],
)
@pytest.mark.parametrize(
    "value",
    ["1", b"\x01", Decimal(1), 1.0, None, True, False],
    ids=["str", "bytes", "Decimal", "float", "None", "true", "false"],
)
def test_a_non_integer_is_refused_before_it_is_compared(
    call: Callable[[Any], object], err_msg: str, value: object
) -> None:
    """Each wrong type, a bool included, is refused by its type name.

    Unchecked, each would meet an operator or a lookup first, and leave
    as Python's bare TypeError, as some other refusal, or not at all
    (issues #3008 and #3023).
    """
    match = f"^{err_msg}: {type(value).__name__}$"
    with pytest.raises(BTClibTypeError, match=match):
        call(value)


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
    assert var_int.serialize(Sighash.ALL) == b"\x01"
    assert var_int.parse(b"\x01", max_size=Sighash.ALL) == 1

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
    assert not is_integer(None)
