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
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

import pytest

from btclib import base58, bech32, var_int
from btclib.alias import TaprootScriptTree
from btclib.amount import valid_sats_amount
from btclib.b32 import p2wpkh
from btclib.b58 import p2pkh, wif_from_prv_key
from btclib.bip32 import BIP32KeyData
from btclib.bip32.bip32 import rootxprv_from_seed, xpub_from_xprv
from btclib.bip32.der_path import (
    bytes_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
    str_from_index_int,
)
from btclib.block import BlockHeader
from btclib.block.block import bip34_commitment
from btclib.block.block_context import BlockContext
from btclib.block.mining import mine
from btclib.block.proof_of_work import hash_rate, retarget_first_height
from btclib.curves import (
    PreparedPoint,
    bytes_from_point,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.ecc.bms import sign as bms_sign
from btclib.ecc.dsa import sign as dsa_sign
from btclib.ecc.ssa import point_from_bip340pub_key
from btclib.ecc.ssa import sign as ssa_sign
from btclib.ecc.ssa import verify as ssa_verify
from btclib.exceptions import BTClibTypeError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.hashes import merkle_root_from_branch, sha256
from btclib.key import PrvKeyData
from btclib.mnemonic.entropy import bin_str_entropy_from_wordlist_indexes
from btclib.number_theory import mod_inv, mod_inv_batch_var, mod_inv_var
from btclib.psbt.psbt import PSBT_V2, Psbt
from btclib.script import input_script_sig, sig_hash
from btclib.to_prv_key import int_from_prv_key
from btclib.to_pub_key import point_from_key, point_from_pub_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import (
    bytes_from_octets,
    encode_num,
    hex_string,
    int_from_integer,
    is_integer,
)
from btclib.wallet.script_wallet import KeyGroup

_TX_ID = "01" * 32
_RATE = FeeRate(sats_per_kvbyte=1000)
# the key is 1, so the x-only public key it verifies under is `secp256k1.G[0]`
_SSA_SIG = ssa_sign(b"msg", 1)
_NOW = datetime(2026, 8, 4, tzinfo=timezone.utc)
# a one-leaf tree and the prevout of the one input `_tx` builds: what the
# two index parameters below have to be handed something valid to index
_SCRIPT_TREE: TaprootScriptTree = [(0xC0, ["OP_1"])]
_PREVOUTS = [TxOut(1, b"")]
_XPUB = xpub_from_xprv(rootxprv_from_seed("00" * 32))


def _tx(version: Any = 1, lock_time: Any = 0) -> Tx:
    return Tx(
        version,
        lock_time,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


def _psbt(**field: Any) -> Psbt:
    """Return the shortest psbt there is, with one field of it replaced.

    Version 2, whose fields are its own: a v0 psbt refuses
    `tx_modifiable` outright, which is a rule about the value of a field
    whose type has to be asked first.
    """
    fields: dict[str, Any] = {
        "tx_version": 1,
        "inputs": [],
        "outputs": [],
        "version": PSBT_V2,
        "hd_key_paths": {},
    }
    return Psbt(**(fields | field), check_validity=False)


def _header(version: Any = 1, nonce: Any = 1) -> BlockHeader:
    return BlockHeader(
        version,
        "00" * 32,
        "11" * 32,
        datetime(2009, 1, 9, tzinfo=timezone.utc),
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
    # a psbt is asked by `assert_valid`, `check_validity=False` on the way
    # in being what lets a field of any type at all into one
    ("psbt version", lambda v: _psbt(version=v).assert_valid()),
    ("psbt tx modifiable", lambda v: _psbt(tx_modifiable=v).assert_valid()),
    ("psbt fallback lock time", lambda v: _psbt(fallback_lock_time=v).assert_valid()),
    ("key group threshold", lambda v: KeyGroup(v, [_XPUB])),
    ("header version", _header),
    ("header nonce", lambda v: _header(nonce=v)),
    ("block height", lambda v: BlockContext(v, _NOW)),
    ("bip34 height", lambda v: BlockContext(1, _NOW, v)),
    ("private key scalar", PrvKeyData),
    (
        "bip32 depth",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", v, b"\x00" * 4, 0, b"\x00" * 32, b"\x00" * 33
        ),
    ),
    (
        "bip32 index",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", 0, b"\x00" * 4, v, b"\x00" * 32, b"\x00" * 33
        ),
    ),
    ("dust threshold", lambda v: valid_sats_amount(1, dust=v)),
    ("derivation index", indexes_from_der_path),
    ("derivation index in a sequence", lambda v: indexes_from_der_path([v])),
    ("derivation path as bytes", bytes_from_der_path),
    ("derivation path as text", str_from_der_path),
    ("derivation index as a step", str_from_index_int),
    ("output size", lambda v: bytes_from_octets(b"x", v)),
    ("output size in an iterable", lambda v: bytes_from_octets(b"x", [v])),
    ("base58 output size", lambda v: base58.decode(base58.encode(b"x"), v)),
    ("var_int", var_int.serialize),
    ("var_int max_size", lambda v: var_int.parse(b"\x01", max_size=v)),
    ("bech32 5-bit value", lambda v: bech32.encode("bc", [v])),
    ("word-list index", lambda v: bin_str_entropy_from_wordlist_indexes([v], 2048)),
    ("modular operand", lambda v: mod_inv_var(v, 7)),
    ("modulus", lambda v: mod_inv_var(3, v)),
    ("blinded modular operand", lambda v: mod_inv(v, 7)),
    ("blinded modulus", lambda v: mod_inv(3, v)),
    ("modular operand in a batch", lambda v: mod_inv_batch_var([3, v], 7)),
    ("modulus of a batch", lambda v: mod_inv_batch_var([3], v)),
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
    # Two lines of the library stand behind all of it: `int_from_integer`,
    # and `to_prv_key`'s type gate for the int branch that does not reach
    # the coercion. Neither is alone everywhere -- `bms.sign` is behind
    # both, and `point_from_key`, `p2pkh` and `p2wpkh` meet `to_pub_key`'s
    # gate before either -- so dropping one line lets a bool back through
    # only where nothing else stands behind it, and these cases are here
    # for the reach of the policy and not as a test apiece. `to_pub_key`'s
    # gate is a third line and not a third refusal: drop it and
    # `to_prv_key`'s answers those three one frame down, which is why the
    # wordings below are what pin it
    ("integer coercion", int_from_integer),
    ("hex string", hex_string),
    ("curve multiplier", mult),
    ("curve scalar", scalar_from_prv_key),
    ("private key converter", int_from_prv_key),
    ("public key converter", point_from_key),
    ("WIF private key", wif_from_prv_key),
    ("base58 address key", p2pkh),
    ("bech32 address key", p2wpkh),
    ("message signing key", lambda v: bms_sign(b"msg", v)),
    ("BIP340 x-only key", point_from_bip340pub_key),
    # not the converter twice: `verify` answers False where it cannot
    # verify, so what this pins is that the refusal is not one of those
    # answers -- `BTClibTypeError` is a `TypeError` and the except there
    # takes `ValueError`, which is issue #814's rule
    ("BIP340 verification key", lambda v: ssa_verify(b"msg", v, _SSA_SIG)),
    # `CurveGroup.is_on_curve` is the one funnel behind a `Point` tuple,
    # `point_from_pub_key`, `_x_from_bip340pub_key`, `PreparedPoint` and
    # `bytes_from_point` included, and it read a bool coordinate as an
    # int -- `Q[1] == 0` marking infinity, so a bool `False` for y was
    # read as infinity for any x (issue #1249). One case per funnel
    # pins the reach; `secp256k1.G[1]` is a placeholder y that only the
    # x-coordinate cases need on the curve, is_on_curve's type check
    # running before the equation it would otherwise fail
    ("point x-coordinate", lambda v: secp256k1.is_on_curve((v, secp256k1.G[1]))),
    ("point y-coordinate", lambda v: secp256k1.is_on_curve((secp256k1.G[0], v))),
    ("public key point", lambda v: point_from_pub_key((v, secp256k1.G[1]))),
    (
        "BIP340 x-only point",
        lambda v: point_from_bip340pub_key((v, secp256k1.G[1])),
    ),
    ("prepared point", lambda v: PreparedPoint((v, secp256k1.G[1]))),
    ("point to sec bytes", lambda v: bytes_from_point((v, secp256k1.G[1]))),
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
    """
    with pytest.raises(BTClibTypeError):
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
    ("curve multiplier", mult, "non-integer: True"),
    ("curve scalar", scalar_from_prv_key, "non-integer: True"),
    ("dsa signing key", lambda v: dsa_sign(b"msg", v), "non-integer: True"),
    ("private key converter", int_from_prv_key, "not a private key"),
    ("WIF private key", wif_from_prv_key, "not a private key"),
    ("message signing key", lambda v: bms_sign(b"msg", v), "not a private key"),
    ("public key converter", point_from_key, "not a private or public key"),
    ("base58 address key", p2pkh, "not a private or public key"),
    ("bech32 address key", p2wpkh, "not a private or public key"),
    ("BIP340 x-only key", point_from_bip340pub_key, "non-integer: True"),
    # separate from the three families above: `is_on_curve`'s own
    # refusal of a bool coordinate (issue #1249), one sentence per
    # coordinate and shared by every funnel behind it
    (
        "point x-coordinate",
        lambda v: secp256k1.is_on_curve((v, secp256k1.G[1])),
        "non-integer x-coordinate: True",
    ),
    (
        "point y-coordinate",
        lambda v: secp256k1.is_on_curve((secp256k1.G[0], v)),
        "non-integer y-coordinate: True",
    ),
    (
        "public key point",
        lambda v: point_from_pub_key((v, secp256k1.G[1])),
        "non-integer x-coordinate: True",
    ),
    (
        "prepared point",
        lambda v: PreparedPoint((v, secp256k1.G[1])),
        "non-integer x-coordinate: True",
    ),
]


@pytest.mark.parametrize(
    "call, message",
    [(case[1], case[2]) for case in _WORDINGS],
    ids=[case[0] for case in _WORDINGS],
)
def test_which_check_refuses_the_bool_decides_the_sentence(
    call: Callable[[Any], object], message: str
) -> None:
    """The wordings the release notes promise, held to what is raised.

    `to_pub_key._assert_key_type`'s bool line has nothing else to be
    tested by: dropping it leaves every one of these a refusal, and
    moves the three it answers for onto "not a private key".
    """
    with pytest.raises(BTClibTypeError, match=message):
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
    assert _psbt(fallback_lock_time=1).fallback_lock_time == 1
    assert KeyGroup(1, [_XPUB]).threshold == 1
    assert _header(nonce=1).nonce == 1
    assert BlockContext(1, _NOW).height == 1
    assert valid_sats_amount(1, dust=1) == 1
    assert indexes_from_der_path(1) == [1]
    assert indexes_from_der_path([1, 2]) == [1, 2]
    assert bytes_from_der_path(1).hex() == "01000000"
    assert str_from_der_path([1]) == "m/1"
    assert int_from_integer(1) == 1
    assert hex_string(1) == "01"
    assert mult(1) == secp256k1.G
    assert scalar_from_prv_key(1) == 1
    assert int_from_prv_key(1) == 1
    assert point_from_key(1) == secp256k1.G
    assert wif_from_prv_key(1).startswith("Kw")
    assert p2pkh(1).startswith("1")
    assert p2wpkh(1).startswith("bc1")
    assert bms_sign(b"msg", 1).dsa_sig.r
    assert point_from_bip340pub_key(secp256k1.G[0]) == secp256k1.G
    assert ssa_verify(b"msg", secp256k1.G[0], _SSA_SIG)
    assert secp256k1.is_on_curve(secp256k1.G) is True
    assert point_from_pub_key(secp256k1.G) == secp256k1.G
    assert PreparedPoint(secp256k1.G).point == secp256k1.G
    assert bytes_from_point(secp256k1.G).hex().startswith("02")
    assert str_from_index_int(1) == "1"
    assert bytes_from_octets(b"x", 1) == b"x"
    assert bytes_from_octets(b"xx", [1, 2]) == b"xx"
    assert base58.decode(base58.encode(b"x"), 1) == b"x"
    assert var_int.serialize(1) == b"\x01"
    assert var_int.parse(b"\x01", max_size=1) == 1
    assert bech32.encode("bc", [1]) == b"bc1pdg93mv"
    assert bin_str_entropy_from_wordlist_indexes([1], 2048) == "00000000001"
    assert mod_inv_var(3, 7) == 5
    assert mod_inv(3, 7) == 5
    assert mod_inv_batch_var([3, 2], 7) == [5, 4]
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

    # the str and bytes spellings of a path are untouched by any of it
    assert indexes_from_der_path("m/44h/0h") == [2147483692, 2147483648]


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    These boundaries used to convert what they were handed -- a derivation
    path through `int()`, a dust threshold through a comparison -- or to
    complain about the wrong thing: an output size that is neither a number
    nor an iterable of them met `tuple()` and answered "not iterable", from
    underneath the library rather than through its exception contract.
    """
    with pytest.raises(BTClibTypeError, match="non-integer satoshi dust"):
        valid_sats_amount(1, dust=1.0)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        indexes_from_der_path([2.0])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        str_from_index_int(1.0)  # type: ignore[arg-type]

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

    The path step is the case that has to be *answered* with a number and
    not merely accepted as one: `str()` of an `IntEnum` is its name up to
    Python 3.10, so a derivation path of one would have read
    "Sighash.ALL" there and "1" on every later interpreter -- which the
    3.10 cells of the matrix caught and this assertion now pins.
    """

    class Sighash(IntEnum):
        ALL = 1

    assert is_integer(Sighash.ALL)
    assert valid_sats_amount(Sighash.ALL) == 1
    assert FeeRate(sats_per_kvbyte=Sighash.ALL).sats_per_kvbyte == 1
    assert indexes_from_der_path(Sighash.ALL) == [1]
    assert indexes_from_der_path([Sighash.ALL]) == [1]
    assert str_from_index_int(Sighash.ALL) == "1"
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
