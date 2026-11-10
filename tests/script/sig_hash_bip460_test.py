# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `sig_hash.taproot` under BIP460's aggregation modes.

`bip-0460/wallet-test-vectors.json` is bip-0460's own file of that name,
https://github.com/bitcoin/bips/blob/master/bip-0460/wallet-test-vectors.json,
and tests/_data/README.md pins its revision.

The aggregate signatures of those vectors are BIP458's and BIP459's,
which are ecc's to compute, so they are not asserted here. What is
asserted is the message each input signs, and the part of a witness
that is one input's own BIP340 signature: the whole signature of an
input that opts out, the nonce share of a half aggregation input.
"""

from typing import Any

import pytest
from ecc import ssa

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import (
    address,
    check_output_pubkey,
    output_prvkey_from_merkle_root,
    output_pubkey_from_merkle_root_var,
    sig_hash,
)
from btclib.script.taproot import leaf_hash, tap_tweak
from btclib.tx import Tx, TxOut
from tests import load, vector_id

VECTORS = load("script", "_data", "bip-0460", "wallet-test-vectors.json")

HALF_AGG = 0xBC
FULL_AGG = 0xBD


def _utxos(given: dict[str, Any]) -> list[TxOut]:
    return [
        TxOut(utxo["amountSats"], utxo["scriptPubKey"]) for utxo in given["utxosSpent"]
    ]


def _agg_mode(given: dict[str, Any]) -> int | None:
    agg_mode = given["aggMode"]
    return None if agg_mode is None else int(agg_mode, 16)


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector_id(index, vector["expected"]["address"]))
        for index, vector in enumerate(VECTORS["scriptPubKey"])
    ],
)
def test_script_pub_key(vector: dict[str, Any]) -> None:
    """The witness version 2 output of a key with no script tree."""
    internal_pub_key = vector["given"]["internalPubkey"]
    assert tap_tweak(internal_pub_key).hex() == vector["intermediary"]["tweak"]
    tweaked, _ = output_pubkey_from_merkle_root_var(internal_pub_key)
    assert tweaked.hex() == vector["intermediary"]["tweakedPubkey"]
    script_pub_key = b"\x52\x20" + tweaked
    assert script_pub_key.hex() == vector["expected"]["scriptPubKey"]
    assert address(script_pub_key) == vector["expected"]["address"]


@pytest.mark.parametrize(
    "spending, spending_input",
    [
        pytest.param(
            spending,
            spending_input,
            id=vector_id(
                index,
                f"input{spending_input['given']['txinIndex']}",
                f"aggmode{spending_input['given']['aggMode']}",
                f"hashtype{spending_input['given']['hashType']}",
            ),
        )
        for index, spending in enumerate(VECTORS["keyPathSpending"])
        for spending_input in spending["inputSpending"]
    ],
)
def test_key_path_spending(
    spending: dict[str, Any], spending_input: dict[str, Any]
) -> None:
    """Each input's message, tweak and individual signature, per its mode."""
    tx = Tx.parse(spending["given"]["rawUnsignedTx"])
    utxos = _utxos(spending["given"])
    given = spending_input["given"]
    intermediary = spending_input["intermediary"]
    index = given["txinIndex"]
    hash_type = given["hashType"]
    agg_mode = _agg_mode(given)

    msg_hash = sig_hash.taproot(
        tx, index, utxos, hash_type, 0, b"", b"", agg_mode=agg_mode
    )
    assert msg_hash.hex() == intermediary["sigHash"]

    internal_prv_key = given["internalPrivkey"]
    tweaked_prv_key = output_prvkey_from_merkle_root(internal_prv_key)
    assert tweaked_prv_key.to_bytes(32, "big").hex() == intermediary["tweakedPrivkey"]
    assert tap_tweak(intermediary["internalPubkey"]).hex() == intermediary["tweak"]

    # the individual BIP340 signature, made with the auxiliary randomness
    # of 32 zero bytes BIP460 made it with. An input that opts out
    # carries it whole, as BIP341's key path does; a half aggregation
    # input carries its first 32 bytes, the nonce share. A full
    # aggregation input carries no individual signature to compare
    signature = ssa.sign_(msg_hash, tweaked_prv_key, b"\x00" * 32).serialize()
    element = bytes.fromhex(spending_input["expected"]["witness"][0])
    if agg_mode is None:
        # SIGHASH_DEFAULT is written as no byte at all
        explicit = b"" if hash_type == sig_hash.DEFAULT else bytes([hash_type])
        assert element == signature + explicit
    elif agg_mode == HALF_AGG:
        assert element[:32] == signature[:32]

    # BIP460's witness elements are one element each, so none of them is
    # read as an annex or as a script path: the hash from the signed
    # transaction is the one signed
    signed = Tx.parse(spending["expected"]["rawSignedTx"])
    annex, ext = sig_hash.taproot_annex_and_ext(signed, index)
    assert (annex, ext) == (b"", b"")
    assert (
        sig_hash.taproot(
            signed, index, utxos, hash_type, 0, annex, ext, agg_mode=agg_mode
        )
        == msg_hash
    )


def test_script_path_spending() -> None:
    """A script path of a witness version 2 output is BIP341's and BIP342's."""
    (vector,) = VECTORS["scriptPathSpending"]
    given = vector["given"]
    intermediary = vector["intermediary"]
    expected = vector["expected"]
    script = bytes.fromhex(given["script"])

    tap_leaf_hash = leaf_hash(int(given["leafVersion"], 16), script)
    assert tap_leaf_hash.hex() == intermediary["leafHash"]
    # one leaf, so the merkle root is the leaf hash
    internal_pub_key = given["internalPubkey"]
    assert tap_tweak(internal_pub_key, tap_leaf_hash).hex() == intermediary["tweak"]
    tweaked, _ = output_pubkey_from_merkle_root_var(internal_pub_key, tap_leaf_hash)
    assert tweaked.hex() == intermediary["tweakedPubkey"]
    control_block = bytes.fromhex(intermediary["controlBlock"])
    assert check_output_pubkey(tweaked, script, control_block)
    assert address(bytes.fromhex(expected["scriptPubKey"])) == expected["address"]

    signed = Tx.parse(expected["rawSignedTx"])
    assert [element.hex() for element in signed.vin[0].script_witness.stack] == (
        expected["witness"]
    )
    utxos = _utxos(given)
    annex, ext = sig_hash.taproot_annex_and_ext(signed, 0)
    msg_hash = sig_hash.taproot(signed, 0, utxos, given["hashType"], 1, annex, ext)
    assert msg_hash.hex() == intermediary["sigHash"]
    # the leaf is `<x-only key> OP_CHECKSIG`
    ssa.assert_as_valid_(msg_hash, script[1:33], bytes.fromhex(expected["witness"][0]))
    # BIP460 aggregates key path spends only
    with pytest.raises(BTClibValueError, match="aggregation mode for a script path"):
        sig_hash.taproot(
            signed, 0, utxos, given["hashType"], 1, annex, ext, agg_mode=HALF_AGG
        )


def _first_key_path_input() -> tuple[Tx, list[TxOut]]:
    spending = VECTORS["keyPathSpending"][0]
    return Tx.parse(spending["given"]["rawUnsignedTx"]), _utxos(spending["given"])


def test_the_message_commits_to_the_mode() -> None:
    """One input signs a different message under each mode and under none.

    What makes aggregation consensual, per BIP460: a signature made for
    one mode verifies under no other.
    """
    tx, utxos = _first_key_path_input()
    hashes = {
        sig_hash.taproot(tx, 0, utxos, sig_hash.ALL, 0, b"", b"", agg_mode=agg_mode)
        for agg_mode in (None, HALF_AGG, FULL_AGG)
    }
    assert len(hashes) == 3


@pytest.mark.parametrize("agg_mode", [0x00, 0x01, 0x50, 0xBB, 0xBE, 0xFF, 0x1BC, -0xBC])
def test_a_byte_no_group_is_marked_with_is_refused(agg_mode: int) -> None:
    """A byte BIP460 marks no group with is refused.

    An undefined marker is no upgrade hook.
    """
    tx, utxos = _first_key_path_input()
    with pytest.raises(BTClibValueError, match="invalid aggregation mode: "):
        sig_hash.taproot(tx, 0, utxos, sig_hash.ALL, 0, b"", b"", agg_mode=agg_mode)


@pytest.mark.parametrize("agg_mode", [True, "0xbc", b"\xbc", 188.0])
def test_a_mode_that_is_no_integer_is_refused(agg_mode: Any) -> None:
    """A bool, a string, bytes and a float are refused as a type."""
    tx, utxos = _first_key_path_input()
    with pytest.raises(BTClibTypeError, match="invalid aggregation mode type: "):
        sig_hash.taproot(tx, 0, utxos, sig_hash.ALL, 0, b"", b"", agg_mode=agg_mode)


@pytest.mark.parametrize("ext_flag", [1, 0x7F])
def test_a_mode_is_refused_beside_an_extension_flag(ext_flag: int) -> None:
    """A mode is refused with any extension flag but the key path's."""
    tx, utxos = _first_key_path_input()
    with pytest.raises(BTClibValueError, match="aggregation mode for a script path"):
        sig_hash.taproot(
            tx, 0, utxos, sig_hash.ALL, ext_flag, b"", b"", agg_mode=FULL_AGG
        )


@pytest.mark.parametrize("ext_flag", [-1, 0x80, 200])
def test_an_out_of_range_extension_flag_is_named_as_such(ext_flag: int) -> None:
    """An out-of-range extension flag is refused as such under a mode."""
    tx, utxos = _first_key_path_input()
    with pytest.raises(BTClibValueError, match="invalid extension flag: "):
        sig_hash.taproot(
            tx, 0, utxos, sig_hash.ALL, ext_flag, b"", b"", agg_mode=FULL_AGG
        )


def test_an_extension_flag_that_is_no_integer_is_named_as_such() -> None:
    """A mode beside a wrong extension flag leaves the flag's refusal to it."""
    tx, utxos = _first_key_path_input()
    ext_flag: Any = "1"
    with pytest.raises(BTClibTypeError, match="invalid extension flag type"):
        sig_hash.taproot(
            tx, 0, utxos, sig_hash.ALL, ext_flag, b"", b"", agg_mode=HALF_AGG
        )


def test_bip341_s_failures_hold_under_a_mode() -> None:
    """BIP460's SigMsg is BIP341's, failure conditions included."""
    tx, utxos = _first_key_path_input()
    # the transaction has one output and this is its second input
    with pytest.raises(BTClibValueError, match="Sighash single without"):
        sig_hash.taproot(tx, 1, utxos, sig_hash.SINGLE, 0, b"", b"", agg_mode=HALF_AGG)
    with pytest.raises(BTClibValueError, match="Unknown hash type"):
        sig_hash.taproot(tx, 0, utxos, 0x80, 0, b"", b"", agg_mode=HALF_AGG)
