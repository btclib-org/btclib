# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip322` module.

The vectors are BIP322's own two files, vendored whole under
`tests/_data/`; `tests/_data/README.md` pins the revision of each. They
are what the BIP publishes and what its reference implementation was
checked against, so what they cover is what this module is held to: the
three transaction hashes, every variant in both directions, and the
error cases -- a wrong message, a wrong signer, a wrong address, a
malformed encoding -- which a verifier that answered "valid" too readily
would pass all of the first group and none of the second.
"""

from __future__ import annotations

import base64
import dataclasses
from typing import Any

import pytest

from btclib import bip322
from btclib.b32 import p2tr, p2wpkh, p2wsh
from btclib.b58 import p2pkh, p2wpkh_p2sh, wif_from_prv_key
from btclib.ecc import bms, dsa
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibValueError,
    InconclusiveError,
)
from btclib.hashes import hash160
from btclib.psbt import Psbt
from btclib.script import ScriptPubKey, address, serialize
from btclib.script.engine import ALL_FLAGS, ScriptFlag
from btclib.script.sig_hash import ALL, segwit_v0
from btclib.script.taproot import output_pubkey
from btclib.script.witness import Witness
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load, vector_id

BASIC = load("_data", "basic-test-vectors.json", encoding="utf-8")
GENERATED = load("_data", "generated-test-vectors.json", encoding="utf-8")

# the two private keys of the round-trip tests below, and the second is
# there to be the wrong one: a signature that verifies for the key that
# made it says nothing until one that did not is refused
WIF = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
OTHER_WIF = "L4DksdGZ4KQJfcLHD5Dv25fu8Rxyv7hHi2RjZR4TYzr8c6h9VNrp"

# native segwit: the script types whose signature the simple variant may
# carry, the rest of `to_sign` being fixed for them
_NATIVE_SEGWIT = frozenset({"p2wpkh", "p2wsh", "p2tr"})


def _address(wif: str, script_type: str) -> str:
    """Return the address of one of the four types a single key owns."""
    if script_type == "p2tr":
        pub_key = pub_keyinfo_from_key(wif, compressed=True)[0]
        return p2tr(output_pubkey(pub_key)[0])
    return {"p2pkh": p2pkh, "p2wpkh": p2wpkh, "p2sh-p2wpkh": p2wpkh_p2sh}[script_type](
        wif
    )


def _cases(group: str) -> list[dict[str, Any]]:
    """Return the vectors of one group, both files' merged."""
    cases: list[dict[str, Any]] = BASIC.get(group, []) + GENERATED.get(group, [])
    return cases


def _ids(group: str) -> list[str]:
    return [
        vector_id(i, case.get("type"), case.get("description"))
        for i, case in enumerate(_cases(group))
    ]


def test_required_and_upgradeable_rules_are_every_flag_named() -> None:
    """The two flag sets, against the OR of what each lists by name.

    Each is built as one long `|` chain over distinct-bit `ScriptFlag`
    members, seven and five of them respectively: an `&` anywhere in
    that chain collapses everything already accumulated to the left of
    it against a single bit, and nothing before this test called either
    name to notice a REQUIRED_RULES a hundred times smaller than the
    seven flags it names.
    """
    required = ALL_FLAGS
    for flag in (
        ScriptFlag.STRICTENC,
        ScriptFlag.LOW_S,
        ScriptFlag.NULLFAIL,
        ScriptFlag.MINIMALDATA,
        ScriptFlag.CLEANSTACK,
        ScriptFlag.MINIMALIF,
        ScriptFlag.CONST_SCRIPTCODE,
    ):
        required |= flag
    assert required == bip322.REQUIRED_RULES

    upgradeable = (
        ScriptFlag.DISCOURAGE_UPGRADABLE_NOPS
        | ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        | ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
        | ScriptFlag.DISCOURAGE_OP_SUCCESS
        | ScriptFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    )
    assert upgradeable == bip322.UPGRADEABLE_RULES
    # the two sets do not overlap: a required rule failing is invalid, an
    # upgradeable one inconclusive, and a flag in both could not be either
    assert not bip322.REQUIRED_RULES & bip322.UPGRADEABLE_RULES


@pytest.mark.parametrize("case", BASIC["tx_hashes"], ids=_ids("tx_hashes"))
def test_tx_hashes(case: dict[str, str]) -> None:
    """The two virtual transactions are the txids the BIP states.

    Where these agree, everything downstream is anchored: the message
    hash is the tag and the message, `to_spend` is that hash and the
    challenge script, and `to_sign` is `to_spend`'s txid. The third of
    the three messages is non-ASCII down to an astral-plane emoji, which
    is the case a length prefix or a terminator would break.
    """
    msg = case["message"].encode()
    script_pub_key = ScriptPubKey.from_address(case["address"]).script
    spend = bip322.to_spend(msg, script_pub_key)

    assert bip322.message_hash(msg).hex() == case["message_hash"]
    assert spend.id.hex() == case["to_spend_tx_hash"]
    assert bip322.to_sign(spend).id.hex() == case["to_sign_tx_hash"]


@pytest.mark.parametrize("case", _cases("simple"), ids=_ids("simple"))
def test_simple_vector(case: dict[str, Any]) -> None:
    """A witness stack verifies for the address it was made for.

    One of the four carries no prefix at all, which is the compatibility
    case: a verifier reads a prefixless signature as *simple*.
    """
    for signature in case["bip322_signatures"]:
        bip322.assert_as_valid(case["message"].encode(), case["address"], signature)
        assert bip322.verify(case["message"].encode(), case["address"], signature)


@pytest.mark.parametrize("case", _cases("full"), ids=_ids("full"))
def test_full_vector(case: dict[str, Any]) -> None:
    """A whole `to_sign` verifies, time locks and script_sig included.

    Ten script types, each signed with version 2, a lock time and a
    sequence: the fields the simple variant cannot carry, and the p2sh
    and p2sh-p2wsh cases the script_sig it has nowhere to put.
    """
    for signature in case["bip322_signatures"]:
        bip322.assert_as_valid(case["message"].encode(), case["address"], signature)


def _proof_of_funds_params() -> list[Any]:
    """Return the proof-of-funds vectors, named by what they show control of."""
    params = []
    for i, case in enumerate(GENERATED["proof_of_funds"]):
        types = {
            spent["type"] for group in case["additional_inputs"] for spent in group
        }
        params.append(pytest.param(case, id=vector_id(i, case["type"], *sorted(types))))
    return params


@pytest.mark.parametrize("case", _proof_of_funds_params())
def test_proof_of_funds_vector(case: dict[str, Any]) -> None:
    """A finalized psbt verifies, the utxos it shows control of included.

    Two of the three show a p2pkh or p2sh-p2wpkh output, which a psbt
    names with the whole funding transaction rather than with a
    `witness_utxo` -- and the generator wrote those transactions with a
    null tx_id and vout 0, which `OutPoint.assert_valid` refused until
    issue 513. So these two are also the test that the refusal is gone:
    without it they never reach a script at all.
    """
    for signature in case["bip322_signatures"]:
        bip322.assert_as_valid(case["message"].encode(), case["address"], signature)


@pytest.mark.parametrize("case", _cases("error"), ids=_ids("error"))
def test_error_vector(case: dict[str, str]) -> None:
    """Every error vector is refused, and `verify` says so without raising.

    Both exceptions of the parse contract are expected: a truncated
    buffer is a `BTClibRuntimeError` where a value that cannot mean what
    it says is a `BTClibValueError`, and this file is not the place that
    decides which of the two malformed base64 turns into.
    """
    assert not bip322.verify(
        case["message"].encode(), case["address"], case["signature"]
    )
    with pytest.raises((BTClibValueError, BTClibRuntimeError)):
        bip322.assert_as_valid(
            case["message"].encode(), case["address"], case["signature"]
        )


@pytest.mark.parametrize("script_type", ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr"])
@pytest.mark.parametrize("msg", [b"", b"Hello World", "öäüéàè 测试文本 😄".encode()])
def test_sign_and_verify(script_type: str, msg: bytes) -> None:
    """What `sign` writes, `verify` reads: the four single-key types.

    And the three refusals worth having beside it -- another message,
    another address, another signer -- because a verifier that accepts
    everything passes the first assertion too.
    """
    addr = _address(WIF, script_type)
    sig = bip322.sign(msg, WIF, addr)
    assert sig.variant == (
        bip322.SIMPLE if script_type in _NATIVE_SEGWIT else bip322.FULL
    )

    text = sig.b64encode()
    assert bip322.verify(msg, addr, text)
    assert bip322.verify(msg, addr, sig)
    assert not bip322.verify(msg + b"!", addr, text)
    assert not bip322.verify(msg, _address(OTHER_WIF, script_type), text)
    other = _address(OTHER_WIF, script_type)
    assert not bip322.verify(msg, addr, bip322.sign(msg, OTHER_WIF, other))


@pytest.mark.parametrize(
    "case", [c for c in _cases("simple") if c["type"] == "p2wpkh"], ids=str
)
def test_signing_reproduces_the_ecdsa_vectors(case: dict[str, Any]) -> None:
    """Our p2wpkh simple signatures are the vectors', byte for byte.

    RFC6979 makes an ECDSA signature a function of the key and the hash,
    so a construction that agrees with the BIP's reference
    implementation agrees down to the base64. The p2wpkh simple case is
    the only comparable one: p2tr signs with BIP340 auxiliary
    randomness and is a different 64 bytes every time, and every *full*
    vector sets a version and a lock time that `sign` does not.
    """
    sig = bip322.sign(
        case["message"].encode(), case["private_keys"][0], case["address"]
    )
    assert sig.b64encode() in case["bip322_signatures"]


def test_sign_refuses_an_address_the_key_does_not_own() -> None:
    """A key that does not open the address is refused before it signs."""
    for script_type in ("p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr"):
        with pytest.raises(BTClibValueError, match="mismatch between private key"):
            bip322.sign(b"", OTHER_WIF, _address(WIF, script_type))


def test_sign_refuses_a_script_no_single_key_satisfies() -> None:
    """p2wsh is not one of the four, and says so rather than signing."""
    script = serialize(
        ["OP_1", pub_keyinfo_from_key(WIF)[0], "OP_1", "OP_CHECKMULTISIG"]
    )
    with pytest.raises(BTClibValueError, match="mismatch between private key"):
        bip322.sign(b"", WIF, p2wsh(script))


def test_sign_refuses_an_uncompressed_key_for_segwit() -> None:
    """An uncompressed key owns a p2pkh address and no other.

    Segwit has no uncompressed spelling, so the three other types are a
    mismatch rather than a signature nobody can verify.
    """
    wif = wif_from_prv_key(
        prv_keyinfo_from_prv_key(WIF)[0], "mainnet", compressed=False
    )
    assert bip322.verify(b"", p2pkh(wif), bip322.sign(b"", wif, p2pkh(wif)))
    for script_type in ("p2wpkh", "p2sh-p2wpkh", "p2tr"):
        with pytest.raises(BTClibValueError, match="mismatch between private key"):
            bip322.sign(b"", wif, _address(WIF, script_type))


def test_multisig_is_signed_through_the_witness_it_needs() -> None:
    """The documented route for a script `sign` does not cover.

    A 2-of-2 p2wsh: the hash is `sig_hash.segwit_v0` over the witness
    script, each key signs it, and the stack -- BIP147's empty dummy,
    the signatures in script order, the witness script -- is a `Sig` of
    the simple variant. Which is the shape the vectors verify, arrived
    at from the other side.
    """
    keys = [pub_keyinfo_from_key(wif, compressed=True)[0] for wif in (WIF, OTHER_WIF)]
    witness_script = serialize(["OP_2", *keys, "OP_2", "OP_CHECKMULTISIG"])
    addr = p2wsh(witness_script)
    msg = b"two keys, one message"

    spend = bip322.to_spend(msg, ScriptPubKey.from_address(addr).script)
    tx = bip322.to_sign(spend)
    msg_hash = segwit_v0(witness_script, tx, 0, ALL, 0)
    signatures = [
        dsa_sign(msg_hash, wif)
        for wif in (WIF, OTHER_WIF)  # script order
    ]
    sig = bip322.Sig(Witness([b"", *signatures, witness_script]))

    assert sig.variant == bip322.SIMPLE
    assert bip322.verify(msg, addr, sig.b64encode())
    assert not bip322.verify(msg, addr, bip322.Sig(Witness([b"", *signatures])))


def dsa_sign(msg_hash: bytes, wif: str) -> bytes:
    """Return the DER signature of the hash, SIGHASH_ALL appended."""
    q = prv_keyinfo_from_prv_key(wif)[0]
    return dsa.sign_(msg_hash, q).serialize() + ALL.to_bytes(1, "big")


def test_legacy_signature_is_accepted_for_p2pkh_alone() -> None:
    """BMS is BIP322's legacy variant, and only for the address it names.

    btclib's own BMS accepts a compressed p2pkh signature for the two
    p2wpkh spellings, which is Electrum's extension; BIP322 restricts
    the legacy variant to p2pkh, so a segwit address is refused here
    whatever `ecc.bms` would say of it.
    """
    msg = b"legacy"
    legacy = bms.sign(msg, WIF).b64encode()
    assert bms.verify(msg, p2wpkh(WIF), legacy)

    assert bip322.verify(msg, p2pkh(WIF), legacy)
    assert not bip322.verify(msg, p2wpkh(WIF), legacy)
    assert not bip322.verify(msg, p2pkh(WIF), legacy, legacy=False)
    assert not bip322.verify(b"another", p2pkh(WIF), legacy)

    # assert_as_valid's own legacy default, not verify's: verify always
    # forwards its own `legacy` argument explicitly, so nothing above
    # reaches assert_as_valid's default unless called directly
    bip322.assert_as_valid(msg, p2pkh(WIF), legacy)


def test_a_simple_signature_is_not_65_octets() -> None:
    """The size that tells a BMS signature from a witness stack.

    The shortest witness stack is a lone BIP340 signature: one element,
    a 64-byte push, 66 octets with the count and the length. So nothing
    a BIP322 signature encodes is 65 octets long, which is what makes
    the prefixless case decidable.
    """
    addr = _address(WIF, "p2tr")
    shortest = bip322.sign(b"", WIF, addr)
    assert len(shortest.serialize()) == 66


def test_sig_round_trip() -> None:
    """Each variant survives b64encode and b64decode, and keeps its name."""
    msg = b"round trip"
    for script_type, variant in (("p2wpkh", bip322.SIMPLE), ("p2pkh", bip322.FULL)):
        sig = bip322.sign(msg, WIF, _address(WIF, script_type))
        text = sig.b64encode()
        assert text[:3] == variant
        assert bip322.Sig.b64decode(text) == sig
        assert bip322.Sig.b64decode(text.encode("ascii")) == sig
        assert bip322.Sig.b64decode(f"  {text}  ") == sig

    psbt_sig = bip322.Sig(Psbt.from_tx(bip322.to_sign(bip322.to_spend(msg, b"\x6a"))))
    assert psbt_sig.variant == bip322.PROOF_OF_FUNDS
    assert bip322.Sig.b64decode(psbt_sig.b64encode()) == psbt_sig


def test_sig_is_frozen_and_check_validity_defaults_to_true() -> None:
    """The one field is frozen, and serialize/b64encode/b64decode refuse.

    A `Tx` payload built with `check_validity=False` is the same kind of
    invalid object the other profiles' `Sig`-like classes use to pin this
    default: nothing before this test assigned to `Sig.payload`, and
    nothing called any of the three at their default check_validity
    instead of passing the keyword explicitly.
    """
    msg, addr = b"frozen", _address(WIF, "p2pkh")
    sig = bip322.sign(msg, WIF, addr)
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.payload = sig.payload  # type: ignore[misc]

    invalid_tx = Tx(1, 0, [], [], check_validity=False)
    invalid = bip322.Sig(invalid_tx)
    with pytest.raises(BTClibValueError):
        invalid.serialize()
    invalid.serialize(check_validity=False)
    with pytest.raises(BTClibValueError):
        invalid.b64encode()
    invalid.b64encode(check_validity=False)
    data = invalid.serialize(check_validity=False)
    with pytest.raises(BTClibValueError):
        bip322.Sig.b64decode(bip322.FULL + base64.b64encode(data).decode("ascii"))
    bip322.Sig.b64decode(
        bip322.FULL + base64.b64encode(data).decode("ascii"), check_validity=False
    )


def test_b64decode_refuses_what_is_not_base64() -> None:
    """A prefix is stripped, a bad encoding is named, and nothing is guessed."""
    with pytest.raises(BTClibValueError, match="invalid base64 encoding"):
        bip322.Sig.b64decode("smp not base64 at all")
    with pytest.raises(BTClibValueError, match="invalid base64 encoding"):
        bip322.Sig.b64decode("full!!!!")
    with pytest.raises(BTClibValueError, match="invalid base64 encoding"):
        bip322.Sig.b64decode("pof☃")

    # a character outside the base64 alphabet embedded in an otherwise
    # decodable string, not one that breaks decoding outright: `!!!!`
    # and `☃` above fail regardless of `validate`, where a stray
    # newline is stripped and silently decoded under `validate=False`
    # and is what `validate=True` is actually for
    sig = bip322.sign(b"x", WIF, _address(WIF, "p2pkh"))
    text = sig.b64encode()
    smuggled = text[:10] + "\n" + text[10:]
    with pytest.raises(BTClibValueError, match="invalid base64 encoding"):
        bip322.Sig.b64decode(smuggled)


def test_is_bms_is_the_exact_65_octets_and_nothing_shorter() -> None:
    """A legacy-looking signature is 65 octets exactly, not merely no more.

    `_is_bms` only sniffs the size to route `assert_as_valid`'s `legacy`
    branch; whichever way it decides, a real check waits downstream.
    But the two downstream checks are not the same one: a base64 blob
    that decodes to fewer than 65 octets is short for `Witness.parse`
    (BIP322, `_is_bms` correctly says no) in one wrong way, and short
    for `bms.Sig.parse` (`_is_bms` wrongly saying yes) in another --
    which is what tells a weakened `<=` apart from `==` here.
    """
    addr = _address(WIF, "p2pkh")
    short = base64.b64encode(b"x" * 40).decode()
    with pytest.raises(BTClibRuntimeError, match="not enough binary data"):
        bip322.assert_as_valid(b"hello", addr, short, legacy=True)


def _to_sign_of(msg: bytes, addr: str, **kwargs: Any) -> tuple[Tx, Tx]:
    """Return (to_spend, to_sign) for an address, the keywords passed on."""
    spend = bip322.to_spend(msg, ScriptPubKey.from_address(addr).script)
    return spend, bip322.to_sign(spend, **kwargs)


def test_shape_of_to_sign_is_checked() -> None:
    """Every field BIP322 fixes is a refusal when it is something else."""
    msg, addr = b"shape", _address(WIF, "p2wpkh")
    signed = bip322.sign(msg, WIF, addr)
    spend, tx = _to_sign_of(msg, addr, witness=signed.payload)

    other = bip322.to_spend(b"other", ScriptPubKey.from_address(addr).script)
    tx.vin[0].prev_out = OutPoint(other.id, 0)
    with pytest.raises(BTClibValueError, match="does not spend to_spend"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    _, tx = _to_sign_of(msg, addr, witness=signed.payload)
    tx.vout.append(TxOut(0, b"\x6a"))
    with pytest.raises(BTClibValueError, match="outputs in to_sign"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    _, tx = _to_sign_of(msg, addr, witness=signed.payload)
    tx.vout[0] = TxOut(1, b"\x6a")
    with pytest.raises(BTClibValueError, match="not the OP_RETURN"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    _, tx = _to_sign_of(msg, addr, witness=signed.payload)
    tx.vin.append(TxIn(OutPoint(spend.id, 0), b"", 0))
    with pytest.raises(BTClibValueError, match="utxos for"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    _, tx = _to_sign_of(msg, addr, witness=signed.payload)
    tx.vin.clear()
    with pytest.raises(BTClibValueError, match="no input in to_sign"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    # zero outputs, not only two: `len(tx.vout) != 1` weakened to `> 1`
    # would let a to_sign with none at all through this check, past the
    # `tx.vout[0]` right after it that a real answer never reaches empty
    spend, tx = _to_sign_of(msg, addr, witness=signed.payload)
    tx.vout.clear()
    with pytest.raises(BTClibValueError, match="outputs in to_sign"):
        bip322._assert_shape(tx, spend, list(spend.vout))

    # a script that is not the OP_RETURN, sorting below it and above it:
    # `!= _OP_RETURN` weakened to `<` or to `>` each miss the direction
    # the vector above does not move in ("\x6a" itself, an equal script
    # excluded by the `.value` check next to it instead)
    for wrong_script in (b"\x00", b"\xff"):
        _, tx = _to_sign_of(msg, addr, witness=signed.payload)
        tx.vout[0] = TxOut(0, wrong_script)
        with pytest.raises(BTClibValueError, match="not the OP_RETURN"):
            bip322.assert_as_valid(msg, addr, bip322.Sig(tx))

    # more utxos than inputs, not only fewer: `!= len(tx.vin)` weakened
    # to `< len(tx.vin)` would accept the extra one silently
    spend, tx = _to_sign_of(msg, addr, witness=signed.payload)
    with pytest.raises(BTClibValueError, match="utxos for"):
        bip322._assert_shape(tx, spend, list(spend.vout) * 2)

    # the error message names the first input, which a second one on
    # the same tx tells apart from the last: `tx.vin[0]` weakened to
    # `tx.vin[-1]` in the f-string alone still raises on the same
    # condition, and only the wrong hex in the message gives it away
    spend, tx = _to_sign_of(msg, addr, witness=signed.payload)
    other_id = bytes(range(32))
    tx.vin[0].prev_out = OutPoint(other_id, 0)
    tx.vin.append(TxIn(OutPoint(spend.id, 0), b"", 0))
    with pytest.raises(BTClibValueError, match=other_id.hex()):
        bip322._assert_shape(tx, spend, [spend.vout[0], spend.vout[0]])


def test_a_version_that_is_not_0_or_2_is_inconclusive() -> None:
    """BIP322's upgradeable rules are a third state, not a refusal.

    The version is the one of them a signature can carry without a
    script to go with it, and it is `InconclusiveError` rather than the
    `BTClibValueError` an invalid signature is -- while `verify` answers
    False for both, an inconclusive signature not being a valid one.
    """
    msg, addr = b"version", _address(WIF, "p2wpkh")
    signed = bip322.sign(msg, WIF, addr)
    _, tx = _to_sign_of(msg, addr, witness=signed.payload, version=1)

    with pytest.raises(InconclusiveError, match="BIP322 allows 0 and 2"):
        bip322.assert_as_valid(msg, addr, bip322.Sig(tx))
    assert not bip322.verify(msg, addr, bip322.Sig(tx))


def test_an_unknown_witness_version_is_inconclusive() -> None:
    """A segwit v2 output is anyone-can-spend, and no proof of anything.

    Which is the second half of the same state: the script *succeeds*,
    the engine's required rules are satisfied, and it is the
    upgradeable rules that refuse it -- so the answer is inconclusive
    and not invalid.
    """
    msg = b"from the future"
    script_pub_key = b"\x52\x14" + hash160(b"whatever")
    addr = address(script_pub_key)
    spend = bip322.to_spend(msg, script_pub_key)
    sig = bip322.Sig(bip322.to_sign(spend, witness=Witness([b"\x01"])))

    with pytest.raises(InconclusiveError, match="upgradeable rule"):
        bip322.assert_as_valid(msg, addr, sig)
    assert not bip322.verify(msg, addr, sig)


def test_proof_of_funds_reuses_an_earlier_non_witness_utxo() -> None:
    """BIP322's optimization: one funding transaction, many inputs of it.

    "the Non-Witness UTXO field may be omitted for any input that spends
    an output from the same transaction as an input earlier in the
    list", which `psbt.prevouts` does not do and this module has to.
    """
    funding = Tx(
        2,
        0,
        [TxIn(OutPoint("00" * 31 + "01", 0), b"", 0xFFFFFFFF)],
        [TxOut(1000, ScriptPubKey.from_address(p2pkh(WIF)).script)] * 2,
    )
    msg, addr = b"pof", _address(WIF, "p2wpkh")
    spend = bip322.to_spend(msg, ScriptPubKey.from_address(addr).script)
    extra = [
        TxIn(OutPoint(funding.id, i), b"", 0xFFFFFFFF) for i in range(len(funding.vout))
    ]
    psbt = Psbt.from_tx(bip322.to_sign(spend, extra_inputs=extra))
    psbt.inputs[0].witness_utxo = spend.vout[0]
    # the first of the two inputs of `funding` carries it, the second not
    psbt.inputs[1].non_witness_utxo = funding

    outs = bip322._psbt_prevouts(psbt)
    assert outs[1] == outs[2] == funding.vout[0]

    psbt.inputs[1].non_witness_utxo = None
    with pytest.raises(BTClibValueError, match="no utxo for input 1"):
        bip322._psbt_prevouts(psbt)

    # the referenced transaction is there, but its vout is not: `vout <
    # len(prev_tx.vout)` weakened to `<=` needs the boundary itself,
    # weakened to `!=` needs one past it -- `<=` still refuses that one
    psbt.inputs[1].non_witness_utxo = funding
    for out_of_range in (len(funding.vout), len(funding.vout) + 1):
        psbt.inputs[1].output_index = out_of_range
        with pytest.raises(BTClibValueError, match="no utxo for input 1"):
            bip322._psbt_prevouts(psbt)
