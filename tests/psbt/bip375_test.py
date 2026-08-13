# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for BIP375's silent payment fields of a psbt.

The vectors are BIP375's own `bip375_test_vectors.json`, vendored whole
under `tests/psbt/_data/`; `tests/_data/README.md` pins the revision.
What is under test is the codec: the six fields BIP375 adds, what each of
them may hold, and that a psbt carrying them survives a parse and a
serialization with every key-value pair of every map intact.

**Why not a byte-for-byte comparison**, which is what every other psbt
vector file here is held to: the generator that produced this one writes
the keys of a map in an order of its own -- PSBT_GLOBAL_VERSION first
where BIP370's psbts put it last, and the outpoint fields of an input map
ahead of the rest -- and a psbt map has no normative order, BIP174
requiring only that a key not repeat. So the comparison is at the level
the format defines: the map read out of upstream's bytes and the map read
out of btclib's are the same set of pairs, and btclib's own serialization
is stable under a second parse.

**What a codec answers and what it does not.** Five of BIP375's six
"PSBT Structure" invalid vectors are field-shape rules and each is
refused here. The sixth is not: "PSBT_GLOBAL_TX_MODIFIABLE field is
non-zero when PSBT_OUT_SCRIPT set for sp output" is an obligation on the
Signer that computed that script, not a statement about a field's
contents. Nor are the other sixteen invalid vectors -- ECDH coverage,
input eligibility and output script derivation are the Signer's and the
Transaction Extractor's roles, which BIP375 adds and this change does
not: they need each input's public key, which for an unsigned input comes
from PSBT_IN_BIP32_DERIVATION rather than from the input itself.
`btclib.ecc.dleq.verify_proof` and `btclib.silent_payments.output_keys`
are the two pieces such a role would be built from, and both are here.
"""

from __future__ import annotations

import base64
import io
from copy import deepcopy
from typing import Any

import pytest

from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt, combine
from btclib.psbt.psbt import PSBT_MAGIC_BYTES
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import deserialize_map
from tests import load, vector_id

_VECTORS = load("psbt", "_data", "bip375_test_vectors.json", encoding="utf-8")

# the five invalid vectors that are a field's shape rather than a role's
# obligation, keyed on the description because the file's order is not a
# contract, and each with the message btclib refuses it with
_REFUSED = {
    "psbt structure: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set": (
        "PSBT_OUT_SP_V0_LABEL without PSBT_OUT_SP_V0_INFO"
    ),
    "psbt structure: incorrect byte length for PSBT_OUT_SP_V0_INFO field": (
        "invalid silent payment info length"
    ),
    "psbt structure: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field": (
        "invalid silent payment input ecdh share length"
    ),
    "psbt structure: incorrect byte length for PSBT_IN_SP_DLEQ field": (
        "invalid silent payment input dleq proof length"
    ),
    "psbt structure: missing PSBT_OUT_SCRIPT field when sending to non-sp output": (
        "missing PSBT_OUT_SCRIPT"
    ),
}


def _params(group: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Return one parametrized case per vector of a group."""
    vectors = _VECTORS[group]
    ids = [
        vector_id(index, vector["description"]) for index, vector in enumerate(vectors)
    ]
    return vectors, ids


_VALID, _VALID_IDS = _params("valid")
_INVALID, _INVALID_IDS = _params("invalid")


def _maps(psbt_bin: bytes) -> list[dict[bytes, bytes]]:
    """Read a psbt as the maps it is, without interpreting a single one.

    Which is what makes the comparison below a comparison of content and
    not of layout: two serializations of one psbt hold the same pairs, in
    whatever order each wrote them.
    """
    stream = io.BytesIO(psbt_bin)
    assert stream.read(len(PSBT_MAGIC_BYTES)) == PSBT_MAGIC_BYTES
    read = [deserialize_map(stream)]
    while stream.tell() < len(psbt_bin):
        read.append(deserialize_map(stream))
    return read


def _round_trip(psbt_b64: str) -> Psbt:
    """Parse a vector, and hold the serialization to what it parsed."""
    psbt = Psbt.b64decode(psbt_b64)
    serialized = psbt.serialize()
    assert _maps(base64.b64decode(psbt_b64)) == _maps(serialized)
    # and btclib's own bytes are stable: a psbt read back from them is
    # this psbt, and writing it again gives the same bytes
    reparsed = Psbt.parse(serialized)
    assert reparsed == psbt
    assert reparsed.serialize() == serialized
    return psbt


@pytest.mark.parametrize("vector", _VALID, ids=_VALID_IDS)
def test_valid_vectors_round_trip(vector: dict[str, Any]) -> None:
    """Every valid vector parses, and nothing of it is lost on the way."""
    psbt = _round_trip(vector["psbt"])
    # every one of them is a version 2 psbt, BIP375 excluding its fields
    # from version 0, and every one of them pays at least one silent
    # payment address -- which is what makes the file BIP375's
    assert psbt.version == 2
    assert any(psbt_out.sp_v0_info for psbt_out in psbt.outputs)


@pytest.mark.parametrize("vector", _INVALID, ids=_INVALID_IDS)
def test_invalid_vectors(vector: dict[str, Any]) -> None:
    """The field-shape rules are refused; the role rules are not.

    A vector this codec accepts is not a vector it disagrees with: BIP375
    calls it invalid for a reason a Signer or a Transaction Extractor
    answers, and the module docstring says which. What the assertion below
    holds is that such a psbt still parses and round-trips, so the role
    that will refuse it has something to read.
    """
    expected = _REFUSED.get(vector["description"])
    if expected is None:
        _round_trip(vector["psbt"])
        return
    with pytest.raises(BTClibValueError, match=expected):
        Psbt.b64decode(vector["psbt"])


def _first_sp_output(psbt: Psbt) -> PsbtOut:
    """Return the first output that pays a silent payment address."""
    return next(out for out in psbt.outputs if out.sp_v0_info)


def test_the_fields_hold_what_the_vectors_carry() -> None:
    """Every BIP375 field is read into the shape it is defined as.

    The vector file publishes no expected values for them -- what it
    publishes is the psbt -- so what pins them is where each value came
    out of: the raw map entry, read by `_maps` without any of the parsing
    under test.
    """
    for vector in _VECTORS["valid"]:
        psbt = Psbt.b64decode(vector["psbt"])
        maps = _maps(base64.b64decode(vector["psbt"]))
        global_map, rest = maps[0], maps[1:]
        input_maps = rest[: len(psbt.inputs)]
        output_maps = rest[len(psbt.inputs) :]

        for type_byte, field in (
            (b"\x07", "sp_ecdh_shares"),
            (b"\x08", "sp_dleq_proofs"),
        ):
            raw = {k[1:]: v for k, v in global_map.items() if k[:1] == type_byte}
            assert getattr(psbt, field) == raw

        for psbt_in, input_map in zip(psbt.inputs, input_maps, strict=True):
            for type_byte, field in (
                (b"\x1d", "sp_ecdh_shares"),
                (b"\x1e", "sp_dleq_proofs"),
            ):
                raw = {k[1:]: v for k, v in input_map.items() if k[:1] == type_byte}
                assert getattr(psbt_in, field) == raw

        for psbt_out, output_map in zip(psbt.outputs, output_maps, strict=True):
            assert psbt_out.sp_v0_info == output_map.get(b"\x09", b"")
            label = output_map.get(b"\x0a")
            expected = None if label is None else int.from_bytes(label, "little")
            assert psbt_out.sp_v0_label == expected


def test_the_shares_and_the_proofs_are_keyed_by_scan_key() -> None:
    """Every key of the four ECDH fields is a compressed point.

    And the same point on both sides of a pair: a share and the proof of
    that share are filed under one scan key, which is what lets a verifier
    find the proof for a share it wants to check. Not asserted as a rule
    -- BIP375 states none, and a psbt carrying a share whose proof has not
    arrived yet is one of its own valid vectors -- but measured, because a
    codec that lost the key data would pass every other test here.
    """
    seen = 0
    for vector in _VECTORS["valid"]:
        psbt = Psbt.b64decode(vector["psbt"])
        for shares, proofs in [
            (psbt.sp_ecdh_shares, psbt.sp_dleq_proofs),
            *[(i.sp_ecdh_shares, i.sp_dleq_proofs) for i in psbt.inputs],
        ]:
            assert set(proofs) <= set(shares)
            for scan_key, share in shares.items():
                assert len(scan_key) == 33
                assert scan_key[0] in (2, 3)
                assert len(share) == 33
                seen += 1
            for proof in proofs.values():
                assert len(proof) == 64
    # the file is what it is about, so a filter that matched nothing would
    # leave every assertion above unrun
    assert seen


def test_a_silent_payment_output_needs_no_script_yet() -> None:
    """BIP370 requires PSBT_OUT_SCRIPT; BIP375 makes it wait.

    A silent payment output script depends on every eligible input, so it
    does not exist while inputs may still be added -- which is the whole
    reason BIP375 exists. An output with neither field is the missing
    script BIP370 refuses, and an output with only the info field is a
    payment whose script is still to come.
    """
    in_progress = next(
        vector
        for vector in _VECTORS["valid"]
        if vector["description"].startswith(
            "in progress: one P2TR input / one sp output"
        )
    )
    psbt = Psbt.b64decode(in_progress["psbt"])
    psbt_out = _first_sp_output(psbt)
    assert not psbt_out.script_pub_key
    assert psbt_out.sp_v0_info

    # and the same output with the info field dropped is the psbt BIP370
    # refuses, which is what says the exemption is the info field's and
    # not a relaxation of the rule
    damaged = deepcopy(psbt)
    _first_sp_output(damaged).sp_v0_info = b""
    with pytest.raises(BTClibValueError, match="missing PSBT_OUT_SCRIPT"):
        damaged.assert_valid()


def test_the_identifier_reads_the_address_and_not_the_script() -> None:
    """BIP375's "Unique Identification", and what it is there to prevent.

    The same psbt is valid before and after a Signer computes a silent
    payment output script, so an identifier built from the script would
    call one psbt two -- and a Combiner comparing identifiers would refuse
    to merge the two halves of one signing session.
    """
    vector = next(
        v
        for v in _VECTORS["valid"]
        if v["description"].startswith("in progress: one P2TR input / one sp output")
    )
    psbt = Psbt.b64decode(vector["psbt"])
    identifier = psbt.unique_id

    computed = deepcopy(psbt)
    _first_sp_output(computed).script_pub_key = b"\x51\x20" + b"\x11" * 32
    computed.assert_valid()
    assert computed.unique_id == identifier
    # and the transaction it builds does read the script, the identifier
    # being the one place the substitution happens
    assert computed.tx != psbt.tx

    # the substitution is the version byte and the two keys, so an output
    # paying a different address is a different psbt
    other = deepcopy(psbt)
    info = bytearray(_first_sp_output(other).sp_v0_info)
    info[1] ^= 1
    _first_sp_output(other).sp_v0_info = bytes(info)
    assert other.unique_id != identifier


def test_the_combiner_merges_the_shares_of_two_signers() -> None:
    """One Signer per input key is what BIP375 expects of a coinjoin.

    Each writes the share and the proof for the inputs it holds the keys
    of, so the shares of a transaction arrive in as many psbts as there
    are signers and a Combiner has to take the union. The two halves are
    split out of one vector here, which is what makes them psbts of one
    transaction -- the identifier the Combiner compares.
    """
    vector = next(
        v
        for v in _VECTORS["valid"]
        if v["description"].startswith(
            "can finalize: two inputs single-signer using per"
        )
    )
    whole = Psbt.b64decode(vector["psbt"])
    assert all(psbt_in.sp_ecdh_shares for psbt_in in whole.inputs)

    first, second = deepcopy(whole), deepcopy(whole)
    first.inputs[1].sp_ecdh_shares = {}
    first.inputs[1].sp_dleq_proofs = {}
    second.inputs[0].sp_ecdh_shares = {}
    second.inputs[0].sp_dleq_proofs = {}
    assert first.unique_id == second.unique_id

    merged = combine([first, second])
    assert merged.inputs[0].sp_ecdh_shares == whole.inputs[0].sp_ecdh_shares
    assert merged.inputs[1].sp_ecdh_shares == whole.inputs[1].sp_ecdh_shares
    assert merged.inputs[0].sp_dleq_proofs == whole.inputs[0].sp_dleq_proofs
    assert merged.inputs[1].sp_dleq_proofs == whole.inputs[1].sp_dleq_proofs
    assert merged.serialize() == whole.serialize()


def test_the_combiner_merges_a_global_share() -> None:
    """The global pair survives a combine as the per-input one does.

    The output fields are not merged the same way and cannot be tested the
    same way, which is worth stating: the address is a Constructor's, so
    every copy of the psbt carries it, and a copy that did not would have
    a different identifier -- BIP375's substitution reads that very field.
    A Combiner would refuse such a pair as two transactions before it
    merged anything, which is why the rule for those fields is
    take-it-if-absent rather than union.
    """
    vector = next(
        v
        for v in _VECTORS["valid"]
        if v["description"].startswith(
            "can finalize: two inputs single-signer using glo"
        )
    )
    whole = Psbt.b64decode(vector["psbt"])
    assert whole.sp_ecdh_shares

    stripped = deepcopy(whole)
    stripped.sp_ecdh_shares = {}
    stripped.sp_dleq_proofs = {}
    assert stripped.unique_id == whole.unique_id

    merged = combine([stripped, whole])
    assert merged.sp_ecdh_shares == whole.sp_ecdh_shares
    assert merged.sp_dleq_proofs == whole.sp_dleq_proofs
    assert merged.serialize() == whole.serialize()


def test_a_label_of_zero_survives_the_serialization() -> None:
    """0 is the change label, so it is the one that must not read as absent.

    BIP352 reserves m = 0 for the outputs a wallet pays to itself and asks
    a scanner to check it always, which makes an output labelled 0 the
    most likely one to carry the field -- and truthiness would drop it.
    """
    vector = next(
        v for v in _VECTORS["valid"] if "label=0 convention" in v["description"]
    )
    psbt = Psbt.b64decode(vector["psbt"])
    assert 0 in [out.sp_v0_label for out in psbt.outputs]
    assert Psbt.parse(psbt.serialize()) == psbt


# a scan key and a spend key, and 33 octets that are neither
_SCAN_KEY = bytes.fromhex(
    "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
)
_SPEND_KEY = bytes.fromhex(
    "03eca4ff11b728e2e0f60ce6222943a6ff55b9d95f627bf9a99d084bc872d50a5b"
)
_NOT_A_POINT = b"\x02" + bytes(32)


def _v0_psbt(vector_prefix: str = "can finalize: one P2PKH input") -> Psbt:
    """Return a version 0 psbt of a BIP375 vector, its fields dropped.

    The conversion is what makes the psbt a version 0 one and the drop is
    what lets it convert at all -- `to_v0` runs `assert_valid`, which is
    the check under test below, so the fields go back on afterwards.
    """
    vector = next(
        v for v in _VECTORS["valid"] if v["description"].startswith(vector_prefix)
    )
    psbt = Psbt.b64decode(vector["psbt"])
    psbt.sp_ecdh_shares = {}
    psbt.sp_dleq_proofs = {}
    for psbt_in in psbt.inputs:
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    for psbt_out in psbt.outputs:
        psbt_out.sp_v0_info = b""
        psbt_out.sp_v0_label = None
    return psbt.to_v0()


def test_no_bip375_field_is_allowed_in_a_v0_psbt() -> None:
    """Version 0 excludes all six, which is BIP375's own table.

    Refused on the way in by the type byte, and refused here as well: a
    psbt *built* with one of these fields and then declared version 0
    would otherwise serialize into bytes this library cannot read back.
    A silent payment output has no script until the inputs are fixed, and
    version 0 has no field to write one into once they are.
    """
    psbt = _v0_psbt()
    assert psbt.version == 0

    for name, mutate in (
        (
            "PSBT_GLOBAL_SP_ECDH_SHARE",
            lambda p: p.sp_ecdh_shares.update({_SCAN_KEY: _SPEND_KEY}),
        ),
        (
            "PSBT_GLOBAL_SP_DLEQ",
            lambda p: p.sp_dleq_proofs.update({_SCAN_KEY: b"\x01" * 64}),
        ),
        (
            "PSBT_IN_SP_ECDH_SHARE",
            lambda p: p.inputs[0].sp_ecdh_shares.update({_SCAN_KEY: _SPEND_KEY}),
        ),
        (
            "PSBT_IN_SP_DLEQ",
            lambda p: p.inputs[0].sp_dleq_proofs.update({_SCAN_KEY: b"\x01" * 64}),
        ),
        (
            "PSBT_OUT_SP_V0_INFO",
            lambda p: setattr(p.outputs[0], "sp_v0_info", _SCAN_KEY + _SPEND_KEY),
        ),
    ):
        damaged = deepcopy(psbt)
        mutate(damaged)
        with pytest.raises(BTClibValueError, match=f"{name} is not allowed in a v0"):
            damaged.assert_valid()

    # the label is the sixth, and it is refused on its own account: an
    # output carrying it alone is refused for the version and not for the
    # missing info field, the version being the first question asked
    damaged = deepcopy(psbt)
    damaged.outputs[0].sp_v0_label = 0
    with pytest.raises(BTClibValueError, match="PSBT_OUT_SP_V0_LABEL is not allowed"):
        damaged.assert_valid()
    # and with both, the info field is the one named -- which is the order
    # the two checks are written in and nothing more
    damaged.outputs[0].sp_v0_info = _SCAN_KEY + _SPEND_KEY
    with pytest.raises(BTClibValueError, match="PSBT_OUT_SP_V0_INFO is not allowed"):
        damaged.assert_valid()


def test_a_v2_psbt_paying_a_silent_payment_address_has_no_v0_form() -> None:
    """`to_v0` drops what version 0 cannot say, and this is not that.

    The lock times and the modifiable flags go because the transaction
    they describe survives the dropping. A silent payment address does
    not: dropping it would hand back a psbt that pays a taproot output
    nobody could explain, and dropping it *before* the script exists
    would hand back a psbt with no output script at all.
    """
    vector = next(
        v for v in _VECTORS["valid"] if v["description"].startswith("can finalize:")
    )
    psbt = Psbt.b64decode(vector["psbt"])
    with pytest.raises(BTClibValueError, match="is not allowed in a v0 psbt"):
        psbt.to_v0()


def test_a_label_is_a_32_bit_unsigned_integer() -> None:
    """The field is set32 of the label, little-endian on the wire."""
    for label in (-1, 2**32):
        with pytest.raises(BTClibValueError, match="invalid silent payment label"):
            PsbtOut(
                amount=1,
                script_pub_key=b"\x51\x20" + b"\x11" * 32,
                sp_v0_info=_SCAN_KEY + _SPEND_KEY,
                sp_v0_label=label,
            )
    # and both ends of the range are labels
    for label in (0, 2**32 - 1):
        psbt_out = PsbtOut(
            amount=1,
            script_pub_key=b"\x51\x20" + b"\x11" * 32,
            sp_v0_info=_SCAN_KEY + _SPEND_KEY,
            sp_v0_label=label,
        )
        assert PsbtOut.parse(psbt_out.serialize(psbt_version=2), psbt_version=2) == (
            psbt_out
        )


def test_every_key_of_every_bip375_field_is_a_point() -> None:
    """33 octets are not a public key, and a scan key has to be one.

    A share filed under 33 octets that are no point names a recipient no
    address ever published, so the ECDH the value claims to be could not
    have been computed against it; the same of an output's two keys, which
    are what a Signer derives the script from.
    """
    script = b"\x51\x20" + b"\x11" * 32
    with pytest.raises(BTClibValueError, match="silent payment scan key"):
        PsbtOut(amount=1, script_pub_key=script, sp_v0_info=_NOT_A_POINT + _SPEND_KEY)
    with pytest.raises(BTClibValueError, match="silent payment spend key"):
        PsbtOut(amount=1, script_pub_key=script, sp_v0_info=_SCAN_KEY + _NOT_A_POINT)

    psbt = _v0_psbt().to_v2()
    for field in ("sp_ecdh_shares", "sp_dleq_proofs"):
        for holder in (psbt, psbt.inputs[0]):
            damaged = deepcopy(psbt)
            target = damaged if holder is psbt else damaged.inputs[0]
            size = 33 if field == "sp_ecdh_shares" else 64
            getattr(target, field)[_NOT_A_POINT] = b"\x01" * size
            with pytest.raises(BTClibValueError, match="scan key"):
                damaged.assert_valid()
