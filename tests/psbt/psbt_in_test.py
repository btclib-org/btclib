# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.psbt_in` module."""

from dataclasses import FrozenInstanceError, fields
from io import BytesIO
from typing import Any, get_args

import pytest

from btclib.alias import ValidSigHashType
from btclib.bip32 import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt, PsbtIn
from btclib.psbt.psbt_in import (
    _DROPPED_ONCE_FINALIZED,
    _KEY_DATA_FIELDS,
    _SERIALIZED_FIELDS,
    _WHOLE_VALUE_FIELDS,
)
from btclib.psbt.psbt_utils import PSBT_SEPARATOR
from btclib.script import Witness
from btclib.script.sig_hash import SIG_HASH_TYPES
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.conftest import JsonGolden


def test_psbt_out() -> None:
    """Check an empty PsbtIn is its separator byte, and round-trips."""
    psbt_in = PsbtIn()
    # an input carries its own terminator, so an empty one is that byte
    # and nothing else, and serialize and parse are inverses
    assert psbt_in.serialize() == PSBT_SEPARATOR
    assert psbt_in == PsbtIn.parse(psbt_in.serialize())
    assert psbt_in == PsbtIn.from_dict(psbt_in.to_dict())


def test_parse_reads_one_input_from_the_stream() -> None:
    """Inputs come one after another, with no count in front of them.

    So each has to end itself and be read to its end, which is what lets
    Psbt.parse loop over them the way Bitcoin Core does -- `s >> input`,
    once per input of the unsigned transaction.
    """
    psbt_in = PsbtIn(redeem_script=b"\x51")
    stream = BytesIO(psbt_in.serialize() + PsbtIn().serialize() + b"the outputs")
    assert PsbtIn.parse(stream) == psbt_in
    assert PsbtIn.parse(stream) == PsbtIn()
    assert stream.read() == b"the outputs"


def test_the_sig_hash_type_is_four_octets_and_no_other_number_of_them() -> None:
    """BIP174 calls PSBT_IN_SIGHASH_TYPE a 32-bit unsigned integer.

    The width is the field, and read without it a one-octet `01` is the
    same SIGHASH_ALL that serializes back as four -- one input with several
    encodings, which is what the rest of the fixed-width fields of the
    format are held away from. `_serialize_uint32` is what writes it, so
    the two directions now agree on the number of octets rather than only
    on the number.
    """
    canonical = bytes.fromhex("01030401000000") + PSBT_SEPARATOR
    psbt_in = PsbtIn.parse(canonical)
    assert psbt_in.sig_hash_type == 1
    assert psbt_in.serialize() == canonical

    for size in (0, 1, 2, 3, 5):
        value = (1).to_bytes(max(size, 4), "little")[:size]
        raw = bytes.fromhex("0103") + bytes([size]) + value + PSBT_SEPARATOR
        err_msg = f"invalid sig_hash type length: {size} bytes instead of 4"
        for check_validity in (True, False):
            with pytest.raises(BTClibValueError, match=err_msg):
                PsbtIn.parse(raw, check_validity=check_validity)


def test_valid_sig_hash_type_matches_sig_hash_types() -> None:
    """ValidSigHashType is a mypy fact about sig_hash_type, checked here.

    Nothing of a Literal exists at run time (issue #273), so what mypy
    cannot check against sig_hash.assert_valid_hash_type's own frozenset,
    the suite does.
    """
    assert set(get_args(ValidSigHashType)) == SIG_HASH_TYPES


def test_compatibility() -> None:
    """Check the compatibility property `sig_hash` defaults to zero."""
    psbt_in = PsbtIn()
    assert not psbt_in.sig_hash


def test_default_arguments_are_not_shared() -> None:
    """Check each PsbtIn gets its own final_script_witness (issue #139)."""
    # guards against the final_script_witness default being built once,
    # at definition time, and shared by every PsbtIn built without it
    # (issue #139)
    psbt_in = PsbtIn()
    assert psbt_in.final_script_witness is not PsbtIn().final_script_witness

    # a Witness is immutable all the way down, so a shared one could not
    # be corrupted; it is still built per call
    with pytest.raises(FrozenInstanceError):
        psbt_in.final_script_witness.stack = ()  # type: ignore[misc]
    assert not PsbtIn().final_script_witness.stack


def test_key_type_tables_name_every_field() -> None:
    """Check the key-type tables and the dataclass name the same fields."""
    # serialize and parse reach a field by the name a table holds, and the
    # failure that has to be tested for is the silent one: a field no table
    # names is serialized as absent and never parsed, and nothing says so.
    # A stale name is loud on its own -- getattr raises AttributeError on
    # every serialize, __init__ a TypeError on every parse -- so what this
    # asks is that the tables and the dataclass name the same set, not that
    # every name in them exists
    field_names = {field.name for field in fields(PsbtIn)}

    assert {name for _, name, _ in _SERIALIZED_FIELDS} == field_names
    # a name here that is not a field is silent too: the drop would simply
    # not happen, and a finalized input would carry what BIP174 says it
    # must not
    assert _DROPPED_ONCE_FINALIZED < field_names

    parsed = {name for name, _, _ in _WHOLE_VALUE_FIELDS.values()}
    parsed |= {name for name, _ in _KEY_DATA_FIELDS.values()}
    # unknown is what no key type claims, so it is in neither table
    assert parsed | {"unknown"} == field_names

    # one key type per entry, in both directions
    assert len(_WHOLE_VALUE_FIELDS.keys() & _KEY_DATA_FIELDS.keys()) == 0
    assert (
        len(_SERIALIZED_FIELDS) == len(_WHOLE_VALUE_FIELDS) + len(_KEY_DATA_FIELDS) + 1
    )


def test_a_finalized_input_drops_everything_the_finalizer_consumed() -> None:
    """BIP174: what a finalizer consumed is not carried beside its result.

    The set is Bitcoin Core's: PSBTInput::Serialize writes exactly these
    fields inside `if (final_script_sig.empty() && final_script_witness
    .IsNull())`, the preimages and the taproot fields included, and
    leaves the utxo outside it for the Extractor to check the built
    transaction against.

    check_validity=False throughout: the values below are placeholders,
    and what is under test is which fields a finalized input emits --
    which a signature that no key made answers exactly as a real one
    would, serialization not being where a signature is checked.
    """
    values: dict[str, Any] = {
        "partial_sigs": {b"\x02" + b"\x01" * 32: b"\x30\x02"},
        "sig_hash_type": 1,
        "redeem_script": b"\x51",
        "witness_script": b"\x51",
        "hd_key_paths": {b"\x02" + b"\x01" * 32: BIP32KeyOrigin(b"\x00" * 4, "m/0")},
        "ripemd160_preimages": {b"\x01" * 20: b"\x02"},
        "sha256_preimages": {b"\x01" * 32: b"\x02"},
        "hash160_preimages": {b"\x01" * 20: b"\x02"},
        "hash256_preimages": {b"\x01" * 32: b"\x02"},
        "taproot_key_spend_signature": b"\x01" * 64,
        "taproot_script_spend_signatures": {b"\x01" * 64: b"\x02" * 64},
        "taproot_leaf_scripts": {b"\xc0" + b"\x01" * 32: (b"\x51", 0xC0)},
        "taproot_hd_key_paths": {
            b"\x01" * 32: ([b"\x02" * 32], BIP32KeyOrigin(b"\x00" * 4, "m/0"))
        },
        "taproot_internal_key": b"\x01" * 32,
        "taproot_merkle_root": b"\x01" * 32,
        "musig2_participant_pub_keys": {
            b"\x02" + b"\x01" * 32: [b"\x02" + b"\x02" * 32]
        },
        "musig2_pub_nonces": {(b"\x02" + b"\x01" * 32) * 2: b"\x03" * 66},
        "musig2_partial_sigs": {(b"\x02" + b"\x01" * 32) * 2: b"\x04" * 32},
    }
    # a field added to the set without a value here would be dropped by a
    # test that never serialized it in the first place
    assert values.keys() == _DROPPED_ONCE_FINALIZED

    # and what survives, which is the half of the contract a set of names
    # cannot state: the two utxo fields, the Extractor needing them to
    # check the transaction it builds, and the unknown ones, which no role
    # understands well enough to drop. Both utxos at once is not a psbt a
    # Creator would write, and is what pins each of them separately
    kept: dict[str, Any] = {
        "non_witness_utxo": Tx(
            vin=[TxIn(OutPoint(b"\x01" * 32, 0))],
            vout=[TxOut(1, b"\x51")],
        ),
        "witness_utxo": TxOut(1, b"\x51"),
        "final_script_witness": Witness([b"\x01"]),
        "unknown": {b"\xfc\x01": b"\x02"},
    }
    # the five BIP370 fields are in neither set, and finalization is not
    # what decides them: an input writes them when its psbt is version 2
    # and folds them into the unsigned transaction when it is version 0,
    # so a finalized input carries them still -- an Extractor needs the
    # outpoint as much as it needs the utxo
    v2_only: dict[str, Any] = {
        "previous_tx_id": b"\x01" * 32,
        "output_index": 0,
        "sequence": 0xFFFFFFFF,
        "required_time_lock_time": 500_000_000,
        "required_height_lock_time": 1,
    }

    # the three dicts and the final script_sig are the whole of an input,
    # so a field added to PsbtIn and to none of them fails here rather
    # than going untested in every direction
    assert values.keys() | kept.keys() | v2_only.keys() | {"final_script_sig"} == {
        field.name for field in fields(PsbtIn)
    }

    bare = PsbtIn(final_script_sig=b"\x51").serialize()

    # one field at a time, which is what tells the two apart: each dropped
    # field does serialize while the input is not finalized -- or "gone
    # once it is" would hold whatever the set said -- and is gone once it
    # is; each kept field is still there
    for name, value in values.items():
        psbt_in = PsbtIn(**{name: value}, check_validity=False)
        assert psbt_in.serialize(check_validity=False) != PSBT_SEPARATOR
        psbt_in = PsbtIn(
            **{name: value}, final_script_sig=b"\x51", check_validity=False
        )
        assert psbt_in.serialize(check_validity=False) == bare
    for name, value in kept.items():
        psbt_in = PsbtIn(
            **{name: value}, final_script_sig=b"\x51", check_validity=False
        )
        assert psbt_in.serialize(check_validity=False) != bare
    # the version and not the finalization: nothing of them in a version
    # 0 map, where the unsigned transaction is where they go, and a field
    # each in a version 2 one, finalized as this input is
    for name, value in v2_only.items():
        psbt_in = PsbtIn(
            **{name: value}, final_script_sig=b"\x51", check_validity=False
        )
        assert psbt_in.serialize(check_validity=False) == bare
        assert psbt_in.serialize(psbt_version=2, check_validity=False) != bare

    # and all of them at once, which is the input a Finalizer hands on
    finalized = PsbtIn(**values, **kept, final_script_sig=b"\x51", check_validity=False)
    assert finalized.serialize(check_validity=False) == PsbtIn(
        **kept, final_script_sig=b"\x51", check_validity=False
    ).serialize(check_validity=False)


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Round-trip a PsbtIn through dict, against the golden json."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    # PsbtIn dataclass
    psbt_in = psbt.inputs[0]
    assert isinstance(psbt_in, PsbtIn)

    # PsbtIn dataclass to dict
    psbt_in_dict = psbt_in.to_dict()
    assert isinstance(psbt_in_dict, dict)
    # the hex, not the dict: a {"asm": ..., "hex": ...} is truthy even for
    # the empty script, so the bare dict would assert nothing
    assert psbt_in_dict["redeem_script"]["hex"]

    # against the json committed beside this module, not written to it
    json_golden("psbt_in.json", psbt_in_dict)

    # PsbtIn dataclass from dict
    psbt_in2 = PsbtIn.from_dict(psbt_in_dict)
    assert isinstance(psbt_in2, PsbtIn)

    assert psbt_in == psbt_in2


def test_scripts_are_rendered_as_asm_and_hex() -> None:
    """The three scripts Bitcoin Core's decodepsbt renders as objects."""
    redeem_script = "a914748284390f9e263a4b766a75d0633c50426eb87587"
    witness_script = "0020" + "00" * 32
    final_script_sig = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    psbt_in = PsbtIn(
        redeem_script=redeem_script,
        witness_script=witness_script,
        final_script_sig=final_script_sig,
    )

    dict_ = psbt_in.to_dict()
    assert dict_["redeem_script"]["hex"] == redeem_script
    assert dict_["witness_script"]["hex"] == witness_script
    assert dict_["final_script_sig"]["hex"] == final_script_sig
    assert dict_["final_script_sig"]["asm"].startswith("OP_DUP OP_HASH160 ")
    assert PsbtIn.from_dict(dict_) == psbt_in

    # the shape to_dict wrote before it wrote that one
    old = {
        **dict_,
        "redeem_script": redeem_script,
        "witness_script": witness_script,
        "final_script_sig": final_script_sig,
    }
    assert PsbtIn.from_dict(old) == psbt_in

    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        PsbtIn.from_dict(
            {**dict_, "witness_script": {"asm": "OP_1", "hex": witness_script}}
        )
