#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Partially Signed Bitcoin Transaction Input (PsbtIn) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

# Standard library imports
from dataclasses import dataclass
from typing import Any, cast

from btclib.alias import Octets
from btclib.bip32.key_origin import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.curves import sec_point
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.psbt.psbt_utils import (
    assert_valid_leaf_scripts,
    assert_valid_redeem_script,
    assert_valid_taproot_bip32_derivation,
    assert_valid_taproot_internal_key,
    assert_valid_taproot_script_keys,
    assert_valid_taproot_signatures,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    decode_leaf_scripts,
    decode_taproot_bip32,
    deserialize_bytes,
    deserialize_int,
    deserialize_tx,
    encode_dict_bytes_bytes,
    encode_leaf_scripts,
    parse_leaf_script,
    parse_taproot_bip32,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_leaf_scripts,
    serialize_taproot_bip32,
    taproot_bip32_to_dict,
)
from btclib.script import Witness
from btclib.script.sig_hash import assert_valid_hash_type
from btclib.tx import Tx, TxOut
from btclib.utils import bytes_from_octets

PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIG_HASH_TYPE = b"\x03"
PSBT_IN_REDEEM_SCRIPT = b"\x04"
PSBT_IN_WITNESS_SCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_FINAL_SCRIPTSIG = b"\x07"
PSBT_IN_FINAL_SCRIPTWITNESS = b"\x08"
PSBT_IN_RIPEMD160 = b"\x0a"
PSBT_IN_SHA256 = b"\x0b"
PSBT_IN_HASH160 = b"\x0c"
PSBT_IN_HASH256 = b"\x0d"
PSBT_IN_TAP_KEY_SIG = b"\x13"
PSBT_IN_TAP_SCRIPT_SIG = b"\x14"
PSBT_IN_TAP_LEAF_SCRIPT = b"\x15"
PSBT_IN_TAP_BIP32_DERIVATION = b"\x16"
PSBT_IN_TAP_INTERNAL_KEY = b"\x17"
PSBT_IN_TAP_MERKLE_ROOT = b"\x18"

# 0xfc is reserved for proprietary use, and needs no constant of its own:
# explicit support for proprietary (and por) is unnecessary,
# see https://github.com/bitcoin/bips/pull/1038


def _deserialize_witness_utxo(k: bytes, v: bytes, type_: str) -> TxOut:
    """Return the dataclass element from its binary representation."""
    # deserialize_bytes is the key-length check: the key of a field that
    # occurs at most once per input is its type byte and nothing else
    return TxOut.parse(deserialize_bytes(k, v, type_))


def _assert_valid_partial_sigs(partial_sigs: Mapping[bytes, bytes]) -> None:
    """Raise an exception if the dataclass element is not valid."""
    for pub_key, sig in partial_sigs.items():
        try:
            # pub_key must be a valid secp256k1 Point in SEC representation
            sec_point.point_from_octets(pub_key)
        except BTClibValueError as e:
            err_msg = "invalid partial signature pub_key: {pub_key!r}"
            raise BTClibValueError(err_msg) from e
        try:
            # the DER signature alone: a partial signature is that plus a
            # sighash type byte (bip 174), so it is not itself a DER
            # encoding, and Sig.parse refuses trailing bytes after the
            # sequence (issue #129). The trailing byte is not checked
            # here: which hash types are admissible depends on the input
            # being spent, which a per-field validator does not know, and
            # issue #173 is where that belongs. Do not let a line of this
            # comment begin with "# type:", which mypy reads as a PEP 484
            # type comment and then calls the try block a syntax error
            dsa.Sig.parse(sig[:-1])
        except BTClibValueError as e:
            err_msg = f"invalid partial signature: {sig!r}"
            raise BTClibValueError(err_msg) from e
        # issue 173: the key is not checked against the signature. Doing so
        # needs the sighash, i.e. the whole transaction, which a per-field
        # validator does not have -- so the question is where it belongs


def _assert_valid_final_script_sig(final_script_sig: bytes) -> None:
    # should check for a valid script
    bytes(final_script_sig)


def _deserialize_final_script_witness(k: bytes, v: bytes, type_: str) -> Witness:
    """Return the dataclass element from its binary representation."""
    return Witness.parse(deserialize_bytes(k, v, type_))


def _assert_valid_ripemd160_preimages(
    ripemd160_preimages: Mapping[bytes, bytes],
) -> None:
    for h, preimage in ripemd160_preimages.items():
        if ripemd160(preimage) != h:
            raise BTClibValueError("invalid RIPEMD160 preimage")


def _assert_valid_sha256_preimages(sha256_preimages: Mapping[bytes, bytes]) -> None:
    for h, preimage in sha256_preimages.items():
        if sha256(preimage) != h:
            raise BTClibValueError("invalid SHA256 preimage")


def _assert_valid_hash160_preimages(hash160_preimages: Mapping[bytes, bytes]) -> None:
    for h, preimage in hash160_preimages.items():
        if hash160(preimage) != h:
            raise BTClibValueError("invalid HASH160 preimage")


def _assert_valid_hash256_preimages(hash256_preimages: Mapping[bytes, bytes]) -> None:
    for h, preimage in hash256_preimages.items():
        if hash256(preimage) != h:
            raise BTClibValueError("invalid HASH256 preimage")


def _serialize_non_witness_utxo(type_: bytes, tx: Tx) -> bytes:
    """Return the binary representation of the dataclass element."""
    # include_witness=True: bip 174 carries the utxo being spent as the
    # network serializes it, and "non-witness" names the input's kind, not
    # a transaction with its witnesses stripped
    return serialize_bytes(type_, tx.serialize(include_witness=True))


def _serialize_witness_utxo(type_: bytes, tx_out: TxOut) -> bytes:
    """Return the binary representation of the dataclass element."""
    return serialize_bytes(type_, tx_out.serialize())


def _serialize_sig_hash_type(type_: bytes, sig_hash_type: int) -> bytes:
    """Return the binary representation of the dataclass element."""
    # bip 174: four bytes, little endian, unsigned
    return serialize_bytes(
        type_, sig_hash_type.to_bytes(4, byteorder="little", signed=False)
    )


def _serialize_final_script_witness(type_: bytes, witness: Witness) -> bytes:
    """Return the binary representation of the dataclass element."""
    return serialize_bytes(type_, witness.serialize())


# what serializing a field takes: its key type and its value, whatever the
# value's shape is -- so the psbt_utils serializers and the four wrappers
# above share one signature, which is what lets the table below be a table
_Serializer = Callable[[bytes, Any], bytes]

# what deserializing a whole value takes: the key, whose length is the
# check, the value, and the name of the field to report in the message
_Deserializer = Callable[[bytes, bytes, str], Any]

# one entry per BIP174 input key type: the type byte, the attribute holding
# the value, and the serializer for that value's shape. A table rather than
# one `if` per field, because the fields differ in exactly these three
# things and in nothing else, and because the order of emission -- which is
# what a psbt's bytes are compared against -- is then a list to read
# instead of a control flow to trace. Order is why it is a list.
#
# The attribute is the init keyword as well, __init__ taking one parameter
# per field, so a field is named once here and once in the parse tables
# below and nowhere else.
#
# A field is serialized only when its value is truthy, an absent field
# being an absent key/value pair, so no serializer here has to answer what
# an empty value would serialize to
_SERIALIZED_FIELDS: list[tuple[bytes, str, _Serializer]] = [
    (PSBT_IN_NON_WITNESS_UTXO, "non_witness_utxo", _serialize_non_witness_utxo),
    (PSBT_IN_WITNESS_UTXO, "witness_utxo", _serialize_witness_utxo),
    (PSBT_IN_PARTIAL_SIG, "partial_sigs", serialize_dict_bytes_bytes),
    (PSBT_IN_SIG_HASH_TYPE, "sig_hash_type", _serialize_sig_hash_type),
    (PSBT_IN_REDEEM_SCRIPT, "redeem_script", serialize_bytes),
    (PSBT_IN_WITNESS_SCRIPT, "witness_script", serialize_bytes),
    (PSBT_IN_BIP32_DERIVATION, "hd_key_paths", serialize_hd_key_paths),
    (PSBT_IN_FINAL_SCRIPTSIG, "final_script_sig", serialize_bytes),
    (
        PSBT_IN_FINAL_SCRIPTWITNESS,
        "final_script_witness",
        _serialize_final_script_witness,
    ),
    # an unknown key is kept whole, its type byte included, so an empty
    # type marker re-emits each of them exactly as it arrived
    (b"", "unknown", serialize_dict_bytes_bytes),
    (PSBT_IN_RIPEMD160, "ripemd160_preimages", serialize_dict_bytes_bytes),
    (PSBT_IN_SHA256, "sha256_preimages", serialize_dict_bytes_bytes),
    (PSBT_IN_HASH160, "hash160_preimages", serialize_dict_bytes_bytes),
    (PSBT_IN_HASH256, "hash256_preimages", serialize_dict_bytes_bytes),
    (PSBT_IN_TAP_KEY_SIG, "taproot_key_spend_signature", serialize_bytes),
    (
        PSBT_IN_TAP_SCRIPT_SIG,
        "taproot_script_spend_signatures",
        serialize_dict_bytes_bytes,
    ),
    (PSBT_IN_TAP_LEAF_SCRIPT, "taproot_leaf_scripts", serialize_leaf_scripts),
    (PSBT_IN_TAP_BIP32_DERIVATION, "taproot_hd_key_paths", serialize_taproot_bip32),
    (PSBT_IN_TAP_INTERNAL_KEY, "taproot_internal_key", serialize_bytes),
    (PSBT_IN_TAP_MERKLE_ROOT, "taproot_merkle_root", serialize_bytes),
]

# bip 174: what a finalizer consumed is not carried beside what it
# produced, so an input with a final script_sig or witness serializes
# without these fields. They are still parsed: dropping what a
# counterparty sent is the Finalizer role's decision, not a codec's.
# Issue 173: the taproot fields have no such condition
_DROPPED_ONCE_FINALIZED = frozenset(
    {
        "partial_sigs",
        "sig_hash_type",
        "redeem_script",
        "witness_script",
        "hd_key_paths",
    }
)

# a BIP174 key is a one-byte type, plus key data for the fields that can
# occur more than once per input -- a pub key, a hash, a control block.
# Telling those two apart is the whole of a parse, so there is a table for
# each: here the fields whose key is the type byte alone, mapped to the
# init keyword they fill, the field name their error message reports, and
# the deserializer of the whole value
_WHOLE_VALUE_FIELDS: dict[bytes, tuple[str, str, _Deserializer]] = {
    PSBT_IN_NON_WITNESS_UTXO: (
        "non_witness_utxo",
        "non-witness utxo",
        deserialize_tx,
    ),
    PSBT_IN_WITNESS_UTXO: ("witness_utxo", "witness-utxo", _deserialize_witness_utxo),
    PSBT_IN_SIG_HASH_TYPE: ("sig_hash_type", "sig_hash type", deserialize_int),
    PSBT_IN_REDEEM_SCRIPT: ("redeem_script", "redeem script", deserialize_bytes),
    PSBT_IN_WITNESS_SCRIPT: ("witness_script", "witness script", deserialize_bytes),
    PSBT_IN_FINAL_SCRIPTSIG: (
        "final_script_sig",
        "final script_sig",
        deserialize_bytes,
    ),
    PSBT_IN_FINAL_SCRIPTWITNESS: (
        "final_script_witness",
        "final script witness",
        _deserialize_final_script_witness,
    ),
    PSBT_IN_TAP_KEY_SIG: (
        "taproot_key_spend_signature",
        "taproot key spend signature",
        deserialize_bytes,
    ),
    PSBT_IN_TAP_INTERNAL_KEY: (
        "taproot_internal_key",
        "taproot internal key",
        deserialize_bytes,
    ),
    PSBT_IN_TAP_MERKLE_ROOT: (
        "taproot_merkle_root",
        "taproot merkle root",
        deserialize_bytes,
    ),
}

# and here the fields whose key carries key data: the init keyword, and the
# parser of one entry's value. bytes is the parser of a value that is
# already bytes, which is the answer for the four preimage maps and the two
# signature maps -- the key data is where those fields' meaning is
_KEY_DATA_FIELDS: dict[bytes, tuple[str, Callable[[bytes], Any]]] = {
    PSBT_IN_PARTIAL_SIG: ("partial_sigs", bytes),
    PSBT_IN_BIP32_DERIVATION: ("hd_key_paths", BIP32KeyOrigin.parse),
    PSBT_IN_RIPEMD160: ("ripemd160_preimages", bytes),
    PSBT_IN_SHA256: ("sha256_preimages", bytes),
    PSBT_IN_HASH160: ("hash160_preimages", bytes),
    PSBT_IN_HASH256: ("hash256_preimages", bytes),
    PSBT_IN_TAP_SCRIPT_SIG: ("taproot_script_spend_signatures", bytes),
    PSBT_IN_TAP_LEAF_SCRIPT: ("taproot_leaf_scripts", parse_leaf_script),
    PSBT_IN_TAP_BIP32_DERIVATION: ("taproot_hd_key_paths", parse_taproot_bip32),
}


@dataclass
class PsbtIn:
    non_witness_utxo: Tx | None
    witness_utxo: TxOut | None
    partial_sigs: dict[bytes, bytes]
    sig_hash_type: int | None
    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    final_script_sig: bytes
    final_script_witness: Witness
    ripemd160_preimages: dict[bytes, bytes]
    sha256_preimages: dict[bytes, bytes]
    hash160_preimages: dict[bytes, bytes]
    hash256_preimages: dict[bytes, bytes]
    taproot_key_spend_signature: bytes
    taproot_script_spend_signatures: dict[bytes, bytes]
    taproot_leaf_scripts: dict[bytes, tuple[bytes, int]]
    taproot_hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]
    taproot_internal_key: bytes
    taproot_merkle_root: bytes
    unknown: dict[bytes, bytes]

    @property
    def sig_hash(self) -> int:
        """Return the sig_hash as int.

        For compatibility with PartiallySignedInput.
        """
        return self.sig_hash_type or 0

    def __init__(
        self,
        non_witness_utxo: Tx | None = None,
        witness_utxo: TxOut | None = None,
        partial_sigs: Mapping[Octets, Octets] | None = None,
        sig_hash_type: int | None = None,
        redeem_script: Octets = b"",
        witness_script: Octets = b"",
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin] | None = None,
        final_script_sig: Octets = b"",
        final_script_witness: Witness | None = None,
        ripemd160_preimages: Mapping[Octets, Octets] | None = None,
        sha256_preimages: Mapping[Octets, Octets] | None = None,
        hash160_preimages: Mapping[Octets, Octets] | None = None,
        hash256_preimages: Mapping[Octets, Octets] | None = None,
        taproot_key_spend_signature: Octets = b"",
        taproot_script_spend_signatures: Mapping[Octets, Octets] | None = None,
        taproot_leaf_scripts: Mapping[Octets, tuple[Octets, int]] | None = None,
        taproot_hd_key_paths: Mapping[Octets, tuple[list[Octets], BIP32KeyOrigin]]
        | None = None,
        taproot_internal_key: Octets = b"",
        taproot_merkle_root: Octets = b"",
        unknown: Mapping[Octets, Octets] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.non_witness_utxo = non_witness_utxo
        self.witness_utxo = witness_utxo
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.partial_sigs = decode_dict_bytes_bytes(partial_sigs)
        self.sig_hash_type = sig_hash_type
        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.final_script_sig = bytes_from_octets(final_script_sig)
        # a Witness() default would be one object shared by every PsbtIn
        # built without it, mutable through any of them
        self.final_script_witness = (
            Witness() if final_script_witness is None else final_script_witness
        )
        self.ripemd160_preimages = decode_dict_bytes_bytes(ripemd160_preimages)
        self.sha256_preimages = decode_dict_bytes_bytes(sha256_preimages)
        self.hash160_preimages = decode_dict_bytes_bytes(hash160_preimages)
        self.hash256_preimages = decode_dict_bytes_bytes(hash256_preimages)
        self.taproot_key_spend_signature = bytes_from_octets(
            taproot_key_spend_signature
        )
        self.taproot_script_spend_signatures = decode_dict_bytes_bytes(
            taproot_script_spend_signatures
        )
        self.taproot_leaf_scripts = decode_leaf_scripts(taproot_leaf_scripts)
        self.taproot_hd_key_paths = decode_taproot_bip32(taproot_hd_key_paths)
        self.taproot_internal_key = bytes_from_octets(taproot_internal_key)
        self.taproot_merkle_root = bytes_from_octets(taproot_merkle_root)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency."""
        if self.non_witness_utxo:
            self.non_witness_utxo.assert_valid()

        if self.witness_utxo:
            self.witness_utxo.assert_valid()

        _assert_valid_partial_sigs(self.partial_sigs)

        if self.sig_hash_type:
            assert_valid_hash_type(self.sig_hash_type)

        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        _assert_valid_final_script_sig(self.final_script_sig)
        self.final_script_witness.assert_valid()

        _assert_valid_ripemd160_preimages(self.ripemd160_preimages)
        _assert_valid_sha256_preimages(self.sha256_preimages)
        _assert_valid_hash160_preimages(self.hash160_preimages)
        _assert_valid_hash256_preimages(self.hash256_preimages)

        assert_valid_taproot_internal_key(self.taproot_internal_key)
        assert_valid_taproot_signatures(
            [self.taproot_key_spend_signature],
            "taproot key path signature",
        )
        assert_valid_taproot_script_keys(
            list(self.taproot_script_spend_signatures.keys()),
            "invalid taproot script path key length",
        )
        assert_valid_taproot_signatures(
            list(self.taproot_script_spend_signatures.values()),
            "taproot script path signature",
        )
        assert_valid_leaf_scripts(self.taproot_leaf_scripts)
        assert_valid_taproot_bip32_derivation(self.taproot_hd_key_paths)

        assert_valid_unknown(self.unknown)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            "non_witness_utxo": self.non_witness_utxo.to_dict(check_validity=False)
            if self.non_witness_utxo
            else None,
            "witness_utxo": self.witness_utxo.to_dict(check_validity=False)
            if self.witness_utxo
            else None,
            "partial_signatures": encode_dict_bytes_bytes(self.partial_sigs),
            "sig_hash": self.sig_hash_type,
            # issue 172: Core renders a script as {"asm": ..., "hex": ...}
            "redeem_script": self.redeem_script.hex(),
            # issue 172: Core renders a script as {"asm": ..., "hex": ...}
            "witness_script": self.witness_script.hex(),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            # issue 172: Core renders a script as {"asm": ..., "hex": ...}
            "final_script_sig": self.final_script_sig.hex(),
            "final_script_witness": self.final_script_witness.to_dict(
                check_validity=False
            ),
            "ripemd160_preimages": encode_dict_bytes_bytes(self.ripemd160_preimages),
            "sha256_preimages": encode_dict_bytes_bytes(self.sha256_preimages),
            "hash160_preimages": encode_dict_bytes_bytes(self.hash160_preimages),
            "hash256_preimages": encode_dict_bytes_bytes(self.hash256_preimages),
            "taproot_key_spend_signature": self.taproot_key_spend_signature.hex(),
            "taproot_script_spend_signatures": encode_dict_bytes_bytes(
                self.taproot_script_spend_signatures
            ),
            "taproot_leaf_scripts": encode_leaf_scripts(self.taproot_leaf_scripts),
            "taproot_hd_key_paths": taproot_bip32_to_dict(self.taproot_hd_key_paths),
            "taproot_internal_key": self.taproot_internal_key.hex(),
            "taproot_merkle_root": self.taproot_merkle_root.hex(),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: type[PsbtIn], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> PsbtIn:
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            decode_from_bip32_derivs(dict_["bip32_derivs"]),
        )
        taproot_hd_key_paths = cast(
            Mapping[Octets, tuple[list[Octets], BIP32KeyOrigin]],
            decode_from_bip32_derivs(dict_["taproot_hd_key_paths"]),
        )
        return cls(
            Tx.from_dict(dict_["non_witness_utxo"], check_validity=False)
            if dict_["non_witness_utxo"]
            else None,
            TxOut.from_dict(dict_["witness_utxo"], check_validity=False)
            if dict_["witness_utxo"]
            else None,
            dict_["partial_signatures"],
            dict_["sig_hash"],
            dict_["redeem_script"],
            dict_["witness_script"],
            hd_key_paths,
            dict_["final_script_sig"],
            Witness.from_dict(dict_["final_script_witness"], check_validity=False),
            dict_["ripemd160_preimages"],
            dict_["sha256_preimages"],
            dict_["hash160_preimages"],
            dict_["hash256_preimages"],
            dict_["taproot_key_spend_signature"],
            dict_["taproot_script_spend_signatures"],
            dict_["taproot_leaf_scripts"],
            taproot_hd_key_paths,
            dict_["taproot_internal_key"],
            dict_["taproot_merkle_root"],
            dict_["unknown"],
            check_validity=check_validity,
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        finalized = bool(self.final_script_sig or self.final_script_witness)

        psbt_in_bin: list[bytes] = []
        for type_, field, serialize_field in _SERIALIZED_FIELDS:
            if finalized and field in _DROPPED_ONCE_FINALIZED:
                continue
            value = getattr(self, field)
            if value:
                psbt_in_bin.append(serialize_field(type_, value))
        return b"".join(psbt_in_bin)

    @classmethod
    def parse(
        cls: type[PsbtIn],
        input_map: Mapping[bytes, bytes],
        *,
        check_validity: bool = True,
    ) -> PsbtIn:
        """Return a PsbtIn by parsing binary data."""
        # FIX parse must use BinaryData
        # the init keywords the map fills; whatever it does not carry keeps
        # the default __init__ gives it, which is what makes the two tables
        # above the whole of the mapping
        fields: dict[str, Any] = {}

        for k, v in input_map.items():
            type_ = k[:1]
            if type_ in _WHOLE_VALUE_FIELDS:
                field, what, deserialize = _WHOLE_VALUE_FIELDS[type_]
                fields[field] = deserialize(k, v, what)
            elif type_ in _KEY_DATA_FIELDS:
                field, parse_value = _KEY_DATA_FIELDS[type_]
                # setdefault: such a field is as many map entries as it has
                # key data, so it is accumulated and not assigned
                fields.setdefault(field, {})[k[1:]] = parse_value(v)
            else:  # unknown
                # keyed by the whole key: what makes it unknown is its type
                # byte, so that byte is part of what has to be given back
                fields.setdefault("unknown", {})[k] = v

        return cls(**fields, check_validity=check_validity)
