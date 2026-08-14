# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Partially Signed Bitcoin Transaction Input (PsbtIn) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

# Standard library imports
from dataclasses import dataclass
from typing import Any, cast

from btclib.alias import BinaryData, Octets, ValidSigHashType
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
    MUSIG2_PARTIAL_SIG_SIZE,
    MUSIG2_PUB_NONCE_SIZE,
    PSBT_SEPARATOR,
    SP_DLEQ_PROOF_SIZE,
    SP_ECDH_SHARE_SIZE,
    assert_not_a_v2_field,
    assert_valid_leaf_scripts,
    assert_valid_musig2_participant_pub_keys,
    assert_valid_musig2_session_data,
    assert_valid_psbt_version,
    assert_valid_redeem_script,
    assert_valid_sp_scan_key_map,
    assert_valid_taproot_bip32_derivation,
    assert_valid_taproot_internal_key,
    assert_valid_taproot_script_keys,
    assert_valid_taproot_signatures,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    decode_leaf_scripts,
    decode_musig2_participant_pub_keys,
    decode_taproot_bip32,
    deserialize_bytes,
    deserialize_map,
    deserialize_sized_int,
    deserialize_tx,
    encode_dict_bytes_bytes,
    encode_leaf_scripts,
    encode_musig2_participant_pub_keys,
    parse_leaf_script,
    parse_musig2_participant_pub_keys,
    parse_taproot_bip32,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_leaf_scripts,
    serialize_musig2_participant_pub_keys,
    serialize_sized_int,
    serialize_taproot_bip32,
    taproot_bip32_to_dict,
)
from btclib.script import Witness, script_from_dict, script_to_dict
from btclib.script.sig_hash import assert_valid_hash_type
from btclib.tx import OutPoint, Tx, TxOut
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
)

__all__ = [
    "LOCK_TIME_THRESHOLD",
    "PSBT_IN_BIP32_DERIVATION",
    "PSBT_IN_FINAL_SCRIPTSIG",
    "PSBT_IN_FINAL_SCRIPTWITNESS",
    "PSBT_IN_HASH160",
    "PSBT_IN_HASH256",
    "PSBT_IN_MUSIG2_PARTIAL_SIG",
    "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS",
    "PSBT_IN_MUSIG2_PUB_NONCE",
    "PSBT_IN_NON_WITNESS_UTXO",
    "PSBT_IN_OUTPUT_INDEX",
    "PSBT_IN_PARTIAL_SIG",
    "PSBT_IN_PREVIOUS_TXID",
    "PSBT_IN_REDEEM_SCRIPT",
    "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
    "PSBT_IN_REQUIRED_TIME_LOCKTIME",
    "PSBT_IN_RIPEMD160",
    "PSBT_IN_SEQUENCE",
    "PSBT_IN_SHA256",
    "PSBT_IN_SIG_HASH_TYPE",
    "PSBT_IN_SP_DLEQ",
    "PSBT_IN_SP_ECDH_SHARE",
    "PSBT_IN_TAP_BIP32_DERIVATION",
    "PSBT_IN_TAP_INTERNAL_KEY",
    "PSBT_IN_TAP_KEY_SIG",
    "PSBT_IN_TAP_LEAF_SCRIPT",
    "PSBT_IN_TAP_MERKLE_ROOT",
    "PSBT_IN_TAP_SCRIPT_SIG",
    "PSBT_IN_WITNESS_SCRIPT",
    "PSBT_IN_WITNESS_UTXO",
    "PsbtIn",
]

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
PSBT_IN_PREVIOUS_TXID = b"\x0e"
PSBT_IN_OUTPUT_INDEX = b"\x0f"
PSBT_IN_SEQUENCE = b"\x10"
PSBT_IN_REQUIRED_TIME_LOCKTIME = b"\x11"
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = b"\x12"
PSBT_IN_TAP_KEY_SIG = b"\x13"
PSBT_IN_TAP_SCRIPT_SIG = b"\x14"
PSBT_IN_TAP_LEAF_SCRIPT = b"\x15"
PSBT_IN_TAP_BIP32_DERIVATION = b"\x16"
PSBT_IN_TAP_INTERNAL_KEY = b"\x17"
PSBT_IN_TAP_MERKLE_ROOT = b"\x18"
PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = b"\x1a"
PSBT_IN_MUSIG2_PUB_NONCE = b"\x1b"
PSBT_IN_MUSIG2_PARTIAL_SIG = b"\x1c"
PSBT_IN_SP_ECDH_SHARE = b"\x1d"
PSBT_IN_SP_DLEQ = b"\x1e"

# the input fields a version 0 input must not carry. Five of them are
# BIP370's: the outpoint and sequence a v0 input reads from the unsigned
# transaction, and the two locktimes that transaction's own is computed
# from. The last two are BIP375's, excluded from version 0 for a reason of
# its own -- a silent payment output has no script until the inputs are
# fixed, and only version 2 has a field to write one into afterwards.
# See psbt_utils.assert_not_a_v2_field
_V2_FIELDS = {
    PSBT_IN_PREVIOUS_TXID: "PSBT_IN_PREVIOUS_TXID",
    PSBT_IN_OUTPUT_INDEX: "PSBT_IN_OUTPUT_INDEX",
    PSBT_IN_SEQUENCE: "PSBT_IN_SEQUENCE",
    PSBT_IN_REQUIRED_TIME_LOCKTIME: "PSBT_IN_REQUIRED_TIME_LOCKTIME",
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
    PSBT_IN_SP_ECDH_SHARE: "PSBT_IN_SP_ECDH_SHARE",
    PSBT_IN_SP_DLEQ: "PSBT_IN_SP_DLEQ",
}

# the boundary BIP65 draws between the two kinds of lock time, and BIP370
# with it: below it a value is a block height, at it or above a Unix
# timestamp. It is why an input can require one kind or the other and why
# a psbt requiring both is refused -- one nLockTime field cannot be both
# a height and a time
LOCK_TIME_THRESHOLD = 500_000_000

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
            err_msg = f"invalid partial signature pub_key: {pub_key!r}"
            raise BTClibValueError(err_msg) from e
        try:
            # the DER signature alone: a partial signature is that plus a
            # sighash type byte (BIP174), so it is not itself a DER
            # encoding, and Sig.parse refuses trailing bytes after the
            # sequence (issue #129). Neither that byte nor the key is
            # checked against the signature here: both questions need the
            # transaction -- which sighash types the input admits, and
            # which hash the signature actually commits to -- so both are
            # the Finalizer's, and psbt.finalize asks them. Do not
            # let a line of this comment begin with "# type:", which mypy
            # reads as a PEP 484 type comment and then calls the try block
            # a syntax error
            dsa.Sig.parse(sig[:-1])
        except BTClibValueError as e:
            err_msg = f"invalid partial signature: {sig!r}"
            raise BTClibValueError(err_msg) from e


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
    # include_witness=True: BIP174 carries the utxo being spent as the
    # network serializes it, and "non-witness" names the input's kind, not
    # a transaction with its witnesses stripped
    return serialize_bytes(type_, tx.serialize(include_witness=True))


def _serialize_witness_utxo(type_: bytes, tx_out: TxOut) -> bytes:
    """Return the binary representation of the dataclass element."""
    return serialize_bytes(type_, tx_out.serialize())


def _serialize_final_script_witness(type_: bytes, witness: Witness) -> bytes:
    """Return the binary representation of the dataclass element."""
    return serialize_bytes(type_, witness.serialize())


def _serialize_previous_tx_id(type_: bytes, tx_id: bytes) -> bytes:
    """Return the binary representation of the dataclass element.

    BIP370 asks for "standard byte order, not display byte order", which
    is the order OutPoint.serialize writes and the reverse of the one
    btclib holds a tx_id in: `Tx.id`, `OutPoint.tx_id` and this field are
    then one value, comparable without a reversal at every use.
    """
    return serialize_bytes(type_, tx_id[::-1])


def _deserialize_previous_tx_id(k: bytes, v: bytes, type_: str) -> bytes:
    """Return the dataclass element from its binary representation."""
    tx_id = deserialize_bytes(k, v, type_)
    if len(tx_id) != 32:
        err_msg = f"invalid {type_} length: {len(tx_id)} bytes instead of 32"
        raise BTClibValueError(err_msg)
    return tx_id[::-1]


def _serialize_uint32(type_: bytes, value: int) -> bytes:
    """Return the binary representation of a 4-byte little-endian field."""
    return serialize_sized_int(type_, value, 4)


def _deserialize_uint32(k: bytes, v: bytes, type_: str) -> int:
    """Return the dataclass element from its binary representation."""
    return deserialize_sized_int(k, v, type_, 4)


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
    (PSBT_IN_SIG_HASH_TYPE, "sig_hash_type", _serialize_uint32),
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
    # the five of BIP370, in the ascending order of the type byte the rest
    # of the table is in: a version 2 psbt written any other way still
    # parses, and stops being the byte-for-byte answer to the one the BIP
    # publishes
    (PSBT_IN_PREVIOUS_TXID, "previous_tx_id", _serialize_previous_tx_id),
    (PSBT_IN_OUTPUT_INDEX, "output_index", _serialize_uint32),
    (PSBT_IN_SEQUENCE, "sequence", _serialize_uint32),
    (PSBT_IN_REQUIRED_TIME_LOCKTIME, "required_time_lock_time", _serialize_uint32),
    (PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, "required_height_lock_time", _serialize_uint32),
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
    # the three of BIP373, after the taproot fields as their type bytes
    # are: Bitcoin Core writes them there too (PSBTInput::Serialize), and
    # the psbts the BIP publishes are what that order is measured against
    (
        PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
        "musig2_participant_pub_keys",
        serialize_musig2_participant_pub_keys,
    ),
    (PSBT_IN_MUSIG2_PUB_NONCE, "musig2_pub_nonces", serialize_dict_bytes_bytes),
    (PSBT_IN_MUSIG2_PARTIAL_SIG, "musig2_partial_sigs", serialize_dict_bytes_bytes),
    # the two of BIP375, last as their type bytes are: an ECDH share for
    # one recipient's scan key, and the BIP374 proof that it was computed
    # with the private key of this input's own public key
    (PSBT_IN_SP_ECDH_SHARE, "sp_ecdh_shares", serialize_dict_bytes_bytes),
    (PSBT_IN_SP_DLEQ, "sp_dleq_proofs", serialize_dict_bytes_bytes),
]

# the fields of the table above that only a version 2 input writes. They
# are held whatever the version, the outpoint and sequence of a version 0
# input being what its psbt's unsigned transaction is built from; what the
# version decides is whether they are written as fields of the input map
# or as the transaction they are folded into
_V2_ONLY = frozenset(
    {
        "previous_tx_id",
        "output_index",
        "sequence",
        "required_time_lock_time",
        "required_height_lock_time",
    }
)

# the fields whose absence is None rather than a falsy value: an output
# index of 0 is the first output of the previous transaction and a
# sequence of 0 is the one BIP125 signals with, so "write it if it is
# truthy" -- the rule for every other field here -- would drop exactly
# what a version 2 input has to carry
_PRESENT_IF_NOT_NONE = frozenset(
    {
        "output_index",
        "sequence",
        "required_time_lock_time",
        "required_height_lock_time",
    }
)

# BIP174: what a finalizer consumed is not carried beside what it
# produced, so an input with a final script_sig or witness serializes
# without these fields. They are still parsed: dropping what a
# counterparty sent is the Finalizer role's decision, not a codec's.
# The list is the whole of what Bitcoin Core's PSBTInput::Serialize puts
# inside its `if (final_script_sig.empty() && final_script_witness
# .IsNull())`, the preimages and the taproot and MuSig2 fields included:
# each of them is an input to signing, and a finalized input has been
# signed -- a MuSig2 session most of all, its nonces being single use.
# The utxo fields are outside it there and here, an Extractor needing
# them to check the transaction it builds; so are the unknown ones,
# which no role understands well enough to drop.
# BIP375's ECDH share and DLEQ proof are outside it too, and for the
# utxo's reason rather than by omission: BIP375 gives the Transaction
# Extractor the job of recomputing every silent payment output script and
# verifying it against those two, which it cannot do if finalizing threw
# them away. Core's list predates that BIP and says nothing about them
_DROPPED_ONCE_FINALIZED = frozenset(
    {
        "partial_sigs",
        "sig_hash_type",
        "redeem_script",
        "witness_script",
        "hd_key_paths",
        "ripemd160_preimages",
        "sha256_preimages",
        "hash160_preimages",
        "hash256_preimages",
        "taproot_key_spend_signature",
        "taproot_script_spend_signatures",
        "taproot_leaf_scripts",
        "taproot_hd_key_paths",
        "taproot_internal_key",
        "taproot_merkle_root",
        "musig2_participant_pub_keys",
        "musig2_pub_nonces",
        "musig2_partial_sigs",
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
    PSBT_IN_SIG_HASH_TYPE: ("sig_hash_type", "sig_hash type", _deserialize_uint32),
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
    PSBT_IN_PREVIOUS_TXID: (
        "previous_tx_id",
        "previous txid",
        _deserialize_previous_tx_id,
    ),
    PSBT_IN_OUTPUT_INDEX: ("output_index", "output index", _deserialize_uint32),
    PSBT_IN_SEQUENCE: ("sequence", "sequence", _deserialize_uint32),
    PSBT_IN_REQUIRED_TIME_LOCKTIME: (
        "required_time_lock_time",
        "required time locktime",
        _deserialize_uint32,
    ),
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: (
        "required_height_lock_time",
        "required height locktime",
        _deserialize_uint32,
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
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: (
        "musig2_participant_pub_keys",
        parse_musig2_participant_pub_keys,
    ),
    # bytes for both: what identifies a nonce and a partial signature is
    # the whole of their key data, and it is the same key data for the two
    PSBT_IN_MUSIG2_PUB_NONCE: ("musig2_pub_nonces", bytes),
    PSBT_IN_MUSIG2_PARTIAL_SIG: ("musig2_partial_sigs", bytes),
    # bytes for both again: the key data of each is the scan key of the
    # recipient the share is for, and the value is a point or a proof
    PSBT_IN_SP_ECDH_SHARE: ("sp_ecdh_shares", bytes),
    PSBT_IN_SP_DLEQ: ("sp_dleq_proofs", bytes),
}


@dataclass
class PsbtIn:
    """The per-input map of a psbt: one field per BIP174/BIP370 key type.

    What each role fills in for one input on its way to a signature --
    the spent output or the transaction holding it, scripts, hd paths,
    partial and taproot signatures, preimages, the finalized script or
    witness -- with what no key type names kept in `unknown`. A field
    a psbt does not carry is None, or empty for the collection types.
    """

    non_witness_utxo: Tx | None
    witness_utxo: TxOut | None
    partial_sigs: dict[bytes, bytes]
    sig_hash_type: ValidSigHashType | None
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
    previous_tx_id: bytes
    output_index: int | None
    sequence: int | None
    required_time_lock_time: int | None
    required_height_lock_time: int | None
    musig2_participant_pub_keys: dict[bytes, list[bytes]]
    musig2_pub_nonces: dict[bytes, bytes]
    musig2_partial_sigs: dict[bytes, bytes]
    sp_ecdh_shares: dict[bytes, bytes]
    sp_dleq_proofs: dict[bytes, bytes]

    @property
    def prev_out(self) -> OutPoint:
        """Return the outpoint this input spends.

        The two fields as the one value every other btclib caller takes,
        `TxIn.prev_out` included; an input that does not carry both is an
        input Psbt.assert_valid refuses, and OutPoint says so here.
        """
        return OutPoint(self.previous_tx_id, self.output_index or 0)

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
        sig_hash_type: ValidSigHashType | None = None,
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
        previous_tx_id: Octets = b"",
        output_index: int | None = None,
        sequence: int | None = None,
        required_time_lock_time: int | None = None,
        required_height_lock_time: int | None = None,
        musig2_participant_pub_keys: Mapping[Octets, Sequence[Octets]] | None = None,
        musig2_pub_nonces: Mapping[Octets, Octets] | None = None,
        musig2_partial_sigs: Mapping[Octets, Octets] | None = None,
        sp_ecdh_shares: Mapping[Octets, Octets] | None = None,
        sp_dleq_proofs: Mapping[Octets, Octets] | None = None,
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
        self.previous_tx_id = bytes_from_octets(previous_tx_id)
        self.output_index = output_index
        self.sequence = sequence
        self.required_time_lock_time = required_time_lock_time
        self.required_height_lock_time = required_height_lock_time
        self.musig2_participant_pub_keys = decode_musig2_participant_pub_keys(
            musig2_participant_pub_keys
        )
        self.musig2_pub_nonces = decode_dict_bytes_bytes(musig2_pub_nonces)
        self.musig2_partial_sigs = decode_dict_bytes_bytes(musig2_partial_sigs)
        self.sp_ecdh_shares = decode_dict_bytes_bytes(sp_ecdh_shares)
        self.sp_dleq_proofs = decode_dict_bytes_bytes(sp_dleq_proofs)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency.

        The BIP370 fields are checked for what they hold and not for
        whether they are there: which of them an input must carry is the
        psbt's version, which an input on its own does not know, so
        Psbt.assert_valid asks that question and this one answers what
        an input can be asked alone.
        """
        if self.previous_tx_id and len(self.previous_tx_id) != 32:
            err_msg = f"invalid previous txid: {len(self.previous_tx_id)} bytes"
            raise BTClibValueError(err_msg)

        if self.output_index is not None and not 0 <= self.output_index <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid output index: {self.output_index}")

        if self.sequence is not None and not 0 <= self.sequence <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid sequence: {self.sequence}")

        # the two bounds are BIP370's own, and they are what makes each
        # field one kind of lock time: a time locktime below the BIP65
        # threshold would be read as a block height by every node, and a
        # height at or above it as a timestamp. Zero is excluded from the
        # height because it is nLockTime's "no lock time at all", so an
        # input requiring it requires nothing
        if self.required_time_lock_time is not None and not (
            LOCK_TIME_THRESHOLD <= self.required_time_lock_time <= 0xFFFFFFFF
        ):
            err_msg = f"invalid required time locktime: {self.required_time_lock_time}"
            raise BTClibValueError(err_msg)

        if self.required_height_lock_time is not None and not (
            0 < self.required_height_lock_time < LOCK_TIME_THRESHOLD
        ):
            err_msg = (
                f"invalid required height locktime: {self.required_height_lock_time}"
            )
            raise BTClibValueError(err_msg)

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

        assert_valid_musig2_participant_pub_keys(self.musig2_participant_pub_keys)
        assert_valid_musig2_session_data(
            self.musig2_pub_nonces, MUSIG2_PUB_NONCE_SIZE, "musig2 public nonce"
        )
        assert_valid_musig2_session_data(
            self.musig2_partial_sigs,
            MUSIG2_PARTIAL_SIG_SIZE,
            "musig2 partial signature",
        )

        assert_valid_sp_scan_key_map(
            self.sp_ecdh_shares, SP_ECDH_SHARE_SIZE, "silent payment input ecdh share"
        )
        assert_valid_sp_scan_key_map(
            self.sp_dleq_proofs, SP_DLEQ_PROOF_SIZE, "silent payment input dleq proof"
        )

        assert_valid_unknown(self.unknown)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the input map as a dict of json-friendly values.

        Keys are hex, hd paths are BIP174's bip32_derivs shape;
        from_dict reads the same shape back.
        """
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
            "redeem_script": script_to_dict(self.redeem_script),
            "witness_script": script_to_dict(self.witness_script),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "final_script_sig": script_to_dict(self.final_script_sig),
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
            "previous_tx_id": self.previous_tx_id.hex(),
            "output_index": self.output_index,
            "sequence": self.sequence,
            "required_time_lock_time": self.required_time_lock_time,
            "required_height_lock_time": self.required_height_lock_time,
            "musig2_participant_pub_keys": encode_musig2_participant_pub_keys(
                self.musig2_participant_pub_keys
            ),
            "musig2_pub_nonces": encode_dict_bytes_bytes(self.musig2_pub_nonces),
            "musig2_partial_sigs": encode_dict_bytes_bytes(self.musig2_partial_sigs),
            "sp_ecdh_shares": encode_dict_bytes_bytes(self.sp_ecdh_shares),
            "sp_dleq_proofs": encode_dict_bytes_bytes(self.sp_dleq_proofs),
        }

    @classmethod
    def from_dict(
        cls: type[PsbtIn], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> PsbtIn:
        """Build a PsbtIn from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "psbt input")
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            # check_validity=False, as for every other element here (issue
            # 264): PsbtIn.assert_valid below validates it as part of the whole
            decode_from_bip32_derivs(dict_["bip32_derivs"], check_validity=False),
        )
        taproot_hd_key_paths = cast(
            Mapping[Octets, tuple[list[Octets], BIP32KeyOrigin]],
            decode_from_bip32_derivs(
                dict_["taproot_hd_key_paths"], check_validity=False
            ),
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
            script_from_dict(dict_["redeem_script"]),
            script_from_dict(dict_["witness_script"]),
            hd_key_paths,
            script_from_dict(dict_["final_script_sig"]),
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
            dict_["previous_tx_id"],
            dict_["output_index"],
            dict_["sequence"],
            dict_["required_time_lock_time"],
            dict_["required_height_lock_time"],
            dict_["musig2_participant_pub_keys"],
            dict_["musig2_pub_nonces"],
            dict_["musig2_partial_sigs"],
            dict_["sp_ecdh_shares"],
            dict_["sp_dleq_proofs"],
            check_validity=check_validity,
        )

    def serialize(self, *, psbt_version: int = 0, check_validity: bool = True) -> bytes:
        """Return the binary representation of the input map.

        psbt_version is the version of the psbt the map belongs to, and
        it decides whether the BIP370 fields are written here or folded
        into the psbt's unsigned transaction; an input serialized on its
        own is written as version 0, the version BIP174 defines. It is
        asked for, and not read for its truth: every version that is not
        0 wrote the BIP370 fields, so a `None` or a 3 wrote a version 2
        input and said nothing.
        """
        assert_valid_psbt_version(psbt_version)

        if check_validity:
            self.assert_valid()

        finalized = bool(self.final_script_sig or self.final_script_witness)

        psbt_in_bin: list[bytes] = []
        for type_, field, serialize_field in _SERIALIZED_FIELDS:
            if finalized and field in _DROPPED_ONCE_FINALIZED:
                continue
            if psbt_version == 0 and field in _V2_ONLY:
                continue
            value = getattr(self, field)
            if value is None or (not value and field not in _PRESENT_IF_NOT_NONE):
                continue
            psbt_in_bin.append(serialize_field(type_, value))

        # the map ends itself, as it does in Bitcoin Core
        # (PSBTInput::Serialize): a psbt is a sequence of maps with no
        # count in front of it, so a map that leaves its terminator to the
        # container cannot be read back on its own
        psbt_in_bin.append(PSBT_SEPARATOR)
        return b"".join(psbt_in_bin)

    @classmethod
    def parse(
        cls: type[PsbtIn],
        data: BinaryData,
        *,
        psbt_version: int = 0,
        check_validity: bool = True,
    ) -> PsbtIn:
        """Return a PsbtIn by parsing binary data.

        One map is read, its terminator included, which leaves the stream
        on the input after this one.

        psbt_version is the version of the psbt the map belongs to, which
        decides whether a BIP370 type byte is a field of this input or
        one this version must not carry; an input read on its own is read
        as version 0, the version BIP174 defines. Asked for as
        `serialize` asks for it, and for the same reason.

        Octets are one whole input and a stream is the caller's, as they
        are for the psbt these maps make: `Psbt.parse` threads one stream
        through the inputs and the outputs, and what follows an input in it
        is the next one.
        """
        assert_valid_psbt_version(psbt_version)

        stream = bytesio_from_binarydata(data)
        input_map = deserialize_map(stream)
        assert_no_trailing(data, stream, "psbt input")
        # the init keywords the map fills; whatever it does not carry keeps
        # the default __init__ gives it, which is what makes the two tables
        # above the whole of the mapping
        fields: dict[str, Any] = {}

        for k, v in input_map.items():
            type_ = k[:1]
            # before the dispatch and not inside its `unknown` arm: these
            # five type bytes are fields of the table below now, so a
            # version 0 psbt carrying one would be read rather than refused
            assert_not_a_v2_field(type_, psbt_version, _V2_FIELDS)
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
