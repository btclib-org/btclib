# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Partially Signed Bitcoin Transaction (Psbt) helper functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from io import BytesIO
from typing import Any

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.bip32 import BIP32KeyOrigin
from btclib.bip32.der_path import indexes_from_der_path, str_from_der_path
from btclib.curves import sec_point
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script.sig_hash import DEFAULT, SIG_HASH_TYPES
from btclib.script.taproot import assert_valid_control_block
from btclib.tx import Tx
from btclib.utils import (
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
    is_integer,
    list_from_json_array,
    read_exactly,
)

__all__ = [
    "FINGERPRINT_SIZE",
    "LEAF_HASH_SIZE",
    "MUSIG2_PARTIAL_SIG_SIZE",
    "MUSIG2_PUB_KEY_SIZE",
    "MUSIG2_PUB_NONCE_SIZE",
    "MUSIG2_SESSION_KEY_SIZES",
    "PSBT_SEPARATOR",
    "PSBT_V0",
    "PSBT_V2",
    "SP_DLEQ_PROOF_SIZE",
    "SP_ECDH_SHARE_SIZE",
    "SP_SCAN_KEY_SIZE",
    "SP_V0_INFO_SIZE",
    "SP_V0_INFO_VERSION",
    "SP_V0_LABEL_SIZE",
    "assert_not_a_v2_field",
    "assert_valid_leaf_scripts",
    "assert_valid_musig2_participant_pub_keys",
    "assert_valid_musig2_pub_key",
    "assert_valid_musig2_session_data",
    "assert_valid_psbt_version",
    "assert_valid_redeem_script",
    "assert_valid_sp_scan_key_map",
    "assert_valid_sp_v0_info",
    "assert_valid_taproot_bip32_derivation",
    "assert_valid_taproot_internal_key",
    "assert_valid_taproot_script_keys",
    "assert_valid_taproot_signatures",
    "assert_valid_unknown",
    "assert_valid_witness_script",
    "decode_dict_bytes_bytes",
    "decode_leaf_scripts",
    "decode_musig2_participant_pub_keys",
    "decode_taproot_bip32",
    "decode_taproot_tree",
    "deserialize_bytes",
    "deserialize_count",
    "deserialize_map",
    "deserialize_sized_int",
    "deserialize_tx",
    "encode_dict_bytes_bytes",
    "encode_leaf_scripts",
    "encode_musig2_participant_pub_keys",
    "encode_taproot_tree",
    "parse_leaf_script",
    "parse_musig2_participant_pub_keys",
    "parse_taproot_bip32",
    "parse_taproot_tree",
    "serialize_bytes",
    "serialize_count",
    "serialize_dict_bytes_bytes",
    "serialize_hd_key_paths",
    "serialize_leaf_scripts",
    "serialize_musig2_participant_pub_keys",
    "serialize_sized_int",
    "serialize_taproot_bip32",
    "serialize_taproot_tree",
    "taproot_bip32_from_dict",
    "taproot_bip32_to_dict",
]

# BIP371 defines the tap_bip32_derivation value as a compact size number
# of 32-byte leaf hashes, followed by the 4-byte master fingerprint and
# the derivation path
LEAF_HASH_SIZE = 32
FINGERPRINT_SIZE = 4

# every key BIP373 carries is a compressed point, and the BIP's own
# footnote says why not the x-only form the taproot fields use: BIP328
# derives BIP32 children of an aggregate key, which needs the evenness
# byte, and the master fingerprints of PSBT_IN_TAP_BIP32_DERIVATION need
# the y coordinate to be computed at all
MUSIG2_PUB_KEY_SIZE = 33

# what one contribution to one session is keyed by: the participant's own
# key, the aggregate key it is contributing to, and the tapleaf hash of
# the script being signed -- present when the aggregate key is a key in a
# script, omitted when it is the taproot internal or output key, which is
# the shorter of the two lengths
MUSIG2_SESSION_KEY_SIZES = (
    2 * MUSIG2_PUB_KEY_SIZE,
    2 * MUSIG2_PUB_KEY_SIZE + LEAF_HASH_SIZE,
)

# what each of the two rounds of BIP327 produces: NonceGen two points,
# Sign one scalar
MUSIG2_PUB_NONCE_SIZE = 66
MUSIG2_PARTIAL_SIG_SIZE = 32

# BIP375's four sizes. The scan key that keys the two ECDH fields is a
# compressed point, as the musig2 keys above are and for the same reason:
# a silent payment address publishes both keys in that form, so the psbt
# carries what the address carried
SP_SCAN_KEY_SIZE = MUSIG2_PUB_KEY_SIZE
# a share is one point, and a BIP374 proof is two scalars
SP_ECDH_SHARE_SIZE = MUSIG2_PUB_KEY_SIZE
SP_DLEQ_PROOF_SIZE = 64
# the two published keys of the address being paid, concatenated
SP_V0_INFO_SIZE = 2 * MUSIG2_PUB_KEY_SIZE
# the label as four bytes, little-endian here where BIP352 hashes it
# big-endian
SP_V0_LABEL_SIZE = 4
# the version byte the unique identifier prefixes the info with, so that
# what stands in for an output script cannot collide with a real one
SP_V0_INFO_VERSION = b"\x00"

# what ends every map of a psbt: a key of length zero, which no real key
# can be. It lives here, and not next to the magic bytes, because all
# three kinds of map write it -- the global one, and each input and
# output.
#
# The name is Bitcoin Core's, and it settles an ambiguity that is
# BIP174's own: the spec spells <magic> as the five bytes 0x70 0x73 0x62
# 0x74 0xFF, then calls the 0xff inside them a separator as well ("the
# separator is part of the 5 byte header"), so the word names two
# different bytes in one document. Here it names this one, and only this
# one; the 0xff has no constant of its own, being part of
# psbt.PSBT_MAGIC_BYTES, which is where the header says the rest
PSBT_SEPARATOR = b"\x00"

# the two versions there are, here rather than in `psbt.py` for the reason
# `assert_valid_psbt_version` below states: the maps take one as an
# argument, and they are underneath the psbt that has one as a field
PSBT_V0 = 0
PSBT_V2 = 2


def deserialize_map(data: BinaryData) -> dict[bytes, bytes]:
    """Return one map, read from the stream up to its 0x00 separator.

    The separator is consumed, so the stream is left on whatever comes
    after the map: threading one stream through is what reads the maps of
    a psbt in order. The map alone is handed back, the stream not being
    the function's to give -- a caller passing a stream already holds it,
    and one passing octets has nothing left to read from anyway.
    """
    stream = bytesio_from_binarydata(data)
    if len(stream.getbuffer()) == stream.tell():  # the end of the stream buffer
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: dict[bytes, bytes] = {}
    while True:
        # a map ends at its 0x00 separator; running out of buffer before
        # one is a truncated psbt, not the end of the map
        marker = stream.read(1)
        if not marker:
            raise BTClibValueError("malformed psbt: unterminated map")
        if marker[0] == 0:
            return partial_map
        stream.seek(-1, 1)  # reset stream position
        key = read_exactly(stream, var_int.parse(stream), "psbt map key")
        value = read_exactly(stream, var_int.parse(stream), "psbt map value")
        if key in partial_map:
            raise BTClibValueError(f"duplicated key in psbt map: 0x{key.hex()}")
        partial_map[key] = value


def serialize_hd_key_paths(
    type_: bytes, hd_key_paths: Mapping[bytes, BIP32KeyOrigin]
) -> bytes:
    """Return the binary representation of the dataclass element."""
    if len(type_) != 1:
        err_msg = f"invalid type marker length: {len(type_)}, instead of 1"
        raise BTClibValueError(err_msg)

    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v.serialize())
            for k, v in sorted(hd_key_paths.items())
        ]
    )


def deserialize_sized_int(
    k: bytes, v: bytes, type_: str, size: int, *, signed: bool = False
) -> int:
    """Return the int of a little-endian value of exactly `size` octets.

    The size is what makes the value one encoding of one number, and every
    fixed-width field of BIP174 and BIP370 needs it: a four-byte field
    written in five octets, or in one, deserializes to the same integer and
    serializes back to four, which is one psbt with several encodings --
    the malleability `read_exactly` refuses a level down, where the length
    is the map's rather than the field's.

    There is no unsized counterpart, and that is deliberate: the BIPs
    define no psbt integer field without a width, the two counts of BIP370
    being compact size and having `deserialize_count`. A helper reading a
    value of any length is a field boundary left to whoever writes the
    bytes.

    signed=True for an output's amount, the one field btclib reads as
    the signed integer the BIPs define. BIP370 defines the transaction
    version as signed too, and `btclib.psbt.psbt` reads it unsigned,
    with the reason at the two sites that do.
    """
    assert_type(signed, bool, "signed")
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    if len(v) != size:
        err_msg = f"invalid {type_} length: {len(v)} bytes instead of {size}"
        raise BTClibValueError(err_msg)
    return int.from_bytes(v, byteorder="little", signed=signed)


def deserialize_count(k: bytes, v: bytes, type_: str) -> int:
    """Return the count a compact size uint value holds.

    The two BIP370 counts are compact size, not fixed width, so the size
    check of deserialize_sized_int does not apply; what takes its place
    is that the whole value has to be the number. var_int.parse refuses
    a non-canonical encoding on its own, and octets left after it would
    be the same malleability by another route.
    """
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    stream = BytesIO(v)
    count = var_int.parse(stream)
    if stream.read():
        err_msg = f"invalid {type_}: {len(v)} bytes for a {len(var_int.serialize(count))}-byte count"
        raise BTClibValueError(err_msg)
    return count


def serialize_count(type_: bytes, count: int) -> bytes:
    """Return the binary representation of a compact size uint field."""
    return serialize_bytes(type_, var_int.serialize(count))


def serialize_sized_int(
    type_: bytes, value: int, size: int, *, signed: bool = False
) -> bytes:
    """Return the binary representation of a fixed-size integer field."""
    assert_type(signed, bool, "signed")
    return serialize_bytes(
        type_, value.to_bytes(size, byteorder="little", signed=signed)
    )


def encode_dict_bytes_bytes(dict_: Mapping[bytes, bytes]) -> dict[str, str]:
    """Return the json representation of the dataclass element."""
    # unknown could be sorted, partial_sigs cannot
    return {k.hex(): v.hex() for k, v in dict_.items()}


def decode_dict_bytes_bytes(map_: Mapping[Octets, Octets] | None) -> dict[bytes, bytes]:
    """Return the dataclass element from its json representation."""
    # unknown could be sorted, partial_sigs cannot
    if map_ is None:
        return {}
    return {bytes_from_octets(k): bytes_from_octets(v) for k, v in map_.items()}


def serialize_dict_bytes_bytes(
    type_: bytes, dictionary: Mapping[bytes, bytes]
) -> bytes:
    """Return the binary representation of the dataclass element."""
    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v)
            for k, v in sorted(dictionary.items())
        ]
    )


def encode_leaf_scripts(
    dict_: Mapping[bytes, tuple[bytes, int]],
) -> dict[str, tuple[str, int]]:
    """Return the json representation of a tap_leaf_script.

    A tap_leaf_script has a control block as key, and a taproot script
    and leaf version as value.
    """
    return {k.hex(): (v[0].hex(), v[1]) for k, v in dict_.items()}


def decode_leaf_scripts(
    map_: Mapping[Octets, tuple[Octets, int]] | None,
) -> dict[bytes, tuple[bytes, int]]:
    """Return a tap_leaf_script from its json representation."""
    if map_ is None:
        return {}
    return {
        bytes_from_octets(k): (bytes_from_octets(v[0]), v[1]) for k, v in map_.items()
    }


def serialize_leaf_scripts(
    type_: bytes, dictionary: dict[bytes, tuple[bytes, int]]
) -> bytes:
    """Return the binary representation of the tap_leaf_script."""
    return b"".join(
        [
            var_bytes.serialize(type_ + k)
            + var_bytes.serialize(v[0] + v[1].to_bytes(1, "big"))
            for k, v in sorted(dictionary.items())
        ]
    )


def parse_leaf_script(v: bytes) -> tuple[bytes, int]:
    """Split the script and the leaf version.

    BIP371 writes the value of a PSBT_IN_TAP_LEAF_SCRIPT as the script
    followed by the one byte of its leaf version, so an empty value is
    not a zero-length script: it is a record without the only field it
    is required to carry, which v[-1] would answer with an IndexError.
    """
    if not v:
        raise BTClibValueError("empty leaf script: no room for the leaf version")
    return (v[:-1], v[-1])


def encode_taproot_tree(
    list_: list[tuple[int, int, bytes]],
) -> list[tuple[int, int, str]]:
    """Return the json representation of a tap_tree.

    A tapree is a list of depth, leaf version, and taproot script.
    """
    return [(v[0], v[1], v[2].hex()) for v in list_]


def decode_taproot_tree(
    list_: Sequence[tuple[int, int, Octets]] | None,
) -> list[tuple[int, int, bytes]]:
    """Return a tap_tree from its json representation."""
    if list_ is None:
        return []
    return [(v[0], v[1], bytes_from_octets(v[2])) for v in list_]


def serialize_taproot_tree(type_: bytes, list_: list[tuple[int, int, bytes]]) -> bytes:
    """Return the binary representation of the tap_tree."""
    return var_bytes.serialize(type_) + var_bytes.serialize(
        b"".join(
            [
                v[0].to_bytes(1, "big")
                + v[1].to_bytes(1, "big")
                + var_bytes.serialize(v[2])
                for v in list_
            ]
        )
    )


def parse_taproot_tree(v: bytes) -> list[tuple[int, int, bytes]]:
    """Return a tap_tree from its bytes representation."""
    out: list[tuple[int, int, bytes]] = []

    stream = bytesio_from_binarydata(v)
    while True:
        v = stream.read(1)
        if not v:
            return out
        depth = int.from_bytes(v, "big")
        leaf_version = int.from_bytes(stream.read(1), "big")
        script = var_bytes.parse(stream)
        out.append((depth, leaf_version, script))


def taproot_bip32_to_dict(
    taproot_hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]],
) -> list[dict[str, Any]]:
    """Return the json representation of a tap_bip32_derivation.

    A tap_bip32_derivation is a list of leaf_hashes, master fingerprint,
    derivation path.
    """
    return [
        {
            "pub_key": pub_key.hex(),
            "leaf_hashes": [x.hex() for x in leaf_hashes],
            "master_fingerprint": key_origin.master_fingerprint.hex(),
            "path": str_from_der_path(key_origin.der_path),
        }
        for pub_key, (leaf_hashes, key_origin) in sorted(taproot_hd_key_paths.items())
    ]


def taproot_bip32_from_dict(
    taproot_hd_key_paths: list[dict[str, str]],
    *,
    check_validity: bool = True,
) -> dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]:
    """Return a tap_bip32_derivation from its json representation."""
    return {
        bytes_from_octets(bip32_deriv["pub_key"], 32 if check_validity else None): (
            [
                bytes_from_octets(x)
                for x in list_from_json_array(
                    bip32_deriv["leaf_hashes"], "taproot leaf hashes"
                )
            ],
            BIP32KeyOrigin(
                bytes_from_octets(
                    bip32_deriv["master_fingerprint"], 4 if check_validity else None
                ),
                indexes_from_der_path(bip32_deriv["path"]),
                check_validity=check_validity,
            ),
        )
        for bip32_deriv in (
            fields_from_json_object(item, "taproot bip32 derivation")
            for item in list_from_json_array(
                taproot_hd_key_paths, "taproot bip32 derivations"
            )
        )
    }


def decode_taproot_bip32(
    dict_: Mapping[Octets, tuple[Sequence[Octets], BIP32KeyOrigin]] | None,
) -> dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]:
    """Parse correctly the tap_bip32_derivation init arguments."""
    if dict_ is None:
        return {}
    taproot_bip32 = {
        bytes_from_octets(k): ([bytes_from_octets(x) for x in v[0]], v[1])
        for k, v in dict_.items()
    }
    return dict(sorted(taproot_bip32.items()))


def serialize_taproot_bip32(
    type_: bytes, dict_: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]
) -> bytes:
    """Return the binary representation of the tap_bip32_derivation."""
    return b"".join(
        [
            var_bytes.serialize(type_ + k)
            + var_bytes.serialize(
                var_int.serialize(len(v[0])) + b"".join(v[0]) + v[1].serialize()
            )
            for k, v in sorted(dict_.items())
        ]
    )


def parse_taproot_bip32(v: bytes) -> tuple[list[bytes], BIP32KeyOrigin]:
    """Return a tap_bip32_derivation from its bytes representation."""
    stream = bytesio_from_binarydata(v)
    len_ = var_int.parse(stream)
    # bound the allocation by the data actually available, not by the
    # count a counterparty declared: stream.read returns b"" past the end
    # of the stream without raising, so the comprehension below would
    # otherwise run len_ times whatever v is
    available = len(v) - stream.tell()
    if len_ * LEAF_HASH_SIZE + FINGERPRINT_SIZE > available:
        err_msg = f"invalid number of leaf hashes: {len_}"
        raise BTClibValueError(err_msg)
    leaves = [stream.read(LEAF_HASH_SIZE) for _ in range(len_)]
    bip32keyorigin = BIP32KeyOrigin.parse(stream.read())
    return (leaves, bip32keyorigin)


def parse_musig2_participant_pub_keys(v: bytes) -> list[bytes]:
    """Return the participants of one aggregate key, in aggregation order.

    BIP373 writes the value as the participants' compressed keys
    concatenated, so a value that is not a whole number of keys is not a
    list of them, and an empty one is a field naming an aggregate key
    with no participants -- which KeyAgg has no answer for.

    A list and not a set: the order is the order aggregation was done in,
    which decides the aggregate key, and BIP327's KeyAgg is where a
    reordering stops being the same key.
    """
    if not v or len(v) % MUSIG2_PUB_KEY_SIZE:
        err_msg = f"invalid musig2 participant pub keys: {len(v)} bytes, "
        err_msg += f"not a positive multiple of {MUSIG2_PUB_KEY_SIZE}"
        raise BTClibValueError(err_msg)
    return [
        v[i : i + MUSIG2_PUB_KEY_SIZE] for i in range(0, len(v), MUSIG2_PUB_KEY_SIZE)
    ]


def serialize_musig2_participant_pub_keys(
    type_: bytes, dict_: Mapping[bytes, Sequence[bytes]]
) -> bytes:
    """Return the binary representation of the musig2_participant_pub_keys."""
    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(b"".join(v))
            for k, v in sorted(dict_.items())
        ]
    )


def encode_musig2_participant_pub_keys(
    dict_: Mapping[bytes, Sequence[bytes]],
) -> dict[str, list[str]]:
    """Return the json representation of the musig2_participant_pub_keys."""
    return {k.hex(): [x.hex() for x in v] for k, v in sorted(dict_.items())}


def decode_musig2_participant_pub_keys(
    dict_: Mapping[Octets, Sequence[Octets]] | None,
) -> dict[bytes, list[bytes]]:
    """Parse correctly the musig2_participant_pub_keys init argument."""
    if dict_ is None:
        return {}
    participants = {
        bytes_from_octets(k): [bytes_from_octets(x) for x in v]
        for k, v in dict_.items()
    }
    return dict(sorted(participants.items()))


def assert_valid_musig2_pub_key(pub_key: bytes, what: str) -> None:
    """Raise unless the octets are a compressed secp256k1 public key.

    The length is what the four x-only vectors of BIP373 fail on. The
    point parse is what Bitcoin Core asks beyond it -- `IsFullyValid` on
    every key of every one of these fields -- and it is what makes 33
    octets a key rather than 33 octets: a psbt naming an aggregate key
    that is not on the curve names a session no signer can join.
    """
    if len(pub_key) != MUSIG2_PUB_KEY_SIZE:
        err_msg = f"invalid {what} length: {len(pub_key)} bytes "
        err_msg += f"instead of {MUSIG2_PUB_KEY_SIZE}"
        raise BTClibValueError(err_msg)
    try:
        sec_point.point_from_octets(pub_key)
    except BTClibValueError as e:
        raise BTClibValueError(f"invalid {what}: {pub_key.hex()}") from e


def assert_valid_musig2_participant_pub_keys(
    participants: Mapping[bytes, Sequence[bytes]],
) -> None:
    """Raise unless every key of a musig2_participant_pub_keys is one.

    The aggregate key is the key data and the participants are the value,
    which is the whole of what this field can be checked for on its own:
    that the participants aggregate to the key they are filed under is
    KeyAgg's answer, and asking it here would make a codec depend on a
    signing session.
    """
    for aggregate_pub_key, participant_pub_keys in participants.items():
        assert_valid_musig2_pub_key(aggregate_pub_key, "musig2 aggregate pub key")
        if not participant_pub_keys:
            err_msg = "invalid musig2 participant pub keys: "
            err_msg += f"none for aggregate key {aggregate_pub_key.hex()}"
            raise BTClibValueError(err_msg)
        for participant_pub_key in participant_pub_keys:
            assert_valid_musig2_pub_key(
                participant_pub_key, "musig2 participant pub key"
            )


def assert_valid_sp_scan_key_map(
    map_: Mapping[bytes, bytes], value_size: int, what: str
) -> None:
    """Raise unless every entry is a scan key against a value of its size.

    One rule for the four BIP375 fields keyed that way -- the global and
    per-input ECDH share, and the BIP374 proof of each -- because they
    differ in nothing but the size of the value: a share is a point and a
    proof is two scalars.

    The scan key is parsed and not merely measured, as the musig2 keys
    above are: a psbt filing a share under 33 octets that are no point
    names a recipient no address ever published, and the ECDH the value
    claims to be could not have been computed against it.

    What is *not* checked here is that the value is the share it claims to
    be. That is BIP374's answer, `btclib.ecc.dleq.verify_proof` over the
    input keys, and asking it here would make a codec verify a proof.
    """
    for scan_key, value in map_.items():
        assert_valid_musig2_pub_key(scan_key, f"{what} scan key")
        if len(value) != value_size:
            err_msg = f"invalid {what} length: {len(value)} bytes "
            err_msg += f"instead of {value_size}"
            raise BTClibValueError(err_msg)


def assert_valid_sp_v0_info(info: bytes) -> None:
    """Raise unless the octets are a silent payment address's two keys.

    The scan key and the spend key of the address being paid, in the
    compressed form the address itself carries them in, and both parsed:
    an output whose keys are not points is an output no Signer can derive
    a script for, and the field is what a Signer derives it from.
    """
    if not info:
        return
    if len(info) != SP_V0_INFO_SIZE:
        err_msg = f"invalid silent payment info length: {len(info)} bytes "
        err_msg += f"instead of {SP_V0_INFO_SIZE}"
        raise BTClibValueError(err_msg)
    assert_valid_musig2_pub_key(info[:SP_SCAN_KEY_SIZE], "silent payment scan key")
    assert_valid_musig2_pub_key(info[SP_SCAN_KEY_SIZE:], "silent payment spend key")


def assert_valid_musig2_session_data(
    session_data: Mapping[bytes, bytes], value_size: int, what: str
) -> None:
    """Raise unless every entry of a nonce or partial signature map fits.

    One rule for the two fields because BIP373 gives them one key -- the
    participant's key, the aggregate key, and the tapleaf hash or nothing
    -- and they differ only in the size of what a round produced.
    """
    for key, value in session_data.items():
        if len(key) not in MUSIG2_SESSION_KEY_SIZES:
            sizes = " or ".join(str(size) for size in MUSIG2_SESSION_KEY_SIZES)
            err_msg = f"invalid {what} key length: {len(key)} bytes instead of {sizes}"
            raise BTClibValueError(err_msg)
        assert_valid_musig2_pub_key(
            key[:MUSIG2_PUB_KEY_SIZE], "musig2 participant pub key"
        )
        assert_valid_musig2_pub_key(
            key[MUSIG2_PUB_KEY_SIZE : 2 * MUSIG2_PUB_KEY_SIZE],
            "musig2 aggregate pub key",
        )
        if len(value) != value_size:
            err_msg = f"invalid {what} length: {len(value)} bytes "
            err_msg += f"instead of {value_size}"
            raise BTClibValueError(err_msg)


def serialize_bytes(type_: bytes, value: bytes) -> bytes:
    """Return the binary representation of the dataclass element."""
    return var_bytes.serialize(type_) + var_bytes.serialize(value)


def deserialize_bytes(k: bytes, v: bytes, type_: str) -> bytes:
    """Return the dataclass element from its binary representation."""
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return v


def assert_valid_redeem_script(redeem_script: bytes) -> None:
    """Raise an exception if the dataclass element is not valid."""
    # should check for a valid script
    bytes(redeem_script)


def assert_valid_witness_script(witness_script: bytes) -> None:
    """Raise an exception if the dataclass element is not valid."""
    # should check for a valid script
    bytes(witness_script)


def assert_valid_unknown(data: Mapping[bytes, bytes]) -> None:
    """Raise an exception if the dataclass element is not valid."""
    for key, value in data.items():
        bytes(key)
        bytes(value)


def assert_valid_psbt_version(version: Any) -> None:
    """Refuse a psbt version that is not one of the two there are.

    Here rather than in `psbt.py`, where the psbt is: the version is as
    much an argument of `PsbtIn.serialize` and `PsbtOut.parse`, which
    decide by it whether the BIP370 fields belong to the map or to the
    unsigned transaction, and those two modules are underneath `psbt.py`
    and cannot import from it.

    The type before the range, as `Tx.assert_valid` checks its own two
    int fields: a comparison against a value of no integer type raises
    from underneath the library, and a bool passes every one of them as
    one or zero -- `to_dict`/`from_dict` being a json boundary, where
    `true` would be version 0 rather than a schema error.

    Then the two versions there are, which is a narrower rule than "a
    version btclib does not know": a psbt claiming version 3 is not a
    psbt of a later BIP, no such BIP being written. Version 1 is not one
    of them and never will be -- BIP370 skipped the number because
    version 0 had been colloquially called version 1 while it was being
    designed.
    """
    if not is_integer(version):
        raise BTClibTypeError(f"invalid version type: {type(version).__name__}")
    # must be a 4-bytes int
    if not 0 <= version <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid version: {version}")
    if version not in {PSBT_V0, PSBT_V2}:
        raise BTClibValueError(f"invalid psbt version: {version}")


def assert_not_a_v2_field(
    key_type: bytes, psbt_version: int, v2_fields: Mapping[bytes, str]
) -> None:
    """Refuse a BIP370 field in a psbt whose version excludes it.

    BIP370 lists 0 under "Versions Requiring Exclusion" for each of the
    twelve fields it defines, so a version 0 psbt carrying one of them
    is invalid rather than merely odd: the file says it is not version 2
    and then carries what only version 2 has.

    Filing the key under `unknown` instead accepts it and round-trips it
    byte for byte, which is the right answer for a type byte nobody has
    defined and the wrong one for a type byte this BIP defines and
    forbids here.

    Version 0 alone is refused: in a version 2 psbt these type bytes are
    the fields the parse is looking for, and the tables are what names
    them there too.
    """
    if psbt_version == 0 and (name := v2_fields.get(key_type)):
        raise BTClibValueError(f"{name} is not allowed in a v0 psbt")


def assert_valid_taproot_internal_key(key: bytes) -> None:
    """Fails when the internal pubkey has not the correct length."""
    if key and len(key) != 32:
        raise BTClibValueError("invalid taproot internal key length")


def assert_valid_taproot_script_keys(keys: list[bytes], err_msg: str) -> None:
    """Fails when the keys have not the correct length.

    Each key is the sum of a 32byte pubkey and a 32 byte leaf hash.
    """
    if any(key and len(key) != 64 for key in keys):
        raise BTClibValueError(err_msg)


def assert_valid_taproot_signatures(signatures: list[bytes], what: str) -> None:
    """Fails when a signature is not a BIP340 signature and its hash type.

    BIP341 spends a taproot output with 64 bytes of signature, or 65 when
    the sig_hash type is not the default one: the extra byte is that type,
    appended. BIP371 says "64 or 65 bytes" for both PSBT_IN_TAP_KEY_SIG
    and PSBT_IN_TAP_SCRIPT_SIG, and the script engine's get_hashtype
    already reads them that way -- requiring 64 alone here would keep a
    signature Bitcoin Core accepts out of a psbt (issue #122).

    0x00 is refused as the appended byte, as BIP341 refuses it and the
    engine does: SIGHASH_DEFAULT is what the 64-byte form means, so
    spelling it out is a second encoding of one signature.
    """
    for signature in signatures:
        if not signature:
            continue

        # 63 and 66 bytes are what BIP371's own two invalid vectors carry
        # for each of the two fields, so widening 64 to (64, 65) leaves
        # every one of them rejected
        if len(signature) not in {64, 65}:
            err_msg = f"invalid {what} length: {len(signature)} bytes"
            err_msg += " instead of 64 or 65"
            raise BTClibValueError(err_msg)

        if len(signature) == 65:
            sig_hash_type = signature[-1]
            if sig_hash_type == DEFAULT:
                err_msg = f"invalid {what}: explicit SIGHASH_DEFAULT"
                err_msg += "; the 64-byte signature is what means it"
                raise BTClibValueError(err_msg)
            # SIG_HASH_TYPES rather than a second list of the seven
            # values: it is the set the script engine and sig_hash.taproot
            # test against, and a psbt carrying what neither would accept
            # is a signature nothing can spend with
            if sig_hash_type not in SIG_HASH_TYPES:
                err_msg = f"invalid {what} sig_hash type: {hex(sig_hash_type)}"
                raise BTClibValueError(err_msg)


def assert_valid_taproot_bip32_derivation(
    derivations: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]],
) -> None:
    """Fails when the public keys have not the correct length."""
    for pubkey in derivations:
        if len(pubkey) != 32:
            raise BTClibValueError("invalid taproot bip32 derivation")


def assert_valid_leaf_scripts(leaf_scripts: dict[bytes, tuple[bytes, int]]) -> None:
    """Fails when the control blocks have not the correct length."""
    for control_block in leaf_scripts:
        assert_valid_control_block(control_block)


def deserialize_tx(
    k: bytes,
    v: bytes,
    type_: str,
    include_witness: bool | None = True,
    *,
    unsigned_template: bool = False,
) -> Tx:
    """Return the dataclass element from its binary representation.

    unsigned_template=True for a PSBT's global unsigned transaction, which
    is incomplete by construction and so cannot satisfy the "at least one
    input" and "at least one output" of Tx.assert_valid; see the docstring
    there. The other caller is a non-witness utxo, which is a complete
    transaction and gets the full check.

    The parse itself is unvalidated and assert_valid called afterwards:
    validating on the way in would report what is wrong with the
    transaction where what is wrong is the value. A witness serialization
    of a transaction with no outputs is such a value -- to be refused for
    the encoding this could not write back, where a validating parse
    answers "Missing outputs", which is true of it but not the fault.
    """
    # None is a declared value for include_witness -- "either encoding" --
    # and every other non-bool decides which one is accepted
    if include_witness is not None:
        assert_type(include_witness, bool, "include_witness")
    assert_type(unsigned_template, bool, "unsigned_template")
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    tx = Tx.parse(v, check_validity=False)
    if (
        not include_witness
        and tx.serialize(include_witness=False, check_validity=False) != v
    ):
        raise BTClibValueError("wrong tx serialization format")
    tx.assert_valid(unsigned_template=unsigned_template)
    return tx
