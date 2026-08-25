# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Partially Signed Bitcoin Transaction Output (PsbtOut).

Dataclass and functions.
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from btclib.alias import BinaryData, Octets
from btclib.amount import valid_sats_amount
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt_utils import (
    PSBT_SEPARATOR,
    assert_not_a_v2_field,
    assert_valid_musig2_participant_pub_keys,
    assert_valid_psbt_version,
    assert_valid_redeem_script,
    assert_valid_sp_v0_info,
    assert_valid_taproot_bip32_derivation,
    assert_valid_taproot_internal_key,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    decode_musig2_participant_pub_keys,
    decode_taproot_bip32,
    decode_taproot_tree,
    deserialize_bytes,
    deserialize_map,
    deserialize_sized_int,
    encode_dict_bytes_bytes,
    encode_musig2_participant_pub_keys,
    encode_taproot_tree,
    parse_musig2_participant_pub_keys,
    parse_taproot_bip32,
    parse_taproot_tree,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_musig2_participant_pub_keys,
    serialize_sized_int,
    serialize_taproot_bip32,
    serialize_taproot_tree,
    taproot_bip32_from_dict,
    taproot_bip32_to_dict,
)
from btclib.script import script_from_dict, script_to_dict
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
)

__all__ = [
    "PSBT_OUT_AMOUNT",
    "PSBT_OUT_BIP32_DERIVATION",
    "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS",
    "PSBT_OUT_REDEEM_SCRIPT",
    "PSBT_OUT_SCRIPT",
    "PSBT_OUT_SP_V0_INFO",
    "PSBT_OUT_SP_V0_LABEL",
    "PSBT_OUT_TAP_BIP32_DERIVATION",
    "PSBT_OUT_TAP_INTERNAL_KEY",
    "PSBT_OUT_TAP_TREE",
    "PSBT_OUT_WITNESS_SCRIPT",
    "PsbtOut",
]

PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
PSBT_OUT_AMOUNT = b"\x03"
PSBT_OUT_SCRIPT = b"\x04"
PSBT_OUT_TAP_INTERNAL_KEY = b"\x05"
PSBT_OUT_TAP_TREE = b"\x06"
PSBT_OUT_TAP_BIP32_DERIVATION = b"\x07"
PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = b"\x08"
PSBT_OUT_SP_V0_INFO = b"\x09"
PSBT_OUT_SP_V0_LABEL = b"\x0a"

# the output fields a version 0 output must not carry. Two are BIP370's:
# the amount and the script_pub_key, which a v0 output reads from the
# unsigned transaction. The other two are BIP375's, and are excluded from
# version 0 because what they are for cannot happen there -- a silent
# payment output has no script until the inputs are fixed, and a version 0
# psbt has no field to write the script into once they are
_V2_FIELDS = {
    PSBT_OUT_AMOUNT: "PSBT_OUT_AMOUNT",
    PSBT_OUT_SCRIPT: "PSBT_OUT_SCRIPT",
    PSBT_OUT_SP_V0_INFO: "PSBT_OUT_SP_V0_INFO",
    PSBT_OUT_SP_V0_LABEL: "PSBT_OUT_SP_V0_LABEL",
}
# 0xfc is reserved for proprietary use, and needs no constant of its own:
# explicit support for proprietary (and por) is unnecessary,
# see https://github.com/bitcoin/bips/pull/1038


def _serialized_v2_fields(psbt_out: PsbtOut) -> list[bytes]:
    """Return the two BIP370 fields of an output map, in type-byte order.

    `is not None` for the amount, an output paying zero satoshi being an
    output; truthiness for the script, an empty one being what an output
    that does not carry the field has -- the two are indistinguishable
    here, and a psbt saying an output pays to no script at all is not
    one a Constructor writes.
    """
    serialized: list[bytes] = []
    if psbt_out.amount is not None:
        serialized.append(
            serialize_sized_int(PSBT_OUT_AMOUNT, psbt_out.amount, 8, signed=True)
        )
    if psbt_out.script_pub_key:
        serialized.append(serialize_bytes(PSBT_OUT_SCRIPT, psbt_out.script_pub_key))
    return serialized


# BIP375's two output fields, each of them one key-value pair with no key
# data: the name an error message reports, and the deserializer of the
# whole value. A table because they differ in nothing else, and because
# `parse` had no branch to spare
_SP_FIELDS: dict[bytes, tuple[str, Callable[[bytes, bytes, str], Any]]] = {
    PSBT_OUT_SP_V0_INFO: ("silent payment info", deserialize_bytes),
    PSBT_OUT_SP_V0_LABEL: (
        "silent payment label",
        lambda k, v, what: deserialize_sized_int(k, v, what, 4),
    ),
}


def _serialized_sp_fields(psbt_out: PsbtOut) -> list[bytes]:
    """Return the two BIP375 fields of an output map, in type-byte order.

    The label is `is not None` and not truthiness: 0 is the change label,
    which BIP352 reserves for the outputs a wallet pays to itself and
    asks a scanner to check always, so an output labelled 0 is the one
    output most likely to carry the field.
    """
    serialized: list[bytes] = []
    if psbt_out.sp_v0_info:
        serialized.append(serialize_bytes(PSBT_OUT_SP_V0_INFO, psbt_out.sp_v0_info))
    if psbt_out.sp_v0_label is not None:
        serialized.append(
            serialize_sized_int(PSBT_OUT_SP_V0_LABEL, psbt_out.sp_v0_label, 4)
        )
    return serialized


def _serialized_taproot_fields(psbt_out: PsbtOut) -> list[bytes]:
    """Return the three BIP371 fields of an output map, in type-byte order.

    Here rather than inline, as the BIP370 pair above is: what an output
    writes is one list per BIP, in ascending order of type byte, and
    `serialize` is then that order and nothing else.
    """
    serialized: list[bytes] = []
    if psbt_out.taproot_internal_key:
        serialized.append(
            serialize_bytes(PSBT_OUT_TAP_INTERNAL_KEY, psbt_out.taproot_internal_key)
        )
    if psbt_out.taproot_tree:
        serialized.append(
            serialize_taproot_tree(PSBT_OUT_TAP_TREE, psbt_out.taproot_tree)
        )
    if psbt_out.taproot_hd_key_paths:
        serialized.append(
            serialize_taproot_bip32(
                PSBT_OUT_TAP_BIP32_DERIVATION, psbt_out.taproot_hd_key_paths
            )
        )
    return serialized


@dataclass
class PsbtOut:
    """The per-output map of a psbt: one field per BIP174/BIP370 key type.

    The scripts and hd paths that let a wallet recognize an output as
    its own, BIP370's amount and script_pub_key of the output being
    built, and what no key type names in `unknown`. A field a psbt
    does not carry is None, or empty for the collection types.
    """

    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    taproot_internal_key: bytes
    taproot_tree: list[tuple[int, int, bytes]]
    taproot_hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]
    unknown: dict[bytes, bytes]
    amount: int | None
    script_pub_key: bytes
    musig2_participant_pub_keys: dict[bytes, list[bytes]]
    sp_v0_info: bytes
    sp_v0_label: int | None

    def __init__(
        self,
        redeem_script: Octets = b"",
        witness_script: Octets = b"",
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin] | None = None,
        taproot_internal_key: Octets = b"",
        taproot_tree: Sequence[tuple[int, int, Octets]] | None = None,
        taproot_hd_key_paths: Mapping[Octets, tuple[list[bytes], BIP32KeyOrigin]]
        | None = None,
        unknown: Mapping[Octets, Octets] | None = None,
        amount: int | None = None,
        script_pub_key: Octets = b"",
        musig2_participant_pub_keys: Mapping[Octets, Sequence[Octets]] | None = None,
        sp_v0_info: Octets = b"",
        sp_v0_label: int | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.taproot_internal_key = bytes_from_octets(taproot_internal_key)
        self.taproot_tree = decode_taproot_tree(taproot_tree)
        self.taproot_hd_key_paths = decode_taproot_bip32(taproot_hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))
        self.amount = amount
        self.script_pub_key = bytes_from_octets(script_pub_key)
        self.musig2_participant_pub_keys = decode_musig2_participant_pub_keys(
            musig2_participant_pub_keys
        )
        self.sp_v0_info = bytes_from_octets(sp_v0_info)
        self.sp_v0_label = sp_v0_label

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency.

        The two BIP370 fields are checked for what they hold and not for
        whether they are there: which of them an output must carry is the
        psbt's version, which an output on its own does not know, so
        Psbt.assert_valid asks that question (PsbtIn.assert_valid says
        the same of the five fields of an input).
        """
        if self.amount is not None:
            # BIP370 spells the amount as a signed 64-bit integer, as the
            # transaction does, and valid_sats_amount is the range every
            # other amount in btclib is held to: negative is not an
            # amount, and above MAX_MONEY is not one either
            valid_sats_amount(self.amount)

        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_taproot_internal_key(self.taproot_internal_key)
        assert_valid_taproot_bip32_derivation(self.taproot_hd_key_paths)
        assert_valid_musig2_participant_pub_keys(self.musig2_participant_pub_keys)

        assert_valid_sp_v0_info(self.sp_v0_info)
        if self.sp_v0_label is not None and not 0 <= self.sp_v0_label <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid silent payment label: {self.sp_v0_label}")
        # BIP375: "If this field is not included in the output, then the
        # field PSBT_OUT_SP_V0_INFO must be included" is said of the
        # script, and the label is the other way round -- it names the
        # label of an address the info field is the keys of, so a label
        # without an address labels nothing. One of BIP375's own invalid
        # vectors is exactly this
        if self.sp_v0_label is not None and not self.sp_v0_info:
            err_msg = "PSBT_OUT_SP_V0_LABEL without PSBT_OUT_SP_V0_INFO"
            raise BTClibValueError(err_msg)

        assert_valid_unknown(self.unknown)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the output map as a dict of json-friendly values.

        Keys are hex, hd paths are BIP174's bip32_derivs shape;
        from_dict reads the same shape back.
        """
        if check_validity:
            self.assert_valid()

        return {
            "redeem_script": script_to_dict(self.redeem_script),
            "witness_script": script_to_dict(self.witness_script),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "taproot_internal_key": self.taproot_internal_key.hex(),
            "taproot_tree": encode_taproot_tree(self.taproot_tree),
            "taproot_hd_key_paths": taproot_bip32_to_dict(self.taproot_hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
            "amount": self.amount,
            "script_pub_key": script_to_dict(self.script_pub_key),
            "musig2_participant_pub_keys": encode_musig2_participant_pub_keys(
                self.musig2_participant_pub_keys
            ),
            "sp_v0_info": self.sp_v0_info.hex(),
            "sp_v0_label": self.sp_v0_label,
        }

    @classmethod
    def from_dict(
        cls: type[PsbtOut], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> PsbtOut:
        """Build a PsbtOut from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "psbt output")
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            # check_validity=False, as for every other element here (issue
            # 264): PsbtOut.assert_valid below validates it as part of the whole
            decode_from_bip32_derivs(dict_["bip32_derivs"], check_validity=False),
        )
        taproot_hd_key_paths = cast(
            Mapping[Octets, tuple[list[bytes], BIP32KeyOrigin]],
            # and the same for the taproot derivations (issue 311)
            taproot_bip32_from_dict(
                dict_["taproot_hd_key_paths"], check_validity=False
            ),
        )
        return cls(
            script_from_dict(dict_["redeem_script"]),
            script_from_dict(dict_["witness_script"]),
            hd_key_paths,
            dict_["taproot_internal_key"],
            dict_["taproot_tree"],
            taproot_hd_key_paths,
            dict_["unknown"],
            dict_["amount"],
            script_from_dict(dict_["script_pub_key"]),
            dict_["musig2_participant_pub_keys"],
            dict_["sp_v0_info"],
            dict_["sp_v0_label"],
            check_validity=check_validity,
        )

    def serialize(self, *, psbt_version: int = 0, check_validity: bool = True) -> bytes:
        """Return the binary representation of the output map.

        psbt_version is the version of the psbt the map belongs to, and
        it decides whether the two BIP370 fields are written here or
        folded into the psbt's unsigned transaction; an output
        serialized on its own is written as version 0, the version
        BIP174 defines. It is asked for, and not read for its truth:
        every version that is not 0 wrote the BIP370 fields, so a `None`
        or a 3 wrote a version 2 output and said nothing.
        """
        assert_valid_psbt_version(psbt_version)

        if check_validity:
            self.assert_valid()

        psbt_out_bin: list[bytes] = []

        if self.redeem_script:
            psbt_out_bin.append(
                serialize_bytes(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)
            )

        if self.witness_script:
            psbt_out_bin.append(
                serialize_bytes(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)
            )

        if self.hd_key_paths:
            psbt_out_bin.append(
                serialize_hd_key_paths(PSBT_OUT_BIP32_DERIVATION, self.hd_key_paths)
            )

        # between 0x02 and 0x05 because that is where their type bytes
        # belong: the order the fields are written in is what a psbt's
        # bytes are compared against, and BIP370's own psbts are in
        # ascending order of type byte
        if psbt_version == 2:
            psbt_out_bin.extend(_serialized_v2_fields(self))

        psbt_out_bin.extend(_serialized_taproot_fields(self))

        if self.musig2_participant_pub_keys:
            psbt_out_bin.append(
                serialize_musig2_participant_pub_keys(
                    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
                    self.musig2_participant_pub_keys,
                )
            )

        # 0x09 and 0x0a, so after the musig2 field and before `unknown`
        if psbt_version == 2:
            psbt_out_bin.extend(_serialized_sp_fields(self))

        if self.unknown:
            psbt_out_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        # the map ends itself, as it does in Bitcoin Core
        # (PSBTOutput::Serialize); PsbtIn.serialize says why
        psbt_out_bin.append(PSBT_SEPARATOR)
        return b"".join(psbt_out_bin)

    @classmethod
    def parse(
        cls: type[PsbtOut],
        data: BinaryData,
        *,
        psbt_version: int = 0,
        check_validity: bool = True,
    ) -> PsbtOut:
        """Return a PsbtOut by parsing binary data.

        One map is read, its terminator included, which leaves the stream
        on the output after this one.

        psbt_version is the version of the psbt the map belongs to, which
        decides whether a BIP370 type byte is a field of this output or
        one this version must not carry; an output read on its own is
        read as version 0, the version BIP174 defines. Asked for as
        `serialize` asks for it, and for the same reason.

        Octets are one whole output and a stream is the caller's, as they
        are for the psbt these maps make: `Psbt.parse` threads one stream
        through the inputs and the outputs, and what follows an output in it
        is the next one.
        """
        assert_valid_psbt_version(psbt_version)

        stream = bytesio_from_binarydata(data)
        output_map = deserialize_map(stream)
        assert_no_trailing(data, stream, "psbt output")
        redeem_script = b""
        witness_script = b""
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        taproot_internal_key = b""
        taproot_tree: list[tuple[int, int, bytes]] = []
        taproot_hd_key_paths: dict[Octets, tuple[list[bytes], BIP32KeyOrigin]] = {}
        unknown: dict[Octets, Octets] = {}
        amount: int | None = None
        script_pub_key = b""
        musig2_participant_pub_keys: dict[Octets, Sequence[Octets]] = {}
        sp_fields: dict[bytes, Any] = {}

        # the three fields whose key carries key data, each of them as many
        # map entries as it has keys: the map they accumulate into, and the
        # parser of one entry's value. A table because they differ in
        # nothing else, one `elif` each having been three ways to write the
        # same two lines
        key_data_fields: dict[bytes, tuple[dict[Any, Any], Callable[[bytes], Any]]] = {
            PSBT_OUT_BIP32_DERIVATION: (hd_key_paths, BIP32KeyOrigin.parse),
            PSBT_OUT_TAP_BIP32_DERIVATION: (taproot_hd_key_paths, parse_taproot_bip32),
            PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: (
                musig2_participant_pub_keys,
                parse_musig2_participant_pub_keys,
            ),
        }

        for k, v in output_map.items():
            # before the dispatch and not in its `unknown` arm: 0x03 and
            # 0x04 are fields of this output now, so a version 0 psbt
            # carrying one would be read rather than refused
            assert_not_a_v2_field(k[:1], psbt_version, _V2_FIELDS)
            if k[:1] == PSBT_OUT_AMOUNT:
                amount = deserialize_sized_int(k, v, "amount", 8, signed=True)
            elif k[:1] == PSBT_OUT_SCRIPT:
                script_pub_key = deserialize_bytes(k, v, "script")
            elif k[:1] == PSBT_OUT_REDEEM_SCRIPT:
                redeem_script = deserialize_bytes(k, v, "redeem script")
            elif k[:1] == PSBT_OUT_WITNESS_SCRIPT:
                witness_script = deserialize_bytes(k, v, "witness script")
            elif k[:1] == PSBT_OUT_TAP_INTERNAL_KEY:
                taproot_internal_key = deserialize_bytes(k, v, "taproot internal key")
            elif k[:1] == PSBT_OUT_TAP_TREE:
                taproot_tree = parse_taproot_tree(v)
            elif (sp_field := _SP_FIELDS.get(k[:1])) is not None:
                # one branch for BIP375's pair, and a table beside it: the
                # dispatch was at C901's limit, and the two differ in
                # nothing but the parser of a value with no key data
                what, deserialize = sp_field
                sp_fields[k[:1]] = deserialize(k, v, what)
            elif (key_data_field := key_data_fields.get(k[:1])) is not None:
                # one key at a time, a field of this kind being as many map
                # entries as it has keys
                accumulated, parse_value = key_data_field
                accumulated[k[1:]] = parse_value(v)
            else:  # unknown
                unknown[k] = v

        return cls(
            redeem_script,
            witness_script,
            hd_key_paths,
            taproot_internal_key,
            taproot_tree,
            taproot_hd_key_paths,
            unknown,
            amount,
            script_pub_key,
            musig2_participant_pub_keys,
            sp_fields.get(PSBT_OUT_SP_V0_INFO, b""),
            sp_fields.get(PSBT_OUT_SP_V0_LABEL),
            check_validity=check_validity,
        )
