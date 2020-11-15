#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Input.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import dsa, secpoint, varbytes
from .exceptions import BTClibValueError
from .psbt_out import (
    _assert_valid_bip32_derivs,
    _assert_valid_proprietary,
    _assert_valid_unknown,
    _deserialize_proprietary,
    _serialize_dict_bytes_bytes,
    _serialize_proprietary,
    decode_bip32_derivs,
    decode_dict_bytes_bytes,
    encode_bip32_derivs,
    encode_dict_bytes_bytes,
)
from .script import SIGHASHES
from .tx import Tx
from .tx_in import witness_deserialize, witness_serialize
from .tx_out import TxOut

PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIGHASH_TYPE = b"\x03"
PSBT_IN_REDEEM_SCRIPT = b"\x04"
PSBT_IN_WITNESS_SCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_FINAL_SCRIPTSIG = b"\x07"
PSBT_IN_FINAL_SCRIPTWITNESS = b"\x08"
PSBT_IN_POR_COMMITMENT = b"\x09"
# TODO: add support for the following
# PSBT_IN_RIPEMD160 = b"\0x0a"
# PSBT_IN_SHA256 = b"\0x0b"
# PSBT_IN_HASH160 = b"\0x0c"
# PSBT_IN_HASH256 = b"\0x0d"
PSBT_IN_PROPRIETARY = b"\xfc"


def _assert_valid_partial_signatures(partial_signatures: Dict[bytes, bytes]) -> None:

    for pubkey, sig in partial_signatures.items():
        # pubkey must be a valid secp256k1 Point in SEC representation
        secpoint.point_from_octets(pubkey)
        if not dsa.deserialize(sig):
            raise BTClibValueError("invalid signature in partial_signatures")


_PsbtIn = TypeVar("_PsbtIn", bound="PsbtIn")


@dataclass
class PsbtIn(DataClassJsonMixin):
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_signatures: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=encode_dict_bytes_bytes, decoder=decode_dict_bytes_bytes
        ),
    )
    sighash: Optional[int] = None
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    bip32_derivs: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(encoder=encode_bip32_derivs, decoder=decode_bip32_derivs),
    )
    final_script_sig: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    final_script_witness: List[bytes] = field(
        default_factory=list,
        metadata=config(
            encoder=lambda val: [v.hex() for v in val],
            decoder=lambda val: [bytes.fromhex(v) for v in val],
        ),
    )
    por_commitment: Optional[str] = None
    proprietary: Dict[int, Dict[str, str]] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=encode_dict_bytes_bytes, decoder=decode_dict_bytes_bytes
        ),
    )

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        out = cls()
        for key, value in input_map.items():
            if key[0:1] == PSBT_IN_NON_WITNESS_UTXO:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_NON_WITNESS_UTXO key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.non_witness_utxo = Tx.deserialize(value)
            elif key[0:1] == PSBT_IN_WITNESS_UTXO:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_WITNESS_UTXO key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.witness_utxo = TxOut.deserialize(value)
            elif key[0:1] == PSBT_IN_PARTIAL_SIG:
                if len(key) not in (34, 66):
                    err_msg = "invalid PSBT_IN_PARTIAL_SIG SEC pubkey length"
                    err_msg += f": {len(key)-1} instead of (33, 65)"
                    raise BTClibValueError(err_msg)
                out.partial_signatures[key[1:]] = value
            elif key[0:1] == PSBT_IN_SIGHASH_TYPE:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_SIGHASH_TYPE key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                if len(value) != 4:
                    raise BTClibValueError(
                        "invalid value length in PSBT_IN_SIGHASH_TYPE"
                    )
                out.sighash = int.from_bytes(value, "little")
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTSIG:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_FINAL_SCRIPTSIG key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.final_script_sig = value
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                if len(key) != 1:
                    err_msg = (
                        f"invalid PSBT_IN_FINAL_SCRIPTWITNESS key length: {len(key)}"
                    )
                    raise BTClibValueError(err_msg)
                out.final_script_witness = witness_deserialize(value)
            elif key[0:1] == PSBT_IN_POR_COMMITMENT:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_POR_COMMITMENT key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.por_commitment = value.decode("utf-8")  # TODO: see bip127
            elif key[0:1] == PSBT_IN_REDEEM_SCRIPT:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_REDEEM_SCRIPT key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.redeem_script = value
            elif key[0:1] == PSBT_IN_WITNESS_SCRIPT:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_IN_WITNESS_SCRIPT key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.witness_script = value
            elif key[0:1] == PSBT_IN_BIP32_DERIVATION:
                if len(key) not in (34, 66):
                    err_msg = "invalid PSBT_IN_BIP32_DERIVATION pubkey length"
                    err_msg += f": {len(key)-1} instead of (33, 65)"
                    raise BTClibValueError(err_msg)
                out.bip32_derivs[key[1:]] = value
            elif key[0:1] == PSBT_IN_PROPRIETARY:
                out.proprietary = _deserialize_proprietary(key, value)
            else:  # unknown
                out.unknown[key] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.non_witness_utxo:
            out += b"\x01" + PSBT_IN_NON_WITNESS_UTXO
            out += varbytes.encode(self.non_witness_utxo.serialize())
        if self.witness_utxo:
            out += b"\x01" + PSBT_IN_WITNESS_UTXO
            out += varbytes.encode(self.witness_utxo.serialize())
        if self.partial_signatures:
            out += _serialize_dict_bytes_bytes(
                self.partial_signatures, PSBT_IN_PARTIAL_SIG
            )
        if self.sighash:
            out += b"\x01" + PSBT_IN_SIGHASH_TYPE
            out += b"\x04" + self.sighash.to_bytes(4, "little")
        if self.redeem_script:
            out += b"\x01" + PSBT_IN_REDEEM_SCRIPT
            out += varbytes.encode(self.redeem_script)
        if self.witness_script:
            out += b"\x01" + PSBT_IN_WITNESS_SCRIPT
            out += varbytes.encode(self.witness_script)
        if self.final_script_sig:
            out += b"\x01" + PSBT_IN_FINAL_SCRIPTSIG
            out += varbytes.encode(self.final_script_sig)
        if self.final_script_witness:
            out += b"\x01" + PSBT_IN_FINAL_SCRIPTWITNESS
            wit = witness_serialize(self.final_script_witness)
            out += varbytes.encode(wit)
        if self.por_commitment:
            out += b"\x01" + PSBT_IN_POR_COMMITMENT
            out += varbytes.encode(self.por_commitment.encode("utf-8"))
        if self.bip32_derivs:
            out += _serialize_dict_bytes_bytes(
                self.bip32_derivs, PSBT_IN_BIP32_DERIVATION
            )
        if self.proprietary:
            out += _serialize_proprietary(self.proprietary, PSBT_IN_PROPRIETARY)
        if self.unknown:
            out += _serialize_dict_bytes_bytes(self.unknown, b"")

        return out

    def assert_valid(self) -> None:
        if self.non_witness_utxo is not None:
            self.non_witness_utxo.assert_valid()

        if self.witness_utxo is not None:
            self.witness_utxo.assert_valid()

        if self.sighash is not None and self.sighash not in SIGHASHES:
            err_msg = f"invalid sighash: {self.sighash}"
            raise BTClibValueError(err_msg)

        if not isinstance(self.redeem_script, bytes):
            err_msg = "invalid redeem_script"
            raise BTClibValueError(err_msg)
        if not isinstance(self.witness_script, bytes):
            err_msg = "invalid witness_script"
            raise BTClibValueError(err_msg)
        if not isinstance(self.final_script_sig, bytes):
            err_msg = "invalid final_script_sig"
            raise BTClibValueError(err_msg)
        if not isinstance(self.final_script_witness, list):
            err_msg = "invalid final_script_witness"
            raise BTClibValueError(err_msg)

        if self.por_commitment is not None and not self.por_commitment.encode("utf-8"):
            err_msg = "invalid por_commitment"
            raise BTClibValueError(err_msg)

        _assert_valid_partial_signatures(self.partial_signatures)
        _assert_valid_bip32_derivs(self.bip32_derivs)
        _assert_valid_proprietary(self.proprietary)
        _assert_valid_unknown(self.unknown)
