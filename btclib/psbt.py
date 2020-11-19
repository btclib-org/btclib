#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from base64 import b64decode, b64encode
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import script, varint
from .alias import ScriptToken
from .exceptions import BTClibValueError
from .psbt_in import PsbtIn, _deserialize_int, _deserialize_tx
from .psbt_out import (
    PsbtOut,
    _assert_valid_bip32_derivs,
    _assert_valid_unknown,
    _decode_bip32_derivs,
    _decode_dict_bytes_bytes,
    _deserialize_bip32_derivs,
    _encode_bip32_derivs,
    _encode_dict_bytes_bytes,
    _serialize_bytes,
    _serialize_dict_bytes_bytes,
)
from .scriptpubkey import payload_from_scriptPubKey
from .tx import Tx
from .tx_out import TxOut
from .utils import hash160, sha256

_Psbt = TypeVar("_Psbt", bound="Psbt")

PSBT_MAGIC_BYTES = b"psbt"
PSBT_SEPARATOR = b"\xff"
PSBT_DELIMITER = b"\x00"

PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_XPUB = b"\x01"
PSBT_GLOBAL_VERSION = b"\xfb"
# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_GLOBAL_PROPRIETARY = b"\xfc"


def _assert_valid_version(version: int) -> None:

    # must be a 4-bytes int
    if not 0 <= version <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid version: {version}")
    # actually the only version that is currently handled is zero
    if version != 0:
        raise BTClibValueError(f"invalid non-zero version: {version}")


@dataclass
class Psbt(DataClassJsonMixin):
    tx: Tx = field(default=Tx())
    inputs: List[PsbtIn] = field(default_factory=list)
    outputs: List[PsbtOut] = field(default_factory=list)
    version: int = 0
    bip32_derivs: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(encoder=_encode_bip32_derivs, decoder=_decode_bip32_derivs),
    )
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )

    @classmethod
    def deserialize(cls: Type[_Psbt], data: bytes, assert_valid: bool = True) -> _Psbt:

        out = cls()

        if data[:4] != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")
        if data[4:5] != PSBT_SEPARATOR:
            raise BTClibValueError("malformed psbt: missing separator")

        global_map, data = deserialize_map(data[5:])
        for k, v in global_map.items():
            if k[0:1] == PSBT_GLOBAL_UNSIGNED_TX:
                # legacy transaction
                out.tx = _deserialize_tx(k, v, "global unsigned tx")
            elif k[0:1] == PSBT_GLOBAL_VERSION:
                out.version = _deserialize_int(k, v, "global version")
            elif k[0:1] == PSBT_GLOBAL_XPUB:
                out.bip32_derivs.update(
                    _deserialize_bip32_derivs(k, v, "Psbt BIP32 xkey")
                )
            else:  # unknown
                out.unknown[k] = v

        if not out.tx.version:
            raise BTClibValueError("missing transaction")
        for _ in out.tx.vin:
            input_map, data = deserialize_map(data)
            out.inputs.append(PsbtIn.deserialize(input_map))
        for _ in out.tx.vout:
            output_map, data = deserialize_map(data)
            out.outputs.append(PsbtOut.deserialize(output_map))

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = PSBT_MAGIC_BYTES + PSBT_SEPARATOR

        temp = self.tx.serialize()
        out += _serialize_bytes(PSBT_GLOBAL_UNSIGNED_TX, temp)
        if self.version:
            temp = self.version.to_bytes(4, "little")
            out += _serialize_bytes(PSBT_GLOBAL_VERSION, temp)
        if self.bip32_derivs:
            out += _serialize_dict_bytes_bytes(PSBT_GLOBAL_XPUB, self.bip32_derivs)
        if self.unknown:
            out += _serialize_dict_bytes_bytes(b"", self.unknown)

        out += PSBT_DELIMITER
        for input_map in self.inputs:
            out += input_map.serialize() + b"\x00"
        for output_map in self.outputs:
            out += output_map.serialize() + b"\x00"
        return out

    @classmethod
    def decode(cls: Type[_Psbt], string: str, assert_valid: bool = True) -> _Psbt:
        data = b64decode(string)
        return cls.deserialize(data, assert_valid)

    def encode(self, assert_valid: bool = True) -> str:
        out = self.serialize(assert_valid)
        return b64encode(out).decode("ascii")

    def assert_valid(self) -> None:
        "Assert logical self-consistency."

        self.tx.assert_valid()

        _assert_valid_version(self.version)
        _assert_valid_bip32_derivs(self.bip32_derivs)
        _assert_valid_unknown(self.unknown)

        if len(self.tx.vin) != len(self.inputs):
            raise BTClibValueError("mismatched number of tx.vin and psbt_in")
        for vin in self.tx.vin:
            if vin.scriptSig != b"":
                raise BTClibValueError("non empty scriptSig")
            if vin.txinwitness != []:
                raise BTClibValueError("non empty txinwitness")

        if len(self.tx.vout) != len(self.outputs):
            raise BTClibValueError("mismatched number of tx.vout and psbt_out")

        for psbt_in in self.inputs:
            psbt_in.assert_valid()

        for psbt_out in self.outputs:
            psbt_out.assert_valid()

    def assert_signable(self) -> None:

        for i, tx_in in enumerate(self.tx.vin):

            non_witness_utxo = self.inputs[i].non_witness_utxo
            witness_utxo = self.inputs[i].witness_utxo

            if non_witness_utxo:
                txid = tx_in.prevout.txid
                if non_witness_utxo.txid != txid:
                    err_msg = "invalid non_witness_utxo txid"
                    err_msg += f": {non_witness_utxo.txid.hex()}"
                    raise BTClibValueError(err_msg)

            if witness_utxo:
                if not isinstance(witness_utxo, TxOut):
                    raise BTClibValueError("witness_utxo is not a TxOut")
                script_pubkey = witness_utxo.scriptPubKey
                script_type = payload_from_scriptPubKey(script_pubkey)[0]
                if script_type == "p2sh":
                    script_pubkey = self.inputs[i].redeem_script
                script_type = payload_from_scriptPubKey(script_pubkey)[0]
                if script_type not in ("p2wpkh", "p2wsh"):
                    raise BTClibValueError("script type not it ('p2wpkh', 'p2wsh')")

            if self.inputs[i].redeem_script:
                if non_witness_utxo:
                    script_pubkey = non_witness_utxo.vout[
                        tx_in.prevout.vout
                    ].scriptPubKey
                elif witness_utxo:
                    script_pubkey = witness_utxo.scriptPubKey
                hash_ = hash160(self.inputs[i].redeem_script)
                if hash_ != payload_from_scriptPubKey(script_pubkey)[1]:
                    raise BTClibValueError("invalid redeem script hash")

            if self.inputs[i].witness_script:
                if non_witness_utxo:
                    script_pubkey = non_witness_utxo.vout[
                        tx_in.prevout.vout
                    ].scriptPubKey
                elif witness_utxo:
                    script_pubkey = witness_utxo.scriptPubKey
                if self.inputs[i].redeem_script:
                    script_pubkey = self.inputs[i].redeem_script

                hash_ = sha256(self.inputs[i].witness_script)
                if hash_ != payload_from_scriptPubKey(script_pubkey)[1]:
                    raise BTClibValueError("invalid witness script hash")


# FIXME: use stream, not repeated bytes slicing
def deserialize_map(data: bytes) -> Tuple[Dict[bytes, bytes], bytes]:
    if len(data) == 0:
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: Dict[bytes, bytes] = {}
    while True:
        if data[0] == 0:
            data = data[1:]
            return partial_map, data
        key_len = varint.decode(data)
        data = data[len(varint.encode(key_len)) :]
        key = data[:key_len]
        data = data[key_len:]
        value_len = varint.decode(data)
        data = data[len(varint.encode(value_len)) :]
        value = data[:value_len]
        data = data[value_len:]
        if key in partial_map:
            raise BTClibValueError(f"duplicated key in psbt map: 0x{key.hex()}")
        partial_map[key] = value


def psbt_from_tx(tx: Tx) -> Psbt:
    tx = deepcopy(tx)
    for inp in tx.vin:
        inp.scriptSig = b""
        inp.txinwitness = []
    inputs = [PsbtIn() for _ in tx.vin]
    outputs = [PsbtOut() for _ in tx.vout]
    return Psbt(tx=tx, inputs=inputs, outputs=outputs)


def _combine_field(
    psbt_map: Union[PsbtIn, PsbtOut, Psbt], out: Union[PsbtIn, PsbtOut, Psbt], key: str
) -> None:

    item = getattr(psbt_map, key)
    if not item:
        return
    attr = getattr(out, key)
    if not attr:
        setattr(out, key, item)
    elif attr != item:
        if isinstance(item, dict):
            attr.update(item)
        # TODO: fails for final_script_witness
        # elif isinstance(item, list):
        #     additional_elements = [i for i in item if i not in attr]
        #     attr += additional_elements


def combine_psbts(psbts: List[Psbt]) -> Psbt:
    final_psbt = psbts[0]
    txid = psbts[0].tx.txid
    for psbt in psbts[1:]:
        if psbt.tx.txid != txid:
            raise BTClibValueError(f"mismatched psbt.tx.txid: {psbt.tx.txid.hex()}")

    for psbt in psbts[1:]:

        for i, inp in enumerate(final_psbt.inputs):
            _combine_field(psbt.inputs[i], inp, "non_witness_utxo")
            _combine_field(psbt.inputs[i], inp, "witness_utxo")
            _combine_field(psbt.inputs[i], inp, "partial_signatures")
            _combine_field(psbt.inputs[i], inp, "sighash")
            _combine_field(psbt.inputs[i], inp, "redeem_script")
            _combine_field(psbt.inputs[i], inp, "witness_script")
            _combine_field(psbt.inputs[i], inp, "bip32_derivs")
            _combine_field(psbt.inputs[i], inp, "final_script_sig")
            _combine_field(psbt.inputs[i], inp, "final_script_witness")
            _combine_field(psbt.inputs[i], inp, "unknown")

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "bip32_derivs")
            _combine_field(psbt.outputs[i], out, "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "version")
        _combine_field(psbt, final_psbt, "bip32_derivs")
        _combine_field(psbt, final_psbt, "unknown")

    return final_psbt


def finalize_psbt(psbt: Psbt) -> Psbt:
    psbt = deepcopy(psbt)
    for psbt_in in psbt.inputs:
        if not psbt_in.partial_signatures:
            raise BTClibValueError("missing signatures")
        sigs = psbt_in.partial_signatures.values()
        multi_sig = len(sigs) > 1
        if psbt_in.witness_script:
            psbt_in.final_script_sig = script.serialize([psbt_in.redeem_script.hex()])
            psbt_in.final_script_witness = [b""] if multi_sig else []
            psbt_in.final_script_witness += sigs
            psbt_in.final_script_witness += [psbt_in.witness_script]
        else:
            # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
            final_script_sig: List[ScriptToken] = [0] if multi_sig else []
            final_script_sig += [sig.hex() for sig in sigs]
            final_script_sig += [psbt_in.redeem_script.hex()]
            psbt_in.final_script_sig = script.serialize(final_script_sig)
        psbt_in.partial_signatures = {}
        psbt_in.sighash = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.bip32_derivs = {}
    return psbt


def extract_tx(psbt: Psbt) -> Tx:
    tx = psbt.tx
    for i, vin in enumerate(tx.vin):
        vin.scriptSig = psbt.inputs[i].final_script_sig
        if psbt.inputs[i].final_script_witness:
            vin.txinwitness = psbt.inputs[i].final_script_witness
    return tx
