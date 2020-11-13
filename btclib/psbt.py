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

from dataclasses_json import DataClassJsonMixin

from . import script, varbytes, varint
from .alias import ScriptToken
from .bip32 import str_from_bip32_path
from .psbt_in import PsbtIn
from .psbt_out import (
    PsbtOut,
    _assert_valid_bip32_derivs,
    _assert_valid_proprietary,
    _assert_valid_unknown,
    _deserialize_proprietary,
    _serialize_bip32_derivs,
    _serialize_proprietary,
    _serialize_unknown,
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
PSBT_GLOBAL_PROPRIETARY = b"\xfc"


@dataclass
class Psbt(DataClassJsonMixin):
    tx: Tx = field(default=Tx())
    inputs: List[PsbtIn] = field(default_factory=list)
    outputs: List[PsbtOut] = field(default_factory=list)
    version: int = 0
    bip32_derivs: List[Dict[str, str]] = field(default_factory=list)
    proprietary: Dict[int, Dict[str, str]] = field(default_factory=dict)
    unknown: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def deserialize(cls: Type[_Psbt], data: bytes, assert_valid: bool = True) -> _Psbt:

        out = cls()

        assert data[:4] == PSBT_MAGIC_BYTES, "malformed psbt: missing magic bytes"
        assert data[4:5] == PSBT_SEPARATOR, "malformed psbt: missing separator"

        global_map, data = deserialize_map(data[5:])
        for key, value in global_map.items():
            if key[0:1] == PSBT_GLOBAL_UNSIGNED_TX:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.tx = Tx.deserialize(value)  # legacy trensaction
            elif key[0:1] == PSBT_GLOBAL_VERSION:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert len(value) == 4, f"invalid version length: {len(value)}"
                out.version = int.from_bytes(value, "little")
            elif key[0:1] == PSBT_GLOBAL_XPUB:
                assert len(key) == 78 + 1, f"invalid xpub length: {len(key)-1}"
                out.bip32_derivs.append(
                    {
                        "pubkey": key[1:].hex(),
                        "master_fingerprint": value[:4].hex(),
                        "path": str_from_bip32_path(value[4:], "little"),
                    }
                )
            elif key[0:1] == PSBT_GLOBAL_PROPRIETARY:
                out.proprietary = _deserialize_proprietary(key, value)
            else:  # unknown
                out.unknown[key.hex()] = value.hex()

        assert out.tx.version, "missing transaction"
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

        out += b"\x01" + PSBT_GLOBAL_UNSIGNED_TX
        out += varbytes.encode(self.tx.serialize())
        if self.version:
            out += b"\x01" + PSBT_GLOBAL_VERSION
            out += b"\x04" + self.version.to_bytes(4, "little")
        if self.bip32_derivs:
            out += _serialize_bip32_derivs(self.bip32_derivs, PSBT_GLOBAL_XPUB)
        if self.proprietary:
            out += _serialize_proprietary(self.proprietary, PSBT_GLOBAL_PROPRIETARY)
        if self.unknown:
            out += _serialize_unknown(self.unknown)

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
        assert len(self.tx.vin) == len(
            self.inputs
        ), "mismatched number of tx.vin and psbt_in"
        for vin in self.tx.vin:
            assert vin.scriptSig == b""
            assert vin.txinwitness == []
        assert len(self.tx.vout) == len(
            self.outputs
        ), "mismatched number of tx.vout and psbt_out"

        for psbt_in in self.inputs:
            psbt_in.assert_valid()

        for psbt_out in self.outputs:
            psbt_out.assert_valid()

        # must be a 4-bytes int
        assert 0 <= self.version <= 0xFFFFFFFF
        # actually the only version that is currently handled is zero
        assert self.version == 0

        _assert_valid_bip32_derivs(self.bip32_derivs)
        _assert_valid_proprietary(self.proprietary)
        _assert_valid_unknown(self.unknown)

    def assert_signable(self) -> None:

        for i, tx_in in enumerate(self.tx.vin):

            non_witness_utxo = self.inputs[i].non_witness_utxo
            witness_utxo = self.inputs[i].witness_utxo

            if non_witness_utxo:
                txid = tx_in.prevout.txid
                assert isinstance(non_witness_utxo, Tx)
                assert non_witness_utxo.txid == txid

            if witness_utxo:
                assert isinstance(witness_utxo, TxOut)
                script_pubkey = witness_utxo.scriptPubKey
                script_type = payload_from_scriptPubKey(script_pubkey)[0]
                if script_type == "p2sh":
                    script_pubkey = self.inputs[i].redeem_script
                script_type = payload_from_scriptPubKey(script_pubkey)[0]
                assert script_type in ["p2wpkh", "p2wsh"]

            if self.inputs[i].redeem_script:
                if non_witness_utxo:
                    script_pubkey = non_witness_utxo.vout[
                        tx_in.prevout.vout
                    ].scriptPubKey
                elif witness_utxo:
                    script_pubkey = witness_utxo.scriptPubKey
                hash_ = hash160(self.inputs[i].redeem_script)
                assert hash_ == payload_from_scriptPubKey(script_pubkey)[1]

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
                assert hash_ == payload_from_scriptPubKey(script_pubkey)[1]


# FIXME: use stream, not repeated bytes slicing
def deserialize_map(data: bytes) -> Tuple[Dict[bytes, bytes], bytes]:
    assert len(data) != 0, "malformed psbt: at least a map is missing"
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
        assert key not in partial_map, f"duplicated psbt map: {key.hex()}"
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
        elif isinstance(item, list):
            # TODO: fails for final_script_witness
            additional_elements = [i for i in item if i not in attr]
            attr += additional_elements


def combine_psbts(psbts: List[Psbt]) -> Psbt:
    final_psbt = psbts[0]
    txid = psbts[0].tx.txid
    for psbt in psbts[1:]:
        assert psbt.tx.txid == txid

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
            _combine_field(psbt.inputs[i], inp, "por_commitment")
            _combine_field(psbt.inputs[i], inp, "proprietary")
            _combine_field(psbt.inputs[i], inp, "unknown")

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "bip32_derivs")
            _combine_field(psbt.outputs[i], out, "proprietary")
            _combine_field(psbt.outputs[i], out, "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "version")
        _combine_field(psbt, final_psbt, "bip32_derivs")
        _combine_field(psbt, final_psbt, "proprietary")
        _combine_field(psbt, final_psbt, "unknown")

    return final_psbt


def finalize_psbt(psbt: Psbt) -> Psbt:
    psbt = deepcopy(psbt)
    for psbt_in in psbt.inputs:
        assert psbt_in.partial_signatures, "missing signatures"
        sigs = psbt_in.partial_signatures.values()
        multi_sig = len(sigs) > 1
        if psbt_in.witness_script:
            psbt_in.final_script_sig = script.serialize([psbt_in.redeem_script.hex()])
            psbt_in.final_script_witness = [b""] if multi_sig else []
            psbt_in.final_script_witness += [bytes.fromhex(sig) for sig in sigs]
            psbt_in.final_script_witness += [psbt_in.witness_script]
        else:
            # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
            final_script_sig: List[ScriptToken] = [0] if multi_sig else []
            final_script_sig += sigs
            final_script_sig += [psbt_in.redeem_script.hex()]
            psbt_in.final_script_sig = script.serialize(final_script_sig)
        psbt_in.partial_signatures = {}
        psbt_in.sighash = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.bip32_derivs = []
        psbt_in.por_commitment = None
    return psbt


def extract_tx(psbt: Psbt) -> Tx:
    tx = psbt.tx
    for i, vin in enumerate(tx.vin):
        vin.scriptSig = psbt.inputs[i].final_script_sig
        if psbt.inputs[i].final_script_witness:
            vin.txinwitness = psbt.inputs[i].final_script_witness
    return tx
