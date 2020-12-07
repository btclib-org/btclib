#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

import base64
from copy import deepcopy
from dataclasses import InitVar, dataclass, field
from typing import Dict, List, Tuple, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import script, var_int
from .alias import Octets, ScriptToken, String
from .exceptions import BTClibValueError
from .psbt_in import PsbtIn, _deserialize_int, _deserialize_tx
from .psbt_out import (
    PsbtOut,
    _assert_valid_hd_keypaths,
    _assert_valid_unknown,
    _decode_dict_bytes_bytes,
    _decode_hd_keypaths,
    _deserialize_hd_keypaths,
    _encode_dict_bytes_bytes,
    _encode_hd_keypaths,
    _serialize_bytes,
    _serialize_dict_bytes_bytes,
)
from .script_pub_key import payload_from_script_pub_key
from .tx import Tx
from .utils import bytes_from_octets, hash160, sha256
from .witness import Witness

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
    tx: Tx = Tx(check_validity=False)
    inputs: List[PsbtIn] = field(default_factory=list)
    outputs: List[PsbtOut] = field(default_factory=list)
    version: int = 0
    hd_keypaths: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            field_name="bip32_derivs",
            encoder=_encode_hd_keypaths,
            decoder=_decode_hd_keypaths,
        ),
    )
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        # PSBT Creator must create an unsigned transaction and
        # place it in the PSBT.
        if self.tx:
            if self.tx.vin:
                for inp in self.tx.vin:
                    inp.script_sig = b""
                    inp.witness = Witness()
                if not self.inputs:
                    self.inputs = [PsbtIn() for _ in self.tx.vin]
            if self.tx.vout and not self.outputs:
                self.outputs = [PsbtOut() for _ in self.tx.vout]

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        "Assert logical self-consistency."

        self.tx.assert_valid()

        # ensure a non-null tx has been included
        if not (self.tx.vin and self.tx.vout):
            raise BTClibValueError("null transaction")

        # ensure the tx is unsigned
        if any(tx_in.script_sig or tx_in.witness for tx_in in self.tx.vin):
            raise BTClibValueError("non empty script_sig or witness")

        if len(self.tx.vin) != len(self.inputs):
            err_msg = "mismatched number of psb.tx.vin and psb.inputs: "
            err_msg += f"{len(self.tx.vin)} vs {len(self.inputs)}"
            raise BTClibValueError(err_msg)

        for psbt_in in self.inputs:
            psbt_in.assert_valid()

        if any(
            psbt_in.non_witness_utxo
            and psbt_in.non_witness_utxo.tx_id != tx_in.prev_out.tx_id
            for psbt_in, tx_in in zip(self.inputs, self.tx.vin)
        ):
            err_msg = "mismatched non-witness utxo / outpoint tx_id"
            raise BTClibValueError(err_msg)

        if len(self.tx.vout) != len(self.outputs):
            err_msg = "mismatched number of psb.tx.vout and psbt.outputs: "
            err_msg += f"{len(self.tx.vout)} vs {len(self.outputs)}"
            raise BTClibValueError(err_msg)

        for psbt_out in self.outputs:
            psbt_out.assert_valid()

        _assert_valid_version(self.version)
        _assert_valid_hd_keypaths(self.hd_keypaths)
        _assert_valid_unknown(self.unknown)

    def assert_signable(self) -> None:

        self.assert_valid()

        for i, tx_in in enumerate(self.tx.vin):

            non_witness_utxo = self.inputs[i].non_witness_utxo
            witness_utxo = self.inputs[i].witness_utxo

            if witness_utxo:
                script_pub_key = witness_utxo.script_pub_key
                script_type = payload_from_script_pub_key(script_pub_key)[0]
                if script_type == "p2sh":
                    script_pub_key = self.inputs[i].redeem_script
                script_type = payload_from_script_pub_key(script_pub_key)[0]
                if script_type not in ("p2wpkh", "p2wsh"):
                    raise BTClibValueError("script type not it ('p2wpkh', 'p2wsh')")

            if self.inputs[i].redeem_script:
                if non_witness_utxo:
                    script_pub_key = non_witness_utxo.vout[
                        tx_in.prev_out.vout
                    ].script_pub_key
                elif witness_utxo:
                    script_pub_key = witness_utxo.script_pub_key
                hash_ = hash160(self.inputs[i].redeem_script)
                if hash_ != payload_from_script_pub_key(script_pub_key)[1]:
                    raise BTClibValueError("invalid redeem script hash")

            if self.inputs[i].witness_script:
                if non_witness_utxo:
                    script_pub_key = non_witness_utxo.vout[
                        tx_in.prev_out.vout
                    ].script_pub_key
                elif witness_utxo:
                    script_pub_key = witness_utxo.script_pub_key
                if self.inputs[i].redeem_script:
                    script_pub_key = self.inputs[i].redeem_script

                hash_ = sha256(self.inputs[i].witness_script)
                if hash_ != payload_from_script_pub_key(script_pub_key)[1]:
                    raise BTClibValueError("invalid witness script hash")

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        psbt_bin = PSBT_MAGIC_BYTES + PSBT_SEPARATOR

        temp = self.tx.serialize(include_witness=True)
        psbt_bin += _serialize_bytes(PSBT_GLOBAL_UNSIGNED_TX, temp)
        if self.version:
            temp = self.version.to_bytes(4, "little")
            psbt_bin += _serialize_bytes(PSBT_GLOBAL_VERSION, temp)
        if self.hd_keypaths:
            psbt_bin += _serialize_dict_bytes_bytes(PSBT_GLOBAL_XPUB, self.hd_keypaths)
        if self.unknown:
            psbt_bin += _serialize_dict_bytes_bytes(b"", self.unknown)

        psbt_bin += PSBT_DELIMITER
        for input_map in self.inputs:
            psbt_bin += input_map.serialize() + b"\x00"
        for output_map in self.outputs:
            psbt_bin += output_map.serialize() + b"\x00"
        return psbt_bin

    @classmethod
    def deserialize(
        cls: Type[_Psbt], psbt_bin: Octets, assert_valid: bool = True
    ) -> _Psbt:
        "Return a Psbt by parsing binary data."

        # FIXME: psbt_bin should be BinaryData
        # stream = bytesio_from_binarydata(psbt_bin)
        # and the deserialization should happen reading the stream
        # not slicing bytes
        psbt_bin = bytes_from_octets(psbt_bin)
        psbt = cls(check_validity=False)

        if psbt_bin[:4] != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")
        if psbt_bin[4:5] != PSBT_SEPARATOR:
            raise BTClibValueError("malformed psbt: missing separator")

        global_map, psbt_bin = deserialize_map(psbt_bin[5:])
        for k, v in global_map.items():
            if k[0:1] == PSBT_GLOBAL_UNSIGNED_TX:
                # legacy transaction
                psbt.tx = _deserialize_tx(k, v, "global unsigned tx")
            elif k[0:1] == PSBT_GLOBAL_VERSION:
                psbt.version = _deserialize_int(k, v, "global version")
            elif k[0:1] == PSBT_GLOBAL_XPUB:
                psbt.hd_keypaths.update(
                    _deserialize_hd_keypaths(k, v, "Psbt BIP32 xkey")
                )
            else:  # unknown
                psbt.unknown[k] = v

        for _ in psbt.tx.vin:
            input_map, psbt_bin = deserialize_map(psbt_bin)
            psbt.inputs.append(PsbtIn.deserialize(input_map))

        for _ in psbt.tx.vout:
            output_map, psbt_bin = deserialize_map(psbt_bin)
            psbt.outputs.append(PsbtOut.deserialize(output_map))

        if assert_valid:
            psbt.assert_valid()
        return psbt

    def b64encode(self, assert_valid: bool = True) -> bytes:
        psbt_bin = self.serialize(assert_valid)
        return base64.b64encode(psbt_bin)

    @classmethod
    def b64decode(
        cls: Type[_Psbt], psbt_str: String, assert_valid: bool = True
    ) -> _Psbt:
        if isinstance(psbt_str, str):
            psbt_str = psbt_str.strip()
        psbt_decoded = base64.b64decode(psbt_str)
        return cls.deserialize(psbt_decoded, assert_valid)


# FIXME: use stream, not repeated bytes slicing
def deserialize_map(psbt_bin: bytes) -> Tuple[Dict[bytes, bytes], bytes]:
    if len(psbt_bin) == 0:
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: Dict[bytes, bytes] = {}
    while True:
        if psbt_bin[0] == 0:
            psbt_bin = psbt_bin[1:]
            return partial_map, psbt_bin
        key_len = var_int.deserialize(psbt_bin)
        psbt_bin = psbt_bin[len(var_int.serialize(key_len)) :]
        key = psbt_bin[:key_len]
        psbt_bin = psbt_bin[key_len:]
        value_len = var_int.deserialize(psbt_bin)
        psbt_bin = psbt_bin[len(var_int.serialize(value_len)) :]
        value = psbt_bin[:value_len]
        psbt_bin = psbt_bin[value_len:]
        if key in partial_map:
            raise BTClibValueError(f"duplicated key in psbt map: 0x{key.hex()}")
        partial_map[key] = value


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
    tx_id = psbts[0].tx.tx_id
    for psbt in psbts[1:]:
        if psbt.tx.tx_id != tx_id:
            raise BTClibValueError(f"mismatched psbt.tx.tx_id: {psbt.tx.tx_id.hex()}")

    for psbt in psbts[1:]:

        for i, inp in enumerate(final_psbt.inputs):
            _combine_field(psbt.inputs[i], inp, "non_witness_utxo")
            _combine_field(psbt.inputs[i], inp, "witness_utxo")
            _combine_field(psbt.inputs[i], inp, "partial_sigs")
            _combine_field(psbt.inputs[i], inp, "sig_hash_type")
            _combine_field(psbt.inputs[i], inp, "redeem_script")
            _combine_field(psbt.inputs[i], inp, "witness_script")
            _combine_field(psbt.inputs[i], inp, "hd_keypaths")
            _combine_field(psbt.inputs[i], inp, "final_script_sig")
            _combine_field(psbt.inputs[i], inp, "final_script_witness")
            _combine_field(psbt.inputs[i], inp, "unknown")

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "hd_keypaths")
            _combine_field(psbt.outputs[i], out, "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "version")
        _combine_field(psbt, final_psbt, "hd_keypaths")
        _combine_field(psbt, final_psbt, "unknown")

    return final_psbt


def finalize_psbt(psbt: Psbt) -> Psbt:
    """Finalize the Psbt.

    The Input Finalizer must only accept a PSBT.

    For each input, the Input Finalizer determines
    if the input has enough data to pass validation.
    If it does, it must construct the
    0x07 Finalized scriptSig and
    0x08 Finalized scriptWitness
    and place them into the input key-value map.

    All other data except the UTXO and unknown fields
    in the input key-value map should be cleared from the PSBT.
    The UTXO should be kept to allow Transaction Extractors
    to verify the final network serialized transaction.
    """
    psbt = deepcopy(psbt)
    psbt.assert_valid()
    # TODO: finalizers must fail to finalize inputs
    # which have signatures that do not match the specified sign_hash type
    for psbt_in in psbt.inputs:
        if not psbt_in.partial_sigs:
            raise BTClibValueError("missing signatures")
        sigs = psbt_in.partial_sigs.values()
        multi_sig = len(sigs) > 1
        if psbt_in.witness_script:
            psbt_in.final_script_sig = script.serialize([psbt_in.redeem_script.hex()])
            psbt_in.final_script_witness = Witness([b""]) if multi_sig else Witness()
            psbt_in.final_script_witness.stack += sigs
            psbt_in.final_script_witness.stack += [psbt_in.witness_script]
        else:
            # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
            final_script_sig: List[ScriptToken] = [0] if multi_sig else []
            final_script_sig += [sig.hex() for sig in sigs]
            final_script_sig += [psbt_in.redeem_script.hex()]
            psbt_in.final_script_sig = script.serialize(final_script_sig)
        psbt_in.partial_sigs = {}
        psbt_in.sig_hash_type = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.hd_keypaths = {}
    return psbt


def extract_tx(psbt: Psbt, assert_valid: bool = True) -> Tx:
    """Extract the Tx fro the Psbt

    The Transaction Extractor must only accept a PSBT.
    It checks whether all inputs have complete scriptSigs
    and scriptWitnesses by checking for the presence of
    0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed records.

    If they do, the Transaction Extractor should construct
    complete scriptSigs and scriptWitnesses and encode them
    into network serialized transactions.
    Otherwise the Extractor must not modify the PSBT.

    The Extractor should produce a fully valid,
    network serialized transaction if all inputs are complete.

    The Transaction Extractor does not need to know
    how to interpret scripts in order to extract
    the network serialized transaction.
    However it may be able to in order to validate
    the network serialized transaction at the same time.
    """

    if assert_valid:
        psbt.assert_valid()

    tx = psbt.tx
    for tx_vin, psbt_input in zip(tx.vin, psbt.inputs):
        tx_vin.script_sig = psbt_input.final_script_sig
        if psbt_input.final_script_witness:
            tx_vin.witness = psbt_input.final_script_witness

    if assert_valid:
        tx.assert_valid()
    return tx
