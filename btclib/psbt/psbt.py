#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction (Psbt) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""
from __future__ import annotations

import base64
import random
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence, TypeVar

from btclib.alias import Octets, String
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import (
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_int,
    deserialize_map,
    deserialize_tx,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
)
from btclib.script import Witness, serialize, type_and_payload
from btclib.tx import Tx, join_txs
from btclib.utils import bytesio_from_binarydata

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
class Psbt:
    tx: Tx
    inputs: list[PsbtIn]
    outputs: list[PsbtOut]
    version: int
    hd_key_paths: HdKeyPaths
    unknown: dict[bytes, bytes]

    def __init__(
        self,
        tx: Tx,
        inputs: Sequence[PsbtIn],
        outputs: Sequence[PsbtOut],
        version: int,
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin],
        unknown: Mapping[Octets, Octets] | None = None,
        check_validity: bool = True,
    ) -> None:
        self.tx = tx
        self.inputs = list(inputs)
        self.outputs = list(outputs)
        self.version = version
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency."""
        self.tx.assert_valid()

        # ensure a non-null tx has been included
        if not (self.tx.vin and self.tx.vout):
            raise BTClibValueError("null transaction")

        # ensure the tx is unsigned
        if any(tx_in.script_sig or tx_in.script_witness for tx_in in self.tx.vin):
            raise BTClibValueError("non empty script_sig or witness")

        if len(self.tx.vin) != len(self.inputs):
            err_msg = "mismatched number of psb.tx.vin and psb.inputs: "
            err_msg += f"{len(self.tx.vin)} vs {len(self.inputs)}"
            raise BTClibValueError(err_msg)

        for psbt_in in self.inputs:
            psbt_in.assert_valid()

        if any(
            psbt_in.non_witness_utxo
            and psbt_in.non_witness_utxo.id != tx_in.prev_out.tx_id
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
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_unknown(self.unknown)

    def assert_signable(self) -> None:
        self.assert_valid()

        for i, tx_in in enumerate(self.tx.vin):
            non_witness_utxo = self.inputs[i].non_witness_utxo
            redeem_script = self.inputs[i].redeem_script
            # with python>=3.8 use walrus operator
            # if witness_utxo := self.inputs[i].witness_utxo:
            witness_utxo = self.inputs[i].witness_utxo
            if witness_utxo:
                script_pub_key = witness_utxo.script_pub_key
                script_type, payload = type_and_payload(script_pub_key.script)
                if script_type == "p2sh":
                    script_type, _ = type_and_payload(redeem_script)
                if script_type not in ("p2wpkh", "p2wsh"):
                    raise BTClibValueError("script type not it ('p2wpkh', 'p2wsh')")
            elif non_witness_utxo:
                script_pub_key = non_witness_utxo.vout[
                    tx_in.prev_out.vout
                ].script_pub_key
                _, payload = type_and_payload(script_pub_key.script)
            else:
                err_msg = "missing script_pub_key"
                raise BTClibValueError(err_msg)

            if redeem_script and payload != hash160(redeem_script):
                raise BTClibValueError("invalid redeem script hash160")

            if self.inputs[i].witness_script:
                if redeem_script:
                    _, payload = type_and_payload(redeem_script)
                if payload != sha256(self.inputs[i].witness_script):
                    raise BTClibValueError("invalid witness script sha256")

    def to_dict(self, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            "tx": self.tx.to_dict(),
            "inputs": [psbt_in.to_dict(False) for psbt_in in self.inputs],
            "outputs": [psbt_out.to_dict(False) for psbt_out in self.outputs],
            "version": self.version,
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: type[Psbt], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> Psbt:
        return cls(
            Tx.from_dict(dict_["tx"]),
            [PsbtIn.from_dict(psbt_in, False) for psbt_in in dict_["inputs"]],
            [PsbtOut.from_dict(psbt_out, False) for psbt_out in dict_["outputs"]],
            dict_["version"],
            # FIXME
            decode_from_bip32_derivs(dict_["bip32_derivs"]),  # type: ignore[arg-type]
            dict_["unknown"],
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        psbt_bin: list[bytes] = [PSBT_MAGIC_BYTES, PSBT_SEPARATOR]

        temp = self.tx.serialize(include_witness=False)
        psbt_bin.append(serialize_bytes(PSBT_GLOBAL_UNSIGNED_TX, temp))
        if self.version:
            temp = self.version.to_bytes(4, byteorder="little", signed=False)
            psbt_bin.append(serialize_bytes(PSBT_GLOBAL_VERSION, temp))
        if self.hd_key_paths:
            psbt_bin.append(serialize_hd_key_paths(PSBT_GLOBAL_XPUB, self.hd_key_paths))
        if self.unknown:
            psbt_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        psbt_bin.append(PSBT_DELIMITER)
        psbt_bin.extend(input_map.serialize() + b"\x00" for input_map in self.inputs)
        psbt_bin.extend(output_map.serialize() + b"\x00" for output_map in self.outputs)
        return b"".join(psbt_bin)

    @classmethod
    def parse(cls: type[Psbt], psbt_bin: Octets, check_validity: bool = True) -> Psbt:
        """Return a Psbt by parsing binary data."""
        # FIXME psbt_bin should be BinaryData
        # stream = bytesio_from_binarydata(psbt_bin)
        # and the deserialization should happen reading the stream
        # not slicing bytes

        tx = Tx(check_validity=False)
        version = 0
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        unknown: dict[Octets, Octets] = {}

        # psbt_bin = bytes_from_octets(psbt_bin)
        stream = bytesio_from_binarydata(psbt_bin)

        if stream.read(4) != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")
        if stream.read(1) != PSBT_SEPARATOR:
            raise BTClibValueError("malformed psbt: missing separator")

        global_map, stream = deserialize_map(stream)
        for k, v in global_map.items():
            if k[:1] == PSBT_GLOBAL_UNSIGNED_TX:
                tx = deserialize_tx(k, v, "global unsigned tx", False)
            elif k[:1] == PSBT_GLOBAL_VERSION:
                version = deserialize_int(k, v, "global version")
            elif k[:1] == PSBT_GLOBAL_XPUB:
                hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
            else:  # unknown
                unknown[k] = v

        inputs: list[PsbtIn] = []
        for _ in tx.vin:
            input_map, stream = deserialize_map(stream)
            inputs.append(PsbtIn.parse(input_map))

        outputs: list[PsbtOut] = []
        for _ in tx.vout:
            output_map, stream = deserialize_map(stream)
            outputs.append(PsbtOut.parse(output_map))

        return cls(
            tx,
            inputs,
            outputs,
            version,
            hd_key_paths,
            unknown,
            check_validity,
        )

    def b64encode(self, check_validity: bool = True) -> str:
        psbt_bin = self.serialize(check_validity)
        return base64.b64encode(psbt_bin).decode("ascii")

    @classmethod
    def b64decode(
        cls: type[Psbt], psbt_str: String, check_validity: bool = True
    ) -> Psbt:
        if isinstance(psbt_str, str):
            psbt_str = psbt_str.strip()

        psbt_decoded = base64.b64decode(psbt_str)

        return cls.parse(psbt_decoded, check_validity)

    @classmethod
    def from_tx(cls: type[Psbt], tx: Tx, check_validity: bool = True) -> Psbt:
        for tx_in in tx.vin:
            tx_in.script_sig = b""
            tx_in.script_witness = Witness()
        inputs = [PsbtIn() for _ in tx.vin]
        outputs = [PsbtOut() for _ in tx.vout]

        psbt_version = 0
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        unknown: dict[Octets, Octets] = {}

        return cls(
            tx,
            inputs,
            outputs,
            psbt_version,
            hd_key_paths,
            unknown,
            check_validity,
        )

    def sort_inputs(self, ordering_func: Callable[[PsbtIn], int] | None = None) -> None:
        """Sort psbt inputs.

        sorting logic is ordering_func if present, shuffle otherwise.
        """
        self.inputs, self.tx.vin = _sort_or_shuffle_together(
            self.inputs, self.tx.vin, ordering_func
        )

    def sort_outputs(
        self, ordering_func: Callable[[PsbtOut], int] | None = None
    ) -> None:
        """Sort psbt outputs.

        sorting logic is ordering_func if present, shuffle otherwise.
        """
        self.outputs, self.tx.vout = _sort_or_shuffle_together(
            self.outputs, self.tx.vout, ordering_func
        )


def _combine_field(
    psbt_map: PsbtIn | PsbtOut | Psbt, out: PsbtIn | PsbtOut | Psbt, key: str
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
        # TODO fails for final_script_witness
        # elif isinstance(item, list):
        #     additional_elements = [i for i in item if i not in attr]
        #     attr += additional_elements


def combine_psbts(psbts: Sequence[Psbt]) -> Psbt:
    """Merge Psbt data from multiple Psbts with same TxId.

    Basically used to merge signatures.
    """
    final_psbt = psbts[0]
    tx_id = psbts[0].tx.id
    for psbt in psbts[1:]:
        if psbt.tx.id != tx_id:
            raise BTClibValueError(f"mismatched psbt.tx.id: {psbt.tx.id.hex()}")

    final_psbt.version = max(psbt.version for psbt in psbts)
    for psbt in psbts[1:]:
        for i, inp in enumerate(final_psbt.inputs):
            _combine_field(psbt.inputs[i], inp, "non_witness_utxo")
            _combine_field(psbt.inputs[i], inp, "witness_utxo")
            _combine_field(psbt.inputs[i], inp, "partial_sigs")
            _combine_field(psbt.inputs[i], inp, "sig_hash_type")
            _combine_field(psbt.inputs[i], inp, "redeem_script")
            _combine_field(psbt.inputs[i], inp, "witness_script")
            _combine_field(psbt.inputs[i], inp, "hd_key_paths")
            _combine_field(psbt.inputs[i], inp, "final_script_sig")
            _combine_field(psbt.inputs[i], inp, "final_script_witness")
            _combine_field(psbt.inputs[i], inp, "unknown")

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "hd_key_paths")
            _combine_field(psbt.outputs[i], out, "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "hd_key_paths")
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
    # TODO finalizers must fail to finalize inputs
    # which have signatures that do not match the specified sign_ type
    for psbt_in in psbt.inputs:
        if not psbt_in.partial_sigs:
            raise BTClibValueError("missing signatures")
        sigs = psbt_in.partial_sigs.values()
        # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
        cmds: list[bytes] = [b""] if len(sigs) > 1 else []
        cmds += sigs
        if psbt_in.witness_script:
            psbt_in.final_script_sig = serialize([psbt_in.redeem_script])
            psbt_in.final_script_witness = Witness(cmds + [psbt_in.witness_script])
        else:
            psbt_in.final_script_sig = serialize(cmds + [psbt_in.redeem_script])
        psbt_in.partial_sigs = {}
        psbt_in.sig_hash_type = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.hd_key_paths = {}
    return psbt


def extract_tx(psbt: Psbt, check_validity: bool = True) -> Tx:
    """Extract the Tx fro the Psbt.

    The Transaction Extractor must only accept a PSBT.
    It checks whether all inputs have complete scriptSigs
    and scriptWitnesses by checking for the presence of
    0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed
    records.

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
    if check_validity:
        psbt.assert_valid()

    tx = psbt.tx
    for tx_in, psbt_input in zip(tx.vin, psbt.inputs):
        tx_in.script_sig = psbt_input.final_script_sig
        if psbt_input.final_script_witness:
            tx_in.script_witness = psbt_input.final_script_witness

    if check_validity:
        tx.assert_valid()
    return tx


TypeA = TypeVar("TypeA")
TypeB = TypeVar("TypeB")


def _sort_or_shuffle_together(
    sequence_a: Sequence[TypeA],
    sequence_b: Sequence[TypeB],
    ordering_func: Callable[[TypeA], int] | None = None,
) -> tuple[list[TypeA], list[TypeB]]:
    """Sort together with ordering_func if provided, else shuffle together.

    Sort is on TypeA, both sequences must have same length.
    """
    if len(sequence_a) != len(sequence_b):
        raise BTClibValueError("sequences must have same length")

    tmp = list(zip(sequence_a, sequence_b))
    if ordering_func is None:
        random.shuffle(tmp)
    else:
        tmp.sort(key=lambda t: ordering_func(t[0]))  # type: ignore
    tuple_a, tuple_b = zip(*tmp)
    return list(tuple_a), list(tuple_b)


def _ensure_consistency(psbts: Sequence[Psbt]) -> None:
    """Check validity of each psbt and conflicts in key_paths or unknown."""
    key_paths: dict[bytes, BIP32KeyOrigin] = {}
    r_key_paths: dict[BIP32KeyOrigin, bytes] = {}
    unknown: dict[bytes, bytes] = {}
    for psbt in psbts:
        psbt.assert_valid()

        if any(
            pub_key in key_paths and key_origin != key_paths[pub_key]
            for pub_key, key_origin in psbt.hd_key_paths.items()
        ):
            raise BTClibValueError("hd_key_paths: same pub_key, different key_origin")
        key_paths.update(psbt.hd_key_paths)

        if any(
            key_origin in r_key_paths and pub_key != r_key_paths[key_origin]
            for pub_key, key_origin in psbt.hd_key_paths.items()
        ):
            raise BTClibValueError("hd_key_paths: same key_origin, different pub_key")
        r_key_paths.update(
            {key_origin: pub_key for pub_key, key_origin in psbt.hd_key_paths.items()}
        )

        if any(
            key in unknown and value != unknown[key]
            for key, value in psbt.unknown.items()
        ):
            raise BTClibValueError("unknown: same key, different value")
        unknown.update(psbt.unknown)


def join_psbts(
    psbts: Sequence[Psbt],
    enforce_same_tx_version: bool,
    enforce_same_tx_lock_time: bool,
    merge_out: bool,
    shuffle_inp: bool,
    shuffle_out: bool,
    sort_inp: Callable[[PsbtIn], int] | None = None,
    sort_out: Callable[[PsbtOut], int] | None = None,
) -> Psbt:
    """Join multiple psbts into a single one by merging inputs and outputs.

    inputs/outputs are shuffled by default. If shuffle_{in|out}=False,
    they are simply concatenated in the same order as psbts are
    specified. A specific ordering can be specified via sort_{inp|out},
    which overwrite shuffle when present.
    """
    _ensure_consistency(psbts)

    inputs = [inp for psbt in psbts for inp in psbt.inputs]
    outputs = [outp for psbt in psbts for outp in psbt.outputs]
    hd_key_paths: dict[Octets, BIP32KeyOrigin] = {
        k: v for psbt in psbts for k, v in psbt.hd_key_paths.items()
    }
    unknown: dict[Octets, Octets] = {
        k: v for psbt in psbts for k, v in psbt.unknown.items()
    }
    version = max(psbt.version for psbt in psbts)

    merged_tx = join_txs(
        [psbt.tx for psbt in psbts],
        enforce_same_tx_version,
        enforce_same_tx_lock_time,
        False,
        False,
        False,
    )

    psbt = Psbt(merged_tx, inputs, outputs, version, hd_key_paths, unknown)
    if shuffle_inp or sort_inp:
        psbt.sort_inputs(sort_inp)
    if shuffle_out or sort_out:
        psbt.sort_outputs(sort_out)
    if merge_out:
        # TODO is it ok to merge outputs after sorting?
        raise BTClibValueError("output merge not implemented yet")

    psbt.assert_valid()
    return psbt
