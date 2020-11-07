#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction.

https://en.bitcoin.it/wiki/BIP_0174
"""

from base64 import b64decode, b64encode
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import der, varint
from .alias import Octets, String
from .bip32 import (
    BIP32KeyData,
    BIP32Path,
    bytes_from_bip32_path,
    str_from_bip32_path,
)
from .der import DERSig
from .script import SIGHASHES
from .scriptpubkey import payload_from_scriptPubKey
from .secpoint import bytes_from_point
from .to_pubkey import PubKey
from .tx import Tx
from .tx_in import witness_deserialize, witness_serialize
from .tx_out import TxOut
from .utils import (
    bytes_from_octets,
    hash160,
    sha256,
    token_or_string_to_hex_string,
)


def _pubkey_to_hex_string(pubkey: PubKey) -> str:
    if isinstance(pubkey, tuple):
        return bytes_from_point(pubkey).hex()
    elif isinstance(pubkey, BIP32KeyData):
        return (pubkey.key).hex()
    elif isinstance(pubkey, str):
        return pubkey

    return pubkey.hex()


@dataclass
class HdKeyPaths(DataClassJsonMixin):
    hd_keypaths: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def add_hd_keypath(self, key: PubKey, fingerprint: Octets, path: BIP32Path) -> None:

        key_str = _pubkey_to_hex_string(key)
        # assert key_str == pubkeyinfo_from_key(key)[0].hex()

        fingerprint_str = bytes_from_octets(fingerprint, 4).hex()
        path_str = str_from_bip32_path(path, "little")

        self.hd_keypaths[key_str] = {
            "fingerprint": fingerprint_str,
            "derivation_path": path_str,
        }

    def get_hd_keypath(self, key: PubKey) -> Tuple[str, str]:

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        entry = self.hd_keypaths[key_str]
        return entry["fingerprint"], entry["derivation_path"]

    def assert_valid(self) -> None:
        pass


@dataclass
class PartialSigs(DataClassJsonMixin):
    sigs: Dict[str, bytes] = field(default_factory=dict)

    def add_sig(self, key: PubKey, sig: DERSig):

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        r, s, sighash = der._deserialize(sig)
        sig_str = der._serialize(r, s, sighash)

        self.sigs[key_str] = sig_str

    def get_sig(self, key: PubKey) -> bytes:

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        return self.sigs[key_str]

    def assert_valid(self) -> None:
        pass


_PsbtIn = TypeVar("_PsbtIn", bound="PsbtIn")


@dataclass
class PsbtIn(DataClassJsonMixin):
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_sigs: PartialSigs = field(default_factory=PartialSigs)
    sighash: Optional[int] = None
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_keypaths: HdKeyPaths = field(default_factory=HdKeyPaths)
    final_script_sig: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    final_script_witness: List[bytes] = field(
        default_factory=list,
        metadata=config(encoder=lambda val: [v.hex() for v in val]),
    )
    por_commitment: Optional[str] = None
    proprietary: Dict[int, Dict[str, bytes]] = field(default_factory=dict)
    unknown: Dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        out = cls()
        for key, value in input_map.items():
            if key[0] == 0x00:  # non_witness_utxo
                assert len(key) == 1
                out.non_witness_utxo = Tx.deserialize(value)
            elif key[0] == 0x01:  # witness_utxo
                assert len(key) == 1
                out.witness_utxo = TxOut.deserialize(value)
            elif key[0] == 0x02:  # partial_sigs
                assert len(key) == 33 + 1
                out.partial_sigs.add_sig(key[1:], value)
            elif key[0] == 0x03:  # sighash
                assert len(key) == 1
                assert len(value) == 4
                out.sighash = int.from_bytes(value, "little")
            elif key[0] == 0x04:  # redeem_script
                assert len(key) == 1
                out.redeem_script = value
            elif key[0] == 0x05:  # witness_script
                assert len(key) == 1
                out.witness_script = value
            elif key[0] == 0x06:  # hd_keypaths
                if len(key) != 33 + 1:
                    raise ValueError(f"invalid key lenght: {len(key)-1}")
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0] == 0x07:  # final_script_sig
                assert len(key) == 1
                out.final_script_sig = value
            elif key[0] == 0x08:  # final_script_witness
                assert len(key) == 1
                out.final_script_witness = witness_deserialize(value)
            elif key[0] == 0x09:  # por_commitment
                assert len(key) == 1
                out.por_commitment = value.hex()  # TODO: bip127
            elif key[0] == 0xFC:  # proprietary
                prefix = varint.decode(key[1:])
                if prefix not in out.proprietary.keys():
                    out.proprietary[prefix] = {}
                key = key[1 + len(varint.encode(prefix)) :]
                out.proprietary[prefix][key.hex()] = value
            else:  # unknown keys
                out.unknown[key.hex()] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""
        if self.non_witness_utxo:
            out += b"\x01\x00"
            utxo = self.non_witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.witness_utxo:
            out += b"\x01\x01"
            utxo = self.witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.partial_sigs:
            for key, value in self.partial_sigs.sigs.items():
                out += b"\x22\x02" + bytes.fromhex(key)
                out += varint.encode(len(value)) + value
        if self.sighash:
            out += b"\x01\x03"
            out += b"\x04" + self.sighash.to_bytes(4, "little")
        if self.redeem_script:
            out += b"\x01\x04"
            out += varint.encode(len(self.redeem_script)) + self.redeem_script
        if self.witness_script:
            out += b"\x01\x05"
            out += varint.encode(len(self.witness_script)) + self.witness_script
        if self.hd_keypaths:
            for xpub, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                out += b"\x22\x06" + bytes.fromhex(xpub)
                keypath = bytes.fromhex(hd_keypath["fingerprint"])
                keypath += bytes_from_bip32_path(
                    hd_keypath["derivation_path"], "little"
                )
                out += varint.encode(len(keypath)) + keypath
        if self.final_script_sig:
            out += b"\x01\x07"
            out += varint.encode(len(self.final_script_sig)) + self.final_script_sig
        if self.final_script_witness:
            out += b"\x01\x08"
            wit = witness_serialize(self.final_script_witness)
            out += varint.encode(len(wit)) + wit
        if self.por_commitment:  # TODO
            out += b"\x01\x09"
            c = bytes.fromhex(self.por_commitment)
            out += varint.encode(len(c)) + c
        if self.proprietary:
            for (owner, dictionary) in self.proprietary.items():
                for key, value2 in dictionary.items():
                    key_bytes = b"\xfc" + varint.encode(owner) + bytes.fromhex(key)
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value2)) + value2
        if self.unknown:
            for key, value2 in self.unknown.items():
                out += varint.encode(len(key) // 2) + bytes.fromhex(key)
                out += varint.encode(len(value2)) + value2
        return out

    def assert_valid(self) -> None:
        if self.non_witness_utxo is not None:
            self.non_witness_utxo.assert_valid()
        if self.witness_utxo is not None:
            self.witness_utxo.assert_valid()
        self.partial_sigs.assert_valid()
        if self.sighash is not None:
            assert self.sighash in SIGHASHES, f"invalid sighash: {self.sighash}"
        assert isinstance(self.redeem_script, bytes)
        assert isinstance(self.witness_script, bytes)
        self.hd_keypaths.assert_valid()
        assert isinstance(self.final_script_sig, bytes)
        assert isinstance(self.final_script_witness, list)
        if self.por_commitment is not None:
            assert isinstance(self.por_commitment, str)
        assert isinstance(self.proprietary, dict)
        assert isinstance(self.unknown, dict)

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]


_PsbtOut = TypeVar("_PsbtOut", bound="PsbtOut")


@dataclass
class PsbtOut(DataClassJsonMixin):
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_keypaths: HdKeyPaths = field(default_factory=HdKeyPaths)
    proprietary: Dict[int, Dict[str, bytes]] = field(default_factory=dict)
    unknown: Dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def deserialize(
        cls: Type[_PsbtOut], output_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtOut:
        out = cls()
        for key, value in output_map.items():
            if key[0] == 0x00:
                assert len(key) == 1
                out.redeem_script = value
            elif key[0] == 0x01:
                assert len(key) == 1
                out.witness_script = value
            elif key[0] == 0x02:
                if len(key) != 33 + 1:
                    raise ValueError(f"invalid key lenght: {len(key)-1}")
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0] == 0xFC:  # proprietary use
                prefix = varint.decode(key[1:])
                if prefix not in out.proprietary.keys():
                    out.proprietary[prefix] = {}
                key = key[1 + len(varint.encode(prefix)) :]
                out.proprietary[prefix][key.hex()] = value
            else:  # unknown keys
                out.unknown[key.hex()] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""
        if self.redeem_script:
            out += b"\x01\x00"
            out += varint.encode(len(self.redeem_script)) + self.redeem_script
        if self.witness_script:
            out += b"\x01\x01"
            out += varint.encode(len(self.witness_script)) + self.witness_script
        if self.hd_keypaths:
            for xpub, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                out += b"\x22\x02" + bytes.fromhex(xpub)
                keypath = bytes.fromhex(hd_keypath["fingerprint"])
                keypath += bytes_from_bip32_path(
                    hd_keypath["derivation_path"], "little"
                )
                out += varint.encode(len(keypath)) + keypath
        if self.proprietary:
            for (owner, dictionary) in self.proprietary.items():
                for key, value in dictionary.items():
                    key_bytes = b"\xfc" + varint.encode(owner) + bytes.fromhex(key)
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value)) + value
        if self.unknown:
            for key, value in self.unknown.items():
                out += varint.encode(len(key) // 2) + bytes.fromhex(key)
                out += varint.encode(len(value)) + value
        return out

    def assert_valid(self) -> None:
        pass

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]


_PSbt = TypeVar("_PSbt", bound="Psbt")

_PSBT_MAGIC_BYTES = b"psbt\xff"


@dataclass
class Psbt(DataClassJsonMixin):
    tx: Tx = field(default=Tx())
    inputs: List[PsbtIn] = field(default_factory=list)
    outputs: List[PsbtOut] = field(default_factory=list)
    version: Optional[int] = 0
    hd_keypaths: HdKeyPaths = field(default_factory=HdKeyPaths)
    proprietary: Dict[int, Dict[str, bytes]] = field(default_factory=dict)
    unknown: Dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def deserialize(cls: Type[_PSbt], string: str, assert_valid: bool = True) -> _PSbt:
        data = b64decode(string)

        assert data[:5] == _PSBT_MAGIC_BYTES, "Malformed psbt: missing magic bytes"

        out = cls()

        global_map, data = deserialize_map(data[5:])
        for key, value in global_map.items():
            if key[0] == 0x00:
                assert len(key) == 1
                out.tx = Tx.deserialize(value)
            elif key[0] == 0x01:
                # TODO add test case
                # why extended key here?
                assert len(key) == 78 + 1, f"invalid key lenght: {len(key)-1}"
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0] == 0xFB:
                assert len(value) == 4
                out.version = int.from_bytes(value, "little")
            elif key[0] == 0xFC:
                prefix = varint.decode(key[1:])
                if prefix not in out.proprietary.keys():
                    out.proprietary[prefix] = {}
                key = key[1 + len(varint.encode(prefix)) :]
                out.proprietary[prefix][key.hex()] = value
            else:  # unknown keys
                out.unknown[key.hex()] = value

        out.inputs = []
        for _ in range(len(out.tx.vin)):
            input_map, data = deserialize_map(data)
            out.inputs.append(PsbtIn.deserialize(input_map))

        out.outputs = []
        for _ in range(len(out.tx.vout)):
            output_map, data = deserialize_map(data)
            out.outputs.append(PsbtOut.deserialize(output_map))

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> str:

        if assert_valid:
            self.assert_valid()

        out = _PSBT_MAGIC_BYTES

        out += b"\x01\x00"
        tx = self.tx.serialize()
        out += varint.encode(len(tx)) + tx
        if self.hd_keypaths:
            for xpub, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                out += b"\x4f\x01" + bytes.fromhex(xpub)
                keypath = bytes.fromhex(hd_keypath["fingerprint"])
                keypath += bytes_from_bip32_path(
                    hd_keypath["derivation_path"], "little"
                )
                out += varint.encode(len(keypath)) + keypath
        if self.version:
            out += b"\x01\xfb\x04"
            out += self.version.to_bytes(4, "little")
        if self.proprietary:
            for (owner, dictionary) in self.proprietary.items():
                for key, value in dictionary.items():
                    key_bytes = b"\xfc" + varint.encode(owner) + bytes.fromhex(key)
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value)) + value
        if self.unknown:
            for key, value in self.unknown.items():
                out += varint.encode(len(key) // 2) + bytes.fromhex(key)
                out += varint.encode(len(value)) + value
        out += b"\x00"
        for input_map in self.inputs:
            out += input_map.serialize() + b"\x00"
        for output_map in self.outputs:
            out += output_map.serialize() + b"\x00"
        return b64encode(out).decode("ascii")

    def assert_valid(self) -> None:
        self.tx.assert_valid()
        for vin in self.tx.vin:
            assert vin.scriptSig == b""
            assert vin.txinwitness == []
        for input_map in self.inputs:
            input_map.assert_valid()
        for output_map in self.outputs:
            output_map.assert_valid()

    def assert_signable(self) -> None:

        for i, tx_in in enumerate(self.tx.vin):

            non_witness_utxo = self.inputs[i].non_witness_utxo
            witness_utxo = self.inputs[i].witness_utxo

            if non_witness_utxo:
                txid = tx_in.prevout.hash
                assert isinstance(non_witness_utxo, Tx)
                assert non_witness_utxo.txid == txid

            if witness_utxo:
                assert isinstance(witness_utxo, TxOut)
                scriptPubKey = witness_utxo.scriptPubKey
                script_type = payload_from_scriptPubKey(scriptPubKey)[0]
                if script_type == "p2sh":
                    scriptPubKey = self.inputs[i].redeem_script
                script_type = payload_from_scriptPubKey(scriptPubKey)[0]
                assert script_type in ["p2wpkh", "p2wsh"]

            if self.inputs[i].redeem_script:
                if non_witness_utxo:
                    scriptPubKey = non_witness_utxo.vout[tx_in.prevout.n].scriptPubKey
                elif witness_utxo:
                    scriptPubKey = witness_utxo.scriptPubKey
                hash = hash160(self.inputs[i].redeem_script)
                assert hash == payload_from_scriptPubKey(scriptPubKey)[1]

            if self.inputs[i].witness_script:
                if non_witness_utxo:
                    scriptPubKey = non_witness_utxo.vout[tx_in.prevout.n].scriptPubKey
                elif witness_utxo:
                    scriptPubKey = witness_utxo.scriptPubKey
                if self.inputs[i].redeem_script:
                    scriptPubKey = self.inputs[i].redeem_script

                hash = sha256(self.inputs[i].witness_script)
                assert hash == payload_from_scriptPubKey(scriptPubKey)[1]

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]


def deserialize_map(data: bytes) -> Tuple[Dict[bytes, bytes], bytes]:
    assert len(data) != 0, "Malformed psbt: at least a map is missing"
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
        assert key not in partial_map.keys(), "Malformed psbt: duplicate keys"
        partial_map[key] = value


def psbt_from_tx(tx: Tx) -> Psbt:
    tx = deepcopy(tx)
    for input in tx.vin:
        input.scriptSig = b""
        input.txinwitness = []
    inputs = [PsbtIn() for _ in tx.vin]
    outputs = [PsbtOut() for _ in tx.vout]
    return Psbt(tx=tx, inputs=inputs, outputs=outputs)


def _combine_field(
    psbt_map: Union[PsbtIn, PsbtOut, Psbt], out: Union[PsbtIn, PsbtOut, Psbt], key: str
) -> None:
    item = getattr(psbt_map, key)
    a = getattr(out, key)
    if isinstance(item, dict) and a and isinstance(a, dict):
        a.update(item)
    elif isinstance(item, dict) or item and not a:
        setattr(out, key, item)
    elif isinstance(item, PartialSigs) and isinstance(a, PartialSigs):
        a.sigs.update(item.sigs)
    elif isinstance(item, HdKeyPaths) and isinstance(a, HdKeyPaths):
        a.hd_keypaths.update(item.hd_keypaths)
    elif item:
        assert item == a, key


def combine_psbts(psbts: List[Psbt]) -> Psbt:
    final_psbt = psbts[0]
    txid = psbts[0].tx.txid
    for psbt in psbts[1:]:
        assert psbt.tx.txid == txid

    for psbt in psbts[1:]:

        for x in range(len(final_psbt.inputs)):
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "non_witness_utxo")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "witness_utxo")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "partial_sigs")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "sighash")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "redeem_script")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "witness_script")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "hd_keypaths")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "final_script_sig")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "final_script_witness")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "por_commitment")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "proprietary")
            _combine_field(psbt.inputs[x], final_psbt.inputs[x], "unknown")

        for _ in final_psbt.outputs:
            _combine_field(psbt.outputs[x], final_psbt.outputs[x], "redeem_script")
            _combine_field(psbt.outputs[x], final_psbt.outputs[x], "witness_script")
            _combine_field(psbt.outputs[x], final_psbt.outputs[x], "hd_keypaths")
            _combine_field(psbt.outputs[x], final_psbt.outputs[x], "proprietary")
            _combine_field(psbt.outputs[x], final_psbt.outputs[x], "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "version")
        _combine_field(psbt, final_psbt, "hd_keypaths")
        _combine_field(psbt, final_psbt, "proprietary")
        _combine_field(psbt, final_psbt, "unknown")

    return final_psbt


def finalize_psbt(psbt: Psbt) -> Psbt:
    psbt = deepcopy(psbt)
    for psbt_in in psbt.inputs:
        assert psbt_in.partial_sigs, "Missing signatures"
        if psbt_in.witness_script:
            psbt_in.final_script_sig = psbt_in.redeem_script
            if len(psbt_in.partial_sigs.sigs) > 1:
                psbt_in.final_script_witness = [b""]
            psbt_in.final_script_witness += psbt_in.partial_sigs.sigs.values()
            psbt_in.final_script_witness += [psbt_in.witness_script]
        else:
            # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
            if len(psbt_in.partial_sigs.sigs) > 1:
                psbt_in.final_script_sig = b"\x00"
            psbt_in.final_script_sig += b"".join(psbt_in.partial_sigs.sigs.values())
            psbt_in.final_script_sig += psbt_in.redeem_script
        psbt_in.partial_sigs = PartialSigs()
        psbt_in.sighash = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.hd_keypaths = HdKeyPaths()
        psbt_in.por_commitment = None
    return psbt


def extract_tx(psbt: Psbt) -> Tx:
    tx = psbt.tx
    for i, vin in enumerate(tx.vin):
        vin.scriptSig = psbt.inputs[i].final_script_sig
        if psbt.inputs[i].final_script_witness:
            vin.txinwitness = psbt.inputs[i].final_script_witness
    return tx
