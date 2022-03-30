#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Transaction Output (TxOut) dataclass.

Dataclass encapsulating value and script_pub_key
(and network to convert script_pub_key to and from address).
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Type, Union

from btclib import var_bytes
from btclib.alias import BinaryData, Octets, String
from btclib.amount import btc_from_sats, sats_from_btc, valid_sats_amount
from btclib.script.script_pub_key import ScriptPubKey
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


# FIXME make it frozen
@dataclass
class TxOut:
    # 8 bytes, unsigned little endian
    value: int  # denominated in satoshi
    script_pub_key: ScriptPubKey

    @property
    def nValue(self) -> int:  # pylint: disable=invalid-name
        "Return the nValue int for compatibility with CTxOut."
        return self.value

    @property
    def scriptPubKey(self) -> bytes:  # pylint: disable=invalid-name
        "Return the scriptPubKey bytes for compatibility with CTxOut."
        return self.script_pub_key.script

    def __init__(
        self,
        value: int,
        script_pub_key: Union[ScriptPubKey, Octets],
        check_validity: bool = True,
    ) -> None:

        object.__setattr__(self, "value", value)
        if not isinstance(script_pub_key, ScriptPubKey):
            script_bytes = bytes_from_octets(script_pub_key)
            script_pub_key = ScriptPubKey(script_bytes)
        object.__setattr__(self, "script_pub_key", script_pub_key)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        valid_sats_amount(self.value)
        # https://github.com/bitcoin/bitcoin/issues/320
        # self.script_pub_key.assert_valid()

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        script = self.script_pub_key.script
        return {
            "value": str(btc_from_sats(self.value)),
            "scriptPubKey": script.hex(),
            "type": self.script_pub_key.type,
            "reqSigs": None,  # FIXME
            "addresses": self.script_pub_key.addresses,
            "network": self.script_pub_key.network,
        }

    @classmethod
    def from_dict(
        cls: Type["TxOut"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "TxOut":

        value = sats_from_btc(dict_["value"])
        script_bin = dict_["scriptPubKey"]
        network = dict_.get("network", "mainnet")
        return cls(value, ScriptPubKey(script_bin, network), check_validity)

    # def is_witness(self) -> Tuple[bool, int, bytes]:
    #     return is_witness(self.script_pub_key)

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.value.to_bytes(8, byteorder="little", signed=False)
        out += var_bytes.serialize(self.script_pub_key.script)
        return out

    @classmethod
    def parse(
        cls: Type["TxOut"],
        data: BinaryData,
        check_validity: bool = True,
    ) -> "TxOut":
        stream = bytesio_from_binarydata(data)
        value = int.from_bytes(stream.read(8), byteorder="little", signed=False)
        script = var_bytes.parse(stream)
        return cls(
            value,
            ScriptPubKey(
                script, "mainnet", check_validity=False
            ),  # https://github.com/bitcoin/bitcoin/issues/320
            check_validity,
        )

    @classmethod
    def from_address(cls: Type["TxOut"], value: int, address: String) -> "TxOut":
        script_pub_key = ScriptPubKey.from_address(address)
        return cls(value, script_pub_key)
