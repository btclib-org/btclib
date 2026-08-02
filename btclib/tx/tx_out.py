#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Transaction Output (TxOut) dataclass.

Dataclass encapsulating value and script_pub_key (and network to convert
script_pub_key to and from address).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from btclib import var_bytes
from btclib.alias import BinaryData, Octets, String
from btclib.amount import btc_from_sats, sats_from_btc, valid_sats_amount
from btclib.script import ScriptPubKey, script_from_dict, script_to_dict
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


# frozen, as the FIXME here asked. Shallow: `value` is immutable, but
# ScriptPubKey extends the plain dataclass Script, so `script_pub_key.script`
# can still be rebound through a frozen TxOut. Freezing Script is a change
# of its own. Its being unhashable also makes the generated TxOut.__hash__
# raise TypeError, so a frozen TxOut is not a hashable one
@dataclass(frozen=True)
class TxOut:
    # 8 bytes, unsigned little endian
    value: int  # denominated in satoshi
    script_pub_key: ScriptPubKey

    @property
    def nValue(self) -> int:
        """Return the nValue int for compatibility with CTxOut."""
        return self.value

    @property
    def scriptPubKey(self) -> bytes:
        """Return the scriptPubKey bytes for compatibility with CTxOut."""
        return self.script_pub_key.script

    def __init__(
        self,
        value: int,
        script_pub_key: ScriptPubKey | Octets,
        *,
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
        # the amount and not the script: a script_pub_key on chain need
        # not parse, and validating it here would refuse transactions
        # that are in blocks -- bitcoin/bitcoin#320, and issue #123

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        # `reqSigs` is not here, and is not to be filled in: Bitcoin Core
        # removed it from every RPC that reported a script in v22
        # (bitcoin/bitcoin#20286), because it only ever answered for a bare
        # multisig -- the m of an m-of-n -- and was 1 or null for every
        # other script, so a consumer reading it as "signatures needed to
        # spend this" read a number that could not know. btclib's was the
        # null of that second case in *all* cases, a key whose value was a
        # constant. Keeping it would be a promise of a fact nobody has:
        # what spending takes is the redeem or witness script's business,
        # and a p2sh or p2wsh output does not carry one
        return {
            "value": str(btc_from_sats(self.value)),
            "scriptPubKey": script_to_dict(self.script_pub_key.script),
            "type": self.script_pub_key.type,
            "addresses": self.script_pub_key.addresses,
            "network": self.script_pub_key.network,
        }

    @classmethod
    def from_dict(
        cls: type[TxOut], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> TxOut:
        value = sats_from_btc(dict_["value"])
        script_bin = script_from_dict(dict_["scriptPubKey"])
        network = dict_.get("network", "mainnet")
        return cls(
            value, ScriptPubKey(script_bin, network), check_validity=check_validity
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.value.to_bytes(8, byteorder="little", signed=False)
        out += var_bytes.serialize(self.script_pub_key.script)
        return out

    @classmethod
    def parse(
        cls: type[TxOut],
        data: BinaryData,
        *,
        check_validity: bool = True,
    ) -> TxOut:
        stream = bytesio_from_binarydata(data)
        value = int.from_bytes(stream.read(8), byteorder="little", signed=False)
        script = var_bytes.parse(stream)
        return cls(
            value,
            ScriptPubKey(
                script, "mainnet", check_validity=False
            ),  # https://github.com/bitcoin/bitcoin/issues/320
            check_validity=check_validity,
        )

    @classmethod
    def from_address(cls: type[TxOut], value: int, address: String) -> TxOut:
        script_pub_key = ScriptPubKey.from_address(address)
        return cls(value, script_pub_key)
