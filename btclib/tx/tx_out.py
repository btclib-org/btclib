# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The TxOut dataclass; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from btclib import var_bytes
from btclib.alias import BinaryData, Octets, String
from btclib.amount import btc_from_sats, sats_from_btc, valid_sats_amount
from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey, script_from_dict, script_to_dict
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
    read_exactly,
)

__all__ = [
    "TxOut",
]


# frozen all the way down: `value` is immutable and ScriptPubKey is frozen
# too (issue 165), so `tx_out.script_pub_key.script = b""` cannot reach
# through a frozen TxOut and rebind the script of whatever else holds that
# ScriptPubKey. Hashable all the way down for the same reason: the
# generated __hash__ hashes the ScriptPubKey field, which is itself
# hashable (issue 416), so a TxOut can be the value of the dict an
# OutPoint keys, or a set member of its own
@dataclass(frozen=True)
class TxOut:
    """One output of a transaction: an amount and who can spend it.

    The value is in satoshi; the script_pub_key is a ScriptPubKey,
    built from bytes when the caller passes them. assert_valid judges
    the amount and not the script, a script_pub_key on chain not
    having to parse.
    """

    # 8 bytes, little endian, signed -- Core's CAmount is int64_t, and
    # check_validity=False exposes that: the highest bit set parses as
    # negative rather than as a satoshi count twice MAX_MONEY (issue 388)
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
        elif check_validity:
            # the object branch asks what the octets branch asks. Building
            # one from octets validates it -- ScriptPubKey's own default --
            # so without this a network name the class refuses enters here
            # and travels on: a TxOut is what carries a script into a Tx's
            # outputs, a Block's transactions and PsbtIn.witness_utxo, and
            # assert_valid below judges the amount alone, on purpose.
            # What it asks is the network name and that the script is
            # bytes, not that the script parses -- Script.assert_valid
            # explains why nothing asks that, and why this cannot refuse a
            # script that is in a block
            script_pub_key.assert_valid()
        object.__setattr__(self, "script_pub_key", script_pub_key)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a value that is not a valid satoshi amount."""
        valid_sats_amount(self.value)
        # the amount and not the script's *contents*: a script_pub_key on
        # chain need not parse, and validating that here would refuse
        # transactions that are in blocks -- bitcoin/bitcoin#320, and issue
        # #123. What the object is asked is what ScriptPubKey asks itself,
        # the network name and that the script is bytes, neither of which
        # is a property of anything on chain. Here as well as in the
        # constructor, so that deferring the check and making it later
        # answer the same question: `check_validity=False` followed by
        # `assert_valid()` is the spelling every caller that builds a
        # TxOut by hand and validates it afterwards uses, and without this
        # that pair passed what the constructor alone refuses. The class is
        # frozen, so a field reassigned behind it is not the reason
        self.script_pub_key.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the output as a dict of json-friendly values.

        The value is a BTC string, not satoshi; type, addresses and
        network are derived for the reader and ignored by from_dict,
        which rebuilds them from the script -- network excepted, read
        back with mainnet as its default.
        """
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
        """Build a TxOut from the dict shape to_dict writes.

        A `null` value is not an amount here, where `valid_sats_amount`
        reads `None` as zero for the caller it was written for: a
        transaction output declares what it pays, so at the json boundary
        that value is a field the file has not filled in rather than a
        request for nothing. Unasked, `{"value": null}` built an output of
        zero satoshi -- legal, an OP_RETURN paying one and BIP322's
        proof-of-funds transactions carrying one, so nothing downstream
        refused it and what came back said something the file did not.

        `PsbtOut.amount` is the same value read the other way, and
        rightly: a psbt output may declare no amount yet, where a
        transaction output cannot.
        """
        dict_ = fields_from_json_object(dict_, "transaction output")
        if dict_["value"] is None:
            raise BTClibValueError("null transaction output value")
        value = sats_from_btc(dict_["value"])
        script_bin = script_from_dict(dict_["scriptPubKey"])
        network = dict_.get("network", "mainnet")
        return cls(
            value, ScriptPubKey(script_bin, network), check_validity=check_validity
        )

    def _serialized_size(self) -> int:
        """Return what serialize writes, without writing it."""
        return 8 + var_bytes._size(self.script_pub_key.script)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the wire serialization: the value, then the script.

        The value is written as CAmount, Core's signed int64_t: a valid
        amount is never negative, but check_validity=False lets one
        through and it must still fit in the eight bytes it came from.
        """
        if check_validity:
            self.assert_valid()

        out = self.value.to_bytes(8, byteorder="little", signed=True)
        out += var_bytes.serialize(self.script_pub_key.script)
        return out

    @classmethod
    def parse(
        cls: type[TxOut],
        data: BinaryData,
        *,
        check_validity: bool = True,
    ) -> TxOut:
        """Build a TxOut by parsing its wire serialization.

        The network is mainnet, the wire not carrying one; the script
        is taken as it comes, scripts on chain not having to parse. The
        value is read as CAmount, Core's signed int64_t: with
        check_validity=False, a high bit set parses negative -- as it
        does for Core -- rather than as an amount above MAX_MONEY.
        """
        stream = bytesio_from_binarydata(data)
        value = int.from_bytes(
            read_exactly(stream, 8, "output value"), byteorder="little", signed=True
        )
        script = var_bytes.parse(stream)
        assert_no_trailing(data, stream, "transaction output")
        return cls(
            value,
            ScriptPubKey(
                script, "mainnet", check_validity=False
            ),  # https://github.com/bitcoin/bitcoin/issues/320
            check_validity=check_validity,
        )

    @classmethod
    def from_address(cls: type[TxOut], value: int, address: String) -> TxOut:
        """Build a TxOut paying the address, network included."""
        script_pub_key = ScriptPubKey.from_address(address)
        return cls(value, script_pub_key)
