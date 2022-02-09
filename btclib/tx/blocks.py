#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Block dataclass.

Dataclass encapsulating BlockHeader and List[Tx].
"""

from dataclasses import dataclass
from math import ceil
from typing import Any, Dict, List, Mapping, Optional, Sequence, Type

from btclib import var_bytes, var_int
from btclib.alias import BinaryData
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256, merkle_root
from btclib.tx.block_header import BlockHeader
from btclib.tx.tx import Tx
from btclib.utils import bytesio_from_binarydata, decode_num

_HF = hash256


@dataclass
class Block:
    header: BlockHeader
    transactions: List[Tx]

    @property
    def size(self) -> int:
        return len(self.serialize(check_validity=False))

    @property
    def weight(self) -> int:
        return sum(t.weight for t in self.transactions)

    @property
    def vsize(self) -> int:
        return ceil(self.weight / 4)

    @property
    def height(self) -> Optional[int]:
        """Return the height committed into a BIP34 coinbase script_sig.

        Version 2 blocks commit block height into the coinbase script_sig.

        https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki

        Block 227,835 (2013-03-24 15:49:13 GMT) was the last version 1 block.
        """
        if not self.transactions[0].is_coinbase():
            raise BTClibValueError("first transaction is not a coinbase")

        if self.header.version == 1:
            return None

        # Height is "serialized CScript": first byte is number of bytes,
        # followed by the _signed_ little-endian representation of the height
        # (genesis block is height zero).
        coinbase_script = self.transactions[0].vin[0].script_sig
        height_ = var_bytes.parse(coinbase_script)
        return decode_num(height_)

    def __init__(
        self,
        header: BlockHeader,
        transactions: Optional[Sequence[Tx]] = None,
        check_validity: bool = True,
    ) -> None:

        self.header = header

        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.transactions = list(transactions) if transactions else []

        if check_validity:
            self.assert_valid()

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        return {
            "header": self.header.to_dict(False),
            "transactions": [tx.to_dict(False) for tx in self.transactions],
        }

    @classmethod
    def from_dict(
        cls: Type["Block"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "Block":

        return cls(
            BlockHeader.from_dict(dict_["header"], False),
            [Tx.from_dict(tx, False) for tx in dict_["transactions"]],
            check_validity,
        )

    def has_segwit_tx(self) -> bool:
        return any(tx.is_segwit() for tx in self.transactions)

    def assert_valid_merkle_root(self) -> None:
        data = [
            tx.serialize(include_witness=False, check_validity=False)
            for tx in self.transactions
        ]
        merkle_root_ = merkle_root(data, _HF)[::-1]
        if merkle_root_ != self.header.merkle_root:
            err_msg = f"invalid merkle root: {self.header.merkle_root.hex()}"
            err_msg += f" instead of: {merkle_root_.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid(self) -> None:

        self.header.assert_valid()

        if not self.transactions[0].is_coinbase():
            raise BTClibValueError("first transaction is not a coinbase")

        for transaction in self.transactions[1:]:
            transaction.assert_valid()

        self.assert_valid_merkle_root()

    def serialize(
        self, include_witness: bool = True, check_validity: bool = True
    ) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.header.serialize(check_validity)
        out += var_int.serialize(len(self.transactions))
        return out + b"".join(
            [t.serialize(include_witness, check_validity) for t in self.transactions]
        )

    @classmethod
    def parse(
        cls: Type["Block"], data: BinaryData, check_validity: bool = True
    ) -> "Block":
        "Return a Block by parsing binary data."

        stream = bytesio_from_binarydata(data)
        header = BlockHeader.parse(stream, check_validity)
        n = var_int.parse(stream)
        # TODO: is a block required to have a coinbase tx?
        transactions = [Tx.parse(stream, check_validity) for _ in range(n)]

        return cls(header, transactions, check_validity)
