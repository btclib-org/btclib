#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, Type, TypeVar

from dataclasses import dataclass
from .alias import Octets
from . import varint, tx
from .utils import hash256, bytes_from_octets

_BlockHeader = TypeVar("_BlockHeader", bound="BlockHeader")


@dataclass
class BlockHeader:
    version: int
    previousblockhash: str
    merkleroot: str
    time: int
    bits: int
    nonce: int

    @classmethod
    def deserialize(cls: Type[_BlockHeader], data: Octets) -> _BlockHeader:

        data = bytes_from_octets(data)

        version = int.from_bytes(data[0:4], "little")
        previousblockhash = data[4:36][::-1].hex()
        merkleroot = data[36:68][::-1].hex()
        timestamp = int.from_bytes(data[68:72], "little")
        bits = int.from_bytes(data[72:76], "little")
        nonce = int.from_bytes(data[76:80], "little")

        header = cls(
            version=version,
            previousblockhash=previousblockhash,
            merkleroot=merkleroot,
            time=timestamp,
            bits=bits,
            nonce=nonce,
        )

        return header

    def serialize(self) -> bytes:
        out = self.version.to_bytes(4, "little")
        out += bytes.fromhex(self.previousblockhash)[::-1]
        out += bytes.fromhex(self.merkleroot)[::-1]
        out += self.time.to_bytes(4, "little")
        out += self.bits.to_bytes(4, "little")
        out += self.nonce.to_bytes(4, "little")
        return out

    @property
    def hash(self) -> str:
        return hash256(self.serialize())[::-1].hex()

    def assert_valid(self) -> None:
        pass


_Block = TypeVar("_Block", bound="Block")


@dataclass
class Block:
    header: BlockHeader
    transactions: List[tx.Tx]

    @classmethod
    def deserialize(cls: Type[_Block], data: Octets) -> _Block:

        data = bytes_from_octets(data)

        header = BlockHeader.deserialize(data[:80])

        data = data[80:]
        transaction_count = varint.decode(data)
        data = data[len(varint.encode(transaction_count)) :]
        transactions: List[tx.Tx] = []
        coinbase = tx.Tx.deserialize(data)
        transactions.append(coinbase)
        data = data[len(coinbase.serialize()) :]
        for x in range(transaction_count - 1):
            transaction = tx.Tx.deserialize(data)
            transactions.append(transaction)
            data = data[len(transaction.serialize()) :]

        block = cls(header=header, transactions=transactions)

        block.assert_valid()

        return block

    def serialize(self, include_witness: bool = True) -> bytes:
        out = self.header.serialize()
        out += varint.encode(len(self.transactions))
        for transaction in self.transactions:
            out += transaction.serialize(include_witness)
        return out

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def weight(self) -> int:
        weight = 0
        for t in self.transactions:
            weight += t.weight
        return weight

    def assert_valid(self) -> None:
        for transaction in self.transactions[1:]:
            transaction.assert_valid()
        self.header.assert_valid()
        assert _generate_merkle_root(self.transactions) == self.header.merkleroot


def _generate_merkle_root(transactions: List[tx.Tx]) -> str:
    hashes = [bytes.fromhex(transaction.txid)[::-1] for transaction in transactions]
    hashes_buffer = []
    while len(hashes) != 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for x in range(len(hashes) // 2):
            hashes_buffer.append(hash256(hashes[2 * x] + hashes[2 * x + 1]))
        hashes = hashes_buffer[:]
        hashes_buffer = []
    return hashes[0][::-1].hex()
