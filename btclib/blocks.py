#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass
from typing import List, Type, TypeVar

from . import tx, varint
from .alias import BinaryData
from .utils import bytesio_from_binarydata, hash256

_BlockHeader = TypeVar("_BlockHeader", bound="BlockHeader")


@dataclass
class BlockHeader:
    version: int
    previousblockhash: str
    merkleroot: str
    time: int
    bits: bytes
    nonce: int

    @classmethod
    def deserialize(cls: Type[_BlockHeader], data: BinaryData) -> _BlockHeader:
        stream = bytesio_from_binarydata(data)
        version = int.from_bytes(stream.read(4), "little")
        previousblockhash = stream.read(32)[::-1].hex()
        merkleroot = stream.read(32)[::-1].hex()
        timestamp = int.from_bytes(stream.read(4), "little")
        bits = stream.read(4)[::-1]
        nonce = int.from_bytes(stream.read(4), "little")
        header = cls(
            version=version,
            previousblockhash=previousblockhash,
            merkleroot=merkleroot,
            time=timestamp,
            bits=bits,
            nonce=nonce,
        )
        header.assert_valid()
        return header

    def serialize(self) -> bytes:
        out = self.version.to_bytes(4, "little")
        out += bytes.fromhex(self.previousblockhash)[::-1]
        out += bytes.fromhex(self.merkleroot)[::-1]
        out += self.time.to_bytes(4, "little")
        out += self.bits[::-1]
        out += self.nonce.to_bytes(4, "little")
        return out

    @property
    def hash(self) -> str:
        return hash256(self.serialize())[::-1].hex()

    def assert_valid(self) -> None:
        if not 1 <= self.version <= 0xFFFFFFFF:
            raise ValueError("Invalid block header version")
        if len(self.previousblockhash) != 64:
            raise ValueError("Invalid block previous hash length")
        if len(self.merkleroot) != 64:
            raise ValueError("Invalid block merkle root length")
        target = int.from_bytes(self.bits[-3:], "little")
        exp: int = pow(256, (self.bits[0] - 3))
        target *= exp
        if int.from_bytes(bytes.fromhex(self.hash), "big") > target:
            raise ValueError("Invalid nonce")


_Block = TypeVar("_Block", bound="Block")


@dataclass
class Block:
    header: BlockHeader
    transactions: List[tx.Tx]

    @classmethod
    def deserialize(cls: Type[_Block], data: BinaryData) -> _Block:
        stream = bytesio_from_binarydata(data)
        header = BlockHeader.deserialize(stream)
        transaction_count = varint.decode(stream)
        transactions: List[tx.Tx] = []
        coinbase = tx.Tx.deserialize(stream)
        transactions.append(coinbase)
        for _ in range(transaction_count - 1):
            transaction = tx.Tx.deserialize(stream)
            transactions.append(transaction)
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
        return sum(t.weight for t in self.transactions)

    def assert_valid(self) -> None:
        for transaction in self.transactions[1:]:
            transaction.assert_valid()
        if _generate_merkle_root(self.transactions) != self.header.merkleroot:
            raise ValueError(
                "The block merkle root is not the merkle root of the block transactions"
            )
        self.header.assert_valid()


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
