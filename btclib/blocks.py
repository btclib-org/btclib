#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import tx, varint
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata, hash256

if sys.version_info.minor == 6:  # python 3.6
    from backports.datetime_fromisoformat import (  # pylint: disable=import-error
        MonkeyPatch,
    )

    MonkeyPatch.patch_fromisoformat()

_BlockHeader = TypeVar("_BlockHeader", bound="BlockHeader")


@dataclass
class BlockHeader(DataClassJsonMixin):
    version: int
    previousblockhash: str
    merkleroot: str
    time: int = field(  # TODO: fix tzinfo=timezone.utc
        metadata=config(
            encoder=lambda t: datetime.fromtimestamp(t).isoformat(),
            decoder=lambda t: datetime.fromisoformat(t).timestamp(),  # type: ignore
        ),
    )
    bits: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    nonce: int

    @classmethod
    def deserialize(
        cls: Type[_BlockHeader], data: BinaryData, assert_valid: bool = True
    ) -> _BlockHeader:
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

        if assert_valid:
            header.assert_valid()
        return header

    # def serialize(self, assert_valid: bool = True) -> bytes:
    def serialize(self) -> bytes:

        out = self.version.to_bytes(4, "little")
        out += bytes.fromhex(self.previousblockhash)[::-1]
        out += bytes.fromhex(self.merkleroot)[::-1]
        out += self.time.to_bytes(4, "little")
        out += self.bits[::-1]
        out += self.nonce.to_bytes(4, "little")

        # TODO: fix recursion
        # if assert_valid:
        #     self.assert_valid()
        return out

    def assert_valid(self) -> None:
        if not 1 <= self.version <= 0xFFFFFFFF:
            raise BTClibValueError("Invalid block header version")
        if len(self.previousblockhash) != 64:
            raise BTClibValueError("Invalid block previous hash length")
        if len(self.merkleroot) != 64:
            raise BTClibValueError("Invalid block merkle root length")
        target = int.from_bytes(self.bits[-3:], "big")
        exp: int = pow(256, (self.bits[0] - 3))
        target *= exp
        if int(self.hash, 16) > target:
            raise BTClibValueError("Invalid nonce")

    # TODO: add difficulty and target properties

    @property
    def hash(self) -> str:
        return hash256(self.serialize())[::-1].hex()


_Block = TypeVar("_Block", bound="Block")


@dataclass
class Block(DataClassJsonMixin):
    header: BlockHeader
    transactions: List[tx.Tx]

    @classmethod
    def deserialize(
        cls: Type[_Block], data: BinaryData, assert_valid: bool = True
    ) -> _Block:
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

        if assert_valid:
            block.assert_valid()
        return block

    def serialize(
        self, include_witness: bool = True, assert_valid: bool = True
    ) -> bytes:
        out = self.header.serialize()
        out += varint.encode(len(self.transactions))
        for transaction in self.transactions:
            out += transaction.serialize(include_witness)

        if assert_valid:
            self.assert_valid()
        return out

    def assert_valid(self) -> None:
        if not self.transactions[0].vin[0].prevout.is_coinbase:
            raise BTClibValueError("first transaction is not a coinbase")
        for transaction in self.transactions[1:]:
            transaction.assert_valid()
        merkel_root = _generate_merkle_root(self.transactions)
        if merkel_root != self.header.merkleroot:
            err_msg = f"invalid Merkle root: {self.header.merkleroot}"
            err_msg += f" instead of: {merkel_root}"
            raise BTClibValueError(err_msg)
        self.header.assert_valid()

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def weight(self) -> int:
        self.assert_valid()
        return sum(t.weight for t in self.transactions)


def _generate_merkle_root(transactions: List[tx.Tx]) -> str:
    hashes = [transaction.txid[::-1] for transaction in transactions]
    hashes_buffer = []
    while len(hashes) != 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for x in range(len(hashes) // 2):
            hashes_buffer.append(hash256(hashes[2 * x] + hashes[2 * x + 1]))
        hashes = hashes_buffer[:]
        hashes_buffer = []
    return hashes[0][::-1].hex()
