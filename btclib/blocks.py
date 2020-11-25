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
from datetime import datetime, timezone
from typing import List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import varint
from .alias import BinaryData
from .exceptions import BTClibValueError
from .tx import Tx
from .utils import bytesio_from_binarydata, hash256, hex_string

if sys.version_info.minor == 6:  # python 3.6
    import backports.datetime_fromisoformat  # pylint: disable=import-error  # pragma: no cover

    backports.datetime_fromisoformat.MonkeyPatch.patch_fromisoformat()  # pragma: no cover

_BlockHeader = TypeVar("_BlockHeader", bound="BlockHeader")


@dataclass
class BlockHeader(DataClassJsonMixin):
    version: int = 0
    previous_block_hash: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    merkle_root: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    time: datetime = field(
        default=datetime.fromtimestamp(0),
        metadata=config(
            encoder=datetime.isoformat, decoder=datetime.fromisoformat  # type: ignore
        ),
    )
    bits: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    nonce: int = 0

    @classmethod
    def deserialize(
        cls: Type[_BlockHeader], data: BinaryData, assert_valid: bool = True
    ) -> _BlockHeader:
        stream = bytesio_from_binarydata(data)

        header = cls()
        header.version = int.from_bytes(stream.read(4), "little", signed=True)
        header.previous_block_hash = stream.read(32)[::-1]
        header.merkle_root = stream.read(32)[::-1]
        t = int.from_bytes(stream.read(4), "little")
        header.time = datetime.fromtimestamp(t, timezone.utc)
        header.bits = stream.read(4)[::-1]
        header.nonce = int.from_bytes(stream.read(4), "little")

        if assert_valid:
            header.assert_valid()
        return header

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.version.to_bytes(4, "little", signed=True)
        out += self.previous_block_hash[::-1]
        out += self.merkle_root[::-1]
        out += int(self.time.timestamp()).to_bytes(4, "little")
        out += self.bits[::-1]
        out += self.nonce.to_bytes(4, "little")

        return out

    def assert_valid(self) -> None:
        if not 0 < self.version <= 0x7FFFFFFF:
            raise BTClibValueError(f"invalid version: {hex(self.version)}")

        if len(self.previous_block_hash) != 32:
            err_msg = "invalid previous block hash"
            err_msg += f": {self.previous_block_hash.hex()}"
            raise BTClibValueError(err_msg)

        if len(self.merkle_root) != 32:
            err_msg = f"invalid merkle root: {hex_string(self.merkle_root)}"
            raise BTClibValueError(err_msg)

        if self.time.timestamp() < 1231006505:
            err_msg = "invalid timestamp (before genesis)"
            date = datetime.fromtimestamp(self.time.timestamp(), timezone.utc)
            err_msg += f": {date}"
            raise BTClibValueError(err_msg)

        if len(self.bits) != 4:
            raise BTClibValueError(f"invalid bits: {self.bits.hex()}")

        if not 0 < self.nonce <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid nonce: {hex(self.nonce)}")

        hash_ = int.from_bytes(self.hash, "big")
        if self.target <= hash_:
            err_msg = f"not enough work: {hex(hash_)}"
            err_msg += f" (target is: {hex(self.target)})"
            raise BTClibValueError(err_msg)

    @property
    def target(self) -> int:
        return int.from_bytes(self.bits[1:], "big") * pow(256, (self.bits[0] - 3))

    @property
    def difficulty(self) -> float:
        # mantissa ratio
        m = 0x00FFFF / int.from_bytes(self.bits[1:], "big")
        # exponent difference
        t = 26 - (self.bits[0] - 3)
        return m * pow(256, t)

    @property
    def hash(self) -> bytes:
        return hash256(self.serialize(assert_valid=False))[::-1]


_Block = TypeVar("_Block", bound="Block")


@dataclass
class Block(DataClassJsonMixin):
    header: BlockHeader = field(default=BlockHeader())
    transactions: List[Tx] = field(default_factory=list)

    @classmethod
    def deserialize(
        cls: Type[_Block], data: BinaryData, assert_valid: bool = True
    ) -> _Block:
        stream = bytesio_from_binarydata(data)

        block = cls()
        block.header = BlockHeader.deserialize(stream)
        n = varint.decode(stream)
        block.transactions = [Tx.deserialize(stream) for _ in range(n)]

        if assert_valid:
            block.assert_valid()
        return block

    def serialize(
        self, include_witness: bool = True, assert_valid: bool = True
    ) -> bytes:
        if assert_valid:
            self.assert_valid()

        out = self.header.serialize()
        out += varint.encode(len(self.transactions))
        return out + b"".join([t.serialize(include_witness) for t in self.transactions])

    def assert_valid(self) -> None:

        self.header.assert_valid()

        if not self.transactions[0].vin[0].prevout.is_coinbase:
            raise BTClibValueError("first transaction is not a coinbase")
        for transaction in self.transactions[1:]:
            transaction.assert_valid()

        merkel_root = _generate_merkle_root(self.transactions)
        if merkel_root != self.header.merkle_root:
            err_msg = f"invalid merkle root: {self.header.merkle_root.hex()}"
            err_msg += f" instead of: {merkel_root.hex()}"
            raise BTClibValueError(err_msg)

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def weight(self) -> int:
        self.assert_valid()
        return sum(t.weight for t in self.transactions)

    # TODO: implement vsize


def _generate_merkle_root(transactions: List[Tx]) -> bytes:
    hashes = [transaction.txid[::-1] for transaction in transactions]
    hashes_buffer = []
    while len(hashes) != 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for i in range(len(hashes) // 2):
            hashes_buffer.append(hash256(hashes[2 * i] + hashes[2 * i + 1]))
        hashes = hashes_buffer[:]
        hashes_buffer = []
    return hashes[0][::-1]
