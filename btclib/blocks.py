#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import sys
from dataclasses import InitVar, dataclass, field
from datetime import datetime, timezone
from math import ceil
from typing import Dict, List, Optional, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config
from dataclasses_json.core import Json

from . import var_bytes, var_int
from .alias import BinaryData
from .exceptions import BTClibValueError
from .tx import Tx
from .utils import bytesio_from_binarydata, hash256, hex_string, merkle_root

# python 3.6
if sys.version_info.minor == 6:  # pragma: no cover
    import backports.datetime_fromisoformat  # type: ignore # pylint: disable=import-error

    backports.datetime_fromisoformat.MonkeyPatch.patch_fromisoformat()


_BlockHeader = TypeVar("_BlockHeader", bound="BlockHeader")


@dataclass
class BlockHeader(DataClassJsonMixin):
    # 4 bytes, _signed_ little endian
    version: int = 0
    # 32 bytes, little endian
    previous_block_hash: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    # 32 bytes, little endian
    merkle_root: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    # 4 bytes, unsigned little endian
    time: datetime = field(
        default=datetime.fromtimestamp(0),
        metadata=config(
            encoder=datetime.isoformat, decoder=datetime.fromisoformat  # type: ignore
        ),
    )
    # 4 bytes, little endian
    bits: bytes = field(
        default=b"",
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    # 4 bytes, unsigned little endian
    nonce: int = 0
    # private data member used only for to_dict
    # use the corresponding public properties instead
    _target: bytes = field(
        default=b"",
        init=False,
        repr=False,
        compare=False,
        metadata=config(
            encoder=lambda v: v.hex(), decoder=bytes.fromhex, field_name="target"
        ),
    )
    _difficulty: float = field(
        default=-1.0,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="difficulty"),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def _set_properties(self) -> None:
        self._target = self.target
        self._difficulty = self.difficulty

    def to_dict(self, encode_json=False) -> Dict[str, Json]:
        self._set_properties()
        return super().to_dict(encode_json)

    @property
    def target(self) -> bytes:
        """Return the BlockHeader proof-of-work target.

        The target aabbcc * 256^dd is represented
        in scientific notation by the 4 bytes bits 0xaabbccdd
        """
        # significand (also known as mantissa or coefficient)
        significand = int.from_bytes(self.bits[1:], byteorder="big", signed=False)
        # power term, also called characteristics
        power_term = pow(256, (self.bits[0] - 3))
        return (significand * power_term).to_bytes(32, byteorder="big", signed=False)

    @property
    def difficulty(self) -> float:
        """Return the BlockHeader difficulty.

        Difficulty is the ratio of the genesis block target
        over the BlockHeader target.

        It represents the average number of hash function evaluations
        required to satisfy the BlockHeader target,
        expressed as multiple of the genesis block difficulty used as unit.

        The difficulty of the genesis block is 2^32 (4*2^30),
        i.e. 4 GigaHash function evaluations.
        """
        # genesis block target
        genesis_significand = 0x00FFFF
        genesis_exponent = 0x1D
        # significand ratio
        significand = genesis_significand / int.from_bytes(
            self.bits[1:], byteorder="big", signed=False
        )
        # power term ratio
        power_term = pow(256, genesis_exponent - self.bits[0])
        return significand * power_term

    def hash(self) -> bytes:
        "Return the reversed 32 bytes hash256 of the BlockHeader."
        s = self.serialize(check_validity=False)
        hash256_ = hash256(s)
        return hash256_[::-1]

    def assert_valid_pow(self) -> None:
        "Assert whether the BlockHeader provides a valid proof-of-work."

        if self.hash() >= self.target:
            err_msg = f"invalid proof-of-work: {self.hash().hex()}"
            err_msg += f" >= {self.target.hex()}"
            raise BTClibValueError(err_msg)

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

        self._set_properties()
        self.assert_valid_pow()

    def serialize(self, check_validity: bool = True) -> bytes:
        "Return a BlockHeader binary serialization."

        if check_validity:
            self.assert_valid()

        # version is signed int
        out = self.version.to_bytes(4, byteorder="little", signed=True)
        out += self.previous_block_hash[::-1]
        out += self.merkle_root[::-1]
        out += int(self.time.timestamp()).to_bytes(4, byteorder="little", signed=False)
        out += self.bits[::-1]
        out += self.nonce.to_bytes(4, byteorder="little", signed=False)

        return out

    @classmethod
    def deserialize(
        cls: Type[_BlockHeader], data: BinaryData, check_validity: bool = True
    ) -> _BlockHeader:
        "Return a BlockHeader by parsing 80 bytes from binary data."

        stream = bytesio_from_binarydata(data)

        # version is a signed int
        version = int.from_bytes(stream.read(4), byteorder="little", signed=True)
        previous_block_hash = stream.read(32)[::-1]
        merkle_root_ = stream.read(32)[::-1]
        t = int.from_bytes(stream.read(4), byteorder="little", signed=False)
        time = datetime.fromtimestamp(t, timezone.utc)
        bits = stream.read(4)[::-1]
        nonce = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        return cls(
            version,
            previous_block_hash,
            merkle_root_,
            time,
            bits,
            nonce,
            check_validity,
        )


_Block = TypeVar("_Block", bound="Block")


@dataclass
class Block(DataClassJsonMixin):
    header: BlockHeader = BlockHeader(check_validity=False)
    transactions: List[Tx] = field(default_factory=list)
    # private data member used only for to_dict
    # use the corresponding public properties instead
    _size: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="size"),
    )
    _weight: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="weight"),
    )
    _vsize: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="vsize"),
    )
    _height: Optional[int] = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="height"),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def _set_properties(self) -> None:
        self._size = self.size
        self._weight = self.weight
        self._vsize = self.vsize
        self._height = self.height

    def to_dict(self, encode_json=False) -> Dict[str, Json]:
        self._set_properties()
        return super().to_dict(encode_json)

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
        """Return the height committed into the coinbase script_sig.

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
        height_ = var_bytes.deserialize(coinbase_script)
        return int.from_bytes(height_, byteorder="little", signed=True)

    def has_segwit_tx(self) -> bool:
        return any(tx.is_segwit() for tx in self.transactions)

    def assert_valid(self) -> None:

        if not self.transactions[0].is_coinbase():
            raise BTClibValueError("first transaction is not a coinbase")
        for transaction in self.transactions[1:]:
            transaction.assert_valid()

        data = [
            tx.serialize(include_witness=False, check_validity=False)
            for tx in self.transactions
        ]
        merkle_root_ = merkle_root(data, hash256)[::-1]
        if merkle_root_ != self.header.merkle_root:
            err_msg = f"invalid merkle root: {self.header.merkle_root.hex()}"
            err_msg += f" instead of: {merkle_root_.hex()}"
            raise BTClibValueError(err_msg)

        self.header.assert_valid()

        self._set_properties()

    def serialize(
        self, include_witness: bool = True, check_validity: bool = True
    ) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.header.serialize()
        out += var_int.serialize(len(self.transactions))
        return out + b"".join([t.serialize(include_witness) for t in self.transactions])

    @classmethod
    def deserialize(
        cls: Type[_Block], data: BinaryData, check_validity: bool = True
    ) -> _Block:
        "Return a Block by parsing binary data."

        stream = bytesio_from_binarydata(data)
        header = BlockHeader.deserialize(stream)
        n = var_int.deserialize(stream)
        transactions = [Tx.deserialize(stream) for _ in range(n)]

        return cls(header, transactions, check_validity)
