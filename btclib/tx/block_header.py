#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BlockHeader dataclass.

Dataclass encapsulating
version, previous block hash, merkle root, time, bits, and nonce.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Tuple, Type, Union

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

_HF = hash256
_HF_LEN = 32  # should be _HF().digest_size
_KEY_SIZE: List[Tuple[str, int]] = [
    ("previous_block_hash", _HF_LEN),
    ("merkle_root", 32),
    ("bits", 4),
]


@dataclass
class BlockHeader:
    # 4 bytes, _signed_ little endian
    version: int
    # _HF_LEN bytes, little endian
    previous_block_hash: bytes
    # _HF_LEN bytes, little endian
    merkle_root: bytes
    # 4 bytes, unsigned little endian
    time: datetime
    # 4 bytes, little endian
    bits: bytes
    # 4 bytes, unsigned little endian
    nonce: int

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
        return (significand * power_term).to_bytes(_HF_LEN, "big", signed=False)

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

    @property
    def hash(self) -> bytes:
        "Return the reversed hash of the BlockHeader."
        s = self.serialize(check_validity=False)
        hash_ = _HF(s)
        return hash_[::-1]

    def __init__(
        self,
        version: int = 1,
        previous_block_hash: Octets = b"",
        merkle_root_: Octets = b"",
        time: datetime = datetime.fromtimestamp(0),
        bits: Octets = b"",
        nonce: int = 0,
        check_validity: bool = True,
    ) -> None:

        self.version = version
        self.previous_block_hash = bytes_from_octets(previous_block_hash)
        self.merkle_root = bytes_from_octets(merkle_root_)
        self.time = time
        self.bits = bytes_from_octets(bits)
        self.nonce = nonce

        if check_validity:
            self.assert_valid()

    def to_dict(self, check_validity: bool = True) -> Dict[str, Union[int, float, str]]:

        if check_validity:
            self.assert_valid()

        return {
            "version": self.version,
            "previous_block_hash": self.previous_block_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "time": datetime.isoformat(self.time),
            "bits": self.bits.hex(),
            "nonce": self.nonce,
            "target": self.target.hex(),
            "difficulty": self.difficulty,
        }

    @classmethod
    def from_dict(
        cls: Type["BlockHeader"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "BlockHeader":

        return cls(
            dict_["version"],
            dict_["previous_block_hash"],
            dict_["merkle_root"],
            datetime.fromisoformat(dict_["time"]),
            dict_["bits"],
            dict_["nonce"],
            check_validity,
        )

    def assert_valid_pow(self) -> None:
        "Assert whether the BlockHeader provides a valid proof-of-work."

        if self.hash >= self.target:
            err_msg = f"invalid proof-of-work: {self.hash.hex()}"
            err_msg += f" >= {self.target.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid(self) -> None:

        # must be a 4-bytes _signed_ integer
        if not 0 < self.version <= 0x7FFFFFFF:
            raise BTClibValueError(f"invalid version: {hex(self.version)}")

        if self.time.timestamp() < 1231006505:
            err_msg = "invalid timestamp (before genesis)"
            date = datetime.fromtimestamp(self.time.timestamp(), timezone.utc)
            err_msg += f": {date}"
            raise BTClibValueError(err_msg)
        # TODO: check for max 4-bytes timestamp

        for key, size in _KEY_SIZE:
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        self.nonce = int(self.nonce)
        if not 0 < self.nonce <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid nonce: {hex(self.nonce)}")

        self.assert_valid_pow()

    def serialize(self, check_validity: bool = True) -> bytes:
        "Return a BlockHeader binary serialization."

        if check_validity:
            self.assert_valid()

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little", signed=True),  # int32_t
                self.previous_block_hash[::-1],
                self.merkle_root[::-1],
                int(self.time.timestamp()).to_bytes(4, "little", signed=False),
                self.bits[::-1],
                self.nonce.to_bytes(4, byteorder="little", signed=False),
            ]
        )

    @classmethod
    def parse(
        cls: Type["BlockHeader"], data: BinaryData, check_validity: bool = True
    ) -> "BlockHeader":
        "Return a BlockHeader by parsing 80 bytes from binary data."

        stream = bytesio_from_binarydata(data)

        # version is a signed int (int32_t, not uint32_t)
        version = int.from_bytes(stream.read(4), byteorder="little", signed=True)
        previous_block_hash = stream.read(_HF_LEN)[::-1]
        merkle_root_ = stream.read(_HF_LEN)[::-1]
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
