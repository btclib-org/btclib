#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""BlockHeader dataclass.

Dataclass encapsulating version, previous block hash, merkle root, time,
bits, and nonce.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

_HF = hash256
_HF_LEN = 32  # should be _HF().digest_size
_KEY_SIZE = [("previous_block_hash", _HF_LEN), ("merkle_root", 32), ("bits", 4)]
# version, previous block hash, merkle root, time, bits, nonce
_REQUIRED_LENGTH = 4 + _HF_LEN + 32 + 4 + 4 + 4

# aware, as the serialization is in seconds since the epoch:
# datetime.fromtimestamp(0) would be naive, i.e. read back as local time,
# and the header would serialize differently on machines in different
# time zones.
#
# A module-level singleton, not a call in the default argument: datetime
# is immutable, so sharing it is harmless, but keeping the call out of
# the signature is what lets ruff's B008 stay enabled to catch the
# mutable defaults that are not.
_EPOCH = datetime.fromtimestamp(0, timezone.utc)


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

        The target yyzzww * 256^(xx-3) is represented in the blockhader
        by the 4 bytes 'bits' xxyyzzww
        """
        # significand (also known as mantissa or coefficient)
        significand = int.from_bytes(self.bits[1:], byteorder="big", signed=False)
        # power term, also called characteristics. Core's SetCompact
        # shifts rather than multiplying by a power of 256, and so does
        # this: pow(256, -1) is a float in python, so an exponent below
        # 3 used to send a 256-bit number through float arithmetic
        exponent = self.bits[0]
        if exponent < 3:
            value = significand >> (8 * (3 - exponent))
        else:
            value = significand << (8 * (exponent - 3))

        # the compact form can denote what 32 bytes cannot hold, and
        # to_bytes answered that with an OverflowError. Core raises the
        # same objection through the fOverflow flag of SetCompact, on
        # which CheckProofOfWork rejects the header
        if value >= 256**_HF_LEN:
            err_msg = f"invalid proof-of-work target: 0x{self.bits.hex()}"
            err_msg += f" overflows {_HF_LEN} bytes"
            raise BTClibValueError(err_msg)

        return value.to_bytes(_HF_LEN, "big", signed=False)

    @property
    def difficulty(self) -> float:
        """Return the BlockHeader difficulty.

        Difficulty is the ratio of the genesis block target over the
        BlockHeader target.

        It represents the average number of hash function evaluations
        required to satisfy the BlockHeader target, expressed as
        multiple of the genesis block difficulty used as unit.

        The difficulty of the genesis block is 2^32 (4*2^30), i.e. 4
        GigaHash function evaluations.
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
        return float(significand * power_term)

    @property
    def hash(self) -> bytes:
        """Return the reversed hash of the BlockHeader."""
        s = self.serialize(check_validity=False)
        hash_ = _HF(s)
        return hash_[::-1]

    def __init__(
        self,
        version: int = 1,
        previous_block_hash: Octets = b"",
        merkle_root: Octets = b"",
        time: datetime = _EPOCH,
        bits: Octets = b"",
        nonce: int = 0,
        *,
        check_validity: bool = True,
    ) -> None:
        # int(), where the annotation already says int, for the same reason
        # bytes_from_octets is called on the Octets fields: from_dict feeds
        # this constructor a json object, where a whole number may arrive
        # as a float. assert_valid used to coerce nonce, i.e. it rewrote
        # the object it was asked to inspect -- and it is called by
        # serialize() and to_dict(), so reading a header mutated it
        self.version = int(version)
        self.previous_block_hash = bytes_from_octets(previous_block_hash)
        self.merkle_root = bytes_from_octets(merkle_root)
        self.time = time
        self.bits = bytes_from_octets(bits)
        self.nonce = int(nonce)

        if check_validity:
            self.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, int | float | str]:
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
        cls: type[BlockHeader], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> BlockHeader:
        return cls(
            dict_["version"],
            dict_["previous_block_hash"],
            dict_["merkle_root"],
            datetime.fromisoformat(dict_["time"]),
            dict_["bits"],
            dict_["nonce"],
            check_validity=check_validity,
        )

    def assert_valid_pow(self) -> None:
        """Assert whether the BlockHeader provides a valid proof-of-work.

        Not called by assert_valid, which answers the other question:
        whether the eighty bytes are a well-formed header. A header being
        mined is structurally valid and has no proof-of-work yet, so a
        candidate could not otherwise be built, serialized, or hashed
        through the ordinary API -- and hashing it is what mining is.

        Block.assert_valid does call this, as Bitcoin Core's CheckBlock
        calls CheckProofOfWork by default: a Block is a block, and the
        proof-of-work is what its transactions are committed by.
        """
        if self.hash >= self.target:
            err_msg = f"invalid proof-of-work: {self.hash.hex()}"
            err_msg += f" >= {self.target.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid(self) -> None:
        # the type check the bytes fields get from bytes() below, for the
        # two int ones. assert_valid used to coerce nonce here instead,
        # which repaired the mistake and rewrote the header to do it; the
        # coercion moved to __init__, and what is left is the report. Not
        # dropped altogether, which would have let a float reach to_bytes
        # and leave the library through an AttributeError
        for key in ("version", "nonce"):
            value = getattr(self, key)
            if not isinstance(value, int):
                err_msg = f"invalid {key} type: {type(value).__name__}"
                raise BTClibTypeError(err_msg)

        # must be a 4-bytes _signed_ integer
        if not 0 < self.version <= 0x7FFFFFFF:
            raise BTClibValueError(f"invalid version: {hex(self.version)}")

        # a naive datetime has no instant attached to it: timestamp()
        # would assume the local time zone, so both this check and the
        # serialization would depend on the machine
        if self.time.tzinfo is None or self.time.tzinfo.utcoffset(self.time) is None:
            err_msg = f"naive timestamp (no time zone): {self.time}"
            raise BTClibValueError(err_msg)

        # int(), because that is the value serialize writes: timestamp()
        # is a float, and truncation toward zero is what makes the bound
        # below the exact one the four bytes have. The genesis bound is
        # unchanged by it -- for a positive x and an integer n, int(x) < n
        # exactly when x < n
        timestamp = int(self.time.timestamp())

        if timestamp < 1231006505:
            err_msg = "invalid timestamp (before genesis)"
            date = datetime.fromtimestamp(timestamp, timezone.utc)
            err_msg += f": {date}"
            raise BTClibValueError(err_msg)

        # the header field is four unsigned bytes, so 2106-02-07 06:28:15Z
        # is the last instant a header can carry. Without this, a later one
        # passed assert_valid and failed in serialize, through the
        # OverflowError of int.to_bytes -- which names neither the field nor
        # the object, so the caller of Block.serialize was told "int too big
        # to convert" about a header it had just been told was valid
        # self.time, where the bound above renders the instant through
        # fromtimestamp: this branch is the one that catches datetime.max,
        # whose timestamp() is 253402300799.999999 rounded up to
        # 253402300800.0 by the float, i.e. year 10000, and fromtimestamp
        # answers that with a ValueError -- building the message would have
        # thrown the very exception this check exists to replace
        if timestamp > 0xFFFFFFFF:
            err_msg = "invalid timestamp (after the last 4-bytes instant)"
            err_msg += f": {self.time}"
            raise BTClibValueError(err_msg)

        for key, size in _KEY_SIZE:
            # bytes() is the type check, not a coercion: it raises
            # TypeError for a field rebound to a str. Unlike bip32's
            # counterpart this loop never assigned the result back
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        # any 4-byte value, zero included: consensus places no lower bound
        # on the nonce, Core does not look at it at all, and a header being
        # mined starts at zero. The bound used to be 0 < nonce, which also
        # served as parse()'s truncation check -- a short read yields zero
        # -- and that is now a length check in parse(), where it belongs
        if not 0 <= self.nonce <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid nonce: {hex(self.nonce)}")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return a BlockHeader binary serialization."""
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
        cls: type[BlockHeader], data: BinaryData, *, check_validity: bool = True
    ) -> BlockHeader:
        """Return a BlockHeader by parsing 80 bytes from binary data."""
        stream = bytesio_from_binarydata(data)
        header_bin = stream.read(_REQUIRED_LENGTH)

        # read past the end of a stream returns what there was, without
        # raising, so a truncated header used to be reported by whichever
        # field the missing bytes happened to fall in: eight bytes short
        # was "invalid nonce", four short "invalid bits length", and
        # twelve short "invalid timestamp (before genesis)" -- the epoch,
        # read from no bytes at all. Reported as truncation now, as
        # BIP32KeyData.parse reports it
        if check_validity and len(header_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(header_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)

        # version is a signed int (int32_t, not uint32_t)
        version = int.from_bytes(header_bin[:4], byteorder="little", signed=True)
        previous_block_hash = header_bin[4 : 4 + _HF_LEN][::-1]
        merkle_root = header_bin[4 + _HF_LEN : 4 + 2 * _HF_LEN][::-1]
        rest = header_bin[4 + 2 * _HF_LEN :]
        t = int.from_bytes(rest[:4], byteorder="little", signed=False)
        time = datetime.fromtimestamp(t, timezone.utc)
        bits = rest[4:8][::-1]
        nonce = int.from_bytes(rest[8:12], byteorder="little", signed=False)

        return cls(
            version,
            previous_block_hash,
            merkle_root,
            time,
            bits,
            nonce,
            check_validity=check_validity,
        )
