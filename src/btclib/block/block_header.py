# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BlockHeader dataclass; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from btclib.alias import BinaryData, Octets
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.block.proof_of_work import (
    MAINNET_POW_LIMIT_BITS,
    is_negative_bits,
    target_from_bits,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
    int_from_json_number,
    is_integer,
)

__all__ = [
    "BlockHeader",
]

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


def _time_from_isoformat(time: Any) -> datetime:
    """Return the time of an ISO 8601 string, which is what to_dict wrote.

    The one field `from_dict` converts before the constructor sees it, so
    it is the one whose wrong value `assert_valid` cannot answer for:
    `datetime.fromisoformat` refuses what is not a string with a
    TypeError of its own and an unparsable string with a bare
    ValueError, and a json boundary owes its caller neither.
    """
    assert_type(time, str, "time")
    try:
        return datetime.fromisoformat(time)
    except ValueError as e:
        raise BTClibValueError(f"invalid time: {e}") from e


@dataclass
class BlockHeader:
    """The eighty bytes a block is identified and mined by.

    Version, previous block hash, merkle root, time, bits, nonce; the
    hashes and bits are held in display order and reversed on the
    wire, the time as an aware datetime. assert_valid answers for the
    eighty bytes alone -- proof-of-work and clock checks are the
    explicit assert_valid_pow and assert_valid_time, a header being
    mined having neither yet.
    """

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
        return target_from_bits(self.bits)

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
        # the ratio of the two targets, and never the compact form
        # decoded a second time here: the sign bit of `bits` is masked
        # off in one place, `target_from_bits`, so that this and `target`
        # cannot disagree about which number the header carries. Core's
        # GetDifficulty divides by the unmasked significand, which it can
        # afford to: the header reaching it has passed CheckProofOfWork,
        # so the bit is not set. This property answers for any header.
        # MAINNET_POW_LIMIT_BITS is the genesis target, which is what
        # makes the genesis difficulty 1
        genesis_target = int.from_bytes(target_from_bits(MAINNET_POW_LIMIT_BITS), "big")
        target = int.from_bytes(self.target, "big")
        if not target:
            # no hash can satisfy a zero target, so no block carries one.
            # Raised as the exception contract requires, rather than left
            # to the ZeroDivisionError of the division below, which names
            # neither the field nor the header
            raise BTClibValueError(f"zero proof-of-work target: {self.bits.hex()}")

        return genesis_target / target

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
        # a coercion, where the annotation already says int, for the same
        # reason bytes_from_octets is called on the Octets fields:
        # from_dict feeds this constructor a json object, where a whole
        # number may arrive as a float. Coercing in assert_valid instead
        # would rewrite the object it is asked to inspect -- and it is
        # called by serialize() and to_dict(), so reading a header would
        # mutate it. A bool is the one thing not coerced but refused,
        # `true` out of json being a schema error rather than version 1
        self.version = int_from_json_number(version, "version")
        self.previous_block_hash = bytes_from_octets(previous_block_hash)
        self.merkle_root = bytes_from_octets(merkle_root)
        self.time = time
        self.bits = bytes_from_octets(bits)
        self.nonce = int_from_json_number(nonce, "nonce")

        if check_validity:
            self.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, int | float | str]:
        """Return the header as a dict of json-friendly values.

        The time is ISO 8601; target and difficulty are derived for
        the reader and ignored by from_dict, which recomputes them
        from bits.
        """
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
        """Build a BlockHeader from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "block header")
        return cls(
            dict_["version"],
            dict_["previous_block_hash"],
            dict_["merkle_root"],
            _time_from_isoformat(dict_["time"]),
            dict_["bits"],
            dict_["nonce"],
            check_validity=check_validity,
        )

    def assert_valid_pow(self, pow_limit_bits: Octets = MAINNET_POW_LIMIT_BITS) -> None:
        """Assert whether the BlockHeader provides a valid proof-of-work.

        Bitcoin Core's CheckProofOfWork: the target the bits denote must
        be one the network allows, and the hash must not exceed it. The
        range of the target is checked first and is four questions, which
        are Core's DeriveTarget -- a negative bits value, a zero target,
        a target 32 bytes cannot hold, a target above the network's
        limit. Each is refused by name, where DeriveTarget returns a bare
        nullopt for all four: a caller of this library is told which rule
        it broke, and the four are as many different mistakes.

        `pow_limit_bits` is the network's easiest target, mainnet's by
        default as `next_bits` takes it, and it is the caller's to state:
        a header carries no claim about which network it belongs to, so
        nothing here can read one. Passing REGTEST_POW_LIMIT_BITS is what
        makes a regtest header acceptable -- and what keeps a regtest one
        from passing for mainnet, which is the hole this closes.

        Not called by assert_valid, which answers the other question:
        whether the eighty bytes are a well-formed header. A header being
        mined is structurally valid and has no proof-of-work yet, so a
        candidate could not otherwise be built, serialized, or hashed
        through the ordinary API -- and hashing it is what mining is.

        Block.assert_valid does call this, as Bitcoin Core's CheckBlock
        calls CheckProofOfWork by default: a Block is a block, and the
        proof-of-work is what its transactions are committed by.
        """
        # DeriveTarget's four range checks, in the order of the condition
        # they are the disjuncts of. Only the last of them needs the
        # network, and none of them looks at the hash: bits alone can be
        # a target no chain would ever hand out.
        #
        # fNegative, which the target cannot report because it is
        # unsigned -- 0x1d80ffff denotes a number below zero and its
        # magnitude is a plausible mainnet target
        if is_negative_bits(self.bits):
            raise BTClibValueError(f"negative proof-of-work target: {self.bits.hex()}")

        # fOverflow is raised by target_from_bits, which is where the
        # 32 bytes are, so reading the target is the third check
        target = self.target

        # a target no hash can satisfy, since a hash is unsigned: Core
        # refuses it here rather than letting the comparison below decide,
        # and block_work refuses it for the same reason
        if not int.from_bytes(target, byteorder="big", signed=False):
            raise BTClibValueError(f"zero proof-of-work target: {self.bits.hex()}")

        # both are 32 bytes big endian, so this is the comparison of the
        # numbers they hold. The limit is the easiest target the network
        # allows, so a target above it is work no network asked for
        pow_limit = target_from_bits(pow_limit_bits)
        if target > pow_limit:
            err_msg = f"proof-of-work target above the limit: {target.hex()}"
            err_msg += f" > {pow_limit.hex()}"
            raise BTClibValueError(err_msg)

        # the target is a bound the hash may reach: CheckProofOfWork
        # rejects on "hash > bnTarget", so a hash equal to the target is
        # the last one that solves the block, and refusing it would be
        # refusing a block every node on the network accepts. No vector
        # can show the difference -- equality asks a 256-bit hash for one
        # exact value -- so the comparison is right by matching Core's,
        # which is the only way it can be right here
        if self.hash > target:
            err_msg = f"invalid proof-of-work: {self.hash.hex()}"
            err_msg += f" > {target.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid_time(self, now: datetime) -> None:
        """Assert that the timestamp is not too far ahead of a clock.

        Bitcoin Core's time-too-new, from ContextualCheckBlockHeader: a
        header more than MAX_FUTURE_BLOCK_TIME ahead of the current time
        is refused, which is what bounds how far a miner can push a
        timestamp forward -- and the reason it is a bound rather than an
        equality is that the network has no clock of its own to check
        against.

        `now` is the caller's, and never `datetime.now()` read here: a
        consensus rule taking the wall clock would have one machine accept
        the block another refuses, and no test of it could be written that
        did not depend on the day it ran on. Which is also why this is not
        called by assert_valid, and why Block.assert_valid does not reach
        it: those two answer for the eighty bytes and for the block, and a
        clock is neither.

        time-too-old is the other half of the pair Core checks beside this
        one, and it is not asked here: it is the median time past of
        eleven ancestors, which needs the chain rather than a datum this
        method takes. `btclib.block.header_context.median_time_past` is
        where the walk lives, and `Block.assert_valid_contextual` is
        where the comparison is made, off `BlockContext.median_time_past`
        rather than off a callable this method could take instead.
        """
        # the type before the time zone: `.tzinfo` on anything else is an
        # AttributeError, which is neither a ValueError nor a TypeError
        # and so is caught by nothing this library tells a caller to catch
        assert_type(now, datetime, "current time")
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            raise BTClibValueError(f"naive current time (no time zone): {now}")

        # int(), as assert_valid does and for the same reason: it is the
        # value the four bytes hold, so a header carrying a fraction of a
        # second is compared as it serializes. The bound keeps the
        # fraction of `now`, which is where Core keeps it too -- its clock
        # is finer than a second and the comparison is in the finer unit
        if int(self.time.timestamp()) > now.timestamp() + MAX_FUTURE_BLOCK_TIME:
            err_msg = f"invalid timestamp (too far in the future): {self.time}"
            err_msg += f" > {now} + {MAX_FUTURE_BLOCK_TIME} seconds"
            raise BTClibValueError(err_msg)

    def _assert_valid_types(self) -> None:
        """Refuse a field the eighty bytes could not be built from.

        The type check the bytes fields get from bytes() below, for the
        three that get none. Not a coercion, which would repair the
        mistake by rewriting the header being inspected (__init__
        coerces, this reports); not dropped either, which would let a
        float reach to_bytes and leave the library through an
        AttributeError, and a str reach `.tzinfo` and leave through
        another one -- neither of them a half of this library's
        exception contract.

        The timestamp is the one field __init__ coerces nothing into: a
        moment has no single spelling to coerce from,
        `datetime.fromtimestamp` needing a time zone the caller has not
        given.
        """
        for key in ("version", "nonce"):
            value = getattr(self, key)
            if not is_integer(value):
                err_msg = f"invalid {key} type: {type(value).__name__}"
                raise BTClibTypeError(err_msg)

        assert_type(self.time, datetime, "timestamp")

    def assert_valid(self) -> None:
        """Refuse a header the eighty bytes could not hold.

        Field types, the version and nonce ranges, the timestamp
        between genesis and the last four-byte instant, the field
        sizes. Nothing here reads a clock or checks the work: those
        are assert_valid_time and assert_valid_pow, whose docstrings
        say why they are separate.
        """
        self._assert_valid_types()

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
        # passes assert_valid and fails in serialize, through the
        # OverflowError of int.to_bytes -- which names neither the field nor
        # the object, so the caller of Block.serialize is told "int too big
        # to convert" about a header it has just been told is valid.
        # self.time, where the bound above renders the instant through
        # fromtimestamp: this branch is the one that catches datetime.max,
        # whose timestamp() is 253402300799.999999 rounded up to
        # 253402300800.0 by the float, i.e. year 10000, and fromtimestamp
        # answers that with a ValueError -- building the message would
        # throw the very exception this check exists to replace
        if timestamp > 0xFFFFFFFF:
            err_msg = "invalid timestamp (after the last 4-bytes instant)"
            err_msg += f": {self.time}"
            raise BTClibValueError(err_msg)

        for key, size in _KEY_SIZE:
            # bytes() is the type check, not a coercion: it raises
            # TypeError for a field rebound to a str. The result is never
            # assigned back: validating must not rewrite the header
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        # any 4-byte value, zero included: consensus places no lower bound
        # on the nonce, Core does not look at it at all, and a header being
        # mined starts at zero. Excluding zero would only be a proxy for
        # truncation -- a short read yields zero -- which parse() checks
        # by length, where it belongs
        if not 0 <= self.nonce <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid nonce: {hex(self.nonce)}")

    def _serialized_size(self) -> int:
        """Return what serialize writes, without writing it.

        The eighty bytes of a header, taken from the fields rather than
        stated: `assert_valid` is what fixes the two hashes and the bits
        at their widths, and this is asked by callers that pass
        `check_validity=False`.
        """
        return (
            4
            + len(self.previous_block_hash)
            + len(self.merkle_root)
            + 4
            + len(self.bits)
            + 4
        )

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
        # raising: check the length up front, or a truncated header is
        # reported by whichever field the missing bytes happen to fall in
        # -- eight bytes short as "invalid nonce", four as "invalid bits
        # length", twelve as "invalid timestamp (before genesis)", the
        # epoch read from no bytes at all. Reported as truncation instead,
        # as BIP32KeyData.parse reports it -- and reported whatever
        # check_validity says, eighty bytes being what makes the slices
        # below mean anything rather than an opinion about the header:
        # btclib/utils.py states the rule and holds the two helpers for it
        if len(header_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(header_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)
        assert_no_trailing(data, stream, "block header")

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
