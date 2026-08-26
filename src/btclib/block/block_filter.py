# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP158 compact block filters; the class docstring has the contract.

A filter is a Golomb-coded set: every script the block touches is mapped
into `[0, N * M)` by SipHash-2-4 keyed on the block hash, the values are
sorted, and the differences between them are Golomb-Rice coded. A light
client that holds the filter can ask whether a script it cares about may
be in the block, and fetch the block only then -- which is BIP157's
`getcfilters`, and the reason the false positive rate `1 / M` is a
parameter rather than an accident.

Only the basic filter type, `0x00`, is defined by BIP158, and it is what
this module builds. BIP157's peer-to-peer messages and Core's filter
index are not here: what a node stores and how it announces it are
questions about a node, where this is the arithmetic over one block.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.block.block import Block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, siphash
from btclib.tx import OutPoint, TxOut
from btclib.tx.limits import MAX_TX_OUT_COUNT
from btclib.utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    is_octets,
)

__all__ = [
    "BASIC_FILTER_M",
    "BASIC_FILTER_P",
    "MAX_FILTER_ELEMENT_COUNT",
    "BasicBlockFilter",
    "filter_header",
    "prevout_scripts_from_utxos",
]

_HF = hash256
_HF_LEN = 32  # should be _HF().digest_size

# BIP158's parameters for the basic filter: P is the bit width of the
# Golomb-Rice remainder, M the inverse of the false positive rate
BASIC_FILTER_P = 19
BASIC_FILTER_M = 784931

# Every element of a basic filter is the script of an output of the block,
# or of an output one of its inputs spends, so a filter holds at most one
# element per input and output of the block together. A TxOut is the
# smaller of the two, so the count `btclib.tx.limits` derives from
# MAX_BLOCK_WEIGHT for a transaction's outputs bounds that sum as well --
# which is what lets `parse` refuse a count before it decodes for it,
# where var_int.MAX_SIZE alone would let nine octets ask for far more.
MAX_FILTER_ELEMENT_COUNT = MAX_TX_OUT_COUNT

# The op code an excluded output script starts with. The byte and not
# `script_pub_key.is_nulldata`: BIP158 excludes "all OP_RETURN output
# scripts", which is Core's `script[0] == OP_RETURN` in
# `BasicFilterElements` (`src/blockfilter.cpp`), where `is_nulldata`
# answers the narrower question of whether the script is the *standard*
# nulldata shape. The chain carries non-standard OP_RETURN outputs -- the
# 15007 row of Core's own vector file is named for one -- and keeping
# them would put elements in the filter that no other implementation has.
_OP_RETURN = 0x6A


class _BitWriter:
    """The bit stream a Golomb-coded set is written to.

    Bits go out most significant first, which is the "big endian" of
    BIP158's `write_bits_big_endian`, and `flush` pads the last octet
    with zeros as the BIP requires.
    """

    def __init__(self) -> None:
        self.octets = bytearray()
        self._buffer = 0
        self._filled = 0

    def write(self, value: int, count: int) -> None:
        """Write the count least significant bits of value, big endian."""
        for shift in range(count - 1, -1, -1):
            self._buffer = (self._buffer << 1) | ((value >> shift) & 1)
            self._filled += 1
            if self._filled == 8:
                self.octets.append(self._buffer)
                self._buffer = 0
                self._filled = 0

    def flush(self) -> bytes:
        """Return the stream, padded with zeros to the octet boundary."""
        if self._filled:
            self.octets.append(self._buffer << (8 - self._filled))
            self._buffer = 0
            self._filled = 0
        return bytes(self.octets)


class _BitReader:
    """The bit stream a Golomb-coded set is read back from.

    The mirror of _BitWriter, and the place a malformed filter is
    caught: a stream that ends inside a unary quotient or a remainder
    has no bits left to give, which is a truncated filter and not a
    value of zero.
    """

    def __init__(self, octets: bytes) -> None:
        self._octets = octets
        self._bit_count = 8 * len(octets)
        self._position = 0

    def read(self, count: int) -> int:
        """Return the next count bits as an integer, big endian."""
        end = self._position + count
        if end > self._bit_count:
            err_msg = "not enough binary data for the block filter:"
            err_msg += f" {self._bit_count - self._position} bits left"
            err_msg += f" instead of {count}"
            raise BTClibValueError(err_msg)

        # the octets the requested bits fall in, read as one number and
        # shifted down by the bits of the last octet that follow them
        window = self._octets[self._position // 8 : (end + 7) // 8]
        value = int.from_bytes(window, byteorder="big") >> (-end % 8)
        self._position = end
        return value & ((1 << count) - 1)

    def assert_exhausted(self) -> None:
        """Refuse what follows the last delta of the set.

        Two shapes, and both are malleability: a whole octet the deltas
        never reached is Core's "encoded_filter contains excess data",
        and a non-zero bit in the padding is a second encoding of the
        same filter, where BIP158 says the stream "is padded with 0's to
        the nearest byte boundary".
        """
        remaining = self._bit_count - self._position
        if remaining >= 8:
            err_msg = f"{remaining // 8} bytes after the block filter"
            raise BTClibValueError(err_msg)
        if remaining and self.read(remaining):
            raise BTClibValueError("non-zero padding after the block filter")


def _golomb_encode(writer: _BitWriter, value: int, p: int) -> None:
    """Write value as BIP158's `golomb_encode` does."""
    quotient = value >> p
    # the quotient in unary -- that many ones and the zero ending them --
    # then the remainder in p bits; `write` keeps the low bits it is asked
    # for, so the value goes in unmasked
    writer.write(((1 << quotient) - 1) << 1, quotient + 1)
    writer.write(value, p)


def _golomb_decode(reader: _BitReader, p: int) -> int:
    """Return the value BIP158's `golomb_decode` reads back."""
    quotient = 0
    while reader.read(1):
        quotient += 1
    return (quotient << p) + reader.read(p)


def _key_from_block_hash(block_hash: bytes) -> tuple[int, int]:
    """Return the SipHash key BIP158 derives from a block hash.

    "The first 16 bytes of the hash (in standard little-endian
    representation) of the block", i.e. of the hash as it is serialized
    and not as it is printed: btclib holds a block hash in display
    order, so the reversal here is what makes the key Core's.
    """
    internal = block_hash[::-1]
    return (
        int.from_bytes(internal[:8], byteorder="little"),
        int.from_bytes(internal[8:16], byteorder="little"),
    )


def _hash_to_range(k0: int, k1: int, element: bytes, upper_bound: int) -> int:
    """Map an element into [0, upper_bound), BIP158's `hash_to_range`.

    The 64-bit SipHash output times the bound, shifted right by 64: a
    multiply-and-shift that is uniform over the range without a modulo,
    and Core's `FastRange64`.
    """
    return (siphash(k0, k1, element) * upper_bound) >> 64


def filter_header(filter_hash: Octets, previous_header: Octets) -> bytes:
    """Return the filter header chaining a filter hash onto the previous one.

    Core's `BlockFilter::ComputeHeader`, and BIP157's definition: "the
    double-SHA256 of the concatenation of the filter hash with the
    previous filter header", both in the internal order -- so a header
    commits to every filter down to genesis, which is what lets a light
    client be told one hash and check the chain of filters against it.
    The previous header of the genesis block's filter is thirty-two zero
    octets.

    Both arguments and the answer are in the display order every hash
    this library hands out is in.

    A function over a hash rather than a method on a filter, because that
    is the general case: BIP157's `cfheaders` message carries the hashes
    of filters its receiver has not got, and deriving the headers is the
    whole of what it is for. `BasicBlockFilter.header` is this over a
    filter that is at hand.
    """
    hash_ = bytes_from_octets(filter_hash, _HF_LEN)
    previous = bytes_from_octets(previous_header, _HF_LEN)
    return _HF(hash_[::-1] + previous[::-1])[::-1]


def prevout_scripts_from_utxos(
    block: Block, utxos: Mapping[OutPoint, TxOut]
) -> list[bytes]:
    """Return the previous output scripts `from_block` asks for.

    The typed adapter over a utxo set: one script per non-coinbase
    input, in the order the block spends them. `OutPoint` is frozen and
    hashable so that it can key such a mapping, and an input the mapping
    does not answer for is refused by name -- a filter built from a
    silently missing prevout is a filter that omits an element, which no
    later check would catch.
    """
    scripts: list[bytes] = []
    for tx in block.transactions:
        if tx.is_coinbase:
            continue
        for tx_in in tx.vin:
            prev_out = tx_in.prev_out
            if prev_out not in utxos:
                err_msg = "unresolved previous output: "
                err_msg += f"{prev_out.tx_id.hex()}:{prev_out.vout}"
                raise BTClibValueError(err_msg)
            scripts.append(utxos[prev_out].script_pub_key.script)
    return scripts


@dataclass
class BasicBlockFilter:
    """The BIP158 basic filter of one block.

    The block hash the filter is keyed by, the number of elements it
    holds, and the Golomb-Rice coded set of their hashes. The hash is in
    the display order `BlockHeader.hash` gives, and is a field rather
    than something read back out of the bytes: BIP157 sends a filter and
    the hash of its block as two things, the serialization below being
    the count and the set alone.

    `match` answers "may this block touch that script", never "does it":
    a Golomb-coded set is a probabilistic structure, and one query in
    BASIC_FILTER_M is a false positive by construction.
    """

    # 32 bytes, in display order
    block_hash: bytes
    # a var_int on the wire, ahead of the set
    element_count: int
    # the Golomb-Rice bit stream, padded with zeros to an octet boundary
    encoded_set: bytes

    def __init__(
        self,
        block_hash: Octets = b"",
        element_count: int = 0,
        encoded_set: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        self.block_hash = bytes_from_octets(block_hash)
        self.element_count = element_count
        self.encoded_set = bytes_from_octets(encoded_set)

        if check_validity:
            self.assert_valid()

    def _decode(self) -> Iterator[int]:
        """Yield the element hashes of the set, in the order they encode.

        Sorted, since what is coded is the difference between each value
        and the one before it. The bound is BIP158's `F = N * M`, which
        `hash_to_range` maps into: a delta sum that reaches it is a set
        no construction could have produced, so it is refused here
        rather than left to a match that would silently never hit.
        """
        reader = _BitReader(bytes(self.encoded_set))
        upper_bound = self.element_count * BASIC_FILTER_M
        value = 0
        for _ in range(self.element_count):
            value += _golomb_decode(reader, BASIC_FILTER_P)
            if value >= upper_bound:
                err_msg = f"block filter element out of range: {value}"
                err_msg += f", max is {upper_bound - 1}"
                raise BTClibValueError(err_msg)
            yield value
        reader.assert_exhausted()

    @property
    def element_hashes(self) -> list[int]:
        """Return the element hashes the set holds, sorted.

        What the elements were is not recoverable -- a filter holds
        their SipHash images and not the scripts -- so this is what a
        caller comparing two filters, or counting how full one is, has
        to work with. `match` is the question about a script.
        """
        return list(self._decode())

    def assert_valid(self) -> None:
        """Refuse a filter the serialized bytes could not hold.

        The block hash width, the element count, and then the set
        itself: decoding it is the only way to know that it holds the
        number of elements it declares, that the bits end where the
        octets do, and that nothing follows them.
        """
        if not is_integer(self.element_count):
            err_msg = f"invalid element count type: {type(self.element_count).__name__}"
            raise BTClibTypeError(err_msg)

        # bytes() is the type check the two octet fields get, not a
        # coercion: validating must not rewrite the object it inspects
        block_hash = bytes(self.block_hash)
        if len(block_hash) != _HF_LEN:
            err_msg = f"invalid block hash length: {len(block_hash)} bytes"
            err_msg += f" instead of {_HF_LEN}"
            raise BTClibValueError(err_msg)

        if not 0 <= self.element_count <= MAX_FILTER_ELEMENT_COUNT:
            err_msg = f"invalid element count: {self.element_count}"
            err_msg += f", max is {MAX_FILTER_ELEMENT_COUNT}"
            raise BTClibValueError(err_msg)

        for _ in self._decode():
            pass

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the BIP158 serialization: the count, then the set."""
        if check_validity:
            self.assert_valid()

        return var_int.serialize(self.element_count) + self.encoded_set

    @classmethod
    def parse(
        cls: type[BasicBlockFilter],
        data: BinaryData,
        block_hash: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> BasicBlockFilter:
        """Return the filter these octets encode, for that block hash.

        The whole of the octets: a Golomb-coded set carries no length of
        its own, only the count of the values coded in it, so the filter
        is however many octets it takes to hold them and there is no
        `assert_no_trailing` to run. What would have been trailing data
        is caught a level down, `_decode` refusing an octet the deltas
        never reached.

        `block_hash` is the caller's because the serialization does not
        carry it -- BIP157's `cfilter` message names the block beside
        the filter -- and without it nothing could be matched: the key
        of the SipHash is derived from it. The default is the empty
        default of the constructor and not a filter keyed on nothing:
        `assert_valid` refuses it for its width, so a caller that omits
        the hash is told which argument it left out.
        """
        stream = bytesio_from_binarydata(data)
        element_count = var_int.parse(stream, MAX_FILTER_ELEMENT_COUNT)
        return cls(
            block_hash, element_count, stream.read(), check_validity=check_validity
        )

    @classmethod
    def from_block(
        cls: type[BasicBlockFilter],
        block: Block,
        prevout_scripts: Sequence[Octets],
        *,
        check_validity: bool = True,
    ) -> BasicBlockFilter:
        """Return the basic filter of a block whose prevouts are resolved.

        BIP158's contents rule: the script of every output that is not
        an OP_RETURN one, and the previous output script of every input
        of every transaction but the coinbase. An empty script is a
        "nil" item the BIP excludes on both sides, and the elements are
        a set, so a script the block repeats weighs once.

        `prevout_scripts` is one script per non-coinbase input, in the
        order the block spends them, and it is the caller's: a block
        does not carry the outputs it spends. The count is checked
        against the block, which is what turns a caller passing the
        wrong list into an error rather than into a filter that is
        quietly not the one the network computed.
        `prevout_scripts_from_utxos` builds the list from a mapping for
        a caller that holds one.
        """
        # every Octets is a Sequence too: passing one script instead of a
        # list of them would zip through its bytes and count them as
        # inputs, so the shape is refused by name
        if is_octets(prevout_scripts):
            err_msg = "invalid previous output scripts type: "
            err_msg += type(prevout_scripts).__name__
            raise BTClibTypeError(err_msg)

        spent = sum(len(tx.vin) for tx in block.transactions if not tx.is_coinbase)
        if len(prevout_scripts) != spent:
            err_msg = f"invalid previous output script count: {len(prevout_scripts)}"
            err_msg += f" instead of {spent}"
            raise BTClibValueError(err_msg)

        elements: set[bytes] = set()
        for tx in block.transactions:
            for tx_out in tx.vout:
                script = tx_out.script_pub_key.script
                if script and script[0] != _OP_RETURN:
                    elements.add(script)
        for prevout_script in prevout_scripts:
            script = bytes_from_octets(prevout_script)
            if script:
                elements.add(script)

        block_hash = block.header.hash
        k0, k1 = _key_from_block_hash(block_hash)
        upper_bound = len(elements) * BASIC_FILTER_M
        values = sorted(
            _hash_to_range(k0, k1, element, upper_bound) for element in elements
        )

        writer = _BitWriter()
        last_value = 0
        for value in values:
            _golomb_encode(writer, value - last_value, BASIC_FILTER_P)
            last_value = value

        return cls(
            block_hash,
            len(elements),
            writer.flush(),
            check_validity=check_validity,
        )

    def match_any(self, elements: Iterable[Octets]) -> bool:
        """Answer whether the filter may hold any of the elements.

        Both sides are sorted and walked once, which is Core's
        `MatchInternal`: the queries are hashed into the same range and
        compared against the values as they decode, so a filter is read
        once however many elements are asked about.

        False for an empty set of elements, and false for an element the
        filter cannot hold -- an empty script, or the script of an
        OP_RETURN output, neither of which is ever put in one.
        """
        # every Octets is itself iterable, so passing one script instead
        # of an iterable of them would zip through its bytes and query
        # each as its own element (issue #1405)
        if is_octets(elements):
            err_msg = "invalid elements type: "
            err_msg += type(elements).__name__
            raise BTClibTypeError(err_msg)

        k0, k1 = _key_from_block_hash(bytes(self.block_hash))
        upper_bound = self.element_count * BASIC_FILTER_M
        targets = sorted(
            {
                _hash_to_range(k0, k1, bytes_from_octets(element), upper_bound)
                for element in elements
            }
        )
        if not targets:
            return False

        index = 0
        for value in self._decode():
            while targets[index] < value:
                index += 1
                if index == len(targets):
                    return False
            if targets[index] == value:
                return True
        return False

    def match(self, element: Octets) -> bool:
        """Answer whether the filter may hold the element."""
        return self.match_any([element])

    @property
    def hash(self) -> bytes:
        """Return the hash of the serialized filter, in display order.

        Core's `BlockFilter::GetHash`, a double SHA256 over the octets
        `serialize` writes; reversed, as every other hash this library
        hands out is.
        """
        return _HF(self.serialize(check_validity=False))[::-1]

    def header(self, previous_header: Octets) -> bytes:
        """Return the filter header that chains this filter to the previous.

        `filter_header` over this filter's own hash: the module function
        is the general form, taking the hash a `cfheaders` message
        carries where the filter itself was never sent.
        """
        return filter_header(self.hash, previous_header)
