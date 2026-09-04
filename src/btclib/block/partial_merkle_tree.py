# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP37's `CPartialMerkleTree`: a subset of a block's txids, authenticated.

A partial merkle tree is a depth-first walk of a block's merkle tree,
where every node that is not on the path to a matched leaf is replaced by
its own hash, and every node that is -- or is an ancestor of one -- is
expanded instead. What is left is a flag bit per visited node and a hash
per node that was not expanded, which is BIP37's own description and
Core's `merkleblock.h` class comment: "a subset of the txid's of a known
block, in a way that allows recovery of the list of txid's and the merkle
root, in an authenticated way". `PartialMerkleTree.merkle_root` and
`.matches` are that recovery, and it is also this module's entire hazard:
nothing about the walk stops a peer from sending flags and hashes that
were never produced by `TraverseAndBuild`, and refusing what the walk
cannot make sense of is what makes the recovered root worth comparing
against a header's.

**Why this is not `btclib.block.merkle_proof`.** That module proves one
leaf against one root, walking a single branch of siblings whose length is
the tree's height; this module walks the whole tree, and what it holds is
however many branches BIP37 chose to keep, sharing every internal node
they have in common. A single proof is what `verifytxoutproof` answers;
a partial tree is what a `merkleblock` carries -- BIP37's own reason for
the second encoding is that several branches sharing a filter would
duplicate their common ancestors under the first one. The arithmetic the
two share is `btclib.hashes.hash256` and the byte-order convention
`merkle_proof.py` already states; nothing about the walk itself is.

**The hazard is the whole of the risk, and it is attacker-supplied.** A
partial tree is two counters and a bit stream, sent by whichever peer
answered a `filterload` -- or, since this library carries no bloom
filter, by any peer that chooses to send one unsolicited. Core carries an
`fBad` flag on `CPartialMerkleTree` for exactly this: `TraverseAndExtract`
(`src/merkleblock.cpp`) sets it rather than indexing past `vBits` or
`vHash`, and `ExtractMatches` answers a zero hash rather than propagating
whatever the walk produced. A zero hash is not this library's answer --
nothing here is `bool`-shaped -- so every one of Core's refusals is a
`BTClibValueError` naming what was wrong, raised by `assert_valid` at
construction and by `merkle_root`/`matches` again on every read, before a
matched txid or a recomputed root reaches a caller.
`ecc/borromean.py` and issues #1088, #1089, #1094 and #1095 are the same
class of defect in a different ring-signature walk, an `IndexError` or a
silent truncation escaping validation rather than a documented refusal.

**This module builds no bloom filter and holds no wire message.** What a
partial tree is a subset *of* -- BIP37's `CBloomFilter`, and the three
messages that construct and load one -- is not here and does not ship;
`btclib.p2p.merkleblock` is where the wire framing is and where that
decision is argued. A tree built by `from_txids` needs only a boolean
per txid, which a caller may derive from a bloom filter it built
elsewhere, from a set of txids it already holds, or from any other
membership test -- this module asks nothing about where the flags came
from, on the building side any more than on the parsing one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from typing_extensions import Self

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.block.limits import MAX_BLOCK_WEIGHT, MIN_SERIALIZABLE_TRANSACTION_WEIGHT
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    is_octets,
    read_exactly,
)

__all__ = [
    "PartialMerkleTree",
]

# the four octets of the transaction count and the thirty-two of a hash;
# the flag bit vector has no fixed width of its own, being however many
# octets the walk below took to encode
_TRANSACTIONS_SIZE = 4
_HASH_SIZE = 32

# Core's own sanity bound on a declared transaction count, ExtractMatches'
# "nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT". This
# library has no MIN_TRANSACTION_WEIGHT beside MIN_SERIALIZABLE_TRANSACTION_
# WEIGHT -- block/limits.py's docstring is why -- and reuses the
# deserialization bound `block.Block.parse` already divides by for the
# same purpose: the loosest bound a transaction that merely *deserializes*
# still leaves is looser than Core's own check, which is fine here, since
# nothing below allocates on this number directly -- it only refuses a
# count no block could hold, which a looser ceiling still does
_MAX_TRANSACTIONS = MAX_BLOCK_WEIGHT // MIN_SERIALIZABLE_TRANSACTION_WEIGHT


def _tree_width(n_transactions: int, height: int) -> int:
    """Return how many nodes a level holds, Core's `CalcTreeWidth`."""
    return (n_transactions + (1 << height) - 1) >> height


def _tree_height(n_transactions: int) -> int:
    """Return the number of levels above the leaves.

    The smallest height whose width is one, i.e. the root -- a single
    transaction is height zero, its own leaf and its own root.
    """
    height = 0
    while _tree_width(n_transactions, height) > 1:
        height += 1
    return height


def _assert_valid_hash(hash_: bytes, what: str) -> None:
    """Refuse what is not the thirty-two octets of a hash256.

    Private and unvalidated of `what`, as a private twin is: every
    caller hands it a literal of this module.
    """
    value = bytes(hash_)
    if len(value) != _HASH_SIZE:
        err_msg = f"invalid {what}: {len(value)} bytes instead of {_HASH_SIZE}"
        raise BTClibValueError(err_msg)


def _hash_sequence(hashes: Sequence[Octets], what: str) -> tuple[bytes, ...]:
    """Return the tuple a sequence of hashes coerces to.

    An `Octets` is itself a `Sequence`, so passing one instead of a list
    of hashes would zip through its bytes and treat each as its own
    hash (issue #1405); `is_octets` is what refuses that shape before
    `assert_type` is asked whether what is left is a `Sequence` at all.
    """
    if is_octets(hashes):
        raise BTClibTypeError(f"invalid {what} type: {type(hashes).__name__}")
    assert_type(hashes, Sequence, what)
    return tuple(bytes_from_octets(hash_) for hash_ in hashes)


def _bits_from_bytes(data: bytes) -> list[bool]:
    """Return one bool per bit of data, Core's `BytesToBits`.

    Least significant bit of each octet first, "packed per 8 in a byte,
    least significant bit first" -- the opposite convention from
    BIP158's Golomb-coded set, which `block_filter._BitReader` reads
    most significant bit first. The two formats share no code because
    they do not share this.
    """
    return [bool((byte >> bit) & 1) for byte in data for bit in range(8)]


def _bits_to_bytes(bits: Sequence[bool]) -> bytes:
    """Return the packed octets bits encodes, Core's `BitsToBytes`."""
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            out[index // 8] |= 1 << (index % 8)
    return bytes(out)


def _traverse_and_build(
    height: int,
    pos: int,
    hashes: Sequence[bytes],
    matches: Sequence[bool],
    bits: list[bool],
    stored_hashes: list[bytes],
) -> bytes:
    """Return one node's hash while recording the bits and hashes it took.

    Core's `TraverseAndBuild`: every node that is the ancestor of a
    matched leaf is expanded and gets no stored hash of its own, and
    every other node is folded into one, flagged and stored. `hashes`
    are every leaf of the tree, in internal byte order; `matches` is one
    bool per leaf, true for the ones a `merkleblock` sender wants a peer
    to keep.
    """
    n_transactions = len(hashes)
    parent_of_match = any(
        matches[leaf]
        for leaf in range(pos << height, min((pos + 1) << height, n_transactions))
    )
    bits.append(parent_of_match)

    if height == 0 or not parent_of_match:
        node_hash = _calc_hash(height, pos, hashes)
        stored_hashes.append(node_hash)
        return node_hash

    left = _traverse_and_build(
        height - 1, pos * 2, hashes, matches, bits, stored_hashes
    )
    width = _tree_width(n_transactions, height - 1)
    if pos * 2 + 1 < width:
        right = _traverse_and_build(
            height - 1, pos * 2 + 1, hashes, matches, bits, stored_hashes
        )
    else:
        right = left
    return hash256(left + right)


def _calc_hash(height: int, pos: int, hashes: Sequence[bytes]) -> bytes:
    """Return a node's hash by climbing from the leaves, Core's `CalcHash`.

    Height zero is a leaf, taken as it is; an odd width pads by
    duplicating the last node of the level, which is Bitcoin's rule and
    not the malleability `_traverse_and_extract` refuses -- the two
    children being the *same node* read twice rather than two distinct,
    equal ones.
    """
    if height == 0:
        return hashes[pos]
    left = _calc_hash(height - 1, pos * 2, hashes)
    width = _tree_width(len(hashes), height - 1)
    right = _calc_hash(height - 1, pos * 2 + 1, hashes) if pos * 2 + 1 < width else left
    return hash256(left + right)


def _traverse_and_extract(
    height: int,
    pos: int,
    n_transactions: int,
    hashes: Sequence[bytes],
    bits: Sequence[bool],
    used: list[int],
    matches: list[tuple[int, bytes]],
) -> bytes:
    """Return one node's hash, consuming bits and hashes as the walk needs them.

    Core's `TraverseAndExtract`, with every `fBad` it sets turned into a
    `BTClibValueError` raised on the spot rather than a flag read back
    afterwards: this walk never returns to a caller holding a matched
    txid or a recomputed root that a malformed tree produced. `used` is
    `[bits_used, hashes_used]`, mutated in place because Python has no
    reference parameter and every recursive call needs to see the same
    counters the others advanced.
    """
    if used[0] >= len(bits):
        err_msg = "partial merkle tree: flag bits exhausted before the walk finished"
        raise BTClibValueError(err_msg)
    parent_of_match = bits[used[0]]
    used[0] += 1

    if height == 0 or not parent_of_match:
        if used[1] >= len(hashes):
            err_msg = "partial merkle tree: hashes exhausted before the walk finished"
            raise BTClibValueError(err_msg)
        node_hash = hashes[used[1]]
        used[1] += 1
        if height == 0 and parent_of_match:
            matches.append((pos, node_hash))
        return node_hash

    left = _traverse_and_extract(
        height - 1, pos * 2, n_transactions, hashes, bits, used, matches
    )
    width = _tree_width(n_transactions, height - 1)
    if pos * 2 + 1 < width:
        right = _traverse_and_extract(
            height - 1, pos * 2 + 1, n_transactions, hashes, bits, used, matches
        )
        if right == left:
            err_msg = "partial merkle tree: two children of one node hash to"
            err_msg += " the same value"
            raise BTClibValueError(err_msg)
    else:
        right = left
    return hash256(left + right)


@dataclass(frozen=True)
class PartialMerkleTree:
    """BIP37's `CPartialMerkleTree`: a transaction count, hashes, and flags.

    `n_transactions` is the block's own transaction count, never derived
    from either vector below -- a partial tree carries it because the
    tree's shape (`_tree_height`, `_tree_width`) is not otherwise
    recoverable from a subset of its leaves. `hashes` is the depth-first
    vector `TraverseAndBuild` stored, one entry per node that was not
    expanded, held in display order as every hash in this library is and
    reversed on the wire; `flags` is the flag bit stream packed as Core's
    `BitsToBytes` packs it, least significant bit of each octet first,
    padded with zero bits to the octet boundary.

    Neither vector is validated against the other, or against
    `n_transactions`, until `merkle_root` or `matches` walks them: two
    hashes and three bits round-trip through `serialize`/`parse` whatever
    tree they do or do not describe, and it is the walk -- run once at
    construction through `assert_valid`, and again whenever a caller
    reads either property -- that is this module's whole hazard and this
    class's whole contract. The module docstring has why refusal there is
    a `BTClibValueError` and never an exception escaping the walk itself.

    Frozen and hashable, every field being immutable.
    """

    n_transactions: int
    hashes: tuple[bytes, ...]
    flags: bytes

    def __init__(
        self,
        n_transactions: int = 0,
        hashes: Sequence[Octets] = (),
        flags: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "n_transactions", n_transactions)
        object.__setattr__(self, "hashes", _hash_sequence(hashes, "hashes"))
        object.__setattr__(self, "flags", bytes_from_octets(flags))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a tree the walk cannot make sense of.

        `n_transactions`'s type is the one field-level check made without
        walking; every other refusal -- the count's range, the two
        vectors against each other, and the walk itself -- is `_walk`'s,
        run here and its answer discarded, as `BasicBlockFilter.assert_valid`
        exhausts its own decode.
        """
        if not is_integer(self.n_transactions):
            err_msg = "invalid n_transactions type: "
            err_msg += type(self.n_transactions).__name__
            raise BTClibTypeError(err_msg)

        self._walk()

    def _walk(self) -> tuple[bytes, tuple[tuple[int, bytes], ...]]:
        """Return the recomputed root and the matched txids with their position.

        Core's `ExtractMatches`, minus the `fBad`/zero-hash pair: every
        one of its refusals is a `BTClibValueError` here, named after
        which condition fired rather than folded into one flag. In
        order: the count is neither zero nor past what any block could
        hold; the hash vector is not longer than the count; there are at
        least as many flag bits as hashes; the walk itself never runs out
        of either (`_traverse_and_extract`) and never finds two children
        of one node equal; and, once the walk is done, no whole octet of
        flag bits and no hash went unused -- a peer that sent more of
        either than the tree needed sent a second encoding of the one
        tree, which is malleability by the same reasoning as the
        duplicate-child refusal.

        The positions are in ascending order, the walk visiting the tree
        left to right; `n_transactions` is not re-derived from them, so a
        caller comparing this against a chain it holds still names the
        block by height or by the header this message travelled beside,
        neither of which this class carries. Private, and read twice over
        by the two properties below: each recomputes rather than caching,
        as `BasicBlockFilter.element_hashes` re-decodes on every read.
        """
        n_transactions = self.n_transactions
        if n_transactions <= 0:
            raise BTClibValueError("partial merkle tree: transaction count is zero")
        if n_transactions > _MAX_TRANSACTIONS:
            err_msg = (
                f"partial merkle tree: transaction count too high: {n_transactions}"
            )
            err_msg += f", max is {_MAX_TRANSACTIONS}"
            raise BTClibValueError(err_msg)

        hashes = []
        for hash_ in self.hashes:
            _assert_valid_hash(hash_, "hash length")
            hashes.append(bytes(hash_)[::-1])
        if len(hashes) > n_transactions:
            err_msg = f"partial merkle tree: {len(hashes)} hashes"
            err_msg += f" for {n_transactions} transactions"
            raise BTClibValueError(err_msg)

        bits = _bits_from_bytes(bytes(self.flags))
        if len(bits) < len(hashes):
            err_msg = f"partial merkle tree: {len(bits)} flag bits"
            err_msg += f" for {len(hashes)} hashes"
            raise BTClibValueError(err_msg)

        height = _tree_height(n_transactions)
        used = [0, 0]
        matches: list[tuple[int, bytes]] = []
        root = _traverse_and_extract(
            height, 0, n_transactions, hashes, bits, used, matches
        )

        # Core's CeilDiv(nBitsUsed, 8) != CeilDiv(vBits.size(), 8): a whole
        # octet the walk never reached, as opposed to the zero padding
        # bits every stream carries up to the octet boundary
        if -(-used[0] // 8) != -(-len(bits) // 8):
            raise BTClibValueError(
                "partial merkle tree: unused flag bits after the walk"
            )
        if used[1] != len(hashes):
            raise BTClibValueError("partial merkle tree: unused hashes after the walk")

        return root[::-1], tuple((pos, txid[::-1]) for pos, txid in matches)

    @property
    def merkle_root(self) -> bytes:
        """Return the root the walk recomputes, refusing what it cannot walk.

        Equal to a header's `merkle_root` only if the tree is one built
        over that header's own block -- `_walk`'s docstring, and
        `btclib.p2p.merkleblock`'s, are where that comparison is a
        caller's and not this class's.
        """
        return self._walk()[0]

    @property
    def matches(self) -> tuple[tuple[int, bytes], ...]:
        """Return the matched txids the walk recovers, with their position."""
        return self._walk()[1]

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the count, then the hash vector, then the flag octets."""
        if check_validity:
            self.assert_valid()

        out = self.n_transactions.to_bytes(_TRANSACTIONS_SIZE, byteorder="little")
        out += var_int.serialize(len(self.hashes))
        for hash_ in self.hashes:
            out += bytes(hash_)[::-1]
        out += var_int.serialize(len(self.flags))
        out += bytes(self.flags)
        return out

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the tree these octets encode, Core's `SERIALIZE_METHODS`.

        No count here is bounded ahead of the read beyond `var_int`'s own
        default: `n_transactions` is a plain four-octet field with no
        allocation behind it, and the two vectors that follow are read
        straight from the stream, so a peer cannot ask for more of
        either than the payload actually carries -- the same reasoning
        `block_filters.CFCheckpt`'s docstring gives for its own unbounded
        vector. What decides whether the tree is one worth walking is
        `assert_valid`, reached through `check_validity` as everywhere
        else in this library, and it is where this module's docstring
        promises every refusal is raised.
        """
        stream = bytesio_from_binarydata(data)

        n_transactions = int.from_bytes(
            read_exactly(stream, _TRANSACTIONS_SIZE, "transaction count"),
            byteorder="little",
        )

        hash_count = var_int.parse(stream)
        hashes = [
            read_exactly(stream, _HASH_SIZE, "hash")[::-1] for _ in range(hash_count)
        ]

        flag_byte_count = var_int.parse(stream)
        flags = read_exactly(stream, flag_byte_count, "flags")
        assert_no_trailing(data, stream, "partial merkle tree")

        return cls(n_transactions, hashes, flags, check_validity=check_validity)

    @classmethod
    def from_txids(
        cls,
        txids: Sequence[Octets],
        matches: Sequence[bool],
        *,
        check_validity: bool = True,
    ) -> Self:
        """Return the tree keeping the txids `matches` flags, over all of them.

        Core's `CPartialMerkleTree(vTxid, vMatch)`/`TraverseAndBuild`:
        `txids` is every transaction of the block, in block order and in
        display order as `Tx.id` gives it, and `matches` is one bool per
        txid, true for the ones a receiver is meant to be able to recover.
        Which txids a sender matches is its own decision and is not
        asked here -- this is the arithmetic BIP37's construction shares
        with any other caller that already knows which positions it
        wants kept.

        Over distinct txids, and within the count `assert_valid` bounds,
        the tree built this way passes it -- which is what makes a call to
        this the way `tests/block/partial_merkle_tree_test.py` builds a
        valid vector rather than recording one by hand. An empty `txids` is
        refused here; the upper bound is not, and neither is a repeated
        txid, which gives two siblings that hash equal -- the walk's
        refusal rather than the construction's.
        """
        if is_octets(txids):
            raise BTClibTypeError(f"invalid txids type: {type(txids).__name__}")
        assert_type(txids, Sequence, "txids")
        if is_octets(matches):
            raise BTClibTypeError(f"invalid matches type: {type(matches).__name__}")
        assert_type(matches, Sequence, "matches")

        internal_hashes = [bytes_from_octets(txid, _HASH_SIZE)[::-1] for txid in txids]
        match_flags = list(matches)
        if len(match_flags) != len(internal_hashes):
            err_msg = f"invalid matches count: {len(match_flags)}"
            err_msg += f" instead of {len(internal_hashes)}"
            raise BTClibValueError(err_msg)
        for flag in match_flags:
            assert_type(flag, bool, "matches element")

        n_transactions = len(internal_hashes)
        if n_transactions == 0:
            raise BTClibValueError(
                "cannot build a partial merkle tree of no transactions"
            )

        height = _tree_height(n_transactions)
        bits: list[bool] = []
        stored_hashes: list[bytes] = []
        _traverse_and_build(
            height, 0, internal_hashes, match_flags, bits, stored_hashes
        )

        return cls(
            n_transactions,
            [hash_[::-1] for hash_ in stored_hashes],
            _bits_to_bytes(bits),
            check_validity=check_validity,
        )
