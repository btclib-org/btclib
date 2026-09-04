# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP37's `merkleblock`: a header, and the partial tree over its block.

Bitcoin Core's `CMerkleBlock` (`src/merkleblock.h`), and the message a
node answers `filterload` with -- one per block that matches the filter,
in place of the `block` a full node would otherwise send. The payload is
the header plus the tree, `SERIALIZE_METHODS(CMerkleBlock, obj)
{ READWRITE(obj.header, obj.txn); }`; the tree's own fields, the walk that
recovers a root and matched txids from them, and this format's whole
hazard are `btclib.block.partial_merkle_tree`, which this module wraps
and does not restate.

**Parsing a `merkleblock` is not endorsing BIP37.** `filterload`,
`filteradd` and `filterclear` -- BIP37's other three messages, which ask
a remote node to build a bloom filter of a wallet's own scripts and hand
it to that node -- are deliberately not in this package at all; that is
the very privacy leak BIP157/158 exist to replace, and offering a
constructor for it would be this library recommending it.
`tests/p2p/core_commands_test.py`'s `_NOT_CARRIED` is where that decision
is recorded. A `merkleblock`, in contrast, is what a peer *sends*,
whether or not it was ever asked to with a `filterload` this library will
not build: software receiving one has to parse it or drop the
connection, and refusing to read what a peer may send is not a defence,
only a missing feature. This module builds no bloom filter, holds no
`filterload` state, and gives a caller no way to construct one --
`PartialMerkleTree.from_txids` takes a boolean per txid however a caller
decided it, which is the whole of what a `merkleblock` needs on either
side of the wire.

**What a `merkleblock` cannot be checked for is that its tree is its
header's.** Core's own `CMerkleBlock::SERIALIZE_METHODS` reads the two
fields with no check between them, and `MerkleBlock.assert_valid` does
the same: it asks that the header is a valid header and that the tree is
one `PartialMerkleTree.merkle_root` and `.matches` can walk, and nothing
here compares the root that walk recomputes against `header.merkle_root`.
A peer can send a header for one block beside a tree built for another,
and the octets still round-trip -- `merkle_proof.py`'s own "a proof is
evidence only together with the header that carries the root" is the
same fact one layer up. Comparing the two is the caller's, once:
`merkleblock.tree.merkle_root == merkleblock.header.merkle_root` is the
whole of it, and only a caller that already trusts the header -- from a
header chain it is following, not from the same message -- gets anything
out of asking.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import Self, override

from btclib.alias import BinaryData
from btclib.block.block_header import BlockHeader
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.exceptions import BTClibTypeError
from btclib.p2p.payload import Payload
from btclib.utils import assert_no_trailing, bytesio_from_binarydata

__all__ = [
    "MerkleBlock",
]


@dataclass(frozen=True)
class MerkleBlock(Payload):
    """The `merkleblock` message: a block header and the partial tree over it.

    Bitcoin Core's `CMerkleBlock`: no field beyond the two, the vector of
    matched positions Core keeps for its own unit tests
    (`vMatchedTxn`, "Public only for unit testing") never having been
    part of the wire encoding -- `MerkleBlock.tree.matches` is where a
    caller here gets the same information back.

    `tree` is the whole hazard this format carries, and it is
    `btclib.block.partial_merkle_tree.PartialMerkleTree`'s, not this
    class's: `assert_valid` here asks that the header and the tree are
    each independently valid, and the module docstring is where what
    that does not check is argued.

    Frozen, and not hashable: `BlockHeader` is a mutable dataclass.
    `dataclasses.replace` is what changes a vector.
    """

    command = "merkleblock"

    header: BlockHeader
    tree: PartialMerkleTree

    def __init__(
        self,
        header: BlockHeader,
        tree: PartialMerkleTree,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "header", header)
        object.__setattr__(self, "tree", tree)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse what is no valid header, or no tree the walk can accept."""
        if not isinstance(self.header, BlockHeader):
            err_msg = "invalid header type: "  # type: ignore[unreachable]
            err_msg += type(self.header).__name__
            raise BTClibTypeError(err_msg)
        self.header.assert_valid()

        if not isinstance(self.tree, PartialMerkleTree):
            err_msg = "invalid tree type: "  # type: ignore[unreachable]
            err_msg += type(self.tree).__name__
            raise BTClibTypeError(err_msg)
        self.tree.assert_valid()

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the header, then the partial tree."""
        if check_validity:
            self.assert_valid()

        out = self.header.serialize(check_validity=check_validity)
        out += self.tree.serialize(check_validity=check_validity)
        return out

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the header and tree the payload carries."""
        stream = bytesio_from_binarydata(data)

        header = BlockHeader.parse(stream, check_validity=check_validity)
        tree = PartialMerkleTree.parse(stream, check_validity=check_validity)
        assert_no_trailing(data, stream, "merkleblock payload")

        return cls(header, tree, check_validity=check_validity)
