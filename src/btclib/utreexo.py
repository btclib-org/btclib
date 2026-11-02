# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A Utreexo accumulator that keeps the roots only: a `Stump`.

Utreexo replaces the UTXO set with a forest of perfect Merkle trees, one
per set bit of the leaf count, and a node keeps the roots alone. A spend
carries a `Proof`: the positions of the leaves it spends and the hashes
needed to climb from them to the roots.

This module follows the draft BIP 181, which specifies the accumulator,
and the order the draft BIP 182 gives a block's changes: its deletions,
then its additions. Both drafts are in
[bitcoin/bips#1923](https://github.com/bitcoin/bips/pull/1923), beside BIP
183. BIP 182's leaf hashes and BIP 183's messages are not here.

`Stump`, `Proof` and `UpdateData` follow rustreexo's, at
mit-dci/rustreexo@b73cbac1f4 (tag v0.7.0), and its `test_values/` files run
against this module unchanged (`tests/_data/README.md` pins them). The Go
library utreexo/utreexo@9869ffeefc (tag v0.18.0), which utreexod uses, is the
second reference. The full forest with leaf caching (`Pollard`, `MemForest`)
is not here: a `Stump` verifies and updates, it never proves.

## The tree

Leaves are 32-byte hashes the caller chose; the accumulator does not say
what they commit to. A parent is SHA-512/256 of its left child followed by
its right child, computed by `hashlib` as `sha512_256`.

A node is named by its position. The leaves of a forest of `rows` rows are
`0 ... 2**rows - 1`, the next row follows, and so on up to the last
position of the top row. `rows` is the least number of rows that holds
every leaf, so a position above the leaves moves when the forest grows.
A proof's target is a position of the forest as it stands, except that one
above the leaves may be counted in a forest of 63 rows, where it does not
move: it is then `2**63` or more. A leaf's position is the same in both.

A deleted leaf leaves an empty node, 32 zero bytes. An empty node does
not hash: the parent of an empty node and any node is that node, and the
parent of two empty nodes is empty. A root may therefore be empty, and
`Stump.roots` always holds one root per set bit of `Stump.leaves`. A leaf
of 32 zero bytes cannot be added or proven, because it reads as empty.

## Where this departs from rustreexo v0.7.0

Among what this module refuses and the reference accepts:

- **A proof carries exactly the hashes its targets call for**, where the
  reference ignores extra ones.
- **An added leaf of 32 zero bytes is refused.** rustreexo reads it as an
  implicit deletion (SwiftSync), which is not implemented here.
- **A remembered index past the added leaves is refused**, where the
  reference ignores it.
- **`update_data` refuses a proof that does not prove `del_hashes`**,
  as `modify` does; the reference computes the update data from it.
- **The bytes are read exactly**: nothing after them, and no `01` tag, the
  placeholder the reference uses to find the roots to destroy and never
  stores.

Every refusal is one of btclib's exceptions, where the reference returns
its own error or panics.

## Serialization

`Stump.serialize` and `Proof.serialize` write rustreexo's bytes,
all integers little endian: for a `Stump` the leaf count, the number of
roots and the roots; for a `Proof` the number of targets, the targets,
the number of hashes and the hashes. A hash is `00` for an empty node and
`02` followed by its 32 bytes otherwise. `parse` refuses the `01` tag, as
the departures above say.

The Go library's `Stump.Serialize` says it is compatible with rustreexo,
but writes each root as 32 bytes with no tag, which is rustreexo's format
up to v0.3.0; `parse` here does not read it. utreexod's wire
encoding of a proof is not implemented.
"""

from __future__ import annotations

import bisect
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO
from typing import Self, cast

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.utils import (
    _message_text,
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_octets,
    read_exactly,
)

__all__ = ["Proof", "Stump", "UpdateData"]

_HASH_SIZE = 32
_EMPTY = bytes(_HASH_SIZE)

# the forest of rustreexo's MAX_FOREST_ROWS: leaf counts and positions
# are unsigned 64-bit integers there, and the leaf count stays below this
_MAX_LEAVES = 1 << 63
_MAX_FOREST_ROWS = 63
# rustreexo's MAX_PROOF_DESERIALIZE_COUNT, for targets and for hashes
_MAX_PROOF_COUNT = 10_000_000
_U64 = (1 << 64) - 1

_TAG_EMPTY = b"\x00"
_TAG_HASH = b"\x02"

_Position = int
_Node = tuple[_Position, bytes]


# --- hashes and checked arguments


def _hashlib_has_sha512_256() -> bool:
    """Return whether `hashlib.new` serves SHA-512/256.

    It is not in `hashlib.algorithms_guaranteed`, so an interpreter may
    lack it.
    """
    try:
        hashlib.new("sha512_256")
    except ValueError:
        return False
    return True


_SHA512_256_IN_HASHLIB = _hashlib_has_sha512_256()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    """Return the parent of two nodes, an empty node being skipped."""
    if left == _EMPTY:
        return right
    if right == _EMPTY:
        return left
    if not _SHA512_256_IN_HASHLIB:
        raise BTClibRuntimeError("hashlib has no sha512_256, the Utreexo hash")
    return hashlib.new("sha512_256", left + right).digest()


def _int(value: object, what: str, ceiling: int) -> int:
    """Return a value that is an int in `[0, ceiling)`, refusing any other."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if not 0 <= value < ceiling:
        raise BTClibValueError(f"invalid {what}: {_message_text(value)}")
    return value


def _u64(value: object, what: str) -> int:
    return _int(value, what, 1 << 64)


def _leaf_count(value: object) -> int:
    return _int(value, "leaves", _MAX_LEAVES)


def _sequence(values: object, what: str) -> Sequence[object]:
    """Refuse an `Octets`, a sequence of ints, as a sequence of items."""
    if is_octets(values):
        raise BTClibTypeError(f"invalid {what} type: {type(values).__name__}")
    assert_type(values, Sequence, what)
    return cast("Sequence[object]", values)


def _hashes(values: object, what: str) -> tuple[bytes, ...]:
    return tuple(
        bytes_from_octets(v, _HASH_SIZE)  # type: ignore[arg-type]
        for v in _sequence(values, what)
    )


def _leaf_hashes(values: object, what: str) -> tuple[bytes, ...]:
    """Return hashes that can be leaves: none of them is empty."""
    hashes = _hashes(values, what)
    if _EMPTY in hashes:
        raise BTClibValueError(f"invalid {what}: an empty hash is no leaf")
    return hashes


def _positions(values: object, what: str) -> tuple[int, ...]:
    return tuple(_u64(v, what) for v in _sequence(values, what))


def _nodes(values: object, what: str) -> tuple[_Node, ...]:
    out = []
    for item in _sequence(values, what):
        pair = _sequence(item, what)
        if len(pair) != 2:
            raise BTClibValueError(f"invalid {what}: not a (position, hash) pair")
        hash_ = bytes_from_octets(pair[1], _HASH_SIZE)  # type: ignore[arg-type]
        out.append((_u64(pair[0], what), hash_))
    return tuple(out)


# --- positions, rustreexo's `util`


def _tree_rows(leaves: int) -> int:
    return (leaves - 1).bit_length() if leaves else 0


def _detect_row(pos: int, rows: int) -> int:
    marker = 1 << rows
    row = 0
    while pos & marker:
        marker >>= 1
        row += 1
    return row


def _parent(pos: int, rows: int) -> int:
    return (pos >> 1) | (1 << rows)


def _parent_many(pos: int, rise: int, rows: int) -> int:
    if rise == 0:
        return pos
    mask = (2 << rows) - 1
    return ((pos >> rise) | (mask << (rows - (rise - 1)))) & mask


def _root_position(leaves: int, row: int, rows: int) -> int:
    mask = (2 << rows) - 1
    before = leaves & (mask << (row + 1))
    return ((before >> row) | (mask << (rows + 1 - row))) & mask


def _is_root_position(pos: int, leaves: int, rows: int) -> bool:
    row = _detect_row(pos, rows)
    return bool(leaves & (1 << row)) and _root_position(leaves, row, rows) == pos


def _start_position_at_row(row: int, rows: int) -> int:
    return (2 << rows) - (2 << (rows - row))


def _is_ancestor(higher: int, lower: int, rows: int) -> bool:
    if higher == lower:
        return False
    lower_row = _detect_row(lower, rows)
    higher_row = _detect_row(higher, rows)
    if higher_row < lower_row:
        return False
    return higher == _parent_many(lower, higher_row - lower_row, rows)


def _remove_bit(value: int, bit: int) -> int:
    upper = value & (_U64 ^ ((2 << bit) - 1))
    lower = value & ((1 << bit) - 1)
    return (upper >> 1) | lower


def _calc_next_pos(pos: int, del_pos: int, rows: int) -> int:
    """Return where the node at `pos` is once the node `del_pos` is gone."""
    del_row = _detect_row(del_pos, rows)
    pos_row = _detect_row(pos, rows)
    lower = _remove_bit(pos, del_row - pos_row)
    higher = (1 << (pos_row + 1)) << (rows - pos_row - 1)
    return higher | lower


def _detwin(nodes: Sequence[int], rows: int) -> list[int]:
    """Replace each pair of sibling nodes by their parent, repeatedly."""
    todo = sorted(nodes)
    out = []
    while todo:
        node = todo.pop(0)
        if todo and todo[0] == node ^ 1:
            parent = _parent(node, rows)
            if parent not in todo:
                bisect.insort(todo, parent)
            todo.pop(0)
        else:
            out.append(node)
    return out


def _detect_offset_trees(pos: int, leaves: int) -> int:
    """Return how many trees of the forest lie before the node `pos`."""
    rows = _tree_rows(leaves)
    row = _detect_row(pos, rows)
    bigger = 0
    marker = pos
    while (marker << row) & ((2 << rows) - 1) >= (1 << rows) & leaves:
        size = (1 << rows) & leaves
        if size:
            marker -= size
            bigger += 1
        rows -= 1
        if rows < 0:
            raise BTClibValueError(f"position {pos} is outside the forest")
    return bigger


def _get_proof_positions(targets: Sequence[int], leaves: int, rows: int) -> list[int]:
    """Return the positions whose hashes a proof of `targets` carries."""
    proof: set[int] = set()
    seen = set(targets)
    computed = list(targets)
    i = 0
    while i < len(computed):
        pos = computed[i]
        i += 1
        if _is_root_position(pos, leaves, rows):
            continue
        sibling = pos ^ 1
        if sibling in seen:
            proof.discard(pos)
        else:
            proof.add(sibling)
        parent = _parent(pos, rows)
        if parent not in seen:
            computed.append(parent)
            seen.add(parent)
    return sorted(proof)


def _roots_to_destroy(adds: int, leaves: int, roots: Sequence[bytes]) -> list[int]:
    """Return the positions of the empty roots that `adds` leaves write over."""
    if _EMPTY not in roots:
        return []
    stack: list[bytes | None] = list(roots)
    destroyed = []
    for add in range(adds):
        row = 0
        while (leaves >> row) & 1:
            if stack.pop() == _EMPTY:
                after = _tree_rows(leaves + (adds - add))
                destroyed.append(_root_position(leaves, row, after))
            row += 1
        stack.append(None)
        leaves += 1
    return destroyed


def _calc_next_positions(
    block_targets: Sequence[int], nodes: Sequence[_Node], leaves: int
) -> list[_Node]:
    """Move `nodes` up to where the deletion of `block_targets` leaves them."""
    rows = _tree_rows(leaves)
    deleted = _detwin(block_targets, rows)
    out = []
    for pos, hash_ in nodes:
        for target in deleted:
            if _is_root_position(pos, leaves, rows):
                break
            if _detect_offset_trees(target, leaves) != _detect_offset_trees(
                pos, leaves
            ):
                continue
            if _is_ancestor(_parent(target, rows), pos, rows):
                pos = _calc_next_pos(pos, target, rows)  # noqa: PLW2901
        out.append((pos, hash_))
    return sorted(out)


def _remap(leaves: int, adds: int, nodes: Sequence[_Node]) -> list[_Node]:
    """Renumber `nodes` after `adds` leaves grew the forest by a row."""
    old_rows = _tree_rows(leaves)
    new_rows = _tree_rows(leaves + adds)
    if new_rows <= old_rows:
        return list(nodes)
    out = []
    for pos, hash_ in nodes:
        row = _detect_row(pos, old_rows)
        offset = pos - _start_position_at_row(row, old_rows)
        out.append((offset + _start_position_at_row(row, new_rows), hash_))
    return out


# --- the proof arithmetic


def _translate(pos: int, from_rows: int, to_rows: int) -> int:
    """Return the position in a forest of `to_rows` rows of the node at `pos`.

    `util::translate` of rustreexo: a leaf keeps its position, a node of a
    higher row keeps its offset in the row.
    """
    row = _detect_row(pos, from_rows)
    if row == 0:
        return pos
    offset = pos - _start_position_at_row(row, from_rows)
    return offset + _start_position_at_row(row, to_rows)


def _to_local(targets: Sequence[int], leaves: int) -> list[int]:
    """Return the targets of a proof as positions of the forest of `leaves`.

    A target is counted in a forest of `_MAX_FOREST_ROWS` rows, so that it
    does not move as the forest grows: `util::translate_to_local` of
    rustreexo v0.7.0.
    """
    rows = _tree_rows(leaves)
    local = []
    for target in targets:
        if _detect_row(target, _MAX_FOREST_ROWS) > rows:
            raise BTClibValueError("proof target outside the forest")
        local.append(_translate(target, _MAX_FOREST_ROWS, rows))
    if (local and not leaves) or any(t >= (2 << rows) - 1 for t in local):
        raise BTClibValueError("proof target outside the forest")
    if len(set(local)) != len(local):
        raise BTClibValueError("duplicate proof targets")
    return local


def _climb(
    proof_targets: Sequence[int],
    proof_hashes: Sequence[bytes],
    pairs: Sequence[tuple[bytes, bytes]],
    leaves: int,
) -> tuple[list[_Node], list[tuple[int, bytes, bytes]]]:
    """Hash the targets and the proof up to the roots.

    `Proof::calculate_hashes_delete` of rustreexo. `pairs` is the `(old, new)`
    hash of each target: equal to verify a proof, `(hash, empty)` to delete
    the target. Return every node reached, at its `new` hash, and the
    `(position, old, new)` of each root reached.
    """
    if len(proof_targets) != len(pairs):
        raise BTClibValueError(
            f"{len(proof_targets)} targets for {len(pairs)} leaf hashes"
        )
    targets = _to_local(proof_targets, leaves)
    rows = _tree_rows(leaves)
    positions = _get_proof_positions(targets, leaves, rows)
    if len(positions) != len(proof_hashes):
        raise BTClibValueError(
            f"{len(proof_hashes)} proof hashes instead of {len(positions)}"
        )

    provided = sorted(
        [
            *zip(targets, pairs, strict=True),
            *((p, (h, h)) for p, h in zip(positions, proof_hashes, strict=True)),
        ]
    )
    computed: list[tuple[int, tuple[bytes, bytes]]] = []
    cursor = [0, 0]  # next computed, next provided

    def take() -> tuple[int, tuple[bytes, bytes]] | None:
        c = computed[cursor[0]] if cursor[0] < len(computed) else None
        p = provided[cursor[1]] if cursor[1] < len(provided) else None
        if c is not None and (p is None or c[0] < p[0]):
            cursor[0] += 1
            return c
        if p is not None:
            cursor[1] += 1
        return p

    roots: list[tuple[int, bytes, bytes]] = []
    while (node := take()) is not None:
        pos, (old, new) = node
        if _is_root_position(pos, leaves, rows):
            roots.append((pos, old, new))
            continue
        sibling = take()
        if sibling is None or sibling[0] != pos | 1:
            raise BTClibValueError(f"no sibling for position {pos}")
        computed.append(
            (
                _parent(pos, rows),
                (_parent_hash(old, sibling[1][0]), _parent_hash(new, sibling[1][1])),
            )
        )
    nodes = [(p, new) for p, (_, new) in [*provided, *computed]]
    return nodes, roots


# --- the public classes


@dataclass(frozen=True, init=False)
class UpdateData:
    """What a `Stump.modify` changed, to update proofs cached before it.

    `prev_num_leaves` is the leaf count before the change; `to_destroy` the
    positions of the empty roots the additions wrote over; `new_add` the
    `(position, hash)` of the nodes the additions created, in the forest
    after the change; `new_del` those of the nodes the deletions changed,
    in the forest before it.
    """

    to_destroy: tuple[int, ...]
    prev_num_leaves: int
    new_add: tuple[_Node, ...]
    new_del: tuple[_Node, ...]

    def __init__(
        self,
        to_destroy: Sequence[int] = (),
        prev_num_leaves: int = 0,
        new_add: Sequence[tuple[int, Octets]] = (),
        new_del: Sequence[tuple[int, Octets]] = (),
    ) -> None:
        object.__setattr__(self, "to_destroy", _positions(to_destroy, "to_destroy"))
        object.__setattr__(self, "prev_num_leaves", _leaf_count(prev_num_leaves))
        object.__setattr__(self, "new_add", _nodes(new_add, "new_add"))
        object.__setattr__(self, "new_del", _nodes(new_del, "new_del"))


def _remaining(stream: BytesIO) -> int:
    return stream.getbuffer().nbytes - stream.tell()


def _read_u64(stream: BytesIO, what: str) -> int:
    return int.from_bytes(read_exactly(stream, 8, what), "little")


def _read_hashes(stream: BytesIO, count: int, what: str) -> list[bytes]:
    hashes = []
    for _ in range(count):
        tag = read_exactly(stream, 1, f"{what} hash tag")
        if tag == _TAG_EMPTY:
            hashes.append(_EMPTY)
        elif tag == _TAG_HASH:
            hash_ = read_exactly(stream, _HASH_SIZE, f"{what} hash")
            if hash_ == _EMPTY:
                raise BTClibValueError(f"{what}: an empty hash written as a hash")
            hashes.append(hash_)
        else:
            raise BTClibValueError(f"{what}: invalid hash tag {tag.hex()}")
    return hashes


def _write_hashes(hashes: Sequence[bytes]) -> bytes:
    return b"".join(_TAG_EMPTY if h == _EMPTY else _TAG_HASH + h for h in hashes)


@dataclass(frozen=True, init=False)
class Proof:
    """The leaves a spend proves, by position, and the hashes that prove them.

    `hashes` are the hashes of the siblings along the paths from `targets`
    to the roots, that cannot be computed from the targets themselves,
    in the order of their positions.
    """

    targets: tuple[int, ...]
    hashes: tuple[bytes, ...]

    def __init__(
        self, targets: Sequence[int] = (), hashes: Sequence[Octets] = ()
    ) -> None:
        object.__setattr__(self, "targets", _positions(targets, "targets"))
        object.__setattr__(self, "hashes", _hashes(hashes, "hashes"))

    @property
    def serialize(self) -> bytes:
        """Return rustreexo's bytes, the targets then the hashes."""
        return (
            len(self.targets).to_bytes(8, "little")
            + b"".join(t.to_bytes(8, "little") for t in self.targets)
            + len(self.hashes).to_bytes(8, "little")
            + _write_hashes(self.hashes)
        )

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the proof of `serialize`'s bytes.

        Construction always validates, so `check_validity` changes nothing.
        """
        del check_validity
        stream = bytesio_from_binarydata(data)
        count = _read_u64(stream, "proof target count")
        # a target takes 8 bytes: do not allocate for a count the data lacks
        if count > _MAX_PROOF_COUNT or count * 8 > _remaining(stream):
            raise BTClibValueError(f"proof: {count} targets do not fit the data")
        targets = [_read_u64(stream, "proof target") for _ in range(count)]
        count = _read_u64(stream, "proof hash count")
        if count > _MAX_PROOF_COUNT or count > _remaining(stream):
            raise BTClibValueError(f"proof: {count} hashes do not fit the data")
        hashes = _read_hashes(stream, count, "proof")
        assert_no_trailing(data, stream, "proof")
        return cls(targets, hashes)

    def update(
        self,
        cached_hashes: Sequence[Octets],
        add_hashes: Sequence[Octets],
        block_targets: Sequence[int],
        remembers: Sequence[int],
        update_data: UpdateData,
    ) -> tuple[Proof, tuple[bytes, ...]]:
        """Return this proof, valid after a block, with its leaf hashes.

        The proof is of `cached_hashes`, leaves a wallet keeps. The block
        deleted `block_targets` and added `add_hashes`, and `update_data` is
        what `Stump.update_data` returned for it. `remembers` indexes
        the added leaves to cache. Leaves in `block_targets` are dropped.

        A hash the new proof needs, that neither the old proof nor the
        block carries, is not known to a stump: that is refused.
        """
        cached = _leaf_hashes(cached_hashes, "cached_hashes")
        adds = _leaf_hashes(add_hashes, "add_hashes")
        deleted = _positions(block_targets, "block_targets")
        kept = _positions(remembers, "remembers")
        assert_type(update_data, UpdateData, "update_data")
        if len(cached) != len(self.targets):
            raise BTClibValueError(
                f"{len(cached)} cached hashes for {len(self.targets)} targets"
            )
        if any(index >= len(adds) for index in kept):
            raise BTClibValueError("a remembered index is past the added leaves")
        leaves = update_data.prev_num_leaves
        local = _to_local(self.targets, leaves)
        block = _to_local(deleted, leaves)
        positions = _get_proof_positions(local, leaves, _tree_rows(leaves))
        if len(positions) != len(self.hashes):
            raise BTClibValueError(
                f"{len(self.hashes)} proof hashes instead of {len(positions)}"
            )

        # update data that does not describe this proof's forest fails on
        # a position, a shift or a length that no valid forest produces
        try:
            proof, cached_nodes = Proof(local, self.hashes)._after_deletion(
                block, cached, update_data.new_del, leaves
            )
            proof, nodes = proof._after_addition(
                adds, cached_nodes, kept, update_data, leaves
            )
            after = _tree_rows(leaves + len(adds))
            fixed = [_translate(t, after, _MAX_FOREST_ROWS) for t in proof.targets]
        except BTClibValueError:
            raise
        except ValueError as error:
            raise BTClibValueError(f"inconsistent update data: {error}") from error
        return Proof(fixed, proof.hashes), nodes

    def _after_deletion(
        self,
        block_targets: Sequence[int],
        cached: Sequence[bytes],
        updated: Sequence[_Node],
        leaves: int,
    ) -> tuple[Proof, tuple[bytes, ...]]:
        rows = _tree_rows(leaves)
        kept = [
            (t, h)
            for t, h in zip(self.targets, cached, strict=True)
            if t not in block_targets
        ]
        targets = [t for t, _ in kept]
        old_positions = _get_proof_positions(self.targets, leaves, rows)
        needed = _get_proof_positions(targets, leaves, rows)

        new_proof: list[_Node] = []
        for pos, hash_ in zip(old_positions, self.hashes, strict=True):
            if pos not in needed:
                continue
            changed = next((h for p, h in updated if p == pos), None)
            value = hash_ if changed is None else changed
            if value != _EMPTY:
                new_proof.append((pos, value))
        for pos in needed:
            if pos in old_positions or pos in block_targets:
                continue
            found = next((h for p, h in updated if p == pos), None)
            if found is not None and found != _EMPTY:
                new_proof.append((pos, found))

        moved = _calc_next_positions(block_targets, new_proof, leaves)
        moved_targets = _calc_next_positions(block_targets, kept, leaves)
        return (
            Proof([p for p, _ in moved_targets], [h for _, h in moved]),
            tuple(h for _, h in moved_targets),
        )

    def _after_addition(
        self,
        adds: Sequence[bytes],
        cached: Sequence[bytes],
        remembers: Sequence[int],
        update_data: UpdateData,
        leaves: int,
    ) -> tuple[Proof, tuple[bytes, ...]]:
        rows = _tree_rows(leaves)
        proof_positions = _get_proof_positions(self.targets, leaves, rows)
        targets = _remap(
            leaves, len(adds), list(zip(self.targets, cached, strict=True))
        )
        proof = _remap(
            leaves, len(adds), list(zip(proof_positions, self.hashes, strict=True))
        )

        # a remembered leaf starts where it was inserted and moves with the
        # roots that the additions write over
        targets.extend((leaves + index, adds[index]) for index in remembers)
        after = leaves + len(adds)
        for node in update_data.to_destroy:
            targets = _calc_next_positions([node], targets, after)
            proof = _calc_next_positions([node], proof, after)
        targets = sorted(set(targets))

        new_targets = [p for p, _ in targets]
        for pos in sorted(_get_proof_positions(new_targets, after, _tree_rows(after))):
            found_hash = next((h for p, h in update_data.new_add if p == pos), None)
            if found_hash is not None:
                proof.append((pos, found_hash))
            elif not any(p == pos for p, _ in proof):
                raise BTClibValueError(f"no proof hash for position {pos}")
        proof.sort()
        return Proof(new_targets, [h for _, h in proof]), tuple(h for _, h in targets)


@dataclass(frozen=True, init=False)
class Stump:
    """The roots of a forest of `leaves` leaves, and nothing else.

    `roots` holds one root per set bit of `leaves`, the tallest tree first;
    an empty root is 32 zero bytes.
    """

    leaves: int
    roots: tuple[bytes, ...]

    def __init__(self, leaves: int = 0, roots: Sequence[Octets] = ()) -> None:
        object.__setattr__(self, "leaves", _leaf_count(leaves))
        object.__setattr__(self, "roots", _hashes(roots, "roots"))
        if len(self.roots) != self.leaves.bit_count():
            raise BTClibValueError(f"{len(self.roots)} roots for {self.leaves} leaves")

    @property
    def serialize(self) -> bytes:
        """Return rustreexo's bytes, the leaf count then the roots."""
        return (
            self.leaves.to_bytes(8, "little")
            + len(self.roots).to_bytes(8, "little")
            + _write_hashes(self.roots)
        )

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the stump of `serialize`'s bytes.

        Construction always validates, so `check_validity` changes nothing.
        """
        del check_validity
        stream = bytesio_from_binarydata(data)
        leaves = _read_u64(stream, "stump leaf count")
        count = _read_u64(stream, "stump root count")
        if count != leaves.bit_count():
            raise BTClibValueError(f"stump: {count} roots for {leaves} leaves")
        roots = _read_hashes(stream, count, "stump")
        assert_no_trailing(data, stream, "stump")
        return cls(leaves, roots)

    def verify(self, proof: Proof, del_hashes: Sequence[Octets]) -> bool:
        """Return whether `proof` proves `del_hashes` leaves of this forest.

        The i-th hash is the leaf at the i-th target. A proof of no leaf
        proves none. A proof that cannot be read against this forest (too
        many or too few hashes, a position outside it) raises. A computed
        root must equal the root at its position.
        """
        assert_type(proof, Proof, "proof")
        leaf_hashes = _leaf_hashes(del_hashes, "del_hashes")
        if not (proof.targets or proof.hashes):
            return not leaf_hashes
        _, reached = _climb(
            proof.targets,
            proof.hashes,
            [(h, h) for h in leaf_hashes],
            self.leaves,
        )
        at = self._roots_by_position()
        return all(at.get(pos) == old for pos, old, _ in reached)

    def _roots_by_position(self) -> dict[int, bytes]:
        """Return the roots by their position in this forest."""
        rows = _tree_rows(self.leaves)
        positions = [
            _root_position(self.leaves, row, rows)
            for row in range(rows, -1, -1)
            if (self.leaves >> row) & 1
        ]
        return dict(zip(positions, self.roots, strict=True))

    def _delete(
        self, gone: Sequence[bytes], proof: Proof
    ) -> tuple[list[_Node], list[bytes]]:
        """Return the nodes the deletion changes, and the roots it leaves."""
        assert_type(proof, Proof, "proof")
        if not (gone or proof.targets or proof.hashes):
            return [], list(self.roots)
        nodes, reached = _climb(
            proof.targets, proof.hashes, [(h, _EMPTY) for h in gone], self.leaves
        )
        at = self._roots_by_position()
        changed = {}
        for pos, old, new in reached:
            if at.get(pos) != old:
                raise BTClibValueError("the proof does not match the roots")
            changed[pos] = new
        roots = [changed.get(pos, root) for pos, root in at.items()]
        positions = set(
            _get_proof_positions(
                _to_local(proof.targets, self.leaves),
                self.leaves,
                _tree_rows(self.leaves),
            )
        )
        return [n for n in nodes if n[0] not in positions], roots

    def _apply(
        self, adds: Sequence[Octets], del_hashes: Sequence[Octets], proof: Proof
    ) -> tuple[Stump, UpdateData]:
        """Delete, then add: the next stump, and what changed."""
        new_leaves = _leaf_hashes(adds, "adds")
        gone = _leaf_hashes(del_hashes, "del_hashes")
        if self.leaves + len(new_leaves) >= _MAX_LEAVES:
            raise BTClibValueError("too many leaves")
        nodes, roots = self._delete(gone, proof)
        roots, created, destroyed = _add(roots, new_leaves, self.leaves)
        return (
            Stump(self.leaves + len(new_leaves), roots),
            UpdateData(destroyed, self.leaves, created, nodes),
        )

    def modify(
        self,
        adds: Sequence[Octets],
        del_hashes: Sequence[Octets],
        proof: Proof,
    ) -> Stump:
        """Delete the proven leaves, then add leaves: the next stump.

        `proof` proves `del_hashes`, as `verify` reads it, and a proof that
        does not is refused.
        """
        return self._apply(adds, del_hashes, proof)[0]

    def update_data(
        self,
        adds: Sequence[Octets],
        del_hashes: Sequence[Octets],
        proof: Proof,
    ) -> UpdateData:
        """Return what `modify` changes, for `Proof.update`.

        Named for what it returns, not `get_*`, which is a query to a node.
        How it departs from rustreexo's `get_update_data` is the module's
        *Where this departs from rustreexo v0.7.0*.
        """
        return self._apply(adds, del_hashes, proof)[1]


def _add(
    roots: list[bytes], adds: Sequence[bytes], leaves: int
) -> tuple[list[bytes], list[_Node], list[int]]:
    """Add leaves to the roots: the roots, the new nodes, the roots destroyed.

    `Stump::add` of rustreexo.
    """
    after = _tree_rows(leaves + len(adds))
    created: set[_Node] = set()
    destroyed = _roots_to_destroy(len(adds), leaves, roots)
    for i, add in enumerate(adds):
        pos = leaves
        for node in _roots_to_destroy(len(adds) - i, leaves, roots):
            pos = _calc_next_pos(pos, node, after)
        row = 0
        hash_ = add
        while (leaves >> row) & 1:
            root = roots.pop()
            if root != _EMPTY:
                created.add((pos & ~1, root))
                created.add((pos, hash_))
                pos = _parent(pos, after)
                hash_ = _parent_hash(root, hash_)
            row += 1
        created.add((pos, hash_))
        roots.append(hash_)
        leaves += 1
    return roots, sorted(created), destroyed
