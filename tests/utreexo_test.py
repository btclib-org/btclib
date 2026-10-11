# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.utreexo` module.

The files of rustreexo's `test_values/` (`tests/_data/README.md` pins them)
are run the way rustreexo's own `src/stump/mod.rs` and `src/proof/mod.rs`
run them. Their leaves are `sha256` of one byte, and a hash of 64 zeros is
an empty node. The properties after them check `Stump` against a model
that builds the trees by recursion and shares no code with the module.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from btclib import utreexo
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.utreexo import (
    Proof,
    Stump,
    UpdateData,
    _detect_offset_trees,
    _detwin,
    _translate,
)
from tests import load, vector_id

EMPTY = bytes(32)

_CASES = load("_data", "rustreexo", "test_cases.json")
_UPDATES = load("_data", "rustreexo", "update_data_tests.json")
_CACHED = load("_data", "rustreexo", "cached_proof_tests.json")


def leaf(preimage: int) -> bytes:
    """Return rustreexo's `hash_from_u8`: sha256 of the one byte."""
    return hashlib.sha256(bytes([preimage])).digest()


def hashes(hexes: list[str]) -> list[bytes]:
    """Return the hashes a vector writes as hex."""
    return [bytes.fromhex(h) for h in hexes]


def grown(*preimages: int) -> Stump:
    """Return the stump of a forest holding these leaves."""
    return Stump().modify([leaf(p) for p in preimages], [], Proof())


# --- rustreexo's vectors


@pytest.mark.parametrize("case", _CASES["insertion_tests"], ids=vector_id)
def test_insertion(case: dict[str, Any]) -> None:
    """Adding leaves gives the roots the file lists."""
    stump = grown(*case["leaf_preimages"])
    assert stump.leaves == len(case["leaf_preimages"])
    assert list(stump.roots) == hashes(case["expected_roots"])


@pytest.mark.parametrize("case", _CASES["deletion_tests"], ids=vector_id)
def test_deletion(case: dict[str, Any]) -> None:
    """Deleting proven leaves gives the roots the file lists."""
    targets = case["target_values"]
    proof = Proof(targets, hashes(case.get("proofhashes", [])))
    stump = grown(*case["leaf_preimages"]).modify([], [leaf(t) for t in targets], proof)
    assert list(stump.roots) == hashes(case["expected_roots"])


@pytest.mark.parametrize("case", _CASES["proof_tests"], ids=vector_id)
def test_proof(case: dict[str, Any]) -> None:
    """A proof verifies as the file says."""
    stump = Stump(case["numleaves"], hashes(case["roots"]))
    proof = Proof(case["targets"], hashes(case["proofhashes"]))
    leaves = [leaf(p) for p in case["target_preimages"]]
    assert stump.verify(proof, leaves) is case["expected"]


@pytest.mark.parametrize("case", _UPDATES, ids=vector_id)
def test_update_data(case: dict[str, Any]) -> None:
    """`Stump.update_data` reports the nodes the file lists."""
    stump = Stump(case["leaves"], hashes(case["roots"]))
    proof = Proof(case["proof_targets"], hashes(case["proof_hashes"]))
    adds = [leaf(p) for p in case["additional_preimages"]]
    update = stump.update_data(adds, hashes(case["del_hashes"]), proof)

    assert update.prev_num_leaves == case["leaves"]
    assert list(update.to_destroy) == case["to_destroy"]
    expected_add = list(
        zip(case["new_add_pos"], hashes(case["new_add_hash"]), strict=True)
    )
    assert list(update.new_add) == expected_add
    for node in zip(case["new_del_pos"], hashes(case["new_del_hashes"]), strict=True):
        assert node in update.new_del


def fixed(targets: list[int], leaves: int) -> list[int]:
    """Count the file's forest-local targets in the forest of 63 rows."""
    rows = (leaves - 1).bit_length() if leaves else 0
    return [_translate(t, rows, 63) for t in targets]


@pytest.mark.parametrize("case", _CACHED, ids=vector_id)
def test_cached_proof(case: dict[str, Any]) -> None:
    """A cached proof, updated across a block, is the one the file lists.

    The file counts targets in the forest as it stands; the proof counts
    them in a forest of 63 rows, as rustreexo v0.7.0's test converts them.
    """
    leaves = case["initial_leaves"]
    stump = Stump(leaves, hashes(case["initial_roots"]))
    block = case["update"]
    adds = [leaf(p) for p in block["adds"]]
    del_hashes = hashes(block["del_hashes"])
    block_targets = fixed(block["proof"]["targets"], leaves)
    block_proof = Proof(block_targets, hashes(block["proof"]["hashes"]))
    update = stump.update_data(adds, del_hashes, block_proof)
    stump = stump.modify(adds, del_hashes, block_proof)

    cached = Proof(
        fixed(case["cached_proof"]["targets"], leaves),
        hashes(case["cached_proof"]["hashes"]),
    )
    proof, cached_hashes = cached.update(
        hashes(case["cached_hashes"]), adds, block_targets, case["remembers"], update
    )

    assert stump.verify(proof, cached_hashes)
    assert list(proof.targets) == fixed(case["expected_targets"], stump.leaves)
    assert list(stump.roots) == hashes(case["expected_roots"])
    assert list(cached_hashes) == hashes(case["expected_cached_hashes"])


# --- reading a proof, to verify or to delete


def test_a_leaf_that_is_not_there_does_not_verify() -> None:
    """A proof of two leaves neither verifies nor deletes if one is wrong.

    Three leaves have two roots, and the proof reaches both. Its second
    assertion is rustreexo v0.7.0's `test_verify_rejects_mismatched_root`.
    """
    stump = grown(0, 1, 2)
    proof = Proof([0, 2], [leaf(1)])
    assert stump.verify(proof, [leaf(0), leaf(2)])
    assert not stump.verify(proof, [leaf(200), leaf(2)])
    assert not stump.verify(proof, [leaf(0), leaf(201)])
    assert not stump.verify(proof, [leaf(200), leaf(201)])
    with pytest.raises(BTClibValueError, match="does not match"):
        stump.modify([], [leaf(200), leaf(2)], proof)


def test_extra_proof_hashes_are_refused() -> None:
    """A proof holds the hashes its targets call for, no more."""
    stump = grown(0, 1, 2)
    proof = Proof([0, 2], [leaf(1), leaf(9)])
    with pytest.raises(BTClibValueError, match="proof hashes"):
        stump.verify(proof, [leaf(0), leaf(2)])


def test_a_proof_of_no_target_carries_no_hash() -> None:
    """Hashes without a target are refused, to verify or to delete."""
    for stump in (grown(0, 1, 2), Stump()):
        for proof in (Proof([], [leaf(9)]), Proof([0], [leaf(9)])):
            with pytest.raises(
                BTClibValueError, match="targets for|proof hashes|outside"
            ):
                stump.verify(proof, [])
    with pytest.raises(BTClibValueError, match="proof hashes"):
        grown(0, 1, 2).modify([], [], Proof([], [leaf(9)]))


def test_targets_in_any_order_read_against_their_own_leaves() -> None:
    """Targets given in another order read against their own leaves."""
    stump = grown(0, 1, 2)
    forward = Proof([0, 2], [leaf(1)])
    backward = Proof([2, 0], [leaf(1)])
    assert stump.verify(forward, [leaf(0), leaf(2)])
    assert stump.verify(backward, [leaf(2), leaf(0)])
    assert not stump.verify(backward, [leaf(0), leaf(2)])


def test_an_empty_proof_proves_no_leaf() -> None:
    """Only the absence of leaves is proven by a proof of none."""
    stump = grown(0, 1, 2)
    assert stump.verify(Proof(), [])
    assert not stump.verify(Proof(), [leaf(0)])
    with pytest.raises(BTClibValueError, match="outside"):
        Stump().verify(Proof([0], [leaf(1)]), [leaf(0)])


def test_an_empty_node_hashes_as_its_sibling() -> None:
    """Delete the left half of eight leaves, then prove a leaf of the right."""
    leaves = [leaf(i) for i in range(8)]
    stump = Stump().modify(leaves, [], Proof())
    stump = stump.modify([], leaves[:4], model_proof(leaves, [0, 1, 2, 3]))
    assert stump.roots == (merkle([EMPTY] * 4 + leaves[4:]),)
    # position 12 is empty: its sibling, the root, is the node it hashes with
    proof = Proof([4], [leaves[5], merkle(leaves[6:]), EMPTY])
    assert stump.verify(proof, [leaves[4]])
    assert not stump.verify(proof, [leaves[5]])
    after = stump.modify([], [leaves[4]], proof)
    assert after.roots == (merkle([EMPTY] * 5 + leaves[5:]),)


def test_a_target_above_the_leaves_is_counted_from_the_fixed_forest() -> None:
    """With eight leaves, 8 and `1 << 63` name the first node of row one."""
    leaves = [leaf(i) for i in range(8)]
    stump = Stump().modify(leaves, [], Proof())
    hashes_ = [merkle(leaves[2:4]), merkle(leaves[4:])]
    node = merkle(leaves[:2])
    assert stump.verify(Proof([8], hashes_), [node])
    assert stump.verify(Proof([1 << 63], hashes_), [node])
    with pytest.raises(BTClibValueError, match="outside"):
        grown(0).verify(Proof([1 << 63]), [node])


# --- the position arithmetic


def test_detwin_replaces_siblings_by_their_parent() -> None:
    """Match `util::test_detwin` of rustreexo, and a parent given twice."""
    assert _detwin([0, 1, 4, 5, 7], 3) == [7, 8, 10]
    assert _detwin([4, 6, 8, 9], 3) == [4, 6, 12]
    assert _detwin([0, 1, 8], 3) == [8]


def test_a_position_outside_the_forest_has_no_offset() -> None:
    """Position 3 of three leaves is padding, below no tree."""
    with pytest.raises(BTClibValueError, match="outside the forest"):
        _detect_offset_trees(3, 3)


# --- serialization


_ROOT_OF_EIGHT = bytes.fromhex(
    "967cf4f16245d9deeb613d89874cc586e8adfd081c117c7b1004421e3f71f64a"
)
_STUMP_OF_EIGHT = (
    bytes([8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]) + _ROOT_OF_EIGHT
)


def test_stump_serialization_matches_rustreexo() -> None:
    """Read and write the bytes the doc example of `Stump::serialize` shows.

    The example is in `src/stump/mod.rs`. Its eight leaves are `[i; 32]`,
    the first of which is empty here, so the stump is read from the bytes
    instead of built.
    """
    stump = Stump.parse(_STUMP_OF_EIGHT)
    assert stump == Stump(8, [_ROOT_OF_EIGHT])
    assert stump.serialize == _STUMP_OF_EIGHT
    assert Stump.parse(_STUMP_OF_EIGHT.hex()) == stump


def test_proof_serialization_matches_rustreexo() -> None:
    """Write the empty proof as the doc example of `Proof::serialize` does."""
    assert Proof().serialize == bytes(16)
    assert Proof.parse(bytes(16)) == Proof()
    proof = Proof([0, 5], [leaf(1), EMPTY])
    assert proof.serialize == (
        (2).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + (5).to_bytes(8, "little")
        + (2).to_bytes(8, "little")
        + b"\x02"
        + leaf(1)
        + b"\x00"
    )
    assert Proof.parse(proof.serialize) == proof


def test_a_stump_with_an_empty_root_round_trips() -> None:
    """An empty root is the one byte `00`."""
    stump = grown(0, 1).modify([], [leaf(0), leaf(1)], Proof([0, 1]))
    assert stump.roots == (EMPTY,)
    assert stump.serialize.endswith(b"\x00")
    assert Stump.parse(stump.serialize) == stump


_ONE = (1).to_bytes(8, "little")
_ZERO = bytes(8)
_FULL = bytes([255] * 8)
_CAP = (10_000_000).to_bytes(8, "little")


@pytest.mark.parametrize(
    "data, match",
    [
        pytest.param(b"", "not enough data", id="nothing"),
        pytest.param(_ONE + _ONE, "not enough data", id="root missing"),
        pytest.param(_ONE + _FULL + b"\x00", "roots for", id="roots missing"),
        pytest.param(_ONE + _ONE + b"\x01", "invalid hash tag", id="placeholder"),
        pytest.param(_ONE + _ONE + b"\x02" + bytes(32), "empty hash", id="zero hash"),
        pytest.param(
            _ONE + _ONE + b"\x02" + b"\x01" * 31, "not enough data", id="short hash"
        ),
        pytest.param(_ONE + _ONE + b"\x00\x00", "after the stump", id="trailing"),
        pytest.param(_ZERO + _ONE + b"\x00", "roots for", id="roots without leaves"),
        pytest.param(
            (3).to_bytes(8, "little") + _ONE + b"\x00",
            "roots for",
            id="one root of three leaves",
        ),
        pytest.param(
            _FULL + (64).to_bytes(8, "little") + bytes(64),
            "invalid leaves",
            id="too many leaves",
        ),
    ],
)
def test_stump_parse_refuses(data: bytes, match: str) -> None:
    """A stump is refused unless its bytes are exactly a valid one."""
    with pytest.raises(BTClibValueError, match=match):
        Stump.parse(data)


@pytest.mark.parametrize(
    "data, match",
    [
        pytest.param(b"", "not enough data", id="nothing"),
        pytest.param(_ONE, "do not fit", id="target missing"),
        pytest.param(_ONE + _ZERO, "not enough data", id="hash count missing"),
        pytest.param(_FULL, "do not fit", id="huge target count"),
        pytest.param(_ZERO + _FULL, "do not fit", id="huge hash count"),
        pytest.param(_CAP, "do not fit", id="targets the data lacks"),
        pytest.param(_ZERO + _CAP, "do not fit", id="hashes the data lacks"),
        pytest.param(_ZERO + _ZERO + b"\x00", "after the proof", id="trailing"),
    ],
)
def test_proof_parse_refuses(data: bytes, match: str) -> None:
    """A proof is refused unless its bytes are exactly a valid one."""
    with pytest.raises(BTClibValueError, match=match):
        Proof.parse(data)


def test_a_proof_may_carry_an_empty_hash() -> None:
    """The proof of a leaf next to an emptied subtree has one."""
    leaves = [leaf(i) for i in range(8)]
    proof = Proof([4], [leaves[5], merkle(leaves[6:]), EMPTY])
    assert Proof.parse(proof.serialize) == proof


# --- refusals


@pytest.mark.parametrize("count", [3, 5, 7])
def test_a_root_is_the_leaf_at_its_own_position_only(count: int) -> None:
    """A computed root must equal the root at its position.

    The last of an odd count of leaves is a root with no hash to climb
    through. Another root claimed as that leaf is not it.
    """
    stump = grown(*range(count))
    proof = Proof([count - 1])
    assert stump.verify(proof, [leaf(count - 1)])
    for root in stump.roots[:-1]:
        assert not stump.verify(proof, [root])
        with pytest.raises(BTClibValueError, match="does not match"):
            stump.modify([], [root], proof)
    assert stump.modify([], [leaf(count - 1)], proof).leaves == count


@pytest.mark.parametrize(
    "build",
    [
        lambda: Proof(None),  # type: ignore[arg-type]
        lambda: Proof(b"\x00"),
        lambda: Proof([True]),
        lambda: Proof([1.5]),  # type: ignore[list-item]
        lambda: Proof([], b"\x00" * 32),  # type: ignore[arg-type]
        lambda: Proof([], [1]),  # type: ignore[list-item]
        lambda: Stump(1.5),  # type: ignore[arg-type]
        lambda: Stump(0, None),  # type: ignore[arg-type]
        lambda: UpdateData(prev_num_leaves="1"),  # type: ignore[arg-type]
        lambda: UpdateData(new_add=[1]),  # type: ignore[list-item]
        lambda: Stump().modify([], [], None),  # type: ignore[arg-type]
        lambda: Stump().verify(None, []),  # type: ignore[arg-type]
        lambda: Proof().update([], [], [], [], None),  # type: ignore[arg-type]
    ],
)
def test_a_wrong_type_is_refused(build: Callable[[], object]) -> None:
    """An argument of a type the signature does not declare is a type error."""
    with pytest.raises(BTClibTypeError):
        build()


@pytest.mark.parametrize(
    "build",
    [
        lambda: Proof([-1]),
        lambda: Proof([1 << 64]),
        lambda: Proof([], ["00"]),
        lambda: Stump(1 << 63, []),
        lambda: Stump(-1),
        lambda: Stump(3, [leaf(0)]),
        lambda: UpdateData(prev_num_leaves=-1),
        lambda: UpdateData(new_add=[(1,)]),  # type: ignore[list-item]
        lambda: UpdateData(new_add=[(1, 2, 3)]),  # type: ignore[list-item]
        lambda: grown(0).modify([EMPTY], [], Proof()),
        lambda: grown(0).modify([], [EMPTY], Proof([0])),
        lambda: grown(0).verify(Proof([0]), [EMPTY]),
        lambda: grown(0, 1).modify([], [leaf(0)], Proof([0, 1], [])),
        lambda: grown(0, 1).modify([], [leaf(0)], Proof()),
        lambda: grown(0, 1).modify([], [leaf(0), leaf(0)], Proof([0, 0], [])),
        lambda: grown(0, 1).modify([], [leaf(0)], Proof([9], [])),
        lambda: Stump().modify([], [leaf(0)], Proof([0])),
        lambda: grown(0, 1).modify([], [leaf(0)], Proof([0], [leaf(1), leaf(1)])),
        lambda: grown(*range(4)).verify(Proof([0]), [leaf(0)]),
        lambda: grown(*range(4)).verify(Proof([0], [leaf(1)] * 3), [leaf(0)]),
        lambda: grown(*range(8)).verify(Proof([0, 8], [leaf(1)] * 3), [leaf(0)] * 2),
    ],
)
def test_a_malformed_argument_is_refused(build: Callable[[], object]) -> None:
    """An argument of the right type that no input carries is a value error."""
    with pytest.raises(BTClibValueError):
        build()


def test_the_leaf_count_has_a_ceiling() -> None:
    """A stump of the most leaves it can hold takes no more."""
    stump = Stump((1 << 63) - 1, [leaf(i) for i in range(63)])
    with pytest.raises(BTClibValueError, match="too many leaves"):
        stump.modify([leaf(0)], [], Proof())
    with pytest.raises(BTClibValueError, match="too many leaves"):
        stump.update_data([leaf(0)], [], Proof())


def test_a_cached_proof_update_is_checked() -> None:
    """`Proof.update` refuses arguments that do not describe one forest."""
    leaves = [leaf(i) for i in range(8)]
    update = grown(*range(8)).update_data([leaf(9)], [], Proof())
    cached = model_proof(leaves, [0])
    for args, match in (
        (([], [], [], [], update), "cached hashes"),
        (([leaf(0)], [EMPTY], [], [], update), "empty hash"),
        (([EMPTY], [], [], [], update), "empty hash"),
        (([leaf(0)], [], [99], [], update), "outside"),
    ):
        with pytest.raises(BTClibValueError, match=match):
            cached.update(*args)
    with pytest.raises(BTClibValueError, match="proof hashes"):
        Proof([0], []).update([leaf(0)], [], [], [], update)
    with pytest.raises(BTClibValueError, match="outside"):
        cached.update([leaf(0)], [], [], [], UpdateData())
    with pytest.raises(BTClibValueError, match="remembered index"):
        cached.update([leaf(0)], [leaf(9)], [], [1], update)


def test_update_data_of_another_forest_is_refused() -> None:
    """Update data that leaves a deleted sibling in the proof is refused.

    Leaf 1 is deleted, so leaf 0 moves up to the root and needs no hash:
    the update data should say that position 1 is now empty.
    """
    cached = Proof([0], [leaf(1)])
    update = UpdateData(prev_num_leaves=2)
    with pytest.raises(BTClibValueError, match="update data"):
        cached.update([leaf(0)], [], [1], [], update)


def test_update_data_destroying_a_full_root_is_refused() -> None:
    """Position 2 is the full root of two leaves: no addition destroys it.

    The refusal is a `BTClibValueError`, not the `ValueError` of a shift.
    """
    update = UpdateData([2], 2)
    with pytest.raises(BTClibValueError, match="update data"):
        Proof([1], [leaf(1)]).update([leaf(2)], [], [], [], update)


def test_a_remembered_leaf_survives_deleting_everything_before_it() -> None:
    """Delete eight leaves, add five, remember one: its proof verifies."""
    leaves = [leaf(i) for i in range(8)]
    adds = [leaf(i) for i in range(10, 15)]
    stump = Stump().modify(leaves, [], Proof())
    everything = list(range(8))
    block = model_proof(leaves, everything)
    update = stump.update_data(adds, leaves, block)
    proof, proven = Proof().update([], adds, everything, [0], update)
    assert proven == (adds[0],)
    assert stump.modify(adds, leaves, block).verify(proof, proven)


def test_a_remembered_leaf_needs_the_nodes_the_update_data_carries() -> None:
    """Update data without the new nodes leaves a remembered leaf unproven."""
    with pytest.raises(BTClibValueError, match="no proof hash"):
        Proof().update([], [leaf(1)], [], [0], UpdateData(prev_num_leaves=1))


def test_hashlib_sha512_256_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe reports what `hashlib.new` does, as for ripemd160."""

    def raising(*_: Any, **__: Any) -> Any:
        raise ValueError("unsupported hash type sha512_256")

    monkeypatch.setattr(hashlib, "new", raising)
    assert not utreexo._hashlib_has_sha512_256()


def test_a_missing_sha512_256_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without SHA-512/256 no parent is hashed, and the refusal says why."""
    monkeypatch.setattr(utreexo, "_SHA512_256_IN_HASHLIB", False)
    with pytest.raises(BTClibRuntimeError, match="sha512_256"):
        grown(1, 2)
    assert grown(1).roots == (leaf(1),)


# --- properties, against a model built by recursion

_MAX_LEAVES = 40


def merkle(nodes: list[bytes]) -> bytes:
    """Return the root of a perfect tree whose leaves are `nodes`."""
    if len(nodes) == 1:
        return nodes[0]
    half = len(nodes) // 2
    left, right = merkle(nodes[:half]), merkle(nodes[half:])
    if left == EMPTY:
        return right
    if right == EMPTY:
        return left
    return hashlib.new("sha512_256", left + right).digest()


def model_roots(leaves: list[bytes]) -> list[bytes]:
    """Return the roots of a forest holding `leaves`, the tallest tree first."""
    roots, start = [], 0
    for bit in reversed(range(len(leaves).bit_length())):
        if len(leaves) >> bit & 1:
            roots.append(merkle(leaves[start : start + (1 << bit)]))
            start += 1 << bit
    return roots


def model_proof(leaves: list[bytes], targets: list[int]) -> Proof:
    """Return the proof of leaves of a forest never deleted from.

    Every node is a position and the leaves under it. A node is on the
    path of a target if the target is under it, and the proof holds the
    sibling of each path node that is not itself on a path.
    """
    count = len(leaves)
    rows = (count - 1).bit_length()
    spans: dict[int, tuple[int, int]] = {}
    tops = set()
    start = first = 0
    for height in reversed(range(count.bit_length())):
        if not count >> height & 1:
            continue
        for row in range(height + 1):
            first = (2 << rows) - (2 << (rows - row))
            for k in range(1 << (height - row)):
                position = first + (start >> row) + k
                spans[position] = (start + (k << row), start + ((k + 1) << row))
        tops.add(first + (start >> height))
        start += 1 << height
    path = {
        position
        for position, (low, high) in spans.items()
        if any(low <= target < high for target in targets)
    }
    siblings = sorted(
        position ^ 1
        for position in path
        if position not in tops and position ^ 1 not in path
    )
    return Proof(
        targets, [merkle(leaves[slice(*spans[position])]) for position in siblings]
    )


_hash = st.binary(min_size=32, max_size=32).filter(any)
_leaf_lists = st.integers(1, _MAX_LEAVES).flatmap(
    lambda n: st.lists(_hash, min_size=n, max_size=n, unique=True)
)


@given(_leaf_lists)
def test_adding_builds_the_model_forest(leaves: list[bytes]) -> None:
    """The roots of added leaves are the model's."""
    stump = Stump().modify(leaves, [], Proof())
    assert stump.leaves == len(leaves)
    assert list(stump.roots) == model_roots(leaves)


@given(_leaf_lists, st.data())
def test_adding_in_batches_is_adding_at_once(
    leaves: list[bytes], data: st.DataObject
) -> None:
    """Where a block ends does not change the roots."""
    cut = data.draw(st.integers(0, len(leaves)))
    stump = Stump().modify(leaves[:cut], [], Proof())
    stump = stump.modify(leaves[cut:], [], Proof())
    assert stump == Stump().modify(leaves, [], Proof())


@given(_leaf_lists, st.lists(_hash, min_size=1, max_size=12, unique=True), st.data())
def test_adding_in_batches_after_deleting(
    leaves: list[bytes], adds: list[bytes], data: st.DataObject
) -> None:
    """Where a block ends does not change the roots over empty ones either."""
    assume(not set(adds) & set(leaves))
    targets = sorted(
        data.draw(st.sets(st.integers(0, len(leaves) - 1), max_size=len(leaves)))
    )
    stump = Stump().modify(leaves, [], Proof())
    stump = stump.modify([], [leaves[t] for t in targets], model_proof(leaves, targets))
    cut = data.draw(st.integers(0, len(adds)))
    split = stump.modify(adds[:cut], [], Proof()).modify(adds[cut:], [], Proof())
    assert split == stump.modify(adds, [], Proof())


@given(_leaf_lists, st.data())
def test_deleting_proven_leaves_empties_them_in_the_model(
    leaves: list[bytes], data: st.DataObject
) -> None:
    """Adding, then deleting, gives the roots of the trees with empty leaves.

    The roots of a forest built without those leaves are another thing:
    deleting leaf `a` of `[a, b, c, d]` leaves `b` beside the node of `c`
    and `d`, where a forest of `[b, c, d]` pairs `b` with `c`.
    """
    targets = sorted(
        data.draw(st.sets(st.integers(0, len(leaves) - 1), max_size=len(leaves)))
    )
    stump = Stump().modify(leaves, [], Proof())
    proof = model_proof(leaves, targets)
    after = stump.modify([], [leaves[t] for t in targets], proof)
    kept = [EMPTY if i in targets else h for i, h in enumerate(leaves)]
    assert list(after.roots) == model_roots(kept)


@given(_leaf_lists, st.data())
def test_a_proof_verifies_its_own_leaves_only(
    leaves: list[bytes], data: st.DataObject
) -> None:
    """Change one leaf of a proof to a hash or a root, or swap two: it fails."""
    targets = sorted(
        data.draw(st.sets(st.integers(0, len(leaves) - 1), min_size=1, max_size=8))
    )
    stump = Stump().modify(leaves, [], Proof())
    proof = model_proof(leaves, targets)
    proven = [leaves[t] for t in targets]
    assert stump.verify(proof, proven)

    forged = data.draw(st.integers(0, len(targets) - 1))
    other = data.draw(st.one_of(_hash, st.sampled_from(stump.roots)))
    assume(other != proven[forged])
    changed = [*proven[:forged], other, *proven[forged + 1 :]]
    assert not stump.verify(proof, changed)
    with pytest.raises(BTClibValueError):
        stump.modify([], changed, proof)

    swapped = [*proven[1:], proven[0]]
    assert (swapped == proven) or not stump.verify(proof, swapped)


@given(_leaf_lists, st.data())
def test_serialization_round_trips(leaves: list[bytes], data: st.DataObject) -> None:
    """Stumps and proofs survive their bytes."""
    targets = sorted(
        data.draw(st.sets(st.integers(0, len(leaves) - 1), max_size=len(leaves)))
    )
    stump = Stump().modify(leaves, [], Proof())
    proof = model_proof(leaves, targets)
    assert Stump.parse(stump.serialize) == stump
    assert Proof.parse(proof.serialize) == proof
    after = stump.modify([], [leaves[t] for t in targets], proof)
    assert Stump.parse(after.serialize) == after


@given(_leaf_lists, st.lists(_hash, max_size=6, unique=True), st.data())
def test_a_cached_proof_stays_valid_across_a_block(
    leaves: list[bytes], adds: list[bytes], data: st.DataObject
) -> None:
    """Update a wallet's proof through a block, then verify it.

    The wallet caches some leaves, the block deletes some and adds some, and
    the wallet remembers some of the added ones.
    """
    assume(not set(adds) & set(leaves))
    indexes = st.sets(st.integers(0, len(leaves) - 1), max_size=len(leaves))
    cached = sorted(data.draw(indexes))
    deleted = sorted(data.draw(indexes))
    drawn = data.draw(st.sets(st.integers(0, max(len(adds) - 1, 0))))
    remembers = sorted(i for i in drawn if i < len(adds))

    stump = Stump().modify(leaves, [], Proof())
    block = model_proof(leaves, deleted)
    gone = [leaves[i] for i in deleted]
    update = stump.update_data(adds, gone, block)
    new_stump = stump.modify(adds, gone, block)
    proof, proven = model_proof(leaves, cached).update(
        [leaves[i] for i in cached], adds, deleted, remembers, update
    )

    assert new_stump.verify(proof, proven)
    survivors = [leaves[i] for i in cached if i not in deleted]
    remembered = [adds[i] for i in remembers]
    assert sorted(proven) == sorted(survivors + remembered)


def test_deleting_does_not_rebuild_the_forest_without_the_leaves() -> None:
    """The trees keep their shape: deleting `a` is not never adding it."""
    leaves = [leaf(i) for i in range(4)]
    stump = Stump().modify(leaves, [], Proof())
    after = stump.modify([], [leaves[0]], model_proof(leaves, [0]))
    assert list(after.roots) != model_roots(leaves[1:])
    assert list(after.roots) == [merkle([EMPTY, *leaves[1:]])]
