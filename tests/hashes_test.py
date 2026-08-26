# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.hashes` module."""

import hashlib
from hashlib import sha256
from typing import Any

import pytest

from btclib import hashes
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import (
    hash160,
    hash256,
    magic_message,
    merkle_root,
    merkle_root_and_mutated,
    merkle_root_and_mutated_from_hashes,
    merkle_root_from_branch,
    ripemd160,
)
from tests.to_key_test import (
    net_unaware_compressed_pub_keys,
    net_unaware_uncompressed_pub_keys,
    plain_prv_keys,
)


def test_ripemd160_wherever_hashlib_has_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two implementations are one function, answering the same.

    Both branches run here, on every host, which is the point: reaching
    the fallback naturally takes an OpenSSL between 3.0.0 and 3.0.6, i.e.
    a `pragma: no cover` branch nothing ever exercises. Patching the flag
    reaches it instead, and the digest of "abc" is pinned so that the
    assertion is not two calls into the same code on a host that has no
    hashlib ripemd160 to begin with.
    """
    abc = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    octets = bytes(range(256))
    expected = ripemd160(octets)

    monkeypatch.setattr(hashes, "_RIPEMD160_IN_HASHLIB", False)
    assert ripemd160(b"abc").hex() == abc
    assert ripemd160(octets) == expected
    # and through the caller that every address goes through
    assert hash160(octets) == ripemd160(sha256(octets).digest())

    # pure_python_ripemd160 concatenates its argument on the argument's
    # own left side, which a memoryview has no __add__ for; a bytearray
    # already works, bytearray + bytes being an operation
    assert ripemd160(memoryview(octets)) == expected
    assert ripemd160(bytearray(octets)) == expected


def test_hashlib_ripemd160_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe reports what hashlib.new does, not what the host is.

    Faking both answers is what makes the fallback selection testable on
    one interpreter; the real answer here is whatever this interpreter's
    OpenSSL says, and the module-level call has already taken it.
    """

    def raising(*_: Any, **__: Any) -> Any:
        raise ValueError("unsupported hash type ripemd160")

    monkeypatch.setattr(hashlib, "new", raising)
    assert not hashes._hashlib_has_ripemd160()

    # the probe only cares that hashlib.new returned rather than raised,
    # so any hash object does; usedforsecurity=False marks this one as
    # the stand-in it is, no digest ever being taken from it
    monkeypatch.setattr(
        hashlib, "new", lambda *_, **__: hashlib.sha1(usedforsecurity=False)
    )
    assert hashes._hashlib_has_ripemd160()


def test_hash160_hash256() -> None:
    """Verify hash160 and hash256 take keys in every octet spelling."""
    test_vectors = (
        plain_prv_keys
        + net_unaware_compressed_pub_keys
        + net_unaware_uncompressed_pub_keys
    )
    for hexstring in test_vectors:
        hash160(hexstring)
        hash256(hexstring)


def test_magic_message_length_prefix() -> None:
    """The message length is a var_int, as Bitcoin Core serializes it.

    The expected length prefixes are spelled out here instead of being
    computed with var_int.serialize, so that the test pins the wire
    format rather than re-deriving it from the code under test: a
    one-byte length would agree up to 252 bytes, silently diverge from
    253 to 255, and overflow above that.
    """
    magic = b"\x18Bitcoin Signed Message:\n"
    test_vectors = (
        (0, b"\x00"),
        (1, b"\x01"),
        (252, b"\xfc"),
        (253, b"\xfd\xfd\x00"),
        (255, b"\xfd\xff\x00"),
        (256, b"\xfd\x00\x01"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0x10000, b"\xfe\x00\x00\x01\x00"),
    )
    for length, prefix in test_vectors:
        msg = b"a" * length
        assert magic_message(msg) == sha256(magic + prefix + msg).digest()


def test_merkle_root_mutation() -> None:
    """A duplicated trailing subtree is flagged, padding is not.

    CVE-2012-2459: duplicating the trailing subtree of a level leaves the
    root unchanged, so the root alone does not commit to the list. The
    expected flags are spelled out per list rather than derived, because
    the failure being guarded against is exactly a wrong rule: flagging
    the padding of an odd level would reject the honest lists here.
    """
    a, b, c, d, e, f = (bytes([i]) * 32 for i in range(6))
    test_vectors = (
        ([a], False),
        ([a, b], False),
        ([a, b, c], False),  # c is padded with itself: honest
        ([a, b, c, c], True),  # ...and here duplicated: mutated
        ([a, b, c, d, e], False),
        ([a, b, c, d, e, f], False),
        # duplicating two leaves shows up one level up, not at the leaves
        ([a, b, c, d, e, f, e, f], True),
    )
    for data, mutated in test_vectors:
        assert merkle_root_and_mutated(data, hash256)[1] is mutated

    # the root cannot tell the mutation from the list it was built on
    assert merkle_root([a, b, c], hash256) == merkle_root([a, b, c, c], hash256)
    assert merkle_root([a, b, c, d, e, f], hash256) == merkle_root(
        [a, b, c, d, e, f, e, f], hash256
    )


def test_merkle_root_from_hashes() -> None:
    """The bottom level is taken as it is, the leaves being hashes already."""
    a, b, c = (bytes([i]) * 32 for i in range(3))
    leaves = [hash256(item) for item in (a, b, c)]
    assert merkle_root_and_mutated_from_hashes(leaves, hash256) == (
        merkle_root_and_mutated([a, b, c], hash256)
    )
    # a leaf no preimage hashes to, as the coinbase one of a witness tree
    assert merkle_root_and_mutated_from_hashes([b"\x00" * 32], hash256) == (
        b"\x00" * 32,
        False,
    )


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_merkle_root_from_branch_octets_spellings(index: int) -> None:
    """Every `Octets` spelling of leaf and branch reaches the same root.

    `root` and `sibling` land on either side of `+` depending on which
    bit of `index` is set at each step, and a memoryview has no
    `__add__` on either side of it. Which side a branch element lands
    on is not known until `index` has been halved down to it, so the
    implementation copies every element to `bytes` unconditionally
    rather than only the ones a memoryview would otherwise fail on.
    """
    leaf = bytes([0x11]) * 32
    siblings = [bytes([0x22]) * 32, bytes([0x33]) * 32]
    expected = merkle_root_from_branch(leaf, siblings, index, hash256)

    for spell in (bytes, lambda b: b.hex(), bytearray, memoryview):
        root = merkle_root_from_branch(
            spell(leaf), [spell(s) for s in siblings], index, hash256
        )
        assert root == expected
        assert isinstance(root, bytes)


def test_merkle_root_from_branch_empty_branch_is_bytes() -> None:
    """An empty branch answers the leaf, in this function's own bytes."""
    leaf = bytes([0x11]) * 32
    root = merkle_root_from_branch(memoryview(leaf), [], 0, hash256)
    assert root == leaf
    assert isinstance(root, bytes)


def test_merkle_root_empty() -> None:
    """Refuse an empty merkle tree rather than loop forever."""
    # guards against looping forever, never reducing an empty level to a
    # root
    with pytest.raises(BTClibValueError, match="empty merkle tree"):
        merkle_root([], hash256)


@pytest.mark.parametrize(
    "hf",
    [sha256(), hashlib.sha256(b"already fed"), b"\x00", None, 42],
    ids=["a-digest-object", "a-fed-digest", "octets", "None", "an-int"],
)
def test_a_hash_function_that_is_not_one_is_refused(hf: Any) -> None:
    """`sha256()` where `sha256` belongs is the caller error this names.

    A BTClibTypeError and not a BTClibValueError, which is what the five
    boolean verifications rely on: theirs is an `except (ValueError,
    BTClibRuntimeError)`, so a value error here would be reported as a
    signature that does not verify rather than reaching the caller who
    made the mistake.
    """
    with pytest.raises(BTClibTypeError, match="not a hash function"):
        hashes._assert_valid_hf(hf)


def test_a_hash_function_that_is_one_passes() -> None:
    """The control, over the three shapes a caller can legitimately pass."""
    for hf in (sha256, hashlib.sha512, lambda: hashlib.sha256()):  # noqa: PLW0108
        hashes._assert_valid_hf(hf)
