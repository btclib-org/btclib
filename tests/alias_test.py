# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the type aliases of btclib.alias.

Two of them are about hash functions: HashF, the constructor that every
hf in the library is, and HashDigestF, the one-shot digest the merkle
functions of btclib.hashes take. HashF returns a Protocol rather than Any.

What a checker rejects cannot be asserted from inside the suite, so what is
asserted here is the run-time incompatibility the types describe: swapping
one for the other does not merely type-check badly, it does not work.
"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any, get_args, get_type_hints

import pytest

from btclib.alias import HashDigestF, HashF, HashObject, Octets
from btclib.hashes import hash256, merkle_root, reduce_to_hlen, tagged_hash


def test_the_two_hash_notions_are_not_interchangeable() -> None:
    """Which is why they have two names.

    hashlib.sha256 is a constructor: called with data it returns an object,
    not a digest. hash256 is a one-shot digest: it cannot be called with no
    argument at all.
    """
    data = [b"a", b"b"]

    # each works where it belongs
    assert len(merkle_root(data, hash256)) == 32
    assert len(reduce_to_hlen(b"m", hashlib.sha256)) == 32

    # a HashF where a one-shot digest goes: sha256(b"ab") is a HASH object,
    # so the level above it is a list of objects and the concatenation fails
    with pytest.raises(TypeError):
        merkle_root(data, hashlib.sha256)  # type: ignore[arg-type]

    # a one-shot digest where a HashF goes: it is called with no argument
    with pytest.raises(TypeError):
        reduce_to_hlen(b"m", hash256)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        tagged_hash(b"t", b"m", hash256)  # type: ignore[arg-type]


def test_hash_f_returns_a_protocol_not_any() -> None:
    """Returning Any would leave everything downstream of it unchecked.

    Eleven sites in the package read digest_size and nine build a digest
    through update(). With HashF returning Any, a typo in either is a
    run-time AttributeError in a mypy-strict code base -- and mypy reports
    even a *correct* hf().digest() as "Returning Any".
    """
    hints = get_type_hints(HashObject.digest)
    assert hints["return"] is bytes
    assert get_type_hints(HashObject.hexdigest)["return"] is str

    # digest_size and block_size are properties, so read them off the class
    assert get_type_hints(HashObject.digest_size.fget)["return"] is int  # type: ignore[attr-defined]
    assert get_type_hints(HashObject.block_size.fget)["return"] is int  # type: ignore[attr-defined]
    assert get_type_hints(HashObject.name.fget)["return"] is str  # type: ignore[attr-defined]

    # update alone is Any, and only because hmac.new's digestmod wants a
    # parameter type this package cannot spell before 3.12
    assert get_type_hints(HashObject.update)["data"] is Any


def test_a_real_hashlib_object_satisfies_the_protocol() -> None:
    """Structural typing has to describe something that exists."""
    hash_object = hashlib.sha256()
    for name, member in inspect.getmembers(HashObject):
        if name.startswith("_"):
            continue
        assert hasattr(hash_object, name), f"hashlib.sha256() has no {name}"
        assert member is not None

    assert isinstance(hash_object.digest_size, int)
    assert isinstance(hash_object.block_size, int)
    assert isinstance(hash_object.name, str)
    hash_object.update(b"m")
    assert isinstance(hash_object.digest(), bytes)
    assert isinstance(hash_object.hexdigest(), str)
    assert isinstance(hash_object.copy().digest(), bytes)


def test_the_aliases_are_distinct() -> None:
    """Verify the two aliases differ in arity, hence in assignability."""
    assert HashF != HashDigestF

    # a constructor: no argument in, a HashObject out
    parameters, returns = get_args(HashF)
    assert parameters == []
    assert returns is HashObject

    # a one-shot digest: Octets in, bytes out. The arities alone make the
    # two unassignable to each other, which is what a checker acts on.
    # Against `Octets` itself and not against what it expands to: the
    # spellings it names are its own to change
    parameters, returns = get_args(HashDigestF)
    assert parameters == [Octets]
    assert returns is bytes
