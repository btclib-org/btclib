# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the type aliases of btclib.alias.

HashDigestF is the one-shot digest the merkle functions of btclib.hashes
take, where btclib_ecc.alias.HashF is the constructor that every hf in the
library is; btclib_ecc's own suite holds HashF and HashObject.

What a checker rejects cannot be asserted from inside the suite, so what is
asserted here is the run-time incompatibility the types describe: swapping
one for the other does not merely type-check badly, it does not work.
"""

from __future__ import annotations

import hashlib
from typing import get_args

import pytest
from btclib_ecc.alias import HashF
from btclib_ecc.hashes import reduce_to_hlen, tagged_hash

from btclib.alias import HashDigestF, Octets
from btclib.hashes import hash256, merkle_root


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


def test_a_one_shot_digest_takes_octets_and_returns_bytes() -> None:
    """Verify the alias differs in arity from btclib_ecc's HashF.

    That one is a constructor, with no argument in and a HashObject out.
    """
    assert HashF != HashDigestF

    # a one-shot digest: Octets in, bytes out. The arities alone make the
    # two unassignable to each other, which is what a checker acts on.
    # Against `Octets` itself and not against what it expands to: the
    # spellings it names are its own to change
    parameters, returns = get_args(HashDigestF)
    assert parameters == [Octets]
    assert returns is bytes
