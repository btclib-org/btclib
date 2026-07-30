#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Hash based helper functions."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Callable

from btclib import var_int
from btclib.alias import HashF, Octets
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets

# see https://bugs.python.org/issue47101
# With OpenSSL 3.x, hashlib still includes ripemd160
# but it is not usable unless the legacy provider is loaded.
try:
    hashlib.new("ripemd160")
except ValueError:  # pragma: no cover
    import ctypes

    ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
    ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")


def ripemd160(octets: Octets) -> bytes:
    """Return the RIPEMD160(*) of the input octet sequence."""
    octets = bytes_from_octets(octets)
    return hashlib.new("ripemd160", octets).digest()


def sha1(octets: Octets) -> bytes:
    """Return the SHA1(*) of the input octet sequence."""
    octets = bytes_from_octets(octets)
    return hashlib.sha1(octets).digest()  # noqa: S324


def sha256(octets: Octets) -> bytes:
    """Return the SHA256(*) of the input octet sequence."""
    octets = bytes_from_octets(octets)
    return hashlib.sha256(octets).digest()


def hash160(octets: Octets) -> bytes:
    """Return the HASH160=RIPEMD160(SHA256) of the input octet sequence."""
    return ripemd160(sha256(octets))


def hash256(octets: Octets) -> bytes:
    """Return the SHA256(SHA256(*)) of the input octet sequence."""
    return sha256(sha256(octets))


def reduce_to_hlen(msg: Octets, hf: HashF = hashlib.sha256) -> bytes:
    msg = bytes_from_octets(msg)
    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return bytes(h.digest())


def magic_message(msg: Octets) -> bytes:
    msg = bytes_from_octets(msg)
    # Both strings are length-prefixed as var_int (CompactSize), as Core
    # does by serializing them with CDataStream; the 0x18 prefix of the
    # magic string is the var_int of its own 24 bytes.
    # A fixed one-byte length would agree with Core up to 252 bytes only,
    # silently diverge from 253 to 255, and overflow above that.
    t = b"\x18Bitcoin Signed Message:\n" + var_int.serialize(len(msg)) + msg
    return sha256(t)


def merkle_root_and_mutated_from_hashes(
    hashes: Sequence[bytes], hf: Callable[[bytes | str], bytes]
) -> tuple[bytes, bool]:
    """Return the Merkle tree root, and whether the tree is mutated.

    The bottom level is the provided list of hashes, taken as they are:
    this is the tree over values that are hashes already, as the witness
    tree of a block is (its coinbase leaf, all zeros, is the hash of
    nothing at all). Core's ComputeMerkleRoot is the same function;
    merkle_root_and_mutated is the one hashing the leaves first.

    The second returned value flags CVE-2012-2459: a level holding two
    equal siblings has the same root as the shorter list carrying only
    one of them, so the root does not commit to the list it was computed
    from. Bitcoin Core computes the same flag (the `mutated` out
    parameter of BlockMerkleRoot) and rejects such a block.
    """
    level = list(hashes)
    if not level:
        # the loop below would never reduce an empty level to a root
        raise BTClibValueError("empty merkle tree")

    mutated = False
    while len(level) != 1:
        # The pairs are read before an odd level is padded, because the
        # padding hashes the last value with itself: that is Bitcoin's
        # algorithm, not a mutation, and flagging it would reject every
        # block having an odd level anywhere in its tree, i.e. almost
        # every block (block 200,000 has five of them). What is flagged
        # is two *distinct* siblings that are equal, at any level: a
        # duplicated trailing subtree surfaces as an equal pair at the
        # level it was duplicated from, not necessarily at the leaves.
        mutated |= any(level[i] == level[i + 1] for i in range(0, len(level) - 1, 2))
        if len(level) % 2:
            level.append(level[-1])
        level = [hf(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], mutated


def merkle_root_and_mutated(
    data: Sequence[bytes], hf: Callable[[bytes | str], bytes]
) -> tuple[bytes, bool]:
    """Return the Merkle tree root, and whether the tree is mutated.

    The Merkle tree is a binary tree constructed with the provided list
    of binary data as bottom level, then recursively going up one level
    by hashing every hash value pair in the current level, until a
    single value (root) is obtained.

    See merkle_root_and_mutated_from_hashes for the mutation flag, and
    for the variant taking a bottom level of hashes.
    """
    return merkle_root_and_mutated_from_hashes([hf(item) for item in data], hf)


def merkle_root(data: Sequence[bytes], hf: Callable[[bytes | str], bytes]) -> bytes:
    """Return the Merkle tree root of a list of binary hashes.

    The Merkle tree is a binary tree constructed with the provided list
    of binary data as bottom level, then recursively going up one level
    by hashing every hash value pair in the current level, until a
    single value (root) is obtained.

    The root alone does not tell whether the list is the CVE-2012-2459
    mutation of a shorter one; whoever validates a block must use
    merkle_root_and_mutated and reject a mutated tree.
    """
    return merkle_root_and_mutated(data, hf)[0]


def tagged_hash(tag: bytes, m: bytes, hf: HashF = hashlib.sha256) -> bytes:
    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return bytes(h2.digest())
