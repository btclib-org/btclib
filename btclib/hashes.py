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
from collections.abc import Callable, Sequence

from btclib import var_int
from btclib._ripemd160 import ripemd160 as pure_python_ripemd160
from btclib.alias import HashDigestF, HashF, Octets
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets


def _hashlib_has_ripemd160() -> bool:
    """Whether this interpreter's hashlib can do RIPEMD-160 at all.

    OpenSSL 3.0.0-3.0.6 ships ripemd160 in the legacy provider alone, so
    there hashlib.new raises ValueError unless that provider has been
    loaded: https://bugs.python.org/issue47101. OpenSSL 3.0.7 put it back
    in the default provider (openssl/openssl#19375), and no interpreter
    the suite runs under links one of the seven affected releases -- but
    something still shipping does. Ubuntu 22.04 is on
    openssl 3.0.2-0ubuntu1.26 as of 2026-07-30, no ripemd anywhere in its
    changelog, supported to 2027-04 and under ESM to 2032; RHEL 9.0 and
    9.1 are on 3.0.1. A host in FIPS mode is the other False, and there
    no provider makes it True: RIPEMD-160 is not a FIPS algorithm, while
    bitcoin addresses are RIPEMD-160 whatever a policy says.

    Not a Linux question but a *distro python* one: the python.org
    installers never bundled an affected OpenSSL (3.11 has 1.1.1q, 3.12
    has 3.0.11, 3.13 has 3.0.15), macOS system python is LibreSSL, which
    has ripemd160, and python-build-standalone is on 3.5.x.

    Loading the legacy provider at import time, via
    `ctypes.CDLL("libssl.so")`, is the alternative, and it is wrong
    twice over (issue 144). Unversioned `libssl.so` is the dev-package
    symlink -- jammy's libssl3 ships `libssl.so.3` and
    `ossl-modules/legacy.so`, and the symlink comes with libssl-dev --
    so it raises OSError on precisely the hosts that need it: a server,
    a container, a venv built from wheels. And it re-enables OpenSSL's
    deprecated algorithms for the whole process, every other library in
    the interpreter included, as an import side effect, which under FIPS
    is not even permitted.

    The fallback below costs about 130x an OpenSSL digest (60 us against
    0.45 us here, on 32 bytes), and is paid only where the alternative is
    that `import btclib.hashes` raises.
    """
    try:
        hashlib.new("ripemd160")
    except ValueError:
        return False
    return True


_RIPEMD160_IN_HASHLIB = _hashlib_has_ripemd160()


def ripemd160(octets: Octets) -> bytes:
    """Return the RIPEMD160(*) of the input octet sequence."""
    octets = bytes_from_octets(octets)
    if _RIPEMD160_IN_HASHLIB:
        return hashlib.new("ripemd160", octets).digest()
    return pure_python_ripemd160(octets)


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
    hashes: Sequence[bytes], hf: HashDigestF
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
    data: Sequence[bytes], hf: HashDigestF
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


def merkle_root(data: Sequence[bytes], hf: HashDigestF) -> bytes:
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


def merkle_root_from_branch(
    leaf: Octets,
    branch: Sequence[Octets],
    index: int,
    hf: HashDigestF,
    check_inner_node: Callable[[bytes], None] | None = None,
) -> bytes:
    """Return the Merkle root a branch proves, in internal byte order.

    The verifier's side of merkle_root_and_mutated_from_hashes: given a
    leaf, the siblings met on the way up and the leaf's position, this is
    the root the tree must have had. Equal to a header's merkle_root, the
    leaf was in that block -- the arithmetic behind Core's
    verifytxoutproof, and behind every light client.

    `index` is the leaf's position in the bottom level; its bits say
    left child or right child at each step, lowest bit first. `branch`
    holds one sibling per level, bottom-up. Both are what they are in the
    tree, so both are in internal byte order, as this module's other
    Merkle functions are: btclib.block.merkle_proof is the entry point
    taking the reversed order that a txid and a header are displayed in.

    A branch is evidence only together with the header that carries the
    root, and only about the tree: proving that a leaf is *a
    transaction* of the block needs one more check, which is
    `check_inner_node`. It is called with the 64 bytes each level hashes,
    and it is a parameter rather than code here because refusing them
    means knowing what a transaction looks like -- a layer this module
    sits below, and must not import.
    """
    if index < 0:
        raise BTClibValueError(f"negative leaf index: {index}")

    root = bytes_from_octets(leaf, 32)
    for sibling_ in branch:
        # a branch item that is not a hash cannot be a sibling
        sibling = bytes_from_octets(sibling_, 32)
        if index % 2:
            # the running hash is a right child, and a left sibling equal
            # to it is the CVE-2012-2459 duplication: a shorter list has
            # this very same root, so the root does not commit to the one
            # at hand. Padding an odd level duplicates its *last* node,
            # which is a left child, so a legitimate tree never lands
            # here -- the builder's side of the same fact is the
            # `mutated` flag of merkle_root_and_mutated_from_hashes
            if sibling == root:
                err_msg = "mutated merkle branch: a right child equal to its sibling"
                raise BTClibValueError(err_msg)
            pair = sibling + root
        else:
            pair = root + sibling
        if check_inner_node is not None:
            check_inner_node(pair)
        root = hf(pair)
        index //= 2

    # every bit of the position must have been spent on a step: an index
    # still non-zero means the branch is too short for the leaf it claims
    # to place, and a branch too short proves nothing at all
    if index:
        err_msg = f"leaf index too high for a {len(branch)}-step merkle branch"
        raise BTClibValueError(err_msg)

    return root


def tagged_hash(tag: bytes, m: bytes, hf: HashF = hashlib.sha256) -> bytes:
    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return bytes(h2.digest())
