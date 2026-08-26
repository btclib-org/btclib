# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The hash functions of bitcoin.

ripemd160 and sha1 through sha256, the hash160 and hash256 pairs,
BIP340's tagged hash, SipHash-2-4, the BMS magic envelope, and the
merkle roots and branches of a block.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence

from btclib import var_int
from btclib._ripemd160 import ripemd160 as pure_python_ripemd160
from btclib.alias import HashDigestF, HashF, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import bytes_from_octets, is_integer, is_octets

__all__ = [
    "hash160",
    "hash256",
    "magic_message",
    "merkle_root",
    "merkle_root_and_mutated",
    "merkle_root_and_mutated_from_hashes",
    "merkle_root_from_branch",
    "reduce_to_hlen",
    "ripemd160",
    "sha1",
    "sha256",
    "siphash",
    "tagged_hash",
]

_MASK64 = 0xFFFFFFFFFFFFFFFF


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

    Not a Linux question but a *distro Python* one: the python.org
    installers never bundled an affected OpenSSL (3.11 has 1.1.1q, 3.12
    has 3.0.11, 3.13 has 3.0.15), macOS system Python is LibreSSL, which
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
    # OP_SHA1 is a consensus op code: the script says SHA1, and the only
    # correct answer is the one the network computes, so the weakness of
    # the algorithm is not a choice made here. usedforsecurity=False
    # states that to hashlib rather than to the linter alone, as a noqa
    # would: it is the documented way to ask for a blocked digest in a
    # restricted environment, so a host whose policy allows SHA1 for
    # non-security use alone answers here instead of raising.
    return hashlib.sha1(octets, usedforsecurity=False).digest()


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


def _sip_key_word(value: int, name: str) -> int:
    """Return value, refusing anything that is not an unsigned 64-bit word."""
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {name} type: {type(value).__name__}")
    if not 0 <= value <= _MASK64:
        raise BTClibValueError(f"{name} out of range: {value}")
    return value


def _rotl64(n: int, b: int) -> int:
    """Return the 64-bit left rotation of n by b bits, 0 < b < 64."""
    return ((n << b) | (n >> (64 - b))) & _MASK64


def _siphash_round(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    """Return the state after one SipRound, `crypto/siphash.h`'s SipRound."""
    v0 = (v0 + v1) & _MASK64
    v1 = _rotl64(v1, 13)
    v1 ^= v0
    v0 = _rotl64(v0, 32)
    v2 = (v2 + v3) & _MASK64
    v3 = _rotl64(v3, 16)
    v3 ^= v2
    v0 = (v0 + v3) & _MASK64
    v3 = _rotl64(v3, 21)
    v3 ^= v0
    v2 = (v2 + v1) & _MASK64
    v1 = _rotl64(v1, 17)
    v1 ^= v2
    v2 = _rotl64(v2, 32)
    return v0, v1, v2, v3


def siphash(k0: int, k1: int, octets: Octets) -> int:
    """Return SipHash-2-4 of octets, keyed by the 128-bit (k0, k1).

    k0 and k1 are the two 64-bit words of the key, in the order Core's
    `CSipHasher(k0, k1)` takes them (`crypto/siphash.h`) and its Python
    mirror `siphash(k0, k1, data)`
    (`test/functional/test_framework/crypto/siphash.py`) reads them out
    of a key: two rounds of compression per eight-byte word of octets,
    padded with a trailing byte counting the input length mod 256, and
    four rounds of finalization. The result is an unsigned 64-bit
    integer, `v0 ^ v1 ^ v2 ^ v3` of the finalized state, never negative
    and never wider than 8 bytes.

    A hash keyed on a peer- or block-derived secret and not a
    general-purpose digest: BIP158's filter and BIP152's short
    transaction IDs both build their key from data no counterparty
    chooses, which is what keeps this fast, non-cryptographic
    construction from being a hash-flooding target.

    Bitcoin Core's Python test framework offers a second entry point,
    `siphash256(k0, k1, num)`, for hashing a 256-bit integer -- `num`
    is Core's `uint256` read as a Python int, and the wrapper is only
    `num.to_bytes(32, 'little')` ahead of the call above. btclib
    represents a 32-byte hash as bytes already in that same internal
    order (`hashes.merkle_root` and its callers), so a caller here
    passes such a value to octets directly, and no such wrapper is
    provided: it would restate the conversion this library never
    needed in the first place.
    """
    k0 = _sip_key_word(k0, "k0")
    k1 = _sip_key_word(k1, "k1")
    data = bytes_from_octets(octets)

    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    count = 0
    pending = 0
    for byte in data:
        pending |= byte << (8 * (count % 8))
        count = (count + 1) & 0xFF
        if count & 7 == 0:
            v3 ^= pending
            v0, v1, v2, v3 = _siphash_round(v0, v1, v2, v3)
            v0, v1, v2, v3 = _siphash_round(v0, v1, v2, v3)
            v0 ^= pending
            pending = 0

    pending |= count << 56
    v3 ^= pending
    v0, v1, v2, v3 = _siphash_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _siphash_round(v0, v1, v2, v3)
    v0 ^= pending

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _siphash_round(v0, v1, v2, v3)

    return v0 ^ v1 ^ v2 ^ v3


def _assert_valid_hf(hf: HashF) -> None:
    """Refuse an hf that is not a hash constructor.

    The mistake it catches is `sha256()` written where `sha256` belongs --
    the digest object instead of the class that makes one -- which is a
    caller's own error and not a statement about the message or the
    signature it was passed with.

    `callable` and not a trial call: a digest object is not callable, so
    the check is a slot lookup rather than the hash it would otherwise
    have to build, which matters where it sits in front of a verification
    the bindings answer in 22 us.

    So it is not exhaustive, and does not need to be: a callable of the
    wrong shape -- `hashes.hash256`, which takes the message rather than
    making a digest -- still fails at the `hf()` that follows, with the
    plain TypeError `tests/alias_test.py` pins there on purpose. What
    matters for the verifications is not the class but that neither one is
    a ValueError, so neither is mistaken for a signature that does not
    verify.

    A `BTClibTypeError` for the reason the class exists, and with a
    consequence the boolean verifications depend on: it is a `TypeError`,
    so their `except (ValueError, BTClibRuntimeError)` does not catch it
    and a caller's mistake reaches the caller instead of being reported as
    a signature that does not verify.
    """
    if not callable(hf):
        raise BTClibTypeError(f"not a hash function: {hf!r} is not callable")


def reduce_to_hlen(msg: Octets, hf: HashF = hashlib.sha256) -> bytes:
    """Return the message digested by hf, one digest long.

    Step 4 of SEC 1 v.2 section 4.1.3: what the un-underscored
    signing and verifying spellings do to a message before handing it
    to their trailing-underscore twins.
    """
    # here as well as in the verifications this feeds, and not only there:
    # they take the message already reduced, so this is where an hf of
    # theirs is first called and where a bad one would otherwise leave as
    # the bare TypeError of `hf()`
    _assert_valid_hf(hf)
    msg = bytes_from_octets(msg)
    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return h.digest()


def magic_message(msg: Octets) -> bytes:
    """Return the hash BMS signs: the message in Core's magic envelope.

    Both the "Bitcoin Signed Message:" magic and the message enter
    var_int-length-prefixed, then hash256 of the whole; the envelope
    is what keeps a signed message from being a valid transaction
    signature.
    """
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
    """Return the merkle tree root, and whether the tree is mutated.

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
    """Return the merkle tree root, and whether the tree is mutated.

    The merkle tree is a binary tree constructed with the provided list
    of binary data as bottom level, then recursively going up one level
    by hashing every hash value pair in the current level, until a
    single value (root) is obtained.

    See merkle_root_and_mutated_from_hashes for the mutation flag, and
    for the variant taking a bottom level of hashes.
    """
    return merkle_root_and_mutated_from_hashes([hf(item) for item in data], hf)


def merkle_root(data: Sequence[bytes], hf: HashDigestF) -> bytes:
    """Return the merkle tree root of a list of binary hashes.

    The merkle tree is a binary tree constructed with the provided list
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
    """Return the merkle root a branch proves, in internal byte order.

    The verifier's side of merkle_root_and_mutated_from_hashes: given a
    leaf, the siblings met on the way up and the leaf's position, this is
    the root the tree must have had. Equal to a header's merkle_root, the
    leaf was in that block -- the arithmetic behind Core's
    verifytxoutproof, and behind every light client.

    `index` is the leaf's position in the bottom level; its bits say
    left child or right child at each step, lowest bit first. `branch`
    holds one sibling per level, bottom-up. Both are what they are in the
    tree, so both are in internal byte order, as this module's other
    The merkle functions are: btclib.block.merkle_proof is the entry point
    taking the reversed order that a txid and a header are displayed in.

    A branch is evidence only together with the header that carries the
    root, and only about the tree: proving that a leaf is *a
    transaction* of the block needs one more check, which is
    `check_inner_node`. It is called with the 64 bytes each level hashes,
    and it is a parameter rather than code here because refusing them
    means knowing what a transaction looks like -- a layer this module
    sits below, and must not import.
    """
    # every Octets is itself a Sequence, so passing one instead of a list
    # of siblings would zip through its bytes and hash each as its own
    # sibling (issue #1405)
    if is_octets(branch):
        raise BTClibTypeError(f"invalid branch type: {type(branch).__name__}")

    # the type before the sign, `"0" < 0` being a bare TypeError about
    # the operands: an index is a position and a bool is not one, `True`
    # naming the second leaf of every tree it is passed to
    if not is_integer(index):
        raise BTClibTypeError(f"invalid leaf index type: {type(index).__name__}")
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
    """Return BIP340's tagged hash: hf(hf(tag) || hf(tag) || m).

    The doubled tag digest is what makes a hash under one tag invalid
    under every other.
    """
    # libsecp256k1 computes exactly this in hashes.tagged_sha256, and the
    # binding is not called because it is slower at every size: 0.53 us
    # against 0.44 on an empty message, 0.63 against 0.44 on 64 bytes,
    # 2.27 against 0.70 on 1 kB, and 111 against 20 on 64 kB. hashlib's
    # SHA256 is OpenSSL's, hardware-accelerated, where libsecp256k1
    # compiles its own portable C. This path also has to stay for
    # hf != sha256, so delegating would buy neither speed nor one
    # implementation less.
    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return h2.digest()
