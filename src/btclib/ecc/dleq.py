# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Discrete logarithm equality proofs, according to BIP374.

https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki

A DLEQ proof is 64 bytes saying that two points share one discrete
logarithm: for A = a*G and C = a*B, it proves that the prover knows an
`a` satisfying both, and reveals nothing else about it. The shape is a
Schnorr signature -- a nonce commitment folded into a challenge, and an
s that opens it -- computed twice over, once with G as the base and once
with B, so that a single s answers for both.

**What it attests, and what it does not.** The proof says that the same
scalar relates A to G and C to B. It says nothing about the value of
that scalar, nothing about who holds it, and nothing about whether C is
the point either party wanted: a prover who deliberately picks the wrong
B proves equivalence over that B and the proof is valid. Its use is the
one BIP352 has for it, and the reason BIP374 exists: an ECDH shared
secret C computed from the key A that signed an input is provably the
right shared secret, so a wrong output script is caught before it is
broadcast rather than after the funds are gone. A signature would not
catch it -- a wrongly derived output script is consensus-valid.

The generator is an argument, which no other BIP in this library makes
it: BIP374 passes G in so that the algorithm serves another curve, and
the vectors exercise arbitrary generators. What is *not* an argument is
the curve or the hash function, as in `btclib.ecc.musig2`: BIP374 is
defined for secp256k1 with sha256, the 33-byte compressed points, the
32-byte scalars and the three tags below are that pair's serialization,
and there is no other pair for which a test vector exists.

The message is optional and, when present, exactly 32 bytes -- BIP374's
own restriction, and unlike the arbitrary-size message of
`btclib.ecc.ssa`. It binds the proof to a statement of the protocol
above, so that a proof of knowledge cannot be replayed as a proof of
knowledge *and* of that statement.
"""

from __future__ import annotations

import secrets

from btclib.alias import Integer, Octets, Point
from btclib.curves import (
    bytes_from_point,
    double_mult_var,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import tagged_hash
from btclib.to_pub_key import PubKey, point_from_pub_key
from btclib.utils import bytes_from_octets

__all__ = [
    "assert_proof_as_valid",
    "generate_proof",
    "verify_proof",
]

# BIP374's tags, which are what makes a DLEQ hash a DLEQ hash: a
# different string is a different scheme, so these are frozen by the
# specification and not by taste
_AUX_TAG = b"BIP0374/aux"
_NONCE_TAG = b"BIP0374/nonce"
_CHALLENGE_TAG = b"BIP0374/challenge"

# a scalar, and the 64-byte proof made of two of them
_SCALAR_SIZE = 32
_PROOF_SIZE = 64


def _challenge(
    A: Point, B: Point, C: Point, R1: Point, R2: Point, G: Point, msg: bytes
) -> int:
    """Return BIP374's challenge, which is *not* reduced modulo n.

    The full 256-bit hash is what the proof carries and what verification
    compares, so reducing it here would answer a different question than
    the one the vectors ask: an `e` above n is a legitimate challenge, and
    the reduction happens where it belongs, inside the multiplication.
    """
    t = b"".join(
        [
            bytes_from_point(A, secp256k1),
            bytes_from_point(B, secp256k1),
            bytes_from_point(C, secp256k1),
            bytes_from_point(G, secp256k1),
            bytes_from_point(R1, secp256k1),
            bytes_from_point(R2, secp256k1),
            msg,
        ]
    )
    return int.from_bytes(tagged_hash(_CHALLENGE_TAG, t), "big")


def _msg_bytes(msg: Octets | None) -> bytes:
    """Return the message as BIP374's m', an absent one being empty.

    An empty message and no message are the same input to the hashes, so
    b"" cannot be passed to mean "no message": 32 bytes or nothing.
    """
    return b"" if msg is None else bytes_from_octets(msg, _SCALAR_SIZE)


def _bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def generate_proof(
    a: Integer,
    B: PubKey,
    aux: Octets | None = None,
    G: PubKey = secp256k1.G,
    msg: Octets | None = None,
) -> bytes:
    """Return the 64-byte DLEQ proof for A = a*G and C = a*B.

    `aux` is BIP374's auxiliary random data, 32 bytes, and is fresh
    randomness when it is not given: the same recommendation BIP340 makes
    for its own, the derivation being deterministic underneath -- a
    counter, or all zeros, still cannot repeat a nonce across two
    messages -- and the randomness the hardening on top of it.

    A BTClibValueError for an `a` outside 1..n-1 or a B, G that is no
    public key, which are BIP374's two "fail" conditions before any
    arithmetic happens.
    """
    a_int = scalar_from_prv_key(a)
    B_point = point_from_pub_key(B)
    G_point = point_from_pub_key(G)
    m = _msg_bytes(msg)
    aux_bytes = (
        secrets.token_bytes(_SCALAR_SIZE)
        if aux is None
        else bytes_from_octets(aux, _SCALAR_SIZE)
    )

    A = mult(a_int, G_point)
    C = mult(a_int, B_point)

    # the key is masked with the hashed randomness by xor, rather than
    # hashed together with it, to keep the number of operations touching
    # the actual secret low: BIP340's rationale, which BIP374 adopts
    t = _bytes_xor(
        a_int.to_bytes(_SCALAR_SIZE, "big"), tagged_hash(_AUX_TAG, aux_bytes)
    )
    # the message enters the nonce as well as the challenge, and that is
    # not redundancy: two proofs over the same a, B and G but different
    # messages, with an all-zero aux, would share a nonce and hand out a
    # by elementary algebra
    rand = tagged_hash(
        _NONCE_TAG,
        t + bytes_from_point(A, secp256k1) + bytes_from_point(C, secp256k1) + m,
    )
    k = int.from_bytes(rand, "big") % secp256k1.n
    if k == 0:  # pragma: no cover
        # a preimage of a multiple of n for the nonce tagged hash: not
        # reachable by choosing arguments, and BIP374 fails rather than
        # signs with it
        raise BTClibRuntimeError("invalid zero nonce")

    R1 = mult(k, G_point)
    R2 = mult(k, B_point)
    e = _challenge(A, B_point, C, R1, R2, G_point, m)
    s = (k + e * a_int) % secp256k1.n
    proof = e.to_bytes(_SCALAR_SIZE, "big") + s.to_bytes(_SCALAR_SIZE, "big")

    # BIP374's last step before returning, and it is in the algorithm
    # rather than in its reference harness: a proof that does not verify
    # is a fault in the arithmetic that produced it, and handing it out
    # is what the protocol above was going to use it to rule out
    if not verify_proof(A, B_point, C, proof, G_point, msg):  # pragma: no cover
        raise BTClibRuntimeError("implausible proof failure")
    return proof


def assert_proof_as_valid(
    A: PubKey,
    B: PubKey,
    C: PubKey,
    proof: Octets,
    G: PubKey = secp256k1.G,
    msg: Octets | None = None,
) -> None:
    """Raise unless the proof holds for A, B, C under G and msg.

    `verify_proof` is the spelling that answers True or False; this one
    says why, which is the difference between a proof that does not hold
    and an argument that is no point or no 64-byte proof at all.
    """
    A_point = point_from_pub_key(A)
    B_point = point_from_pub_key(B)
    C_point = point_from_pub_key(C)
    G_point = point_from_pub_key(G)
    m = _msg_bytes(msg)
    proof_bytes = bytes_from_octets(proof, _PROOF_SIZE)

    e = int.from_bytes(proof_bytes[:_SCALAR_SIZE], "big")
    s = int.from_bytes(proof_bytes[_SCALAR_SIZE:], "big")
    # e is not range-checked, and that asymmetry is BIP374's: the
    # challenge is the unreduced hash, so an e above n is what an honest
    # prover produces about one time in 2^128, while an s above n cannot
    # be one -- s is computed mod n
    if s >= secp256k1.n:
        raise BTClibValueError("s not in 0..n-1")

    R1 = double_mult_var(s, G_point, -e, A_point)
    if R1[1] == 0:
        raise BTClibValueError("invalid (INF) R1")
    R2 = double_mult_var(s, B_point, -e, C_point)
    if R2[1] == 0:
        raise BTClibValueError("invalid (INF) R2")

    if e != _challenge(A_point, B_point, C_point, R1, R2, G_point, m):
        raise BTClibValueError("invalid challenge")


def verify_proof(
    A: PubKey,
    B: PubKey,
    C: PubKey,
    proof: Octets,
    G: PubKey = secp256k1.G,
    msg: Octets | None = None,
) -> bool:
    """Return True if the proof holds for A, B, C under G and msg."""
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_proof_as_valid(A, B, C, proof, G, msg)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
