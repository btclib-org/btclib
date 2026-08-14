# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Pedersen commitment functions.

In a commitment scheme the committer:

* decides (or is given) a secret message v
* decides a random secret r
* *commits* to v by applying the public commitment
  scheme algorithm and producing a commitment C=Commit(r,v)
* makes C public

Later, when he reveals r and v, the verifier *opens* the
commitment checking if indeed C=Commit(r,v).

Pedersen commitment uses a public group of large order n
in which the discrete logarithm is hard.
In the case of an elliptic curve group, the generator G is
supplemented with a second random generator H and
the commitment algorithm is Commit(r,v)=rG+vH.
It is crucial for H to be Nothing-Up-My-Sleeve (NUMS), i.e.
the discrete logarithm of H with respect to G must be unknown.
"""

from functools import lru_cache
from hashlib import sha256

from btclib.alias import HashF, Point
from btclib.curves import Curve, bytes_from_point, double_mult_var, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.utils import int_from_bits

__all__ = [
    "assert_as_valid",
    "commit",
    "second_generator",
    "verify",
]


# (ec, hf) is the cache key: both change the answer, and both are
# hashable -- Curve.__hash__ exists precisely so that equal curves
# share cache entries (curve.py's _eq_key), and hf is compared by
# identity, the same conservative choice _libsecp256k1_serves
# makes for sha256. maxsize is a number, not None: ec is
# caller-supplied, and an unbounded cache on it would be a memory
# leak. The cached value is a Point, i.e. a tuple, so returning the
# same one to every caller is safe -- there is no mutable object to
# share by accident.
@lru_cache(maxsize=128)
def second_generator(ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Second (with respect to G) elliptic curve generator.

    Second (with respect to G) Nothing-Up-My-Sleeve (NUMS)
    elliptic curve generator.

    The hash of G is coerced it to a point (x_H, y_H).
    If the resulting point is not on the curve, keep on
    incrementing x_H until a valid curve point (x_H, y_H) is obtained.

    The result is cached on (ec, hf): it is a constant for that pair,
    recomputing it on every call cost 71% of a commitment (issue #287).

    idea:
    https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source:
    https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    """
    # the generator is read off the curve before anything is done with
    # it, so this is where the three functions below first reach theirs;
    # and it is inside the cache rather than in front of it, an ec of no
    # curve type being a key like any other -- hashable, so lru_cache
    # would take it, and never stored, exceptions not being cached
    _assert_valid_ec(ec)
    G_bytes = bytes_from_point(ec.G, ec, compressed=False)
    hash_ = hf()
    hash_.update(G_bytes)
    hash_digest = hash_.digest()
    x_H = int_from_bits(hash_digest, ec.nlen) % ec.n
    while True:
        try:
            y_H = ec.y_even_var(x_H)
        except BTClibValueError:
            x_H += 1
            x_H %= ec.p
        else:
            return x_H, y_H


def commit(r: int, v: int, ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Commit to r, returning rG+vH.

    Commit to r, returning rG+vH. H is the second Nothing-Up-My-Sleeve
    (NUMS) generator of the curve.
    """
    H = second_generator(ec, hf)
    Q = double_mult_var(v, H, r, ec.G, ec)
    # r and v both zero mod n commit here; anything else would need
    # the discrete log of H
    if Q[1] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    return Q


def assert_as_valid(
    r: int, v: int, commitment: Point, ec: Curve = secp256k1, hf: HashF = sha256
) -> None:
    """Refuse a commitment that (r, v) does not open.

    The commitment is recomputed and compared; verify is the boolean
    answer.

    The type of the commitment is checked and its *value* is not: a
    `None` compares unequal to every point, so `verify` reported a
    commitment of no type at all as one that does not open, where a pair
    of ints that is no commitment is exactly what False is for (issue
    #814). `is_on_curve` is deliberately not asked -- that would refuse a
    wrong value too.
    """
    if not isinstance(commitment, tuple):
        err_msg = f"invalid commitment type: {type(commitment).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    if commitment != commit(r, v, ec, hf):
        raise BTClibRuntimeError("commitment verification failed")


def verify(
    r: int, v: int, commitment: Point, ec: Curve = secp256k1, hf: HashF = sha256
) -> bool:
    """Open the commitment and return True if valid."""
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_as_valid(r, v, commitment, ec, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
