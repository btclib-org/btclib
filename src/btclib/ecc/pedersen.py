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

from btclib.alias import HashF, Integer, Point
from btclib.curves import Curve, bytes_from_point, double_mult_var, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.utils import assert_type, int_from_bits, int_from_integer

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
    """Second (with respect to G) Nothing-Up-My-Sleeve (NUMS) generator.

    A commitment rG+vH is only binding if nobody knows log_G(H): a
    committer who did could open the same commitment to any (r, v) of
    their choosing. H is therefore not chosen but derived -- the hash of
    G is read as a candidate x-coordinate, and the candidate is
    incremented until it lands on the curve -- so that computing a
    discrete logarithm relating H to G is the only way to a value this
    function could also have produced, and nobody has one.

    The result is cached on (ec, hf): it is a constant for that pair,
    recomputing it on every call cost 71% of a commitment (issue #287).

    For (secp256k1, sha256), the pair used everywhere else in this
    module by default, the derived H equals the H hardcoded as
    `secp256k1_generator_h` in libsecp256k1-zkp -- the H of Elements and
    of Confidential Transactions.
    `tests/ecc/pedersen_test.py::test_second_generator` pins that
    value; no published constant exists to pin it against on another
    curve or hash function.

    idea:
    https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source:
    https://github.com/BlockstreamResearch/secp256k1-zkp/blob/master/src/modules/generator/main_impl.h
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


def commit(r: Integer, v: Integer, ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Commit to v under blinding factor r, returning rG+vH.

    H is `second_generator`, whose docstring has why nobody can open
    this to a different (r, v). r=0 mod n is refused: it commits with no
    blinding at all, Q is then v*H, a point anyone who guesses v can
    recompute. The check is on r alone and not on its range, because the
    sum of two blinding factors is a blinding factor too -- a Pedersen
    commitment is additively homomorphic -- and is routinely >= ec.n
    (issue #1250). It also subsumes the former separate check for r and
    v both landing on INF: with r=0 mod n excluded, Q lands there only if
    v is 0 mod n too, which is an ordinary commitment to a zero value and
    not a blinding failure.

    Checked here and nowhere else in the module: `assert_as_valid`
    recomputes the commitment through this function, and `verify`
    already turns the `BTClibValueError` this raises into `False`, the
    same way it does for every other invalid (r, v).
    """
    H = second_generator(ec, hf)
    if int_from_integer(r) % ec.n == 0:
        err_msg = "invalid (unblinded) commitment: r is 0 mod n"
        raise BTClibValueError(err_msg)
    return double_mult_var(v, H, r, ec.G, ec)


def assert_as_valid(
    r: Integer, v: Integer, commitment: Point, ec: Curve = secp256k1, hf: HashF = sha256
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
    assert_type(commitment, tuple, "commitment")

    if commitment != commit(r, v, ec, hf):
        raise BTClibRuntimeError("commitment verification failed")


def verify(
    r: Integer, v: Integer, commitment: Point, ec: Curve = secp256k1, hf: HashF = sha256
) -> bool:
    """Open the commitment and return True if valid."""
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_as_valid(r, v, commitment, ec, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
