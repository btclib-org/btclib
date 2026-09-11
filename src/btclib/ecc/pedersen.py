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

**The octets say residuosity, where a SEC prefix says parity.**
libsecp256k1-zkp writes a commitment as one octet and then x, and that
octet reports whether y is a quadratic residue:
`secp256k1_pedersen_commitment_save` writes
`9 ^ secp256k1_fe_is_square_var(&ge->y)` and
`secp256k1_generator_serialize` writes `11 ^` the same bit, both in
`src/modules/generator/main_impl.h`;
`secp256k1_rangeproof_serialize_point` writes `1 ^` it, in
`src/modules/rangeproof/rangeproof_impl.h`. That third tag is the base
`ecc.rangeproof` hashes a point under and lifts a ring commitment's x
against, and that module reaches the codec below for both rather than
carrying one of its own. Lifting such an octet by the parity the
`02`/`03` of `curves.point_from_octets` carries answers the same point
for some x and its negation for others, with nothing in the octets to
say which reading wrote them, so the two are not one function under two
names.

The codec below is secp256k1's and takes no `ec`: the tags and the
width of x are libsecp256k1-zkp's format, and that library is
secp256k1's. `generator_from_seed` takes none for a different reason:
the map it runs is written around sqrt(-3) and the curve's own b, so it
is a construction of this field rather than a format read in it.
`commit` takes an `ec` because rG+v*gen is a sum of points, which every
curve has, and takes the generator rather than deriving one because a
commitment is only as binding as the generator behind it and a caller
with several assets has one per asset.
"""

from functools import lru_cache
from hashlib import sha256

from btclib.alias import HashF, Integer, Octets, Point
from btclib.curves import Curve, bytes_from_point, double_mult_var, mult, secp256k1
from btclib.curves.curve import _assert_valid_ec, _is_x_coordinate_var
from btclib.curves.curve_group import HEX_THRESHOLD
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.number_theory import legendre_symbol_var, mod_sqrt_var
from btclib.utils import (
    assert_type,
    bytes_from_octets,
    hex_string,
    int_from_bits,
    int_from_integer,
)

__all__ = [
    "assert_as_valid",
    "bytes_from_commitment",
    "bytes_from_generator",
    "commit",
    "commitment_from_octets",
    "generator_from_octets",
    "generator_from_seed",
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

    For (secp256k1, sha256), this function's own default pair, the
    derived H equals the H hardcoded as
    `secp256k1_generator_h` in libsecp256k1-zkp -- the H of Elements and
    of Confidential Transactions.
    `tests/ecc/pedersen_test.py::test_second_generator` pins that value
    against a literal, and
    `tests/ecc/pedersen_test.py::test_second_generator_matches_zkp`
    against `btclib_secp256k1.zkp.generator.h()`, which is that library
    answering with its own copy rather than a transcription of it. No
    published constant exists to pin either against on another curve or
    hash function.

    idea:
    https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source:
    https://github.com/BlockstreamResearch/secp256k1-zkp/blob/master/src/modules/generator/main_impl.h
    """
    # the generator is read off the curve before anything is done with
    # it, so an ec of no curve type is turned down here; and the
    # refusal is inside the cache rather than in front of it, such an
    # ec being a key like any other -- hashable, so lru_cache would
    # take it, and never stored, exceptions not being cached
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


# what a seed occupies: `secp256k1_generator_generate`'s own `key32`
_SEED_SIZE = 32

# the prefixes `secp256k1_generator_generate_internal` hashes the seed
# under, the trailing space of each included: the C declares each an
# octet longer than what it writes, so no terminator is hashed
_FIRST_GENERATION = b"1st generation: "
_SECOND_GENERATION = b"2nd generation: "

# sqrt(-3) and (sqrt(-3) - 1)/2, the two field constants the map below
# is written around. libsecp256k1-zkp writes them as literals, `negc`
# there being the negation of the first, where the field answers them:
# for a p of 3 mod 4 `mod_sqrt_var` returns the root that is itself a
# square, and `test_the_map_constants_are_derived` holds that root
# against the literal. `ecc.ellswift._constants` derives the same root
# the same way, SwiftEC being written around it too.
_SQRT_MINUS_3 = mod_sqrt_var(-3 % secp256k1.p, secp256k1.p)
_HALF_SQRT_MINUS_3_LESS_1 = (_SQRT_MINUS_3 - 1) * pow(2, -1, secp256k1.p) % secp256k1.p


def _shallue_van_de_woestijne(t: int) -> Point:
    """Return the point of the curve that field element maps to.

    `shallue_van_de_woestijne` in `src/modules/generator/main_impl.h`,
    which is Fouque and Tibouchi's *Indifferentiable Hashing to
    Barreto-Naehrig Curves*: for `w = c*t/(1 + b + t**2)` the three
    candidates `d - t*w`, `-(d - t*w + 1)` and `1 + 1/w**2` are
    x-coordinates of which at least one is the curve's, and the first
    that is names the point. `c` is sqrt(-3) and `d` is `(c - 1)/2`.

    The joint denominator `j = (1 + b + t**2) * (-3*t**2)` is what
    spares the second inversion, and it vanishes at t = 0 alone --
    `1 + b + t**2` cannot, -8 being no square modulo p. The C reads
    `secp256k1_fe_inv`'s own answer of zero for an inverse of zero and
    so lands on `(d, f(d))` there, which is what the zero below writes
    out.

    The y is the one that is a quadratic residue, negated where t is
    odd. The paper turns it on the Jacobi symbol of t; the C uses the
    parity instead and gives the reason, which holds here: nothing above
    reads t except through t**2, so any criterion that turns with the
    sign of t answers a point of the same pair, and the parity is
    cheaper than the symbol.

    zkp forms all three roots and selects among them with
    `secp256k1_fe_cmov`, which is what makes its walk constant-time;
    this asks `curves.curve._is_x_coordinate_var` for existence instead
    and forms the one root it needs. What is walked here is a digest of
    the seed alone: `generator_from_seed` adds the blinding factor as
    `blind*G` to the sum of the points, so no secret of a caller's
    reaches this function.

    An integer outside 0..p-1 is no field element and is refused, which
    is `secp256k1_fe_set_b32_limit`'s own refusal of the digest
    `generator_from_seed` hands it.
    """
    p = secp256k1.p
    if not 0 <= t < p:
        err_msg = "field element not in 0..p-1: "
        err_msg += f"{hex_string(t)}" if t > HEX_THRESHOLD else f"{t}"
        raise BTClibValueError(err_msg)

    t_2 = t * t % p
    wd = (t_2 + secp256k1._b + 1) % p
    x3d = -3 * t_2 % p
    j = wd * x3d % p
    j_inv = pow(j, -1, p) if j else 0
    x_1 = (_HALF_SQRT_MINUS_3_LESS_1 - _SQRT_MINUS_3 * t_2 % p * x3d % p * j_inv) % p
    x_2 = -(x_1 + 1) % p
    x_3 = (1 + pow(wd, 3, p) * j_inv) % p

    # the cascade `secp256k1_fe_cmov` writes: the second candidate where
    # the first is no x-coordinate, and the third where neither is
    if _is_x_coordinate_var(x_1, secp256k1):
        x = x_1
    elif _is_x_coordinate_var(x_2, secp256k1):
        x = x_2
    else:
        x = x_3
    y = secp256k1.y_quadratic_residue_var(x)
    return x, p - y if t % 2 else y


def generator_from_seed(seed: Octets, blind: Integer | None = None) -> Point:
    """Return the generator that seed derives, blinded where asked.

    `secp256k1_generator_generate_internal`: the seed is hashed under
    two prefixes, each digest is read as a field element and mapped to
    the curve by `_shallue_van_de_woestijne`, and the two points are
    summed. `secp256k1_generator.h` publishes the result as distributed
    uniformly over the curve, with no known discrete logarithm with
    respect to G or to any other generator this answers -- which is what
    a confidential transaction committing each of several assets under
    its own generator asks for, `commit` and `ecc.rangeproof` taking the
    generator they work at.

    `blind` adds `blind*G` to that sum, and one function takes it where
    the C publishes a call per case: `secp256k1_generator_generate_blinded`
    at a blinding factor of zero is `secp256k1_generator_generate`, which
    is what `test_generator_generate` asserts of each of its own vectors.
    A factor at or past n is refused, `secp256k1_scalar_set_b32`'s
    overflow being what refuses it there; zero is not, a generator being
    public where `commit`'s own blinding factor is secret.

    `second_generator` is the other generator this module names, and the
    two are unrelated constructions: that one increments the hash of G
    until it lands on the curve, where this maps a digest onto it.

    source:
    https://github.com/BlockstreamResearch/secp256k1-zkp/blob/master/src/modules/generator/main_impl.h
    """
    seed_bytes = bytes_from_octets(seed, _SEED_SIZE)
    Q = secp256k1.add_aff_var(
        _shallue_van_de_woestijne(
            int.from_bytes(sha256(_FIRST_GENERATION + seed_bytes).digest(), "big")
        ),
        _shallue_van_de_woestijne(
            int.from_bytes(sha256(_SECOND_GENERATION + seed_bytes).digest(), "big")
        ),
    )
    if blind is None:
        return Q

    blind_int = int_from_integer(blind)
    if not 0 <= blind_int < secp256k1.n:
        err_msg = "blinding factor not in 0..n-1: "
        err_msg += (
            f"{hex_string(blind_int)}" if blind_int > HEX_THRESHOLD else f"{blind_int}"
        )
        raise BTClibValueError(err_msg)
    return secp256k1.add_aff_var(Q, mult(blind_int, secp256k1.G, secp256k1))


def commit(r: Integer, v: Integer, gen: Point, ec: Curve = secp256k1) -> Point:
    """Commit to v under blinding factor r, returning rG+v*gen.

    `gen` is the generator the commitment is made under and the caller
    names it, as `secp256k1_pedersen_commit` takes its own `gen`:
    `second_generator` is the one this library derives for a curve and a
    hash function, `generator_from_seed` the map that derives any other,
    and nobody can open the commitment to a different (r, v) for as long
    as log_G(gen) is unknown, which is what both derivations buy.

    No hash function, where `second_generator` takes one: a hash is how
    a generator is derived and says nothing about a sum of points.

    r=0 mod n is refused: it commits with no
    blinding at all, Q is then v*gen, a point anyone who guesses v can
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
    # ahead of the check below, which reads ec.n: `double_mult_var`
    # asks the same of the same ec, and only after that read
    _assert_valid_ec(ec)
    if int_from_integer(r) % ec.n == 0:
        err_msg = "invalid (unblinded) commitment: r is 0 mod n"
        raise BTClibValueError(err_msg)
    return double_mult_var(v, gen, r, ec.G, ec)


def assert_as_valid(
    r: Integer, v: Integer, commitment: Point, gen: Point, ec: Curve = secp256k1
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

    if commitment != commit(r, v, gen, ec):
        raise BTClibRuntimeError("commitment verification failed")


def verify(
    r: Integer, v: Integer, commitment: Point, gen: Point, ec: Curve = secp256k1
) -> bool:
    """Open the commitment and return True if valid."""
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_as_valid(r, v, commitment, gen, ec)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


# the leading octet of each of libsecp256k1-zkp's serializations, before
# the bit that reports the residuosity of y is xored into it. Every tag
# is odd, so bit 0 of the octet is that bit complemented: it is set
# exactly where y is not a square, which is what
# `secp256k1_pedersen_commitment_load` reads to decide whether to negate
# the point `secp256k1_ge_set_xquad` lifted, and what
# `secp256k1_rangeproof_verify_impl` reads for the same decision. An
# even tag would leave bit 0 the bit itself, and that negation would
# take the wrong half.
#
# 1 is the tag whose other bits are all zero, so a rangeproof's octet is
# the residuosity bit alone: `secp256k1_rangeproof_serialize_point`
# writes `data[0] = !secp256k1_fe_is_square_var(&point->y)`, and a proof
# carries that bit in a packed field rather than in front of an x, which
# is why `ecc.rangeproof` calls `_bytes_from_point` and `_point_from_x`
# and never `_point_from_octets`
_RANGEPROOF_TAG = 1
_COMMITMENT_TAG = 9
_GENERATOR_TAG = 11


def _bytes_from_point(Q: Point, tag: int) -> bytes:
    """Return `tag ^ is_square(y)` and then x, at whichever tag.

    The tag is the whole of what the encodings do not share, so what
    they all refuse is asked here rather than once each: a pair that is
    no point of secp256k1, and the infinity point, which has no x to
    write.

    The Legendre symbol is what `secp256k1_fe_is_square_var` answers,
    and each computes it as a gcd rather than as an exponentiation.
    """
    secp256k1.require_on_curve(Q)
    if Q[1] == 0:  # infinity point in affine coordinates
        raise BTClibValueError("no bytes representation for infinity point")

    residue = legendre_symbol_var(Q[1], secp256k1.p) == 1
    return bytes([tag ^ int(residue)]) + Q[0].to_bytes(secp256k1.p_size, "big")


def _point_from_x(x: int, not_square: bool) -> Point:
    """Return the point x names, with the y the residuosity bit asks for.

    `secp256k1_ge_set_xquad` answers the y that is a square, and the
    negation is the one `secp256k1_pedersen_commitment_load` makes on
    bit 0 of a tagged octet and `secp256k1_rangeproof_verify_impl` on a
    ring commitment's own sign bit. Both refusals are
    `y_quadratic_residue_var`'s, which says which: an x at or past p,
    read there through `secp256k1_fe_set_b32_limit`, and an x that is
    the x-coordinate of no point, which is what `secp256k1_ge_set_xquad`
    fails on -- `secp256k1_pedersen_commitment_parse` asking
    `secp256k1_ge_x_on_curve_var` ahead of any lift instead.
    """
    y = secp256k1.y_quadratic_residue_var(x)
    return x, secp256k1.p - y if not_square else y


def _point_from_octets(octets: Octets, tag: int, name: str) -> Point:
    """Return the point those octets name, lifted by residuosity.

    `secp256k1_pedersen_commitment_parse`'s own refusal, at whichever
    tag: `(input[0] & 0xFE) != 8` is the leading octet outside the pair,
    written here against the tag it is given. The lift, and what else
    it turns down, are `_point_from_x`'s, on bit 0 of the prefix.
    """
    octets = bytes_from_octets(octets, secp256k1.p_size + 1)
    prefix = octets[0]
    if prefix & 0xFE != tag ^ 1:
        raise BTClibValueError(f"not a {name}: prefix 0x{prefix:02x}")

    x = int.from_bytes(octets[1:], byteorder="big")
    return _point_from_x(x, bool(prefix & 1))


def bytes_from_commitment(Q: Point) -> bytes:
    """Return a commitment as libsecp256k1-zkp serializes one.

    `secp256k1_pedersen_commitment_serialize` hands back what
    `_save` stored: `08` where the y of the commitment is a quadratic
    residue and `09` where it is not, then x. `curves.bytes_from_point`
    writes the parity of that same y, so the two answer the same octets
    only where the y that is a square is also the even one.
    """
    return _bytes_from_point(Q, _COMMITMENT_TAG)


def commitment_from_octets(octets: Octets) -> Point:
    """Return the commitment libsecp256k1-zkp's octets name.

    `secp256k1_pedersen_commitment_parse`. An Elements output carries
    these, and this is the lift a caller holding them makes before
    calling anything that takes the commitment as a point --
    `ecc.rangeproof.RangeProof.pubk_rings`, `assert_as_valid`, `verify`.
    """
    return _point_from_octets(octets, _COMMITMENT_TAG, "Pedersen commitment")


def bytes_from_generator(Q: Point) -> bytes:
    """Return a generator as libsecp256k1-zkp serializes one.

    `secp256k1_generator_serialize`, which is `bytes_from_commitment`'s
    octet at another tag: `0a` for a y that is a quadratic residue and
    `0b` for one that is not. `second_generator` is the generator this
    library computes; a blinded asset generator is what else this format
    carries.
    """
    return _bytes_from_point(Q, _GENERATOR_TAG)


def generator_from_octets(octets: Octets) -> Point:
    """Return the generator libsecp256k1-zkp's octets name.

    `secp256k1_generator_parse`, whose `(input[0] & 0xFE) != 10` refuses
    a commitment's own leading octet -- which is what
    `test_generator_fixed_vector` puts to it in
    `src/modules/generator/tests_impl.h`. The x is the same octets
    either way, so the tag is the whole of what keeps the two formats
    apart.
    """
    return _point_from_octets(octets, _GENERATOR_TAG, "generator")
