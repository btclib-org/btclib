# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.curve` module."""

import copy
import itertools
from functools import partial
from hashlib import sha256, sha512

import pytest

from btclib.alias import INF, INFJ, Integer, JacPoint, Point
from btclib.curves import (
    Curve,
    CurveGroup,
    bytes_from_point,
    # the module, not only the names in it: the libsecp256k1 dispatch is a
    # module attribute, and patching it off is how no_bindings below
    # reaches the Python arithmetic underneath
    curve,
    double_mult,
    mult,
    multi_mult,
    secp256k1,
)
from btclib.curves.curve import (
    CURVES,
    NIST,
    Brainpool,
    Brainpool_params2,
    NIST_params2,
    SEC2v1,
    SEC2v1_params2,
    SEC2v2,
    SEC2v2_params2,
    _is_x_coordinate,
    _libsecp256k1_applicable,
    _libsecp256k1_multi_mult_,
    _sec_from_point,
    _y_even,
)

# cached_multiples and jac_from_aff are implementation helpers of
# curve_group, not part of what btclib.curves exports: they are taken from the
# module that defines them
from btclib.curves.curve_group import cached_multiples, jac_from_aff, mult_jac
from btclib.ecc import second_generator
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.number_theory import mod_inv, mod_sqrt
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from tests import load, vector_id

# test curves: very low cardinality. The name is p and n, in that order,
# so the four with the larger second number are the n > p ones -- ec13_19,
# ec17_23, ec19_23 and ec23_31 -- and test_curves_with_n_above_p below is
# what keeps that spread from disappearing in an edit
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves = {"ec13_11": Curve(13, 7, 6, (1, 1), 11, 1, False)}
low_card_curves["ec13_19"] = Curve(13, 0, 2, (1, 9), 19, 1, False)
# 17 % 4 = 1; 17 % 8 = 1
low_card_curves["ec17_13"] = Curve(17, 6, 8, (0, 12), 13, 2, False)
low_card_curves["ec17_23"] = Curve(17, 3, 5, (1, 14), 23, 1, False)
# 19 % 4 = 3; 19 % 8 = 3
low_card_curves["ec19_13"] = Curve(19, 0, 2, (4, 16), 13, 2, False)
low_card_curves["ec19_23"] = Curve(19, 2, 9, (0, 16), 23, 1, False)
# 23 % 4 = 3; 23 % 8 = 7
low_card_curves["ec23_19"] = Curve(23, 9, 7, (5, 4), 19, 1, False)
low_card_curves["ec23_31"] = Curve(23, 5, 1, (0, 1), 31, 1, False)

# the union operator, as in curves.curve: it builds a new dict, leaving
# low_card_curves and CURVES untouched
all_curves = low_card_curves | CURVES

ec23_31 = low_card_curves["ec23_31"]

# the very same curve as secp256k1, in another object: nothing that
# dispatches to the libsecp256k1 bindings may tell the two apart, and
# the ecc tests import this one to check that none of them does
secp256k1_bis: Curve = eval(repr(secp256k1))  # noqa: S307


def test_mult_on_secp256k1() -> None:
    """Verify mult against G's published coordinates and edge scalars."""
    assert mult(0) == INF

    G = mult(1)
    assert G[0] == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    assert G[1] == 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    G_ = mult(secp256k1.n - 1)
    assert G_[0] == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    assert G_[1] == 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777

    # mult reduces the scalar modulo n, and never hands the bindings the
    # zero scalar they reject: what is not a private key still multiplies
    for invalid_prvkey in (-1, 0, secp256k1.n, secp256k1.p):
        mult(invalid_prvkey)


# https://github.com/rustyrussell/secp256k1-py/blob/master/tests/data/pubkey.json
# 349 vectors, JSON-equal to upstream and pretty-printed at four
# spaces on the way in; tests/_data/README.md pins the revision
@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector_id(index, vector["seckey"][:16]))
        for index, vector in enumerate(
            load("curves", "_data", "pubkey.json")["vectors"]
        )
    ],
)
def test_secp256k1_py_vectors(vector: dict[str, str]) -> None:
    """Reproduce secp256k1-py's pubkey vectors, in both encodings."""
    prv_key = bytes.fromhex(vector["seckey"])
    assert len(prv_key) == 32
    pubkey_uncp = bytes.fromhex(vector["pubkey"])
    assert len(pubkey_uncp) == 65
    pubkey_comp = bytes.fromhex(vector["compressed"])
    assert len(pubkey_comp) == 33

    assert pub_keyinfo_from_prv_key(prv_key, compressed=False)[0] == pubkey_uncp
    assert pub_keyinfo_from_prv_key(prv_key, compressed=True)[0] == pubkey_comp


def test_exceptions() -> None:
    """Refuse each invalid curve parameter with its own message."""
    # good curve
    Curve(13, 0, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p is not prime: "):
        Curve(15, 0, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="negative a: "):
        Curve(13, -1, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p <= a: "):
        Curve(13, 13, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="negative b: "):
        Curve(13, 0, -2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p <= b: "):
        Curve(13, 0, 13, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="zero discriminant"):
        Curve(11, 7, 7, (1, 9), 19, 1, False)

    err_msg = "generator must be a sequence\\[int, int\\]"
    with pytest.raises(BTClibValueError, match=err_msg):
        Curve(13, 0, 2, (1, 9, 1), 19, 1, False)  # type: ignore[arg-type]

    with pytest.raises(BTClibValueError, match="Generator is not on the curve"):
        Curve(13, 0, 2, (2, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="n is not prime: "):
        Curve(13, 0, 2, (1, 9), 20, 1, False)

    with pytest.raises(BTClibValueError, match="n not in "):
        Curve(13, 0, 2, (1, 9), 71, 1, False)

    with pytest.raises(BTClibValueError, match="INF point cannot be a generator"):
        Curve(13, 0, 2, INF, 19, 1, False)

    with pytest.raises(BTClibValueError, match="n is not the group order: "):
        Curve(13, 0, 2, (1, 9), 17, 1, False)

    # the same curve, with the group order check turned off: everything
    # else about it checks out, which is why the check has to exist
    Curve(13, 0, 2, (1, 9), 17, 1, False, order_check=False)

    with pytest.raises(BTClibValueError, match="invalid cofactor: "):
        Curve(13, 0, 2, (1, 9), 19, 2, False)

    with pytest.raises(BTClibValueError, match="weak curve: the embedding degree"):
        Curve(11, 2, 7, (6, 9), 7, 2, True)


# y^2 = x^3 + x + 6 over F_13 has 13 points, cofactor 1: an anomalous
# curve, and the smallest one this library will be asked about. Every
# check but step 8 passes on it -- n is prime, Hasse holds, n*G is INF,
# the cofactor is the expected one, and the MOV check computes
# pow(p, i, p) = 0, never 1 -- while its logarithm transfers to addition
# in F_p and is polynomial-time. Both spellings of p are tested because
# comparing n against the unconverted parameter passed the int one and
# accepted the hex string, which is how every catalogued curve, and the
# json data behind it, writes a prime (issue #166)
@pytest.mark.parametrize("p", [13, "0x0d", b"\x0d"], ids=["int", "str", "bytes"])
def test_anomalous_curve(p: Integer) -> None:
    """Refuse the n == p anomalous curve, however p is spelled."""
    with pytest.raises(BTClibValueError, match="n=p weak curve: "):
        Curve(p, 1, 6, (2, 9), 13, 1)


def test_curves_with_n_above_p() -> None:
    """Hasse admits n > p, and six catalogued curves take it up (issue 183).

    The neighbour of the n == p check that issue #166 found never fired: p
    and n are within 2*sqrt(p) of each other, so which is the larger is a
    property of the curve and not of the library, and `secp112r1`,
    `secp128r1`, `secp160k1`, `secp160r1`, `secp160r2` and `secp224k1` all
    have the order above the field prime. Four of the eight
    low-cardinality curves are on that side too, which is what makes the
    case testable at all: every (private key, nonce, challenge) triple of a
    curve of order 19 fits in a test.

    What n > p decides is whether `r = x_K % ec.n` can reduce, and it
    cannot: x_K < p < n. tests/ecc/dsa_test.py draws the consequence for
    key recovery, next to the cofactor-2 case it is the mirror of.
    """
    above = {name for name, ec in low_card_curves.items() if ec.n > ec.p}
    assert above == {"ec13_19", "ec17_23", "ec19_23", "ec23_31"}
    below = {name for name, ec in low_card_curves.items() if ec.n < ec.p}
    assert below == {"ec13_11", "ec17_13", "ec19_13", "ec23_19"}
    # no curve has n == p: Curve refuses to build one, anomalous curves
    # being weak (test_anomalous_curve)
    assert not [ec for ec in all_curves.values() if ec.n == ec.p]

    assert {name for name, ec in CURVES.items() if ec.n > ec.p} == {
        "secp112r1",
        "secp128r1",
        "secp160k1",
        "secp160r1",
        "secp160r2",
        "secp224k1",
    }

    for name in sorted(above):
        ec = low_card_curves[name]
        # every point of the curve, x below n, so nothing to reduce
        for q in range(1, ec.n):
            x_K = ec.x_aff_from_jac(mult_jac(q, ec.GJ, ec))
            assert x_K < ec.n
            assert x_K % ec.n == x_K


def test_catalogued_curves() -> None:
    """Rebuild the catalogue from its json data, with every check on.

    btclib.curves.curve builds it with order_check=False and
    weakness_check=False, the two being 123 ms of a 168 ms module
    import; this is where they happen instead, and both
    default to on, so constructing the curves here is what runs them. A
    wrong n in the json data, or a curve whose embedding degree is small,
    fails a test rather than nothing at all.

    Not the only place either check happens -- test_ec_repr rebuilds each
    curve from its repr, and test_curve_group and test_curve_group_2
    assert n*G == INF through ten distinct mult implementations -- but the
    one that is about them.
    """
    catalogues = (Brainpool_params2, NIST_params2, SEC2v1_params2, SEC2v2_params2)
    checked = set()
    for params2 in catalogues:
        for name, (p, a, b, G, n, cofactor) in params2.items():
            rebuilt = Curve(p, a, b, G, n, cofactor, name=name)
            assert rebuilt == CURVES[name]
            checked.add(name)
    assert checked == set(CURVES)


def test_aff_jac_conversions() -> None:
    """Round-trip affine and Jacobian coordinates; INF has neither."""
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
        QJ = jac_from_aff(Q)
        assert ec.aff_from_jac(QJ) == Q
        x_Q = ec.x_aff_from_jac(QJ)
        assert Q[0] == x_Q
        y_Q = ec.y_aff_from_jac(QJ)
        assert Q[1] == y_Q

        assert ec.aff_from_jac(jac_from_aff(INF)) == INF

        with pytest.raises(BTClibValueError, match="INF has no x-coordinate"):
            ec.x_aff_from_jac(INFJ)

        with pytest.raises(BTClibValueError, match="INF has no y-coordinate"):
            ec.y_aff_from_jac(INFJ)


def test_add_double_aff() -> None:
    """Test self-consistency of add and double in affine coordinates."""
    for ec in all_curves.values():
        # add G and the infinity point
        assert ec.add_aff(ec.G, INF) == ec.G
        assert ec.add_aff(INF, ec.G) == ec.G

        # double G
        G2 = ec.add_aff(ec.G, ec.G)
        assert ec.double_aff(ec.G) == G2

        # double INF
        assert ec.add_aff(INF, INF) == INF
        assert ec.double_aff(INF) == INF

        # add G and minus G
        assert ec.add_aff(ec.G, ec.negate(ec.G)) == INF

        # add INF and "minus" INF
        assert ec.add_aff(INF, ec.negate(INF)) == INF


def test_add_double_jac() -> None:
    """Test self-consistency of add and double in Jacobian coordinates."""
    for ec in all_curves.values():
        # add G and the infinity point
        assert ec.jac_equality(ec.add_jac(ec.GJ, INFJ), ec.GJ)
        assert ec.jac_equality(ec.add_jac(INFJ, ec.GJ), ec.GJ)

        # double G
        GJ2 = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.jac_equality(GJ2, ec.double_jac(ec.GJ))

        # double INF
        assert ec.jac_equality(ec.add_jac(INFJ, INFJ), INFJ)
        assert ec.jac_equality(ec.double_jac(INFJ), INFJ)

        # add G and minus G
        assert ec.jac_equality(ec.add_jac(ec.GJ, ec.negate_jac(ec.GJ)), INFJ)

        # add INF and "minus" INF
        assert ec.jac_equality(ec.add_jac(INFJ, ec.negate_jac(INFJ)), INFJ)


def test_add_double_aff_jac() -> None:
    """Test consistency between affine and Jacobian add/double methods."""
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
        QJ = jac_from_aff(Q)

        # add Q and G
        R = ec.add_aff(Q, ec.G)
        RJ = ec.add_jac(QJ, ec.GJ)
        assert ec.aff_from_jac(RJ) == R

        # double Q
        R = ec.double_aff(Q)
        RJ = ec.double_jac(QJ)
        assert ec.aff_from_jac(RJ) == R
        assert ec.add_aff(Q, Q) == R
        assert ec.jac_equality(RJ, ec.add_jac(QJ, QJ))


def _textbook_add(ec: CurveGroup, P: Point | None, Q: Point | None) -> Point | None:
    """Apply the chord-and-tangent law, with infinity spelled as None.

    The reference the two library routines are held against below, and
    deliberately not written the way they are: infinity is a value of its
    own here rather than the y == 0 of `alias`, so no ordering of the
    special cases can hide inside it.
    """
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % ec.p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + ec._a) * mod_inv(2 * P[1], ec.p) % ec.p
    else:
        lam = (Q[1] - P[1]) * mod_inv(Q[0] - P[0], ec.p) % ec.p
    x = (lam * lam - P[0] - Q[0]) % ec.p
    return x, (lam * (P[0] - x) - P[1]) % ec.p


def _jac_spellings(ec: CurveGroup, P: Point | None) -> list[JacPoint]:
    """Two Jacobian frames of a point, or three spellings of infinity.

    (x*z^2, y*z^3, z) is the same affine point for every z != 0, and
    add_jac compares coordinates that only a common frame makes
    comparable, so one frame would not exercise the comparison. Infinity
    is any Z == 0 triple: the INFJ constant, what `jac_from_aff` turns
    the affine INF into, and the all-zero triple that `jac_equality`
    reads as equal to everything.
    """
    if P is None:
        return [INFJ, jac_from_aff(INF), (0, 0, 0)]
    return [(P[0] * z * z % ec.p, P[1] * z**3 % ec.p, z) for z in (1, 2)]


def test_point_addition_exhaustive() -> None:
    """Every pair of points of every low-cardinality curve, both routines.

    All of the group, not the prime-order subgroup: what the tiny curves
    are for is that "every point plus every point" fits in a test, and
    the special cases -- infinity on either side, doubling, P + (-P) --
    are then reached by construction rather than by being named one at a
    time, in every Jacobian frame rather than in the one the caller
    happened to hand over.
    """
    for name, ec in low_card_curves.items():
        # no curve in the table has a point with y == 0, which is the one
        # affine coordinates cannot tell from INF. Asserted rather than
        # worked around, so that a curve added to the table cannot
        # quietly weaken the affine half below
        assert all(ec._y2(x) for x in range(ec.p)), name

        points: list[Point | None] = [None]
        points.extend(
            (x, y)
            for x in range(ec.p)
            for y in range(ec.p)
            if ec._y2(x) == y * y % ec.p
        )
        for P in points:
            for Q in points:
                expected = _textbook_add(ec, P, Q)
                for PJ in _jac_spellings(ec, P):
                    for QJ in _jac_spellings(ec, Q):
                        RJ = ec.add_jac(PJ, QJ)
                        got = None if RJ[2] == 0 else ec.aff_from_jac(RJ)
                        assert got == expected, f"{name}: {PJ} + {QJ}"
                R = ec.add_aff(INF if P is None else P, INF if Q is None else Q)
                assert (INF if expected is None else expected) == R, (
                    f"{name}: {P} + {Q}"
                )


def test_add_jac_infinity_is_not_a_doubling() -> None:
    """P + infinity is P, whatever Z == 0 triple infinity arrives as.

    add_jac's doubling test compares affine coordinates, and Z == 0
    leaves X and Y free to be anything at all: INFJ is (7, 0, 0) and
    `jac_from_aff(INF)` is (5, 0, 0), those x-coordinates picked for
    being invalid rather than for being zero. On a curve of
    characteristic 7 or 5 they reduce to zero, the test reads "same x,
    same y" and doubles -- issue 171, where P + INFJ answered 2*P. The
    all-zero triple does it on every curve, secp256k1 included.
    """
    for ec in (
        Curve(7, 1, 6, (1, 1), 11, 1, False),
        Curve(5, 2, 1, (0, 1), 7, 1, False),
        secp256k1,
    ):
        for infinity in (INFJ, jac_from_aff(INF), (0, 0, 0)):
            assert ec.aff_from_jac(ec.add_jac(ec.GJ, infinity)) == ec.G
            assert ec.aff_from_jac(ec.add_jac(infinity, ec.GJ)) == ec.G
            assert ec.add_jac(infinity, infinity)[2] == 0


class _CountedInt(int):
    """An int that counts the arithmetic every result of it took.

    Counting rather than timing: what an early return on a special case
    changes is the operations performed, and that is an assertion, where
    the time they take is a measurement -- and a noisy one, Python
    integers costing what their size costs. The count is a class
    attribute because the operands of an operation are two.
    """

    calls = 0

    def __mul__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(self) * int(other))

    def __rmul__(self, other: int) -> "_CountedInt":
        return self * other

    def __mod__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(self) % int(other))

    def __rmod__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(other) % int(self))

    def __add__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(self) + int(other))

    def __radd__(self, other: int) -> "_CountedInt":
        return self + other

    def __sub__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(self) - int(other))

    def __rsub__(self, other: int) -> "_CountedInt":
        _CountedInt.calls += 1
        return _CountedInt(int(other) - int(self))


def _counted(P: JacPoint) -> JacPoint:
    return _CountedInt(P[0]), _CountedInt(P[1]), _CountedInt(P[2])


def test_add_jac_does_the_same_arithmetic_around_infinity() -> None:
    """Infinity costs an addition exactly what a pair of points costs.

    Which is the point of add_jac not returning early on it: infinity is
    the identity, so a double-and-add reaches it wherever the scalar has
    a zero digit, and a case answered without the arithmetic is those
    digits on the clock. The coinciding pair is the other kind of special
    case, and is asserted here to count *differently*: that is the one
    branch add_jac keeps, and it keeps it because reaching the case needs
    the accumulator to land on a table entry or its negation, which on a
    curve with a real order it does not.

    The count does not see the values, only the operations, so what it
    holds is the shape of the code -- an early return, a case that skips
    a multiplication. That the stand-ins are the size of a real
    coordinate, which is the other half of it and the half that Python
    integers make necessary, is a measurement and lives in the comments
    of add_jac.
    """
    # the instrument first: every operation add_jac performs has to come
    # back counted from either side, a plain int on the left included, or
    # a case would count as cheaper than it is
    _CountedInt.calls = 0
    one = _CountedInt(1)
    assert (one * 2, 2 * one, one % 2, 2 % one, one + 2, 2 + one, one - 2, 2 - one) == (
        2,
        2,
        1,
        0,
        3,
        3,
        -1,
        1,
    )
    assert _CountedInt.calls == 8

    # a curve of its own: the stand-ins take part in the arithmetic, so
    # they have to be counted too, and secp256k1 is shared with every
    # other test in the suite
    ec = copy.copy(secp256k1)
    ec._stand_in_q = _counted(ec._stand_in_q)
    ec._stand_in_r = _counted(ec._stand_in_r)

    PJ = _counted(ec.GJ)
    QJ = _counted(ec.double_jac(ec.GJ))
    infinity = _counted(INFJ)

    def operations(A: JacPoint, B: JacPoint) -> int:
        _CountedInt.calls = 0
        ec.add_jac(A, B)
        return _CountedInt.calls

    counts = {
        "P + Q": operations(PJ, QJ),
        "P + INFJ": operations(PJ, infinity),
        "INFJ + P": operations(infinity, PJ),
        "INFJ + INFJ": operations(infinity, infinity),
    }
    assert len(set(counts.values())) == 1, counts
    # and the branch, which does not hide: the doubling it answers with
    # costs about what the tail of the general formula costs, so it is
    # dearer, while the opposite pair returns infinity and pays nothing
    generic = counts["P + Q"]
    assert operations(PJ, PJ) > generic
    assert operations(PJ, ec.negate_jac(PJ)) < generic
    # and the same again for the doubling, which has no case at all
    _CountedInt.calls = 0
    ec.double_jac(PJ)
    doubling = _CountedInt.calls
    _CountedInt.calls = 0
    ec.double_jac(infinity)
    assert _CountedInt.calls == doubling


def test_add_aff_takes_infinity_before_doubling() -> None:
    """The order of add_aff's two special cases is the working one.

    Not an inelegance to be tidied by testing for doubling first (issue
    171): INF is (5, 0) and its x-coordinate is arbitrary, so a doubling
    test reading it would answer "same x, different y, hence INF" for
    INF + P whenever P has x == 5. ec23_19 is generated by (5, 4), which
    is exactly that point, and every curve whose generator shares an
    x-coordinate with INF is.
    """
    ec = low_card_curves["ec23_19"]
    assert ec.G[0] == INF[0]
    assert ec.add_aff(INF, ec.G) == ec.G
    assert ec.add_aff(ec.G, INF) == ec.G


def test_ec_repr() -> None:
    """Round-trip every curve, and a bare group, through eval(repr)."""
    for ec in all_curves.values():
        ec_repr = repr(ec)
        if ec in low_card_curves.values() or ec.p_size < 24:
            ec_repr = f"{ec_repr[:-1]}, False)"
        ec2 = eval(ec_repr)  # noqa: S307
        assert str(ec) == str(ec2)
        assert ec == ec2

    # the group underneath names its own class, so it eval's back to a
    # group rather than to a Curve short of four arguments
    group = CurveGroup(secp256k1.p, 0, 7)
    assert repr(group).startswith("CurveGroup(")
    assert str(group).startswith("CurveGroup\n")
    assert eval(repr(group)) == group  # noqa: S307


def test_ec_repr_groups_its_hex() -> None:
    """A curve integer reads `DEADBEEF 00000000`, not `0xdeadbeef00000000`.

    Which is what `hex_string` produces everywhere else in the library,
    and what the round-trip above quietly depends on: it is a literal in
    the repr, so a `0x` prefix would be a *number* where the constructor
    is handed a string, and `Curve` would take it either way.
    """
    for ec in all_curves.values():
        assert "0x" not in repr(ec)

    # a curve small enough to render in decimal renders in decimal
    assert repr(low_card_curves["ec13_11"]) == "Curve(13, 7, 6, (1, 1), 11, 1)"

    # above HEX_THRESHOLD it is grouped hex, in single quotes: four bytes
    # a group, upper case, the shortest group first
    p, x_G = (
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F",
        "79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798",
    )
    assert repr(secp256k1).startswith(f"Curve('{p}', 0, 7, ('{x_G}', '")
    # `a` and `b` are 0 and 7, below the threshold, so they stay decimal
    # even here: the rule is the value's size, not the curve's

    # and a size that is not a multiple of four bytes groups the remainder
    # first rather than padding it
    assert repr(CURVES["secp112r2"]).startswith(
        "Curve('DB7C 2ABF62E3 5E668076 BEAD208B'"
    )


def test_curve_equality() -> None:
    """A curve is its parameters, not the object that holds them."""
    # the dispatch to the libsecp256k1 bindings compares ec against
    # secp256k1: with the identity comparison inherited from object, any
    # other object holding the very same parameters silently took the
    # Python path, twelve times slower and saying nothing about it
    assert secp256k1_bis is not secp256k1
    assert secp256k1_bis == secp256k1
    assert hash(secp256k1_bis) == hash(secp256k1)
    assert _libsecp256k1_applicable(secp256k1_bis)
    assert mult(3, None, secp256k1_bis) == mult(3)

    # equal curves are equal lru_cache keys, so they share the entries
    assert cached_multiples(secp256k1.GJ, secp256k1_bis) is cached_multiples(
        secp256k1.GJ, secp256k1
    )

    # the name is not a parameter: SEC 2 and NIST catalogue one curve
    assert CURVES["secp256r1"] == CURVES["nistp256"]
    assert CURVES["secp256r1"] != secp256k1
    assert secp256k1 != "not a curve"

    # the group of every point of the curve is not the subgroup a caller
    # multiplies in, whatever the two share: same p, a and b, and the one
    # has neither a generator nor an order. The comparison runs both ways
    # round, __eq__ answering NotImplemented rather than False
    group = CurveGroup(secp256k1.p, 0, 7)
    assert group == CurveGroup(secp256k1.p, 0, 7)
    assert group != secp256k1
    assert secp256k1 != group

    # the generator is part of what defines the curve, and not by picking
    # the points out. n being prime, 2G generates the very same subgroup,
    # and what differs is the correspondence between scalars and points,
    # so the same private key is another public key altogether
    on_2G = Curve(secp256k1.p, 0, 7, mult(2), secp256k1.n, 1)
    assert on_2G != secp256k1
    assert mult(3, None, on_2G) != mult(3)


def test_sec2_catalogues_share_one_curve() -> None:
    """Verify SEC 2 v.2 holds the very objects of v.1, secp256k1 too."""
    # the eight curves of SEC 2 v.2 are in v.1 too; guards against them
    # being built twice, where only one of the two objects is the
    # secp256k1 the dispatch compares against and SEC2v2 holds the other
    for ec_name, ec in SEC2v2.items():
        assert SEC2v1[ec_name] is ec
    assert SEC2v2["secp256k1"] is secp256k1


def test_each_catalogue_holds_what_it_is_named_after() -> None:
    """Guard against CURVES aliasing SEC2v1.

    "CURVES = SEC2v1" would bind the same dict, so CURVES.update(NIST) and
    CURVES.update(Brainpool) would pour those catalogues into the SEC 2 v.1
    one: SEC2v1 with 27 entries instead of its own 15, and
    SEC2v1["nistp256"] answering a curve that is not in SEC 2 v.1 at all.
    The union operator builds a new dict, which is what keeps them apart.
    """
    assert CURVES is not SEC2v1

    assert set(CURVES) == set(SEC2v1) | set(NIST) | set(Brainpool)
    assert len(CURVES) == len(SEC2v1) + len(NIST) + len(Brainpool)

    # no catalogue holds a name from another
    assert not set(SEC2v1) & set(NIST)
    assert not set(SEC2v1) & set(Brainpool)
    assert not set(NIST) & set(Brainpool)

    # SEC 2 v.2 is the one overlap there really is, being a subset of v.1
    assert set(SEC2v2) <= set(SEC2v1)

    # and the curves are still all reachable through CURVES
    for catalogue in (SEC2v1, NIST, Brainpool):
        for ec_name, ec in catalogue.items():
            assert CURVES[ec_name] is ec


def test_libsecp256k1_applicable() -> None:
    """Verify the dispatch takes secp256k1 with sha256, nothing else."""
    assert _libsecp256k1_applicable(secp256k1)
    assert _libsecp256k1_applicable(secp256k1, sha256)
    assert not _libsecp256k1_applicable(CURVES["secp256r1"])
    assert not _libsecp256k1_applicable(CURVES["secp256r1"], sha256)
    assert not _libsecp256k1_applicable(secp256k1, sha512)
    # hf is compared by identity, deliberately: a wrapper around sha256
    # takes the Python path, which is slower and never wrong
    assert not _libsecp256k1_applicable(secp256k1, partial(sha256))


def test_is_on_curve() -> None:
    """Refuse non-tuples and out-of-range coordinates, on every curve."""
    for ec in all_curves.values():
        with pytest.raises(BTClibValueError, match="point must be a tuple"):
            ec.is_on_curve("not a point")  # type: ignore[arg-type]

        with pytest.raises(BTClibValueError, match="x-coordinate not in 0..p-1: "):
            ec.y(ec.p)

        # just a point, not INF
        Q = ec.G
        with pytest.raises(BTClibValueError, match="y-coordinate not in 1..p-1: "):
            ec.is_on_curve((Q[0], ec.p))


def test_negate() -> None:
    """Verify P plus its negation is INF; refuse mixed coordinates."""
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
        minus_Q = ec.negate(Q)
        assert ec.add(Q, minus_Q) == INF

        # Jacobian coordinates
        QJ = jac_from_aff(Q)
        minus_QJ = ec.negate_jac(QJ)
        assert ec.jac_equality(ec.add_jac(QJ, minus_QJ), INFJ)

        # negate of INF is INF
        minus_INF = ec.negate(INF)
        assert minus_INF == INF

        # negate of INFJ is INFJ
        minus_INFJ = ec.negate_jac(INFJ)
        assert ec.jac_equality(minus_INFJ, INFJ)

        with pytest.raises(BTClibTypeError, match="not a point"):
            ec.negate(ec.GJ)  # type: ignore[arg-type]

        with pytest.raises(BTClibTypeError, match="not a Jacobian point"):
            ec.negate_jac(ec.G)  # type: ignore[arg-type]


def test_symmetry() -> None:
    """Methods to break symmetry: quadratic residue, even/odd, low/high."""
    for ec in low_card_curves.values():
        # just a point, not INF
        Q = ec.G
        x_Q = Q[0]

        assert not ec.y_even(x_Q) % 2
        assert ec.y_low(x_Q) <= ec.p // 2

        # compute all quadratic residues
        hasRoot = {1}
        hasRoot.update(i * i % ec.p for i in range(2, ec.p))

        if ec.p % 4 == 3:
            quad_res = ec.y_quadratic_residue(x_Q)

            # in this case only quad_res is a quadratic residue
            assert quad_res in hasRoot
            root = mod_sqrt(quad_res, ec.p)
            assert quad_res == (root * root) % ec.p
            root = ec.p - root
            assert quad_res == (root * root) % ec.p

            assert ec.p - quad_res not in hasRoot
            with pytest.raises(BTClibValueError, match="no root for "):
                mod_sqrt(ec.p - quad_res, ec.p)
        else:
            assert ec.p % 4 == 1
            # cannot use y_quadratic_residue in this case
            err_msg = "field prime is not equal to 3 mod 4: "
            with pytest.raises(BTClibValueError, match=err_msg):
                ec.y_quadratic_residue(x_Q)

            y_even = ec.y_even(x_Q)
            y_odd = ec.p - y_even
            # in this case neither or both y_Q are quadratic residues
            neither = y_odd not in hasRoot and y_even not in hasRoot
            both = y_odd in hasRoot and y_even in hasRoot
            assert neither or both
            if y_odd in hasRoot:  # both have roots
                root = mod_sqrt(y_odd, ec.p)
                assert y_odd == (root * root) % ec.p
                root = ec.p - root
                assert y_odd == (root * root) % ec.p
                root = mod_sqrt(y_even, ec.p)
                assert y_even == (root * root) % ec.p
                root = ec.p - root
                assert y_even == (root * root) % ec.p
            else:
                err_msg = "no root for "
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_sqrt(y_odd, ec.p)
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_sqrt(y_even, ec.p)

    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_even(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_low(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_quadratic_residue(INF[0])


def test_assorted_mult() -> None:
    """Cross-check mult, double_mult and multi_mult on a tiny curve."""
    ec = ec23_31
    H = second_generator(ec)
    for k1 in range(-2, ec.n):
        K1 = mult(k1, ec.G, ec)
        for k2 in range(-2, ec.n):
            K2 = mult(k2, H, ec)

            shamir = double_mult(k1, ec.G, k2, ec.G, ec)
            assert shamir == mult(k1 + k2, None, ec)

            shamir = double_mult(k1, INF, k2, H, ec)
            assert ec.is_on_curve(shamir)
            assert shamir == K2

            shamir = double_mult(k1, ec.G, k2, INF, ec)
            assert ec.is_on_curve(shamir)
            assert shamir == K1

            shamir = double_mult(k1, ec.G, k2, H, ec)
            assert ec.is_on_curve(shamir)
            K1K2 = ec.add(K1, K2)
            assert shamir == K1K2

            k3 = ec.n // 3  # just a random point, not INF
            K3 = mult(k3, ec.G, ec)
            K1K2K3 = ec.add(K1K2, K3)
            assert ec.is_on_curve(K1K2K3)
            boscoster = multi_mult([k1, k2, k3], [ec.G, H, ec.G], ec)
            assert ec.is_on_curve(boscoster)
            assert boscoster == K1K2K3, k3

            k4 = ec.n // 4  # just a random point, not INF
            K4 = mult(k4, H, ec)
            K1K2K3K4 = ec.add(K1K2K3, K4)
            assert ec.is_on_curve(K1K2K3K4)
            points = [ec.G, H, ec.G, H]
            boscoster = multi_mult([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(boscoster)
            assert boscoster == K1K2K3K4, k4
            assert multi_mult([k1, k2, k3, 0], points, ec) == K1K2K3
            assert multi_mult([k1, k2, 0, 0], points, ec) == K1K2
            assert multi_mult([k1, 0, 0, 0], points, ec) == K1
            assert multi_mult([0, 0, 0, 0], points, ec) == INF

            err_msg = "mismatch between number of scalars and points: "
            with pytest.raises(BTClibValueError, match=err_msg):
                multi_mult([k1, k2, k3, k4], [ec.G, H, ec.G], ec)


def test_double_mult() -> None:
    """Verify double_mult against add and mult over small scalars."""
    H = second_generator(secp256k1)
    G = secp256k1.G
    assert double_mult(0, G, 0, H) == INF
    assert double_mult(1, G, 0, H) == G
    assert double_mult(0, G, 1, H) == H
    for i, j in itertools.product(range(-1, 3), range(-1, 3)):
        exp = secp256k1.add(mult(i), mult(j, H))
        assert exp == double_mult(i, G, j, H)


def test_multi_mult() -> None:
    """Verify multi_mult against double_mult, issue 175's pairs too."""
    with pytest.raises(BTClibValueError, match="not a multi_mult"):
        multi_mult([1], [secp256k1.G])

    H = second_generator(secp256k1)
    G = secp256k1.G
    assert multi_mult([0, 0], [G, H]) == INF
    assert multi_mult([1, 0], [G, H]) == G
    assert multi_mult([0, 1], [G, H]) == H

    assert multi_mult([-1, 0], [G, H]) != INF
    assert multi_mult([0, -1], [G, H]) != INF

    for i, j in itertools.product(range(-1, 3), range(-1, 3)):
        exp = double_mult(i, G, j, H)
        assert exp == multi_mult([i, j], [G, H])

    # issue 175: a scalar pair of distant magnitude is what the
    # subtractive Bos-Coster step could not finish, and a mixed sign is
    # merely the worst instance of it -- -1 reduces to n-1, next to 1
    n = secp256k1.n
    for i, j in ((10**6, 1), (1, 10**6), (n - 1, 1), (n - 1, n - 2)):
        assert double_mult(i, G, j, H) == multi_mult([i, j], [G, H])


def no_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the libsecp256k1 dispatch off, and the bindings out of reach.

    The predicate is what mult, double_mult and multi_mult ask, and
    patching it is the pattern of tests/script_engine/python_path_test.py.
    Replacing the three bindings functions besides is what proves they
    were not asked anyway: a dispatch this does not cover raises here
    instead of quietly measuring the bindings against themselves.
    """

    def refuse(*_: object, **__: object) -> bytes:
        # a green suite is one where this never runs: the pragma is the
        # same one borromean and bms carry, for a line the arithmetic --
        # here the dispatch above it -- rules out
        raise AssertionError(  # pragma: no cover
            "the libsecp256k1 dispatch is patched off"
        )

    monkeypatch.setattr(curve, "_libsecp256k1_applicable", lambda *_: False)
    monkeypatch.setattr(curve, "libsecp256k1_mult", refuse)
    monkeypatch.setattr(curve, "libsecp256k1_pubkey_tweak_mul", refuse)
    monkeypatch.setattr(curve, "libsecp256k1_pubkey_combine", refuse)
    monkeypatch.setattr(curve, "libsecp256k1_pubkey_parse", refuse)
    monkeypatch.setattr(curve, "libsecp256k1_pubkey_serialize", refuse)


def test_libsecp256k1_arbitrary_point() -> None:
    """The bindings' point arithmetic against the Python arithmetic.

    Every multiplication of secp256k1 goes through libsecp256k1 now, the
    generator's and any other point's, so the Python arithmetic is what
    the suite has to reach on purpose: the dispatch is patched off and the
    same call made again. The bindings are the authority on the answer --
    they are what bitcoin runs -- and the Python implementation is the one
    being held against them, `mult` reaching its GLV endomorphism there
    and `multi_mult` its Bos-Coster.

    A spread of scalars and points rather than a random draw, so that a
    failure is the same failure tomorrow. G is among the points on
    purpose: it takes the ec_pubkey_create branch of `mult`, where every
    other point takes the ec_pubkey_tweak_mul one.
    """
    n = secp256k1.n
    scalars = (1, 2, 3, 7, 10**6, n // 2, n - 2, n - 1)
    points = [mult(k) for k in (1, 2, 3, 7, n // 3, n - 1)]
    # every scalar paired with a point, the large ones included: a sum of
    # two small scalars is not what the wNAF and the endomorphism differ on
    pairs = list(zip(scalars, points + points[:2], strict=True))

    for m, Q in itertools.product(scalars, points):
        libsecp256k1_answer = mult(m, Q)
        with pytest.MonkeyPatch.context() as patch:
            no_bindings(patch)
            assert mult(m, Q) == libsecp256k1_answer

    for (u, H), (v, Q) in itertools.product(pairs, repeat=2):
        libsecp256k1_answer = double_mult(u, H, v, Q)
        assert multi_mult([u, v], [H, Q]) == libsecp256k1_answer
        with pytest.MonkeyPatch.context() as patch:
            no_bindings(patch)
            assert double_mult(u, H, v, Q) == libsecp256k1_answer
            assert multi_mult([u, v], [H, Q]) == libsecp256k1_answer

    # and the many-scalar sum, which is what ssa's batch verification is
    libsecp256k1_answer = multi_mult(scalars, points + points[:2])
    with pytest.MonkeyPatch.context() as patch:
        no_bindings(patch)
        assert multi_mult(scalars, points + points[:2]) == libsecp256k1_answer


@pytest.mark.parametrize("bindings", [True, False], ids=["bindings", "python"])
def test_multiplications_the_bindings_decline(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zero scalar, infinity, and a sum that is infinity.

    None of the three is a libsecp256k1 argument or answer -- a pubkey is
    a point of the curve and never the identity -- and each has to be
    recognized before the call rather than caught from it. The same table
    is asserted of both implementations, which is the point of it: what
    the bindings decline, the Python arithmetic answers, and the two
    cannot disagree about infinity.
    """
    if not bindings:
        no_bindings(monkeypatch)

    n = secp256k1.n
    G = secp256k1.G
    H = second_generator(secp256k1)

    # a zero scalar, and infinity as the point
    assert mult(0, H) == INF
    assert mult(n, H) == INF  # n reduces to zero
    assert mult(3, INF) == INF
    assert mult(0, INF) == INF

    # both of them again, as one term of a sum
    assert double_mult(0, H, 0, G) == INF
    assert double_mult(0, H, 3, G) == mult(3)
    assert double_mult(3, INF, 5, H) == mult(5, H)
    assert double_mult(3, H, 5, INF) == mult(3, H)
    assert multi_mult([0, 0], [H, G]) == INF
    assert multi_mult([3, 0], [H, G]) == mult(3, H)
    assert multi_mult([3, 5], [INF, H]) == mult(5, H)

    # and the sum that is infinity: v = n - u with the same point, the
    # one-line case, then the same through multi_mult
    assert double_mult(5, H, n - 5, H) == INF
    assert multi_mult([5, n - 5], [H, H]) == INF

    # an intermediate that is infinity and a total that is not: the
    # running total starts again from the term that follows it
    assert multi_mult([5, n - 5, 3], [H, H, H]) == mult(3, H)

    # a total that is infinity from three terms of which no two cancel:
    # 5 + (n-3) + 2*(n-1) is 2n
    assert multi_mult([5, n - 3, n - 1], [H, H, mult(2, H)]) == INF

    # the same point twice is P + P, a doubling and not a cancellation
    assert multi_mult([5, 5], [H, H]) == mult(10, H)
    assert double_mult(5, H, 5, H) == mult(10, H)


def test_libsecp256k1_multi_mult_bytes() -> None:
    """The bytes boundary the dispatch is built on.

    `_sec_from_point` is `bytes_from_point` without the checks that the
    dispatch has already made, and asserting the two agree is what keeps
    it from drifting into a different serialization; `None` is infinity,
    which has no serialization at all.
    """
    H = second_generator(secp256k1)
    sec = _sec_from_point(H)
    assert sec == bytes_from_point(H, compressed=False)
    assert len(sec) == 2 * secp256k1.p_size + 1

    assert _libsecp256k1_multi_mult_([5], [sec]) == _sec_from_point(mult(5, H))
    assert _libsecp256k1_multi_mult_([5, 3], [sec, sec]) == _sec_from_point(mult(8, H))
    assert _libsecp256k1_multi_mult_([5, secp256k1.n - 5], [sec, sec]) is None


@pytest.mark.parametrize("bindings", [True, False], ids=["bindings", "python"])
def test_x_coordinate_lift(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """The two delegated square roots, against the Python arithmetic.

    A compressed public key is "this x, and the y that goes with it", so
    ec_pubkey_parse answers both of the questions `_is_x_coordinate` and
    `_y_even` ask (issue 284) -- and `ec.y_even` is what they are held
    against, over the 400 smallest field elements, of which 208 are not
    x-coordinates at all. It is those that have to be checked: an
    implementation accepting one would take a public key consensus
    refuses, and the two do not even fail alike -- the bindings raise a
    bare ValueError where btclib names the offending value.

    A spread fixed by construction rather than a random draw, so that a
    failure is the same failure tomorrow, and the same one asserted of
    both implementations.
    """
    if not bindings:
        no_bindings(monkeypatch)

    ec = secp256k1
    refused = 0
    for x in range(400):
        try:
            y_even = ec.y_even(x)
        except BTClibValueError as e:
            refused += 1
            python_msg = str(e)
            assert not _is_x_coordinate(x, ec)
            # the message names the value, which is why the refusal stays
            # curve_group's to phrase rather than the bindings' to raise
            with pytest.raises(BTClibValueError, match="invalid x-coordinate: ") as err:
                _y_even(x, ec)
            assert str(err.value) == python_msg
        else:
            assert _is_x_coordinate(x, ec)
            assert _y_even(x, ec) == y_even
            assert y_even % 2 == 0
            assert ec.is_on_curve((x, y_even))
    assert refused == 208

    # the x of a point, which is the case every caller has
    assert _is_x_coordinate(ec.G[0], ec)
    assert _y_even(ec.G[0], ec) == ec.G[1]

    # outside the field, where there is no x-coordinate to have and no
    # p-size serialization to ask the bindings about either
    for x in (-1, ec.p, ec.p + 1, 2**256):
        assert not _is_x_coordinate(x, ec)
        with pytest.raises(BTClibValueError, match="x-coordinate not in 0..p-1"):
            _y_even(x, ec)


def test_x_coordinate_lift_of_every_other_curve() -> None:
    """No curve but secp256k1 has bindings to reach, so ec.y answers.

    Exhaustively on a low-cardinality curve, where every field element is
    a candidate and the answer is the Python arithmetic by construction:
    what is asserted is that the two functions are that arithmetic, the
    default argument of secp256k1 not having leaked into either.
    """
    for ec in (CURVES["secp256r1"], low_card_curves["ec13_11"]):
        for x in range(min(ec.p, 24)):
            try:
                y_even = ec.y_even(x)
            except BTClibValueError:
                assert not _is_x_coordinate(x, ec)
                with pytest.raises(BTClibValueError, match="x-coordinate"):
                    _y_even(x, ec)
            else:
                assert _is_x_coordinate(x, ec)
                assert _y_even(x, ec) == y_even
