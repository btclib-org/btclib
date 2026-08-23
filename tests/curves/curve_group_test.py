# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.curve_group` module."""

import random
from functools import partial

import pytest
from typing_extensions import override

from btclib.alias import INF, INFJ, JacPoint, Point
from btclib.curves import Curve, CurveGroup, find_all_points, secp256k1

# the mult_* variants under test, and the helpers they are built on, come
# from the module that defines them: btclib.curves exports mult,
# double_mult_var and multi_mult_var, not a menu of implementations
from btclib.curves.curve_group import (
    _MULTI_MULT_W,
    BOS_COSTER_THRESHOLD,
    MAX_W,
    _blinded_jac,
    _cached_multiples,
    _double_mult_var,
    _jac_from_aff,
    _mult,
    _mult_aff_var,
    _mult_base_3_var,
    _mult_fixed_base,
    _mult_fixed_window_cached_var,
    _mult_fixed_window_var,
    _mult_jac_var,
    _mult_mont_ladder_var,
    _mult_recursive_aff_var,
    _mult_recursive_jac_var,
    _mult_regular_window,
    _multi_mult_bos_coster_var,
    _multi_mult_var,
    _multi_mult_w_NAF_var,
    _multiples,
    _odd_multiples,
    _signed_odd_multiples_aff,
    _wNAF_of_m,
    signed_odd_digits,
)
from btclib.ecc import second_generator
from btclib.exceptions import BTClibValueError
from tests.curves.curve_test import all_curves, low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mult_recursive_aff() -> None:
    """Check the recursive affine mult on boundary scalars, every curve."""
    for ec in all_curves.values():
        assert _mult_recursive_aff_var(0, ec.G, ec) == INF
        assert _mult_recursive_aff_var(0, INF, ec) == INF

        assert _mult_recursive_aff_var(1, INF, ec) == INF
        assert _mult_aff_var(1, ec.G, ec) == ec.G

        Q = ec.add_aff_var(ec.G, ec.G)
        assert _mult_recursive_aff_var(2, ec.G, ec) == Q

        Q = _mult_recursive_aff_var(ec.n - 1, ec.G, ec)
        assert ec.negate(ec.G) == Q
        assert _mult_recursive_aff_var(ec.n - 1, INF, ec) == INF

        assert ec.add_aff_var(Q, ec.G) == INF
        assert _mult_recursive_aff_var(ec.n, ec.G, ec) == INF
        assert _mult_recursive_aff_var(ec.n, INF, ec) == INF

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_recursive_aff_var(-1, ec.G, ec)

    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_recursive_aff_var(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult(q, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(QJ)), f"{q}, {ec}"
            assert ec.aff_from_jac_var(QJ) == Q, f"{q}, {ec}"
            assert _mult_recursive_aff_var(q, INF, ec) == INF, f"{q}, {ec}"
            assert ec.is_jac_equal(INFJ, _mult(q, INFJ, ec)), f"{q}, {ec}"


def test_mult_recursive_jac() -> None:
    """Check the recursive Jacobian mult on boundary scalars, every curve."""
    for ec in all_curves.values():
        assert ec.is_jac_equal(_mult_recursive_jac_var(0, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_recursive_jac_var(0, INFJ, ec), INFJ)

        assert ec.is_jac_equal(_mult_recursive_jac_var(1, INFJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_recursive_jac_var(1, ec.GJ, ec), ec.GJ)

        PJ = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.is_jac_equal(PJ, _mult_recursive_jac_var(2, ec.GJ, ec))

        PJ = _mult_recursive_jac_var(ec.n - 1, ec.GJ, ec)
        assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
        assert ec.is_jac_equal(_mult_recursive_jac_var(ec.n - 1, INFJ, ec), INFJ)

        assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.is_jac_equal(_mult_recursive_jac_var(ec.n, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_recursive_jac_var(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_recursive_jac_var(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_recursive_jac_var(k1, ec.GJ, ec)
        assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


def test_mult_aff() -> None:
    """Check the affine double-and-add on boundary scalars, every curve."""
    for ec in all_curves.values():
        assert _mult_aff_var(0, ec.G, ec) == INF
        assert _mult_aff_var(0, INF, ec) == INF

        assert _mult_aff_var(1, INF, ec) == INF
        assert _mult_aff_var(1, ec.G, ec) == ec.G

        Q = ec.add_aff_var(ec.G, ec.G)
        assert _mult_aff_var(2, ec.G, ec) == Q

        Q = _mult_aff_var(ec.n - 1, ec.G, ec)
        assert ec.negate(ec.G) == Q
        assert _mult_aff_var(ec.n - 1, INF, ec) == INF

        assert ec.add_aff_var(Q, ec.G) == INF
        assert _mult_aff_var(ec.n, ec.G, ec) == INF
        assert _mult_aff_var(ec.n, INF, ec) == INF

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_aff_var(-1, ec.G, ec)

    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_aff_var(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult(q, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(QJ)), f"{q}, {ec}"
            assert ec.aff_from_jac_var(QJ) == Q, f"{q}, {ec}"
            assert _mult_aff_var(q, INF, ec) == INF, f"{q}, {ec}"
            assert ec.is_jac_equal(INFJ, _mult(q, INFJ, ec)), f"{q}, {ec}"


def test_mult_jac() -> None:
    """Check the Jacobian double-and-add on boundary scalars, every curve."""
    for ec in all_curves.values():
        assert ec.is_jac_equal(_mult_jac_var(0, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_jac_var(0, INFJ, ec), INFJ)

        assert ec.is_jac_equal(_mult_jac_var(1, INFJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_jac_var(1, ec.GJ, ec), ec.GJ)

        PJ = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.is_jac_equal(PJ, _mult_jac_var(2, ec.GJ, ec))

        PJ = _mult_jac_var(ec.n - 1, ec.GJ, ec)
        assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
        assert ec.is_jac_equal(_mult_jac_var(ec.n - 1, INFJ, ec), INFJ)

        assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.is_jac_equal(_mult_jac_var(ec.n, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_jac_var(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_jac_var(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_jac_var(k1, ec.GJ, ec)
        assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


def test_mont_ladder() -> None:
    """Check the Montgomery ladder on boundary scalars and against _mult."""
    for ec in low_card_curves.values():
        assert ec.is_jac_equal(_mult_mont_ladder_var(0, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(0, INFJ, ec), INFJ)

        assert ec.is_jac_equal(_mult_mont_ladder_var(1, INFJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(1, ec.GJ, ec), ec.GJ)

        PJ = _mult_mont_ladder_var(2, ec.GJ, ec)
        assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

        PJ = _mult_mont_ladder_var(ec.n - 1, ec.GJ, ec)
        assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n - 1, INFJ, ec), INFJ)

        assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_mont_ladder_var(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_mont_ladder_var(k1, ec.GJ, ec)
        assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


def test_mult_base_3() -> None:
    """Check the base-3 mult on boundary scalars and against _mult."""
    for ec in low_card_curves.values():
        assert ec.is_jac_equal(_mult_base_3_var(0, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_base_3_var(0, INFJ, ec), INFJ)

        assert ec.is_jac_equal(_mult_base_3_var(1, INFJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_base_3_var(1, ec.GJ, ec), ec.GJ)

        PJ = _mult_base_3_var(2, ec.GJ, ec)
        assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

        PJ = _mult_base_3_var(ec.n - 1, ec.GJ, ec)
        assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
        assert ec.is_jac_equal(_mult_base_3_var(ec.n - 1, INFJ, ec), INFJ)

        assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.is_jac_equal(_mult_base_3_var(ec.n, ec.GJ, ec), INFJ)
        assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            _mult_base_3_var(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_base_3_var(k1, ec.GJ, ec)
        assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


def test_cached_multiples() -> None:
    """Verify the cache holds 2**MAX_W multiples of the generator."""
    ec = secp256k1
    M = _cached_multiples(ec.GJ, ec)
    assert len(M) == 2**MAX_W


def test_multiples() -> None:
    """Check the table of multiples, size by size, against additions."""
    ec = secp256k1
    with pytest.raises(BTClibValueError, match="size too low: "):
        _multiples(ec.GJ, 1, ec)

    T = [INFJ, ec.GJ]
    M = _multiples(ec.GJ, 2, ec)
    assert len(M) == 2
    assert M == T

    T.append(ec.double_jac(ec.GJ))
    M = _multiples(ec.GJ, 3, ec)
    assert len(M) == 3
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = _multiples(ec.GJ, 4, ec)
    assert len(M) == 4
    assert M == T

    T.append(ec.double_jac(T[2]))
    M = _multiples(ec.GJ, 5, ec)
    assert len(M) == 5
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = _multiples(ec.GJ, 6, ec)
    assert len(M) == 6
    assert M == T

    T.append(ec.double_jac(T[3]))
    M = _multiples(ec.GJ, 7, ec)
    assert len(M) == 7
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = _multiples(ec.GJ, 8, ec)
    assert len(M) == 8
    assert M == T

    T.append(ec.double_jac(T[4]))
    M = _multiples(ec.GJ, 9, ec)
    assert len(M) == 9
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = _multiples(ec.GJ, 10, ec)
    assert len(M) == 10
    assert M == T


def test_mult_fixed_window() -> None:
    """Check the fixed-window mult on boundary scalars, for every width."""
    for w in range(1, MAX_W):
        for ec in low_card_curves.values():
            assert ec.is_jac_equal(
                _mult_fixed_window_var(0, ec.GJ, ec, w, cached=False), INFJ
            )
            assert ec.is_jac_equal(
                _mult_fixed_window_var(0, INFJ, ec, w, cached=False), INFJ
            )

            assert ec.is_jac_equal(
                _mult_fixed_window_var(1, INFJ, ec, w, cached=False), INFJ
            )
            assert ec.is_jac_equal(
                _mult_fixed_window_var(1, ec.GJ, ec, w, cached=False), ec.GJ
            )

            PJ = _mult_fixed_window_var(2, ec.GJ, ec, w, cached=False)
            assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = _mult_fixed_window_var(ec.n - 1, ec.GJ, ec, w, cached=False)
            assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
            assert ec.is_jac_equal(
                _mult_fixed_window_var(ec.n - 1, INFJ, ec, w, cached=False), INFJ
            )

            assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.is_jac_equal(
                _mult_fixed_window_var(ec.n, ec.GJ, ec, w, cached=False), INFJ
            )
            assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n, INFJ, ec), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_fixed_window_var(-1, ec.GJ, ec, w, cached=False)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_fixed_window_var(1, ec.GJ, ec, -w, cached=False)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_fixed_window_var(k1, ec.GJ, ec, w, cached=False)
            assert ec.is_jac_equal(K1, _mult_jac_var(k1, ec.GJ, ec))


def test_signed_odd_digits() -> None:
    """The regular recoding against hand-computed digits, and its errors.

    Vectors first, digit by digit and small enough to be checked on paper,
    because the round trip below cannot fail on a recoding that is wrong
    in a way its own reconstruction shares: -5 + 3*16 is 43 whether or not
    -5 is the digit the algorithm should have produced.
    """
    assert signed_odd_digits(43, 4, 2) == [-5, 3]
    assert signed_odd_digits(5, 1, 3) == [-1, 1, 1]
    assert signed_odd_digits(255, 2, 4) == [3, 3, 3, 3]
    # a scalar of one digit, padded out to three: the low digits go as
    # negative as they can and the top one carries the whole value
    assert signed_odd_digits(1, 4, 3) == [-15, -15, 1]
    assert signed_odd_digits(1, 4, 1) == [1]

    err_msg = "negative m: "
    with pytest.raises(BTClibValueError, match=err_msg):
        signed_odd_digits(-1, 4, 2)
    with pytest.raises(BTClibValueError, match="non positive w: "):
        signed_odd_digits(1, 0, 2)
    with pytest.raises(BTClibValueError, match="even m: "):
        signed_odd_digits(4, 4, 2)
    with pytest.raises(BTClibValueError, match="size too low: "):
        signed_odd_digits(1, 4, 0)
    with pytest.raises(BTClibValueError, match="does not fit 1 digits: "):
        signed_odd_digits(17, 4, 1)


def test_signed_odd_digits_properties() -> None:
    """The three properties the multiplication is built on, over a spread.

    Every digit odd and inside the window, the count exactly the one
    asked for whatever the scalar, and the digits summing back to m --
    the last one against the definition of a base-2^w expansion, which is
    not how signed_odd_digits computes them.
    """
    rnd = random.Random(0x5164ED)
    for w in range(1, 7):
        for size in range(1, 6):
            scalars = [1, (1 << (w * size)) - 1] + [
                rnd.randrange(1 << (w * size)) | 1 for _ in range(20)
            ]
            for m in scalars:
                digits = signed_odd_digits(m, w, size)
                assert len(digits) == size, (m, w, size)
                assert all(d % 2 for d in digits), (m, w, size)
                assert all(0 < abs(d) < 2**w for d in digits), (m, w, size)
                # positive, which is what lets the accumulator start there
                assert digits[-1] > 0, (m, w, size)
                assert sum(d << (w * i) for i, d in enumerate(digits)) == m


def test_signed_odd_multiples_aff() -> None:
    """The table against the multiplications of the digits that index it."""
    for ec in (ec23_31, secp256k1):
        for w in range(1, 6):
            T = _signed_odd_multiples_aff(ec.GJ, ec, w)
            assert len(T) == 2**w
            for d in range(-(2**w - 1), 2**w, 2):
                expected = ec.aff_from_jac_var(_mult_jac_var(d % ec.n, ec.GJ, ec))
                assert T[(d + 2**w - 1) // 2] == expected, (d, w)


def test_add_jac_aff_answers_add_jac_on_every_pair() -> None:
    """The mixed sum against the general one, exhaustively.

    Every point of every low-cardinality curve as the affine operand,
    infinity included, against every point of the subgroup as the
    Jacobian one, whose Z is a real one rather than the 1 an affine point
    converts to. The two are the same formula with the second operand's Z
    known to be one, so what holds add_jac's branch-free infinity
    handling and its one branch on V correct holds this one's too -- and
    these curves are where both are reached at all.
    """
    for ec in low_card_curves.values():
        points = [*find_all_points(ec), INF]
        jac = [_jac_from_aff(P) for P in points]
        jac += [_mult_jac_var(k, ec.GJ, ec) for k in range(ec.n)]
        for PJ in jac:
            for R in points:
                mixed = ec.add_jac_aff(PJ, R)
                assert ec.is_jac_equal(ec.add_jac(PJ, _jac_from_aff(R)), mixed)


class _CountingGroup(CurveGroup):
    """secp256k1's group, counting the point additions it is asked for.

    The number of additions is what the scalar used to decide (issue 254),
    and counting them is how the test below says it no longer does: a
    timing at 0.8 ms a multiplication is noise against a spread of one
    addition in seventy.
    """

    def __init__(self) -> None:
        # secp256k1's own p, a and b, which is the curve every measurement
        # in curve_group's docstrings is taken on
        super().__init__(secp256k1.p, 0, 7)
        self.additions = 0

    @override
    def add_jac(self, Q: JacPoint, R: JacPoint) -> JacPoint:
        self.additions += 1
        return super().add_jac(Q, R)

    @override
    def add_jac_aff(self, Q: JacPoint, R: Point) -> JacPoint:
        # counted beside add_jac and not apart from it: what the test
        # below is about is how many additions a scalar costs, and the
        # regular window indexes an affine table where the fixed one it is
        # measured against indexes a Jacobian one
        self.additions += 1
        return super().add_jac_aff(Q, R)


def test_regular_window_addition_count_is_the_same_for_every_scalar() -> None:
    """Issue 254, as the property it is: one count, not a range of them.

    The fixed window over the same scalars is the control, and what varies
    for it is the *size* of the scalar: its digit count is
    ceil(m.bit_length() / w), so it makes one addition and w doublings
    fewer for every window the scalar is short of a full one. Hence the
    scalars of distant sizes here beside the full-length random ones --
    over 256-bit scalars alone the control would be constant too, a
    quarter of the 20 the seed picks being needed to reach a shorter
    digit count at all.
    """
    ec = _CountingGroup()
    rnd = random.Random(0x9EC0DE)
    scalars = [rnd.randrange(secp256k1.n) for _ in range(10)]
    scalars += [0, 1, 2, 3, 1 << 100, secp256k1.n >> 17, secp256k1.n - 1]

    regular = set()
    fixed = set()
    for m in scalars:
        ec.additions = 0
        _mult_regular_window(m, secp256k1.GJ, ec, w=4)
        regular.add(ec.additions)
        ec.additions = 0
        _mult_fixed_window_var(m, secp256k1.GJ, ec, w=4, cached=False)
        fixed.add(ec.additions)

    assert len(regular) == 1, regular
    assert len(fixed) > 1, fixed


def test_mult_fixed_base() -> None:
    """Check the fixed-base ladder against the multiplication it replaces.

    Every scalar of the low-cardinality curves, whose scalar_len is a
    handful of bits, so the per-position tables are short enough to build
    at every width; and the boundaries on secp256k1, where a table is 43
    positions. A scalar above ec.scalar_len bits has no table to index and
    is refused by the recoding, which is what the last case asserts:
    `curves.mult` reduces mod n before reaching here, as every entry point
    of the library does.
    """
    for w in range(1, MAX_W):
        for ec in low_card_curves.values():
            for m in range(ec.n + 1):
                assert ec.is_jac_equal(
                    _mult_fixed_base(m, ec.GJ, ec, w),
                    _mult_jac_var(m % ec.n, ec.GJ, ec),
                ), (m, w, ec)
            assert ec.is_jac_equal(_mult_fixed_base(1, INFJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_fixed_base(-1, ec.GJ, ec, w)
            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_fixed_base(1, ec.GJ, ec, -w)

    ec = secp256k1
    for m in (0, 1, 2, 3, ec.n - 1, ec.n, ec.n + 1):
        assert ec.is_jac_equal(
            _mult_fixed_base(m, ec.GJ, ec, w=4), _mult_jac_var(m, ec.GJ, ec)
        ), m

    with pytest.raises(BTClibValueError, match="does not fit"):
        _mult_fixed_base(1 << ec.scalar_len, ec.GJ, ec, w=4)


def test_mult_regular_window() -> None:
    """Check the regular-window mult on boundaries and oversized scalars."""
    for w in range(1, MAX_W):
        for ec in low_card_curves.values():
            assert ec.is_jac_equal(_mult_regular_window(0, ec.GJ, ec, w), INFJ)
            assert ec.is_jac_equal(_mult_regular_window(0, INFJ, ec, w), INFJ)

            assert ec.is_jac_equal(_mult_regular_window(1, INFJ, ec, w), INFJ)
            assert ec.is_jac_equal(_mult_regular_window(1, ec.GJ, ec, w), ec.GJ)

            PJ = _mult_regular_window(2, ec.GJ, ec, w)
            assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = _mult_regular_window(ec.n - 1, ec.GJ, ec, w)
            assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
            assert ec.is_jac_equal(_mult_regular_window(ec.n - 1, INFJ, ec, w), INFJ)

            assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.is_jac_equal(_mult_regular_window(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_regular_window(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_regular_window(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_regular_window(k1, ec.GJ, ec, w)
            assert ec.is_jac_equal(K1, _mult_jac_var(k1, ec.GJ, ec))

    # a scalar of more bits than the group has, which is the one case where
    # the digit count is the scalar's own again: the answer is still the
    # multiplication, the recoding being asked for the digits it needs
    ec = secp256k1
    for m in (ec.n, ec.n + 1, 2 * ec.n, 1 << 300):
        assert ec.is_jac_equal(
            _mult_regular_window(m, ec.GJ, ec, w=4), _mult_jac_var(m, ec.GJ, ec)
        ), m


def test_mult_fixed_window_cached() -> None:
    """Check the cached fixed-window mult on boundary scalars and widths."""
    for _ in range(1, MAX_W):
        for ec in low_card_curves.values():
            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(0, ec.GJ, ec, w=4), INFJ
            )
            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(0, INFJ, ec, w=4), INFJ
            )

            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(1, INFJ, ec, w=4), INFJ
            )
            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(1, ec.GJ, ec, w=4), ec.GJ
            )

            PJ = _mult_fixed_window_cached_var(2, ec.GJ, ec, w=4)
            assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = _mult_fixed_window_cached_var(ec.n - 1, ec.GJ, ec, w=4)
            assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)
            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(ec.n - 1, INFJ, ec, w=4), INFJ
            )

            assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.is_jac_equal(
                _mult_fixed_window_cached_var(ec.n, ec.GJ, ec, w=4), INFJ
            )
            assert ec.is_jac_equal(_mult_mont_ladder_var(ec.n, INFJ, ec), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_fixed_window_cached_var(-1, ec.GJ, ec, w=4)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_fixed_window_cached_var(1, ec.GJ, ec, -1)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_fixed_window_cached_var(k1, ec.GJ, ec, w)
            assert ec.is_jac_equal(K1, _mult_jac_var(k1, ec.GJ, ec))


def test_assorted_jac_mult() -> None:
    """Check the double and multi mults exhaustively against sums of mults."""
    ec = ec23_31
    H = second_generator(ec)
    HJ = _jac_from_aff(H)
    for k1 in range(ec.n):
        K1J = _mult(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult(k2, HJ, ec)

            shamir = _double_mult_var(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(shamir))
            assert ec.is_jac_equal(shamir, _mult(k1 + k2, ec.GJ, ec))

            shamir = _double_mult_var(k1, INFJ, k2, HJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(shamir))
            assert ec.is_jac_equal(shamir, K2J)

            shamir = _double_mult_var(k1, ec.GJ, k2, INFJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(shamir))
            assert ec.is_jac_equal(shamir, K1J)

            shamir = _double_mult_var(k1, ec.GJ, k2, HJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(shamir))
            K1JK2J = ec.add_jac(K1J, K2J)
            assert ec.is_jac_equal(K1JK2J, shamir)

            k3 = ec.n // 3  # just a point, not INF
            K3J = _mult(k3, ec.GJ, ec)
            K1JK2JK3J = ec.add_jac(K1JK2J, K3J)
            assert ec.is_on_curve(ec.aff_from_jac_var(K1JK2JK3J))
            boscoster = _multi_mult_var([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(boscoster))
            assert ec.aff_from_jac_var(K1JK2JK3J) == ec.aff_from_jac_var(boscoster), k3
            assert ec.is_jac_equal(K1JK2JK3J, boscoster)

            k4 = ec.n // 4  # just a point, not INF
            K4J = _mult(k4, HJ, ec)
            K1JK2JK3JK4J = ec.add_jac(K1JK2JK3J, K4J)
            assert ec.is_on_curve(ec.aff_from_jac_var(K1JK2JK3JK4J))
            points = [ec.GJ, HJ, ec.GJ, HJ]
            boscoster = _multi_mult_var([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(ec.aff_from_jac_var(boscoster))
            assert ec.aff_from_jac_var(K1JK2JK3JK4J) == ec.aff_from_jac_var(
                boscoster
            ), k4
            assert ec.is_jac_equal(K1JK2JK3JK4J, boscoster)
            assert ec.is_jac_equal(
                K1JK2JK3J, _multi_mult_var([k1, k2, k3, 0], points, ec)
            )
            assert ec.is_jac_equal(K1JK2J, _multi_mult_var([k1, k2, 0, 0], points, ec))
            assert ec.is_jac_equal(K1J, _multi_mult_var([k1, 0, 0, 0], points, ec))
            assert ec.is_jac_equal(INFJ, _multi_mult_var([0, 0, 0, 0], points, ec))

            err_msg = "mismatch between number of scalars and points: "
            with pytest.raises(BTClibValueError, match=err_msg):
                _multi_mult_var([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ], ec)

            err_msg = "negative coefficient: "
            with pytest.raises(BTClibValueError, match=err_msg):
                _multi_mult_var([k1, k2, -k3], [ec.GJ, HJ, ec.GJ], ec)

    with pytest.raises(BTClibValueError, match="negative first coefficient: "):
        _double_mult_var(-5, HJ, 1, ec.GJ, ec)
    with pytest.raises(BTClibValueError, match="negative second coefficient: "):
        _double_mult_var(1, HJ, -5, ec.GJ, ec)


def test_mult_on_a_characteristic_7_curve() -> None:
    """Every multiplication, on the curve where INFJ's x-coordinate is 0.

    INFJ is (7, 0, 0), so p == 7 is where that arbitrary x reduces to
    zero and add_jac's doubling test can mistake the identity for the
    other operand (issue 171). Before it was fixed, _mult_jac_var answered
    wrong for 6 of the 13 scalars here, the ladder and _mult_recursive_jac_var
    for 12 of 13, and _double_mult_var for 100 of the 169 coefficient pairs;
    the two fixed windows happened not to, every scalar of a curve this
    small fitting in one base-16 digit -- which is why the reference here
    is _mult_aff_var, the one multiplication that forms no Jacobian point at
    all.
    """
    ec = Curve(7, 0, 3, (1, 2), 13, 1, False)
    # named pairs rather than the functions alone: three of them take a
    # window width, which carries no default now, and a partial has no
    # __name__ for the assertion to report
    variants = (
        ("_mult", _mult),
        ("_mult_jac_var", _mult_jac_var),
        ("_mult_recursive_jac_var", _mult_recursive_jac_var),
        ("_mult_mont_ladder_var", _mult_mont_ladder_var),
        ("_mult_base_3_var", _mult_base_3_var),
        ("_mult_fixed_window_var", partial(_mult_fixed_window_var, w=4, cached=False)),
        ("_mult_fixed_window_cached_var", partial(_mult_fixed_window_cached_var, w=4)),
        ("_mult_regular_window", partial(_mult_regular_window, w=4)),
    )
    for k in range(ec.n):
        expected = _mult_aff_var(k, ec.G, ec)
        for name, mult_f in variants:
            assert ec.aff_from_jac_var(mult_f(k, ec.GJ, ec)) == expected, name
        for j in range(ec.n):
            shamir = _double_mult_var(k, ec.GJ, j, ec.GJ, ec)
            assert ec.aff_from_jac_var(shamir) == _mult_aff_var(k + j, ec.G, ec), (k, j)


def _sum_of_mults(
    scalars: list[int], jac_points: list[JacPoint], ec: CurveGroup
) -> JacPoint:
    """Return the sum the multi multiplications have to agree with.

    One scalar multiplication per point and then the additions: the
    answer no algorithm is clever about, and the one both of them are
    checked against.
    """
    R = INFJ
    for n, PJ in zip(scalars, jac_points, strict=True):
        R = ec.add_jac(R, _mult(n, PJ, ec))
    return R


def test_multi_mult_w_NAF() -> None:
    """Interleaved wNAF against Bos-Coster and the plain sum of mults.

    Exhaustive over the scalar pairs of two low-cardinality curves, for
    the widths where the table of odd multiples has one entry (w of 1 and
    2, digits of +-1 only) and where it has more, and with the zero
    scalar, the point at infinity and a scalar of one digit against one
    of five -- the case where a wNAF runs out of digits before the loop
    does.
    """
    for ec in (low_card_curves["ec13_11"], ec23_31):
        HJ = _jac_from_aff(second_generator(ec))
        # MAX_W by name rather than the 5 it is today: it is the widest
        # window the dispatch ever asks for, and a test that stops one
        # short of the tuning constant stops covering it the moment the
        # constant moves
        for w in (1, 2, 3, MAX_W):
            for k1 in range(ec.n):
                for k2 in range(ec.n):
                    scalars = [k1, k2, ec.n // 3]
                    points = [ec.GJ, HJ, ec.GJ]
                    expected = _sum_of_mults(scalars, points, ec)
                    got = _multi_mult_w_NAF_var(
                        scalars, points, ec, w, ec._fixed_points
                    )
                    assert ec.is_jac_equal(got, expected), (k1, k2, w)
                    assert ec.is_jac_equal(
                        got, _multi_mult_bos_coster_var(scalars, points, ec)
                    ), (k1, k2, w)

            # a zero scalar, an INF point, and scalars of distant lengths
            assert ec.is_jac_equal(
                _multi_mult_w_NAF_var([0, 0], [ec.GJ, HJ], ec, w, ec._fixed_points),
                INFJ,
            )
            for scalars in ([0, 3], [3, 0], [1, ec.n - 1], [ec.n - 1, 1]):
                for points in ([ec.GJ, HJ], [INFJ, HJ], [ec.GJ, INFJ]):
                    expected = _sum_of_mults(scalars, points, ec)
                    got = _multi_mult_w_NAF_var(
                        scalars, points, ec, w, ec._fixed_points
                    )
                    assert ec.is_jac_equal(got, expected), (scalars, w)

        # a window wider than the order itself, where the table of odd
        # multiples wraps past n and holds the point at infinity among
        # its entries -- and where a scalar of this curve is one digit.
        # Not in the exhaustive loop above: the table is 2^(w-2) entries
        # and every pair would pay for it, for a case the digits below
        # 2^(w-1) already cover
        for w in (ec.n.bit_length() + 1, ec.n.bit_length() + 3):
            for scalars in ([1, ec.n - 1], [ec.n // 2, 3], [0, ec.n - 1]):
                points = [ec.GJ, HJ]
                expected = _sum_of_mults(scalars, points, ec)
                got = _multi_mult_w_NAF_var(scalars, points, ec, w, ec._fixed_points)
                assert ec.is_jac_equal(got, expected), (scalars, w)

    ec = secp256k1
    with pytest.raises(BTClibValueError, match="non positive w: "):
        _multi_mult_w_NAF_var([1, 1], [ec.GJ, ec.GJ], ec, 0, ec._fixed_points)


def test_multi_mult_agrees_across_curves() -> None:
    """Random scalars on every curve in the catalogue, not just secp256k1.

    The two implementations and the sum of mults, on three points of
    each: a fixed seed, so a failure is reproducible, and the curves that
    are not secp256k1 are the ones only the Python path ever answers.
    """
    rnd = random.Random(0x2AC0FFEE)
    for ec in all_curves.values():
        HJ = _jac_from_aff(second_generator(ec))
        points = [ec.GJ, HJ, _mult(3, ec.GJ, ec)]
        scalars = [rnd.randrange(ec.n) for _ in points]
        expected = _sum_of_mults(scalars, points, ec)
        assert ec.is_jac_equal(
            _multi_mult_w_NAF_var(scalars, points, ec, _MULTI_MULT_W, ec._fixed_points),
            expected,
        )
        assert ec.is_jac_equal(
            _multi_mult_bos_coster_var(scalars, points, ec), expected
        )


def test_multi_mult_dispatch() -> None:
    """Both sides of the threshold, and the errors they share.

    The count of the nonzero scalars is what picks the implementation, so
    the test is a batch one scalar short of BOS_COSTER_THRESHOLD and one
    exactly on it: the two have to answer the same point, and the same
    error to the same bad arguments. Scalars from 1 rather than from 0,
    so that the batch is the size it is named: a zero among them would
    move the dispatch to the other side of the threshold and the test
    would still pass, testing the other branch twice.
    """
    ec = ec23_31
    HJ = _jac_from_aff(second_generator(ec))
    rnd = random.Random(0x175212)
    for size in (BOS_COSTER_THRESHOLD - 1, BOS_COSTER_THRESHOLD):
        points = [ec.GJ if i % 2 else HJ for i in range(size)]
        scalars = [rnd.randrange(1, ec.n) for _ in range(size)]
        expected = _sum_of_mults(scalars, points, ec)
        assert ec.is_jac_equal(_multi_mult_var(scalars, points, ec), expected)
        assert ec.is_jac_equal(
            _multi_mult_w_NAF_var(scalars, points, ec, _MULTI_MULT_W, ec._fixed_points),
            expected,
        )
        assert ec.is_jac_equal(
            _multi_mult_bos_coster_var(scalars, points, ec), expected
        )

        # all zero, whatever the algorithm: nothing to sum. Asked of
        # both by name, the dispatch no longer being able to reach
        # Bos-Coster with it -- a batch of nothing but zeros is a batch
        # of no nonzero scalars, which is below any threshold
        assert ec.is_jac_equal(_multi_mult_var([0] * size, points, ec), INFJ)
        assert ec.is_jac_equal(
            _multi_mult_w_NAF_var(
                [0] * size, points, ec, _MULTI_MULT_W, ec._fixed_points
            ),
            INFJ,
        )
        assert ec.is_jac_equal(_multi_mult_bos_coster_var([0] * size, points, ec), INFJ)

        # a batch of this length whose *work* is two scalars: the zeros
        # are dropped downstream, so the count that dispatches counts
        # them out first and this goes to the interleaved wNAF
        sparse = [scalars[0], *([0] * (size - 2)), scalars[-1]]
        assert ec.is_jac_equal(
            _multi_mult_var(sparse, points, ec), _sum_of_mults(sparse, points, ec)
        )

        err_msg = "mismatch between number of scalars and points: "
        with pytest.raises(BTClibValueError, match=err_msg):
            _multi_mult_var(scalars, points[1:], ec)
        with pytest.raises(BTClibValueError, match="negative coefficient: "):
            _multi_mult_var([-1, *scalars[1:]], points, ec)

    with pytest.raises(BTClibValueError, match="not a multi_mult_var"):
        _multi_mult_var([1], [ec.GJ], ec)


def test_multi_mult_distant_magnitudes() -> None:
    """Issue 175, asked of the implementation that can still hang.

    _multi_mult_var sends two scalars to the interleaved wNAF, which is
    indifferent to their magnitudes, so the pathological pairs reach
    Bos-Coster only inside a batch above the threshold -- where they are
    the whole of the batch's cost. Euclid's quotient is what bounds it:
    the subtractive step takes 10.6 s on the first pair and does not
    finish on the third, and this test would say so by not returning.
    """
    ec = secp256k1
    HJ = _jac_from_aff(second_generator(ec))
    for scalars in ([10**6, 1], [1, 10**6], [ec.n - 1, 1], [ec.n - 1, ec.n - 2]):
        expected = _sum_of_mults(scalars, [ec.GJ, HJ], ec)
        assert ec.is_jac_equal(_multi_mult_var(scalars, [ec.GJ, HJ], ec), expected)
        assert ec.is_jac_equal(
            _multi_mult_bos_coster_var(scalars, [ec.GJ, HJ], ec), expected
        )


def test_jac_equality() -> None:
    """Check is_jac_equal on equal representations and on unequal points."""
    ec = ec23_31
    assert ec.is_jac_equal(ec.GJ, _jac_from_aff(ec.G))

    # q in [2, n-1], as the difference with ec.GJ is checked below
    q = 2
    Q = _mult_aff_var(q, ec.G, ec)
    QJ = _mult(q, ec.GJ, ec)
    assert ec.is_jac_equal(QJ, _jac_from_aff(Q))
    assert not ec.is_jac_equal(QJ, ec.negate_jac(QJ))
    assert not ec.is_jac_equal(QJ, ec.GJ)


def test_INF() -> None:
    """Verify INF's y is 0 and its x is no coordinate of secp256k1."""
    assert INF[1] == 0

    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_var(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_var(INF[0] + secp256k1.n)


def test_aff_from_jac_batch_is_aff_from_jac_over_a_sequence() -> None:
    """The batch answers what the conversions one at a time answer.

    Infinity keeps its place in the list and is not in the batch, having
    no Z to invert: what a caller gets back is as long as what it passed,
    which is what makes the answer indexable beside the input.
    """
    for ec in all_curves.values():
        QJs = [_mult(k, ec.GJ, ec) for k in (1, 2, 3, ec.n - 1)]
        assert ec.aff_from_jac_batch_var(QJs) == [ec.aff_from_jac_var(QJ) for QJ in QJs]

        # infinity first, last and in between, so that the peeling back
        # off the running products starts and stops beside one
        mixed = [INFJ, QJs[0], INFJ, INFJ, QJs[1], INFJ]
        assert ec.aff_from_jac_batch_var(mixed) == [
            ec.aff_from_jac_var(QJ) for QJ in mixed
        ]

        # nothing to invert at all, and nothing to convert at all
        assert ec.aff_from_jac_batch_var([INFJ, INFJ]) == [INF, INF]
        assert ec.aff_from_jac_batch_var([]) == []


def test_blinding_changes_the_coordinates_and_not_the_point() -> None:
    """A rescaled point is the same point with a Z nobody can predict.

    Which is the whole of what it is for: (X, Y, Z) and
    (l^2*X, l^3*Y, l*Z) are one affine point, so what a caller sees is
    unchanged and what a multiplication forms along the way is not the
    same integers twice.
    """
    for ec in all_curves.values():
        for k in (1, 2, 3, ec.n - 1):
            QJ = _mult(k, ec.GJ, ec)
            blinded = [_blinded_jac(QJ, ec) for _ in range(8)]
            for B in blinded:
                assert ec.aff_from_jac_var(B) == ec.aff_from_jac_var(QJ)
                assert ec.is_jac_equal(B, QJ)
            # a curve of eleven points has eleven values of l to draw
            # from, so the Z's are only expected to differ where p is big
            if ec.p > 2**32:
                assert len({B[2] for B in blinded}) > 1

        # infinity has no affine coordinates to preserve and stays
        # infinity, Z == 0 scaling to Z == 0
        assert _blinded_jac(INFJ, ec)[2] == 0


def test_the_interleaved_loop_makes_the_operations_its_wnafs_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One doubling per bit position, and the point each nonzero digit names.

    What `_additions_by_position` reorganized is where a digit is looked up,
    not what is done with it (issue 906), and a comparison of results would
    be blind to a reordering that answers the same point -- group addition
    commutes. So the operations are asserted: the sequence of doublings and
    additions the call makes, *with the point each addition takes*, against
    the sequence the wNAFs of its own scalars name. Recorded without their
    argument the additions would pin how many a position makes and not which
    they are, so reversing two of them at one position would still pass.

    `fixed=frozenset()` so that every point gets the width `w` asked for
    here and the tables are reproducible from `_odd_multiples`: a memoized
    table comes at `_FIXED_POINT_W`, and this is about the loop rather than
    about which width a point earns.

    The curve is built here rather than being `secp256k1` itself, because
    `monkeypatch.setattr` on an instance restores by assigning the bound
    method back: it lands in that instance's `__dict__` and stays there for
    every test after this one. Harmless on a shared curve as things stand,
    and not something to leave for the day one of these methods is patched
    on the class.
    """
    ec = Curve(
        secp256k1.p,
        0,
        7,
        secp256k1.G,
        secp256k1.n,
        1,
        weakness_check=False,
        order_check=False,
    )
    w = _MULTI_MULT_W
    points = [ec.GJ, _mult(3, ec.GJ, ec), _mult(5, ec.GJ, ec)]
    scalars = [
        0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
        0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,
        0x539,
    ]

    # the sequence the wNAFs name, built before anything is patched: a
    # signed digit d names T[(d-1)//2] and the opposite of T[(-d-1)//2],
    # which is what makes an addition's argument predictable from the wNAF
    # alone -- and `_odd_multiples` doubles too, so building the tables under
    # the recorder would put its own operations in the log
    tables = [ec.aff_from_jac_batch_var(_odd_multiples(PJ, ec, w)) for PJ in points]
    nafs = [_wNAF_of_m(n, w) for n in scalars]
    expected: list[tuple[str, Point | None]] = []
    for j in reversed(range(max(len(naf) for naf in nafs))):
        expected.append(("double", None))
        for naf, T in zip(nafs, tables, strict=True):
            d = naf[j] if j < len(naf) else 0
            if d:
                expected.append(
                    ("add", T[(d - 1) // 2] if d > 0 else ec.negate(T[(-d - 1) // 2]))
                )

    operations: list[tuple[str, Point | None]] = []
    real_double, real_add = ec.double_jac, ec.add_jac_aff

    def double(R: JacPoint) -> JacPoint:
        operations.append(("double", None))
        return real_double(R)

    def add(R: JacPoint, P: Point) -> JacPoint:
        operations.append(("add", P))
        return real_add(R, P)

    monkeypatch.setattr(ec, "double_jac", double)
    monkeypatch.setattr(ec, "add_jac_aff", add)
    got = _multi_mult_w_NAF_var(scalars, points, ec, w, frozenset())
    # the tail, because a table of odd multiples is built before the loop and
    # with the same doubling: one per point, its additions being Jacobian and
    # so not `add_jac_aff`. That prefix is what `fixed` spares a memoized
    # point and is not what this asserts
    assert operations[: len(points)] == [("double", None)] * len(points)
    assert operations[len(points) :] == expected

    # and the point is still the right one, the sequence being asserted
    # about a call that answered
    assert ec.is_jac_equal(got, _sum_of_mults(scalars, points, ec))
