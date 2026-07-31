#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.curve` module."""

import itertools
from functools import partial
from hashlib import sha256, sha512

import pytest

from btclib.alias import INF, INFJ, Integer
from btclib.curves import Curve, CurveGroup, double_mult, mult, multi_mult, secp256k1
from btclib.curves.curve import (
    CURVES,
    NIST,
    Brainpool,
    Brainpool_params2,
    CurveSubGroup,
    NIST_params2,
    SEC2v1,
    SEC2v1_params2,
    SEC2v2,
    SEC2v2_params2,
    _libsecp256k1_applicable,
)

# cached_multiples and jac_from_aff are implementation helpers of
# curve_group, not part of what btclib.curves exports: they are taken from the
# module that defines them
from btclib.curves.curve_group import cached_multiples, jac_from_aff
from btclib.ecc import second_generator
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.number_theory import mod_sqrt
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from tests import vectors

# test curves: very low cardinality
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

# with python>=3.9 use dict union operator
# all_curves = low_card_curves | CURVES
all_curves = low_card_curves.copy()
all_curves.update(CURVES)

ec23_31 = low_card_curves["ec23_31"]

# the very same curve as secp256k1, in another object: nothing that
# dispatches to the libsecp256k1 bindings may tell the two apart, and
# the ecc tests import this one to check that none of them does
secp256k1_bis: Curve = eval(repr(secp256k1))  # noqa: S307


def test_mult_on_secp256k1() -> None:
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
        pytest.param(vector, id=vectors.vector_id(index, vector["seckey"][:16]))
        for index, vector in enumerate(
            vectors.load("curves", "_data", "pubkey.json")["vectors"]
        )
    ],
)
def test_secp256k1_py_vectors(vector: dict[str, str]) -> None:
    prv_key = bytes.fromhex(vector["seckey"])
    assert len(prv_key) == 32
    pubkey_uncp = bytes.fromhex(vector["pubkey"])
    assert len(pubkey_uncp) == 65
    pubkey_comp = bytes.fromhex(vector["compressed"])
    assert len(pubkey_comp) == 33

    assert pub_keyinfo_from_prv_key(prv_key, compressed=False)[0] == pubkey_uncp
    assert pub_keyinfo_from_prv_key(prv_key, compressed=True)[0] == pubkey_comp


def test_exceptions() -> None:
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

    with pytest.raises(UserWarning, match="weak curve"):
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
    with pytest.raises(BTClibValueError, match="n=p weak curve: "):
        Curve(p, 1, 6, (2, 9), 13, 1)


def test_catalogued_curves() -> None:
    """Rebuild the catalogue from its json data, with every check on.

    btclib.curves.curve builds it with order_check=False and
    weakness_check=False, the two being 123 ms of the 168 ms importing
    the module used to take; this is where they happen instead, and both
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
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
        QJ = jac_from_aff(Q)
        assert Q == ec.aff_from_jac(QJ)
        x_Q = ec.x_aff_from_jac(QJ)
        assert Q[0] == x_Q
        y_Q = ec.y_aff_from_jac(QJ)
        assert Q[1] == y_Q

        assert INF == ec.aff_from_jac(jac_from_aff(INF))

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
        assert G2 == ec.double_aff(ec.G)

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
        assert R == ec.aff_from_jac(RJ)

        # double Q
        R = ec.double_aff(Q)
        RJ = ec.double_jac(QJ)
        assert R == ec.aff_from_jac(RJ)
        assert R == ec.add_aff(Q, Q)
        assert ec.jac_equality(RJ, ec.add_jac(QJ, QJ))


def test_ec_repr() -> None:
    for ec in all_curves.values():
        ec_repr = repr(ec)
        if ec in low_card_curves.values() or ec.p_size < 24:
            ec_repr = f"{ec_repr[:-1]}, False)"
        ec2 = eval(ec_repr)  # noqa: S307
        assert str(ec) == str(ec2)
        assert ec == ec2


def test_ec_repr_groups_its_hex() -> None:
    """A curve integer is rendered `DEADBEEF 00000000`, not `0xdeadbeef00000000`.

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
    # python path, twelve times slower and saying nothing about it
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

    # the parent classes are not the curve, whatever they share with it
    group = CurveGroup(secp256k1.p, 0, 7)
    subgroup = CurveSubGroup(secp256k1.p, 0, 7, secp256k1.G)
    assert group == CurveGroup(secp256k1.p, 0, 7)
    assert subgroup == CurveSubGroup(secp256k1.p, 0, 7, secp256k1.G)
    assert group != subgroup
    assert group != secp256k1
    assert subgroup != secp256k1
    # the generator is part of what defines the subgroup
    assert subgroup != CurveSubGroup(secp256k1.p, 0, 7, mult(2))


def test_sec2_catalogues_share_one_curve() -> None:
    # the eight curves of SEC 2 v.2 are in v.1 too, and used to be built
    # twice: only one of the two objects was the secp256k1 the dispatch
    # compares against, and SEC2v2 held the other one
    for ec_name, ec in SEC2v2.items():
        assert SEC2v1[ec_name] is ec
    assert SEC2v2["secp256k1"] is secp256k1


def test_each_catalogue_holds_what_it_is_named_after() -> None:
    """CURVES was SEC2v1, and the two update() calls filled both.

    "CURVES = SEC2v1" bound the same dict, so CURVES.update(NIST) and
    CURVES.update(Brainpool) poured those catalogues into the SEC 2 v.1 one:
    SEC2v1 ended up with 27 entries instead of its own 15, and
    SEC2v1["nistp256"] answered a curve that is not in SEC 2 v.1 at all.
    The union operator the stale "with python>=3.9" comment asked for builds
    a new dict, which is what keeps them apart.
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
    assert _libsecp256k1_applicable(secp256k1)
    assert _libsecp256k1_applicable(secp256k1, sha256)
    assert not _libsecp256k1_applicable(CURVES["secp256r1"])
    assert not _libsecp256k1_applicable(CURVES["secp256r1"], sha256)
    assert not _libsecp256k1_applicable(secp256k1, sha512)
    # hf is compared by identity, deliberately: a wrapper around sha256
    # takes the python path, which is slower and never wrong
    assert not _libsecp256k1_applicable(secp256k1, partial(sha256))


def test_is_on_curve() -> None:
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
        for i in range(2, ec.p):
            hasRoot.add(i * i % ec.p)

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
            assert K1K2 == shamir

            k3 = ec.n // 3  # just a random point, not INF
            K3 = mult(k3, ec.G, ec)
            K1K2K3 = ec.add(K1K2, K3)
            assert ec.is_on_curve(K1K2K3)
            boscoster = multi_mult([k1, k2, k3], [ec.G, H, ec.G], ec)
            assert ec.is_on_curve(boscoster)
            assert K1K2K3 == boscoster, k3

            k4 = ec.n // 4  # just a random point, not INF
            K4 = mult(k4, H, ec)
            K1K2K3K4 = ec.add(K1K2K3, K4)
            assert ec.is_on_curve(K1K2K3K4)
            points = [ec.G, H, ec.G, H]
            boscoster = multi_mult([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(boscoster)
            assert K1K2K3K4 == boscoster, k4
            assert K1K2K3 == multi_mult([k1, k2, k3, 0], points, ec)
            assert K1K2 == multi_mult([k1, k2, 0, 0], points, ec)
            assert K1 == multi_mult([k1, 0, 0, 0], points, ec)
            assert INF == multi_mult([0, 0, 0, 0], points, ec)

            err_msg = "mismatch between number of scalars and points: "
            with pytest.raises(BTClibValueError, match=err_msg):
                multi_mult([k1, k2, k3, k4], [ec.G, H, ec.G], ec)


def test_double_mult() -> None:
    H = second_generator(secp256k1)
    G = secp256k1.G
    assert double_mult(0, G, 0, H) == INF
    assert double_mult(1, G, 0, H) == G
    assert double_mult(0, G, 1, H) == H
    for i, j in itertools.product(range(-1, 3), range(-1, 3)):
        exp = secp256k1.add(mult(i), mult(j, H))
        assert exp == double_mult(i, G, j, H)


def test_multi_mult() -> None:
    with pytest.raises(BTClibValueError, match="not a multi_mult"):
        multi_mult([1], [secp256k1.G])

    H = second_generator(secp256k1)
    G = secp256k1.G
    assert multi_mult([0, 0], [G, H]) == INF
    assert multi_mult([1, 0], [G, H]) == G
    assert multi_mult([0, 1], [G, H]) == H

    assert multi_mult([-1, 0], [G, H]) != INF
    assert multi_mult([0, -1], [G, H]) != INF

    for i, j in itertools.product(range(3), range(3)):
        exp = double_mult(i, G, j, H)
        assert exp == multi_mult([i, j], [G, H])
