#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for what the packages export.

`__all__` is a decision about the public surface, and it had drifted: it
carried a benchmark's worth of multiplication implementations in `btclib.curves`
while `btclib.ecc` advertised four helpers and none of the six signature
schemes behind them, and `btclib.mnemonic` neither of its two schemes.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
"""

from __future__ import annotations

import btclib.curves
import btclib.ecc
import btclib.mnemonic
from btclib.curves import curve_group, curve_group_2


def test_ec_exports_the_curve_api_not_the_benchmark() -> None:
    """One multiplication, not fourteen ways to spell it.

    mult dispatches to libsecp256k1 for secp256k1 and the generator, which
    is exactly what a caller choosing mult_jac from the same namespace --
    on the strength of its name -- gives up.
    """
    assert sorted(btclib.curves.__all__) == [
        "Curve",
        "CurveGroup",
        "bytes_from_point",
        "bytes_from_prv_key_int",
        "double_mult",
        "find_all_points",
        "find_subgroup_points",
        "mult",
        "multi_mult",
        "point_from_octets",
        "secp256k1",
    ]

    # the implementations are still there, in the module that defines them
    variants = [
        (curve_group, "mult_aff"),
        (curve_group, "mult_base_3"),
        (curve_group, "mult_fixed_window"),
        (curve_group, "mult_fixed_window_cached"),
        (curve_group, "mult_jac"),
        (curve_group, "mult_mont_ladder"),
        (curve_group, "mult_recursive_aff"),
        (curve_group, "mult_recursive_jac"),
        (curve_group, "cached_multiples"),
        (curve_group, "jac_from_aff"),
        (curve_group, "multiples"),
        (curve_group_2, "mult_endomorphism_secp256k1"),
        (curve_group_2, "mult_sliding_window"),
        (curve_group_2, "mult_w_NAF"),
    ]
    for module, name in variants:
        assert hasattr(module, name), f"{module.__name__}.{name} went missing"
        assert name not in btclib.curves.__all__


def test_ecc_exports_the_signature_schemes() -> None:
    """Guards against dsa, ssa and bms dropping out of the export list."""
    assert sorted(btclib.ecc.__all__) == [
        "ansi_x9_63_kdf",
        "bip340_nonce_",
        "bms",
        "borromean",
        "diffie_hellman",
        "dsa",
        "ecies",
        "musig2",
        "pedersen",
        "second_generator",
        "ssa",
    ]

    # importing the package is enough to reach them, which is the point:
    # guards against btclib.ecc.dsa raising AttributeError until something
    # else in the process happens to import the submodule
    for name in ("dsa", "ssa", "bms", "borromean", "pedersen", "ecies", "musig2"):
        module = getattr(btclib.ecc, name)
        assert module.__name__ == f"btclib.ecc.{name}"

    # and bms resolves dsa through the package that is importing it, which
    # the single sorted import line does not have to work around: a name
    # that is not yet an attribute falls back to a submodule import
    assert btclib.ecc.bms.dsa is btclib.ecc.dsa  # type: ignore[attr-defined]


def test_mnemonic_exports_its_three_schemes() -> None:
    for name in ("bip39", "electrum", "slip39"):
        assert name in btclib.mnemonic.__all__
        module = getattr(btclib.mnemonic, name)
        assert module.__name__ == f"btclib.mnemonic.{name}"


def test_every_exported_name_exists() -> None:
    """An `__all__` entry that names nothing is a broken `import *`."""
    for package in (btclib.curves, btclib.ecc, btclib.mnemonic):
        for name in package.__all__:
            assert hasattr(package, name), f"{package.__name__}.{name} is not there"
