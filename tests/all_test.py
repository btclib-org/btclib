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

from importlib import import_module
from pkgutil import iter_modules

import btclib
import btclib.curves
import btclib.ecc
import btclib.mnemonic
import btclib.script
from btclib.curves import curve_group, curve_group_2
from btclib.script import script_pub_key


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
        "ellswift",
        "musig2",
        "pedersen",
        "second_generator",
        "ssa",
    ]

    # importing the package is enough to reach them, which is the point:
    # guards against btclib.ecc.dsa raising AttributeError until something
    # else in the process happens to import the submodule
    for name in (
        "dsa",
        "ssa",
        "bms",
        "borromean",
        "pedersen",
        "ecies",
        "ellswift",
        "musig2",
    ):
        module = getattr(btclib.ecc, name)
        assert module.__name__ == f"btclib.ecc.{name}"

    # and bms resolves dsa through the package that is importing it, which
    # the single sorted import line does not have to work around: a name
    # that is not yet an attribute falls back to a submodule import
    assert btclib.ecc.bms.dsa is btclib.ecc.dsa  # type: ignore[attr-defined]


def test_script_exports_both_halves_of_every_pair() -> None:
    """`is_x` beside `assert_x`, and `address` beside `addresses`.

    Written as the pairing rather than as the list of names, because the
    pairing is the invariant: a script type added to `script_pub_key`
    brings both halves, and exporting one of the two is what this catches.
    """
    for name in ("address", "addresses"):
        assert name in btclib.script.__all__

    types = sorted(n[3:] for n in vars(script_pub_key) if n.startswith("is_"))
    assert types  # a typo in the prefix would otherwise pass silently
    for script_type in types:
        for prefix in ("is_", "assert_"):
            name = f"{prefix}{script_type}"
            assert hasattr(script_pub_key, name), f"{name} went missing"
            assert name in btclib.script.__all__, f"{name} is not exported"


def test_mnemonic_exports_its_three_schemes() -> None:
    for name in ("bip39", "electrum", "slip39"):
        assert name in btclib.mnemonic.__all__
        module = getattr(btclib.mnemonic, name)
        assert module.__name__ == f"btclib.mnemonic.{name}"


def test_every_exported_name_exists() -> None:
    """An `__all__` entry that names nothing is a broken `import *`.

    Every package of the library, found rather than listed: a package added
    to btclib is a package this checks, where a list here would be one more
    thing to keep true -- and it is what caught `btclib.script` being
    outside the four names this used to hold. Nested packages are not
    walked, `btclib.script.engine` being the only one; asking `pkgutil` to
    walk them would import every module of the library, which
    tests/imports_test.py already does deliberately and one module at a
    time.
    """
    packages = [
        import_module(f"btclib.{name}")
        for _, name, is_package in iter_modules(btclib.__path__)
        if is_package
    ]
    assert packages, "no package found under btclib"
    for package in packages:
        names = getattr(package, "__all__", None)
        assert names, f"{package.__name__} declares no __all__"
        for name in names:
            assert hasattr(package, name), f"{package.__name__}.{name} is not there"
