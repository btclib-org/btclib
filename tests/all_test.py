#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for what the library exports.

`__all__` is a decision about the public surface, and it had drifted: it
carried a benchmark's worth of multiplication implementations in `btclib.curves`
while `btclib.ecc` advertised four helpers and none of the six signature
schemes behind them, and `btclib.mnemonic` neither of its two schemes.

Every package declares one and so does every top-level module, which is the
answer issue #338 asked for: a name is public here because a list says so,
not because it happens to lack a leading underscore. A list per module is a
list per module to keep true, and the last three tests are what keeps it,
rather than a reviewer noticing.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
"""

from __future__ import annotations

import ast
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from types import ModuleType

import btclib
import btclib.curves
import btclib.ecc
import btclib.mnemonic
import btclib.psbt
import btclib.script
from btclib.curves import curve_group, curve_group_2
from btclib.psbt import psbt_utils
from btclib.script import script_pub_key

# what a module defines without a leading underscore and deliberately does
# not export, with the reason beside the list in each module's docstring.
# A name added here is a decision; a name that has to be added here to make
# the suite pass is one that was about to become public by accident
UNEXPORTED = {
    "btclib.descriptors": ["CHECKSUM_CHARSET", "GENERATOR", "INPUT_CHARSET"],
    "btclib.network": ["datadir"],
}


def top_level_modules() -> list[ModuleType]:
    """Return btclib and its top-level modules, the private one excluded.

    Found rather than listed, as the packages are below: a module added to
    the library is a module these tests ask about. `btclib._ripemd160` is
    out because a module whose name opens with an underscore is not part of
    the surface at all -- what is public *in* it is not reachable by any
    spelling a caller is offered -- and the packages are out because
    `test_every_exported_name_exists` walks those.
    """
    return [
        btclib,
        *(
            import_module(f"btclib.{name}")
            for _, name, is_package in iter_modules(btclib.__path__)
            if not is_package and not name.startswith("_")
        ),
    ]


def imported_names(module: ModuleType) -> set[str]:
    """Return the names a module's own import statements bind.

    Read off the source rather than the module object, there being nothing
    in a module's namespace to say how a name got there. Only the top-level
    statements are read: an import inside a function binds a local.
    """
    tree = ast.parse(Path(str(module.__file__)).read_text(encoding="utf-8"))
    return {
        alias.asname or alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }


def defined_public_names(module: ModuleType) -> set[str]:
    """Return the public names a module defines itself.

    Everything in its namespace, minus the underscored, minus what it
    imported, minus the modules: a submodule becomes an attribute of its
    package as soon as anything imports it, so `btclib.b58` is in
    `vars(btclib)` by the time any test runs.
    """
    imported = imported_names(module)
    return {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and name not in imported
        and not isinstance(value, ModuleType)
    }


def test_ec_exports_the_curve_api_not_the_benchmark() -> None:
    """One multiplication, not fourteen ways to spell it.

    mult dispatches to libsecp256k1 for secp256k1 and the generator, which
    is exactly what a caller choosing mult_jac from the same namespace --
    on the strength of its name -- gives up.
    """
    assert sorted(btclib.curves.__all__) == [
        "CURVES",
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
        "bip340_nonce",
        "bms",
        "borromean",
        "commit_nonce",
        "dh",
        "diffie_hellman",
        "dsa",
        "ecies",
        "ellswift",
        "musig2",
        "pedersen",
        "rfc6979_nonce",
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
        "dh",
        "rfc6979_nonce",
        "bip340_nonce",
        "commit_nonce",
    ):
        module = getattr(btclib.ecc, name)
        assert module.__name__ == f"btclib.ecc.{name}"

    # the expert door stays in the module that defines it: a name ending in
    # an underscore takes a reduced message and an explicit curve, and
    # dsa.sign_ is not exported either
    for module_name, name in (
        ("rfc6979_nonce", "rfc6979_nonce_"),
        ("bip340_nonce", "bip340_nonce_"),
        ("commit_nonce", "commit_nonce_"),
    ):
        module = getattr(btclib.ecc, module_name)
        assert hasattr(module, name), f"btclib.ecc.{module_name}.{name} went missing"
        assert name not in btclib.ecc.__all__

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
    """Verify bip39, electrum and slip39 are exported and importable."""
    for name in ("bip39", "electrum", "slip39"):
        assert name in btclib.mnemonic.__all__
        module = getattr(btclib.mnemonic, name)
        assert module.__name__ == f"btclib.mnemonic.{name}"


def test_mnemonic_names_every_submodule_it_has() -> None:
    """The schemes, the entry point, and the two modules under all of them.

    `entropy` and `mnemonic` were the two the list left out, so what those
    hold and does not come out flat -- `WordLists` and `data_file` -- had no
    named way in. The submodules are found rather than listed: one added to
    the package is one this asks about.
    """
    submodules = sorted(name for _, name, _ in iter_modules(btclib.mnemonic.__path__))
    assert submodules == [
        "bip39",
        "dispatch",
        "electrum",
        "entropy",
        "mnemonic",
        "slip39",
    ]
    for name in submodules:
        assert name in btclib.mnemonic.__all__, f"{name} is not exported"
        module = getattr(btclib.mnemonic, name)
        assert module.__name__ == f"btclib.mnemonic.{name}"


def test_psbt_exports_the_format_not_its_plumbing() -> None:
    """The maps and the roles, not how one field of one map is written.

    The list it replaces held more names from psbt_utils than names for the
    psbt itself, `encode_dict_bytes_bytes` twice among them, so a caller
    reading `btclib.psbt` was offered the plumbing of a file format ahead
    of the format.
    """
    assert sorted(btclib.psbt.__all__) == [
        "Psbt",
        "PsbtIn",
        "PsbtOut",
        "combine",
        "estimated_input_sizes",
        "extract_tx",
        "finalize",
        "join",
        "musig2",
        "prevouts",
    ]

    # BIP373 is a role, so the module is the name, as btclib.ecc.dsa is
    assert btclib.psbt.musig2.__name__ == "btclib.psbt.musig2"

    # the plumbing is still there, in the module that defines it
    for name in (
        "assert_valid_unknown",
        "decode_dict_bytes_bytes",
        "deserialize_map",
        "deserialize_tx",
        "encode_dict_bytes_bytes",
        "serialize_bytes",
        "serialize_dict_bytes_bytes",
        "serialize_hd_key_paths",
    ):
        assert hasattr(psbt_utils, name), f"psbt_utils.{name} went missing"
        assert name not in btclib.psbt.__all__


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


def test_every_module_declares_one_too() -> None:
    """A top-level module says what it exports, as a package does.

    Half the library declared its surface and the other half left it to a
    leading character, so `from btclib.b58 import *` handed out `Key`,
    `Octets`, `String`, `sha256` and `network_from_key_value` beside the
    seven names that module defines. This is the same check
    `test_every_exported_name_exists` makes of the packages: a list, not
    empty, naming things that are there.
    """
    modules = top_level_modules()
    assert len(modules) > 1, "no top-level module found under btclib"
    for module in modules:
        names = getattr(module, "__all__", None)
        assert names, f"{module.__name__} declares no __all__"
        for name in names:
            assert hasattr(module, name), f"{module.__name__}.{name} is not there"


def test_no_module_exports_a_name_it_imported() -> None:
    """A module exports what it defines, which is what packages do not.

    A package's `__all__` is re-export by design -- `btclib.ecc` names
    `dsa`, defined a module away -- and for a module the same thing is a
    leak: `Octets` reached through `btclib.b58` is that module's import
    section, where `btclib.alias.Octets` is the name a caller wants. A
    module with a reason to re-export something is a conversation to have
    with this test, not around it.
    """
    for module in top_level_modules():
        imported = imported_names(module)
        for name in module.__all__:
            assert name not in imported, f"{module.__name__} re-exports {name}"


def test_nothing_becomes_public_by_accident() -> None:
    """Every public name is exported or recorded as kept out.

    This is the check the underscore convention cannot make: a helper that
    grows into a name callers depend on does so silently, where a package
    takes an edit to a list. `UNEXPORTED` is that edit for modules, and
    `sorted` is what the failure reads as -- the names not accounted for,
    against the ones that are.
    """
    for module in top_level_modules():
        kept_out = sorted(defined_public_names(module) - set(module.__all__))
        assert kept_out == UNEXPORTED.get(module.__name__, []), (
            f"{module.__name__} defines public names that are neither"
            f" exported nor recorded in UNEXPORTED: {kept_out}"
        )
