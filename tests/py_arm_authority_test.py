# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What says the Python arm is right, other than the bindings.

The suite validates btclib's Python arms *against* libsecp256k1: the
bindings are the authority on the answer -- they are what bitcoin runs --
and agreeing with them is what a second implementation owes.

Issue #198 needs the other property. A test framework built on btclib
runs the Python arm precisely so that Bitcoin Core's use of libsecp256k1
is not checked with libsecp256k1; if the only thing that ever says the
Python arm is right is a comparison with libsecp256k1, the circle is
closed one level up rather than broken. So this file is the inventory
issue #993 asks for: per arm, which vectors of somebody else's making
reach it.

Two things make the inventory possible to keep true rather than to
believe. The arms are counted from the source -- a function containing a
call to `is_libsecp256k1_serving` is an arm, which is the same definition
issue #968 made by hand -- so one added without an entry here fails.

The arms of the curve arithmetic and of every scheme but `bms` are the
btclib_ecc package's, which keeps this inventory for its own (issue
#2282). What is here is btclib's: the script engine's two verifications,
taproot's tweaks, and BIP324's x-only ECDH.
And the entries were measured, not reasoned:

    uv run --locked --no-default-groups --group harness \
        pytest <one module> --cov=btclib --cov-report=json --cov-fail-under=0

in an environment with no bindings installed, reading back which lines of
each arm ran. A module is named here when its run reached the arm's body,
the `def` line excluded -- that line runs at import and would report
every arm of every imported module as reached.

**Nothing here re-runs the measurement.** The tests below check the
table's shape -- its keys against the parser, its empty entries against
the named set, its cited modules against the vector table, its entries
against that same table -- and none reruns the coverage that produced
`_AUTHORITY`'s values, because a pull request is not where that question
belongs: every module `_THIRD_PARTY_VECTORS` names, under coverage, in
an environment with no bindings, is minutes rather than seconds, and
nothing here asks a contributor's branch to pay for it.

That re-derivation runs weekly instead, is
`.github/workflows/py-arm-authority.yml`, calling
`.github/scripts/check_py_arm_authority.py` -- issue #1003's answer.
It repeats the measurement above, module by module, and fails loudly on
any of three disagreements: an entry claims a module that no longer
reaches the arm (stale, the harmful direction), a module reaches an arm
its entry does not name (the table understates, still worth knowing), or
something now reaches an arm in `_WITHOUT_AN_AUTHORITY` (the good news
this file is written to notice). A sentinel and not a gate: it has no
branch rule, so between one run and the next -- and on any pull request
that is not itself about this file, the script or the workflow -- the
table can go stale exactly as it could before, for up to a month rather
than forever.

**The attribution is per module, and a module may also hold tests btclib
wrote.** So an entry says "a module built on third-party vectors reaches
this arm", which is weaker than "this vector reaches this arm" and is what
the measurement supports. Sharpening it means selecting the vector-driven
tests within a module, which no marker in the tree expresses today.

One arm is reached by no such module at all, and what would change that
is known: `ecc.ellswift.xdh`, the x-only ECDH. BIP324's
`packet_encoding_test_vectors.csv` carries, per pair of encodings, the
shared x-coordinate and the shared secret, and no module here reads it
yet (issue #2307).
"""

from __future__ import annotations

import ast
from pathlib import Path

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"
_TESTS = Path(__file__).parent

# the vendored vectors each module below is built on, by the name they
# carry in `tests/_data` or a `_data` beside the module. What makes a
# source third-party is who wrote it: a BIP, Bitcoin Core, Project
# Wycheproof, an RFC -- and not btclib, which is why `vectors.json` and
# `btclib_test_vectors.json` appear nowhere here
_THIRD_PARTY_VECTORS: dict[str, tuple[str, ...]] = {
    "ecc/bms_test.py": ("signmessage.json",),
    "key_io_test.py": ("key_io_valid.json", "key_io_invalid.json"),
    "script/sig_hash_legacy_test.py": ("sig_hash_legacy_test_vectors.json",),
    "script/sig_hash_taproot_test.py": ("taproot_test_vector.json",),
    "script/taproot_test.py": ("script_assets_test.json",),
    "script_engine/script_test.py": ("script_tests.json",),
    "script_engine/transactions_test.py": ("tx_valid.json", "tx_invalid.json"),
}

# arm -> the modules of `_THIRD_PARTY_VECTORS` whose run reaches it. An
# empty tuple is an arm no third-party vector reaches, and the module
# docstring says what would
_AUTHORITY: dict[str, tuple[str, ...]] = {
    "ecc.ellswift.xdh": (),
    "script.engine.script.dsa_verify": (
        "script/sig_hash_legacy_test.py",
        "script_engine/script_test.py",
        "script_engine/transactions_test.py",
    ),
    "script.engine.tapscript.ssa_verify": (
        "script/sig_hash_taproot_test.py",
        "script_engine/script_test.py",
        "script_engine/transactions_test.py",
    ),
    "script.taproot._tweaked_prvkey": (
        "script/sig_hash_taproot_test.py",
        "script/taproot_test.py",
        "script_engine/script_test.py",
    ),
    "script.taproot._tweaked_pubkey": (
        "script/sig_hash_taproot_test.py",
        "script/taproot_test.py",
        "script_engine/script_test.py",
    ),
    "script.taproot.check_output_pubkey": (
        "script/sig_hash_taproot_test.py",
        "script/taproot_test.py",
        "script_engine/script_test.py",
        "script_engine/transactions_test.py",
    ),
}

# the ones the measurement found nothing for, named so that closing one
# is a line deleted here rather than a number nobody re-derives
_WITHOUT_AN_AUTHORITY = frozenset({"ecc.ellswift.xdh"})


def _arm_locations() -> dict[str, tuple[Path, int, int]]:
    """Return every Python arm, mapped to where its body runs.

    The definition issue #968 used, applied by the parser rather than by
    hand: a function whose source calls `is_libsecp256k1_serving` has two
    arms, and the one this file is about is the arm that call declines.

    Three things about how it counts, each of which errs loudly rather
    than quietly, which is the direction this file needs:

    - the match is textual, over the function's own source. A comment or
      a docstring writing the call spelling invents an arm, and a nested
      function is attributed to its enclosing function as well as to
      itself. Neither can hide a real arm.
    - `AsyncFunctionDef` is walked as well as `FunctionDef`. The tree has
      no async in it; one holding a dispatch would otherwise be invisible
      rather than reported, and invisible is the direction that costs.
    - the key is `module.funcname`, so two same-named methods of two
      classes in one module would collide into one entry and leave one
      arm unexamined.

    The range is the function's own body -- `node.body[0].lineno` through
    `node.end_lineno`, the `def` line itself excluded on purpose, since it
    runs at import regardless of whether the function is ever called and
    would otherwise report every arm of every imported module as reached.
    `.github/scripts/check_py_arm_authority.py` is what reads this
    range against a coverage run's `executed_lines` to re-derive
    `_AUTHORITY`; `_py_arms()` below reads only the keys.
    """
    found: dict[str, tuple[Path, int, int]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        module = ".".join(path.relative_to(_LIBRARY).with_suffix("").parts)
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if "is_libsecp256k1_serving(" in segment:
                assert node.end_lineno is not None  # set by ast.parse always
                found[f"{module}.{node.name}"] = (
                    path,
                    node.body[0].lineno,
                    node.end_lineno,
                )
    return found


def _py_arms() -> set[str]:
    """Return every function of btclib that holds a dispatch to the bindings.

    The keys of `_arm_locations()`, which is where the counting rule --
    and the collision it can hit -- is written down.
    """
    return set(_arm_locations())


def test_every_py_arm_is_in_the_inventory() -> None:
    """An arm added without an entry fails here, which is the point.

    The inventory is worth nothing if it can go quietly out of date: a
    dispatch added tomorrow would have an unexamined Python arm, and the
    claim this file makes -- that every arm has an authority other than
    the bindings, or is the one that does not -- would be about the tree
    of the day it was written.
    """
    listed = set(_AUTHORITY)
    found = _py_arms()
    assert listed == found, (
        f"not in the inventory: {sorted(found - listed)};"
        f" gone from the library: {sorted(listed - found)}"
    )


def test_the_arms_without_an_authority_are_the_ones_that_are_known() -> None:
    """Empty entries and the named set are one fact, stated twice."""
    empty = {arm for arm, sources in _AUTHORITY.items() if not sources}
    assert empty == _WITHOUT_AN_AUTHORITY, (
        f"newly without an authority: {sorted(empty - _WITHOUT_AN_AUTHORITY)};"
        f" no longer without one: {sorted(_WITHOUT_AN_AUTHORITY - empty)}"
    )


def test_every_named_module_is_in_the_tree_and_reads_its_vectors() -> None:
    """A module named here exists, and the vectors it is named for do too.

    Both halves, because either one going stale makes the inventory a
    claim about files rather than about tests: a module renamed leaves an
    entry pointing at nothing, and a vector file dropped leaves a module
    named as third-party that no longer is.
    """
    for module, vectors in _THIRD_PARTY_VECTORS.items():
        path = _TESTS / module
        assert path.is_file(), f"{module} is named in the inventory and is not here"
        source = path.read_text(encoding="utf-8")
        for vector in vectors:
            assert vector in source, f"{module} no longer names {vector}"


def test_every_authority_names_a_module_of_the_table() -> None:
    """No entry may cite a module whose vectors are not written down."""
    for arm, sources in _AUTHORITY.items():
        for module in sources:
            assert module in _THIRD_PARTY_VECTORS, (
                f"{arm} cites {module}, which no line of _THIRD_PARTY_VECTORS covers"
            )
