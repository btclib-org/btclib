# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for what the library exports.

`__all__` is a decision about the public surface, and it had drifted: it
carried a benchmark's worth of multiplication implementations in `btclib.curves`
while `btclib.ecc` advertised four helpers and none of the six signature
schemes behind them, and `btclib.mnemonic` neither of its two schemes.

Every module and package of the library declares one, at every depth, which
is the answer issue #338 asked for: a name is public here because a list
says so, not because it happens to lack a leading underscore. A list per
module is a list per module to keep true, and the policy tests below are
what keeps it, rather than a reviewer noticing.

`btclib.__all__` is the root of that tree, and one of those tests walks it
from the root, into every module-valued export, down to a node that has
none. The command line of `docs/proposals/cli.md` walks the same edges and
stops at a shorter list: what it publishes as a command group is this tree
minus the exclusions that proposal records. So this test descends
everywhere the export tree goes -- that tree is what it is about -- and
the assertion that the command tree does not belongs to the walker, where
the proposal asks for it.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules, walk_packages
from types import ModuleType

import bitcoin_core_rpc
import pytest

import btclib
import btclib.curves
import btclib.ecc
import btclib.mnemonic
import btclib.psbt
import btclib.script
from btclib import consensus
from btclib.curves import curve_group, curve_group_2
from btclib.psbt import psbt_utils
from btclib.script import script_pub_key

# what a module defines without a leading underscore and deliberately does
# not export, with the reason beside the list in each module's docstring.
# A name added here is a decision; a name that has to be added here to make
# the suite pass is one that was about to become public by accident
UNEXPORTED = {
    "btclib": ["name"],
    "btclib.curves.curve": ["datadir"],
    "btclib.descriptors.descriptors": [
        "CHECKSUM_CHARSET",
        "GENERATOR",
        "INPUT_CHARSET",
    ],
    "btclib.network": ["datadir"],
}

# what a module exports without defining it, which for a module rather than a
# package is a leak -- and REEXPORTED below is the exception, one entry per
# re-exporting module, grouped here by the decision each belongs to rather
# than counted: a module recorded there is not leaking, it is aliasing the
# canonical object under the name a caller already had.
#
# The `bitcoin-core-rpc` package is the canonical source of the rpc client
# and of the transport under it, and btclib depends on it rather than
# carrying a copy. Some of the modules below aliasing it held those objects
# themselves before it became a package of its own; others were written
# afterwards, aliasing it from the start rather than ever declaring a second
# copy. Either way, each states its own reasoning in its own docstring -- a
# transport has one bounded-read policy, and an import path published here
# stays valid.
#
# `btclib.consensus` is the second decision: a transaction's counts and a
# witness stack's are arithmetic on the block weight, and neither `btclib.tx`
# nor `btclib.script` can import `btclib.block`, so the two constants they
# divide by are defined below all three. `btclib.block.limits` names them
# still, being where the rest of Core's header is and where a caller reading
# a block's own rules goes.
#
# `btclib.psbt.psbt_utils` is the third: the two psbt versions decide what
# an input and an output map write and read, and neither `psbt_in` nor
# `psbt_out` can import `psbt`, so the pair is defined below all three.
# `btclib.psbt.psbt` names them still, being where the rest of the format's
# constants are.
#
# So a name here is not a name about to leak: it is the same object under
# the name a caller already had, which each entry records its canonical
# module for and the test below asserts. What would be a leak is a module
# not listed here, or a listed module exporting a name its recorded
# canonical module does not
REEXPORTED = {
    "btclib.fetch.bitcoin_core": (
        bitcoin_core_rpc,
        [
            "COOKIE_USER",
            "DEFAULT_DATADIR",
            "BitcoinCoreRpcClient",
            "chain_from_network",
            "cookie_auth",
        ],
    ),
    "btclib.fetch.transport": (
        bitcoin_core_rpc,
        [
            "DEFAULT_MAX_BODY_SIZE",
            "DEFAULT_TIMEOUT",
            "MAX_ERROR_BODY_SIZE",
            "HttpTransport",
            "SessionTransport",
            "http_request",
            "urlopen_transport",
        ],
    ),
    "btclib.p2p.magic": (
        bitcoin_core_rpc,
        ["magic_from_chain", "magic_from_signet_challenge"],
    ),
    "btclib.block.limits": (
        consensus,
        ["MAX_BLOCK_WEIGHT", "WITNESS_SCALE_FACTOR"],
    ),
    "btclib.psbt.psbt": (
        psbt_utils,
        ["PSBT_V0", "PSBT_V2"],
    ),
}

# every direct child module of every package, on the side of the decision
# its parent made about it: `groups` is what the parent publishes, which is
# what docs/proposals/cli.md's command tree descends into, and `unpublished`
# is what it deliberately does not -- a module holding names the parent
# re-exports flat, or an implementation nothing outside the package calls.
#
# The two together are asserted to be the package's whole directory, which
# is the half a table of the published edges alone cannot check: a child
# module added and left out of its parent's `__all__` changes neither the
# list nor the edges, and that is the missing edge which had `btclib.script`
# publishing none of the three subgroups its own tables promise. Both sides
# are recorded, so a module added to a package fails the suite until
# somebody says which of the two it is.
#
# btclib itself is not here: its children are the top-level modules, and
# test_the_root_publishes_every_top_level_module asserts the same partition
# against the directory with nothing on the unpublished side
CHILD_MODULES = {
    "btclib.bip32": {
        "groups": [],
        "unpublished": ["bip32", "der_path", "key_origin"],
    },
    "btclib.block": {
        "groups": ["build", "merkle_proof", "mining", "proof_of_work"],
        "unpublished": [
            "block",
            "block_context",
            "block_filter",
            "block_header",
            "genesis",
            "header_context",
            "limits",
        ],
    },
    "btclib.curves": {
        "groups": [],
        "unpublished": [
            "curve",
            "curve_group",
            "curve_group_2",
            "curve_group_f",
            "sec_point",
        ],
    },
    "btclib.descriptors": {
        "groups": ["miniscript"],
        "unpublished": ["descriptors", "key_expression"],
    },
    "btclib.ecc": {
        "groups": [
            "bip340_nonce",
            "bms",
            "borromean",
            "commit_nonce",
            "dh",
            "dleq",
            "dsa",
            "ecies",
            "ellswift",
            "musig2",
            "pedersen",
            "rfc6979_nonce",
            "ssa",
        ],
        "unpublished": [],
    },
    "btclib.fetch": {
        "groups": [],
        "unpublished": [
            "bitcoin_core",
            "decorators",
            "esplora",
            "fetcher",
            "transport",
        ],
    },
    "btclib.mnemonic": {
        "groups": [
            "bip39",
            "dispatch",
            "electrum",
            "entropy",
            "mnemonic",
            "slip39",
        ],
        "unpublished": [],
    },
    "btclib.p2p": {
        "groups": [],
        "unpublished": [
            "address",
            "addrv2",
            "block_filters",
            "compact_blocks",
            "data",
            "handshake",
            "inventory",
            "keepalive",
            "limits",
            "magic",
            "message",
            "negotiation",
            "payload",
            "reject",
        ],
    },
    "btclib.psbt": {
        "groups": ["musig2", "silent_payments"],
        "unpublished": [
            "psbt",
            "psbt_in",
            "psbt_out",
            "psbt_size",
            "psbt_utils",
            "psbt_view",
        ],
    },
    "btclib.script": {
        "groups": ["engine", "sig_hash", "taproot"],
        "unpublished": [
            "limits",
            "op_codes_tapscript",
            "script",
            "script_pub_key",
            "sig_ops",
            "witness",
        ],
    },
    "btclib.script.engine": {
        "groups": [],
        "unpublished": ["flags", "script", "script_op_codes", "tapscript"],
    },
    "btclib.tx": {
        "groups": [],
        "unpublished": [
            "coin",
            "limits",
            "out_point",
            "tx",
            "tx_context",
            "tx_in",
            "tx_out",
        ],
    },
    "btclib.wallet": {
        "groups": [],
        "unpublished": [
            "descriptor_wallet",
            "key_wallet",
            "script_wallet",
            "wallet",
        ],
    },
}


def public_name(dotted: str) -> bool:
    """Whether every component of a dotted module name is public."""
    return not any(part.startswith("_") for part in dotted.split("."))


def library_modules() -> list[ModuleType]:
    """Return every module and package of the library, private ones out.

    Found rather than listed: one added to btclib is one these tests ask
    about, and the walk is the whole tree rather than the top level, the
    packages having submodules a caller reaches by name --
    `btclib.ecc.dsa`, `btclib.script.sig_hash` -- and a command line
    reaching them through `__all__` alone.

    `btclib._ripemd160` is out, and so is anything under a private name: a
    module whose name opens with an underscore is not part of the surface,
    so what is public *in* it is not reachable by any spelling a caller is
    offered.
    """
    return [
        btclib,
        *(
            import_module(name)
            for _, name, _ in walk_packages(btclib.__path__, "btclib.")
            if public_name(name)
        ),
    ]


def module_scope(body: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield the statements a module executes in its own namespace.

    Every statement of the body, and then inside each compound one, which
    runs at module scope too: an import in a module-level `try`, `if`,
    `with`, `for`, `while` or `match` binds a global exactly as a
    top-level one does, and `try: from dependency import PublicType` is
    how an optional import is written. A function or a class opens a scope
    of its own, so an import in either binds nothing here, and neither is
    descended into.
    """
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(node, field, None)
            if isinstance(statements, list):
                nested += statements
        for clause in (*getattr(node, "handlers", ()), *getattr(node, "cases", ())):
            nested += clause.body
        yield from module_scope(nested)


def imported_names_in(source: str) -> set[str]:
    """Return the names the import statements of one module source bind."""
    return {
        alias.asname or alias.name.split(".")[0]
        for node in module_scope(ast.parse(source).body)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }


def imported_names(module: ModuleType) -> set[str]:
    """Return the names a module's own import statements bind.

    Read off the source rather than the module object, there being nothing
    in a module's namespace to say how a name got there.
    """
    return imported_names_in(Path(str(module.__file__)).read_text(encoding="utf-8"))


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
    is exactly what a caller choosing _mult_jac_var from the same namespace --
    on the strength of its name -- gives up.
    """
    assert sorted(btclib.curves.__all__) == [
        "CURVES",
        "Curve",
        "CurveGroup",
        "PreparedPoint",
        "bytes_from_point",
        "bytes_from_prv_key_int",
        "double_mult_var",
        "find_all_points",
        "find_subgroup_points",
        "is_libsecp256k1_serving",
        "mult",
        "multi_mult_var",
        "point_from_octets",
        "scalar_from_prv_key",
        "secp256k1",
        "set_libsecp256k1_serving",
    ]

    # the implementations are still there, in the module that defines them
    variants = [
        (curve_group, "_mult_aff_var"),
        (curve_group, "_mult_base_3_var"),
        (curve_group, "_mult_fixed_window_var"),
        (curve_group, "_mult_fixed_window_cached_var"),
        (curve_group, "_mult_jac_var"),
        (curve_group, "_mult_mont_ladder_var"),
        (curve_group, "_mult_recursive_aff_var"),
        (curve_group, "_mult_recursive_jac_var"),
        (curve_group, "_cached_multiples"),
        (curve_group, "_jac_from_aff"),
        (curve_group, "_multiples"),
        (curve_group_2, "_double_mult_endomorphism_secp256k1_var"),
        (curve_group_2, "_mult_endomorphism_secp256k1"),
        (curve_group_2, "_mult_endomorphism_secp256k1_var"),
        (curve_group_2, "_mult_sliding_window_var"),
        (curve_group_2, "_mult_w_NAF_var"),
    ]
    for module, name in variants:
        assert hasattr(module, name), f"{module.__name__}.{name} went missing"
        assert name not in btclib.curves.__all__


def test_ecc_exports_the_signature_schemes() -> None:
    """Guards against dsa, ssa and bms dropping out of the export list."""
    assert sorted(btclib.ecc.__all__) == [
        "bip340_nonce",
        "bms",
        "borromean",
        "commit_nonce",
        "dh",
        "diffie_hellman",
        "dleq",
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
        "dleq",
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


def test_script_publishes_the_three_subgroups_the_cli_promises() -> None:
    """`sig_hash`, `taproot` and `engine` are groups, so they are named.

    The transitive walk cannot ask this: it follows the edges that are
    there, so a group `docs/proposals/cli.md` promises and no list
    publishes is a walk that stops early and a test that passes. That file
    spells `script sig-hash`, `script taproot` and `script engine`, and
    these are the three edges `btclib.script` carries for them -- listed
    here rather than derived from the proposal, prose being no place to
    read a contract from, and pinned because the two that are imported on
    demand are the two a refactor can drop without anything else noticing.
    """
    for group in ("engine", "sig_hash", "taproot"):
        assert group in btclib.script.__all__, f"script does not publish {group}"
        assert getattr(btclib.script, group).__name__ == f"btclib.script.{group}"

    # that these three are the only ones is CHILD_MODULES' assertion, for
    # this package as for every other. What is left here is the behaviour
    # of the two the package does not import: reachable by name, offered to
    # a prompt, and no answer for anything else
    assert set(btclib.script.__all__) <= set(dir(btclib.script))
    with pytest.raises(AttributeError, match="has no attribute 'sig_hashes'"):
        _ = btclib.script.sig_hashes


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
        "InputSolver",
        "KeyManager",
        "Psbt",
        "PsbtIn",
        "PsbtOut",
        "PsbtView",
        "SolutionSizer",
        "assert_signatures_only",
        "assert_signed",
        "combine",
        "ecdsa_sig_hash",
        "estimated_input_sizes",
        "extract_tx",
        "finalize",
        "join",
        "musig2",
        "new_signers",
        "prevouts",
        "sign",
        "silent_payments",
        "taproot_sig_hash",
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

    Every module and package of the library, found rather than listed: one
    added to btclib is one this checks, where a list here would be one more
    thing to keep true, and a module missing `__all__` is what this catches
    that a fixed list cannot. The whole tree is walked, which imports every
    module of the library; tests/imports_test.py does that deliberately
    and one module at a time, for the cycle a bulk import hides, and this
    one asks a question that needs them all loaded.

    An empty list is a legitimate answer, and the assertion says when: a
    module with nothing public of its own -- a package `__init__` that only
    re-exports, or a module that is all private helpers -- declares `[]`
    rather than nothing, so that the declaration is there to read.
    """
    modules = library_modules()
    assert len(modules) > 40, f"only {len(modules)} modules found under btclib"
    for module in modules:
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        assert names or not defined_public_names(module), (
            f"{module.__name__} declares an empty __all__ and defines"
            f" {sorted(defined_public_names(module))}"
        )
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

    `REEXPORTED` is that conversation, grouped by decision rather than by
    module: every module aliasing an object the `bitcoin-core-rpc` package
    canonically holds keeps the name a caller already had, a transport
    having one bounded-read policy to keep; `btclib.block.limits` names the
    two constants `btclib.consensus` defines below the package, which is
    where a caller reading a block's rules looks for them; and
    `btclib.psbt.psbt` names the two psbt versions that `psbt_utils` defines
    below the maps taking one as an argument.

    Asserted both ways, because a skip list is only half a table: it says
    which names may be re-exported and nothing about whether they still are,
    so dropping one of these aliases from an `__all__` would have been
    invisible to every test in this file. The recorded names and the
    re-exported ones must be the same set, and each must be the canonical
    object of the module the entry records rather than a same-named one --
    which is the property the whole arrangement exists for.
    """
    for module in library_modules():
        if hasattr(module, "__path__"):  # a package re-exports for a living
            continue
        imported = imported_names(module)
        leaked = {name for name in module.__all__ if name in imported}
        recorded = REEXPORTED.get(module.__name__)
        if recorded is None:
            assert not leaked, f"{module.__name__} re-exports {sorted(leaked)}"
            continue
        canonical, allowed = recorded
        assert leaked == set(allowed), (
            f"{module.__name__} re-exports {sorted(leaked)}, where REEXPORTED"
            f" records {sorted(allowed)}"
        )
        for name in allowed:
            assert getattr(module, name) is getattr(canonical, name), (
                f"{module.__name__}.{name} is not the canonical"
                f" {canonical.__name__}.{name}"
            )


def test_the_export_tree_is_walkable_to_its_leaves() -> None:
    """Every module reachable through `__all__` declares one of its own.

    `docs/proposals/cli.md` reads its command tree off these same edges: a
    group is a module-valued export, its commands are that module's own list,
    and an out-of-repo walker sees nothing this library does not publish. So a
    module named in a parent's list and declaring nothing is a node the
    walk arrives at and cannot descend from -- which is what this asks
    about, transitively from `btclib` down, following exports rather than
    the file tree.

    Every published module is walked here, including the ones that proposal
    excludes from the *command* tree: what is asserted is that the export
    tree has a declared surface everywhere, which is true of a module whose
    exports no command line should offer as well as of every other.

    A module-valued export is also checked to be a submodule of the module
    exporting it: `btclib.ecc.dsa` is `btclib.ecc`'s to publish, and a
    module from somewhere else in the tree would make the path a caller
    reads off the walk -- `btclib ecc dsa sign` -- name something the
    import does not.
    """
    seen = {btclib.__name__}
    frontier = [btclib]
    while frontier:
        module = frontier.pop()
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        for name in names:
            value = getattr(module, name)
            if not isinstance(value, ModuleType):
                continue
            assert value.__name__ == f"{module.__name__}.{name}", (
                f"{module.__name__} exports {name}, which is {value.__name__}"
            )
            # the set is the frontier's filter rather than a check on the
            # way out: one module reachable from two parents would be
            # walked twice, and nothing here is -- which is what the
            # `no branch` says, the tree being one and the filter being
            # what would keep a future re-export from doubling the walk
            if value.__name__ not in seen:  # pragma: no branch
                seen.add(value.__name__)
                frontier.append(value)
    # the root, the nine packages, the nested one, and the modules they
    # publish: a walk that stopped at the root would satisfy the loop above
    assert len(seen) > 30, f"the export tree walk reached {len(seen)} modules"


def test_every_child_module_is_a_group_or_deliberately_not() -> None:
    """Each package's children are partitioned, and the parts are recorded.

    Two directions, and the second is the one nothing else here can see.
    The published side is the exact module-valued exports, so a submodule
    imported into an `__init__` for one name and left in `__all__` by habit
    is a command group nobody decided on. The union of the two sides is the
    package's whole directory, so a child module added and left out of the
    list -- which changes neither the list nor the edges, and is how
    `btclib.script` came to publish none of the three subgroups its own
    tables promise -- fails until somebody writes down which side it is on.

    The empty published sides are as deliberate as the rest: `curves`,
    `tx`, `bip32`, `fetch` and `script.engine` offer a flat surface and no
    group. Every package has to be in the table, so a new one is a decision
    rather than a silent pair of empty lists.
    """
    packages = [module for module in library_modules() if hasattr(module, "__path__")]
    assert len(packages) == len(CHILD_MODULES) + 1, (
        "btclib itself plus every package CHILD_MODULES records"
    )
    for package in packages:
        if package.__name__ == "btclib":  # the directory is its assertion
            continue
        assert package.__name__ in CHILD_MODULES, f"{package.__name__} is not recorded"
        recorded = CHILD_MODULES[package.__name__]
        edges = sorted(
            name
            for name in package.__all__
            if isinstance(getattr(package, name), ModuleType)
        )
        assert edges == recorded["groups"], f"{package.__name__} publishes {edges}"
        children = sorted(
            child
            for _, child, _ in iter_modules(package.__path__)
            if public_name(child)
        )
        assert sorted([*recorded["groups"], *recorded["unpublished"]]) == children, (
            f"{package.__name__}'s children are {children}"
        )


def test_the_root_publishes_every_top_level_module() -> None:
    """`btclib.__all__` is the tree's root, so nothing top-level is missing.

    The list is written out rather than discovered -- a declaration is a
    list somebody edited -- and this is the other half of that: a module
    added to `src/btclib/` and not published here would be a group the command
    line cannot reach and a name `getattr(btclib, ...)` cannot answer,
    where a discovered list would have published it without anybody
    deciding to.
    """
    top_level = sorted(
        name for _, name, _ in iter_modules(btclib.__path__) if public_name(name)
    )
    assert sorted(btclib.__all__) == top_level
    # and each answers on a package that imported none of them, which is
    # what the module __getattr__ is for
    for name in top_level:
        assert getattr(btclib, name).__name__ == f"btclib.{name}"


def test_the_root_answers_only_for_what_it_publishes() -> None:
    """A name outside the list raises, as an attribute of anything does.

    `btclib._ripemd160` is not asserted absent, and could not be: the
    import machinery sets a submodule as an attribute of its package, so
    `btclib.hashes` importing it puts the name there. What the list decides
    is what this package imports *for* a caller, and `import
    btclib._ripemd160` is the caller's own business.
    """
    with pytest.raises(AttributeError, match="has no attribute 'b59'"):
        _ = btclib.b59
    # dir() answers the published tree, not only what has been imported
    assert set(btclib.__all__) <= set(dir(btclib))


def test_the_import_scan_reaches_a_nested_import() -> None:
    """A module-level `try` binds a global, and a function body does not.

    The check above is only as good as this scan: an optional dependency
    imported in a `try` and named in `__all__` is exactly the re-export it
    refuses, and reading `tree.body` alone would have let it through.
    """
    source = (
        "try:\n"
        "    from dependency import PublicType\n"
        "except ImportError:\n"
        "    from fallback import PublicType\n"
        "if TYPE_CHECKING:\n"
        "    from typing import Never\n"
        "for _name in ():\n"
        "    import late\n"
        "def f():\n"
        "    import local\n"
        "class C:\n"
        "    import attribute\n"
    )
    assert imported_names_in(source) == {"PublicType", "Never", "late"}


def test_nothing_becomes_public_by_accident() -> None:
    """Every public name is exported or recorded as kept out.

    This is the check the underscore convention cannot make: a helper that
    grows into a name callers depend on does so silently, where a package
    takes an edit to a list. `UNEXPORTED` is that edit for modules, and
    `sorted` is what the failure reads as -- the names not accounted for,
    against the ones that are.
    """
    for module in library_modules():
        kept_out = sorted(defined_public_names(module) - set(module.__all__))
        assert kept_out == UNEXPORTED.get(module.__name__, []), (
            f"{module.__name__} defines public names that are neither"
            f" exported nor recorded in UNEXPORTED: {kept_out}"
        )
