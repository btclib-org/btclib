# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `btclib` package.

Every module must be importable *first*, with no other btclib module in
sys.modules yet. Nothing else in the suite establishes that: a test
module reaches its subject through whatever the modules imported before
it have already pulled in, so a cycle that only bites the caller who
happens to arrive from the other side stays invisible.

The cycle this guards against is real: issue #147 found b58 ->
btclib.script -> script.script_pub_key -> b58, surviving only because
script_pub_key imported the modules rather than their names, so that the
partially initialized b58 was never asked for an attribute at import
time -- with nothing in that file to say so.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

import btclib
from tests import module_names


def btclib_modules() -> list[str]:
    """Return the btclib modules in sys.modules, the bindings excluded."""
    # not startswith("btclib"), which would also catch btclib_ecc and the
    # btclib_secp256k1 bindings: neither is part of this package, and
    # reimporting a cffi extension module is another matter entirely
    return [
        name for name in sys.modules if name == "btclib" or name.startswith("btclib.")
    ]


@pytest.fixture
def unimported_btclib() -> Iterator[None]:
    """Hide every btclib module from sys.modules, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it is what issue #147 used to demonstrate the
    failure, but as a test it costs an interpreter start-up per module,
    and buys nothing: the import machinery decides what to execute by
    consulting sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in btclib_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in btclib_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported_btclib: None) -> None:
    """Import each module first, with no other btclib module loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def test_exceptions_imports_nothing_of_btclibs_and_no_client(
    unimported_btclib: None,
) -> None:
    """btclib.exceptions declares its own classes and reaches nothing.

    It used to import the rpc client, which was in-tree then and defined
    the six classes this module now declares. That put `urllib.request`,
    and `ssl` and `socket` under it, behind every import reaching here --
    which is most of the library, an exception being what most of it
    raises. Since the client became a package of its own, the classes are
    btclib's again and `btclib_wallet.fetch.fetcher.client_errors` translates at
    the one boundary that needs it.

    So the cost pinned here is nothing at all: no btclib module beyond
    this one, and no socket machinery. `sys.modules` is what says so,
    rather than a timing.
    """
    importlib.import_module("btclib.exceptions")
    assert set(btclib_modules()) == {"btclib", "btclib.exceptions"}

    # a subprocess for the half `unimported_btclib` cannot arrange: that
    # fixture takes btclib out of `sys.modules` and leaves every other
    # package where it is, so a `bitcoin_core_rpc` some earlier test
    # imported is still there and asserting its absence in this
    # interpreter would fail for a reason that is not the one under test.
    # A fresh interpreter has neither, and importing this module is the
    # whole of what runs in it
    probe = "import btclib.exceptions, sys; print(sorted(sys.modules))"
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    assert "'bitcoin_core_rpc'" not in loaded
    assert "'urllib.request'" not in loaded


def test_consensus_imports_nothing_of_btclibs(unimported_btclib: None) -> None:
    """btclib.consensus declares its constants and reaches nothing.

    The per-network table lives there rather than beside `Network`
    because of this: `btclib.block`, `btclib.tx` and `btclib.script` all
    read something of it, `btclib.network` reads it to give each network
    its `consensus` row, and an import in the other direction would be
    the cycle of issue #147 -- `btclib.script.engine` imports
    `btclib.script.witness`, which imports this module.

    The second half is what makes `ConsensusParams.script_flags_at`
    possible at all. It answers a `ScriptFlag`, whose enum is inside that
    cycle, so it imports the engine when it is called rather than when
    this module is: importing costs nothing, and asking for the flags is
    what brings the engine in.
    """
    consensus = importlib.import_module("btclib.consensus")
    assert set(btclib_modules()) == {"btclib", "btclib.consensus"}

    consensus.CONSENSUS_PARAMS["mainnet"].script_flags_at(0)
    assert "btclib.script.engine.flags" in btclib_modules()


def test_the_codec_does_not_pay_for_the_rpc_package() -> None:
    """`btclib.p2p` publishes the message start without importing it.

    The package's whole claim is that it opens no socket, and the module
    holding the message start reaches `bitcoin_core_rpc` -- but only its
    `chains` module, which depends on nothing beyond the standard
    library; `urllib.request`, and `ssl` and `socket` under it, live in
    `client.py` and `transport.py`, which a message-start lookup never
    reaches. ARCHITECTURE.md states the property this keeps: "no module
    loads `urllib.request` on its way to anything else".

    So `src/btclib/p2p/__init__.py` answers the three names through PEP 562,
    as `src/btclib/script/__init__.py` answers `sig_hash` and `engine`, and
    what is pinned here is both halves: importing the package costs
    nothing, and asking for a message start costs only
    `bitcoin_core_rpc` itself -- never `urllib.request`.

    `socket` is deliberately not asserted absent anywhere here.
    `src/btclib/__init__.py` reads the version with `importlib.metadata`,
    which imports `email.utils` on every interpreter before 3.13, and
    that module imports `socket` for `make_msgid` -- so `socket` is in
    `sys.modules` after importing anything of btclib's, says nothing
    about this package, and asserting its absence passes here and fails
    on most of the matrix. What re-measures it, on any interpreter:
    `UV_PROJECT_ENVIRONMENT=.venv-3.11 uv run --python 3.11 python -c
    "import btclib.p2p, sys; print('socket' in sys.modules)"`.

    A subprocess for the reason the test above gives: `unimported_btclib`
    takes btclib out of `sys.modules` and leaves `bitcoin_core_rpc` where
    an earlier test put it.

    What the package *does* import eagerly, and what a reader of the
    above would otherwise wonder about, is `ipaddress`: a `version` and an
    `addr` carry sixteen-octet addresses, and that module is what holds
    one. It is arithmetic and text -- it imports `functools` and nothing
    else -- where `socket.inet_pton`, which is the other way to write the
    same conversion, would put the C library's resolver behind a codec.
    """
    package_name = "'bitcoin_core_rpc'"
    transport_cost = "'urllib.request'"

    probe = "import btclib.p2p, sys; print(sorted(sys.modules))"
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    assert package_name not in loaded
    assert transport_cost not in loaded

    # and the other half, so that the first is a property of the codec
    # and not of a dependency that stopped importing what it imports --
    # the package is reached the moment a message start is asked for, and
    # `urllib.request` still is not: `chains.py` is the whole of what
    # that lookup runs
    probe = "import btclib.p2p as p; p.magic_from_chain; import sys; print(sorted(sys.modules))"
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    assert package_name in loaded
    assert transport_cost not in loaded


def test_electrum_codec_stays_stdlib_light() -> None:
    """`btclib.electrum` is the codec, and importing it opens nothing.

    `btclib_wallet.fetch.electrum` is the fetcher built on it, and that
    package's `__init__` imports every fetcher, `urllib`, `ssl` and
    `socket` behind them: an importer of this module alone -- node, should
    it ever serve the protocol rather than only speak it -- pays for none
    of that. `btclib.p2p`'s own docstring states the same rule for the
    same reason, and `_HEAVY_MODULES` below is the list both are held to.

    A subprocess and not `unimported_btclib`, for the reason the p2p test
    above gives.
    """
    loaded = _loaded_after_importing("btclib.electrum")
    assert not set(loaded) & set(_HEAVY_MODULES)


def test_the_tests_package_imports_no_btclib_submodule() -> None:
    """Importing the `tests` package alone must reach no `btclib` submodule.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported_btclib`
    included, so this probe is a subprocess rather than that fixture, the
    same way the two tests above are. Neither the suite's coverage floor
    nor the weekly no-bindings census reads what a test body goes on to
    call, only what the import itself reaches: a value built at
    `tests/__init__.py`'s own module scope by calling into `btclib`'s
    curve arithmetic showed up in the census as reached by a module that
    asks no question about a scalar multiplication (issue #2120).
    """
    probe = (
        "import sys, tests; "
        "print(sorted(m for m in sys.modules "
        "if m == 'btclib' or m.startswith('btclib.')))"
    )
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=Path(__file__).resolve().parents[1],
    ).stdout
    assert ast.literal_eval(loaded) == ["btclib"]


def test_address_encodings_stay_below_script(unimported_btclib: None) -> None:
    """b58 and b32 must not import btclib.script.

    script.script_pub_key imports both of them to render an address, so
    an import the other way is the cycle of issue #147 — and importing
    any script submodule is an import of btclib.script, whose __init__
    pulls script_pub_key in. p2sh-wrapped SegWit is the temptation: b58
    needs the [OP_0, witness program] redeem script, and spells it out
    instead of calling script.serialize.
    """
    importlib.import_module("btclib.b58")
    importlib.import_module("btclib.b32")
    assert not [name for name in btclib_modules() if name.startswith("btclib.script")]


def test_network_stays_below_block(unimported_btclib: None) -> None:
    """btclib.network must not import btclib.block.

    block.block already reaches btclib.network transitively, through
    btclib.tx's TxOut.script_pub_key importing script.script_pub_key for
    the address tables -- so a Network field holding a Block would close
    issue #147's cycle from the other side. ISS 1602's genesis_block is
    the temptation this guards: it lives in btclib.block.genesis, built
    on demand, rather than beside NETWORKS.
    """
    importlib.import_module("btclib.network")
    assert not [name for name in btclib_modules() if name.startswith("btclib.block")]


def test_script_publishes_sig_hash_and_the_engine_without_importing_them(
    unimported_btclib: None,
) -> None:
    """btclib.script names two submodules it must not import.

    Both reach the transaction stack -- `sig_hash` imports `btclib.tx`,
    whose `tx_in` and `tx_out` import `btclib.script` back, and
    `btclib.script.engine.script` asks this very package for `sig_hash` --
    so an import of either from `src/btclib/script/__init__.py` would run on a
    half-initialized package, which is issue #147 again. The `__getattr__`
    there is what publishes them instead, and this is the measurement:
    importing the package leaves both out of sys.modules, and asking for
    the attribute is what brings them in.
    """
    script = importlib.import_module("btclib.script")
    loaded = btclib_modules()
    assert not [name for name in loaded if name.startswith("btclib.tx")]
    assert not [name for name in loaded if name.startswith("btclib.script.engine")]
    assert "btclib.script.sig_hash" not in loaded
    # taproot is the third group and is imported, its four flat names being
    # re-exported: the asymmetry is in the package docstring
    assert "btclib.script.taproot" in loaded

    assert script.sig_hash.__name__ == "btclib.script.sig_hash"
    assert script.engine.__name__ == "btclib.script.engine"
    assert "btclib.tx" in btclib_modules()


# What heavier than the stdlib basics means for issue #2129's rule that a
# package below `btclib` is stdlib-light. Not `socket`: `btclib/__init__.py`
# reads `__version__` through `importlib.metadata`, which pulls in
# `email.utils` and, through it, `socket`, on every interpreter before
# 3.13 -- test_the_codec_does_not_pay_for_the_rpc_package above measures
# this and does not assert `socket`'s absence for the same reason, so a
# check here that did would be red on part of the matrix and green on the
# rest for a fact about the interpreter rather than about the module under
# check. None of these is pulled in by anything below btclib, on any
# interpreter of the matrix.
_HEAVY_MODULES = ("urllib.request", "ssl", "http.client", "bitcoin_core_rpc")


def _loaded_after_importing(module_name: str) -> list[str]:
    """Import one module in a fresh interpreter and return sorted(sys.modules).

    A fresh subprocess rather than `unimported_btclib`: that fixture only
    hides btclib's own modules from `sys.modules`, so a third-party package
    an earlier test already imported -- `bitcoin_core_rpc`, most
    concretely -- would still answer present, and the absence a lightness
    check exists to prove would mean nothing.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    return cast("list[str]", ast.literal_eval(stdout))


def _assert_stays_within(entry_point: str, allowed_btclib_modules: set[str]) -> None:
    """Assert one module's own closure, subset rather than equal.

    Subset because a new edge into the module is the defect this exists
    to catch, and a removed one is not: an equality assertion would fail
    on a removed edge exactly as loudly as on a regression.
    """
    loaded = _loaded_after_importing(entry_point)
    btclib_loaded = {m for m in loaded if m == "btclib" or m.startswith("btclib.")}
    assert btclib_loaded <= allowed_btclib_modules
    assert not set(loaded) & set(_HEAVY_MODULES)


def test_curves_stays_stdlib_light() -> None:
    """`btclib.curves` loads nothing of btclib's beyond its own modules.

    Its names are btclib_ecc's objects bound again (issue #2282), so
    what it costs a caller is that package's closure, which the heavy
    modules are asserted absent from as well.
    """
    _assert_stays_within(
        "btclib.curves",
        {
            "btclib",
            "btclib.curves",
            "btclib.curves.curve",
            "btclib.curves.curve_group",
            "btclib.curves.curve_group_2",
            "btclib.curves.curve_group_f",
            "btclib.curves.sec_point",
        },
    )


# the units `btclib.ecc` may load: itself, `curves`, and the substrate
# `ecc.ellswift.xdh` reads its octets with
_ECC_UNITS = frozenset({"curves", "ecc", "alias", "exceptions", "utils"})


def test_ecc_stays_stdlib_light() -> None:
    """`btclib.ecc` loads `curves`, the substrate and itself, nothing else.

    `ecc/__init__.py` imports every scheme but `bms` eagerly, so this is
    the whole of the package as a caller gets it, and `bms` is asserted
    absent from it.
    """
    loaded = _loaded_after_importing("btclib.ecc")
    # the package itself is loaded under any of its modules
    btclib_loaded = {m for m in loaded if _is_btclib(m) and m != "btclib"}
    assert "btclib.ecc.dsa" in btclib_loaded
    assert "btclib.ecc.bms" not in btclib_loaded
    assert sorted(m for m in btclib_loaded if m.split(".")[1] not in _ECC_UNITS) == []
    assert not set(loaded) & set(_HEAVY_MODULES)


def test_the_codecs_stay_stdlib_light() -> None:
    """`btclib.base58` and `btclib.bech32` stay in `btclib` under issue #2129.

    Codecs with no bitcoin in them (ARCHITECTURE.md), and not a
    package of their own: their consumers spread over rows 4 and 5 of
    that issue's table, so no single package is short of them. One
    allowlist for the pair, the two being held to the same reach. `base58`
    reaches `hashes` for its checksum, and `_ripemd160` and `var_int`
    arrive with it; `bech32` reaches nothing of btclib's beyond the
    substrate.
    """
    loaded = _loaded_after_importing("btclib.base58")
    loaded_both = set(loaded) | set(_loaded_after_importing("btclib.bech32"))
    btclib_loaded = {m for m in loaded_both if m == "btclib" or m.startswith("btclib.")}
    assert btclib_loaded <= {
        "btclib",
        "btclib.alias",
        "btclib.exceptions",
        "btclib.utils",
        "btclib.base58",
        "btclib.bech32",
        "btclib.hashes",
        "btclib._ripemd160",
        "btclib.var_int",
    }
    assert not loaded_both & set(_HEAVY_MODULES)


def test_hashes_stays_stdlib_light() -> None:
    """`btclib.hashes`, with `_ripemd160`, stays in `btclib` under issue #2129.

    Not a package of its own, for the reason `base58` and `bech32` are
    not. `tagged_hash` and `reduce_to_hlen` are btclib_ecc's, bound
    again here (issue #2282), and that package is one issue #2129's rule
    4 holds stdlib-light. `_hashlib_has_ripemd160` makes whether this
    interpreter's hashlib carries RIPEMD-160 a runtime question rather
    than an import; this checks that the module reaches nothing heavy
    rather than assumes it.
    """
    _assert_stays_within(
        "btclib.hashes",
        {
            "btclib",
            "btclib.alias",
            "btclib.exceptions",
            "btclib.utils",
            "btclib.hashes",
            "btclib._ripemd160",
            "btclib.var_int",
        },
    )


# Row 5 of issue #2129, `btclib-wallet`, in that table's order, with
# `mnemonic/`, which went with `bip85`: the units that left this package
# for `btclib_wallet`. That package imports btclib rather than being
# imported by it, so the check on it is not what it reaches but that
# nothing here reaches back -- under its old name or its new one.
_APPLICATION_SLAB = (
    "bip32",
    "bip44",
    "bip85",
    "slip132",
    "psbt",
    "descriptors",
    "silent_payments",
    "bip21",
    "bolt11",
    "bolt9",
    "bip38",
    "minikey",
    "bip322",
    "coin_selection",
    "tx_builder",
    "tx_or_psbt",
    "wallet",
    "hwi",
    "psbt_signer",
    "psbt_signer_contract",
    "core_import",
    "fetch",
    "mnemonic",
)

# the import package row 5 is published as
_WALLET_PACKAGE = "btclib_wallet"


def _is_btclib(name: str) -> bool:
    """Answer whether a dotted name is this package's, the bindings excluded.

    `name == "btclib" or name.startswith("btclib.")`, not a bare
    `startswith("btclib")`: `btclib_modules` above states the same
    boundary, for the same reason -- `btclib_secp256k1`, the bindings,
    matches the bare form and is not part of this package.
    """
    return name == "btclib" or name.startswith("btclib.")


def _is_btclib_or_wallet(name: str) -> bool:
    """Answer whether a dotted name is this package's or `btclib_wallet`'s."""
    return (
        _is_btclib(name)
        or name == _WALLET_PACKAGE
        or name.startswith(f"{_WALLET_PACKAGE}.")
    )


def _btclib_names_imported_by(path: Path) -> set[str]:
    """Return every dotted btclib or btclib_wallet name one file's imports name.

    `from btclib import wallet` and `from btclib.wallet import Wallet` name
    the same package two different ways; joining the `from` module with
    each of its aliases covers both, and `import btclib.wallet.foo` is
    already a complete dotted name on its own.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(
                alias.name for alias in node.names if _is_btclib_or_wallet(alias.name)
            )
        elif isinstance(node, ast.ImportFrom) and _is_btclib_or_wallet(
            node.module or ""
        ):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


def _slab_edges(
    imports_by_file: dict[str, set[str]], slab_roots: tuple[str, ...]
) -> dict[str, list[str]]:
    """Return, file by file, which of its btclib imports reach the slab.

    Separated from the scan below so that the branch a clean tree never
    takes -- a file's own imports actually naming something in the slab
    -- can be tripped on purpose, by a synthetic mapping, rather than left
    for the whole suite's 100% floor to fail on a defensive check nothing
    green ever crosses.
    """
    edges = {}
    for file, names in imports_by_file.items():
        reached = sorted(
            n for n in names if any(n == r or n.startswith(f"{r}.") for r in slab_roots)
        )
        if reached:
            edges[file] = reached
    return edges


def test_the_application_slab_check_finds_a_planted_edge() -> None:
    """`_slab_edges` reports a file that imports the slab.

    The real tree has no such file -- that is what the test below
    measures -- so this is the only green run that ever crosses the
    branch reporting one.
    """
    edges = _slab_edges(
        {"outside.py": {"btclib.wallet.wallet"}, "clean.py": {"btclib.alias"}},
        ("btclib.wallet",),
    )
    assert edges == {"outside.py": ["btclib.wallet.wallet"]}


def test_the_application_slab_scan_reads_both_names(tmp_path: Path) -> None:
    """`_btclib_names_imported_by` collects the slab under either name.

    The tree has no import of `btclib_wallet`, so without a planted file
    nothing would show that the scan below reads one at all: a collector
    keyed on `btclib` alone would answer the same empty set for a module
    importing the package above it.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import btclib_wallet.bip32\nfrom btclib_wallet import psbt\n"
        "from btclib_secp256k1 import dsa\n",
        encoding="utf-8",
    )
    assert _btclib_names_imported_by(planted) == {
        "btclib_wallet.bip32",
        "btclib_wallet",
        "btclib_wallet.psbt",
    }


def test_the_application_slab_has_no_inbound_edge() -> None:
    """Nothing here imports the slab: issue #2129's rule 2.

    Static rather than a subprocess probe: `import btclib` alone loads
    nothing (`btclib/__init__.py`'s own `__getattr__` is why), so no
    runtime measurement of a plain import can tell whether some other
    module of the tree reaches the slab -- only asking what every source
    file's own import statements name can. `root.rglob("*.py")` walks the
    installed package the same way `module_names` does, from
    `btclib.__path__`, so this checks the tree the suite runs against
    rather than a copy on disk that might be stale. Every file is scanned,
    for both spellings of the slab: `btclib.<unit>`, which no longer
    resolves, and `btclib_wallet`, which depends on this package and so
    cannot be depended on by it.

    The slab's units are asserted absent from the tree first. A unit that
    came back, as a copy or as a module re-exporting `btclib_wallet`'s, is
    what rule 3 refuses, and a scan that walked it would be reading the
    slab from inside rather than the protocol side.
    """
    root = Path(btclib.__path__[0])
    for name in _APPLICATION_SLAB:
        assert not (root / f"{name}.py").exists(), name
        assert not (root / name).exists(), name
    slab_roots = (
        _WALLET_PACKAGE,
        *(f"btclib.{name}" for name in _APPLICATION_SLAB),
    )
    imports_by_file = {
        str(path.relative_to(root)): _btclib_names_imported_by(path)
        for path in root.rglob("*.py")
    }
    assert _slab_edges(imports_by_file, slab_roots) == {}
