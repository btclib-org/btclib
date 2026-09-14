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
    # not startswith("btclib"), which would also catch the
    # btclib_secp256k1 bindings: they are not part of this package, and
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
    btclib's again and `btclib.fetch.fetcher.client_errors` translates at
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
    reaches. README.md states the property this keeps: "No module loads
    `urllib.request` on its way to anything else".

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


def test_electrum_codec_does_not_import_fetch() -> None:
    """`btclib.electrum` is the codec `btclib.fetch.electrum` is built on.

    Not the reverse: `btclib.fetch.__init__` imports every fetcher, so an
    importer of this module alone -- node, should it ever serve the
    protocol rather than only speak it -- does not pay for `urllib`,
    `ssl` and `socket` through that package. `btclib.p2p`'s own docstring
    states the same rule for the same reason.

    A subprocess and not `unimported_btclib`: that fixture takes btclib
    out of `sys.modules` and leaves `bitcoin_core_rpc` wherever an
    earlier test in this process put it, so `btclib.fetch`'s absence
    needs a fresh interpreter to mean anything -- the same reason the
    p2p test above uses one.
    """
    probe = "import btclib.electrum, sys; print(sorted(sys.modules))"
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    assert "btclib.fetch" not in loaded


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


def test_b58_stays_below_bip32(unimported_btclib: None) -> None:
    """b58 and b32 must not import btclib.bip32.

    A WIF is Base58Check with a prefix and a flag, and `b58` parses and
    writes the whole of it; an extended key is BIP32's own format, so
    reading one is `bip32`'s job, not `b58`'s (CLAUDE.md's *Architecture*,
    issue #1188). `tests/b58_test.py` imports `btclib.bip32` at module
    scope for a refusal test of its own, so the fixture is what keeps
    that import from making this assertion pass for the wrong reason.
    """
    importlib.import_module("btclib.b58")
    importlib.import_module("btclib.b32")
    assert "btclib.bip32" not in btclib_modules()


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


# What issue #1192 means by heavier than the stdlib basics. Not `socket`:
# `btclib/__init__.py` reads `__version__` through `importlib.metadata`,
# which pulls in `email.utils` and, through it, `socket`, on every
# interpreter before 3.13 -- test_the_codec_does_not_pay_for_the_rpc_package
# above measures this and does not assert `socket`'s absence for the same
# reason, so a candidate check that did would be red on part of the matrix
# and green on the rest for a fact about the interpreter rather than about
# the candidate. These four are never pulled in by anything below btclib,
# on any interpreter of the matrix.
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
    """Assert one candidate's own closure, subset rather than equal.

    Subset because a new edge into the candidate is the defect this test
    exists to catch, and a removed one is not: the elliptic-curve
    candidate's own reach is explicitly expected to shrink as issue #1188
    lands, and an equality assertion would fail on that shrinking exactly
    as loudly as on a real regression, which is not what "a check that
    belongs in the cut" should cost the next branch that removes an edge.
    """
    loaded = _loaded_after_importing(entry_point)
    btclib_loaded = {m for m in loaded if m == "btclib" or m.startswith("btclib.")}
    assert btclib_loaded <= allowed_btclib_modules
    assert not set(loaded) & set(_HEAVY_MODULES)


def test_curves_stays_stdlib_light() -> None:
    """`btclib.curves` is issue #1185's candidate, minus `ecc`.

    `ecc` is left out of this check rather than pinned as "less bms": its
    own `__init__` imports `bms` eagerly beside every other scheme, so
    asking for any one scheme today reaches `bms` and, through it, `b32`,
    `b58`, `key` and `network` regardless of which scheme was asked for --
    there is no way to import "ecc, less bms" as the tree stands, and
    pinning the amalgam would assert a shape issue #1185 proposes to
    undo rather than one the tree has. `curves` alone has no such wrinkle:
    it is the package's own arithmetic, and its docstring already states
    "Nothing here knows what a signature is."
    """
    _assert_stays_within(
        "btclib.curves",
        {
            "btclib",
            "btclib.alias",
            "btclib.exceptions",
            "btclib.utils",
            "btclib.number_theory",
            "btclib._libsecp256k1",
            "btclib.curves",
            "btclib.curves.curve",
            "btclib.curves.curve_group",
            "btclib.curves.curve_group_2",
            "btclib.curves.curve_group_f",
            "btclib.curves.sec_point",
        },
    )


def test_the_codec_candidate_stays_stdlib_light() -> None:
    """`btclib.base58` and `btclib.bech32` are issue #1186's one candidate.

    One package for both, per that issue's own "one, not two" decision, so
    this imports both rather than each alone. `base58` reaches `hashes`
    for its checksum -- the one edge that would need answering before the
    pair could depend on something other than btclib, which is issue
    #1191's question and not this one's.
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
    """`btclib.hashes`, with `_ripemd160`, is issue #1191's candidate.

    Its own case for being a package rather than plumbing is that it is a
    vocabulary -- `hash160`, `hash256`, `siphash`, the merkle helpers --
    and that `_hashlib_has_ripemd160` makes whether this interpreter's
    hashlib still carries RIPEMD-160 a runtime-profile question. Neither
    of those is a stdlib-heavy import, which is what this checks rather
    than assumes.
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


def test_mnemonic_stays_stdlib_light() -> None:
    """`btclib.mnemonic` is issue #1183's candidate: BIP39, SLIP39, Electrum.

    Three functions that build an extended private key --
    `bip39.mxprv_from_mnemonic`, `slip39.mxprv_from_mnemonics` and
    `electrum.mxprv_from_mnemonic`, which refuses the pre-2.0 scheme
    outright -- are why this reaches `bip32` and `network` rather than
    stopping at the seed the way BIP39 and SLIP39 themselves do. A
    fourth, `electrum.old_master_pub_key_from_mnemonic`, answers that
    pre-2.0 scheme with a plain public-key point instead of an extended
    key, which is why it reaches `curves` and neither of the other two.
    Issue #1183 keeps all four in btclib and moves the rest. What this
    checks is that the reach, wherever it stops, never leaves
    stdlib-light territory on the way.
    """
    _assert_stays_within(
        "btclib.mnemonic",
        {
            "btclib",
            "btclib.alias",
            "btclib.exceptions",
            "btclib.utils",
            "btclib.mnemonic",
            "btclib.mnemonic.bip39",
            "btclib.mnemonic.dispatch",
            "btclib.mnemonic.electrum",
            "btclib.mnemonic.entropy",
            "btclib.mnemonic.mnemonic",
            "btclib.mnemonic.slip39",
            "btclib.bip32",
            "btclib.bip32.bip32",
            "btclib.bip32.der_path",
            "btclib.bip32.key_origin",
            "btclib.base58",
            "btclib.hashes",
            "btclib._ripemd160",
            "btclib.var_int",
            "btclib.curves",
            "btclib.curves.curve",
            "btclib.curves.curve_group",
            "btclib.curves.curve_group_2",
            "btclib.curves.curve_group_f",
            "btclib.curves.sec_point",
            "btclib.number_theory",
            "btclib._libsecp256k1",
            "btclib.network",
            "btclib.consensus",
        },
    )


# issue #1184's candidate: the modules nothing in btclib imports. It points
# the other way from the four above -- it would import btclib, not be
# imported by it -- so its own check is the opposite shape: not what it
# reaches, but that nothing below it reaches back.
_APPLICATION_SLAB = (
    "wallet",
    "hwi",
    "core_import",
    "psbt_signer",
    "psbt_signer_contract",
)


def _is_btclib(name: str) -> bool:
    """Answer whether a dotted name is this package's, the bindings excluded.

    `name == "btclib" or name.startswith("btclib.")`, not a bare
    `startswith("btclib")`: `btclib_modules` above states the same
    boundary, for the same reason -- `btclib_secp256k1`, the bindings,
    matches the bare form and is not part of this package.
    """
    return name == "btclib" or name.startswith("btclib.")


def _btclib_names_imported_by(path: Path) -> set[str]:
    """Return every dotted btclib name one source file's own imports name.

    `from btclib import wallet` and `from btclib.wallet import Wallet` name
    the same package two different ways; joining the `from` module with
    each of its aliases covers both, and `import btclib.wallet.foo` is
    already a complete dotted name on its own.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names if _is_btclib(alias.name))
        elif isinstance(node, ast.ImportFrom) and _is_btclib(node.module or ""):
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


def test_the_application_slab_has_no_inbound_edge() -> None:
    """Nothing in btclib imports `wallet`, `hwi`, `core_import` or the signers.

    Static rather than a subprocess probe: `import btclib` alone loads
    nothing (`btclib/__init__.py`'s own `__getattr__` is why), so no
    runtime measurement of a plain import can tell whether some other
    module of the tree reaches the slab -- only asking what every source
    file's own import statements name can. `root.rglob("*.py")` walks the
    installed package the same way `module_names` does, from
    `btclib.__path__`, so this checks the tree the suite runs against
    rather than a copy on disk that might be stale.
    """
    root = Path(btclib.__path__[0])
    slab_roots = tuple(f"btclib.{name}" for name in _APPLICATION_SLAB)
    slab_files = {
        path
        for name in _APPLICATION_SLAB
        for path in (
            [root / f"{name}.py"]
            if (root / f"{name}.py").is_file()
            else (root / name).rglob("*.py")
        )
    }
    imports_by_file = {
        str(path.relative_to(root)): _btclib_names_imported_by(path)
        for path in root.rglob("*.py")
        if path not in slab_files
    }
    assert _slab_edges(imports_by_file, slab_roots) == {}
