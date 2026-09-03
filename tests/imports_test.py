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

import importlib
import pkgutil
import subprocess
import sys
from collections.abc import Iterator

import pytest

import btclib

MODULE_NAMES = [
    "btclib",
    *(module.name for module in pkgutil.walk_packages(btclib.__path__, "btclib.")),
]


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
    failure, but as a test it costs an interpreter start-up per module
    (~0.2 s, times some sixty of them) and buys nothing: the import
    machinery decides what to execute by consulting sys.modules and
    nothing else.

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


@pytest.mark.parametrize("module_name", MODULE_NAMES)
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
    btclib_node uses `socket.inet_pton`, and it is a package that does
    open connections.
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
