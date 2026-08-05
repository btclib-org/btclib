# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Bitcoin Core RPC source is standalone and canonically re-exported."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path

from btclib import bitcoin_core_rpc
from btclib.bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    FetchError,
    HttpError,
    RpcError,
)
from btclib.fetch import BitcoinCoreRpcClient as ExportedBitcoinCoreRpcClient
from btclib.fetch import transport as transport_exports
from btclib.fetch.bitcoin_core import BitcoinCoreRpcClient as LegacyRpcClient


def _source_path() -> Path:
    path = bitcoin_core_rpc.__file__
    assert path is not None
    return Path(path)


def test_the_client_source_imports_only_the_standard_library() -> None:
    """A copied file has no package or third-party import left behind."""
    tree = ast.parse(_source_path().read_text(encoding="utf-8"))
    # a relative import is the one this would otherwise not see: the file
    # sits inside the package, so `from . import fetcher` is how a
    # dependency on btclib comes back, and `node.module` is None for the
    # `from . import x` spelling -- an empty set of roots, and an assertion
    # that passes. The level is what says an import is relative at all
    relative = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level
    ]
    assert not relative
    imported_roots = {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_roots.update(
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert imported_roots <= {*sys.stdlib_module_names, "__future__"}


def test_the_single_copied_file_imports_and_calls_without_btclib(
    tmp_path: Path,
) -> None:
    """Exercise results and structured errors with site packages disabled."""
    vendored = tmp_path / "bitcoin_core_rpc.py"
    shutil.copy2(_source_path(), vendored)
    smoke = """
import importlib.util
import json
import sys
from decimal import Decimal

for module_name in ("a_vendored_bitcoin_core_rpc", "z_vendored_bitcoin_core_rpc"):
    spec = importlib.util.spec_from_file_location(module_name, sys.argv[1])
    assert spec is not None and spec.loader is not None
    rpc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rpc)
    assert rpc.FetchError.__module__ == module_name

# what -I -S bought, asserted rather than assumed: no site packages, no
# PYTHONPATH and no script directory on sys.path, so there is no btclib
# here to have been reached. Without these two, an isolation that stopped
# working would leave a test that passes and proves nothing
assert "btclib" not in sys.modules
try:
    import btclib
except ImportError:
    pass
else:
    raise AssertionError("btclib is importable here, so this proves nothing")

calls = []
def transport(request, timeout):
    calls.append((request, timeout))
    request_id = json.loads(request.data)["id"]
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "result": 1.25}
    ).encode()
    return 200, body

client = rpc.BitcoinCoreRpcClient(
    "http://127.0.0.1:8332",
    user="rpcuser",
    password="rpcpassword",  # pragma: allowlist secret
    transport=transport,
)
assert client.call("getbalance") == Decimal("1.25")
assert len(calls) == 1

def rpc_error(request, timeout):
    request_id = json.loads(request.data)["id"]
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id,
         "error": {"code": -5, "message": "not found", "data": {"tx": 1}}}
    ).encode()
    return 200, body

client.transport = rpc_error
try:
    client.call("getrawtransaction")
except rpc.RpcError as error:
    assert error.code == -5 and error.data == {"tx": 1}
else:
    raise AssertionError("RpcError not raised")

client.transport = lambda request, timeout: (503, b"not json")
try:
    client.call("getblockcount")
except rpc.HttpError as error:
    assert error.status == 503
else:
    raise AssertionError("HttpError not raised")
"""
    subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-S", "-c", smoke, str(vendored)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )


def test_btclib_reexports_the_canonical_objects() -> None:
    """Compatibility imports are aliases, not hand-maintained copies."""
    assert ExportedBitcoinCoreRpcClient is BitcoinCoreRpcClient
    assert LegacyRpcClient is BitcoinCoreRpcClient

    assert BTClibValueError is bitcoin_core_rpc.BTClibValueError
    assert BTClibTypeError is bitcoin_core_rpc.BTClibTypeError
    assert BTClibRuntimeError is bitcoin_core_rpc.BTClibRuntimeError
    assert FetchError is bitcoin_core_rpc.FetchError
    assert HttpError is bitcoin_core_rpc.HttpError
    assert RpcError is bitcoin_core_rpc.RpcError
    assert FetchError.__module__ == "btclib.exceptions"

    assert transport_exports.HttpTransport is bitcoin_core_rpc.HttpTransport
    assert transport_exports.urlopen_transport is bitcoin_core_rpc.urlopen_transport
    assert transport_exports.http_request is bitcoin_core_rpc.http_request
