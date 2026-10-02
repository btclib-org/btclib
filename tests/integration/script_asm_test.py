# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`script_to_asm` against `ScriptToAsmStr`, on a live regtest node.

`decodescript` renders a script without the sighash decode. A script
placed as the `scriptSig` of a transaction given to `decoderawtransaction`
is rendered with it, which is what Core does for every input.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib import var_bytes
from btclib.script import script_to_asm
from tests.script.script_asm_test import CASES, PUB_KEY, _push, _sig


def _random_script(rng: random.Random) -> bytes:
    """Return a few op codes, short pushes, signatures and stray bytes."""
    parts: list[bytes] = []
    for _ in range(rng.randrange(1, 8)):
        kind = rng.random()
        if kind < 0.4:
            parts.append(bytes([rng.randrange(0x4F, 256)]))
        elif kind < 0.7:
            n = rng.randrange(0, 9)
            parts.append(bytes([n]) + rng.randbytes(n))
        elif kind < 0.85:
            parts.append(bytes.fromhex(_push(_sig(rng.randrange(256)))))
        else:
            parts.append(rng.randbytes(rng.randrange(1, 4)))
    return b"".join(parts)


def _push_corpus(rng: random.Random) -> Iterator[bytes]:
    """Yield a push of each length class in each width, whole and cut short."""
    for n in (*range(80), 255, 256, 257, 520, 521, 65535, 65536):
        data = rng.randbytes(n)
        pushes = [
            b"\x4e" + n.to_bytes(4, "little") + data,
        ]
        if n < 65536:
            pushes.append(b"\x4d" + n.to_bytes(2, "little") + data)
        if n < 76:
            pushes.append(bytes([n]) + data)
        if n < 256:
            pushes.append(b"\x4c" + bytes([n]) + data)
        for push in pushes:
            yield push
            yield push[:-1]


def _number_corpus() -> Iterator[bytes]:
    """Yield a push of every width up to five bytes, and every sign."""
    for width in range(6):
        for last in (0x00, 0x01, 0x7F, 0x80, 0x81, 0xFF):
            for fill in (0x00, 0x80, 0xFF):
                number = bytes([fill] * (width - 1) + [last]) if width else b""
                yield bytes.fromhex(_push(number))


def _signature_corpus() -> Iterator[bytes]:
    """Yield a signature with each hash type byte, bare and after OP_RETURN."""
    for hash_type in range(256):
        sig = _push(_sig(hash_type))
        yield bytes.fromhex(sig + _push(bytes.fromhex(PUB_KEY)))
        yield bytes.fromhex("6a" + sig)


def corpus(count: int = 2000) -> Iterator[bytes]:
    """Yield scripts of every shape ScriptToAsmStr tells apart, seeded.

    Every one-byte script, pushes, numbers, signatures, and random scripts.
    """
    rng = random.Random(2461)
    for i in range(256):
        yield bytes([i])
        yield bytes([i, 0x51])
    yield from _push_corpus(rng)
    yield from _number_corpus()
    yield from _signature_corpus()
    for _ in range(count):
        yield _random_script(rng)


def _decoded(node: BitcoinCoreRpcClient, script: bytes) -> str:
    """Return the asm of script as the scriptSig of the one input of a tx."""
    tx = (
        (2).to_bytes(4, "little")
        + b"\x01"
        + b"\x11" * 32  # an outpoint that is not a coinbase's
        + bytes(4)
        + var_bytes.serialize(script)
        + b"\xff" * 4
        + b"\x01"
        + bytes(8)
        + b"\x00"
        + bytes(4)
    )
    result: dict[str, Any] = node.call("decoderawtransaction", [tx.hex()])
    return str(result["vin"][0]["scriptSig"]["asm"])


def _plain(node: BitcoinCoreRpcClient, script: bytes) -> str:
    result: dict[str, Any] = node.call("decodescript", [script.hex()])
    return str(result["asm"])


def test_node_gives_the_table(node: BitcoinCoreRpcClient) -> None:
    """The rows of the unit tests are what the node says."""
    for script, plain, decoded in CASES:
        assert _plain(node, bytes.fromhex(script)) == plain, script
        assert _decoded(node, bytes.fromhex(script)) == decoded, script


def test_script_to_asm_agrees_with_core(node: BitcoinCoreRpcClient) -> None:
    """Every script of the corpus renders as the node renders it, twice."""
    for script in corpus():
        assert script_to_asm(script) == _plain(node, script), script.hex()
        assert script_to_asm(script, attempt_sighash_decode=True) == _decoded(
            node, script
        ), script.hex()
