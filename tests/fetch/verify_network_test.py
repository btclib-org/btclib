# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""No backend answers a question before the chain it is on is agreed.

`NetworkVerifyingFetcher._verify_once` is the check, and what carries the
property is the *set* of methods that call it: an entry point that does
not is outside the guard, answering from a host on another chain with
every other test green. The coverage floor cannot see it either -- the
call is a statement every `verify_network=False` test executes and
returns from at once -- which is what issue #1701 measured, and why the
call sites here are read out of the source rather than listed by hand.

Each case builds a fetcher whose scripted host serves testnet under a
mainnet label, calls one entry point, and asserts both halves: the
refusal, and that the host was asked once. One request is the chain
question alone, so the fetch behind it never went out.

The fixtures are each backend's own test module's, imported rather than
repeated: what a recorded reply looks like is that module's business.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib.fetch.electrum import ElectrumFetcher
from btclib.fetch.esplora import EsploraFetcher
from btclib.fetch.fetcher import Fetcher
from tests.fetch import TIP_HEIGHT, TX_ID, Recorded
from tests.fetch.bitcoin_core_rest_test import chaininfo
from tests.fetch.bitcoin_core_rest_test import client as rest_client
from tests.fetch.bitcoin_core_rest_test import recording as rest_recording
from tests.fetch.bitcoin_core_test import blockchaininfo
from tests.fetch.bitcoin_core_test import client as rpc_client
from tests.fetch.bitcoin_core_test import recording as rpc_recording
from tests.fetch.electrum_test import TESTNET_GENESIS_HEADER, LineRecorded
from tests.fetch.esplora_test import BASE, TESTNET_GENESIS

_FETCH = Path(__file__).parents[2] / "src" / "btclib" / "fetch"


@dataclass(frozen=True)
class _Backend:
    """A fetcher on a host that serves another chain, and its refusal."""

    build: Callable[[], tuple[Fetcher, Sequence[object]]]
    refusal: str


def _core() -> tuple[Fetcher, Sequence[object]]:
    """Return a mainnet fetcher over a node reporting the chain `test`."""
    endpoint = rpc_client(blockchaininfo(chain="test"))
    return BitcoinCoreFetcher(endpoint, "mainnet"), rpc_recording(endpoint).requests


def _rest() -> tuple[Fetcher, Sequence[object]]:
    """Return a mainnet fetcher over `-rest` reporting the chain `test`."""
    endpoint = rest_client((200, chaininfo(chain="test")))
    return BitcoinCoreRestFetcher(endpoint, "mainnet"), rest_recording(
        endpoint
    ).requests


def _esplora() -> tuple[Fetcher, Sequence[object]]:
    """Return a mainnet fetcher over an explorer on testnet's genesis."""
    transport = Recorded((200, TESTNET_GENESIS.encode()))
    return EsploraFetcher(BASE, transport=transport), transport.requests


def _electrum() -> tuple[Fetcher, Sequence[object]]:
    """Return a mainnet fetcher over a server on testnet's genesis."""
    transport = LineRecorded(TESTNET_GENESIS_HEADER)
    return ElectrumFetcher("mainnet", transport=transport), transport.requests


_BACKENDS = {
    "BitcoinCoreFetcher": _Backend(_core, "reports chain 'test', not the 'main'"),
    "BitcoinCoreRestFetcher": _Backend(_rest, "reports chain 'test', not the 'main'"),
    "ElectrumFetcher": _Backend(_electrum, TESTNET_GENESIS),
    "EsploraFetcher": _Backend(_esplora, TESTNET_GENESIS),
}

# the questions `Fetcher` declares, which every backend answers and
# every backend checks the chain in front of
_QUESTIONS: dict[str, Callable[[Fetcher], object]] = {
    "get_best_block_id": lambda endpoint: endpoint.get_best_block_id(),
    "get_block_count": lambda endpoint: endpoint.get_block_count(),
    "get_block_header": lambda endpoint: endpoint.get_block_header(TIP_HEIGHT),
    "get_tx": lambda endpoint: endpoint.get_tx(TX_ID),
}

# what `Fetcher` does not declare, each pinned where its own backend is
# tested rather than a second time here:
# `test_broadcast_verifies_the_network_before_sending_anything` in
# `bitcoin_core_test.py` and in `esplora_test.py`, and
# `test_get_tx_merkle_and_verify_tx_are_refused_on_another_chain_too` in
# `electrum_test.py`
_ELSEWHERE = {
    ("BitcoinCoreFetcher", "broadcast"),
    ("ElectrumFetcher", "get_tx_merkle"),
    ("EsploraFetcher", "broadcast"),
}


def _call_sites() -> set[tuple[str, str]]:
    """Return every (class, method) of the package that calls the check."""
    found: set[tuple[str, str]] = set()
    for path in sorted(_FETCH.glob("*.py")):
        module = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(call, ast.Call)
                    and ast.unparse(call.func) == "self._verify_once"
                    for call in ast.walk(method)
                ):
                    found.add((node.name, method.name))
    return found


@pytest.mark.parametrize("backend", sorted(_BACKENDS))
@pytest.mark.parametrize("question", sorted(_QUESTIONS))
def test_no_question_is_answered_by_a_host_on_another_chain(
    backend: str, question: str
) -> None:
    """The chain is asked about first, whichever question was asked.

    One request is the whole of what the host is allowed to see: the
    check consumed it, and the request the question would have made was
    never sent.
    """
    endpoint, asked = _BACKENDS[backend].build()
    with pytest.raises(BTClibValueError, match=_BACKENDS[backend].refusal):
        _QUESTIONS[question](endpoint)
    assert len(asked) == 1


def test_every_call_site_is_pinned() -> None:
    """The census, and the reason this file is not a list kept by hand.

    A call site the cases above do not pin fails here rather than
    passing on a check no case exercises; a pinned call site deleted
    fails both here and in the case that was covering it. An entry point
    that never calls the check leaves no call site to compare, so it is
    the gap this module's docstring names and not one this test closes.
    """
    pinned = {
        (backend, question) for backend in _BACKENDS for question in _QUESTIONS
    } | _ELSEWHERE
    found = _call_sites()
    assert found == pinned, (
        f"not pinned by a test: {sorted(found - pinned)};"
        f" gone from the tree: {sorted(pinned - found)}"
    )


def test_the_walk_reads_calls_and_not_names() -> None:
    """The control: a walk finding nothing would pass the census silently.

    `ElectrumFetcher._header_at` is the absence with the shape of the
    defect: its docstring names `_verify_once` and its body does not call
    it, so a walk reading names rather than calls invents it. The other
    two mention the check nowhere and would be absent from a name walk
    too; they say what the census must not invent for a different reason
    -- `text` is the seam `EsploraFetcher.assert_network` itself goes
    through, so a check in it would ask the explorer about the explorer,
    and `ElectrumFetcher.verify_tx` reaches the chain through
    `get_block_header` and asks nothing of its own.
    """
    found = _call_sites()
    assert ("EsploraFetcher", "get_tx") in found
    assert ("ElectrumFetcher", "_header_at") not in found
    assert ("EsploraFetcher", "text") not in found
    assert ("ElectrumFetcher", "verify_tx") not in found
