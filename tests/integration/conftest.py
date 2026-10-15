# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the integration tests need, and what makes them skip.

The tests that talk to a node need two switches, and both have to be on.
`BTCLIB_INTEGRATION` in the environment is the opt-in: these tests start
programs, listen on a socket and write to disk, which is not what
`uv run pytest` should do to somebody who asked for the unit suite. The
second is the program itself -- `bitcoind` here -- because an opt-in
that fails for a missing binary would report a defect that is not one.

So the ordinary run reports them skipped and says which switch was off,
and the whole flow is one command:

    BTCLIB_INTEGRATION=1 uv run pytest tests/integration

The node is this session's own: a regtest data directory under pytest's
tmp_path, ephemeral rpc and p2p ports, and a cookie file for the
credentials. It never touches a node the maintainer is running, which is
the reason none of the defaults -- port 18443, ~/.bitcoin -- is used.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

# how long the node is given to answer its first rpc call: a regtest
# bitcoind is up in well under a second on any machine that can run this
# suite, and the wait is a poll rather than a sleep, so this bounds only
# the failure case
_STARTUP_TIMEOUT = 30.0

# what pytest-timeout gives each node test here, setup and teardown included,
# so that a bitcoind that stops answering fails the test waiting on it
# instead of hanging the run until the workflow's timeout-minutes ends
# the job. The session's first test pays the node's startup and its last
# the node's shutdown. The shutdown waits at most _STOP_TIMEOUT; the
# startup's deadline is _STARTUP_TIMEOUT, but it is read between
# calls, and the call in flight can outlast it by bitcoin_core_rpc's own
# DEFAULT_TIMEOUT. This sits above those three together plus the slowest
# test: the fixture's own deadlines, which say what they were waiting
# for, fire first. Measured 2026-09-27
# against bitcoind 31.1: the slowest node test, coinstats_test.py's, took
# under 12 s of setup and call on a macOS machine at a one-minute load
# average between 20 and 45, and under 2 s on ubuntu-latest
# (integration-bitcoind run 36309935817). `--durations=0
# --durations-min=0` on the run the module docstring gives re-derives it
_TEST_TIMEOUT = 120.0

# how many times the node is started, each on ports of its own, while a
# port it was given is taken
_BIND_ATTEMPTS = 5

# what Core writes to debug.log of a port that is taken, read at Bitcoin
# Core commit cce32b16874e and at v31.1, the release the workflow pins.
# The p2p listener says so (src/net.cpp). The rpc server has one
# endpoint (`-rpcallowip` below) and, where it cannot bind it, exits with
# "Unable to bind any endpoint for RPC server" and does not say why in
# v31.1 (src/httpserver.cpp); on a port picked a moment before, a taken
# port is the cause. The rpc line reaches only the log, stderr saying only
# "Unable to start HTTP server", so the log is what is read for both.
# Other bind errors in net.cpp say "(bind returned error ...)" instead and
# are not retried
_PORT_TAKEN = re.compile(
    r"Unable to bind to \S+ on this computer\. .+ is probably already running"
    r"|Unable to bind any endpoint for RPC server"
)

# how long a terminated node is given to exit
_STOP_TIMEOUT = 30.0

_T = TypeVar("_T")

_HERE = Path(__file__).parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Bound every node test of this directory with pytest-timeout.

    A marker per test, which pytest-timeout reads ahead of the `timeout`
    key of `[tool.pytest.ini_options]`: that key bounds the rest of the
    suite, against a slowest test that waits on no node, and the number
    above is measured against this directory's node tests.
    `qa_assets_test.py` waits on no node, so the key bounds it. The hook
    sees every item of the session, not only this directory's, hence the
    path test.
    """
    for item in items:
        if _HERE in item.path.parents and item.path.name != "qa_assets_test.py":
            item.add_marker(pytest.mark.timeout(_TEST_TIMEOUT))


def _free_port() -> int:
    """Return a port nothing is listening on, by letting the OS pick one.

    Bound and closed rather than guessed: a fixed port is what makes two
    runs of a test suite fight each other, and the maintainer's own
    regtest node is exactly the kind of thing already on 18443.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="session")
def bitcoind_path() -> str:
    """Return the bitcoind to run, skipping the whole module without one."""
    if not os.environ.get("BTCLIB_INTEGRATION"):
        pytest.skip("set BTCLIB_INTEGRATION=1 to run the node tests")
    path = os.environ.get("BTCLIB_BITCOIND") or shutil.which("bitcoind")
    if path is None:
        pytest.skip("no bitcoind: name one in BTCLIB_BITCOIND or put it on PATH")
    return path


class PortTaken(Exception):  # noqa: N818
    """The node exited because a port it was given is held by another."""


def port_was_taken(log: str) -> bool:
    """Return whether the node's log says a port it was given is taken."""
    return _PORT_TAKEN.search(log) is not None


def start_on_free_ports(start: Callable[[], _T], attempts: int = _BIND_ATTEMPTS) -> _T:
    """Return what `start` returns, calling it again while a port is taken.

    `_free_port` closes the port it picked, so another process can bind
    it before the node does, and the node then exits. `start` picks its
    ports itself, so each call is a fresh try; the last attempt's
    `PortTaken` is not caught.
    """
    for _ in range(attempts - 1):
        try:
            return start()
        except PortTaken:
            continue
    return start()


@dataclass(frozen=True)
class RunningNode:
    """A started node: its rpc client, its p2p port and its process."""

    client: BitcoinCoreRpcClient
    p2p_port: int
    process: subprocess.Popen[bytes]


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Terminate the process and wait for it."""
    process.terminate()
    process.wait(timeout=_STOP_TIMEOUT)


def _start_node(bitcoind: Sequence[str], datadir: Path) -> RunningNode:
    """Return a node on rpc and p2p ports of its own, once it answers.

    `-fallbackfee` because a regtest chain has no fee history to estimate
    from, and Core refuses to fund a transaction without one; the wallet
    calls here fund nothing, but a caller reading this as a recipe would
    meet that on the first `walletcreatefundedpsbt`.

    `-bind` names the one address this node listens for p2p on, and does
    so regardless of `-listen`'s own default -- Core's own reference for
    the option is "bind to given address and always listen on it" -- so
    a fixed, ephemeral, loopback-only port is what a p2p test dials.

    `-natpmp`, `-discover` and `-listenonion` are then switched off by
    hand, because the interaction that switched all three off for us was
    `-listen=0`, which naming `-bind` means no longer passing. Each
    defaults to on and each reaches past this machine -- a port mapping
    asked of the gateway, a public address looked up, a Tor control port
    dialled -- which is not what a throwaway regtest node wants of a
    developer's own network.

    A node that does not answer is stopped, so a failed try leaves no
    process behind.
    """
    port, p2p_port = _free_port(), _free_port()
    process = subprocess.Popen(  # noqa: S603
        [
            *bitcoind,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={port}",
            "-rpcbind=127.0.0.1",
            # Core ignores `-rpcbind` without it and binds ::1 as well as
            # 127.0.0.1. A taken 127.0.0.1 port then leaves the node up on
            # ::1, which the client does not dial, instead of exiting
            "-rpcallowip=127.0.0.1",
            f"-bind=127.0.0.1:{p2p_port}",
            "-natpmp=0",
            "-discover=0",
            "-listenonion=0",
            "-fallbackfee=0.0002",
            # so that `gettxoutsetinfo` answers at a named height, which
            # is what makes it read the index's own incrementally
            # maintained numbers rather than scan the set: the two are
            # the same answer where they agree and only the index says
            # anything about how it was kept
            "-coinstatsindex=1",
            "-printtoconsole=0",
        ],
    )
    client = BitcoinCoreRpcClient(
        f"http://127.0.0.1:{port}", cookie_path=datadir / "regtest" / ".cookie"
    )
    try:
        _wait_for(client, process, datadir / "regtest" / "debug.log")
    except BaseException:
        _stop(process)
        raise
    return RunningNode(client, p2p_port, process)


@pytest.fixture(scope="session")
def running_node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[RunningNode]:
    """Yield a regtest node started for this session.

    Each try has a data directory of its own, so that a node that exited
    on a taken port leaves nothing the next one reads.
    """
    started = start_on_free_ports(
        lambda: _start_node([bitcoind_path], tmp_path_factory.mktemp("regtest"))
    )
    try:
        yield started
    finally:
        _stop(started.process)


@pytest.fixture(scope="session")
def p2p_port(running_node: RunningNode) -> int:
    """Return the port the node's p2p listener is bound to.

    A fixture of its own so that a p2p test asks for the port alone.
    """
    return running_node.p2p_port


@pytest.fixture(scope="session")
def node(running_node: RunningNode) -> BitcoinCoreRpcClient:
    """Return an rpc client of the regtest node started for this session."""
    return running_node.client


def _wait_for(
    client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes], log: Path
) -> None:
    """Poll until the node answers, or fail with what it did instead.

    A node that exits with a taken port in its `log` raises `PortTaken`.
    """
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            text = (
                log.read_text(encoding="utf-8", errors="replace")
                if log.exists()
                else ""
            )
            if port_was_taken(text):
                raise PortTaken(text)
            pytest.fail(f"bitcoind exited with {process.returncode}")
        try:
            client.call("getblockchaininfo")
        # every failure before the node is up is the same failure: the
        # cookie file is not written yet, or the socket is not listening
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
        else:
            return
    pytest.fail(f"bitcoind did not answer within {_STARTUP_TIMEOUT} s")


@pytest.fixture
def wallets(
    node: BitcoinCoreRpcClient,
) -> tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient]:
    """Return a client of a funded wallet and one of a watch-only wallet.

    Two, because they are the two halves of what is being tested: the
    first holds keys and coins and stands for the rest of the world, and
    the second holds descriptors btclib built and no key at all -- which
    is what a wallet watching a hardware signer is.

    Named after the moment they were made, so that a session running
    several tests has no wallet of one still open in another; and
    `for_wallet` is the client's own way of naming the endpoint, the
    wallet being a path on the url rather than an argument.
    """
    suffix = f"{time.monotonic_ns():x}"
    miner, watcher = f"miner-{suffix}", f"watch-{suffix}"
    node.call("createwallet", [miner])
    # disable_private_keys, which is what makes the second wallet one that
    # can only watch: it is the third parameter of createwallet
    node.call("createwallet", [watcher, True])
    return node.for_wallet(miner), node.for_wallet(watcher)
