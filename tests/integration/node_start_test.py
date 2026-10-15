# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The node's start survives a port taken between pick and bind.

`_free_port` closes the port it picked, so a process that binds it first
makes `bitcoind` exit. These tests need no `bitcoind` and no opt-in: the
node is a stand-in script that binds the `-rpcport` and `-bind` ports as
`bitcoind` does and, where it cannot, writes to `debug.log` the line Core
writes and exits. `conftest.py` says where those lines were read. They
run in every ordinary run.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from tests.integration import conftest as node_module
from tests.integration.conftest import (
    PortTaken,
    _start_node,
    _stop,
    port_was_taken,
    start_on_free_ports,
)

# the stand-in for `bitcoind`: it binds both ports, writes `ready` once it
# holds them, and otherwise logs what Core logs when it cannot and exits
NODE = textwrap.dedent(
    """
    import pathlib, socket, sys, time
    args = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a)
    log_dir = pathlib.Path(args["-datadir"]) / "regtest"
    log_dir.mkdir(parents=True)
    held = []
    rpc = f"127.0.0.1:{args['-rpcport']}"
    for address in (rpc, args["-bind"]):
        host, port = address.rsplit(":", 1)
        sock = socket.socket()
        try:
            sock.bind((host, int(port)))
        except OSError:
            line = (
                "Unable to bind any endpoint for RPC server"
                if address == rpc
                else f"Unable to bind to {address} on this computer."
                " Bitcoin Core is probably already running."
            )
            (log_dir / "debug.log").write_text(line + "\\n")
            sys.exit(1)
        sock.listen()
        held.append(sock)
    (log_dir / "ready").write_text("")
    time.sleep(60)
    """
)


class _ReadyClient:
    """Answer once the stand-in has written `ready`, as the node's rpc does."""

    def __init__(self, url: str, cookie_path: Path) -> None:
        self.ready = cookie_path.parent / "ready"

    def call(self, method: str, *_: Any) -> dict[str, Any]:
        if not self.ready.exists():
            raise OSError("not listening")
        return {}


@pytest.fixture
def node_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Return the command of the stand-in node, with its client in place."""
    script = tmp_path / "node.py"
    script.write_text(NODE)
    monkeypatch.setattr(node_module, "BitcoinCoreRpcClient", _ReadyClient)
    return [sys.executable, str(script)]


@pytest.fixture
def held_port() -> Iterator[int]:
    """Yield a port another process holds, listening."""
    with closing(socket.socket()) as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        yield int(holder.getsockname()[1])


def _nth_port_is(monkeypatch: pytest.MonkeyPatch, nth: int, port: int) -> None:
    """Make the `nth` port picked (0 the rpc one, 1 the p2p one) `port`."""
    real = node_module._free_port
    picked: list[int] = []

    def pick() -> int:
        picked.append(1)
        return port if len(picked) == nth + 1 else real()

    monkeypatch.setattr(node_module, "_free_port", pick)


def _run(tmp_path: Path, command: list[str], attempts: int = 5) -> Any:
    datadirs = iter(range(attempts))
    return start_on_free_ports(
        lambda: _start_node(command, tmp_path / f"datadir{next(datadirs)}"),
        attempts,
    )


@pytest.mark.parametrize("nth", [0, 1], ids=["rpc", "p2p"])
def test_a_node_on_a_taken_port_is_started_again_on_another(
    tmp_path: Path,
    node_command: list[str],
    held_port: int,
    nth: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first rpc or p2p port is taken; the second try holds fresh ones."""
    _nth_port_is(monkeypatch, nth, held_port)
    started = _run(tmp_path, node_command)
    try:
        # the first try's datadir holds the log it met the held port with
        assert (tmp_path / "datadir0" / "regtest" / "debug.log").exists()
        assert started.p2p_port != held_port
        assert started.process.poll() is None
    finally:
        _stop(started.process)


def test_a_taken_port_on_the_last_attempt_is_raised(
    tmp_path: Path,
    node_command: list[str],
    held_port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With one attempt, the taken port is raised as `PortTaken`."""
    _nth_port_is(monkeypatch, 1, held_port)
    with pytest.raises(PortTaken, match="Unable to bind"):
        _run(tmp_path, node_command, attempts=1)


def test_a_node_that_exits_for_another_reason_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exit that does not name a taken port is not retried."""
    monkeypatch.setattr(node_module, "BitcoinCoreRpcClient", _ReadyClient)
    with pytest.raises(pytest.fail.Exception, match="exited with 3"):
        _start_node([sys.executable, "-c", "raise SystemExit(3)"], tmp_path)


def test_start_on_free_ports_calls_start_again_after_each_taken_port() -> None:
    """Two takes then a success is three calls and the success returned."""
    calls: list[int] = []

    def start() -> str:
        calls.append(1)
        if len(calls) < 3:
            raise PortTaken
        return "up"

    assert start_on_free_ports(start) == "up"
    assert len(calls) == 3


def test_start_on_free_ports_gives_up_after_its_attempts() -> None:
    """Every call taken: `attempts` calls, then the last `PortTaken`."""
    calls: list[int] = []

    def start() -> str:
        calls.append(1)
        raise PortTaken

    with pytest.raises(PortTaken):
        start_on_free_ports(start, attempts=4)
    assert len(calls) == 4


_BIND = "Unable to bind to 127.0.0.1:1 on this computer"
_P2P_TAKEN = _BIND + ". Bitcoin Core is probably already running."
_OTHER_BIND = _BIND + " (bind returned error 13)"
_LOCKED = (
    "Cannot obtain a lock on directory /x. Bitcoin Core is probably already running."
)


@pytest.mark.parametrize(
    "log, taken",
    [
        (_P2P_TAKEN, True),
        ("Unable to bind any endpoint for RPC server", True),
        (_OTHER_BIND, False),
        (_LOCKED, False),
        ("something else", False),
    ],
)
def test_port_was_taken_reads_the_nodes_complaint(log: str, taken: bool) -> None:
    """Read as taken: Core's p2p line and its rpc line for no endpoint."""
    assert port_was_taken(log) is taken


def test_a_node_that_does_not_answer_is_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A node that never answers has exited after the failure."""
    started: list[subprocess.Popen[bytes]] = []
    real = subprocess.Popen

    def record(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real(*args, **kwargs)
        started.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", record)
    monkeypatch.setattr(node_module, "BitcoinCoreRpcClient", _ReadyClient)
    monkeypatch.setattr(node_module, "_STARTUP_TIMEOUT", 0.5)
    with pytest.raises(pytest.fail.Exception, match="did not answer"):
        _start_node([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path)
    (process,) = started
    assert process.poll() is not None
