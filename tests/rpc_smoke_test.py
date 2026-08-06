# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the pure half of the rpc smoke script of `.github/scripts`.

Most of `rpc_smoke.py` is not testable here at all, and is not supposed to
be: `node`, `probe`, `check_protocol`, `check_cookie`'s wallet-bearing
siblings, `generate_chain` and everything `smoke` calls in turn all talk
to a real `BitcoinCoreRpcClient` backed by a real bitcoind, which is the
one thing this script exists to have -- a mock of it would be testing
that the mock agrees with itself. `.github/workflows/rpc-smoke.yml` is
where that half is exercised, against Core itself, on a schedule and
before a release; it is not duplicated here.

What is covered is the half with no node behind it: `check`, the plain
predicate every other function calls; `port_is_free`, a socket check;
`check_legacy_reply` and `check_v2_reply`, which read a status and a
plain `dict` -- exactly the shape `probe` hands them, but built here by
hand rather than read off a wire; `check_cookie`, which is file
parsing (`cookie_auth` reads a path, no client passed to it at all); and
`print_log_tail`. `main`'s argument parsing is covered by its own
failure modes, which is what does not need `--bitcoind` to be real.

The script is loaded by path, `.github/scripts` being no package: the
mutation-counter test does the same for the same reason.
"""

from __future__ import annotations

import importlib.util
import runpy
import sys
from contextlib import closing
from pathlib import Path
from socket import socket
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "rpc_smoke.py"


@pytest.fixture(scope="module")
def smoke() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("rpc_smoke", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_prints_ok_on_a_true_claim(
    smoke: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """A true claim prints `ok` and the claim, and raises nothing."""
    smoke.check(True, "the node answers")
    assert capsys.readouterr().out == "ok   the node answers\n"


def test_check_raises_on_a_false_claim(smoke: ModuleType) -> None:
    """A false claim is a SmokeError naming the claim that failed."""
    with pytest.raises(smoke.SmokeError, match="the node answers"):
        smoke.check(False, "the node answers")


def test_port_is_free_when_nothing_listens(smoke: ModuleType) -> None:
    """A port nothing binds to any more reads as free."""
    with closing(socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    assert smoke.port_is_free(free_port)


def test_port_is_free_is_false_once_something_listens(smoke: ModuleType) -> None:
    """A port a listening socket holds reads as not free."""
    with closing(socket()) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        assert not smoke.port_is_free(listener.getsockname()[1])


@pytest.mark.parametrize("rpc_error", [False, True])
def test_check_legacy_reply_accepts_a_wellformed_reply(
    smoke: ModuleType, rpc_error: bool
) -> None:
    """A 1.1 result and a 1.1 error, each shaped as Core shapes them."""
    reply: dict[str, Any] = {
        "result": None if rpc_error else 1,
        "error": {} if rpc_error else None,
    }
    smoke.check_legacy_reply(500 if rpc_error else 200, reply, rpc_error=rpc_error)


def test_check_legacy_reply_rejects_a_jsonrpc_member(smoke: ModuleType) -> None:
    """A 1.1 reply carries no `jsonrpc` member at all."""
    reply = {"jsonrpc": "2.0", "result": 1, "error": None}
    with pytest.raises(smoke.SmokeError, match="no jsonrpc member"):
        smoke.check_legacy_reply(200, reply, rpc_error=False)


def test_check_legacy_reply_rejects_a_missing_member(smoke: ModuleType) -> None:
    """A 1.1 reply carries both `result` and `error`, one of them null."""
    with pytest.raises(smoke.SmokeError, match="both result and error"):
        smoke.check_legacy_reply(200, {"result": 1}, rpc_error=False)


def test_check_legacy_reply_rejects_the_wrong_status_for_an_error(
    smoke: ModuleType,
) -> None:
    """A 1.1 rpc error arrives under an HTTP 500, not a 200."""
    reply: dict[str, Any] = {"result": None, "error": {}}
    with pytest.raises(smoke.SmokeError, match="HTTP 500"):
        smoke.check_legacy_reply(200, reply, rpc_error=True)


def test_check_legacy_reply_rejects_a_populated_result_on_an_error(
    smoke: ModuleType,
) -> None:
    """A 1.1 error reply's `result` is null, never a value."""
    reply = {"result": 1, "error": {}}
    with pytest.raises(smoke.SmokeError, match="null result"):
        smoke.check_legacy_reply(500, reply, rpc_error=True)


def test_check_legacy_reply_rejects_a_missing_error_object(smoke: ModuleType) -> None:
    """A 1.1 error reply's `error` is populated, never null."""
    reply = {"result": None, "error": None}
    with pytest.raises(smoke.SmokeError, match="has the error object"):
        smoke.check_legacy_reply(500, reply, rpc_error=True)


def test_check_legacy_reply_rejects_a_populated_error_on_a_result(
    smoke: ModuleType,
) -> None:
    """A 1.1 result reply's `error` is null, never populated."""
    reply = {"result": 1, "error": {}}
    with pytest.raises(smoke.SmokeError, match="null error"):
        smoke.check_legacy_reply(200, reply, rpc_error=False)


@pytest.mark.parametrize("rpc_error", [False, True])
def test_check_v2_reply_accepts_a_wellformed_reply(
    smoke: ModuleType, rpc_error: bool
) -> None:
    """A 2.0 result and a 2.0 error, each with exactly one member set."""
    reply: dict[str, Any] = {"jsonrpc": "2.0"}
    reply["error" if rpc_error else "result"] = {} if rpc_error else 1
    smoke.check_v2_reply(200, reply, rpc_error=rpc_error)


def test_check_v2_reply_rejects_a_missing_marker(smoke: ModuleType) -> None:
    """A 2.0 reply echoes the `jsonrpc: "2.0"` marker."""
    with pytest.raises(smoke.SmokeError, match="echoes the 2.0 marker"):
        smoke.check_v2_reply(200, {"result": 1}, rpc_error=False)


def test_check_v2_reply_rejects_a_non_200_status(smoke: ModuleType) -> None:
    """A 2.0 reply arrives under an HTTP 200, error or not."""
    reply = {"jsonrpc": "2.0", "result": 1}
    with pytest.raises(smoke.SmokeError, match="HTTP 200"):
        smoke.check_v2_reply(500, reply, rpc_error=False)


def test_check_v2_reply_rejects_a_result_with_no_result_member(
    smoke: ModuleType,
) -> None:
    """A 2.0 result reply carries a `result` member."""
    with pytest.raises(smoke.SmokeError, match="has a result member"):
        smoke.check_v2_reply(200, {"jsonrpc": "2.0"}, rpc_error=False)


def test_check_v2_reply_rejects_a_result_carrying_both_members(
    smoke: ModuleType,
) -> None:
    """A 2.0 result reply carries no `error` member alongside it."""
    reply = {"jsonrpc": "2.0", "result": 1, "error": {}}
    with pytest.raises(smoke.SmokeError, match="no error member"):
        smoke.check_v2_reply(200, reply, rpc_error=False)


def test_check_v2_reply_rejects_an_error_with_no_error_member(
    smoke: ModuleType,
) -> None:
    """A 2.0 error reply carries an `error` member."""
    with pytest.raises(smoke.SmokeError, match="has an error member"):
        smoke.check_v2_reply(200, {"jsonrpc": "2.0"}, rpc_error=True)


def test_check_v2_reply_rejects_an_error_carrying_both_members(
    smoke: ModuleType,
) -> None:
    """A 2.0 error reply carries no `result` member alongside it."""
    reply = {"jsonrpc": "2.0", "result": 1, "error": {}}
    with pytest.raises(smoke.SmokeError, match="no result member"):
        smoke.check_v2_reply(200, reply, rpc_error=True)


def test_check_cookie_reads_the_credential(smoke: ModuleType, tmp_path: Path) -> None:
    """A cookie naming the node's own user and a non-empty password passes."""
    cookie = tmp_path / ".cookie"
    cookie.write_text(f"{smoke.COOKIE_USER}:s3cr3t", encoding="utf-8")
    smoke.check_cookie(cookie)


def test_check_cookie_rejects_a_missing_file(smoke: ModuleType, tmp_path: Path) -> None:
    """No file at the cookie path is a SmokeError, not a crash."""
    with pytest.raises(smoke.SmokeError, match="wrote its cookie"):
        smoke.check_cookie(tmp_path / "no-such-cookie")


def test_check_cookie_rejects_the_wrong_user(smoke: ModuleType, tmp_path: Path) -> None:
    """The cookie's user field has to be `COOKIE_USER`."""
    cookie = tmp_path / ".cookie"
    cookie.write_text("someoneelse:s3cr3t", encoding="utf-8")
    with pytest.raises(smoke.SmokeError, match=f"names {smoke.COOKIE_USER}"):
        smoke.check_cookie(cookie)


def test_check_cookie_rejects_an_empty_password(
    smoke: ModuleType, tmp_path: Path
) -> None:
    """A cookie with nothing after the colon has no password to check."""
    cookie = tmp_path / ".cookie"
    cookie.write_text(f"{smoke.COOKIE_USER}:", encoding="utf-8")
    with pytest.raises(smoke.SmokeError, match="carries a password"):
        smoke.check_cookie(cookie)


def test_print_log_tail_prints_only_the_last_lines(
    smoke: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only the last `LOG_TAIL_LINES` lines of the log reach stderr."""
    datadir = tmp_path
    log = datadir / smoke.DATADIR_SUBDIR / "debug.log"
    log.parent.mkdir(parents=True)
    lines = [f"line {n}" for n in range(smoke.LOG_TAIL_LINES + 5)]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    smoke.print_log_tail(datadir)

    err = capsys.readouterr().err
    assert "line 4\n" not in err
    assert "line 5" in err
    assert f"line {smoke.LOG_TAIL_LINES + 4}" in err


def test_print_log_tail_is_silent_when_there_is_no_log(
    smoke: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No debug.log at all prints nothing, rather than failing to read one."""
    smoke.print_log_tail(tmp_path)
    assert capsys.readouterr().err == ""


def test_main_requires_every_argument(
    smoke: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Argparse's own failure, which needs no bitcoind to reach.

    Called in-process rather than through a subprocess: a subprocess runs
    in its own interpreter, and this project collects no coverage from
    one, which would leave `main`'s own argument parsing looking untested
    when it is exactly what this covers.
    """
    monkeypatch.setattr(sys, "argv", ["rpc_smoke.py"])
    with pytest.raises(SystemExit) as excinfo:
        smoke.main()
    assert excinfo.value.code == 2
    assert "--bitcoind" in capsys.readouterr().err


def test_main_rejects_an_unknown_protocol(
    smoke: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--protocol` only accepts the two json-rpc versions Core speaks."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rpc_smoke.py",
            "--bitcoind",
            "/does/not/matter",
            "--core-version",
            "27.2",
            "--protocol",
            "1.0",
        ],
    )
    with pytest.raises(SystemExit) as excinfo:
        smoke.main()
    assert excinfo.value.code == 2
    assert "--protocol" in capsys.readouterr().err


def test_the_main_guard_runs_the_script_as___main__(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess or a node.

    `runpy.run_path` executes the file fresh with `__name__` set to
    `"__main__"` in this interpreter, so the guard is under test; an
    argument argparse itself refuses is what lets that happen with no
    `--bitcoind` needed -- the failure is raised evaluating `main()`,
    before anything past argument parsing runs.
    """
    monkeypatch.setattr(sys, "argv", ["rpc_smoke.py"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert excinfo.value.code == 2
    assert "--bitcoind" in capsys.readouterr().err
