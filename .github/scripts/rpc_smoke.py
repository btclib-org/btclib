#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The one claim recorded replies cannot make: a live node answers this way.

`tests/fetch` exercises the whole of the request building, the status
handling and the error mapping against replies recorded from Core, and
opens no socket doing it. What it cannot establish is that Core sends
those replies -- the recording *is* the thing being classified -- so this
script starts a bitcoind of a stated version, on a regtest chain it
generates itself, and asks it every question `btclib.fetch.bitcoin_core`
answers.

What it proves, and why each item is here rather than in the suite:

- the protocol version the node speaks, read off the wire. The reply to
  a request carrying the 2.0 marker is inspected before btclib
  classifies it, because the shapes `_legacy_result` and `_v2_result`
  read are exactly what a recording asserts without evidence: no
  `jsonrpc` member and an rpc error under an HTTP 500 for 1.1, the marker
  echoed and an rpc error under a 200 for 2.0;
- a result and an error under that version, and then the same two through
  `call`, which is btclib's classification of what was just read raw;
- the cookie file the node wrote, at the path Core's layout puts it, one
  ascii line with a colon in it;
- the `/wallet/<name>` endpoint of a node with two wallets loaded, which
  is the case where the endpoint is load-bearing: with two of them the
  node refuses a wallet method that names neither;
- the three fetcher answers against a chain generated here, so the
  expected height is arithmetic rather than a recording, and the
  transaction fetched is one whose id btclib recomputes from the bytes.

The expected protocol version is an argument and not something derived
from the version number: what the matrix pins is the claim that v27
answers 1.1 and the current release answers 2.0, and a node that stopped
doing so has to fail this rather than be accommodated by it.

Run it against a node of your own with `--bitcoind`; CONTRIBUTING.md
carries the command, and `.github/workflows/rpc-smoke.yml` the download
that verifies which binary it is.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from btclib import b32
from btclib.exceptions import FetchError, HttpError, RpcError
from btclib.fetch.bitcoin_core import (
    COOKIE_USER,
    BitcoinCoreFetcher,
    BitcoinCoreRpcClient,
    cookie_auth,
)
from btclib.fetch.transport import http_request

# regtest, and the node is started with no -rpcport so that the port is
# Core's own default for the chain rather than one this script chose:
# `from_network` builds that number from Core's table, and a live node is
# what says the two still agree
NETWORK = "regtest"
RPC_PORT = 18443

# the subdirectory Core puts a regtest datadir in, which is where the
# cookie is written. Spelled out rather than imported from the private
# table in btclib.fetch.bitcoin_core: what is being checked is that btclib's
# copy of Core's layout is Core's layout, and a check reading the value
# under test proves nothing
DATADIR_SUBDIR = "regtest"

# 100 blocks of coinbase maturity plus the one that is spendable after
# them: the height at which exactly one subsidy has matured, so the
# wallet balance below is one subsidy exactly. Regtest halves every 150
# blocks, so that subsidy is the full 50 BTC
MATURITY_HEIGHT = 101
SUBSIDY = Decimal(50)

# a space and a plus, and both on purpose: a wallet is a directory and may
# be called anything a filesystem accepts, so the endpoint has to
# percent-encode the name. A space written into a url unencoded is a
# malformed request line, and a plus is a space to anything reading the
# path as a query string -- `for_wallet` is what this checks, and the two
# characters are what would make it address a different endpoint or none
WALLET = "btclib smoke+wallet"
# the second one exists so that the first one has to be named: a node with
# a single wallet loaded answers a wallet method on the bare endpoint too,
# which would make the endpoint check pass without the endpoint
OTHER_WALLET = "btclib-other"

# the generator point as a compressed public key, i.e. the public key of
# the private key 1: the one key in bitcoin published everywhere and
# owned by nobody. What it is for is an address no wallet of this node
# knows, so that the coinbase paid to it is a transaction only -txindex
# can answer for -- and, incidentally, btclib's own address encoding put
# in front of Core's parser
FOREIGN_PUB_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# what the fee estimator cannot supply on a chain with no fee history:
# without it `sendtoaddress` fails rather than sending, and the
# transaction to fetch is the whole point of sending one
FALLBACK_FEE = "0.0002"

# how long the node is given to open its rpc port, and how often it is
# asked. bitcoind loads the block index before it answers, which on a
# fresh regtest datadir is immediate and on a loaded runner is not
STARTUP_TIMEOUT = 120.0
STARTUP_POLL = 0.25

# the id every raw probe below sends, and what the node has to echo. Fixed
# rather than random, unlike `call`'s: there is one probe in flight at a
# time here, and a constant is what makes the echo check readable
PROBE_ID = "btclib-smoke-probe"

# what is printed of the node's own log when a check fails: enough to
# carry a refused bind or a wallet error, not the whole of a debug.log
LOG_TAIL_LINES = 40


class SmokeError(RuntimeError):
    """A live node did not answer the way the recorded replies say it does."""


def check(condition: bool, claim: str) -> None:
    """Report a claim the node has just confirmed, or fail on it.

    The claim is what is printed on success and what the exception names on
    failure, so it is worded as the thing being asserted: the log of a
    green run is the list of what a live node was actually asked.
    """
    if not condition:
        raise SmokeError(f"a live node contradicts this: {claim}")
    print(f"ok   {claim}")


def port_is_free(port: int) -> bool:
    """Say whether anything is listening on the loopback port."""
    with closing(socket.socket()) as probe:
        return probe.connect_ex(("127.0.0.1", port)) != 0


@contextmanager
def node(bitcoind: Path, datadir: Path) -> Iterator[BitcoinCoreRpcClient]:
    """Run a regtest bitcoind on Core's own rpc port, and stop it after.

    No `-rpcport` and no `-rpcuser`: the port, the datadir layout and the
    cookie are the node's defaults, which is what makes `from_network` and
    `cookie_auth` checkable at all. `-txindex` so `getrawtransaction`
    answers for a transaction no wallet of this node knows, and `-listen=0`
    because a smoke test has no peers.
    """
    if not port_is_free(RPC_PORT):
        err_msg = f"something is already listening on {NETWORK} rpc port {RPC_PORT}:"
        err_msg += " this script talks to Core's default port on purpose, so stop it"
        raise SmokeError(err_msg)
    command = [
        str(bitcoind),
        f"-{NETWORK}",
        f"-datadir={datadir}",
        "-txindex",
        "-listen=0",
        f"-fallbackfee={FALLBACK_FEE}",
        # the node's own log stays in its datadir, where `print_log_tail`
        # reads it when a check fails: on the console it interleaves with
        # the checks, and what a green run is worth reading for is the
        # checks
        "-printtoconsole=0",
    ]
    # the client before the node, so that the `finally` below always has
    # one to stop it with: the cookie is read at every call, so a client
    # built before the file exists is a client that works once it does
    client = BitcoinCoreRpcClient.from_network(
        NETWORK, cookie_path=datadir / DATADIR_SUBDIR / ".cookie"
    )
    # S603: the executable is a path this script was handed, and every
    # other word of the command line is a constant above; no shell is
    # involved, so nothing here is parsed as anything but arguments
    process = subprocess.Popen(command)  # noqa: S603
    try:
        wait_for_rpc(client, process)
        yield client
    finally:
        stop(client, process)


def wait_for_rpc(
    client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes]
) -> None:
    """Wait until the node answers, or say what it did instead.

    Both failures on the way are the node not being up yet: no cookie file
    and a refused connection arrive as `FetchError`, and the rpc error -28
    is what it answers while it loads the block index. A node that exited
    is not waited for -- its own output on the console says why.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            err_msg = f"bitcoind exited with {process.returncode} before answering"
            raise SmokeError(err_msg)
        try:
            client.call("getblockchaininfo")
        except (FetchError, RpcError):
            time.sleep(STARTUP_POLL)
        else:
            return
    raise SmokeError(f"no rpc answer in {STARTUP_TIMEOUT} s")


def stop(client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes]) -> None:
    """Ask the node to stop, and make sure it did.

    Through the rpc, which is how a node is stopped without losing what it
    has not flushed. A node that does not go down on its own is killed:
    this runs in a `finally`, so the failure being reported is the one
    worth keeping.
    """
    try:
        client.call("stop")
        process.wait(timeout=STARTUP_TIMEOUT)
    except (FetchError, RpcError, subprocess.TimeoutExpired):
        process.kill()
        process.wait()


def probe(
    client: BitcoinCoreRpcClient, method: str, params: Sequence[Any]
) -> tuple[int, Mapping[str, Any]]:
    """Return the status and the json of a reply, before btclib reads it.

    The same request `call` builds, the 2.0 marker included, sent through
    the same transport -- and then neither classified nor validated, which
    is the point: what the checks below read is the shape of the reply
    itself, which is the thing every recorded fixture asserts.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": PROBE_ID, "method": method, "params": list(params)}
    ).encode()
    status, payload = http_request(
        client.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": client.auth_header(),
        },
    )
    reply = json.loads(payload)
    check(reply.get("id") == PROBE_ID, "the node echoes the id the request carried")
    return status, reply


def check_legacy_reply(
    status: int, reply: Mapping[str, Any], *, rpc_error: bool
) -> None:
    """Check a reply against Core's 1.1, the shape `_legacy_result` reads.

    Two claims, and the second is the one that costs: the reply carries no
    version marker at all, and an rpc error arrives as the body of an HTTP
    500 -- so a routine "no such transaction" and a server fault have the
    same status, and the error has to be read before the status is judged.
    Both members are always present, one of them null, which is why the 2.0
    rule of exactly one of them cannot be applied to a 1.1 reply.
    """
    check("jsonrpc" not in reply, "a 1.1 reply carries no jsonrpc member")
    both = "result" in reply and "error" in reply
    check(both, "a 1.1 reply carries both result and error, one of them null")
    if rpc_error:
        check(status == 500, "an rpc error under 1.1 arrives with an HTTP 500")
        check(reply["result"] is None, "the 1.1 error reply has a null result")
        check(reply["error"] is not None, "the 1.1 error reply has the error object")
    else:
        check(status == 200, "a result under 1.1 arrives with an HTTP 200")
        check(reply["error"] is None, "the 1.1 result reply has a null error")


def check_v2_reply(status: int, reply: Mapping[str, Any], *, rpc_error: bool) -> None:
    """Check a reply against JSON-RPC 2.0, as `_v2_result` reads it.

    The marker echoed, an HTTP 200 whatever the outcome -- which is what
    lets a non-200 mean the exchange itself failed -- and exactly one of
    `result` and `error` present rather than both with one null. That last
    one is what tells a 2.0 reply from a 1.1 reply wearing the marker.
    """
    check(reply.get("jsonrpc") == "2.0", "a 2.0 reply echoes the 2.0 marker")
    check(status == 200, "a 2.0 reply arrives with an HTTP 200, error or not")
    if rpc_error:
        check("error" in reply, "the 2.0 error reply has an error member")
        check("result" not in reply, "the 2.0 error reply has no result member")
    else:
        check("result" in reply, "the 2.0 result reply has a result member")
        check("error" not in reply, "the 2.0 result reply has no error member")


def check_protocol(
    client: BitcoinCoreRpcClient, protocol: str, unknown_tx_id: str
) -> None:
    """Read the two reply shapes off the wire, and then through `call`.

    A result and an error under the version the node speaks: the minimum,
    because the error path is where the two versions disagree and the one a
    recording can least be trusted about. The `call` half is btclib
    classifying the very replies just read.
    """
    check_reply = check_legacy_reply if protocol == "1.1" else check_v2_reply
    status, reply = probe(client, "getblockcount", [])
    check_reply(status, reply, rpc_error=False)
    status, reply = probe(client, "getrawtransaction", [unknown_tx_id])
    check_reply(status, reply, rpc_error=True)

    height = client.call("getblockcount")
    check(isinstance(height, int), f"call returns the result: a height of {height}")
    try:
        client.call("getrawtransaction", [unknown_tx_id])
    except RpcError as e:
        # -5 is RPC_INVALID_ADDRESS_OR_KEY, which is what Core answers for
        # a transaction it cannot find, on both sides of the version
        # boundary and whichever layer carried it
        check(
            e.code == -5, "call raises RpcError -5 for a transaction the node has not"
        )
    else:
        raise SmokeError("an unknown transaction id was not an error")


def check_cookie(cookie_path: Path) -> None:
    """Check the credential in the file the node wrote.

    At Core's own path for the chain, which is the other half of what
    `from_network` computes. The first field is documentation -- the node
    compares the whole line -- so what is checked about it is that it is
    still what Core writes, a cookie whose first field is something else
    being a valid one.
    """
    check(cookie_path.is_file(), f"the node wrote its cookie at {cookie_path}")
    credential = cookie_auth(cookie_path)
    user, _, password = credential.partition(":")
    check(user == COOKIE_USER, f"the cookie names {COOKIE_USER} as the user")
    check(bool(password), "the cookie carries a password after the colon")


def check_credentials_refused(client: BitcoinCoreRpcClient) -> None:
    """Check that a wrong credential is an HTTP failure with its status.

    Which is what `HttpError.status` is for: a 401 is the node refusing
    the credential and it will refuse it again, where a 503 from a full
    work queue would not. Core answers a 401 with an empty body, so this
    is also the live case for a status that arrives with nothing a parser
    can read.
    """
    wrong = BitcoinCoreRpcClient(
        client.url,
        user="btclib",
        # S106 and detect-secrets: a credential that is deliberately not
        # the node's, which is the whole of what this checks
        password="not the cookie",  # noqa: S106  # pragma: allowlist secret
    )
    try:
        wrong.call("getblockcount")
    except HttpError as e:
        check(e.status == 401, "a wrong credential is an HttpError carrying a 401")
    else:
        raise SmokeError("the node accepted a credential that is not its cookie")


def check_wallet_endpoint(client: BitcoinCoreRpcClient) -> None:
    """Check `/wallet/<name>` against a node with two wallets loaded.

    Two, because that is the case where the endpoint is load-bearing: a
    node with one wallet loaded answers a wallet method on the bare
    endpoint, so a single-wallet check would pass with no endpoint at all.
    With two, the bare endpoint is an rpc error and each derived client
    reaches the wallet it names -- through a name whose space and plus have
    to survive the url.
    """
    try:
        client.call("getwalletinfo")
    except RpcError as e:
        # -19 is RPC_WALLET_NOT_SPECIFIED, i.e. the node saying the request
        # named no wallet and it will not choose one
        check(e.code == -19, "a wallet method on the bare endpoint is an rpc error")
    else:
        raise SmokeError("a node with two wallets answered a wallet method unasked")
    for name in (WALLET, OTHER_WALLET):
        info = client.for_wallet(name).call("getwalletinfo")
        check(info["walletname"] == name, f"the endpoint of the wallet named {name!r}")


def check_named_params(client: BitcoinCoreRpcClient) -> None:
    """Check both parameter structures Core accepts, against one method.

    An array read positionally and an object read by name, plus Core's
    `args` convention -- an object carrying the leading positional values
    under one key. All three name the genesis block here, which is the one
    hash a regtest chain has before anything is generated.
    """
    genesis = client.call("getblockhash", [0])
    check(len(genesis) == 64, f"positional params: block 0 is {genesis}")
    check(client.call("getblockhash", {"height": 0}) == genesis, "named params")
    check(
        client.call("getblockhash", {"args": [0]}) == genesis, "Core's args convention"
    )


def check_amount_is_decimal(wallet: BitcoinCoreRpcClient) -> None:
    """Check that an amount arrives as a Decimal and is exact.

    The reply is parsed with `parse_float=Decimal`, so a bitcoin amount
    never transits binary floating point. One matured subsidy on a chain
    generated here is an exact number, which is what makes the equality
    below a check rather than a comparison with a tolerance.
    """
    balance = wallet.call("getbalance")
    check(isinstance(balance, Decimal), f"an amount decodes as a Decimal: {balance!r}")
    check(balance == SUBSIDY, f"the matured subsidy is exactly {SUBSIDY}")


def generate_chain(client: BitcoinCoreRpcClient) -> tuple[int, str, str]:
    """Generate the chain the fetcher answers are then checked against.

    Returns the height it left, the id of a wallet transaction and the id
    of a coinbase paid outside both wallets. The height is arithmetic and
    not a reading: `MATURITY_HEIGHT` blocks to the wallet, one to the
    foreign address, and one confirming the transaction sent in between.

    The wallet is created here rather than by the workflow, so that the
    whole of what a check needs is in one place, and so that a local run
    against a bitcoind of one's own leaves nothing behind but the temporary
    datadir.
    """
    for name in (WALLET, OTHER_WALLET):
        client.call("createwallet", [name])
    wallet = client.for_wallet(WALLET)
    mine_to = wallet.call("getnewaddress")
    client.call("generatetoaddress", [MATURITY_HEIGHT, mine_to])
    check_amount_is_decimal(wallet)

    # a coinbase neither wallet has any key for, which is the transaction
    # that could only be answered from the index
    foreign = b32.p2wpkh(FOREIGN_PUB_KEY, NETWORK)
    block_id = client.call("generatetoaddress", [1, foreign])[0]
    foreign_coinbase = client.call("getblock", [block_id, 1])["tx"][0]

    # the amount goes out as a string, which Core reads as an amount and
    # json carries exactly: `call` refuses a Decimal rather than rounding
    # it through float, and a float is the thing being avoided
    tx_id = wallet.call("sendtoaddress", [mine_to, "1.25"])
    client.call("generatetoaddress", [1, foreign])
    return MATURITY_HEIGHT + 2, tx_id, foreign_coinbase


def check_fetcher(
    client: BitcoinCoreRpcClient, height: int, tx_id: str, foreign_coinbase: str
) -> None:
    """Check the three fetcher answers against the generated chain.

    The height is what was generated, so the expected value is arithmetic;
    the tip hash is cross-checked against `getblockhash` at that height,
    which is a second method answering the same question. Both transactions
    come back as a serialization whose id btclib recomputes -- `get_tx`
    raising is what a wrong one looks like -- and the second of them is a
    coinbase no wallet knows, so `-txindex` is what answered it.
    """
    fetcher = BitcoinCoreFetcher(client, NETWORK)
    check(
        fetcher.get_block_count() == height, f"the tip of the generated chain: {height}"
    )
    tip = fetcher.get_best_block_id().hex()
    check(tip == client.call("getblockhash", [height]), f"the tip hash: {tip}")
    tx = fetcher.get_tx(tx_id)
    check(tx.id.hex() == tx_id, f"a wallet transaction, its id recomputed: {tx_id}")
    coinbase = fetcher.get_tx(foreign_coinbase)
    check(
        coinbase.vin[0].prev_out.is_coinbase(),
        f"a coinbase only -txindex can answer for: {foreign_coinbase}",
    )


def check_version(client: BitcoinCoreRpcClient, core_version: str) -> None:
    """Check that the node is the version this run is about.

    What it catches is a download, an unpack or a `--bitcoind` naming
    something other than what the caller thinks: every claim below is a
    claim about a version, so the version is checked before them.
    """
    subversion = client.call("getnetworkinfo")["subversion"]
    expected = f"/Satoshi:{core_version}."
    check(subversion.startswith(expected), f"the node is Core {core_version}")


def smoke(bitcoind: Path, datadir: Path, core_version: str, protocol: str) -> None:
    """Ask a node of a stated version every question the client answers."""
    with node(bitcoind, datadir) as client:
        check_version(client, core_version)
        check_cookie(datadir / DATADIR_SUBDIR / ".cookie")
        check_credentials_refused(client)
        check_named_params(client)
        height, tx_id, foreign_coinbase = generate_chain(client)
        # after the chain, so that the unknown transaction id is unknown to
        # a node with an index and blocks in it: the id is the tip hash,
        # which is a valid 32-byte id and no transaction of any chain
        unknown_tx_id = client.call("getbestblockhash")
        check_protocol(client, protocol, unknown_tx_id)
        check_wallet_endpoint(client)
        check_fetcher(client, height, tx_id, foreign_coinbase)


def print_log_tail(datadir: Path) -> None:
    """Print the end of the node's own log, a failure being about the node."""
    log = datadir / DATADIR_SUBDIR / "debug.log"
    if not log.is_file():
        return
    print(f"\nthe last {LOG_TAIL_LINES} lines of {log}:", file=sys.stderr)
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-LOG_TAIL_LINES:]:
        print(line, file=sys.stderr)


def main() -> int:
    """Run the checks against one node, and say which version answered."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--bitcoind", type=Path, required=True, help="the bitcoind to run"
    )
    parser.add_argument(
        "--core-version", required=True, help="the version it has to report, e.g. 27.2"
    )
    parser.add_argument(
        "--protocol",
        required=True,
        choices=("1.1", "2.0"),
        help="the json-rpc version that node answers",
    )
    args = parser.parse_args()
    with TemporaryDirectory(prefix="btclib-rpc-smoke-") as tmp:
        datadir = Path(tmp)
        try:
            smoke(args.bitcoind, datadir, args.core_version, args.protocol)
        except Exception:
            print_log_tail(datadir)
            raise
    print(
        f"\nCore {args.core_version} answered every check,"
        f" over json-rpc {args.protocol}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
