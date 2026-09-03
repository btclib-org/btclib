# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the integration tests need, and what makes them skip.

Two switches, and both have to be on. `BTCLIB_INTEGRATION` in the
environment is the opt-in: these tests start programs, listen on a
socket and write to disk, which is not what `uv run pytest` should do to
somebody who asked for the unit suite. The second is the program itself
-- `bitcoind` here -- because an opt-in that fails for a missing binary
would report a defect that is not one.

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
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib.amount import sats_from_btc
from btclib.descriptors import Descriptor, add_checksum, parse
from btclib.psbt.psbt import Psbt, extract_tx, finalize
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# how long the node is given to answer its first rpc call: a regtest
# bitcoind is up in well under a second on any machine that can run this
# suite, and the wait is a poll rather than a sleep, so this bounds only
# the failure case
_STARTUP_TIMEOUT = 30.0


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
        pytest.skip("set BTCLIB_INTEGRATION=1 to run the integration tests")
    path = os.environ.get("BTCLIB_BITCOIND") or shutil.which("bitcoind")
    if path is None:
        pytest.skip("no bitcoind: name one in BTCLIB_BITCOIND or put it on PATH")
    return path


@pytest.fixture(scope="session")
def p2p_port() -> int:
    """Return the port `node` below binds its p2p listener to.

    A fixture of its own rather than a value read off `node` after the
    fact: a p2p test needs the number before the node exists, to build
    the `addr_recv` its own `Version` names, and a session-scoped
    fixture is what lets both `node` and a p2p test request the same
    port without either constructing it.
    """
    return _free_port()


@pytest.fixture(scope="session")
def node(
    bitcoind_path: str, p2p_port: int, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[BitcoinCoreRpcClient]:
    """Yield an rpc client of a regtest node started for this session.

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
    """
    datadir = tmp_path_factory.mktemp("regtest")
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603
        [
            bitcoind_path,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={port}",
            "-rpcbind=127.0.0.1",
            f"-bind=127.0.0.1:{p2p_port}",
            "-natpmp=0",
            "-discover=0",
            "-listenonion=0",
            "-fallbackfee=0.0002",
            # so that `getrawtransaction` answers for a confirmed
            # transaction of any wallet: what a psbt needs is the previous
            # transaction whole, and a node without the index answers only
            # for what is still in its mempool
            "-txindex=1",
            "-printtoconsole=0",
        ],
    )
    client = BitcoinCoreRpcClient(
        f"http://127.0.0.1:{port}", cookie_path=datadir / "regtest" / ".cookie"
    )
    try:
        _wait_for(client, process)
        yield client
    finally:
        process.terminate()
        process.wait(timeout=_STARTUP_TIMEOUT)


def _wait_for(client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes]) -> None:
    """Poll until the node answers, or fail with what it did instead."""
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
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


def as_regtest(descriptor: Descriptor) -> Descriptor:
    """Return the descriptor read again as a regtest one.

    Version bytes cannot say which test chain a key is for -- btclib's
    test networks share them, which `bip44` documents where it refuses to
    guess -- so `account_descriptors` answers with the first,
    testnet, and its addresses are `tb1`. The scripts are the same
    scripts; what differs is the human encoding, and regtest spells it
    `bcrt1`. Reading the text back with the network named is how a caller
    gets the addresses this node prints.
    """
    return parse(add_checksum(str(descriptor)), "regtest")


def fund(miner: BitcoinCoreRpcClient, address: str, amount: str = "1.5") -> str:
    """Mine a spendable balance, pay an address, and confirm the payment.

    101 blocks because a coinbase output is spendable after 100, and the
    amount is a string because json carries no exact decimal -- the rpc
    client refuses a `Decimal` rather than rounding one.
    """
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    tx_id = miner.call("sendtoaddress", [address, amount])
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    return str(tx_id)


def spending_psbt(
    node: BitcoinCoreRpcClient,
    utxo: dict[str, Any],
    receive: Descriptor,
    change: Descriptor,
    pay_to: str,
    fee: int = 1_000,
) -> Psbt:
    """Return the psbt spending one utxo: a payment out, and change back.

    Built and updated by btclib alone -- the node is asked for the
    previous transaction and for nothing else -- so what a signer sees is
    a psbt no Core call composed.
    """
    amount = sats_from_btc(Decimal(str(utxo["amount"])))
    prev_tx = Tx.parse(node.call("getrawtransaction", [utxo["txid"]]))
    tx = Tx(
        vin=[TxIn(OutPoint(bytes.fromhex(str(utxo["txid"])), int(utxo["vout"])))],
        vout=[
            TxOut(amount // 2, parse(f"addr({pay_to})", "regtest").script_pub_key()),
            TxOut(amount - amount // 2 - fee, change.script_pub_key(0)),
        ],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    psbt = receive.update_psbt_input(psbt, 0, 0)
    return change.update_psbt_output(psbt, 1, 0)


def broadcast(node: BitcoinCoreRpcClient, psbt: Psbt) -> str:
    """Finalize a signed psbt and hand the transaction to the network.

    Which is the oracle these tests are here for: a signature that does
    not verify, a witness assembled wrong or a fee that is not there are
    all this call failing.
    """
    final = extract_tx(finalize(psbt), check_validity=True)
    # with the witness, which is the whole point of what was just signed:
    # `serialize` asks rather than assuming, a txid being the other one
    raw = final.serialize(include_witness=True).hex()
    tx_id = str(node.call("sendrawtransaction", [raw]))
    assert tx_id == final.id.hex()
    return tx_id
