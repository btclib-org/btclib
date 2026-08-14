# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The whole flow against a real node: btclib builds, Core agrees.

Every part of issue #381's pure half meets its counterparty here, and the
counterparty is the one that decides:

- `descriptors.account_descriptors` builds the pair, and Bitcoin Core
  imports it through `core_import.account_import_requests` — so Core's
  own parser, checksum rule and range handling are what accept it;
- and the range handling is the node's alone: `core_import.widened_range`
  claims Core widens a ranged import to its keypool and then refuses to be
  narrowed, which nothing but a node can confirm;
- Core derives the addresses of that account itself and pays one, so the
  scripts btclib computes are the scripts Core watches;
- btclib builds the psbt, updates both halves, and
  `psbt_signer.request_signatures` sends it to a `SoftwareSigner` and
  checks what comes back;
- `psbt.finalize` assembles the witness, and the network is the oracle:
  `sendrawtransaction` accepts it or the test fails.

A unit test can say a signature verifies; only this can say a node
relays the transaction it is in.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib.amount import sats_from_btc
from btclib.bip32.bip32 import rootxprv_from_seed
from btclib.core_import import (
    DEFAULT_RANGE,
    account_import_requests,
    assert_imported,
    import_request,
    watched_range,
    widened_range,
)
from btclib.exceptions import BTClibRuntimeError
from btclib.network import NETWORKS
from btclib.psbt_signer import SoftwareSigner, export_account, request_signatures
from tests.integration.conftest import as_regtest, broadcast, fund, spending_psbt

pytestmark = pytest.mark.integration

# regtest keys, so that the coin type of the account path is 1 as BIP44
# has it for every test chain. The seed is this file's own: a key that
# signs for coins mined in a directory pytest deletes
ROOT = rootxprv_from_seed("0f" * 16, NETWORKS["regtest"].bip32_prv)
# an account per test, and a test added here wants one of its own too.
# The node is the session's, so two tests sharing an account derive the
# same first address, and the wallet the second one creates sees what the
# first paid to it: `account_import_requests` asks for `now`, which does
# not mean "scan nothing" -- Core rescans from that timestamp less its
# two-hour window, and a regtest chain minted seconds ago lies inside it
# whole. Different accounts are different addresses, and `listunspent`
# then answers for the test that asked
RELAY_ACCOUNT = "m/84h/1h/0h"
DECODE_ACCOUNT = "m/84h/1h/1h"
RANGE_ACCOUNT = "m/84h/1h/2h"


def test_core_imports_what_btclib_exports_and_relays_what_it_signs(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """The pure half of issue #381, end to end, with a node as the judge."""
    miner, watcher = wallets
    signer = SoftwareSigner(ROOT)
    receive, change = export_account(signer, RELAY_ACCOUNT)

    # Core imports the pair, and answers one result per request
    requests = account_import_requests(receive, change, key_range=(0, 20))
    results = watcher.call("importdescriptors", [requests])
    assert [result["success"] for result in results] == [True, True]
    assert not [result for result in results if result.get("error")]

    # and derives the same addresses from them as btclib does
    derived = node.call("deriveaddresses", [requests[0]["desc"], [0, 2]])
    assert derived == [as_regtest(receive).address(index) for index in range(3)]

    # the rest of the world pays the first receiving address
    paid = fund(miner, as_regtest(receive).address(0))

    # which the watch-only wallet sees, because the descriptor said so
    unspent = watcher.call("listunspent", [1, 9999999])
    assert [utxo["txid"] for utxo in unspent] == [paid]
    utxo = unspent[0]
    assert utxo["desc"].startswith("wpkh([")

    psbt = spending_psbt(node, utxo, receive, change, miner.call("getnewaddress"))
    signed = request_signatures(signer, psbt)

    # the network is the oracle: it accepts the transaction or it does not
    tx_id = broadcast(node, signed)
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    assert node.call("getrawtransaction", [tx_id, True])["confirmations"] == 1

    # and the change came back to the wallet, which is what the output
    # updater's exact match is for: Core recognised it as its own
    change_utxo = [
        candidate
        for candidate in watcher.call("listunspent", [1, 9999999])
        if candidate["txid"] == tx_id
    ]
    assert len(change_utxo) == 1
    assert change_utxo[0]["address"] == as_regtest(change).address(0)
    # and Core names the path it came down: the change chain, index zero,
    # which is the descriptor imported as `internal`
    assert "/1/0]" in change_utxo[0]["desc"]


def test_core_widens_a_range_to_its_keypool_and_refuses_to_be_narrowed(
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """The rule `widened_range` is written against, with the node as judge.

    Every claim of that docstring is a claim about Core and about nothing
    in this library: it widens a ranged import to its keypool whatever
    range was asked for, it refuses any later import that would narrow
    what it widened to, and the refusal arrives as `success: false` inside
    a reply rather than as a failed call. A unit test can only restate
    them; this is what can be wrong about them.
    """
    watcher = wallets[1]
    receive = export_account(SoftwareSigner(ROOT), RANGE_ACCOUNT)[0]

    # nothing is watched before the first import
    assert watched_range(receive, watcher.call("listdescriptors")) is None

    # which asks for one index, and Core widens it to a keypool's worth
    one = import_request(receive, active=False, key_range=(0, 0))
    assert_imported([one], watcher.call("importdescriptors", [[one]]))
    watched = watched_range(receive, watcher.call("listdescriptors"))
    assert watched == DEFAULT_RANGE
    # so `widened_range` asks for that from the start, and the reply then
    # states the indexes the caller would otherwise have to assume
    assert widened_range((0, 0)) == watched

    # a span grown past the keypool is imported over the union of the two
    wider = import_request(receive, active=False, key_range=widened_range((0, 1500)))
    assert_imported([wider], watcher.call("importdescriptors", [[wider]]))
    watched = watched_range(receive, watcher.call("listdescriptors"))
    assert watched == (0, 1500)

    # and the import that would narrow it back is refused, inside a reply
    narrow = import_request(receive, active=False, key_range=(0, 999))
    with pytest.raises(BTClibRuntimeError, match="import refused for wpkh"):
        assert_imported([narrow], watcher.call("importdescriptors", [[narrow]]))
    # where the same wanted range, widened by what the wallet answered, is
    # the import that goes through: a span already inside the range is
    # nothing left to import, and not a narrowing of it
    again = import_request(
        receive, active=False, key_range=widened_range((0, 999), watched)
    )
    assert_imported([again], watcher.call("importdescriptors", [[again]]))
    assert watched_range(receive, watcher.call("listdescriptors")) == watched


def test_the_change_output_is_what_the_node_calls_change(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """`decodepsbt` reads back the fields the output updater wrote.

    Which is the interoperability half of that work package: a key origin
    written by btclib is one Core reads, and the descriptor it belongs to
    is the change chain the wallet imported as `internal`.
    """
    miner, watcher = wallets
    signer = SoftwareSigner(ROOT)
    receive, change = export_account(signer, DECODE_ACCOUNT)
    watcher.call(
        "importdescriptors",
        [account_import_requests(receive, change, key_range=(0, 5))],
    )

    fund(miner, as_regtest(receive).address(0), "0.5")
    utxo = watcher.call("listunspent", [1, 9999999])[0]

    psbt = spending_psbt(node, utxo, receive, change, miner.call("getnewaddress"))
    decoded = node.call("decodepsbt", [psbt.b64encode()])

    ((origin,),) = [output["bip32_derivs"] for output in decoded["outputs"] if output]
    assert origin["master_fingerprint"] == signer.master_fingerprint.hex()
    assert origin["path"] == f"{DECODE_ACCOUNT}/1/0"
    assert decoded["outputs"][0] == {}

    # and the amount is what btclib put there, read back by Core
    assert sats_from_btc(Decimal(str(decoded["tx"]["vout"][1]["value"]))) == (
        psbt.tx.vout[1].value
    )
