# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.coinstats` against `gettxoutsetinfo`, on a live regtest node.

`bogo_size` and `tx_out_ser` reproduce no wire size and no storage
format, so nothing in this tree can say either is right: a node's own
`gettxoutsetinfo` can, and it is the only thing that can.
`tests/coinstats_test.py` reads a recorded reply for the same reason,
and this is the same question put to a node of the day rather than to
the one `tests/_data/gettxoutsetinfo_regtest.json` was recorded from:
the walk below is the walk that file holds the output of, so re-recording
it is this test writing down what it collected.

The node is the session's, `-coinstatsindex=1` among its options: asking
`gettxoutsetinfo` at a named height is what makes it answer from the
index, which maintains those numbers incrementally as `CoinStats` does
rather than scanning the set once.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib.amount import sats_from_btc
from btclib.coinstats import CoinStats
from btclib.script import is_unspendable
from btclib.tx.coin import Coin
from btclib.tx.out_point import OutPoint
from btclib.tx.tx_out import TxOut

pytestmark = pytest.mark.integration

# the payload of the OP_RETURN output below, which is what puts an output
# Core's own UTXO set refuses into the chain this walks
_MESSAGE = b"btclib ISS 1623".hex()


def _unspent_outputs(
    node: BitcoinCoreRpcClient, height: int
) -> list[tuple[bytes, Coin]]:
    """Return every unspent output of the chain, the genesis one excepted.

    Read from the node and not from a wallet: `getblock` at verbosity 2
    carries every output of every transaction with the height beside it,
    and `gettxout` answers for exactly the ones Core's own set holds --
    null for one that was spent and null for one it never added, which
    is why an OP_RETURN output is picked up from the block rather than
    from that call.

    Core excludes the genesis coinbase from the set by hand and reports
    its value as `total_unspendable_amount`, so it is left out here the
    way `CoinStatsIndex` leaves it out.
    """
    outputs = []
    for block_height in range(1, height + 1):
        block = node.call("getblock", [node.call("getblockhash", [block_height]), 2])
        for position, tx in enumerate(block["tx"]):
            for out in tx["vout"]:
                script = str(out["scriptPubKey"]["hex"])
                spent = node.call("gettxout", [tx["txid"], out["n"], False]) is None
                if spent and not script.startswith("6a"):
                    continue
                value = sats_from_btc(Decimal(str(out["value"])))
                out_point = OutPoint(bytes.fromhex(str(tx["txid"])), int(out["n"]))
                coin = Coin(TxOut(value, script), int(block["height"]), position == 0)
                outputs.append((out_point.serialize(), coin))
    return outputs


def _op_return_output(node: BitcoinCoreRpcClient, wallet: Any) -> None:
    """Put an output into the chain that Core's own UTXO set will refuse."""
    raw = wallet.call(
        "createrawtransaction",
        [[], [{"data": _MESSAGE}, {wallet.call("getnewaddress"): "0.5"}]],
    )
    funded = wallet.call("fundrawtransaction", [raw])
    signed = wallet.call("signrawtransactionwithwallet", [funded["hex"]])
    node.call("sendrawtransaction", [signed["hex"]])


def test_core_reports_what_coinstats_computes(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """Build a chain, walk its unspent outputs, and match all four numbers.

    A wrong byte in `tx_out_ser` gives a digest that is a plausible 32
    bytes and a wrong fixed part in `bogo_size` a plausible integer, so
    the node answering the same numbers is the whole of the evidence
    that either is Core's.

    The digest is compared reversed: `gettxoutsetinfo` prints it through
    `uint256::GetHex`, which is display order, where `digest` is
    `MuHash3072::Finalize`'s own serialization.
    """
    miner, _ = wallets
    address = miner.call("getnewaddress")
    # 101, so that the first coinbase is mature and can be spent below
    miner.call("generatetoaddress", [101, address])
    miner.call("sendtoaddress", [miner.call("getnewaddress"), "10.0"])
    miner.call("generatetoaddress", [1, address])
    _op_return_output(node, miner)
    # every address type the node writes, so that the script-length term
    # of the bogo size is more than one script long
    for amount, address_type in enumerate(
        ("legacy", "p2sh-segwit", "bech32", "bech32m"), start=1
    ):
        target = miner.call("getnewaddress", ["", address_type])
        miner.call("sendtoaddress", [target, f"{amount}.2345678{amount}"])
    miner.call("generatetoaddress", [1, address])

    height = int(node.call("getblockcount"))
    reported = node.call("gettxoutsetinfo", ["muhash", height])

    stats = CoinStats()
    unspendable = 0
    for out_point_bytes, coin in _unspent_outputs(node, height):
        unspendable += is_unspendable(coin.tx_out.script_pub_key.script)
        stats.insert(out_point_bytes, coin)

    # the walk fed the accumulator what Core's own set refuses, so the
    # gate is what the agreement below rests on and not an empty branch
    assert unspendable
    assert stats.digest[::-1].hex() == reported["muhash"]
    assert stats.transaction_output_count == reported["txouts"]
    assert stats.bogo_size == reported["bogosize"]
    assert stats.total_amount == sats_from_btc(Decimal(str(reported["total_amount"])))
