# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.policy` against `testmempoolaccept`, on a live regtest node.

Each transaction is put to the node and to btclib, and the two must
agree on whether it is standard and, where it is not, on the reason.
Core checks `IsStandardTx` before it looks the inputs up, so a
transaction spending outputs that do not exist is refused for its
standardness first and for "missing-inputs" only once it is standard.
`AreInputsStandard` and `IsWitnessStandard` need the outputs spent, so
those transactions spend outputs mined here with `generateblock`, which
takes what the mempool would refuse.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib import b32
from btclib.amount import sats_from_btc
from btclib.exceptions import BTClibValueError
from btclib.policy import (
    MAX_P2SH_SIGOPS,
    MAX_TX_LEGACY_SIGOPS,
    are_inputs_standard,
    assert_standard_tx,
    is_witness_standard,
)
from btclib.script import serialize
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from tests.policy_test import (
    ANCHOR,
    CONTROL_BLOCK,
    KEY_1,
    KEY_2,
    KEY_3,
    OP_1,
    OP_RETURN,
    SIG,
    TAPSCRIPT,
    X_ONLY,
    _max_sigops_redeem_script,
    _multisig,
    _p2pk,
    _p2pkh,
    _p2sh,
    _p2tr,
    _p2wpkh,
    _p2wsh,
)

pytestmark = pytest.mark.integration

# OP_TRUE as a witness script: what the coins mined here pay to, so that
# spending them needs no key
_OP_TRUE = b"\x51"
_VALUE = 100_000
_PAD = b"\x01"


def _standardness_cases() -> list[Tx]:
    """Return transactions IsStandardTx judges, spending nothing that exists."""

    def tx(
        version: int = 2,
        script_sig: bytes = serialize([b"\x00" * 65]),
        vout: list[TxOut] | None = None,
    ) -> Tx:
        vin = [TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 0xFFFFFFFF)]
        return Tx(version, 0, vin, vout or [TxOut(90_000, _p2pkh(KEY_1))])

    cases = [
        tx(),
        tx(version=0),
        tx(version=4),
        tx(version=0xFFFFFFFF),
        tx(script_sig=serialize([b"\x00" * 1647])),
        tx(script_sig=serialize([b"\x00" * 1648])),
        tx(script_sig=serialize(["OP_NOP"])),
        tx(script_sig=serialize(["OP_1", "OP_RESERVED"])),
        tx(vout=[TxOut(90_000, OP_1)]),
        tx(vout=[TxOut(90_000, _multisig(1, [KEY_1]))]),
        tx(vout=[TxOut(90_000, _multisig(1, [KEY_1, KEY_2, KEY_3, KEY_1]))]),
        tx(vout=[TxOut(0, OP_RETURN + OP_RETURN)]),
        tx(vout=[TxOut(0, OP_RETURN + serialize(["OP_RESERVED", "OP_16"]))]),
        tx(vout=[TxOut(545, _p2pkh(KEY_1))]),
        tx(vout=[TxOut(545, _p2pkh(KEY_1)), TxOut(293, _p2wpkh(KEY_1))]),
        tx(vout=[TxOut(546, _p2pkh(KEY_1)), TxOut(294, _p2wpkh(KEY_1))]),
        tx(vout=[TxOut(239, ANCHOR), TxOut(239, ANCHOR)]),
    ]
    # 400000 weight units, and 400004
    for size in (19, 20):
        vin = [TxIn(OutPoint(b"\x01" * 32, i), b"", 0xFFFFFFFF) for i in range(2438)]
        payload = OP_RETURN + serialize([b"\x00" * size])
        cases.append(Tx(2, 0, vin, [TxOut(1000, payload)]))
    return cases


def _reason(node: BitcoinCoreRpcClient, tx: Tx) -> str | None:
    """Return Core's reject reason, None for a transaction it accepts."""
    hex_tx = tx.serialize(include_witness=True).hex()
    result: dict[str, Any] = node.call("testmempoolaccept", [[hex_tx]])[0]
    return None if result["allowed"] else str(result["reject-reason"])


def test_is_standard_tx_agrees_with_core(node: BitcoinCoreRpcClient) -> None:
    """Core gives btclib's reason, or "missing-inputs" where btclib has none."""
    reasons = []
    for tx in _standardness_cases():
        try:
            assert_standard_tx(tx)
        except BTClibValueError as e:
            expected = str(e)
        else:
            expected = "missing-inputs"
        reasons.append(expected)
        assert _reason(node, tx) == expected, tx
    # both answers are asked, every reason a default node can give included
    assert set(reasons) == {
        "missing-inputs",
        "version",
        "tx-size",
        "scriptsig-size",
        "scriptsig-not-pushonly",
        "scriptpubkey",
        "dust",
    }


def _input_cases() -> list[tuple[list[bytes], list[bytes], list[list[bytes]]]]:
    """Return (prevouts, script_sigs, witnesses) for each spend to judge."""
    fifteen = serialize(
        ["OP_1"] + [KEY_1] * MAX_P2SH_SIGOPS + ["OP_15", "OP_CHECKMULTISIG"]
    )
    sixteen = serialize(["OP_16", "OP_CHECKMULTISIG"])
    drop_99 = serialize(["OP_DROP"] * 99)
    drop_100 = serialize(["OP_DROP"] * 100)
    script_3600 = serialize([_PAD * 59] * 59 + ["OP_DROP"] * 60)
    script_3601 = serialize([_PAD * 59] * 59 + ["OP_DROP"] * 61)
    single = [
        (_p2pkh(KEY_1), serialize([SIG, KEY_1]), []),
        (OP_1, b"", []),
        (serialize(["OP_2", X_ONLY]), b"", []),
        (_p2sh(fifteen), serialize([fifteen]), []),
        (_p2sh(sixteen), serialize([sixteen]), []),
        (_p2sh(_OP_TRUE), b"", []),
        (ANCHOR, b"", []),
        (ANCHOR, b"", [_PAD]),
        (_p2pkh(KEY_1), serialize([SIG, KEY_1]), [_PAD]),
        (_p2wpkh(KEY_1), b"", [_PAD * 81, KEY_1]),
        (_p2wsh(drop_100), b"", [_PAD] * 101 + [drop_100]),
        (_p2wsh(drop_99), b"", [_PAD * 80] * 100 + [drop_99]),
        (_p2wsh(drop_99), b"", [_PAD * 81] * 100 + [drop_99]),
        (_p2wsh(script_3600), b"", [_PAD, _PAD, script_3600]),
        (_p2wsh(script_3601), b"", [_PAD, _PAD, _PAD, script_3601]),
        (
            _p2sh(_p2wsh(drop_100)),
            serialize([_p2wsh(drop_100)]),
            [_PAD] * 101 + [drop_100],
        ),
        (_p2tr(X_ONLY), b"", [_PAD * 64]),
        (_p2tr(X_ONLY), b"", [_PAD * 64, b"\x50"]),
        (_p2tr(X_ONLY), b"", [TAPSCRIPT, b""]),
        (_p2tr(X_ONLY), b"", [_PAD * 80, TAPSCRIPT, CONTROL_BLOCK]),
        (_p2tr(X_ONLY), b"", [_PAD * 81, TAPSCRIPT, CONTROL_BLOCK]),
        (_p2tr(X_ONLY), b"", [_PAD * 81, TAPSCRIPT, b"\xc2" + X_ONLY]),
    ]
    cases = [
        ([prevout], [script_sig], [stack]) for prevout, script_sig, stack in single
    ]

    # BIP54: 166 p2sh inputs of 15 sigops each and p2pk ones, 2500 and 2501
    redeem_script = _max_sigops_redeem_script()
    p2sh_count = MAX_TX_LEGACY_SIGOPS // MAX_P2SH_SIGOPS
    for p2pk_count in (10, 11):
        prevouts = [_p2sh(redeem_script)] * p2sh_count + [_p2pk(KEY_1)] * p2pk_count
        script_sigs = [serialize([redeem_script])] * p2sh_count + [b""] * p2pk_count
        cases.append((prevouts, script_sigs, [[]] * len(prevouts)))
    return cases


def _mine_outputs(node: BitcoinCoreRpcClient, script_pub_keys: list[bytes]) -> bytes:
    """Mine a transaction paying each script `_VALUE`, and return its id.

    It spends a coinbase paid to OP_TRUE, mature at the 101st block, and
    goes into a block with `generateblock`, which checks consensus only.
    """
    address = b32.p2wsh(_OP_TRUE, "regtest")
    hashes = node.call("generatetoaddress", [101, address])
    coinbase = node.call("getblock", [hashes[0], 2])["tx"][0]
    value = sats_from_btc(Decimal(str(coinbase["vout"][0]["value"])))
    vin = [
        TxIn(
            OutPoint(bytes.fromhex(coinbase["txid"]), 0),
            b"",
            0xFFFFFFFF,
            Witness([_OP_TRUE]),
        )
    ]
    vout = [TxOut(_VALUE, script) for script in script_pub_keys]
    change = value - _VALUE * len(vout) - 100_000
    vout.append(TxOut(change, _p2wsh(_OP_TRUE)))
    funding = Tx(2, 0, vin, vout)
    node.call(
        "generateblock", [address, [funding.serialize(include_witness=True).hex()]]
    )
    return funding.id


def test_inputs_agree_with_core(node: BitcoinCoreRpcClient) -> None:
    """Core refuses the inputs or the witness exactly where btclib does."""
    cases = _input_cases()
    script_pub_keys = [prevout for prevouts, _, _ in cases for prevout in prevouts]
    txid = _mine_outputs(node, script_pub_keys)

    verdicts = []
    n = 0
    for prevouts, script_sigs, witnesses in cases:
        vin = []
        for script_sig, stack in zip(script_sigs, witnesses, strict=True):
            vin.append(TxIn(OutPoint(txid, n), script_sig, 0xFFFFFFFF, Witness(stack)))
            n += 1
        tx = Tx(2, 0, vin, [TxOut(50_000, _p2wpkh(KEY_2))])
        assert_standard_tx(tx)
        tx_outs = [TxOut(_VALUE, prevout) for prevout in prevouts]
        if not are_inputs_standard(tx_outs, tx):
            expected = "bad-txns-nonstandard-inputs"
        elif tx.is_segwit and not is_witness_standard(tx_outs, tx):
            expected = "bad-witness-nonstandard"
        else:
            expected = None
        verdicts.append(expected)

        reason = _reason(node, tx)
        policy = {"bad-txns-nonstandard-inputs", "bad-witness-nonstandard"}
        assert (reason if reason in policy else None) == expected, (tx, reason)
    # each of the three answers is asked
    assert set(verdicts) == {
        None,
        "bad-txns-nonstandard-inputs",
        "bad-witness-nonstandard",
    }
