# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on quoting an int in a refusal's message.

`str()` refuses an int past `sys.get_int_max_str_digits()` digits with
a ValueError of its own, which a message quoting such an int would
raise instead of the refusal it is building; `hex()` has no such limit,
and would write the int out in kilobytes. `utils._message_text` and
`utils._message_hex` describe such an int by sign and bit length, and
each case below reaches a message quoting a caller's integer through
one of them (issue #2394).

One file rather than a case per module, as `integer_policy_test.py` is
for the bool: the decision is one, and each case is the shortest call
that reaches a message quoting the value.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from btclib import base58, electrum, var_int
from btclib.alias import TaprootScriptTree
from btclib.b32 import bytes_from_witness_program, power_of_2_base_conversion
from btclib.block import Block, BlockHeader
from btclib.block.block_context import BlockContext
from btclib.block.block_filter import BasicBlockFilter, prevout_scripts_from_utxos
from btclib.block.header_context import (
    header_at_height,
    median_time_past,
    next_bits_required,
)
from btclib.block.mining import mine
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.block.proof_of_work import hash_rate, retarget_first_height
from btclib.coinstats import tx_out_ser
from btclib.consensus import CONSENSUS_PARAMS, subsidy
from btclib.ecc import bms, dsa
from btclib.ecc.ellswift import xdh
from btclib.exceptions import BTClibValueError
from btclib.hashes import merkle_root_from_branch, sha256, siphash
from btclib.key import PrvKeyData
from btclib.p2p.address import NetworkAddress, TimestampedNetworkAddress
from btclib.p2p.addrv2 import NetworkAddressV2, network_address
from btclib.p2p.block_filters import CFilter, GetCFilters
from btclib.p2p.compact_blocks import (
    CmpctBlock,
    GetBlockTxn,
    PrefilledTransaction,
    SendCmpct,
    reconstruct,
)
from btclib.p2p.handshake import Version
from btclib.p2p.inventory import GetBlocks, Inventory
from btclib.p2p.keepalive import Ping
from btclib.p2p.negotiation import FeeFilter, SendTxRcncl
from btclib.p2p.reject import Reject
from btclib.script import ScriptPubKey, input_script_sig, serialize, sig_hash
from btclib.script.engine import verify_input
from btclib.script.script import op_int
from btclib.script.taproot import tree_helper
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.coin import Coin
from btclib.tx.tx_context import assert_coinbase_value
from btclib.utils import bytes_from_octets, encode_num, hex_string

# an int past the default digit limit, and its negation: 16610 bits
_HUGE = 10**5000
_DESCRIPTION = "int of 16610 bits"

_TX_ID = "01" * 32
_NOW = datetime(2026, 8, 4, tzinfo=UTC)
_SCRIPT_TREE: TaprootScriptTree = [(0xC0, ["OP_1"])]
_PUB_KEY = PrvKeyData(1).pub
_P2PKH_PREVOUT = TxOut(1, ScriptPubKey.p2pkh(_PUB_KEY))


def _tx(version: Any = 1, lock_time: Any = 0) -> Tx:
    return Tx(
        version,
        lock_time,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


def _header(version: Any = 1, nonce: Any = 1) -> BlockHeader:
    return BlockHeader(
        version,
        "00" * 32,
        "11" * 32,
        datetime(2009, 1, 9, tzinfo=UTC),
        "1d00ffff",
        nonce,
    )


def _unchecked_prefilled(index: int) -> PrefilledTransaction:
    return PrefilledTransaction(index, _tx(), check_validity=False)


def _verify_unchecked(
    script: list[Any], version: int = 2, lock_time: int = 0, sequence: int = 0
) -> None:
    """Run a script against a transaction no field of which was checked."""
    tx_in = TxIn(OutPoint(_TX_ID, 0), b"", sequence, check_validity=False)
    tx = Tx(version, lock_time, [tx_in], [TxOut(0, b"")], check_validity=False)
    verify_input([TxOut(1, serialize(script))], tx, 0)


def _unresolved_prevout(vout: int) -> object:
    """Ask for the script of an outpoint no field of which was checked."""
    prev_out = OutPoint(_TX_ID, vout, check_validity=False)
    tx_in = TxIn(prev_out, b"", 0, check_validity=False)
    coinbase = Tx(vin=[TxIn()], vout=[TxOut(0, b"")], check_validity=False)
    spend = Tx(vin=[tx_in], vout=[TxOut(0, b"")], check_validity=False)
    block = Block(_header(), [coinbase, spend], check_validity=False)
    return prevout_scripts_from_utxos(block, {})


def _reconstruct(index: int) -> object:
    prefilled = [_unchecked_prefilled(index)]
    return reconstruct(CmpctBlock(_header(), 0, [1], prefilled, check_validity=False))


# what each call is handed, and the shortest call that reaches the
# message quoting it. A negative value where only the lower bound quotes,
# `_HUGE` where the upper one does
_CASES: list[tuple[str, Any, Callable[[Any], object]]] = [
    ("var_int", _HUGE, var_int.serialize),
    ("negative var_int", -_HUGE, var_int.serialize),
    ("var_int max_size", -_HUGE, lambda v: var_int.parse(b"\x01", max_size=v)),
    ("hex string", -_HUGE, hex_string),
    ("output size", _HUGE, lambda v: bytes_from_octets(b"x", v)),
    (
        "base58 output size",
        _HUGE,
        lambda v: base58.decode(base58.encode(b"\x00" * 20), v),
    ),
    (
        "electrum request id",
        _HUGE,
        lambda v: electrum.decode_response(b'{"id": 1, "result": 0}\n', v),
    ),
    (
        "addrv2 network id without an ip",
        _HUGE,
        lambda v: network_address(NetworkAddressV2(network_id=v, check_validity=False)),
    ),
    ("script number", _HUGE, encode_num),
    ("transaction version", _HUGE, _tx),
    ("transaction lock time", _HUGE, lambda v: _tx(lock_time=v)),
    ("outpoint vout", _HUGE, lambda v: OutPoint(_TX_ID, v)),
    ("input sequence", _HUGE, lambda v: TxIn(OutPoint(_TX_ID, 0), b"", v)),
    ("coin height", -_HUGE, lambda v: Coin(TxOut(1, b""), v, is_coinbase=False)),
    (
        "coinstats height",
        _HUGE,
        lambda v: tx_out_ser(
            OutPoint(_TX_ID, 0).serialize(), Coin(TxOut(1, b""), v, False)
        ),
    ),
    (
        "coinbase value ceiling",
        -_HUGE,
        lambda v: assert_coinbase_value(_tx(), subsidy=0, fees=v),
    ),
    ("header version", _HUGE, _header),
    ("negative header version", -_HUGE, _header),
    ("header nonce", _HUGE, lambda v: _header(nonce=v)),
    ("subsidy height", -_HUGE, subsidy),
    ("halving interval", -_HUGE, lambda v: subsidy(0, v)),
    ("block height", -_HUGE, lambda v: BlockContext(v, _NOW)),
    ("bip34 height", -_HUGE, lambda v: BlockContext(1, _NOW, v)),
    ("median time past", -_HUGE, lambda v: BlockContext(1, _NOW, 0, v)),
    (
        "median time past height",
        -_HUGE,
        lambda v: median_time_past(_header(), v, lambda h: h),
    ),
    (
        "header height",
        -_HUGE,
        lambda v: header_at_height(_header(), v, 0, lambda h: h),
    ),
    ("target height", _HUGE, lambda v: header_at_height(_header(), 0, v, lambda h: h)),
    (
        "parent height",
        -_HUGE,
        lambda v: next_bits_required(
            _header(), _header(), v, lambda h: h, CONSENSUS_PARAMS["mainnet"]
        ),
    ),
    ("mining max tries", -_HUGE, lambda v: mine(_header(), v)),
    ("retarget height", _HUGE, retarget_first_height),
    ("hash rate difficulty", -_HUGE, lambda v: hash_rate(v, 600)),
    ("hash rate timespan", -_HUGE, lambda v: hash_rate(1, v)),
    ("hash rate block count", -_HUGE, lambda v: hash_rate(1, 600, v)),
    (
        "block filter element count",
        _HUGE,
        lambda v: BasicBlockFilter(b"\x00" * 32, v),
    ),
    ("unresolved prevout vout", _HUGE, _unresolved_prevout),
    ("partial merkle tree count", _HUGE, PartialMerkleTree),
    (
        "merkle leaf index",
        -_HUGE,
        lambda v: merkle_root_from_branch(b"\x00" * 32, [], v, sha256),
    ),
    ("siphash key", _HUGE, lambda v: siphash(v, 0, b"")),
    ("base conversion value", _HUGE, lambda v: power_of_2_base_conversion([v], 8, 5)),
    ("base conversion width", -_HUGE, lambda v: power_of_2_base_conversion([1], v, 8)),
    ("witness version", _HUGE, lambda v: bytes_from_witness_program(v, b"\x00" * 20)),
    ("op_int", _HUGE, op_int),
    ("multisig threshold", _HUGE, lambda v: ScriptPubKey.p2ms(v, [_PUB_KEY])),
    ("taproot leaf version", _HUGE, lambda v: tree_helper([(v, ["OP_1"])])),
    ("taproot leaf index", _HUGE, lambda v: input_script_sig(None, _SCRIPT_TREE, v)),
    ("sig_hash type", _HUGE, sig_hash.assert_valid_hash_type),
    (
        "sig_hash type width",
        _HUGE,
        lambda v: sig_hash.legacy(b"", _tx(), 0, v),
    ),
    (
        "sig_hash input index",
        _HUGE,
        lambda v: sig_hash.taproot(_tx(), v, [_P2PKH_PREVOUT], 1, 0, b"", b""),
    ),
    (
        "taproot sig_hash type",
        _HUGE,
        lambda v: sig_hash.taproot(_tx(), 0, [_P2PKH_PREVOUT], v, 0, b"", b""),
    ),
    (
        "sig_hash extension flag",
        _HUGE,
        lambda v: sig_hash.taproot(_tx(), 0, [_P2PKH_PREVOUT], 1, v, b"", b""),
    ),
    ("sig_hash amount", _HUGE, lambda v: sig_hash.segwit_v0(b"", _tx(), 0, 1, v)),
    (
        "negative OP_CODESEPARATOR index",
        -_HUGE,
        lambda v: sig_hash.from_tx([_P2PKH_PREVOUT], _tx(), 0, 1, codesep_index=v),
    ),
    (
        "OP_CODESEPARATOR index",
        _HUGE,
        lambda v: sig_hash.from_tx([_P2PKH_PREVOUT], _tx(), 0, 1, codesep_index=v),
    ),
    ("ellswift party", _HUGE, lambda v: xdh(b"\x00" * 64, b"\x00" * 64, 1, v)),
    (
        "bms recovery flag",
        _HUGE,
        lambda v: bms.Sig(v, dsa.Sig(1, 1)),
    ),
    ("feefilter rate", _HUGE, lambda v: FeeFilter(feerate=v)),
    ("sendtxrcncl version", _HUGE, lambda v: SendTxRcncl(version=v)),
    ("sendtxrcncl salt", _HUGE, lambda v: SendTxRcncl(salt=v)),
    ("address services", _HUGE, lambda v: NetworkAddress(services=v)),
    ("address port", _HUGE, lambda v: NetworkAddress(port=v)),
    ("address timestamp", _HUGE, TimestampedNetworkAddress),
    ("addrv2 port", _HUGE, lambda v: NetworkAddressV2(port=v)),
    ("version message version", _HUGE, Version),
    ("sendcmpct version", _HUGE, lambda v: SendCmpct(version=v)),
    ("cmpctblock nonce", _HUGE, lambda v: CmpctBlock(_header(), v)),
    ("cmpctblock short id", _HUGE, lambda v: CmpctBlock(_header(), 0, [v])),
    ("prefilled index", _HUGE, lambda v: PrefilledTransaction(v, _tx())),
    (
        "prefilled previous index",
        _HUGE,
        lambda v: PrefilledTransaction(0, _tx()).serialize(v),
    ),
    (
        "unchecked prefilled index",
        -_HUGE,
        lambda v: _unchecked_prefilled(v).serialize(0, check_validity=False),
    ),
    ("unchecked prefilled order", -_HUGE, _reconstruct),
    ("unchecked prefilled position", _HUGE, _reconstruct),
    ("getblocktxn index", _HUGE, lambda v: GetBlockTxn(indexes=[v])),
    ("inventory type code", _HUGE, lambda v: Inventory(type_code=v)),
    ("locator version", _HUGE, lambda v: GetBlocks(version=v)),
    ("ping nonce", _HUGE, lambda v: Ping(nonce=v)),
    ("reject code", _HUGE, lambda v: Reject(code=v)),
    ("filter start height", _HUGE, lambda v: GetCFilters(start_height=v)),
    ("filter type", _HUGE, lambda v: GetCFilters(filter_type=v)),
    (
        "unchecked lock time against a height",
        _HUGE,
        lambda v: _verify_unchecked(["OP_1", "OP_CHECKLOCKTIMEVERIFY"], lock_time=v),
    ),
    (
        "unchecked lock time against a timestamp",
        -_HUGE,
        lambda v: _verify_unchecked(
            [500_000_000, "OP_CHECKLOCKTIMEVERIFY"], lock_time=v
        ),
    ),
    (
        "unchecked lock time below the script's",
        -_HUGE,
        lambda v: _verify_unchecked(["OP_0", "OP_CHECKLOCKTIMEVERIFY"], lock_time=v),
    ),
    (
        "unchecked version against a relative lock time",
        -_HUGE,
        lambda v: _verify_unchecked(["OP_1", "OP_CHECKSEQUENCEVERIFY"], version=v),
    ),
    (
        "unchecked sequence against a relative lock time",
        # bits 22 and 31 clear, so that the unit is what differs
        _HUGE,
        lambda v: _verify_unchecked([1 << 22, "OP_CHECKSEQUENCEVERIFY"], sequence=v),
    ),
    (
        "unchecked filter type",
        _HUGE,
        lambda v: CFilter(filter_type=v, check_validity=False).basic_filter,
    ),
]


@pytest.mark.parametrize(
    "value, call",
    [(case[1], case[2]) for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_a_refusal_describes_an_int_str_cannot_write(
    value: int, call: Callable[[Any], object]
) -> None:
    """Refused as this library's error, the int named by its bit length."""
    sign = "a negative " if value < 0 else "an "
    with pytest.raises(BTClibValueError, match=sign + _DESCRIPTION):
        call(value)
