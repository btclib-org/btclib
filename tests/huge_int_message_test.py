# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on quoting an int in a refusal's message.

`utils._message_text` describes every int by its sign and bit length,
and `utils._message_field` describes one wider than its field, so that
no digit of a key passed in an int's place reaches the message (issue
#2998). The description is also what keeps an int `str()` cannot write,
one past `sys.get_int_max_str_digits()` digits, from raising a
ValueError of its own in place of the refusal (issue #2394). Each case
below reaches a message quoting a caller's integer through one of them.

One file rather than a case per module, as `integer_policy_test.py` is
for the bool: the decision is one, and each case is the shortest call
that reaches a message quoting the value.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from io import BytesIO
from typing import Any

import pytest
from ecc import dsa

from btclib import bms, compressor, obfuscation, var_int
from btclib.alias import TaprootScriptTree
from btclib.amount import valid_btc_amount, valid_sats_amount
from btclib.b32 import bytes_from_witness_program, power_of_2_base_conversion
from btclib.block import Block, BlockHeader
from btclib.block.block_context import BlockContext
from btclib.block.block_filter import BasicBlockFilter
from btclib.block.header_context import (
    assert_not_timewarp,
    header_at_height,
    median_time_past,
    next_bits_required,
)
from btclib.block.mining import mine
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.block.proof_of_work import hash_rate, retarget_first_height
from btclib.coinstats import tx_out_ser
from btclib.consensus import CONSENSUS_PARAMS, subsidy
from btclib.exceptions import BTClibException, BTClibValueError
from btclib.fee import FeeRate, fee_from_vsize, package_fee
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
from btclib.p2p.headers_sync import ChainStart, anti_dos_work_threshold
from btclib.p2p.inventory import GetBlocks, Inventory
from btclib.p2p.keepalive import Ping
from btclib.p2p.negotiation import FeeFilter, SendTxRcncl
from btclib.p2p.reject import Reject
from btclib.policy import sig_ops_adjusted_weight
from btclib.script import ScriptPubKey, input_script_sig, serialize, sig_hash
from btclib.script.engine import NO_FLAGS, verify_input
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.script import op_int, read_op_code
from btclib.script.taproot import leaf_hash, tree_from_weights, tree_helper
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.coin import Coin
from btclib.tx.tx_context import assert_bip54_coinbase, assert_coinbase_value
from btclib.utils import bytes_from_octets, encode_num, read_exactly
from btclib.utreexo import UpdateData
from tests.secret_free import assert_secret_free, chained, text_of

# an int past the default digit limit, and its negation: 16610 bits
_HUGE = 10**5000
_DESCRIPTION = "int of 16610 bits"

# a fixed random scalar, as `assert_secret_free` asks: bits 22 and 31
# clear and the low 16 bits below 0xFFFF, for the sequence cases, and no
# byte 0x00 or 0x40, the bytes of the 0x400000 the unit mismatch prints
_SCALAR_BYTES = bytes.fromhex(
    "9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9"
)
_SCALAR = int.from_bytes(_SCALAR_BYTES, "big")

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


def _unchecked_coinbase(lock_time: int) -> Tx:
    """Return a coinbase whose lock time was not checked."""
    return Tx(1, lock_time, [TxIn()], [TxOut(1, b"")], check_validity=False)


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


def _outdated_header(version: int) -> None:
    """Check a header whose version was not checked, past BIP65's height."""
    header = BlockHeader(
        version, "00" * 32, "11" * 32, _NOW, "1d00ffff", 1, check_validity=False
    )
    block = Block(header, [_unchecked_coinbase(0)], check_validity=False)
    block.assert_valid_contextual(BlockContext(1_000_000, _NOW))


def _reconstruct(index: int) -> object:
    prefilled = [_unchecked_prefilled(index)]
    return reconstruct(CmpctBlock(_header(), 0, [1], prefilled, check_validity=False))


# what each call is handed, and the shortest call that reaches the
# message quoting it. A negative value where only the lower bound quotes,
# `_HUGE` where the upper one does
_CASES: list[tuple[str, Any, Callable[[Any], object]]] = [
    ("var_int", _HUGE, var_int.serialize),
    ("BTC amount", _HUGE, valid_btc_amount),
    ("satoshi amount", _HUGE, valid_sats_amount),
    ("compressor varint", _HUGE, compressor.serialize_varint),
    ("compressor varint width", _HUGE, lambda v: compressor.serialize_varint(0, v)),
    ("compressed amount", _HUGE, compressor.decompress_amount),
    ("compressed script type", _HUGE, lambda v: compressor.decompress_script(v, b"")),
    ("negative fee rate", -_HUGE, lambda v: FeeRate(sats_per_kvbyte=v)),
    ("fee rate", _HUGE, lambda v: FeeRate(sats_per_kvbyte=v)),
    ("sat/vB quote", _HUGE, FeeRate.from_sats_per_vbyte),
    ("BTC/kvB quote", _HUGE, lambda v: FeeRate.from_btc_per_kvbyte(v, round_up=True)),
    ("virtual size", -_HUGE, lambda v: fee_from_vsize(v, FeeRate(sats_per_kvbyte=1))),
    (
        "ancestor virtual size",
        -_HUGE,
        lambda v: package_fee(1, FeeRate(sats_per_kvbyte=1), ancestor_vsize=v),
    ),
    ("chain work", -_HUGE, lambda v: anti_dos_work_threshold(v, "1d00ffff", 0)),
    (
        "sigop-adjusted weight",
        -_HUGE,
        lambda v: sig_ops_adjusted_weight(v, sig_op_cost=0, bytes_per_sigop=0),
    ),
    ("leaf hash version", _HUGE, lambda v: leaf_hash(v, b"")),
    ("leaf weight", -_HUGE, lambda v: tree_from_weights([(v, (0xC0, ["OP_1"]))])),
    ("read size", _HUGE, lambda v: read_exactly(BytesIO(), v, "field")),
    ("utreexo leaf count", _HUGE, lambda v: UpdateData(prev_num_leaves=v)),
    ("output size", _HUGE, lambda v: bytes_from_octets(b"x", v)),
    ("output sizes", _HUGE, lambda v: bytes_from_octets(b"x", (2, v))),
    (
        "obfuscation offset",
        -_HUGE,
        lambda v: obfuscation.obfuscate(b"\x00", bytes(8), v),
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
        "bip54 coinbase lock time",
        _HUGE,
        lambda v: assert_bip54_coinbase(_unchecked_coinbase(v), 1),
    ),
    (
        "bip54 coinbase height",
        _HUGE,
        lambda v: assert_bip54_coinbase(_unchecked_coinbase(0), v),
    ),
    (
        "negative bip54 coinbase height",
        -_HUGE,
        lambda v: assert_bip54_coinbase(_unchecked_coinbase(0), v),
    ),
    ("header version", _HUGE, _header),
    ("negative header version", -_HUGE, _header),
    ("header nonce", _HUGE, lambda v: _header(nonce=v)),
    ("subsidy height", -_HUGE, subsidy),
    ("halving interval", -_HUGE, lambda v: subsidy(0, v)),
    ("block height", -_HUGE, lambda v: BlockContext(v, _NOW)),
    ("median time past", -_HUGE, lambda v: BlockContext(1, _NOW, median_time_past=v)),
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
        "target height above the height",
        _HUGE,
        lambda v: header_at_height(_header(), v, v + 1, lambda h: h),
    ),
    (
        "parent height",
        -_HUGE,
        lambda v: next_bits_required(
            _header(), _header(), v, lambda h: h, CONSENSUS_PARAMS["mainnet"]
        ),
    ),
    (
        "timewarp parent height",
        -_HUGE,
        lambda v: assert_not_timewarp(
            _header(), _header(), v, CONSENSUS_PARAMS["mainnet"]
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
    (
        "sig_hash aggregation mode",
        _HUGE,
        lambda v: sig_hash.taproot(
            _tx(), 0, [_P2PKH_PREVOUT], 1, 0, b"", b"", agg_mode=v
        ),
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
        "unchecked prefilled previous index",
        _HUGE,
        lambda v: PrefilledTransaction(0, _tx()).serialize(v, check_validity=False),
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
        "unchecked sequence below the script's relative lock time",
        # bits 22 and 31 clear, and the low 16 bits below 0xFFFF
        _HUGE,
        lambda v: _verify_unchecked([0xFFFF, "OP_CHECKSEQUENCEVERIFY"], sequence=v),
    ),
    (
        "chain start median time past",
        _HUGE,
        lambda v: ChainStart(_header(), 0, 1, v, ()),
    ),
    ("outdated header version", -_HUGE, _outdated_header),
    (
        "unchecked filter type",
        _HUGE,
        lambda v: CFilter(filter_type=v, check_validity=False).basic_filter,
    ),
]


# the refusals that name the bound alone, and what each reads
_BOUND_CASES: list[tuple[str, Any, Callable[[Any], object], str]] = [
    (
        "coinbase value ceiling",
        -_HUGE,
        lambda v: assert_coinbase_value(_tx(), subsidy=0, fees=v),
        "^bad-cb-amount: an int of 1 bits above the subsidy and fees$",
    ),
    (
        "median time past bound",
        _HUGE,
        lambda v: Block(
            _header(), [_unchecked_coinbase(0)], check_validity=False
        ).assert_valid_contextual(BlockContext(1, _NOW, median_time_past=v)),
        r"^invalid timestamp \(not after the median past\): 1231459200$",
    ),
    (
        "op code start",
        -_HUGE,
        lambda v: read_op_code(b"\x00", v),
        "^negative start offset$",
    ),
    (
        "push op code",
        _HUGE,
        lambda v: read_push_data(v, BytesIO(), [], False, NO_FLAGS, serialize),
        "^invalid push op code: 0 to 78 expected$",
    ),
]


# the values at the edge of a field a refusal writes in full only where
# the value fits it, and what each reads
_EDGE_CASES: list[tuple[str, int, Callable[[int], object], str]] = [
    (
        "sequence one bit past four bytes",
        2**32 + 1,
        lambda v: _verify_unchecked([0xFFFF, "OP_CHECKSEQUENCEVERIFY"], sequence=v),
        r"^relative lock time > an int of 33 bits \(",
    ),
    (
        "least header version",
        -(2**31),
        _outdated_header,
        r"^invalid version \(outdated\): 0x80000000 < 4$",
    ),
    (
        "header version below the least",
        -(2**31) - 1,
        _outdated_header,
        r"^invalid version \(outdated\): a negative int of 32 bits < 4$",
    ),
]


@pytest.mark.parametrize(
    "value, call, err_msg",
    [case[1:] for case in _EDGE_CASES],
    ids=[case[0] for case in _EDGE_CASES],
)
def test_a_field_is_written_only_where_the_value_fits_it(
    value: int, call: Callable[[int], object], err_msg: str
) -> None:
    """A value that fits its field is written, one just past it described."""
    with pytest.raises(BTClibValueError, match=err_msg):
        call(value)


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


@pytest.mark.parametrize(
    "value, call, err_msg",
    [case[1:] for case in _BOUND_CASES],
    ids=[case[0] for case in _BOUND_CASES],
)
def test_a_refusal_naming_the_bound_writes_no_int_of_it(
    value: int, call: Callable[[Any], object], err_msg: str
) -> None:
    """Refused as this library's error, the bound written as no int."""
    with pytest.raises(BTClibValueError, match=err_msg):
        call(value)


# the refusals whose text is base58-bech32's, which has a _message_text
# of its own that writes the int
_RELAYED = {"base conversion value", "base conversion width"}
_RELAYED_MARK = pytest.mark.xfail(
    raises=AssertionError,
    reason="base58-bech32 writes the int (btclib-org/base58-bech32#118)",
)


_SCALAR_CASES = [*_CASES, *(case[:3] for case in _BOUND_CASES)]


@pytest.mark.parametrize(
    "value, call",
    [
        pytest.param(
            value,
            call,
            id=name,
            marks=[_RELAYED_MARK] if name in _RELAYED else [],
        )
        for name, value, call in _SCALAR_CASES
    ],
)
def test_a_refusal_prints_no_digit_of_a_scalar(
    value: int, call: Callable[[Any], object]
) -> None:
    """A 256-bit scalar in the int's place reaches no exception of the chain.

    Section 7 of the organization's standard: an argument in the wrong place
    may be a key. The scalar takes the sign of the case's value.
    `assert_secret_free` looks for pieces `WINDOW` characters long
    (`tests/secret_free/__init__.py`) of the scalar's decimal and hex. So
    each byte is also looked for as `0x` and
    its hex, and the low two and four bytes a mask leaves of the scalar
    are looked for in decimal and in hex.
    """
    scalar = -_SCALAR if value < 0 else _SCALAR
    with pytest.raises(BTClibValueError) as refusal:
        call(scalar)
    assert_secret_free(refusal.value, [_SCALAR_BYTES, str(_SCALAR)])
    lows = [scalar & (2 ** (8 * size) - 1) for size in (2, 4)]
    masked = [spelling for low in lows for spelling in (str(low), f"{low:x}")]
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _SCALAR_BYTES)
        assert all(spelling not in text for spelling in masked)


def _signed_hex(scalar: int) -> str:
    return f"-{-scalar:x}" if scalar < 0 else f"{scalar:x}"


# the scalar in the int's place as each type that holds its digits or
# its bytes, signed as the scalar is where the type has a sign
_OTHER_TYPES: list[tuple[str, Callable[[int], object]]] = [
    ("hex str", _signed_hex),
    ("decimal str", str),
    ("exponent str", lambda scalar: f"{scalar}e0"),
    ("Decimal", Decimal),
    ("float", float),
    ("bytes", lambda _: _SCALAR_BYTES),
]

# the rows whose call raises in the case's own arithmetic, `v + 1`, and
# never reaches the library: they would pass whatever the library wrote
_NOT_CALLED = {
    ("target height above the height", kind)
    for kind in ("hex str", "decimal str", "exponent str", "bytes")
}

# the rows whose call meets the value in an object built with
# `check_validity=False`, in the script engine or in `reconstruct`, and
# compares it unchecked: Python's bare TypeError or ValueError may leave
_BARE_ERRORS = {
    "unchecked lock time against a height",
    "unchecked lock time against a timestamp",
    "unchecked lock time below the script's",
    "unchecked version against a relative lock time",
    "unchecked sequence against a relative lock time",
    "unchecked sequence below the script's relative lock time",
    "unchecked prefilled order",
    "unchecked prefilled position",
}


@pytest.mark.parametrize(
    "name, value, call",
    [
        pytest.param(
            name,
            spell(-_SCALAR if value < 0 else _SCALAR),
            call,
            id=f"{name}-{kind}",
        )
        for name, value, call in _SCALAR_CASES
        for kind, spell in _OTHER_TYPES
        if (name, kind) not in _NOT_CALLED
    ],
)
def test_a_refusal_prints_no_digit_of_a_scalar_of_another_type(
    name: str, value: object, call: Callable[[Any], object]
) -> None:
    """A 256-bit scalar as a str, a Decimal, a float or bytes is not printed.

    Section 7 of the organization's standard: an argument in the wrong place
    may be a key, whatever its type (issue #3002). `assert_secret_free`
    looks for pieces `WINDOW` characters long
    (`tests/secret_free/__init__.py`) of the scalar's decimal and hex. So
    each byte is also looked for as `0x` and its hex, and the value as
    `str()` and `repr()` write it, a float's digits included.

    A call is refused as this library's error, except a row of
    `_BARE_ERRORS`, which may raise Python's bare TypeError or ValueError.
    The chain is checked whatever it holds.
    """
    expected: tuple[type[Exception], ...] = (
        (TypeError, ValueError) if name in _BARE_ERRORS else (BTClibException,)
    )
    with pytest.raises(expected) as refusal:
        call(value)
    assert_secret_free(refusal.value, [_SCALAR_BYTES, str(_SCALAR)])
    written = [str(value).lower(), repr(value).lower()]
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _SCALAR_BYTES)
        assert all(spelling not in text for spelling in written)


def test_every_row_excused_a_bare_error_is_a_row() -> None:
    """A row renamed or removed leaves no name behind in `_BARE_ERRORS`."""
    assert {name for name, _, _ in _SCALAR_CASES} >= _BARE_ERRORS


_FINER = "^sat/vB fee rate finer than a millisatoshi per virtual byte: "
_NEGATIVE = "^negative sat/vB fee rate: "

# the sat/vB quotes holding the scalar's digits that read as a number
# and are refused for its value, with `round_up` and the refusal's start:
# below a millisatoshi per virtual byte, refused ahead of the divmod, and
# above it with a remainder, refused by it
_QUOTE_CASES: list[tuple[str, str, bool, str]] = [
    ("below a millisatoshi", "0.0000{}", False, _FINER),
    ("negative below a millisatoshi", "-0.0000{}", True, _NEGATIVE),
    ("finer than a millisatoshi", "1.{}", False, _FINER),
    ("negative finer than a millisatoshi", "-1.{}", True, _NEGATIVE),
]

# the quote as each type that holds its digits, and how it is described
_QUOTE_TYPES: list[tuple[str, Callable[[str], object], Callable[[str], str]]] = [
    ("str", str, lambda text: f"a str of length {len(text)}$"),
    ("Decimal", Decimal, lambda _: "a Decimal$"),
]


@pytest.mark.parametrize(
    "value, round_up, err_msg",
    [
        pytest.param(
            spell(form.format(_SCALAR)),
            round_up,
            start + describe(form.format(_SCALAR)),
            id=f"{name}-{kind}",
        )
        for name, form, round_up, start in _QUOTE_CASES
        for kind, spell, describe in _QUOTE_TYPES
    ],
)
def test_a_sat_per_vbyte_refusal_prints_no_digit_of_the_quote(
    value: object, round_up: bool, err_msg: str
) -> None:
    """A quote holding a scalar's digits is described, never written.

    Section 7 of the organization's standard: a value refused as a public
    type counts as a secret, and a number is no name a refusal may quote.
    The message names the rule broken and describes the quote as
    `utils._message_text` does. `assert_secret_free` looks for pieces
    `WINDOW` characters long (`tests/secret_free/__init__.py`) of the
    scalar's decimal and hex. So each byte is also looked for as `0x` and
    its hex, and the quote as `str()` and `repr()` write it.
    """
    with pytest.raises(BTClibValueError, match=err_msg) as refusal:
        FeeRate.from_sats_per_vbyte(value, round_up=round_up)
    assert_secret_free(refusal.value, [_SCALAR_BYTES, str(_SCALAR)])
    written = [str(value).lower(), repr(value).lower()]
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _SCALAR_BYTES)
        assert all(spelling not in text for spelling in written)
