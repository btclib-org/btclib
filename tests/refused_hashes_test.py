# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal prints no hash, root or field of the value it refuses.

Section 7 of the btclib-org standard, *A refusal carries no secret*: a
value refused as a public type may be a key passed in its place, and a
hash of it confirms a guess at it. Each case below puts a fixed random
key where a block, a header, a message or a transaction holds such a
value, and checks the exact text and every exception of the chain
(issue #3005). `tests/refused_octets_test.py` and
`tests/refused_counts_test.py` are the same check for a byte and for a
number read from the octets.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from btclib import var_bytes
from btclib.amount import sats_from_btc
from btclib.block import Block, BlockHeader
from btclib.block.block_context import BlockContext
from btclib.block.block_filter import prevout_scripts_from_utxos
from btclib.block.merkle_proof import assert_as_valid
from btclib.block.proof_of_work import block_work, target_from_bits
from btclib.exceptions import BTClibValueError
from btclib.p2p.message import Message
from btclib.p2p.reject import Reject
from btclib.script.engine import verify_amounts
from btclib.script.sig_hash import redeem_script
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.secret_free import assert_secret_free, chained, text_of

# a fixed random key, as `assert_secret_free` asks
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")

_TIME = datetime(2009, 1, 9, tzinfo=UTC)
# the most satoshis an amount, or a total of amounts, may hold
_MAX_SATOSHI = sats_from_btc(Decimal(21_000_000))


def _header(merkle_root: bytes = bytes(32), bits: str = "1d00ffff") -> BlockHeader:
    """Return a header holding the merkle root and bits, unchecked."""
    return BlockHeader(1, bytes(32), merkle_root, _TIME, bits, 0, check_validity=False)


def _coinbase(script_sig: bytes = b"\x51") -> Tx:
    """Return a coinbase spending nothing, unchecked."""
    tx_in = TxIn(OutPoint(), script_sig, 0xFFFFFFFF)
    return Tx(1, 0, [tx_in], [TxOut(0, b"")], check_validity=False)


def _block(*txs: Tx, merkle_root: bytes = bytes(32)) -> Block:
    """Return a block of the coinbase and the transactions, unchecked."""
    return Block(_header(merkle_root), [_coinbase(), *txs], check_validity=False)


def _spend(prev_out: OutPoint, script_sig: bytes = b"", lock_time: int = 0) -> Tx:
    """Return a transaction spending the outpoint, unchecked."""
    tx_in = TxIn(prev_out, script_sig, 0)
    return Tx(1, lock_time, [tx_in], [TxOut(1, b"")], check_validity=False)


def _committing_block() -> Block:
    """Return a segwit block whose coinbase commits to the key."""
    coinbase = Tx(
        1,
        0,
        [TxIn(OutPoint(), b"\x51", 0xFFFFFFFF, Witness([bytes(32)]))],
        [TxOut(0, bytes.fromhex("6a24aa21a9ed") + _KEY)],
        check_validity=False,
    )
    return Block(_header(), [coinbase], check_validity=False)


_PING = b"ping".ljust(12, b"\x00")

_CASES: list[tuple[str, Callable[[], object], str]] = [
    (
        "command padding",
        lambda: Message.parse(bytes(4) + b"p\x00" + _KEY[:10] + bytes(8)),
        "invalid command padding at byte 2",
    ),
    (
        "command character",
        lambda: Message.parse(bytes(4) + _KEY[:12] + bytes(8)),
        "non-printable character in command at byte 0",
    ),
    # the key's own hash is what the checksum is compared with
    (
        "message checksum",
        lambda: Message.parse(
            bytes(4) + _PING + len(_KEY).to_bytes(4, "little") + _KEY[:4] + _KEY
        ),
        "invalid checksum",
    ),
    # 0x9e, the key's byte 0, starts no utf-8 character
    (
        "reject message",
        lambda: Reject.parse(var_bytes.serialize(_KEY) + b"\x10" + bytes(1)),
        "invalid message: not utf-8 at byte 0",
    ),
    (
        "reject reason",
        lambda: Reject.parse(
            var_bytes.serialize(b"tx") + b"\x10" + var_bytes.serialize(b"ok" + _KEY)
        ),
        "invalid reason: not utf-8 at byte 2",
    ),
    (
        "merkle root",
        lambda: _block(merkle_root=_KEY).assert_valid_merkle_root(),
        "invalid merkle root",
    ),
    (
        "witness commitment",
        lambda: _committing_block().assert_valid_witness_commitment(),
        "invalid witness commitment",
    ),
    (
        "coinbase height",
        lambda: Block(
            _header(), [_coinbase(_KEY)], check_validity=False
        ).assert_valid_coinbase_height(1),
        "invalid coinbase height: 51 expected",
    ),
    (
        "required bits",
        lambda: Block(
            _header(bits=_KEY[:4].hex()), [_coinbase()], check_validity=False
        ).assert_valid_contextual(
            BlockContext(1, _TIME, required_bits=bytes.fromhex("1d00ffff"))
        ),
        "proof-of-work target not the required one: 1d00ffff expected",
    ),
    (
        "non-final transaction",
        lambda: _block(_spend(OutPoint(_KEY, 0), _KEY, 1)).assert_valid_contextual(
            BlockContext(1, _TIME)
        ),
        "non-final transaction 1",
    ),
    # 0x00 after the key's byte 0 as exponent: a zero significand
    (
        "zero target difficulty",
        lambda: _header(bits=_KEY[:1].hex() + "000000").difficulty,
        "zero proof-of-work target",
    ),
    # 0xd7, the key's byte 1, sets the sign bit of the significand
    (
        "negative target",
        lambda: _header(bits=_KEY[:4].hex()).assert_valid_pow(),
        "negative proof-of-work target",
    ),
    (
        "zero target",
        lambda: _header(bits=_KEY[:1].hex() + "000000").assert_valid_pow(),
        "zero proof-of-work target",
    ),
    (
        "target above the limit",
        lambda: _header(bits="20" + _KEY[3:6].hex()).assert_valid_pow(),
        f"proof-of-work target above the limit: {target_from_bits('1d00ffff').hex()}",
    ),
    (
        "proof of work",
        lambda: _header(merkle_root=_KEY).assert_valid_pow(),
        "invalid proof-of-work: hash above the target",
    ),
    (
        "target overflow",
        lambda: target_from_bits(b"\x22" + _KEY[3:6]),
        "invalid proof-of-work target: overflows 32 bytes",
    ),
    (
        "zero target work",
        lambda: block_work(_KEY[:1] + bytes(3)),
        "zero proof-of-work target",
    ),
    (
        "merkle branch",
        lambda: assert_as_valid(_KEY, [_KEY], 0, bytes(32)),
        "invalid merkle branch",
    ),
    (
        "total output amount",
        lambda: Tx(
            1,
            0,
            [TxIn(OutPoint(_KEY, 0), b"", 0)],
            [TxOut(_MAX_SATOSHI, b""), TxOut(int.from_bytes(_KEY[:6], "little"), b"")],
            check_validity=False,
        ).assert_valid(),
        f"invalid total output amount: above {_MAX_SATOSHI}",
    ),
    (
        "total input amount",
        lambda: verify_amounts(
            [TxOut(_MAX_SATOSHI, b""), TxOut(int.from_bytes(_KEY[:6], "little"), b"")],
            _spend(OutPoint(_KEY, 0)),
        ),
        f"invalid total input amount: above {_MAX_SATOSHI}",
    ),
    (
        "unresolved previous output",
        lambda: prevout_scripts_from_utxos(_block(_spend(OutPoint(_KEY, 0))), {}),
        "unresolved previous output: input 0 of transaction 1",
    ),
    # 0xd7, the key's byte 1, is a byte no op code names: the script_sig
    # ends with it where the redeem script's push belongs
    (
        "p2sh redeem script",
        lambda: redeem_script(_KEY[1:2], bytes.fromhex("a914") + bytes(20) + b"\x87"),
        "missing redeem script in the p2sh script_sig",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_a_refusal_prints_no_hash_or_field_of_the_value(
    call: Callable[[], object], err_msg: str
) -> None:
    """The refusal names the field, its position or the bound, never the value.

    `assert_secret_free` looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex, and the text is compared whole, which
    is what finds a hash of the key or a number read from it.
    """
    with pytest.raises(BTClibValueError) as refusal:
        call()
    assert str(refusal.value) == err_msg
    # a cause or a context would be text the whole comparison does not see
    assert all(err_msg.startswith(str(e)) for e in chained(refusal.value))
    assert_secret_free(refusal.value, [_KEY, str(int.from_bytes(_KEY, "big"))])
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _KEY)
