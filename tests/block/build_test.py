# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.build` module.

`block_1.bin` and `block_481824_complete.bin`
(`tests/_data/README.md`'s own entries) are real mainnet blocks, and both
verify themselves the way `Block.parse` always does. Rebuilding each
from its own transactions and comparing the header this module produces
against the one the chain actually carries is a stronger check than any
round trip through this library's own code alone: it is what says
`build_block` computes the merkle root and the witness commitment a real
node agrees with, not merely one that agrees with `Block.assert_valid`.

`test_build_block_reproduces_mainnet_s_genesis` is the third such vector,
and the one every network shares the coinbase shape of -- the same
message and the same pubkey `btclib_node.chains.create_genesis` and
Bitcoin Core's own source both carry. `build_coinbase` cannot build it:
the genesis predates BIP34, so its script_sig commits to no height at
all. What the test measures is `build_block`'s own header assembly,
which is the half a genesis-block builder would still lean on --
ISS 1602 is where the rest of that decision lives.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from btclib.block import Block, bip34_commitment
from btclib.block.build import build_block, build_coinbase
from btclib.block.mining import mine
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.consensus import subsidy
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey, Witness, script
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_DATA = Path(__file__).parent / "_data"
_PREVIOUS = "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04"
_TIME = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
# 0xffff * 2^232, satisfied by one nonce in 256 -- mining_test.py's own
_EASY_BITS = "2000ffff"


def _parse(fname: str) -> Block:
    return Block.parse((_DATA / fname).read_bytes())


def test_build_coinbase_pays_the_subsidy_and_commits_to_the_height() -> None:
    """A coinbase built at a real height, checked against Block itself."""
    height = 700_000
    script_pub_key = ScriptPubKey(b"\x51")  # OP_1
    coinbase = build_coinbase(height, script_pub_key, fees=1_234)

    assert coinbase.is_coinbase
    assert coinbase.vout[0].value == subsidy(height) + 1_234
    assert coinbase.vin[0].script_sig.startswith(bip34_commitment(height))

    built = build_block(_PREVIOUS, [coinbase], _TIME, _EASY_BITS)
    built.assert_valid_coinbase_height(height)


def test_build_coinbase_at_a_low_height_still_meets_the_size_floor() -> None:
    """Heights 0 to 16 are one-byte commitments; the padding covers them."""
    for height in (0, 1, 16):
        coinbase = build_coinbase(height, ScriptPubKey(b"\x51"))
        assert 2 <= len(coinbase.vin[0].script_sig) <= 100


def test_build_coinbase_extra_nonce_changes_the_txid() -> None:
    """A different extra_nonce is a different transaction, on purpose.

    `mining.mine`'s own docstring: once a header's four nonce bytes are
    exhausted, a real miner rolls this to search a fresh merkle root.
    """
    plain = build_coinbase(1, ScriptPubKey(b"\x51"))
    rolled = build_coinbase(1, ScriptPubKey(b"\x51"), extra_nonce=b"\x07")
    assert plain.id != rolled.id
    assert rolled.vin[0].script_sig == bip34_commitment(1) + b"\x01\x07"


def test_build_coinbase_matches_a_real_mainnet_coinbase() -> None:
    """`bip34_commitment` and `subsidy`, measured against block 481,824."""
    block = _parse("block_481824_complete.bin")
    real_coinbase = block.transactions[0]
    height = block.height
    assert height is not None

    assert real_coinbase.vin[0].script_sig.startswith(bip34_commitment(height))
    # the real payment is the subsidy plus whatever fees that block paid;
    # a coinbase can never pay less than the bare subsidy
    assert subsidy(height) <= real_coinbase.vout[0].value


def test_build_coinbase_refuses_what_tx_refuses() -> None:
    """check_validity is Tx's own, not a second copy of Tx's rules."""
    with pytest.raises(BTClibValueError):
        build_coinbase(1, ScriptPubKey(b"\x51"), fees=-(subsidy(1) + 1))


def test_build_block_reproduces_block_1() -> None:
    """Rebuild mainnet's block 1 from its own transactions and header."""
    block = _parse("block_1.bin")
    header = block.header

    built = build_block(
        header.previous_block_hash,
        block.transactions,
        header.time,
        header.bits,
        version=header.version,
    )
    assert built.header.merkle_root == header.merkle_root
    assert not built.transactions[0].is_segwit

    solved = replace(built.header, nonce=header.nonce)
    assert solved.hash == header.hash
    assert solved.hash.hex() == (
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    )


def test_build_block_adds_the_witness_commitment_of_a_real_segwit_block() -> None:
    """Strip block 481,824's own commitment, then rebuild it byte for byte.

    The real coinbase minus its own last output (the commitment) and its
    own witness stack is what a caller assembling this block from
    scratch would have handed `build_block`; what comes back is checked
    against the block a real node actually accepted.
    """
    block = _parse("block_481824_complete.bin")
    header = block.header
    real_coinbase = block.transactions[0]

    bare_vin = TxIn(
        prev_out=real_coinbase.vin[0].prev_out,
        script_sig=real_coinbase.vin[0].script_sig,
        sequence=real_coinbase.vin[0].sequence,
        check_validity=False,
    )
    bare_coinbase = Tx(
        version=real_coinbase.version,
        lock_time=real_coinbase.lock_time,
        vin=[bare_vin],
        vout=real_coinbase.vout[:-1],
        check_validity=False,
    )
    transactions = [bare_coinbase, *block.transactions[1:]]

    built = build_block(
        header.previous_block_hash,
        transactions,
        header.time,
        header.bits,
        version=header.version,
    )

    assert built.transactions[0].vout == real_coinbase.vout
    assert (
        built.transactions[0].vin[0].script_witness.stack
        == real_coinbase.vin[0].script_witness.stack
    )
    assert built.header.merkle_root == header.merkle_root

    solved = replace(built.header, nonce=header.nonce)
    assert solved.hash == header.hash

    # and the whole thing is a block Block.assert_valid accepts, witness
    # commitment included
    Block(solved, built.transactions, check_validity=False).assert_valid()


def test_build_block_adds_no_commitment_without_a_witness() -> None:
    """A block over legacy transactions alone gets no BIP141 output."""
    coinbase = build_coinbase(1, ScriptPubKey(b"\x51"))
    built = build_block(_PREVIOUS, [coinbase], _TIME, _EASY_BITS)
    assert len(built.transactions[0].vout) == 1
    assert not built.transactions[0].is_segwit


def test_build_block_and_mine_round_trips_through_parse() -> None:
    """Build, mine, and let ordinary parsing have the last word.

    A spend carrying a witness, so the commitment this module adds is
    exercised end to end and not merely left absent, as the legacy-only
    test above leaves it.
    """
    coinbase = build_coinbase(700_000, ScriptPubKey(b"\x51"))
    spend_in = TxIn(
        OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, script_witness=Witness([b"\x01"])
    )
    spend = Tx(2, 0, [spend_in], [TxOut(10_00000000, ScriptPubKey(b"\x51"))])

    built = build_block(_PREVIOUS, [coinbase, spend], _TIME, _EASY_BITS)
    # the spend's own witness made this a segwit block, so the coinbase
    # this module returns is not the one build_coinbase built: it is the
    # copy carrying the BIP141 commitment
    assert built.transactions[0].is_segwit
    assert built.transactions[0] is not coinbase

    header = mine(built.header)
    assert header is not None

    block = Block(header, built.transactions, check_validity=False)
    block.assert_valid(REGTEST_POW_LIMIT_BITS)
    assert block.height == 700_000
    round_tripped = block.serialize(check_validity=False)
    assert block == Block.parse(round_tripped, check_validity=False)


def test_build_block_reproduces_mainnet_s_genesis() -> None:
    """The one coinbase shape build_coinbase does not build.

    BIP34 is not in force at height zero, so the genesis commits to no
    height at all. The same message and pubkey `bitcoin/bitcoin`'s own
    genesis carries, reproduced from `btclib_node.chains.create_genesis`'s
    own constants; what this checks is build_block's header assembly,
    over a hand-built coinbase, against the hash `NETWORKS["mainnet"]`
    ships.
    """
    script_sig = script.serialize(
        [
            "FFFF001D",
            b"\x04",
            b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        ]
    )
    pubkey = (
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
        "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    )
    script_pub_key = script.serialize([pubkey, "OP_CHECKSIG"])
    genesis_tx = Tx(
        version=1,
        lock_time=0,
        vin=[TxIn(OutPoint(), script_sig, 0xFFFFFFFF)],
        vout=[TxOut(subsidy(0), script_pub_key)],
    )

    time = datetime.fromtimestamp(1231006505, timezone.utc)
    built = build_block(b"\x00" * 32, [genesis_tx], time, "1d00ffff", version=1)
    solved = replace(built.header, nonce=2083236893)

    assert solved.hash == NETWORKS["mainnet"].genesis_block


def test_build_block_refuses_two_coinbases() -> None:
    """A caller handing build_block a second coinbase gets no Block back.

    `Block.assert_valid_structure` is what refuses it -- the same rule
    `Block.assert_valid` asks, run here even though the proof-of-work
    `assert_valid` also asks for cannot be, a pre-mining candidate having
    none yet.
    """
    coinbase = build_coinbase(1, ScriptPubKey(b"\x51"))
    second_coinbase = build_coinbase(1, ScriptPubKey(b"\x52"))
    with pytest.raises(BTClibValueError, match="more than one coinbase"):
        build_block(_PREVIOUS, [coinbase, second_coinbase], _TIME, _EASY_BITS)


def test_build_block_refuses_a_malformed_non_coinbase_transaction() -> None:
    """A coinbase-shaped input in a transaction that is not one, refused.

    `Tx.assert_valid`'s own rule (bad-txns-prevout-null), reached through
    `assert_valid_structure`'s own per-transaction loop -- not by
    `candidate_block_header`, which only refuses a CVE-2012-2459 merkle
    mutation, and which this transaction does not trigger.
    """
    coinbase = build_coinbase(1, ScriptPubKey(b"\x51"))
    malformed = Tx(
        2,
        0,
        [
            TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF),
            TxIn(OutPoint(), b"", 0xFFFFFFFF),  # the coinbase marker, here
        ],
        [TxOut(1, ScriptPubKey(b"\x51"))],
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="coinbase input"):
        build_block(_PREVIOUS, [coinbase, malformed], _TIME, _EASY_BITS)


def test_build_block_refuses_a_block_over_the_sigop_bound() -> None:
    """MAX_BLOCK_SIGOPS_COST, crossed by one output's own script.

    20,001 legacy CHECKSIGs times WITNESS_SCALE_FACTOR is 80,004, one
    past the 80,000 cap -- refused the same way whether the block came
    from the wire or from this module.
    """
    coinbase = build_coinbase(1, ScriptPubKey(b"\x51"))
    heavy = Tx(
        2,
        0,
        [TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, ScriptPubKey(b"\xac" * 20_001))],
    )
    with pytest.raises(BTClibValueError, match="invalid sigop cost: "):
        build_block(_PREVIOUS, [coinbase, heavy], _TIME, _EASY_BITS)


def test_build_block_refuses_a_block_over_the_weight_cap() -> None:
    """MAX_BLOCK_WEIGHT, crossed by one output's own script.

    A legacy (non-segwit) output over 1,000,000 bytes crosses the
    stripped-size half of `assert_valid_length` -- measured, rather than
    assumed, against `tests/block/block_test.py`'s own weight-cap
    vectors: `4 * stripped_size > MAX_BLOCK_WEIGHT` is the same
    comparison a parsed block is refused by.
    """
    coinbase = build_coinbase(1, ScriptPubKey(b"\x51"))
    heavy = Tx(
        2,
        0,
        [TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, ScriptPubKey(b"\x00" * 1_000_100))],
    )
    with pytest.raises(BTClibValueError, match="invalid stripped size: "):
        build_block(_PREVIOUS, [coinbase, heavy], _TIME, _EASY_BITS)
