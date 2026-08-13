# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.mining` module.

The target mined against is `2000ffff`, harder than regtest's own limit
and easier than anything else a network allows: it is satisfied by one
hash in 256, so the search takes a few hundred evaluations and under a
millisecond, and is still a search rather than a lucky first nonce. The
nonces asserted below are therefore fixed by the candidate they solve --
change a byte of one and its nonce moves. Every assertion goes through the
ordinary validation -- `Block.assert_valid`, which asserts the
proof-of-work, the merkle root and the coinbase -- so what is being
checked is that a block built here is a block, not that two copies of
the same arithmetic agree.

Regtest is therefore the network every block here belongs to, and it is
said out loud: `assert_valid` and `assert_valid_pow` default to mainnet's
limit, which these targets are far above, so each call names
`REGTEST_POW_LIMIT_BITS`. A validation that passed without naming it
would be one that let a regtest block pass for a mainnet one.
"""

from datetime import datetime, timezone

import pytest

from btclib import var_bytes
from btclib.block import Block, BlockHeader
from btclib.block.mining import VERSION, candidate_block_header, mine
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import encode_num

# 0xffff * 2^232, i.e. one chance in 256 that a given nonce solves it
_EASY_BITS = "2000ffff"
_PREVIOUS = "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04"
_TIME = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _coinbase(height: int, extranonce: int = 0) -> Tx:
    """Return a coinbase paying nothing, with the BIP34 height in it."""
    # the height is a serialized CScript push, as Block.height reads it;
    # the extranonce is what a real miner rolls when the four nonce bytes
    # run out, and it is here to keep the script_sig over the two bytes
    # consensus requires
    script_sig = var_bytes.serialize(encode_num(height))
    script_sig += var_bytes.serialize(encode_num(extranonce))
    tx_in = TxIn(OutPoint(), script_sig, 0xFFFFFFFF)
    tx_out = TxOut(50_00000000, ScriptPubKey(b"\x51"))  # OP_1
    return Tx(1, 0, [tx_in], [tx_out])


def _spend() -> Tx:
    """Return an ordinary transaction, so the merkle tree has two leaves."""
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), "0102", 0xFFFFFFFF)
    tx_out = TxOut(10_00000000, ScriptPubKey(b"\x51"))
    return Tx(1, 0, [tx_in], [tx_out])


def test_a_mined_block_is_a_block() -> None:
    """Assemble, mine, and let the ordinary validation have the last word."""
    transactions = [_coinbase(700_000), _spend()]
    candidate = candidate_block_header(_PREVIOUS, transactions, _TIME, _EASY_BITS)

    # a candidate is structurally valid and carries no work: that split
    # is what lets it be built at all
    candidate.assert_valid()
    assert candidate.nonce == 0
    assert candidate.version == VERSION
    assert len(candidate.serialize()) == 80
    with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
        candidate.assert_valid_pow(REGTEST_POW_LIMIT_BITS)

    header = mine(candidate)
    assert header is not None
    assert header.nonce == 278
    assert header.hash <= header.target
    header.assert_valid_pow(REGTEST_POW_LIMIT_BITS)

    # and the same work is no proof-of-work on mainnet, whose limit these
    # bits are 2^24 above: what the header solved is the network it says
    with pytest.raises(BTClibValueError, match="target above the limit: "):
        header.assert_valid_pow()

    # everything except the nonce is what the candidate carried
    assert header.merkle_root == candidate.merkle_root
    assert header.previous_block_hash == candidate.previous_block_hash
    assert header.time == candidate.time
    assert header.bits == candidate.bits

    # and the block it heads validates in full: work, merkle root,
    # coinbase, witness commitment. Built unchecked and then checked,
    # because __init__ has no network to be told about and defaults to
    # mainnet's limit -- the two steps Block.assert_valid documents
    block = Block(header, transactions, check_validity=False)
    block.assert_valid(REGTEST_POW_LIMIT_BITS)
    assert block.height == 700_000
    round_tripped = block.serialize(check_validity=False)
    assert block == Block.parse(round_tripped, check_validity=False)

    # the caller's candidate was not touched
    assert candidate.nonce == 0


def test_the_merkle_root_is_the_one_the_block_checks() -> None:
    """The builder and the validator share a function, and must agree."""
    transactions = [_coinbase(1), _spend(), _spend()]
    candidate = candidate_block_header(_PREVIOUS, transactions, _TIME, _EASY_BITS)

    # assert_valid_merkle_root is the check, and it passes on a header
    # that has no work yet
    Block(candidate, transactions, check_validity=False).assert_valid_merkle_root()

    # a transaction list whose tree is the CVE-2012-2459 mutation of a
    # shorter one heads no candidate: the header would commit to both
    mutated = [*transactions, transactions[-1]]
    with pytest.raises(BTClibValueError, match="duplicate transaction"):
        candidate_block_header(_PREVIOUS, mutated, _TIME, _EASY_BITS)

    # and neither does no transaction list at all
    with pytest.raises(BTClibValueError, match="empty merkle tree"):
        candidate_block_header(_PREVIOUS, [], _TIME, _EASY_BITS)


def test_regtest_target_is_solved_by_the_first_nonce() -> None:
    """Regtest's limit is 2^255: one try in two solves it."""
    transactions = [_coinbase(1)]
    candidate = candidate_block_header(
        _PREVIOUS, transactions, _TIME, REGTEST_POW_LIMIT_BITS
    )
    header = mine(candidate, 2)
    assert header is not None
    assert header.nonce == 0
    Block(header, transactions, check_validity=False).assert_valid(
        REGTEST_POW_LIMIT_BITS
    )

    # issue #403 measured from here: a header solved against regtest's
    # limit and offered to mainnet, which Core's DeriveTarget refuses on
    # "bnTarget > powLimit" and btclib used to accept. Half a try's worth
    # of work, and it was a mainnet block
    with pytest.raises(BTClibValueError, match="target above the limit: "):
        Block(header, transactions, check_validity=False).assert_valid()


def test_a_bounded_search_can_find_nothing() -> None:
    """None is the honest answer: a nonce past the bound may still solve."""
    transactions = [_coinbase(1)]
    candidate = candidate_block_header(_PREVIOUS, transactions, _TIME, _EASY_BITS)

    # the nonce that solves this one is 126, so a search of 126 -- nonces
    # 0 to 125 -- stops one short of it
    assert mine(candidate, 126) is None
    solved = mine(candidate, 127)
    assert solved is not None
    assert solved.nonce == 126

    # a mainnet-grade target is not found either, and the bound is what
    # makes that a return rather than a hang
    hard = candidate_block_header(_PREVIOUS, transactions, _TIME, "1d00ffff")
    assert mine(hard, 1000) is None


def test_the_nonce_field_is_four_bytes() -> None:
    """The search stops at the end of the field, not at max_tries.

    Rolling past it is what a real miner does by changing the extranonce
    in the coinbase and building the candidate again, which is the line
    between this and mining.
    """
    transactions = [_coinbase(1)]
    candidate = candidate_block_header(_PREVIOUS, transactions, _TIME, "1d00ffff")
    candidate.nonce = 0xFFFFFFFF

    # one nonce left to try, however many were asked for
    assert mine(candidate, 1 << 30) is None

    # the extranonce is the way out: a different coinbase is a different
    # merkle root, hence four fresh bytes to search
    other = candidate_block_header(
        _PREVIOUS, [_coinbase(1, extranonce=7)], _TIME, _EASY_BITS
    )
    assert other.merkle_root != candidate.merkle_root
    assert mine(other) is not None


def test_mine_exceptions() -> None:
    """Refuse a non-positive max_tries and bits denoting no target."""
    transactions = [_coinbase(1)]
    candidate = candidate_block_header(_PREVIOUS, transactions, _TIME, _EASY_BITS)

    for max_tries in (0, -1):
        with pytest.raises(BTClibValueError, match="invalid max_tries: "):
            mine(candidate, max_tries)

    # a header whose bits denote no target is not mineable, and it is
    # target_from_bits that says so
    candidate.bits = bytes.fromhex("22ffffff")
    with pytest.raises(BTClibValueError, match="invalid proof-of-work target: "):
        mine(candidate)


def test_candidate_version() -> None:
    """BIP9 leaves the top three bits at 001, and version 1 is dead."""
    assert VERSION == 0x20000000

    transactions = [_coinbase(1)]
    # the caller can still say otherwise: a version is a signalling
    # decision, not arithmetic
    candidate = candidate_block_header(
        _PREVIOUS, transactions, _TIME, _EASY_BITS, version=0x20000004
    )
    assert candidate.version == 0x20000004
    assert BlockHeader.parse(candidate.serialize()).version == 0x20000004
