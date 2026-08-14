# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Candidate block headers, and a toy search for the nonce that solves one.

A toy, and the word is meant: `mine` hashes one nonce at a time in
Python, in one process, over a header it re-serializes on every
evaluation. That is some five orders of magnitude short of what a single
mainnet block needs, so what this is for is a regtest-grade target, a
test, or watching the search work.

What it is not a toy about is the header it produces. The merkle root
comes from the same function `Block.assert_valid_merkle_root` checks
against, and the solved header satisfies `assert_valid_pow` for a network
whose pow limit the bits are within -- `REGTEST_POW_LIMIT_BITS` for a
target of that grade, since mainnet's is the default there and refuses
one. So the result is a block every other implementation accepts, at a
difficulty nobody has to be convinced by.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime

from btclib.alias import Octets
from btclib.block.block import merkle_root_and_mutated_from_transactions
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import Tx
from btclib.utils import assert_type, is_integer

__all__ = [
    "NONCE_SPACE",
    "VERSION",
    "candidate_block_header",
    "mine",
]

# BIP9 leaves the top three bits of the version at 001 and signals in the
# 29 below, so this is the version of a block that signals for nothing.
# Not 1, which BIP34 made unacceptable at height 227,836 and BIP66 and
# BIP65 raised twice more: a candidate carrying it would be rejected by
# every node on the network for a reason that has nothing to do with its
# proof-of-work
VERSION = 0x20000000

# a nonce is four bytes, so this many evaluations exhaust the field
NONCE_SPACE = 0x100000000


def candidate_block_header(
    previous_block_hash: Octets,
    transactions: Sequence[Tx],
    time: datetime,
    bits: Octets,
    *,
    version: int = VERSION,
) -> BlockHeader:
    """Return the unsolved header committing to a list of transactions.

    Everything the header needs except the work: the merkle root is
    computed here, and the nonce starts at zero for `mine` to search
    from. The result is structurally valid -- `assert_valid` passes,
    `serialize` and `hash` work -- and has no proof-of-work, which is
    the state a header is in while it is being mined.

    A transaction list whose merkle tree is the CVE-2012-2459 mutation
    of a shorter one is refused: the header would commit to both lists,
    so it is not a candidate for the one at hand.
    """
    merkle_root, mutated = merkle_root_and_mutated_from_transactions(transactions)
    if mutated:
        raise BTClibValueError("duplicate transaction")

    return BlockHeader(
        version=version,
        previous_block_hash=previous_block_hash,
        merkle_root=merkle_root,
        time=time,
        bits=bits,
        nonce=0,
    )


def mine(header: BlockHeader, max_tries: int = 1 << 20) -> BlockHeader | None:
    """Return the header solved by a nonce, or None if none was found.

    The search runs from the nonce the candidate carries and stops at
    `max_tries` evaluations or at the end of the four-byte field,
    whichever comes first, so it always terminates. None is the honest
    answer to a bounded search: the target may still be satisfiable by a
    nonce past the bound.

    Exhausting the field is not the end of mining, which is why this is
    a toy rather than a miner. A real one then changes what it is
    hashing -- the extranonce in the coinbase script_sig, the timestamp,
    the transaction set -- and searches the four bytes again over the
    new merkle root. Building that header again is `candidate_block_header`.

    The caller's header is left alone: what comes back is a copy.
    """
    # `replace()` says "should be called on dataclass instances" for
    # anything else, from the standard library and about a call the caller
    # never made; `max_tries < 1` is a bare TypeError about the operands,
    # and a float passes it to fail at `range` a few lines down
    assert_type(header, BlockHeader, "header")
    if not is_integer(max_tries):
        raise BTClibTypeError(f"invalid max_tries type: {type(max_tries).__name__}")
    if max_tries < 1:
        raise BTClibValueError(f"invalid max_tries: {max_tries}")

    # a copy taken once, not one per nonce: replace() runs assert_valid,
    # and validating the same header a million times is the whole budget
    candidate = replace(header)
    target = candidate.target
    stop = min(candidate.nonce + max_tries, NONCE_SPACE)
    for nonce in range(candidate.nonce, stop):
        candidate.nonce = nonce
        # the last comparison assert_valid_pow makes, so that what is
        # returned from here is what a Block will accept: the target is a
        # bound the hash may reach, Core rejecting on "hash > bnTarget".
        # The range checks it makes before it are about the bits and not
        # the nonce, so they are the same for every candidate and none of
        # this loop's business: a target no network allows is one this
        # search solves and assert_valid_pow still refuses
        if candidate.hash <= target:
            return candidate

    return None
