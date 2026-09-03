# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a transaction owes the chain before it: finality and locks.

Sequence locks, coinbase maturity, and the coinbase's own value ceiling.

`Tx.assert_valid` is Core's `CheckTransaction`, and `script.engine`'s
`verify_amounts`/`verify_input` are what a transaction can be held to
against its prevouts. Between those two and a block connecting there is
a third set of rules, Core's `src/consensus/tx_verify.cpp` plus
`bad-cb-amount` in `src/validation.cpp`'s `ConnectBlock`, that each need
one fact per prevout beyond the output itself -- the height it was
created at, and whether by a coinbase, which `btclib.tx.coin.Coin`
carries -- and a height and a time to judge against. Every function here
takes those as parameters rather than reading them off a UTXO set or a
block index: btclib must not learn what either is, the same precedent
`btclib.block.header_context`'s `ParentOf` sets for a header walking the
chain through a callable rather than an index.

Bitcoin Core v31.1 (bitcoin/bitcoin@9be056a8a7) is the reference for
every rule, `src/consensus/tx_verify.cpp` and `src/validation.cpp`,
cited beside the code that transcribes it.

## What each function does not take, and why

`is_final`'s `block_time` is a cutoff, not a choice: Core evaluates
`IsFinalTx` in `ContextualCheckBlock` against `pindexPrev->
GetMedianTimePast()` once BIP113 (the CSV deployment) is active on the
chain, and against the block's own timestamp before that -- a decision
made from the chain's own activation height, which this module does not
carry. The caller passes whichever Core would have passed; the
function's own docstring repeats this rather than deciding it.

`assert_sequence_locks` takes no `enforce_bip68` flag. Core's own
`fEnforceBIP68` is `tx.version >= 2 && DeploymentActiveAt(...,
DEPLOYMENT_CSV)`: the first half is a fact about the transaction and
stays in this function, the second is chain state a caller already knows
before it is worth building a `Coin` sequence at all -- a function that
only evaluates the locks once asked, with activation decided outside, is
the smaller contract, and the one that cannot be handed the wrong flag
by accident.

A mempool acceptance, where a coin has no block yet, is not special-cased
here either: `coin.py`'s docstring is where that is, and it is the
caller's `Coin` to build, at Core's `MEMPOOL_HEIGHT` reading, rather than
a branch these functions would otherwise need.

`assert_coinbase_value` takes the fee sum and the subsidy rather than
every other transaction of the block and their own prevouts: Core's own
`ConnectBlock` accumulates `nFees` transaction by transaction as it
connects them, and `btclib.consensus.subsidy` is already the halving
arithmetic -- summing fees from a block's own transactions a second time
here would be a second implementation of what a caller connecting a
block already does once.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx.coin import Coin
from btclib.tx.limits import (
    COINBASE_MATURITY,
    LOCKTIME_THRESHOLD,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_GRANULARITY,
    SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from btclib.tx.tx import Tx
from btclib.utils import is_integer

__all__ = [
    "AncestorMedianTimePast",
    "assert_coinbase_maturity",
    "assert_coinbase_value",
    "assert_sequence_locks",
    "is_final",
]

# a height, and the median time past of the block at it: what
# `assert_sequence_locks` asks for a time-based lock, over however many
# ancestors the caller's own chain state holds rather than over an index
# this module never sees -- the same shape `header_context.ParentOf` is,
# and for the same reason
AncestorMedianTimePast = Callable[[int], int]


def is_final(tx: Tx, height: int, block_time: int) -> bool:
    """Answer whether `tx` is final at `height`, against a `block_time` cutoff.

    Core's `IsFinalTx` (`src/consensus/tx_verify.cpp`, at
    bitcoin/bitcoin@9be056a8a7): a zero `lock_time` is always final;
    otherwise `tx` is final once `height` or `block_time` -- whichever
    `lock_time`'s own units name, decided against `LOCKTIME_THRESHOLD` --
    has passed it, or regardless if every one of `tx`'s own inputs opts
    out of `lock_time` by carrying `SEQUENCE_FINAL`.

    Which instant `block_time` is, is the caller's: `pindexPrev->
    GetMedianTimePast()` once BIP113 (the CSV deployment) is active on
    the chain being validated against, the block's own timestamp before
    that -- Core's `ContextualCheckBlock` decides it from the chain's own
    activation height, which this function does not carry. A caller
    checking a block reports `False` here as Core's own
    `bad-txns-nonfinal`.
    """
    for name, value in (("height", height), ("block_time", block_time)):
        if not is_integer(value):
            err_msg = f"invalid {name} type: {type(value).__name__}"
            raise BTClibTypeError(err_msg)

    if tx.lock_time == 0:
        return True
    cutoff = height if tx.lock_time < LOCKTIME_THRESHOLD else block_time
    if tx.lock_time < cutoff:
        return True
    return all(tx_in.sequence == SEQUENCE_FINAL for tx_in in tx.vin)


def assert_sequence_locks(
    tx: Tx,
    prevouts: Sequence[Coin],
    height: int,
    tip_median_time_past: int,
    ancestor_median_time_past: AncestorMedianTimePast,
) -> None:
    """Refuse `tx` if a BIP68 relative lock time of its inputs is unmet.

    Core's `CalculateSequenceLocks` and `EvaluateSequenceLocks`, combined
    as `SequenceLocks` is (`src/consensus/tx_verify.cpp`, at
    bitcoin/bitcoin@9be056a8a7): `prevouts` aligned with `tx.vin`, one
    `Coin` per input, in place of a freshly-read `CCoinsViewCache`.

    A transaction below version 2 is skipped, matching BIP68 -- the
    module docstring says why no `enforce_bip68` flag is here to skip
    the rest of it too. An input whose sequence carries
    `SEQUENCE_LOCKTIME_DISABLE_FLAG` is skipped the same way, on its own
    rather than the whole transaction's.

    `height` is `Core`'s own `block.nHeight` -- the height of the block
    the transaction is connecting into, one past its own parent's --
    and `tip_median_time_past` is that parent's `GetMedianTimePast()`,
    the reference a height-based lock is compared against directly and a
    time-based one after `ancestor_median_time_past` has turned each
    input's own relative lock into an absolute one.
    `ancestor_median_time_past(h)` is `header_context.median_time_past`
    of the block at height `h`, called once per time-locked input at
    `max(coin.height - 1, 0)` -- the block before the one that confirmed
    the coin, matching Core's own comment on why: "the smallest allowed
    timestamp of the block containing the txout being spent".

    Refuses with `bad-txns-nonfinal`, the message Core's own
    `ConnectBlock` reports a failure of this rule with.
    """
    if len(prevouts) != len(tx.vin):
        err_msg = f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
        raise BTClibValueError(err_msg)
    for name, value in (
        ("height", height),
        ("tip_median_time_past", tip_median_time_past),
    ):
        if not is_integer(value):
            err_msg = f"invalid {name} type: {type(value).__name__}"
            raise BTClibTypeError(err_msg)

    if tx.version < 2:
        return

    min_height = -1
    min_time = -1
    for tx_in, coin in zip(tx.vin, prevouts, strict=True):
        sequence = tx_in.sequence
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            continue
        if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            coin_time = ancestor_median_time_past(max(coin.height - 1, 0))
            min_time = max(
                min_time,
                coin_time
                + ((sequence & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY)
                - 1,
            )
        else:
            min_height = max(
                min_height, coin.height + (sequence & SEQUENCE_LOCKTIME_MASK) - 1
            )

    if min_height >= height or min_time >= tip_median_time_past:
        raise BTClibValueError("bad-txns-nonfinal")


def assert_coinbase_maturity(prevouts: Sequence[Coin], spend_height: int) -> None:
    """Refuse a spend of a coinbase output not yet `COINBASE_MATURITY` deep.

    Core's `Consensus::CheckTxInputs`, `bad-txns-premature-spend-of-
    coinbase` (`src/consensus/tx_verify.cpp`, at
    bitcoin/bitcoin@9be056a8a7): `spend_height - coin.height <
    COINBASE_MATURITY`, for whichever of `prevouts` is a coinbase output.

    `spend_height` is not always the height of the block connecting the
    spend: a mempool acceptance passes one past the active chain's own
    tip instead, matching Core's own `MemPoolAccept::PreChecks`
    (`m_active_chainstate.m_chain.Height() + 1`, `src/validation.cpp`,
    same tag).
    """
    if not is_integer(spend_height):
        err_msg = f"invalid spend_height type: {type(spend_height).__name__}"
        raise BTClibTypeError(err_msg)

    for coin in prevouts:
        if coin.is_coinbase and spend_height - coin.height < COINBASE_MATURITY:
            raise BTClibValueError("bad-txns-premature-spend-of-coinbase")


def assert_coinbase_value(coinbase: Tx, subsidy: int, fees: int) -> None:
    """Refuse a coinbase paying more than the subsidy plus the fees it collects.

    Core's `bad-cb-amount` (`ConnectBlock`, `src/validation.cpp`, at
    bitcoin/bitcoin@9be056a8a7): `blockReward = nFees +
    GetBlockSubsidy(...)`, refused if `coinbase.GetValueOut() >
    blockReward`. `subsidy` is `btclib.consensus.subsidy`'s answer at the
    block's own height; `fees` is the caller's own sum of what every
    other transaction of the block pays in -- the module docstring says
    why summing them again here would be a second implementation of a
    block connector's own bookkeeping.
    """
    for name, value in (("subsidy", subsidy), ("fees", fees)):
        if not is_integer(value):
            err_msg = f"invalid {name} type: {type(value).__name__}"
            raise BTClibTypeError(err_msg)

    coinbase_value = sum(tx_out.value for tx_out in coinbase.vout)
    ceiling = subsidy + fees
    if coinbase_value > ceiling:
        err_msg = f"bad-cb-amount: {coinbase_value} instead of {ceiling}"
        raise BTClibValueError(err_msg)
