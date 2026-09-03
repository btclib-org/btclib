# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.coin_selection` module.

Three oracles, one per claim the module docstring makes.

**The waste formula** is checked against Bitcoin Core's own
`waste_test` (`bitcoin/bitcoin@4ec6ff022a`,
`src/wallet/test/coinselector_tests.cpp:720`), transcribed rather than
re-derived: each of Core's `add_coin(amount, n, selection, fee,
long_term_fee)` calls fixes a fee and a long-term fee directly, which
this module answers from a rate and a weight instead, so each vector is
reproduced with a weight of one virtual byte and a `FeeRate` chosen so
that `fee_from_vsize` returns exactly Core's own figure.

**The three algorithms** are checked against hand-built candidate sets
small enough to verify by inspection, against two of Core's own
`knapsack_solver_test` vectors (`coinselector_tests.cpp:436` and
`:452-453`, fee-independent at `CFeeRate(0)` and transcribed the same
way as the waste vectors), and against the property every one of them
shares: every candidate a selection returns is one of the candidates it
was given, and the effective value of the selection covers the target.

**The pair with `tx_builder.build_psbt`** is checked the way the issue
that asked for this module says to: a selection is turned into `PsbtIn`
maps and handed to `build_psbt`, whose own fee is asserted against the
rate exactly as `tx_builder_test.py` asserts it independently.
"""

from __future__ import annotations

import random
from collections.abc import Sequence

import pytest

import btclib.coin_selection as coin_selection_module
from btclib.coin_selection import (
    CHANGE_LOWER,
    Candidate,
    SelectionResult,
    _branch_and_bound,
    _waste,
    branch_and_bound,
    knapsack,
    select_coins,
    single_random_draw,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import DUST_RELAY_FEE_RATE, FeeRate, dust_threshold, fee_from_vsize
from btclib.psbt.psbt_in import PsbtIn
from btclib.script import ScriptPubKey, Witness
from btclib.tx import OutPoint, TxOut, input_weight
from btclib.tx_builder import _target_overhead_vsize, build_psbt

# two public keys of no private key anybody holds, as tx_builder_test.py
# uses them: nothing here signs, the scripts existing to be measured and
# dust-checked
PAY_KEY = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CHANGE_KEY = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
PAY_SCRIPT = ScriptPubKey.p2wpkh(PAY_KEY)
CHANGE_SCRIPT = ScriptPubKey.p2wpkh(CHANGE_KEY)

# a p2wpkh input's own weight: no scriptSig, a DER signature and a
# compressed public key in the witness -- the same worst-case satisfaction
# psbt_size.SIG_SIZE and COMPRESSED_PUB_KEY_SIZE assume elsewhere in the
# tree
P2WPKH_WEIGHT = input_weight(b"", Witness(["00" * 72, "00" * 33]))

ONE_SAT_PER_VBYTE = FeeRate.from_sats_per_vbyte(1)
TEN_SAT_PER_VBYTE = FeeRate.from_sats_per_vbyte(10)


def candidate(
    value: int,
    index: int,
    weight: int = P2WPKH_WEIGHT,
    script: ScriptPubKey = PAY_SCRIPT,
) -> Candidate:
    """Return a candidate spending a p2wpkh output of that value."""
    return Candidate(OutPoint(bytes([index]) * 32, 0), TxOut(value, script), weight)


def _rate(sats_per_vbyte: int) -> FeeRate:
    """Return a `FeeRate` that prices exactly `sats_per_vbyte` at 1 vbyte.

    The waste vectors below fix a per-candidate fee directly, the way
    Core's own `add_coin` does; this is what turns such a fee back into a
    `FeeRate` for a `Candidate` of `_ONE_VBYTE_WEIGHT`.
    """
    return FeeRate(sats_per_kvbyte=sats_per_vbyte * 1_000)


# a candidate weighing exactly one virtual byte, so that fee_from_vsize
# of it at _rate(n) is exactly n satoshi -- what turns Core's fixed fee
# figures back into a rate and a weight
_ONE_VBYTE_WEIGHT = 4


def _cents(values: Sequence[int]) -> list[Candidate]:
    """Return one-vbyte candidates of these values, Core's own `add_coin` unit.

    The `knapsack_solver_test` vectors below name their coins in cents;
    the unit does not matter to the arithmetic, only the ratios between
    the values, so this reads them back as bare satoshi.
    """
    return [
        Candidate(
            OutPoint(bytes([i + 1]) * 32, 0), TxOut(v, PAY_SCRIPT), _ONE_VBYTE_WEIGHT
        )
        for i, v in enumerate(values)
    ]


def _target(outputs: Sequence[TxOut], fee_rate: FeeRate, candidate_count: int) -> int:
    """Return what `_prepare` computes as the target: outputs plus overhead.

    Read off `_target_overhead_vsize`, the same production arithmetic
    `_prepare` itself calls, rather than a figure hand-derived and left
    to go stale the day that arithmetic changes -- what the module's own
    boundary is checked against is
    `test_a_changeless_match_funds_build_psbt_with_no_change_script`,
    which asks `build_psbt` and not this module for the answer.
    `candidate_count` is the size of the pool the test at hand actually
    passes in -- `_prepare` reads it from `candidates`, not `outputs`.
    """
    overhead = _target_overhead_vsize(outputs, candidate_count)
    return sum(tx_out.value for tx_out in outputs) + fee_from_vsize(overhead, fee_rate)


def test_candidate_rejects_a_wrong_outpoint() -> None:
    """Refuse an outpoint of the wrong type."""
    for wrong in (None, 1.5, "not an outpoint"):
        with pytest.raises(BTClibTypeError):
            Candidate(wrong, TxOut(1_000, PAY_SCRIPT), P2WPKH_WEIGHT)  # type: ignore[arg-type]


def test_candidate_rejects_a_wrong_tx_out() -> None:
    """Refuse a tx_out of the wrong type."""
    for wrong in (None, 1.5, "not a tx_out"):
        with pytest.raises(BTClibTypeError):
            Candidate(OutPoint(b"\x01" * 32, 0), wrong, P2WPKH_WEIGHT)  # type: ignore[arg-type]


def test_candidate_rejects_a_weight_of_the_wrong_type() -> None:
    """Refuse a weight of the wrong type."""
    for wrong in (None, 1.5, "68"):
        with pytest.raises(BTClibTypeError):
            Candidate(OutPoint(b"\x01" * 32, 0), TxOut(1_000, PAY_SCRIPT), wrong)  # type: ignore[arg-type]


def test_candidate_rejects_a_non_positive_weight() -> None:
    """Refuse a weight of zero or below."""
    for wrong in (0, -1):
        with pytest.raises(BTClibValueError, match="non-positive weight"):
            Candidate(OutPoint(b"\x01" * 32, 0), TxOut(1_000, PAY_SCRIPT), wrong)


def test_candidate_effective_value_is_the_value_less_its_own_fee() -> None:
    """Match fee_from_vsize's own arithmetic rather than a second one."""
    c = candidate(100_000, 1)
    assert c.vsize == P2WPKH_WEIGHT // 4
    assert c.fee(TEN_SAT_PER_VBYTE) == fee_from_vsize(c.vsize, TEN_SAT_PER_VBYTE)
    assert c.effective_value(TEN_SAT_PER_VBYTE) == 100_000 - c.fee(TEN_SAT_PER_VBYTE)


# a check_validity=False candidate, of a shape select_coins has to catch
# on its own: a weight downstream fee_from_vsize does not refuse by
# itself, since a vsize of 0 owes 0 at every rate
_FREE_CANDIDATE = Candidate(
    OutPoint(b"\x02" * 32, 0), TxOut(1_000, PAY_SCRIPT), 0, check_validity=False
)


@pytest.mark.parametrize(
    "algorithm",
    [branch_and_bound, knapsack, single_random_draw],
)
def test_a_check_validity_false_candidate_of_zero_weight_is_refused(
    algorithm: object,
) -> None:
    """Catch what check_validity=False lets through, at every algorithm."""
    with pytest.raises(BTClibValueError, match="non-positive weight"):
        algorithm(  # type: ignore[operator]
            [_FREE_CANDIDATE],
            [TxOut(500, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
        )


def test_select_coins_refuses_a_wrong_typed_candidate_sequence() -> None:
    """Refuse a candidates argument that is not a sequence."""
    with pytest.raises(BTClibTypeError):
        select_coins(
            "not a sequence",  # type: ignore[arg-type]
            [TxOut(500, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
        )


def test_select_coins_refuses_change_spend_weight_without_a_change_script() -> None:
    """Read a change_spend_weight of None as no change wanted."""
    result = select_coins(
        [candidate(100_000, 1)],
        [TxOut(500, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
    )
    assert result.change == 0


def test_select_coins_requires_change_spend_weight_with_a_change_script() -> None:
    """Refuse a change script with no change_spend_weight beside it."""
    with pytest.raises(BTClibValueError, match="change_spend_weight is required"):
        select_coins(
            [candidate(100_000, 1)],
            [TxOut(500, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            CHANGE_SCRIPT.script,
        )


def test_select_coins_refuses_a_non_positive_change_spend_weight() -> None:
    """Refuse a change_spend_weight of zero or below."""
    for wrong in (0, -1):
        with pytest.raises(BTClibValueError, match="non-positive change_spend_weight"):
            select_coins(
                [candidate(100_000, 1)],
                [TxOut(500, PAY_SCRIPT)],
                TEN_SAT_PER_VBYTE,
                ONE_SAT_PER_VBYTE,
                CHANGE_SCRIPT.script,
                wrong,
            )


def test_select_coins_refuses_an_unknown_algorithm_name() -> None:
    """Refuse an algorithms entry naming none of the three."""
    with pytest.raises(BTClibValueError, match="unknown algorithm"):
        select_coins(
            [candidate(100_000, 1)],
            [TxOut(500, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            algorithms=("bnb", "coinjoin"),
        )


def test_select_coins_refuses_an_empty_algorithms_sequence() -> None:
    """Refuse an empty algorithms sequence."""
    with pytest.raises(BTClibValueError, match="no algorithm named"):
        select_coins(
            [candidate(100_000, 1)],
            [TxOut(500, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            algorithms=(),
        )


def test_select_coins_reports_insufficient_funds() -> None:
    """Raise with a specific message rather than answering None."""
    with pytest.raises(BTClibValueError, match="no selection of the candidates covers"):
        select_coins(
            [candidate(1_000, 1)],
            [TxOut(60_000, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
        )


# ---------------------------------------------------------------------------
# The waste formula, transcribed from Core's waste_test
# (bitcoin/bitcoin@4ec6ff022a, src/wallet/test/coinselector_tests.cpp:720).
# Core fixes a fee and a long-term fee per coin directly; here each is
# `_rate(n)` over a one-virtual-byte candidate, so that `Candidate.fee`
# answers exactly `n`.
# ---------------------------------------------------------------------------


def _two_coins(fee: int, long_term_fee: int) -> list[Candidate]:
    """Two candidates, Core's `add_coin(1 * COIN, ..)` and `(2 * COIN, ..)`."""
    return [
        Candidate(
            OutPoint(b"\x01" * 32, 0), TxOut(100_000_000, PAY_SCRIPT), _ONE_VBYTE_WEIGHT
        ),
        Candidate(
            OutPoint(b"\x02" * 32, 0), TxOut(200_000_000, PAY_SCRIPT), _ONE_VBYTE_WEIGHT
        ),
    ]


def test_waste_with_change_is_the_change_cost_and_the_fee_difference() -> None:
    """Core's first waste_test case: change cost plus the fee difference."""
    fee, fee_diff, change_cost, target = 100, 40, 125, 200_000_000
    selected = _two_coins(fee, fee - fee_diff)
    waste = _waste(
        selected,
        target,
        _rate(fee),
        _rate(fee - fee_diff),
        change=1,
        change_cost=change_cost,
    )
    assert waste == fee_diff * 2 + change_cost


def test_waste_grows_with_the_fee_and_a_fixed_long_term_fee() -> None:
    """A higher fee at the same long-term rate raises the waste."""
    fee, fee_diff, change_cost, target = 100, 40, 125, 200_000_000
    lower = _waste(
        _two_coins(fee, fee - fee_diff),
        target,
        _rate(fee),
        _rate(fee - fee_diff),
        change=1,
        change_cost=change_cost,
    )
    higher = _waste(
        _two_coins(fee * 2, fee - fee_diff),
        target,
        _rate(fee * 2),
        _rate(fee - fee_diff),
        change=1,
        change_cost=change_cost,
    )
    assert higher > lower


def test_waste_shrinks_when_the_long_term_fee_exceeds_the_fee() -> None:
    """A long-term rate above the fee lowers the waste."""
    fee, fee_diff, change_cost, target = 100, 40, 125, 200_000_000
    below_long_term = _waste(
        _two_coins(fee, fee + fee_diff),
        target,
        _rate(fee),
        _rate(fee + fee_diff),
        change=1,
        change_cost=change_cost,
    )
    assert below_long_term == fee_diff * -2 + change_cost

    above_long_term = _waste(
        _two_coins(fee, fee - fee_diff),
        target,
        _rate(fee),
        _rate(fee - fee_diff),
        change=1,
        change_cost=change_cost,
    )
    assert below_long_term < above_long_term


def test_waste_without_change_is_the_excess_and_the_fee_difference() -> None:
    """No change: the excess over target stands in for the change cost."""
    fee, fee_diff, excess = 100, 40, 80
    in_amt = 300_000_000
    exact_target = in_amt - fee * 2
    target = exact_target - excess
    waste = _waste(
        _two_coins(fee, fee - fee_diff), target, _rate(fee), _rate(fee - fee_diff), 0, 0
    )
    assert waste == fee_diff * 2 + excess

    waste_above_long_term = _waste(
        _two_coins(fee, fee + fee_diff), target, _rate(fee), _rate(fee + fee_diff), 0, 0
    )
    assert waste_above_long_term == fee_diff * -2 + excess
    assert waste_above_long_term < waste


def test_waste_is_just_the_change_cost_when_fee_equals_long_term_fee() -> None:
    """A fee equal to the long-term rate leaves only the change cost."""
    fee, change_cost, target = 100, 125, 200_000_000
    waste = _waste(
        _two_coins(fee, fee),
        target,
        _rate(fee),
        _rate(fee),
        change=1,
        change_cost=change_cost,
    )
    assert waste == change_cost


def test_waste_is_zero_at_the_exact_target_with_no_fee_difference() -> None:
    """No excess, no fee difference, no change: zero waste."""
    fee, in_amt = 100, 300_000_000
    exact_target = in_amt - fee * 2
    waste = _waste(_two_coins(fee, fee), exact_target, _rate(fee), _rate(fee), 0, 0)
    assert waste == 0


def test_waste_is_negative_when_the_long_term_fee_dominates() -> None:
    """A long-term rate above the fee can make the waste negative."""
    fee, in_amt = 100, 300_000_000
    exact_target = in_amt - fee * 2
    fee_diff = 90
    waste = _waste(
        _two_coins(fee, fee + fee_diff),
        exact_target,
        _rate(fee),
        _rate(fee + fee_diff),
        0,
        0,
    )
    assert waste == -2 * fee_diff


def test_waste_is_negative_with_change_when_the_cost_does_not_offset_it() -> None:
    """A large fee difference can outweigh the change cost too."""
    fee, change_cost, target = 100, 125, 200_000_000
    large_fee_diff = 90
    waste = _waste(
        _two_coins(fee, fee + large_fee_diff),
        target,
        _rate(fee),
        _rate(fee + large_fee_diff),
        change=1,
        change_cost=change_cost,
    )
    assert waste == -55


# ---------------------------------------------------------------------------
# The three algorithms
# ---------------------------------------------------------------------------


def _covers(result: SelectionResult, candidates: Sequence[Candidate]) -> bool:
    """Every selected candidate is one of the candidates offered, once each."""
    pool = list(candidates)
    for c in result.selected:
        if c not in pool:
            return False
        pool.remove(c)
    return True


def test_covers_helper_reports_a_selection_outside_the_pool() -> None:
    """The helper's own negative case, which no algorithm result trips."""
    outside = candidate(1_000, 1)
    result = SelectionResult((outside,), 0, 0, "bnb")
    assert not _covers(result, [candidate(2_000, 2)])


def test_branch_and_bound_finds_the_exact_changeless_match() -> None:
    """The one candidate matching the target exactly is the selection."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    exact = candidate(_target(outputs, TEN_SAT_PER_VBYTE, 2) + fee, 9)
    result = branch_and_bound(
        [exact, candidate(1_000_000, 1)], outputs, TEN_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE
    )
    assert result.selected == (exact,)
    assert result.change == 0
    assert result.algorithm == "bnb"


def test_branch_and_bound_prefers_the_exact_match_within_the_window() -> None:
    """Two candidates both fall in the window; the exact one wastes less."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    target = _target(outputs, TEN_SAT_PER_VBYTE, 2)
    exact = candidate(target + fee, 1)
    # the excess this one leaves is waste the exact match does not carry
    within_window = candidate(target + fee + 50, 2)
    result = branch_and_bound(
        [exact, within_window],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
    )
    assert result.selected == (exact,)


def test_branch_and_bound_raises_when_no_window_match_exists() -> None:
    """No combination lands in the window: bnb raises rather than guesses."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    with pytest.raises(BTClibValueError, match="no changeless selection"):
        branch_and_bound(
            [candidate(100_000, 1), candidate(50_000, 2), candidate(30_000, 3)],
            outputs,
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            CHANGE_SCRIPT.script,
            P2WPKH_WEIGHT,
        )


def test_knapsack_covers_the_target_with_change() -> None:
    """A selection whose effective value covers the target, with change."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    candidates = [candidate(100_000, 1), candidate(50_000, 2), candidate(30_000, 3)]
    result = knapsack(
        candidates,
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        rng=random.Random(0),
    )
    assert _covers(result, candidates)
    total = sum(c.effective_value(TEN_SAT_PER_VBYTE) for c in result.selected)
    assert total >= 60_000
    assert result.algorithm == "knapsack"


def test_knapsack_finds_the_single_exact_match() -> None:
    """An exact match short-circuits the subset-sum search."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    exact = candidate(_target(outputs, TEN_SAT_PER_VBYTE, 2) + fee, 9)
    result = knapsack(
        [exact, candidate(1_000_000, 1)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        rng=random.Random(0),
    )
    assert result.selected == (exact,)


def test_knapsack_falls_back_to_the_lowest_larger_candidate() -> None:
    """Nothing below target: the smallest candidate above it is picked."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    # every candidate below target is missing entirely: the only way to
    # reach it is the smallest one that alone exceeds it
    result = knapsack(
        [candidate(1_000_000, 1), candidate(2_000_000, 2)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        rng=random.Random(0),
    )
    assert result.selected == (candidate(1_000_000, 1),)


def test_knapsack_raises_when_the_pool_is_short_of_the_target() -> None:
    """Every candidate together still short of the target: knapsack raises."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    with pytest.raises(BTClibValueError, match="knapsack"):
        knapsack(
            [candidate(1_000, 1), candidate(2_000, 2)],
            outputs,
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            rng=random.Random(0),
        )


def test_single_random_draw_is_deterministic_under_a_seeded_engine() -> None:
    """The same seed draws the same selection twice."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    candidates = [candidate(100_000, 1), candidate(50_000, 2), candidate(30_000, 3)]
    first = single_random_draw(
        candidates, outputs, TEN_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE, rng=random.Random(42)
    )
    second = single_random_draw(
        candidates, outputs, TEN_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE, rng=random.Random(42)
    )
    assert first.selected == second.selected
    assert first.waste == second.waste


def test_single_random_draw_leaves_room_for_change_lower_bound() -> None:
    """The target SRD draws to includes CHANGE_LOWER, not just the payment."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    result = single_random_draw(
        [candidate(1_000_000, 1)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        rng=random.Random(0),
    )
    total = sum(c.effective_value(TEN_SAT_PER_VBYTE) for c in result.selected)
    assert total >= 60_000 + CHANGE_LOWER


def test_single_random_draw_raises_when_the_shuffle_never_covers_target() -> None:
    """Every candidate shuffled in and still short: SRD raises."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    with pytest.raises(BTClibValueError, match="single random draw"):
        single_random_draw(
            [candidate(1_000, 1)],
            outputs,
            TEN_SAT_PER_VBYTE,
            ONE_SAT_PER_VBYTE,
            rng=random.Random(0),
        )


def test_select_coins_keeps_the_lowest_waste_result() -> None:
    """Among several algorithms that succeed, the lowest waste wins."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    exact = candidate(_target(outputs, TEN_SAT_PER_VBYTE, 4) + fee, 9)
    candidates = [
        exact,
        candidate(100_000, 1),
        candidate(50_000, 2),
        candidate(30_000, 3),
    ]
    result = select_coins(
        candidates,
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        rng=random.Random(3),
    )
    # the exact bnb match has zero change and the least waste among any
    # combination reaching the same target
    assert result.selected == (exact,)
    assert result.algorithm == "bnb"


def test_select_coins_runs_only_the_named_algorithms() -> None:
    """`algorithms` restricts which of the three actually run."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    candidates = [candidate(100_000, 1), candidate(50_000, 2), candidate(30_000, 3)]
    result = select_coins(
        candidates,
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        algorithms=("knapsack",),
        rng=random.Random(0),
    )
    assert result.algorithm == "knapsack"


# ---------------------------------------------------------------------------
# The pair with tx_builder.build_psbt
# ---------------------------------------------------------------------------


def test_a_selection_funds_the_payment_build_psbt_asks_for() -> None:
    """A selection's candidates, turned into PsbtIn maps, fund build_psbt."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    candidates = [candidate(100_000, 1), candidate(50_000, 2), candidate(30_000, 3)]
    result = select_coins(
        candidates,
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        rng=random.Random(11),
    )
    psbt_inputs = [
        PsbtIn(
            witness_utxo=c.tx_out,
            previous_tx_id=c.outpoint.tx_id,
            output_index=c.outpoint.vout,
        )
        for c in result.selected
    ]
    built = build_psbt(psbt_inputs, outputs, TEN_SAT_PER_VBYTE, CHANGE_SCRIPT.script)
    assert built.fee == fee_from_vsize(built.psbt.vsize_estimate(), TEN_SAT_PER_VBYTE)
    total_in = sum(c.tx_out.value for c in result.selected)
    assert total_in == sum(o.value for o in outputs) + built.fee + built.change


def test_a_changeless_match_funds_build_psbt_with_no_change_script() -> None:
    """The target's own overhead term closes the gap `build_psbt` would find.

    `branch_and_bound`'s target is `sum(outputs)` plus what the
    transaction's own version, lock time, output count and output bytes
    cost -- `_target_overhead_vsize`, read from `build_psbt`'s own
    estimate rather than a second copy of it. A changeless match built
    to the satoshi against this target now funds `build_psbt` exactly,
    where matching `sum(outputs)` alone once left it short by the bytes
    only the whole transaction, and not one candidate, carries.
    """
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    exact = candidate(
        _target(outputs, TEN_SAT_PER_VBYTE, 1) + candidate(0, 9).fee(TEN_SAT_PER_VBYTE),
        9,
    )
    result = branch_and_bound([exact], outputs, TEN_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE)
    assert result.change == 0
    psbt_inputs = [
        PsbtIn(
            witness_utxo=c.tx_out,
            previous_tx_id=c.outpoint.tx_id,
            output_index=c.outpoint.vout,
        )
        for c in result.selected
    ]
    built = build_psbt(psbt_inputs, outputs, TEN_SAT_PER_VBYTE)
    assert built.change_index is None


def test_target_overhead_is_padded_at_the_pool_size_var_int_boundary() -> None:
    """253 candidates: the pool's own var_int grows past one byte.

    `_target_overhead_vsize` bounds the input count's own var_int by the
    candidate pool's size, `len(candidates)`, since the count actually
    selected is not yet known and can never exceed it. Below 253
    candidates that var_int is one byte either way and the pad is zero;
    here the pool is exactly 253, and every one of them has to be
    selected to reach the target, so the built transaction's own
    var_int really does grow to three bytes -- `build_psbt` is the
    oracle that proves the padded target still funds it. Real p2wpkh
    candidates, not the one-vbyte trick: `build_psbt`'s own size
    estimate reads each input's script, not `Candidate.weight`, so a
    weight this module is not actually asked to price would misprice
    the very thing this test checks.
    """
    pool_size = 253
    per_candidate = 100
    fee = candidate(0, 254).fee(TEN_SAT_PER_VBYTE)
    overhead = _target_overhead_vsize([TxOut(0, PAY_SCRIPT)], pool_size)
    overhead_fee = fee_from_vsize(overhead, TEN_SAT_PER_VBYTE)
    target = pool_size * per_candidate
    outputs = [TxOut(target - overhead_fee, PAY_SCRIPT)]
    # summed effective value across the whole pool matches target exactly
    candidates = [candidate(per_candidate + fee, i) for i in range(1, pool_size + 1)]
    result = knapsack(
        candidates, outputs, TEN_SAT_PER_VBYTE, TEN_SAT_PER_VBYTE, rng=random.Random(0)
    )
    assert len(result.selected) == pool_size
    psbt_inputs = [
        PsbtIn(
            witness_utxo=c.tx_out,
            previous_tx_id=c.outpoint.tx_id,
            output_index=c.outpoint.vout,
        )
        for c in result.selected
    ]
    built = build_psbt(psbt_inputs, outputs, TEN_SAT_PER_VBYTE)
    assert built.change_index is None


def test_dust_fee_rate_decides_whether_change_survives() -> None:
    """Below the dust threshold change is dropped; above it, it is created."""
    outputs = [TxOut(1_000, PAY_SCRIPT)]
    threshold = dust_threshold(CHANGE_SCRIPT.script, DUST_RELAY_FEE_RATE)
    # what a candidate's own value has to clear before a single satoshi of
    # change exists: the target, the change output's own creation fee, and
    # this candidate's own fee at the same weight every candidate() below
    # carries
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    creation_fee = fee_from_vsize(
        coin_selection_module._change_output_vsize(CHANGE_SCRIPT.script),
        TEN_SAT_PER_VBYTE,
    )
    base = _target(outputs, TEN_SAT_PER_VBYTE, 1) + creation_fee + fee

    # too little left over for change to clear the dust threshold: dropped
    dropped = select_coins(
        [candidate(base + threshold - 1, 1)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        dust_fee_rate=DUST_RELAY_FEE_RATE,
        rng=random.Random(0),
    )
    assert dropped.change == 0

    # plenty left over: change clears the threshold and is created
    created = select_coins(
        [candidate(base + threshold + 10_000, 2)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        P2WPKH_WEIGHT,
        dust_fee_rate=DUST_RELAY_FEE_RATE,
        rng=random.Random(0),
    )
    assert created.change >= threshold


# ---------------------------------------------------------------------------
# The corners the tests above do not reach on their own
# ---------------------------------------------------------------------------


def test_change_spend_weight_of_the_wrong_type_is_a_type_error() -> None:
    """A change_spend_weight of the wrong type leaves as a type error."""
    for wrong in (1.5, "68"):
        with pytest.raises(BTClibTypeError, match="invalid change_spend_weight type"):
            select_coins(
                [candidate(100_000, 1)],
                [TxOut(500, PAY_SCRIPT)],
                TEN_SAT_PER_VBYTE,
                ONE_SAT_PER_VBYTE,
                CHANGE_SCRIPT.script,
                wrong,  # type: ignore[arg-type]
            )


def test_branch_and_bound_raises_on_an_empty_eligible_pool() -> None:
    """Every candidate priced out at this rate: the search pool is empty."""
    outputs = [TxOut(500, PAY_SCRIPT)]
    worthless = candidate(1, 1)  # a p2wpkh input's own fee alone exceeds this
    with pytest.raises(BTClibValueError, match="no changeless selection"):
        branch_and_bound([worthless], outputs, TEN_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE)


def test_branch_and_bound_keeps_the_lower_waste_of_two_window_matches() -> None:
    """A whitebox check of the search itself: the second match found is worse.

    Two single-candidate matches both fall in a `[target, target +
    cost_of_change]` window of 5000; the higher-effective-value one is
    explored first (the pool is sorted descending) and has the lower
    total waste, so when the second is evaluated the search must keep
    the first rather than replace it -- the `waste <= best_waste` branch
    answering False, which a single-solution search never exercises.
    """
    fee_rate = _rate(10)
    long_term_fee_rate = _rate(1)
    # weight 48 -> vsize 12 -> fee 120, long-term fee 12, waste_i 108
    tried_first = Candidate(OutPoint(b"\x01" * 32, 0), TxOut(64_120, PAY_SCRIPT), 48)
    # weight 1780 -> vsize 445 -> fee 4450, long-term fee 445, waste_i 4005
    tried_second = Candidate(OutPoint(b"\x02" * 32, 0), TxOut(64_950, PAY_SCRIPT), 1780)
    assert tried_first.effective_value(fee_rate) == 64_000
    assert tried_second.effective_value(fee_rate) == 60_500
    selected = _branch_and_bound(
        [tried_first, tried_second], 60_000, 5_000, fee_rate, long_term_fee_rate
    )
    assert selected == [tried_first]


def test_branch_and_bound_stops_at_the_search_budget() -> None:
    """`_BNB_TOTAL_TRIES` bounds the search; a tiny budget hits it at once."""
    original = coin_selection_module._BNB_TOTAL_TRIES
    coin_selection_module._BNB_TOTAL_TRIES = 1
    try:
        candidates = [candidate(40_000, 1), candidate(35_000, 2), candidate(30_000, 3)]
        with pytest.raises(BTClibValueError, match="no changeless selection"):
            branch_and_bound(
                candidates,
                [TxOut(60_000, PAY_SCRIPT)],
                TEN_SAT_PER_VBYTE,
                ONE_SAT_PER_VBYTE,
            )
    finally:
        coin_selection_module._BNB_TOTAL_TRIES = original


def test_knapsack_approximate_best_subset_improves_on_the_first_pass() -> None:
    """Three candidates admit several subsets; the search finds a smaller one.

    `total_lower`, every applicable candidate summed, is only ever the
    starting guess -- `ApproximateBestSubset` keeps searching as long as
    a restart lands on a smaller total that still covers the target, and
    with three candidates admitting several such subsets it must find one.
    """
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    candidates = [candidate(40_000, 1), candidate(35_000, 2), candidate(30_000, 3)]
    result = knapsack(
        candidates, outputs, ONE_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE, rng=random.Random(2)
    )
    assert _covers(result, candidates)
    total = sum(c.effective_value(ONE_SAT_PER_VBYTE) for c in result.selected)
    assert (
        60_000 <= total < sum(c.effective_value(ONE_SAT_PER_VBYTE) for c in candidates)
    )


def test_knapsack_skips_the_widened_search_short_of_the_change_window() -> None:
    """`total_lower` short of `target + change_target`: no second pass.

    A change script asks the subset-sum search for a total anywhere up to
    `target + change_target`, but only once the first pass, aimed at
    `target` alone, has already failed to find an exact match *and*
    `total_lower` reaches that wider window -- short of it, as here, a
    second restart at the wider target would only repeat the first
    search's own answer, so `_knapsack` does not run it.
    """
    fee_rate = _rate(0)
    long_term_fee_rate = _rate(5)
    outputs = [TxOut(16, PAY_SCRIPT)]
    # 6+7+7 = 20: at or above target, short of target + change_target (21),
    # and no subset of the three sums to 16 exactly
    cents = _cents([6, 7, 7])
    result = knapsack(
        cents,
        outputs,
        fee_rate,
        long_term_fee_rate,
        CHANGE_SCRIPT.script,
        _ONE_VBYTE_WEIGHT,
        rng=random.Random(0),
    )
    assert sorted(c.tx_out.value for c in result.selected) == [6, 7, 7]
    assert result.change == 0


def test_knapsack_returns_every_applicable_candidate_on_an_exact_total() -> None:
    """`total_lower == target`: nothing is left out and nothing is added."""
    fee_rate = _rate(1)
    outputs = [TxOut(1_998, PAY_SCRIPT)]
    target = _target(outputs, fee_rate, 2)
    # each candidate weighs one vbyte, so its own fee at fee_rate is 1 --
    # split target plus the two fees between the two candidate values
    half = target // 2
    a = Candidate(
        OutPoint(b"\x01" * 32, 0), TxOut(half + 1, PAY_SCRIPT), _ONE_VBYTE_WEIGHT
    )
    b = Candidate(
        OutPoint(b"\x02" * 32, 0),
        TxOut(target - half + 1, PAY_SCRIPT),
        _ONE_VBYTE_WEIGHT,
    )
    result = knapsack([a, b], outputs, fee_rate, fee_rate, rng=random.Random(0))
    assert set(result.selected) == {a, b}


def test_knapsack_prefers_the_lowest_larger_when_it_beats_the_subset() -> None:
    """A single candidate just above target can beat every subset found."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    just_above = candidate(61_000, 4)
    candidates = [
        candidate(40_000, 1),
        candidate(35_000, 2),
        candidate(30_000, 3),
        just_above,
    ]
    result = knapsack(
        candidates, outputs, ONE_SAT_PER_VBYTE, ONE_SAT_PER_VBYTE, rng=random.Random(5)
    )
    assert result.selected == (just_above,)


def test_knapsack_prefers_the_single_bigger_coin_over_a_larger_subset() -> None:
    """Core's `knapsack_solver_test`, result10: `bitcoin/bitcoin@4ec6ff022a`.

    `coinselector_tests.cpp:436`: candidates of 6, 7, 8, 20 and 30 cents
    against a target of 16 -- the smaller coins best only 6+7+8=21, not as
    good as the next biggest coin alone, 20, so the single 20-cent coin
    is what `KnapsackSolver` returns. `CFeeRate(0)` in Core's own
    `add_coin` calls, transcribed as `_rate(0)` here, is what makes the
    vector fee-independent: effective value is the coin's own amount.
    """
    fee_rate = _rate(0)
    cents = _cents([6, 7, 8, 20, 30])
    result = knapsack(
        cents, [TxOut(16, PAY_SCRIPT)], fee_rate, fee_rate, rng=random.Random(0)
    )
    assert [c.tx_out.value for c in result.selected] == [20]


def test_knapsack_breaks_a_subset_sum_tie_toward_the_single_coin() -> None:
    """Core's `knapsack_solver_test`, result12: `bitcoin/bitcoin@4ec6ff022a`.

    `coinselector_tests.cpp:452-453`: candidates of 5, 6, 7, 8, 18, 20 and 30
    cents against a target of 16 -- the smaller coins can make 5+6+7=18,
    exactly what the next biggest coin, 18, holds alone. `KnapsackSolver`
    ties in favour of the single coin, `ApproximateBestSubset`'s own
    `best_included` starting from `total_lower`'s all-included subset and
    only ever replacing it with a *smaller* total, so a tie never
    displaces the single coin already ahead of it in `lowest_larger`.
    """
    fee_rate = _rate(0)
    cents = _cents([5, 6, 7, 8, 18, 20, 30])
    result = knapsack(
        cents, [TxOut(16, PAY_SCRIPT)], fee_rate, fee_rate, rng=random.Random(0)
    )
    assert [c.tx_out.value for c in result.selected] == [18]


def test_select_coins_with_a_single_algorithm_skips_the_other_two() -> None:
    """algorithms=('bnb',) answers precisely as branch_and_bound would."""
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    fee = candidate(0, 9).fee(TEN_SAT_PER_VBYTE)
    exact = candidate(_target(outputs, TEN_SAT_PER_VBYTE, 2) + fee, 9)
    result = select_coins(
        [exact, candidate(100_000, 1)],
        outputs,
        TEN_SAT_PER_VBYTE,
        ONE_SAT_PER_VBYTE,
        algorithms=("bnb",),
    )
    assert result.algorithm == "bnb"
    assert result.selected == (exact,)
