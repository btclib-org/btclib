# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Choose which candidates fund a payment, before `tx_builder.build_psbt` runs.

`build_psbt` spends every input it is handed, all of them --
`tx_builder`'s module docstring draws that boundary in as many words.
Something upstream of it has to decide *which* utxos those are, and
nothing in the tree did: a caller with a set of unspent outputs and a
target picked by hand, and a hand pick gets two things wrong that this
module exists to compute instead -- change worth less than
`fee.dust_threshold` that should have gone to the fee, and an input
whose own weight costs more than it is worth at the chosen rate.

**Stateless and caller-driven**, the same boundary `fee` and
`tx_builder` draw for the same reason: no wallet, no utxo database, no
node. A `Candidate` is an outpoint, the `TxOut` it names, and the
weight its input will add -- `tx.input_weight`'s answer, supplied by the
caller rather than guessed here, since guessing a script's future
satisfaction is exactly what `psbt.psbt_size.SolutionSizer` exists to
refuse doing blindly. `select_coins` and each of the three algorithms
behind it take those candidates, the outputs being paid, a fee rate, and
answer with the ones to spend and what change, if any, is worth
creating -- `build_psbt` turns that answer into the funded psbt, and is
the authority on the transaction's own final fee: this module's `change`
is what the selection expects, priced on its own simpler arithmetic, not
a second computation of what `build_psbt` will price exactly once the
psbt exists. A candidate's own fee is what its own weight costs, at
`fee_rate`; `target` is that plus what the rest of the transaction costs
-- `tx_builder._target_overhead_vsize`, the version, the lock time, the
output count and the outputs themselves, `build_psbt`'s own estimate
read off a psbt of no inputs rather than a second copy of its
arithmetic, so the two cannot drift apart. Padded by one virtual byte
for the segwit marker, present once any selected input carries a
witness and absent otherwise -- a fact this function, asked before a
single input is chosen, cannot know -- the pad rounding the estimate up
so that a witness-only selection is never short, at the cost of a
witness-free one being asked for one virtual byte it will not spend.
Padded again for the input count's own var_int, bounded by the size of
the candidate pool rather than by the selection chosen from it -- also
not yet decided when this is asked, but never larger than the pool it
is chosen from -- so a pool of 253 candidates or more, where a var_int
grows past one byte, is never short either; below that the pad is zero
and this changes nothing.

**Effective value** -- an output's value less the fee its own input
costs at the chosen rate -- is the quantity every algorithm here selects
on, `Candidate.effective_value`. It is what makes a candidate costing
more to spend than it holds fall out of a selection on its own, rather
than needing a filter a caller has to remember to write.

**The algorithms are Bitcoin Core's**, because they are the ones with
published behaviour to check a port against: `branch_and_bound` searches
for a changeless match within a window above the target, sized by the
cost of creating and later spending change; `knapsack` is Core's
original stochastic subset-sum solver; `single_random_draw` shuffles the
candidates and takes them in that order until the target, plus a lower
bound on the change worth creating, is covered. `select_coins` runs
whichever of the three the caller names -- every one of them, by default
-- and keeps the result of lowest waste, Core's own
`SelectionResult::GetWaste` metric: the difference between what each
selected input costs now and what it would cost at the long-term rate,
plus the cost of the change it creates or, where none is worth creating,
the excess dropped to the fee. `bitcoin/bitcoin@4ec6ff022a`'s
`src/wallet/coinselection.cpp` is where all four are read from.

**What Core's own implementation carries that this one does not, and
why**: an `OutputGroup` batching several utxos of one address, ancestor
and cluster tracking for mempool policy, a maximum selection weight, and
`CoinGrinder`, the fourth algorithm Core added for the weight-minimising
case a `-maxtxweight` policy asks for. Every one of them is wallet
state or mempool policy this module has no access to and the parent
issue draws the same line in front of: privacy-aware grouping is
Electrum's `coinchooser`, named in the issue this module answers as the
pluggable policy a caller brings on top rather than the default here.

`_branch_and_bound` also drops three of Core's own pruning and ordering
refinements. None of them changes which selection the search returns --
the search space is still fully explored inside `_BNB_TOTAL_TRIES`,
only in a different order or with a different early exit along the way:
Core's `descending` comparator
breaks a tie on equal effective value by the lower-waste candidate
(`coinselection.cpp:27-36`), where this module's own sort leaves such a
tie in whatever order the pool arrived in; the `is_feerate_high &&
curr_selection_waste > best_waste` cut (`coinselection.cpp:192-198`)
abandons a partial selection early once no number of further inputs
could beat the best one found at a high fee rate, which this module
does not check and instead lets the budget spend on to the same
conclusion; and the SHIFT loop's skip-clone step
(`coinselection.cpp:243-259`) advances past a run of candidates of
equal effective value rather than evaluating each, which this module
evaluates individually within the same `TOTAL_TRIES` budget.

**Randomness is a parameter, not a call.** `knapsack` and
`single_random_draw` both shuffle, and both take a `random.Random`
instead of reading the module-level `random` functions, so that a test
-- or a caller who wants a reproducible selection -- seeds it. Bitcoin
Core's own reason is the opposite one: `FastRandomContext` is unseeded
by default because a wallet's coin selection must not be predictable
from the outside. Nothing here waives that for a production caller who
passes no seed; `random.Random()` reads system entropy exactly as the
module-level functions do, and is only ever a caller's *explicit*
choice of engine, never this module's own hidden one.

**RBF, CPFP and cancel-by-double-spend stay out**, as the parent issue
lists them: each needs the ownership and change metadata of a change
this module does not track once `select_coins` returns it.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from math import ceil

from btclib import var_int
from btclib.alias import Octets
from btclib.consensus import WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import DUST_RELAY_FEE_RATE, FeeRate, dust_threshold, fee_from_vsize
from btclib.tx import OutPoint, TxOut
from btclib.tx_builder import _target_overhead_vsize
from btclib.utils import assert_type, bytes_from_octets, is_integer

__all__ = [
    "CHANGE_LOWER",
    "Candidate",
    "SelectionResult",
    "branch_and_bound",
    "knapsack",
    "select_coins",
    "single_random_draw",
]

# Core's wallet/coinselection.h CHANGE_LOWER: the smallest change amount
# single random draw ever aims to create, so that a selection landing
# just past the target does not leave a change output worth a handful of
# satoshi. Only single_random_draw reads it -- branch_and_bound and
# knapsack are given the cost of change directly, and size their own
# window from it -- but it is public for the same reason FeeRate's own
# constant is: a caller comparing this module's numbers against Core's
# wants the figure named rather than repeated.
CHANGE_LOWER = 50_000

# the total tries branch_and_bound explores before it stops looking for a
# better solution and returns the best one found so far -- Core's own
# TOTAL_TRIES, coinselection.cpp:113. Search space, not calendar time:
# raised only if a real candidate set is shown to exhaust it short of a
# solution that exists
_BNB_TOTAL_TRIES = 100_000

# ApproximateBestSubset's own iteration count, coinselection.cpp:678 --
# how many random restarts the stochastic subset-sum solver tries before
# giving up on an exact match and falling back to its closest one
_KNAPSACK_ITERATIONS = 1_000


@dataclass(frozen=True)
class Candidate:
    """One utxo under consideration for spending: what and how much it costs.

    `outpoint` and `tx_out` are what any input needs; `weight` is what
    only a caller can answer -- `tx.input_weight` given the scriptSig and
    witness this input's future satisfaction will carry, the same figure
    `psbt.psbt_size.SolutionSizer` computes for an input already claimed
    by a psbt. Guessing it here from `tx_out.script_pub_key` alone would
    be wrong for exactly the inputs `SolutionSizer` itself refuses to
    guess: a script of no standard type, or a taproot script-path spend
    naming a leaf nothing but the caller knows.
    """

    outpoint: OutPoint
    tx_out: TxOut
    weight: int

    def __init__(
        self,
        outpoint: OutPoint,
        tx_out: TxOut,
        weight: int,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "outpoint", outpoint)
        object.__setattr__(self, "tx_out", tx_out)
        object.__setattr__(self, "weight", weight)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a wrong-typed outpoint or output, or a non-positive weight."""
        assert_type(self.outpoint, OutPoint, "outpoint")
        self.outpoint.assert_valid()
        assert_type(self.tx_out, TxOut, "tx_out")
        self.tx_out.assert_valid()

        if not is_integer(self.weight):
            raise BTClibTypeError(f"invalid weight type: {type(self.weight).__name__}")
        if self.weight <= 0:
            # zero is refused beside a negative one: a weightless input
            # spends for free, which no scriptSig and no witness do, and
            # every arithmetic below divides by it or through it
            raise BTClibValueError(f"non-positive weight: {self.weight}")

    @property
    def vsize(self) -> int:
        """Return this input's own virtual size, `Tx.vsize`'s own rounding."""
        return ceil(self.weight / WITNESS_SCALE_FACTOR)

    def fee(self, fee_rate: FeeRate) -> int:
        """Return what spending this input costs at `fee_rate`."""
        return fee_from_vsize(self.vsize, fee_rate)

    def effective_value(self, fee_rate: FeeRate) -> int:
        """Return the value less what spending this input costs, at `fee_rate`.

        Non-positive for an input whose own weight costs at least what it
        holds -- every algorithm here excludes such a candidate from its
        search, matching Core's own precondition that an `OutputGroup`
        entering coin selection already has a positive one.
        """
        return self.tx_out.value - self.fee(fee_rate)


@dataclass(frozen=True)
class SelectionResult:
    """What a selection chose, the change it leaves, and its waste score.

    `change` is 0 where none is worth creating -- below
    `fee.dust_threshold` for `change_script_pub_key`, or where the caller
    named none -- in which case the excess this selection leaves over
    the outputs is dropped to the fee instead, exactly as `build_psbt`
    treats a change output it finds itself unable to create.

    `waste` is Core's `SelectionResult::GetWaste`: comparable across
    algorithms and across selections of the same candidates, and it is
    what `select_coins` orders its attempts by. It is not a fee -- a
    negative value means the long-term rate exceeds the current one, so
    that spending these inputs now rather than consolidating them later
    is a saving instead of a cost.
    """

    selected: tuple[Candidate, ...]
    change: int
    waste: int
    algorithm: str


def _eligible(candidates: Sequence[Candidate], fee_rate: FeeRate) -> list[Candidate]:
    """Return the candidates worth spending at all, at this rate.

    Every algorithm below calls this before it searches: a candidate
    whose effective value is not positive can only ever make a selection
    worse by joining it, so none of the three ever considers one.
    """
    return [c for c in candidates if c.effective_value(fee_rate) > 0]


def _change_output_vsize(change_script_pub_key: bytes) -> int:
    """Return the size a change output of this script adds to the transaction.

    An output is never in the witness, so its virtual size is its size:
    8 bytes of value, the script's own var_int length, and the script.
    The same arithmetic `fee.dust_threshold` computes for the output half
    of its own threshold.
    """
    return (
        8
        + len(var_int.serialize(len(change_script_pub_key)))
        + len(change_script_pub_key)
    )


def _change_cost(
    change_script_pub_key: bytes,
    change_spend_weight: int,
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
) -> int:
    """Return the cost of creating this change output now and spending it later.

    Core's `CoinSelectionParams.m_cost_of_change`: the fee `fee_rate`
    charges the output's own bytes, plus the fee `long_term_fee_rate`
    charges spending it -- `change_spend_weight` being that future
    input's own weight, the same figure a `Candidate` carries for a
    present one, since this module has no more business guessing it for
    an output that does not exist yet than `Candidate.weight` lets it
    guess for one that already does.
    """
    creation_fee = fee_from_vsize(_change_output_vsize(change_script_pub_key), fee_rate)
    spend_vsize = ceil(change_spend_weight / WITNESS_SCALE_FACTOR)
    spend_fee = fee_from_vsize(spend_vsize, long_term_fee_rate)
    return creation_fee + spend_fee


def _waste(
    selected: Sequence[Candidate],
    target: int,
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change: int,
    change_cost: int,
) -> int:
    """Return Core's waste score for this selection: `RecalculateWaste`.

    The cost of spending every selected input now rather than at the
    long-term rate, plus -- where `change` is worth creating -- the cost
    of creating and later spending it, or -- where it is not -- the
    excess this selection leaves over `target`, which is what is dropped
    to the fee instead.
    """
    fee_diff = sum(c.fee(fee_rate) - c.fee(long_term_fee_rate) for c in selected)
    if change:
        return fee_diff + change_cost
    effective_total = sum(c.effective_value(fee_rate) for c in selected)
    return fee_diff + (effective_total - target)


def _score(
    selected: Sequence[Candidate],
    target: int,
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: bytes | None,
    change_spend_weight: int | None,
    dust_fee_rate: FeeRate,
    algorithm: str,
) -> SelectionResult:
    """Turn a raw selection into the `SelectionResult` a caller reads.

    Where `build_psbt` decides a change output against the psbt's own
    estimated size, this decides it against this selection's own simpler
    one -- the two agree unless a selection lands exactly on the
    boundary, which is `build_psbt`'s decision to make, this module's
    `change` being what the selection expected rather than a claim about
    the funded psbt.
    """
    effective_total = sum(c.effective_value(fee_rate) for c in selected)
    change = 0
    change_cost = 0
    if change_script_pub_key is not None:
        assert change_spend_weight is not None  # noqa: S101 -- _prepare's own contract
        change_cost = _change_cost(
            change_script_pub_key, change_spend_weight, fee_rate, long_term_fee_rate
        )
        creation_fee = fee_from_vsize(
            _change_output_vsize(change_script_pub_key), fee_rate
        )
        candidate_change = effective_total - target - creation_fee
        if candidate_change >= dust_threshold(change_script_pub_key, dust_fee_rate):
            change = candidate_change
    waste = _waste(selected, target, fee_rate, long_term_fee_rate, change, change_cost)
    return SelectionResult(tuple(selected), change, waste, algorithm)


def _assert_selection_arguments(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None,
    change_spend_weight: int | None,
    dust_fee_rate: FeeRate,
) -> None:
    """Refuse an argument of the wrong type or shape before anything runs.

    The shape every one of `select_coins` and the three algorithms
    beside it shares, walked the way `tx_builder._assert_arguments` walks
    its own two sequences: as a sequence first, then element by element.
    `assert_valid` on each candidate and output, and not the type check
    alone, is what a `check_validity=False` instance -- a `Candidate` of
    a weight no `tx.input_weight` ever answers, a `TxOut` of no valid
    amount -- needs: nothing downstream of this function builds another
    object that would validate them the way `tx_builder.build_psbt`
    defers to `Psbt`'s own.
    """
    assert_type(candidates, Sequence, "candidates")
    for candidate in candidates:
        assert_type(candidate, Candidate, "candidate")
        candidate.assert_valid()
    assert_type(outputs, Sequence, "outputs")
    for tx_out in outputs:
        assert_type(tx_out, TxOut, "output")
        tx_out.assert_valid()
    assert_type(fee_rate, FeeRate, "fee rate")
    assert_type(long_term_fee_rate, FeeRate, "long-term fee rate")
    assert_type(dust_fee_rate, FeeRate, "dust fee rate")
    if change_script_pub_key is not None and change_spend_weight is None:
        err_msg = "change_spend_weight is required together with change_script_pub_key"
        raise BTClibValueError(err_msg)
    if change_spend_weight is not None:
        if not is_integer(change_spend_weight):
            err_msg = f"invalid change_spend_weight type: {type(change_spend_weight).__name__}"
            raise BTClibTypeError(err_msg)
        if change_spend_weight <= 0:
            raise BTClibValueError(
                f"non-positive change_spend_weight: {change_spend_weight}"
            )


def _prepare(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None,
    change_spend_weight: int | None,
    dust_fee_rate: FeeRate,
) -> tuple[list[Candidate], int, int, bytes | None]:
    """Validate, then return the eligible pool, the target and change budget.

    Shared by `select_coins` and the three algorithms it composes, so
    that "which candidates are worth considering" and "how large a
    window is change worth" are answered once rather than once per
    algorithm. `target` is `sum(outputs)` plus what the transaction's
    own non-input bytes cost at `fee_rate` -- `tx_builder`'s own
    `_target_overhead_vsize`, so that a selection matching this target is
    one `build_psbt` can actually fund rather than one that is short by
    the bytes only the whole transaction, and not one candidate, carries.
    """
    _assert_selection_arguments(
        candidates,
        outputs,
        fee_rate,
        long_term_fee_rate,
        change_script_pub_key,
        change_spend_weight,
        dust_fee_rate,
    )
    change_script = (
        None
        if change_script_pub_key is None
        else bytes_from_octets(change_script_pub_key)
    )
    overhead_vsize = _target_overhead_vsize(outputs, len(candidates))
    overhead_fee = fee_from_vsize(overhead_vsize, fee_rate)
    target = sum(tx_out.value for tx_out in outputs) + overhead_fee
    eligible = _eligible(candidates, fee_rate)
    change_cost = 0
    if change_script is not None:
        assert change_spend_weight is not None  # noqa: S101 -- asserted above
        change_cost = _change_cost(
            change_script, change_spend_weight, fee_rate, long_term_fee_rate
        )
    return eligible, target, change_cost, change_script


def branch_and_bound(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None = None,
    change_spend_weight: int | None = None,
    *,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
) -> SelectionResult:
    """Search for a changeless selection, Core's `SelectCoinsBnB`.

    A depth-first search over the candidates sorted by descending
    effective value, exploring inclusion before omission: a selection
    landing within `[target, target + cost_of_change]` -- the window a
    change output would otherwise have to absorb -- is a solution, and
    the search keeps the one of lowest waste rather than stopping at the
    first. `cost_of_change` is 0 where `change_script_pub_key` is None,
    which asks this search for an exact match to the satoshi -- the
    window a caller sweeping every last one of a set of candidates to a
    single output wants.

    Raised as `BTClibValueError`: no combination of `candidates` reaches
    `target` within the window, at this rate.
    """
    eligible, target, cost_of_change, change_script = _prepare(
        candidates,
        outputs,
        fee_rate,
        long_term_fee_rate,
        change_script_pub_key,
        change_spend_weight,
        dust_fee_rate,
    )
    selected = _branch_and_bound(
        eligible, target, cost_of_change, fee_rate, long_term_fee_rate
    )
    if selected is None:
        err_msg = f"branch and bound: no changeless selection reaches {target} satoshi"
        raise BTClibValueError(err_msg)
    return _score(
        selected,
        target,
        fee_rate,
        long_term_fee_rate,
        change_script,
        change_spend_weight,
        dust_fee_rate,
        "bnb",
    )


# translated close to Core's own branching shape rather than split apart:
# splitting it risks diverging from SelectCoinsBnB's exact search order,
# which is what a caller checking against Core's own vectors relies on
def _branch_and_bound(  # noqa: C901, PLR0912
    pool: Sequence[Candidate],
    target: int,
    cost_of_change: int,
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
) -> list[Candidate] | None:
    """Translate `coinselection.cpp`'s `SelectCoinsBnB`: the search itself.

    Working on indices into `pool`, sorted once by descending effective
    value, exactly as Core's own `utxo_pool` is: the sort is what makes
    the lookahead sum below answer "how much could still be added"
    without recomputing it at every node.
    """
    if not pool:
        return None
    ordered = sorted(pool, key=lambda c: c.effective_value(fee_rate), reverse=True)
    eff = [c.effective_value(fee_rate) for c in ordered]
    waste_i = [c.fee(fee_rate) - c.fee(long_term_fee_rate) for c in ordered]
    n = len(ordered)

    lookahead = [0] * n
    total = 0
    for i in range(n - 1, -1, -1):
        lookahead[i] = total
        total += eff[i]

    if total < target:
        return None

    curr_selection: list[int] = []
    best_selection: list[int] | None = None
    curr_amount = 0
    curr_waste = 0
    best_waste: int | None = None
    next_index = 0
    curr_try = 0

    def deselect_last() -> None:
        nonlocal curr_amount, curr_waste
        i = curr_selection.pop()
        curr_amount -= eff[i]
        curr_waste -= waste_i[i]

    is_done = False
    while not is_done:
        should_cut = False
        should_shift = False

        i = next_index
        curr_amount += eff[i]
        curr_waste += waste_i[i]
        curr_selection.append(i)
        next_index += 1
        curr_try += 1

        tail_lookahead = lookahead[curr_selection[-1]]
        if curr_amount + tail_lookahead < target:
            should_cut = True
        elif curr_amount > target + cost_of_change:
            should_shift = True
        elif curr_amount >= target:
            should_shift = True
            excess = curr_amount - target
            waste = curr_waste + excess
            if best_waste is None or waste <= best_waste:
                best_selection = list(curr_selection)
                best_waste = waste

        if curr_try >= _BNB_TOTAL_TRIES:
            break

        if next_index == n:
            should_cut = True

        if should_cut:
            deselect_last()
            should_shift = True

        while should_shift:
            if not curr_selection:
                is_done = True
                break
            next_index = curr_selection[-1] + 1
            deselect_last()
            should_shift = False

    if best_selection is None:
        return None
    return [ordered[i] for i in best_selection]


def knapsack(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None = None,
    change_spend_weight: int | None = None,
    *,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
    rng: random.Random | None = None,
) -> SelectionResult:
    """Solve subset sum by stochastic approximation, Core's `KnapsackSolver`.

    Every candidate below `target + change_target` is a subset-sum
    candidate; a search of `ApproximateBestSubset` random restarts looks
    for the closest sum at or above `target`, falling back to the single
    smallest candidate that alone covers `target` where the search does
    not do better. `change_target` is `cost_of_change` -- 0 where
    `change_script_pub_key` is None, which asks this search for the
    smallest excess over `target` rather than for room to leave change
    in.

    `rng` seeds the shuffle and the stochastic search; unseeded, a fresh
    `random.Random()` reads system entropy, matching Core's own
    `FastRandomContext` default.

    Raised as `BTClibValueError`: no combination of `candidates` reaches
    `target`, at this rate.
    """
    eligible, target, change_target, change_script = _prepare(
        candidates,
        outputs,
        fee_rate,
        long_term_fee_rate,
        change_script_pub_key,
        change_spend_weight,
        dust_fee_rate,
    )
    # not cryptographic on purpose, matching Core's FastRandomContext --
    # the module docstring's own reasoning
    engine = random.Random() if rng is None else rng  # noqa: S311
    selected = _knapsack(eligible, target, change_target, fee_rate, engine)
    if selected is None:
        err_msg = f"knapsack: no selection of the candidates reaches {target} satoshi"
        raise BTClibValueError(err_msg)
    return _score(
        selected,
        target,
        fee_rate,
        long_term_fee_rate,
        change_script,
        change_spend_weight,
        dust_fee_rate,
        "knapsack",
    )


def _approximate_best_subset(
    engine: random.Random,
    pool: Sequence[Candidate],
    fee_rate: FeeRate,
    total_lower: int,
    target: int,
    iterations: int,
) -> tuple[list[bool], int]:
    """Core's `ApproximateBestSubset`: random restarts over a subset-sum.

    Two passes per restart, the first including each candidate on a coin
    flip, the second sweeping in whatever the first pass left out --
    Core's own comment is that the randomness buys nothing but avoiding a
    degenerate worst case, not privacy or security, which is why a
    caller-seeded `random.Random` costs this module nothing to expose.
    """
    values = [c.effective_value(fee_rate) for c in pool]
    n = len(pool)
    best_included = [True] * n
    best_total = total_lower

    rep = 0
    while rep < iterations and best_total != target:
        included = [False] * n
        total = 0
        reached_target = False
        for pass_ in range(2):
            if reached_target:
                break
            for i in range(n):
                take = bool(engine.getrandbits(1)) if pass_ == 0 else not included[i]
                if not take:
                    continue
                total += values[i]
                included[i] = True
                if total >= target:
                    reached_target = True
                    if total < best_total:
                        best_total = total
                        best_included = list(included)
                    total -= values[i]
                    included[i] = False
        rep += 1
    return best_included, best_total


def _knapsack(
    pool: Sequence[Candidate],
    target: int,
    change_target: int,
    fee_rate: FeeRate,
    engine: random.Random,
) -> list[Candidate] | None:
    """Translate `coinselection.cpp`'s `KnapsackSolver`: the solver itself."""
    shuffled = list(pool)
    engine.shuffle(shuffled)

    lowest_larger: Candidate | None = None
    applicable: list[Candidate] = []
    total_lower = 0
    for candidate in shuffled:
        value = candidate.effective_value(fee_rate)
        if value == target:
            return [candidate]
        if value < target + change_target:
            applicable.append(candidate)
            total_lower += value
        elif lowest_larger is None or value < lowest_larger.effective_value(fee_rate):
            lowest_larger = candidate

    if total_lower == target:
        return list(applicable)

    if total_lower < target:
        return None if lowest_larger is None else [lowest_larger]

    applicable.sort(key=lambda c: c.effective_value(fee_rate), reverse=True)
    best_included, best_total = _approximate_best_subset(
        engine, applicable, fee_rate, total_lower, target, _KNAPSACK_ITERATIONS
    )
    if best_total != target and total_lower >= target + change_target:
        best_included, best_total = _approximate_best_subset(
            engine,
            applicable,
            fee_rate,
            total_lower,
            target + change_target,
            _KNAPSACK_ITERATIONS,
        )

    if lowest_larger is not None and (
        (best_total != target and best_total < target + change_target)
        or lowest_larger.effective_value(fee_rate) <= best_total
    ):
        return [lowest_larger]

    return [
        c for c, included in zip(applicable, best_included, strict=True) if included
    ]


def single_random_draw(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None = None,
    change_spend_weight: int | None = None,
    *,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
    rng: random.Random | None = None,
) -> SelectionResult:
    """Shuffle the candidates and take them in order, Core's `SelectCoinsSRD`.

    The simplest of the three, and Core's own fallback where the other
    two find nothing: a random ordering is accumulated until it covers
    `target` plus `CHANGE_LOWER` and the cost of creating a change
    output -- so that a selection landing just past the target still
    leaves a change worth creating rather than a handful of satoshi --
    or, where `change_script_pub_key` is None, `target` alone.

    `rng` is the shuffle's own engine; unseeded, a fresh `random.Random()`
    reads system entropy.

    Raised as `BTClibValueError`: the shuffled candidates never reach the
    target, at this rate.
    """
    eligible, target, change_cost, change_script = _prepare(
        candidates,
        outputs,
        fee_rate,
        long_term_fee_rate,
        change_script_pub_key,
        change_spend_weight,
        dust_fee_rate,
    )
    # not cryptographic on purpose, matching Core's FastRandomContext --
    # the module docstring's own reasoning
    engine = random.Random() if rng is None else rng  # noqa: S311
    srd_target = target
    if change_script is not None:
        srd_target += CHANGE_LOWER + change_cost
    selected = _single_random_draw(eligible, srd_target, fee_rate, engine)
    if selected is None:
        err_msg = f"single random draw: no shuffle reaches {srd_target} satoshi"
        raise BTClibValueError(err_msg)
    return _score(
        selected,
        target,
        fee_rate,
        long_term_fee_rate,
        change_script,
        change_spend_weight,
        dust_fee_rate,
        "srd",
    )


def _single_random_draw(
    pool: Sequence[Candidate],
    srd_target: int,
    fee_rate: FeeRate,
    engine: random.Random,
) -> list[Candidate] | None:
    """Translate `coinselection.cpp`'s `SelectCoinsSRD`: the draw itself."""
    shuffled = list(pool)
    engine.shuffle(shuffled)

    selected: list[Candidate] = []
    total = 0
    for candidate in shuffled:
        selected.append(candidate)
        total += candidate.effective_value(fee_rate)
        if total >= srd_target:
            return selected
    return None


_ALGORITHMS = ("bnb", "knapsack", "srd")


def select_coins(
    candidates: Sequence[Candidate],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    long_term_fee_rate: FeeRate,
    change_script_pub_key: Octets | None = None,
    change_spend_weight: int | None = None,
    *,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
    algorithms: Sequence[str] = _ALGORITHMS,
    rng: random.Random | None = None,
) -> SelectionResult:
    """Run the named algorithms and return the selection of lowest waste.

    `algorithms` names which of `"bnb"`, `"knapsack"` and `"srd"` to try
    -- every one of them by default, Core's own policy of running all
    three and keeping the best. A caller who wants exactly one names
    it, `algorithms=("bnb",)`, which answers precisely as calling
    `branch_and_bound` would; the composition here is what spares that
    caller from also having to catch its own `BTClibValueError` in
    the presence of the other two.

    Raised as `BTClibValueError`: `algorithms` names something other
    than the three above, or none of the algorithms named finds a
    selection that reaches `outputs` at this rate.
    """
    if not algorithms:
        raise BTClibValueError("no algorithm named")
    unknown = sorted(set(algorithms) - set(_ALGORITHMS))
    if unknown:
        raise BTClibValueError(f"unknown algorithm: {', '.join(unknown)}")

    results: list[SelectionResult] = []
    errors: list[str] = []
    if "bnb" in algorithms:
        try:
            results.append(
                branch_and_bound(
                    candidates,
                    outputs,
                    fee_rate,
                    long_term_fee_rate,
                    change_script_pub_key,
                    change_spend_weight,
                    dust_fee_rate=dust_fee_rate,
                )
            )
        except BTClibValueError as e:
            errors.append(str(e))
    if "knapsack" in algorithms:
        try:
            results.append(
                knapsack(
                    candidates,
                    outputs,
                    fee_rate,
                    long_term_fee_rate,
                    change_script_pub_key,
                    change_spend_weight,
                    dust_fee_rate=dust_fee_rate,
                    rng=rng,
                )
            )
        except BTClibValueError as e:
            errors.append(str(e))
    if "srd" in algorithms:
        try:
            results.append(
                single_random_draw(
                    candidates,
                    outputs,
                    fee_rate,
                    long_term_fee_rate,
                    change_script_pub_key,
                    change_spend_weight,
                    dust_fee_rate=dust_fee_rate,
                    rng=rng,
                )
            )
        except BTClibValueError as e:
            errors.append(str(e))

    if not results:
        # each algorithm's own message already names the target it
        # computed against -- the same figure across all three, `_prepare`
        # being where every one of them reads it -- so this is not repeated
        err_msg = "no selection of the candidates covers the outputs at this "
        err_msg += f"rate: {'; '.join(errors)}"
        raise BTClibValueError(err_msg)

    return min(results, key=lambda result: result.waste)
