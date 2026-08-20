# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Compose the psbt spending a set of outputs, at a fee rate, with change.

Every part of this is elsewhere and nothing composes them, so every
caller composes them again: `Psbt` holds what is being built,
`psbt.prevouts` says what its inputs are worth, `Psbt.vsize_estimate`
says how large the signed transaction will be, `fee.fee_from_vsize`
prices that size and `fee.dust_threshold` says whether the change is
worth creating. `build_psbt` is that composition, and the three
decisions it makes are the ones a hand-written builder gets wrong.

**The fee comes from the rate and the size, and the size comes from the
psbt.** A transaction that is not signed has no size to be priced by --
`Tx.vsize` is read off a serialization, and the signatures are not
written yet -- so the object built here is a psbt: `Psbt.vsize_estimate`
sizes the missing signatures from each input's utxo and scripts, which
is the one thing in the tree that answers before there is anything to
sign. The unsigned transaction is `built.psbt.tx`, a property away, so a
second entry point answering with a `Tx` would be a second spelling of
one answer rather than a second answer.

**Change is an output or it is fee.** Below `dust_threshold` for its own
script an output cannot be relayed, so it is not created and its value
is left to the fee; and the transaction is then smaller than the one
that was priced, so the fee it owes is computed again rather than
reused. `change_index` is which output it is, or None for the branch
that dropped it.

**An input is a `PsbtIn`**: the outpoint it spends, the output that
outpoint names -- `witness_utxo` or `non_witness_utxo`, whichever its
kind of input takes -- and whatever else says how it will be unlocked, a
redeem script or a witness script included. Two things follow from
taking the psbt's own map rather than a pair of an outpoint and a
`TxOut`. Nothing here fetches anything, an outpoint alone saying neither
what it is worth nor what it spends, and a builder that fetches is a
builder with a node in it; and an input whose script is wrapped or
multisig is estimated exactly, its redeem or witness script being a
field of the map that arrives rather than an argument this function
would have to grow. The outputs are `TxOut` and not `PsbtOut` because
the asymmetry is real: the input map is *read*, every byte a signature
will take being computed from it, where nothing computed here reads an
output map -- what a wallet writes into one, `descriptors`'
`update_psbt_output` on the change output at `change_index` included, is
written after this returns and changes no size.

Explicitly not here, both of them boundaries this library draws
elsewhere too:

- **coin selection**. Which utxos to spend is policy with a literature
  behind it, and keeping it out is what lets a caller bring its own;
  this spends the ones it is given, all of them. `tx.input_weight` is
  the number that caller prices a candidate with -- one input, before
  there is a psbt to put it in -- where what a fee is bought by here is
  the whole transaction, which `Psbt.vsize_estimate` is the one arithmetic
  for.
- **a node, an rpc, or wallet state**. The same arguments give the same
  answer forever, which is `fee`'s own boundary: what is downstream of a
  network -- a fee estimate for a confirmation target, which utxos are
  confirmed, the block height that would make an anti-fee-sniping lock
  time -- is fed in rather than fetched.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.fee import DUST_RELAY_FEE_RATE, FeeRate, dust_threshold, fee_from_vsize
from btclib.psbt.psbt import Psbt, prevouts
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import SolutionSizer
from btclib.psbt.psbt_utils import PSBT_V0
from btclib.tx import TxOut
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "FundedPsbt",
    "build_psbt",
]


@dataclass(frozen=True)
class FundedPsbt:
    """A psbt whose fee is paid, and what paying it decided.

    The three answers Bitcoin Core's `fundrawtransaction` gives, which
    is the same triple under its own names: the transaction, `fee`, and
    `changepos` -- spelled here as an index into the psbt's outputs, and
    None where Core writes -1 for the transaction that has no change
    output.

    `fee` is what the inputs are worth less what the outputs hold. It is
    at least what `fee_rate` asked of the estimated size and can exceed
    it, by exactly the change that was too small to create.
    """

    psbt: Psbt
    fee: int
    change_index: int | None

    @property
    def change(self) -> int:
        """Return the satoshi the change output holds, 0 where there is none."""
        if self.change_index is None:
            return 0
        return self.psbt.outputs[self.change_index].amount or 0


def _assert_arguments(
    inputs: Sequence[PsbtIn],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    dust_fee_rate: FeeRate,
) -> None:
    """Refuse an argument of the wrong type before a field is read off it.

    The two sequences are checked as sequences and then element by
    element, which is the shape `tests/built_object_contract_test.py`
    calls a sequence walked before it is checked: `None` is not iterable
    from underneath this library, and a `str` is a sequence of one-character
    strings that would each be read for fields it has not got.
    """
    assert_type(inputs, Sequence, "inputs")
    for psbt_in in inputs:
        assert_type(psbt_in, PsbtIn, "psbt input")
    assert_type(outputs, Sequence, "outputs")
    for tx_out in outputs:
        assert_type(tx_out, TxOut, "output")
    assert_type(fee_rate, FeeRate, "fee rate")
    assert_type(dust_fee_rate, FeeRate, "dust fee rate")


def _assert_spends_once(inputs: Sequence[PsbtIn]) -> None:
    """Refuse a set of inputs naming one outpoint twice.

    Core's `CheckTransaction` refuses it as `bad-txns-inputs-duplicate`,
    and what it costs here is not only that the transaction would be
    rejected: the fee is computed from what the inputs are worth, and an
    outpoint listed twice is counted twice, so the change would be an
    amount the transaction does not have. `Tx.assert_valid` implements
    the rest of `CheckTransaction` and not this rule (issue #1073), so
    the psbt this returns would not be refused by its own validation.
    """
    outpoints = [psbt_in.prev_out for psbt_in in inputs]
    if len(set(outpoints)) != len(outpoints):
        raise BTClibValueError("the same outpoint is spent twice")


def build_psbt(
    inputs: Sequence[PsbtIn],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    change_script_pub_key: Octets | None = None,
    *,
    tx_version: int = 2,
    lock_time: int = 0,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
    sizer: SolutionSizer | None = None,
) -> FundedPsbt:
    """Return the psbt spending these inputs at this rate, and its change.

    `inputs` are the psbt's own input maps, each carrying the outpoint it
    spends and the output that outpoint names; `outputs` are what is
    being paid. What is left over pays the fee, and `change_script_pub_key`
    is where the rest of it goes -- to an output of that script when it
    would be worth more than `dust_threshold` asks, and to the fee when
    it would not. No change script at all is every leftover satoshi to
    the fee, which is what a caller sweeping an address means and what a
    caller who forgot the argument gets, so it is spelled rather than
    defaulted.

    Raised, all as `BTClibValueError`: no inputs, no outputs left to pay,
    an outpoint spent twice, an input carrying no utxo, an input whose
    type the psbt does not determine -- `psbt_size`'s rule, and `sizer`
    is where a caller answers for one -- and inputs that do not cover the
    outputs and the fee.

    `tx_version` and `lock_time` are the transaction's, defaulting to
    Core's own 2 and to no lock time: the block height that would make a
    lock time worth setting is a node's answer, and this function has no
    node. Each input's sequence is its own `PsbtIn.sequence`, and an
    input naming none spends with the final sequence -- no lock time and
    no BIP125 replacement, which a caller wanting either sets on the
    input rather than having overwritten here.

    `dust_fee_rate` is the rate the dust threshold is computed at, Core's
    `-dustrelayfee` default; it is not `fee_rate`, an output being dust
    by what the network will relay rather than by what this transaction
    chose to pay.

    The psbt is version 0, which every Signer reads; `Psbt.to_v2` is the
    other one.
    """
    _assert_arguments(inputs, outputs, fee_rate, dust_fee_rate)
    if not inputs:
        raise BTClibValueError("no inputs")
    _assert_spends_once(inputs)
    change_script = (
        None
        if change_script_pub_key is None
        else bytes_from_octets(change_script_pub_key)
    )

    psbt_outputs = [
        PsbtOut(amount=tx_out.value, script_pub_key=tx_out.script_pub_key.script)
        for tx_out in outputs
    ]
    change_index: int | None = None
    if change_script is not None:
        change_index = len(psbt_outputs)
        # the amount is what the fee leaves and the fee is what this
        # psbt's size costs, so the output has to be in it before there
        # is an amount to put in the output. A value is eight bytes
        # whatever it holds, so the estimate does not move when the
        # placeholder below is replaced by the answer computed from it
        psbt_outputs.append(PsbtOut(amount=0, script_pub_key=change_script))

    # not validated here: `prevouts` below validates, and it is the first
    # thing that reads the psbt
    psbt = Psbt(
        tx_version,
        inputs,
        psbt_outputs,
        PSBT_V0,
        {},
        fallback_lock_time=lock_time,
        check_validity=False,
    )
    total_in = sum(prev_out.value for prev_out in prevouts(psbt))
    total_out = sum(tx_out.value for tx_out in outputs)
    remainder = total_in - total_out

    if change_script is not None:
        fee = fee_from_vsize(psbt.vsize_estimate(sizer), fee_rate)
        change = remainder - fee
        if change >= dust_threshold(change_script, dust_fee_rate):
            # the last output, this having appended it
            psbt.outputs[-1].amount = change
            # the one state nothing else has judged: every other exit
            # returns what `vsize_estimate` last validated
            psbt.assert_valid()
            return FundedPsbt(psbt, fee, change_index)
        # dust cannot be created, so what would have been change is fee
        psbt.outputs.pop()
        change_index = None

    if not psbt.outputs:
        err_msg = "no outputs: nothing is paid, and there is no change to create"
        raise BTClibValueError(err_msg)
    # the whole leftover, which is at least what the rate asks: the
    # transaction is smaller than the one priced above, so what it owes
    # is computed again rather than the larger figure reused
    owed = fee_from_vsize(psbt.vsize_estimate(sizer), fee_rate)
    if remainder < owed:
        err_msg = f"the inputs are worth {total_in} satoshi, "
        err_msg += f"where the outputs and the fee need {total_out + owed}"
        raise BTClibValueError(err_msg)
    return FundedPsbt(psbt, remainder, change_index)
