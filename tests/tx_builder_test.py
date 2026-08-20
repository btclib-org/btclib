# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx_builder` module.

Two oracles, because a builder can be wrong in two ways that no
assertion about its own numbers would catch.

The first is arithmetic, and it is checked against `fee`'s own
functions rather than against figures copied out of a run: what the
transaction pays is what `fee_from_vsize` asks of the size the psbt
estimates, and what the change is worth is measured against
`dust_threshold` for the script it is paid to -- on both sides of it,
the boundary being where a builder that rounds the wrong way stops
relaying.

The second is the network's, as far as this suite can reach it: the
psbt is signed by `SoftwareSigner`, finalized, extracted, and the
transaction that comes out is run under btclib's own script engine. The
size a fee was bought at is then compared with the size that was really
signed -- the estimate is an upper bound, so a transaction is never
below the rate it was built for, and that is the one claim a builder
exists to make.
"""

from __future__ import annotations

import pytest

from btclib.descriptors import Descriptor
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate, dust_threshold, fee_from_vsize
from btclib.psbt.psbt import extract_tx, finalize
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_size import SIG_SIZE
from btclib.psbt_signer import SoftwareSigner, export_account, request_signatures
from btclib.script import ScriptPubKey
from btclib.script.engine import verify_transaction
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx_builder import build_psbt

# BIP39's "abandon abandon ... about" root, which BIP84 publishes and
# `tests/software_signer_test.py` signs with
XPRV_ROOT = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRR"
    "uL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)

# two public keys of no private key anybody holds, which is all the
# arithmetic below needs: nothing signs for these, the scripts being
# there to be measured and to be dust-checked
PAY_KEY = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CHANGE_KEY = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

PAY_SCRIPT = ScriptPubKey.p2wpkh(PAY_KEY)
CHANGE_SCRIPT = ScriptPubKey.p2wpkh(CHANGE_KEY)

# a satoshi a virtual byte, so that a fee read against a size needs no
# conversion in the head of whoever reads a failure here
ONE_SAT_PER_VBYTE = FeeRate.from_sats_per_vbyte(1)
TEN_SAT_PER_VBYTE = FeeRate.from_sats_per_vbyte(10)


def spendable(
    value: int, script: ScriptPubKey = PAY_SCRIPT, tx_id: bytes = b"\x06" * 32
) -> PsbtIn:
    """Return the input map spending one segwit output of that value."""
    return PsbtIn(
        witness_utxo=TxOut(value, script), previous_tx_id=tx_id, output_index=0
    )


def test_the_fee_is_what_the_rate_asks_of_the_estimated_size() -> None:
    """The whole arithmetic, checked against `fee` rather than a figure.

    Every satoshi of the inputs is an output or the fee, the fee is what
    the rate asks of the size this psbt will be once signed, and the
    change is the last output, which is where this appends it.
    """
    built = build_psbt(
        [spendable(100_000)],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
    )

    assert built.fee == fee_from_vsize(built.psbt.vsize_estimate(), TEN_SAT_PER_VBYTE)
    assert built.change_index == 1
    assert built.change == 100_000 - 60_000 - built.fee
    assert sum(tx_out.value for tx_out in built.psbt.tx.vout) + built.fee == 100_000
    assert built.psbt.tx.vout[1].script_pub_key == CHANGE_SCRIPT
    # what a Signer reads, and the version every Signer reads it in
    assert built.psbt.version == 0
    assert built.psbt.tx.version == 2
    assert built.psbt.tx.lock_time == 0


def test_the_transaction_fields_are_the_caller_s() -> None:
    """`tx_version` and `lock_time` reach the transaction being built."""
    built = build_psbt(
        [spendable(100_000)],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        tx_version=3,
        lock_time=800_000,
    )
    assert built.psbt.tx.version == 3
    assert built.psbt.tx.lock_time == 800_000


def test_an_input_spends_with_the_sequence_it_carries() -> None:
    """The sequence is the input's own, and none of it is this builder's.

    An input naming no sequence spends with the final one, which is what
    `psbt.tx` puts there; a caller opting into BIP125 replacement says so
    on the input rather than through an argument here.
    """
    psbt_in = spendable(100_000)
    psbt_in.sequence = 0xFFFFFFFD
    built = build_psbt([psbt_in], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)
    assert built.psbt.tx.vin[0].sequence == 0xFFFFFFFD

    built = build_psbt(
        [spendable(100_000)], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE
    )
    assert built.psbt.tx.vin[0].sequence == 0xFFFFFFFF


def dust_boundary(fee_rate: FeeRate = TEN_SAT_PER_VBYTE) -> tuple[int, int, int]:
    """Return the input value, the payment leaving exactly dust, and the fee.

    Measured rather than tabulated: the amount that leaves the change at
    its dust threshold to the satoshi is the value less the fee of the
    transaction that has a change output less that threshold, and the
    first two of those are what this asks the builder and `fee` for.
    """
    value = 100_000
    # the fee of the shape that has a change output, which no payment
    # amount moves: an output's value is eight bytes whatever it holds
    probe = build_psbt(
        [spendable(value)], [TxOut(1_000, PAY_SCRIPT)], fee_rate, CHANGE_SCRIPT.script
    )
    threshold = dust_threshold(CHANGE_SCRIPT.script)
    return value, value - probe.fee - threshold, probe.fee


def test_change_worth_exactly_the_dust_threshold_is_created() -> None:
    """Exactly the threshold is not dust, which `dust_threshold` says."""
    value, payment, fee = dust_boundary()
    built = build_psbt(
        [spendable(value)],
        [TxOut(payment, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
    )
    assert built.change_index == 1
    assert built.change == dust_threshold(CHANGE_SCRIPT.script)
    assert built.fee == fee


def test_change_one_satoshi_below_the_threshold_becomes_fee() -> None:
    """The branch a hand-written builder gets wrong.

    The output is not created, so the whole leftover is the fee -- more
    than the rate asked for, by what the change would have been -- and
    the transaction that pays it is the smaller one, which is what makes
    the leftover cover a fee it was not weighed against.
    """
    value, payment, fee_with_change = dust_boundary()
    built = build_psbt(
        [spendable(value)],
        [TxOut(payment + 1, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
    )

    assert built.change_index is None
    assert built.change == 0
    assert len(built.psbt.outputs) == 1
    assert built.fee == value - (payment + 1)
    # what the rate asks of the transaction that is really being made,
    # which is smaller than the one priced at fee_with_change
    owed = fee_from_vsize(built.psbt.vsize_estimate(), TEN_SAT_PER_VBYTE)
    assert owed < fee_with_change
    assert built.fee > owed


def test_no_change_script_is_every_leftover_satoshi_to_the_fee() -> None:
    """A sweep: nothing comes back, and the psbt says so with no output."""
    built = build_psbt(
        [spendable(100_000)], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE
    )
    assert built.change_index is None
    assert built.change == 0
    assert built.fee == 40_000
    assert len(built.psbt.outputs) == 1


def test_a_change_output_can_be_the_only_output() -> None:
    """No payment at all is a self-send, and the change is what it pays."""
    built = build_psbt(
        [spendable(100_000)], [], TEN_SAT_PER_VBYTE, CHANGE_SCRIPT.script
    )
    assert built.change_index == 0
    assert built.change == 100_000 - built.fee
    assert built.fee == fee_from_vsize(built.psbt.vsize_estimate(), TEN_SAT_PER_VBYTE)


def test_a_zero_rate_owes_nothing_and_the_change_is_the_whole_leftover() -> None:
    """`fee_from_vsize` answers zero at every size for a zero rate."""
    built = build_psbt(
        [spendable(100_000)],
        [TxOut(60_000, PAY_SCRIPT)],
        FeeRate(sats_per_kvbyte=0),
        CHANGE_SCRIPT.script,
    )
    assert built.fee == 0
    assert built.change == 40_000


def test_the_dust_rate_is_the_network_s_and_not_this_transaction_s() -> None:
    """`dust_fee_rate` moves the threshold; `fee_rate` does not.

    Core computes a dust threshold at `-dustrelayfee` rather than at
    whatever the transaction chose to pay, so a node run with a higher
    one refuses an output this would otherwise create.
    """
    value, payment, _ = dust_boundary()
    ten_times = FeeRate(sats_per_kvbyte=10 * 3000)
    built = build_psbt(
        [spendable(value)],
        [TxOut(payment, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        dust_fee_rate=ten_times,
    )
    assert built.change_index is None
    assert dust_threshold(CHANGE_SCRIPT.script, ten_times) > dust_threshold(
        CHANGE_SCRIPT.script
    )


def test_inputs_that_do_not_cover_the_outputs_and_the_fee() -> None:
    """Refused, with both totals in the message, and on either branch."""
    with pytest.raises(BTClibValueError, match="the inputs are worth"):
        build_psbt([spendable(60_000)], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)
    # the same shortfall reached through the change branch: the change is
    # negative, which is below every threshold, so the output is dropped
    # and what is left still does not pay for the smaller transaction
    with pytest.raises(BTClibValueError, match="the inputs are worth"):
        build_psbt(
            [spendable(60_000)],
            [TxOut(60_000, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            CHANGE_SCRIPT.script,
        )


def test_a_transaction_needs_an_input_and_an_output() -> None:
    """Core's CheckTransaction refuses an empty vin or vout; so does this."""
    with pytest.raises(BTClibValueError, match="no inputs"):
        build_psbt([], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)

    with pytest.raises(BTClibValueError, match="no outputs"):
        build_psbt([spendable(100_000)], [], TEN_SAT_PER_VBYTE)

    # nothing is paid and what would come back is dust, so dropping the
    # change output would leave a transaction with no output at all
    with pytest.raises(BTClibValueError, match="no outputs"):
        build_psbt([spendable(400)], [], ONE_SAT_PER_VBYTE, CHANGE_SCRIPT.script)


def test_one_outpoint_is_spent_once() -> None:
    """A double count in the fee arithmetic, and `bad-txns-inputs-duplicate`.

    `Tx.assert_valid`'s rule, reached here through the `prevouts` that
    reads what the inputs are worth: the fee is what that sum buys, so
    the refusal comes before the number it would corrupt.
    """
    with pytest.raises(BTClibValueError, match="spent twice"):
        build_psbt(
            [spendable(100_000), spendable(100_000)],
            [TxOut(60_000, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
        )
    # an input naming no output index is refused under its own name,
    # `Psbt.assert_valid` checking the input fields before the transaction
    # it builds out of them: `PsbtIn.prev_out` reads a missing index as 0,
    # so read the other way round this would be a duplicate of whatever
    # spends index 0 of the same transaction
    nameless = spendable(100_000)
    nameless.output_index = None
    with pytest.raises(BTClibValueError, match="missing PSBT_IN_OUTPUT_INDEX"):
        build_psbt(
            [nameless, spendable(100_000)],
            [TxOut(60_000, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
        )

    # the same output index of two different transactions is two utxos
    built = build_psbt(
        [spendable(100_000), spendable(100_000, tx_id=b"\x07" * 32)],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
    )
    assert built.change == 200_000 - 60_000 - built.fee


def test_an_input_carrying_no_utxo_has_no_amount() -> None:
    """`prevouts`' refusal, which is what reads the amounts here."""
    psbt_in = PsbtIn(previous_tx_id=b"\x06" * 32, output_index=0)
    with pytest.raises(BTClibValueError, match="no utxo for input 0"):
        build_psbt([psbt_in], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)


def test_an_input_of_no_readable_type_is_answered_by_a_sizer() -> None:
    """`psbt_size`'s rule, reached through the builder.

    A witness script of no standard type has no estimate, so the fee has
    none either; the caller who knows what will satisfy it says so, and
    the fee follows what they said.
    """
    witness_script = b"\x51"  # OP_TRUE, which no classifier names
    psbt_in = spendable(100_000, ScriptPubKey.p2wsh(witness_script))
    psbt_in.witness_script = witness_script

    with pytest.raises(BTClibValueError, match="no estimate"):
        build_psbt([psbt_in], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)

    small = build_psbt(
        [psbt_in],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        sizer=lambda _psbt_in, _tx_in: [],
    )
    large = build_psbt(
        [psbt_in],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
        sizer=lambda _psbt_in, _tx_in: [SIG_SIZE] * 3,
    )
    assert small.fee < large.fee
    assert large.change == 100_000 - 60_000 - large.fee


def test_a_legacy_input_is_priced_from_the_transaction_that_created_it() -> None:
    """The other utxo field: a non-segwit output is not a witness utxo."""
    prev_out = TxOut(100_000, ScriptPubKey.p2pkh(PAY_KEY))
    prev_tx = Tx(vin=[TxIn(OutPoint(b"\x06" * 32, 0))], vout=[prev_out])
    psbt_in = PsbtIn(
        non_witness_utxo=prev_tx, previous_tx_id=prev_tx.id, output_index=0
    )

    built = build_psbt(
        [psbt_in], [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE, CHANGE_SCRIPT.script
    )
    assert built.fee == fee_from_vsize(built.psbt.vsize_estimate(), TEN_SAT_PER_VBYTE)
    # no witness discount on either half of it, so it is dearer than the
    # segwit spend of the same value
    segwit = build_psbt(
        [spendable(100_000)],
        [TxOut(60_000, PAY_SCRIPT)],
        TEN_SAT_PER_VBYTE,
        CHANGE_SCRIPT.script,
    )
    assert built.fee > segwit.fee


@pytest.mark.parametrize("wrong", [None, 1.5, "not a sequence"])
def test_a_sequence_of_the_wrong_type(wrong: object) -> None:
    """Refused before a field is read off anything it holds."""
    with pytest.raises(BTClibTypeError):
        build_psbt(wrong, [TxOut(60_000, PAY_SCRIPT)], TEN_SAT_PER_VBYTE)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        build_psbt([spendable(100_000)], wrong, TEN_SAT_PER_VBYTE)  # type: ignore[arg-type]


@pytest.mark.parametrize("wrong", [None, 1.5])
def test_an_argument_of_the_wrong_type(wrong: object) -> None:
    """Each position refuses what its annotation does not declare."""
    inputs = [spendable(100_000)]
    outputs = [TxOut(60_000, PAY_SCRIPT)]
    with pytest.raises(BTClibTypeError):
        build_psbt([wrong], outputs, TEN_SAT_PER_VBYTE)  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError):
        build_psbt(inputs, [wrong], TEN_SAT_PER_VBYTE)  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError):
        build_psbt(inputs, outputs, wrong)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        build_psbt(inputs, outputs, TEN_SAT_PER_VBYTE, dust_fee_rate=wrong)  # type: ignore[arg-type]


def test_a_change_script_that_is_not_octets() -> None:
    """`bytes_from_octets` is the refusal, as everywhere else taking them."""
    with pytest.raises(BTClibValueError):
        build_psbt(
            [spendable(100_000)],
            [TxOut(60_000, PAY_SCRIPT)],
            TEN_SAT_PER_VBYTE,
            "not hex at all",
        )


def account_input(
    receive: Descriptor, purpose: int, index: int = 0
) -> tuple[PsbtIn, TxOut]:
    """Return the input map spending an address of this account, and its output.

    The whole previous transaction, which is the answer for an input of
    any type, BIP322's `to_sign_psbt` giving the same reason for the same
    choice. The redeem script is the one field the psbt cannot work out
    for itself: a p2sh-wrapped input is spent by what the wrapper hashes
    to, so what a signature will cost is not in the script_pub_key, and
    the caller who knows the account knows the script.
    """
    prev_out = TxOut(100_000, receive.script_pub_key(index))
    prev_tx = Tx(vin=[TxIn(OutPoint(b"\x06" * 32, 0))], vout=[prev_out])
    redeem_script = b""
    if purpose == 49:
        redeem_script = ScriptPubKey.p2wpkh(
            receive.key_expressions[0].sec(index)
        ).script
    return (
        PsbtIn(
            non_witness_utxo=prev_tx,
            previous_tx_id=prev_tx.id,
            output_index=0,
            redeem_script=redeem_script,
        ),
        prev_out,
    )


@pytest.mark.parametrize("purpose", [44, 49, 84, 86])
def test_what_was_built_is_signed_spends_and_pays_the_rate(purpose: int) -> None:
    """The whole flow, once per BIP44 encoding, with two oracles at the end.

    The script engine says the transaction spends what it claims, and
    the size it really took says the fee was not an underestimate: the
    estimate is an upper bound, so the transaction that comes out pays at
    least the rate it was built for. A signature sized wrong, or a change
    output that took the fee with it, fails one of the two.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(signer, f"m/{purpose}h/0h/0h")
    psbt_in, prev_out = account_input(receive, purpose)

    built = build_psbt(
        [psbt_in],
        [TxOut(60_000, receive.script_pub_key(1))],
        TEN_SAT_PER_VBYTE,
        change.script_pub_key(0).script,
    )
    estimate = built.psbt.vsize_estimate()
    assert built.change_index is not None

    psbt = receive.update_psbt_input(built.psbt, 0, 0)
    psbt = change.update_psbt_output(psbt, built.change_index, 0)
    tx = extract_tx(finalize(request_signatures(signer, psbt)))

    verify_transaction([prev_out], tx)
    assert tx.vsize <= estimate
    assert fee_from_vsize(tx.vsize, TEN_SAT_PER_VBYTE) <= built.fee
    assert 100_000 - sum(tx_out.value for tx_out in tx.vout) == built.fee
