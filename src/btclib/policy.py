# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's relay policy: which valid transactions a node relays.

A port of `policy/policy.{h,cpp}`, read at bitcoin/bitcoin@9be056a8a7
(v31.1). A standard transaction is a valid one that a node also relays
and mines; what a block may carry is consensus, and
`btclib.script.engine` is where that is checked.

The constants are policy.h's relay limits and the defaults of the node
options that tune them. `MIN_STANDARD_TX_NONWITNESS_SIZE` and
`MAX_STANDARD_TX_SIGOPS_COST` are read by Core's mempool, not by these
functions. The mining defaults and the mempool's package limits are not
here. Core's `DUST_RELAY_TX_FEE` is
`btclib.fee.DUST_RELAY_FEE_RATE`, a `FeeRate`.

Where Core reads the spent outputs from a coins view, the functions here
take them as a list in input order, as `btclib.script.engine` does.
"""

from __future__ import annotations

from collections.abc import Sequence

from btclib.alias import TxoutType
from btclib.block.limits import MAX_BLOCK_SIGOPS_COST
from btclib.consensus import WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import DUST_RELAY_FEE_RATE, FeeRate, dust_threshold
from btclib.script.engine.script import eval_script
from btclib.script.sig_ops import p2sh_sig_op_count, sig_op_count
from btclib.script.solver import (
    _is_pay_to_anchor,
    _is_pay_to_script_hash,
    _is_push_only,
    _witness_program,
    solver,
)
from btclib.tx.tx import _TX_MAX_STANDARD_VERSION, _TX_MIN_STANDARD_VERSION, Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.utils import _message_text, assert_type, is_integer

__all__ = [
    "DEFAULT_ACCEPT_DATACARRIER",
    "DEFAULT_BYTES_PER_SIGOP",
    "DEFAULT_PERMIT_BAREMULTISIG",
    "MAX_DUST_OUTPUTS_PER_TX",
    "MAX_OP_RETURN_RELAY",
    "MAX_P2SH_SIGOPS",
    "MAX_STANDARD_P2WSH_SCRIPT_SIZE",
    "MAX_STANDARD_P2WSH_STACK_ITEMS",
    "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE",
    "MAX_STANDARD_SCRIPTSIG_SIZE",
    "MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE",
    "MAX_STANDARD_TX_SIGOPS_COST",
    "MAX_STANDARD_TX_WEIGHT",
    "MAX_TX_LEGACY_SIGOPS",
    "MIN_STANDARD_TX_NONWITNESS_SIZE",
    "TX_MAX_STANDARD_VERSION",
    "TX_MIN_STANDARD_VERSION",
    "are_inputs_standard",
    "assert_standard_tx",
    "dust_outputs",
    "is_dust",
    "is_witness_standard",
    "sig_ops_adjusted_weight",
    "spends_non_anchor_witness_prog",
    "virtual_size",
]

# the largest weight a standard transaction may have
MAX_STANDARD_TX_WEIGHT = 400_000
# the smallest non-witness size a standard transaction may have: one of
# 64 bytes could pass for an inner merkle node (CVE-2017-12842)
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
# the most signature checks a standard p2sh redeem script may announce
MAX_P2SH_SIGOPS = 15
# the largest signature check cost a standard transaction may have
MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST // 5
# the most legacy signature checks a standard transaction may run (BIP54)
MAX_TX_LEGACY_SIGOPS = 2_500
# the default of -bytespersigop
DEFAULT_BYTES_PER_SIGOP = 20
# the default of -permitbaremultisig
DEFAULT_PERMIT_BAREMULTISIG = True
# the most witness stack items a standard p2wsh spend may carry, the
# witness script excluded
MAX_STANDARD_P2WSH_STACK_ITEMS = 100
# the largest witness stack item a standard p2wsh spend may carry
MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80
# the largest witness stack item a standard tapscript spend may carry
MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80
# the largest standard p2wsh witness script
MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
# the largest standard script_sig
MAX_STANDARD_SCRIPTSIG_SIZE = 1650
# the default of -datacarrier
DEFAULT_ACCEPT_DATACARRIER = True
# the default of -datacarriersize, in bytes of nulldata script_pub_key
MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT // WITNESS_SCALE_FACTOR
# the most dust outputs a standard transaction may have
MAX_DUST_OUTPUTS_PER_TX = 1
# the standard versions, defined in btclib.tx.tx, where
# `Tx.assert_standard` reads them
TX_MIN_STANDARD_VERSION = _TX_MIN_STANDARD_VERSION
TX_MAX_STANDARD_VERSION = _TX_MAX_STANDARD_VERSION

# Core's ANNEX_TAG, TAPROOT_LEAF_MASK and TAPROOT_LEAF_TAPSCRIPT
_ANNEX_TAG = 0x50
_TAPROOT_LEAF_MASK = 0xFE
_TAPROOT_LEAF_TAPSCRIPT = 0xC0
# WITNESS_V0_SCRIPTHASH_SIZE and WITNESS_V1_TAPROOT_SIZE
_WITNESS_V0_SCRIPTHASH_SIZE = 32
_WITNESS_V1_TAPROOT_SIZE = 32


def _assert_non_negative_integer(value: object, what: str) -> None:
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if value < 0:  # type: ignore[operator]
        raise BTClibValueError(f"negative {what}: {_message_text(value)}")


def _assert_prevouts(prevouts: Sequence[TxOut], tx: Tx) -> None:
    """Refuse a transaction or spent outputs that cannot go together.

    A coinbase spends nothing, so its prevouts are not counted, as Core
    does not read them.
    """
    assert_type(tx, Tx, "tx")
    assert_type(prevouts, Sequence, "prevouts")
    for prevout in prevouts:
        assert_type(prevout, TxOut, "prevout")
    if not tx.is_coinbase and len(prevouts) != len(tx.vin):
        raise BTClibValueError(
            f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
        )


def _redeem_script(script_sig: bytes) -> bytes | None:
    """Return the top of the stack the script_sig leaves, if any.

    None where the script fails or leaves an empty stack. The script
    runs as Core's policy runs it to read a redeem script without
    verifying the spend: `EvalScript` under `SCRIPT_VERIFY_NONE` with a
    `BaseSignatureChecker`, which is `eval_script`'s default.
    """
    stack, error = eval_script(script_sig)
    return None if error else stack[-1] if stack else None


def _is_standard(tx_out_type: TxoutType, solutions: list[bytes]) -> bool:
    """Answer Core's `IsStandard` for a solved script_pub_key."""
    if tx_out_type == "nonstandard":
        return False
    if tx_out_type == "multisig":
        # solver already holds 1 <= m <= n; the bounds are Core's
        m, n = solutions[0][0], solutions[-1][0]
        # up to x-of-3 multisig
        return 1 <= n <= 3 and 1 <= m <= n
    return True


def assert_standard_tx(
    tx: Tx,
    *,
    max_datacarrier_bytes: int | None = MAX_OP_RETURN_RELAY,
    permit_bare_multisig: bool = DEFAULT_PERMIT_BAREMULTISIG,
    dust_relay_fee: FeeRate = DUST_RELAY_FEE_RATE,
) -> None:
    """Refuse a transaction Core's `IsStandardTx` refuses.

    The message of the `BTClibValueError` is Core's reject reason, the
    one `testmempoolaccept` reports: "version", "tx-size",
    "scriptsig-size", "scriptsig-not-pushonly", "scriptpubkey",
    "datacarrier", "bare-multisig" or "dust". The checks run in Core's
    order, so the reason is the first rule the transaction breaks.

    `max_datacarrier_bytes` bounds the nulldata script_pub_keys of the
    transaction taken together, as -datacarriersize does; None is
    -datacarrier=0, no nulldata output at all. `permit_bare_multisig`
    is -permitbaremultisig and `dust_relay_fee` is -dustrelayfee. One
    dust output is standard, as Core's ephemeral dust.
    """
    assert_type(tx, Tx, "tx")
    if max_datacarrier_bytes is not None:
        _assert_non_negative_integer(max_datacarrier_bytes, "max_datacarrier_bytes")
    assert_type(permit_bare_multisig, bool, "permit_bare_multisig")
    assert_type(dust_relay_fee, FeeRate, "dust_relay_fee")

    if not TX_MIN_STANDARD_VERSION <= tx.version <= TX_MAX_STANDARD_VERSION:
        raise BTClibValueError("version")

    if tx.weight > MAX_STANDARD_TX_WEIGHT:
        raise BTClibValueError("tx-size")

    for tx_in in tx.vin:
        if len(tx_in.script_sig) > MAX_STANDARD_SCRIPTSIG_SIZE:
            raise BTClibValueError("scriptsig-size")
        if not _is_push_only(tx_in.script_sig, 0):
            raise BTClibValueError("scriptsig-not-pushonly")

    _assert_standard_outputs(tx, max_datacarrier_bytes or 0, permit_bare_multisig)

    if len(dust_outputs(tx, dust_relay_fee=dust_relay_fee)) > MAX_DUST_OUTPUTS_PER_TX:
        raise BTClibValueError("dust")


def _assert_standard_outputs(
    tx: Tx, datacarrier_bytes_left: int, permit_bare_multisig: bool
) -> None:
    """Refuse the script_pub_keys `IsStandardTx` refuses."""
    for tx_out in tx.vout:
        script_pub_key = tx_out.script_pub_key.script
        tx_out_type, solutions = solver(script_pub_key)
        if not _is_standard(tx_out_type, solutions):
            raise BTClibValueError("scriptpubkey")
        if tx_out_type == "nulldata":
            if len(script_pub_key) > datacarrier_bytes_left:
                raise BTClibValueError("datacarrier")
            datacarrier_bytes_left -= len(script_pub_key)
        elif tx_out_type == "multisig" and not permit_bare_multisig:
            raise BTClibValueError("bare-multisig")


def are_inputs_standard(prevouts: Sequence[TxOut], tx: Tx) -> bool:
    """Answer Core's `AreInputsStandard`.

    A transaction is refused for running more than
    `MAX_TX_LEGACY_SIGOPS` legacy signature checks (BIP54): those of
    each script_sig and of the script_pub_key or redeem script it
    spends, counted accurately. Then each input is refused for spending
    a script_pub_key `solver` calls "nonstandard" or "witness_unknown",
    or a p2sh one whose script_sig leaves no redeem script or one
    announcing more than `MAX_P2SH_SIGOPS` checks. A coinbase is
    standard.
    """
    _assert_prevouts(prevouts, tx)
    if tx.is_coinbase:
        return True

    sig_ops = 0
    for tx_in, prevout in zip(tx.vin, prevouts, strict=True):
        script_sig = tx_in.script_sig
        sig_ops += sig_op_count(script_sig, accurate=True)
        sig_ops += p2sh_sig_op_count(script_sig, prevout.script_pub_key.script)
        if sig_ops > MAX_TX_LEGACY_SIGOPS:
            return False

    for tx_in, prevout in zip(tx.vin, prevouts, strict=True):
        tx_out_type, _ = solver(prevout.script_pub_key.script)
        if tx_out_type in ("nonstandard", "witness_unknown"):
            return False
        if tx_out_type == "scripthash":
            redeem_script = _redeem_script(tx_in.script_sig)
            if redeem_script is None:
                return False
            if sig_op_count(redeem_script, accurate=True) > MAX_P2SH_SIGOPS:
                return False
    return True


def is_witness_standard(prevouts: Sequence[TxOut], tx: Tx) -> bool:
    """Answer Core's `IsWitnessStandard`.

    An input with an empty witness is not judged. One with a witness is
    refused where it spends a pay-to-anchor output, or anything but a
    witness program, bare or nested in p2sh. A p2wsh spend is refused
    for a witness script over `MAX_STANDARD_P2WSH_SCRIPT_SIZE` bytes, or
    for more than `MAX_STANDARD_P2WSH_STACK_ITEMS` other items or one
    over `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` bytes. A taproot spend not
    nested in p2sh is refused for an annex, an empty control block, or a
    tapscript item over `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE` bytes.
    A coinbase is standard.
    """
    _assert_prevouts(prevouts, tx)
    if tx.is_coinbase:
        return True
    return all(
        _is_witness_input_standard(tx_in, prevout)
        for tx_in, prevout in zip(tx.vin, prevouts, strict=True)
    )


def _is_witness_input_standard(tx_in: TxIn, prevout: TxOut) -> bool:
    """Answer `IsWitnessStandard` for one input."""
    stack = tx_in.script_witness.stack
    if not stack:
        return True

    spent = prevout.script_pub_key.script
    # witness stuffing
    if _is_pay_to_anchor(spent):
        return False

    p2sh = _is_pay_to_script_hash(spent)
    script = _redeem_script(tx_in.script_sig) if p2sh else spent
    # no witness for what is not a witness program
    if script is None or (witness := _witness_program(script)) is None:
        return False
    version, program = witness

    if version == 0 and len(program) == _WITNESS_V0_SCRIPTHASH_SIZE:
        return _is_p2wsh_witness_standard(stack)
    if version == 1 and len(program) == _WITNESS_V1_TAPROOT_SIZE and not p2sh:
        return _is_taproot_witness_standard(stack)
    return True


def _is_p2wsh_witness_standard(stack: tuple[bytes, ...]) -> bool:
    """Answer the p2wsh limits on a witness stack that is not empty."""
    if len(stack[-1]) > MAX_STANDARD_P2WSH_SCRIPT_SIZE:
        return False
    items = stack[:-1]
    if len(items) > MAX_STANDARD_P2WSH_STACK_ITEMS:
        return False
    return all(len(item) <= MAX_STANDARD_P2WSH_STACK_ITEM_SIZE for item in items)


def _is_taproot_witness_standard(stack: tuple[bytes, ...]) -> bool:
    """Answer the taproot limits on a witness stack that is not empty.

    A key path spend is a single item, which no rule here reads. Core's
    branch for no item at all is unreachable, an empty witness being
    skipped before this.
    """
    if len(stack) < 2:
        return True
    if stack[-1][:1] == bytes([_ANNEX_TAG]):
        return False
    control_block = stack[-1]
    if not control_block:
        return False
    if control_block[0] & _TAPROOT_LEAF_MASK != _TAPROOT_LEAF_TAPSCRIPT:
        return True
    # the items under the script and the control block
    return all(
        len(item) <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE for item in stack[:-2]
    )


def spends_non_anchor_witness_prog(prevouts: Sequence[TxOut], tx: Tx) -> bool:
    """Answer Core's `SpendsNonAnchorWitnessProg`.

    Whether any input spends a witness program, of a version defined or
    not, bare or nested in p2sh. A bare pay-to-anchor does not count; one
    nested in p2sh does. A p2sh input whose script_sig leaves no redeem
    script is skipped. A coinbase
    spends none.
    """
    _assert_prevouts(prevouts, tx)
    if tx.is_coinbase:
        return False

    for tx_in, prevout in zip(tx.vin, prevouts, strict=True):
        script = prevout.script_pub_key.script
        if _witness_program(script) is not None and not _is_pay_to_anchor(script):
            return True
        if _is_pay_to_script_hash(script):
            redeem_script = _redeem_script(tx_in.script_sig)
            if redeem_script is None:
                continue
            if _witness_program(redeem_script) is not None:
                return True
    return False


def is_dust(tx_out: TxOut, *, dust_relay_fee: FeeRate = DUST_RELAY_FEE_RATE) -> bool:
    """Answer Core's `IsDust`: worth less than `fee.dust_threshold`."""
    assert_type(tx_out, TxOut, "tx_out")
    assert_type(dust_relay_fee, FeeRate, "dust_relay_fee")
    return tx_out.value < dust_threshold(tx_out.script_pub_key.script, dust_relay_fee)


def dust_outputs(tx: Tx, *, dust_relay_fee: FeeRate = DUST_RELAY_FEE_RATE) -> list[int]:
    """Return the indexes of the dust outputs, Core's `GetDust`."""
    assert_type(tx, Tx, "tx")
    assert_type(dust_relay_fee, FeeRate, "dust_relay_fee")
    return [
        i
        for i, tx_out in enumerate(tx.vout)
        if is_dust(tx_out, dust_relay_fee=dust_relay_fee)
    ]


def sig_ops_adjusted_weight(
    weight: int, *, sig_op_cost: int, bytes_per_sigop: int
) -> int:
    """Return Core's `GetSigOpsAdjustedWeight`.

    The weight, or `sig_op_cost` times `bytes_per_sigop` where that is
    more: a transaction heavy in signature checks is priced as if it
    were that large.
    """
    _assert_non_negative_integer(weight, "weight")
    _assert_non_negative_integer(sig_op_cost, "sig_op_cost")
    _assert_non_negative_integer(bytes_per_sigop, "bytes_per_sigop")
    return max(weight, sig_op_cost * bytes_per_sigop)


def virtual_size(
    weight: int,
    *,
    sig_op_cost: int = 0,
    bytes_per_sigop: int = DEFAULT_BYTES_PER_SIGOP,
) -> int:
    """Return Core's `GetVirtualTransactionSize`.

    `sig_ops_adjusted_weight` over `WITNESS_SCALE_FACTOR`, rounded up.
    `weight` is a transaction's, `Tx.weight`, or an input's,
    `btclib.tx.tx_in.input_weight`. Without `sig_op_cost` the answer for
    a transaction is its `Tx.vsize`.
    """
    adjusted = sig_ops_adjusted_weight(
        weight, sig_op_cost=sig_op_cost, bytes_per_sigop=bytes_per_sigop
    )
    return -(-adjusted // WITNESS_SCALE_FACTOR)
