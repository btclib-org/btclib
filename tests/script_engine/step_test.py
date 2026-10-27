# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `step` callback of `btclib.script.engine.verify_input`."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from ecc.curves import bytes_from_point, mult

from btclib.alias import Command, TaprootScriptTree
from btclib.exceptions import BTClibValueError, ScriptError, ScriptErrorCode
from btclib.script import ScriptPubKey
from btclib.script.engine import ALL_FLAGS, NO_FLAGS, ScriptFlag, verify_input
from btclib.script.engine.script_op_codes import ScriptStep
from btclib.script.script import serialize
from btclib.script.taproot import input_script_sig, output_pubkey
from btclib.script.taproot import serialize as serialize_tapscript
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

Frame = tuple[int, int | None, bool, tuple[bytes, ...], tuple[bytes, ...]]


def _trace(
    prevout: TxOut, script_sig: bytes, witness: list[bytes], flags: ScriptFlag
) -> tuple[list[Frame], ScriptError | None]:
    """Return the frames of the spend of `prevout`, and its refusal."""
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 0xFFFFFFFF, Witness(witness))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    frames: list[Frame] = []

    def step(
        index: int,
        op_code: int | None,
        executing: bool,
        stack: tuple[bytes, ...],
        altstack: tuple[bytes, ...],
    ) -> None:
        frames.append((index, op_code, executing, stack, altstack))

    try:
        verify_input([prevout], tx, 0, flags, step=step)
    except ScriptError as error:
        return frames, error
    return frames, None


def test_a_frame_per_command_and_one_at_the_end() -> None:
    """Each command before it runs, a branch not taken, and both stacks."""
    script_pub_key = serialize(
        ["OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF", "OP_DUP", "OP_TOALTSTACK"]
    )
    frames, error = _trace(TxOut(1000, script_pub_key), b"\x51", [], NO_FLAGS)
    assert error is None
    one, two = (b"\x01",), (b"\x02",)
    assert frames == [
        # the script_sig, OP_1
        (0, 0x51, True, (), ()),
        (1, None, True, one, ()),
        # the script_pub_key, on the stack the script_sig left
        (0, 0x63, True, one, ()),
        (1, 0x52, True, (), ()),
        (2, 0x67, True, two, ()),
        (3, 0x53, False, two, ()),
        (4, 0x68, False, two, ()),
        (5, 0x76, True, two, ()),
        (6, 0x6B, True, (b"\x02", b"\x02"), ()),
        (7, None, True, two, two),
    ]


def test_the_end_frame_of_a_stack_size_refusal() -> None:
    """The overflowing command, where Core's tracer ends (issue #2801)."""
    frames, error = _trace(TxOut(1000, b"\x51" * 1001), b"", [], NO_FLAGS)
    assert error is not None
    assert error.code is ScriptErrorCode.STACK_SIZE
    # the empty script_sig ends where it starts
    assert frames[0] == (0, None, True, (), ())
    steps, end = frames[1:-1], frames[-1]
    assert [frame[0] for frame in steps] == list(range(1001))
    assert end[:3] == (1000, None, True)
    assert len(end[3]) == 1001


def _tapscript_spend(
    script: list[Command], stack: list[bytes]
) -> tuple[TxOut, list[bytes]]:
    """Return a one-leaf taproot output and the witness spending its leaf."""
    tree: TaprootScriptTree = [(0xC0, script)]
    output = output_pubkey(None, tree)[0]
    leaf, control = input_script_sig(None, tree, 0)
    witness = [*stack, serialize_tapscript(leaf), control]
    return TxOut(1000, serialize(["OP_1", output])), witness


@pytest.mark.parametrize(
    "script, stack, code, end",
    [
        (["PUB_KEY", "OP_CHECKSIG"], [b"\x01" * 64], "SCHNORR_SIG", 1),
        (["OP_0", "PUB_KEY", "OP_CHECKSIGADD"], [b"\x01"], "SCHNORR_SIG_SIZE", 2),
    ],
)
def test_a_refused_tapscript_signature_check_ends_on_its_operands(
    script: list[str], stack: list[bytes], code: str, end: int
) -> None:
    """The operands stay, as Core's script tracer shows them (issue #2800)."""
    pub_key = bytes_from_point(mult(1))[1:]
    commands: list[Command] = [pub_key if c == "PUB_KEY" else c for c in script]
    prevout, witness = _tapscript_spend(commands, stack)
    frames, error = _trace(prevout, b"", witness, ALL_FLAGS)
    assert error is not None
    assert error.code is ScriptErrorCode[code]
    index, op_code, _, final, altstack = frames[-1]
    assert (index, op_code, altstack) == (end, None, ())
    assert len(final) == len(stack) + len(script) - 1


def test_a_script_not_started_makes_no_call() -> None:
    """A tapscript holding an OP_SUCCESSx is not run."""
    # what follows an OP_SUCCESSx is one bytes command to the serializer
    prevout, witness = _tapscript_spend(["OP_SUCCESS80", b"\x01"], [])
    frames, error = _trace(prevout, b"", witness, ALL_FLAGS)
    assert error is None
    ends = [frame for frame in frames if frame[1] is None]
    # the script_sig and the script_pub_key, and nothing for the leaf
    assert len(ends) == 2


def _raising(error: Exception, *, at_the_end: bool) -> ScriptStep:
    """Return a callback raising `error` per command, or at the end only."""

    def step(
        index: int,
        op_code: int | None,
        executing: bool,
        stack: tuple[bytes, ...],
        altstack: tuple[bytes, ...],
    ) -> None:
        if (op_code is None) == at_the_end:
            raise error

    return step


def _spend(script_sig: bytes) -> tuple[list[TxOut], Tx]:
    """Return a spend of OP_1 with `script_sig`."""
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 0xFFFFFFFF, Witness())
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    return [TxOut(1000, b"\x51")], tx


@pytest.mark.parametrize("at_the_end", [False, True])
@pytest.mark.parametrize(
    "error", [IndexError("callback"), BTClibValueError("callback")]
)
def test_a_callback_exception_leaves_unconverted(
    error: Exception, at_the_end: bool
) -> None:
    """Never a refusal: the interpreter turns these two into one otherwise."""
    prevouts, tx = _spend(b"\x51")
    step = _raising(error, at_the_end=at_the_end)
    with pytest.raises(type(error)) as exc_info:
        verify_input(prevouts, tx, 0, NO_FLAGS, step=step)
    assert exc_info.value is error


def test_a_refusal_in_progress_is_the_context_of_an_end_call_exception() -> None:
    """The callback's exception leaves, and the refusal is not lost."""
    # OP_RETURN, the first script to run and to end
    prevouts, tx = _spend(b"\x6a")
    error = IndexError("callback")
    with pytest.raises(IndexError) as exc_info:
        verify_input(prevouts, tx, 0, NO_FLAGS, step=_raising(error, at_the_end=True))
    assert exc_info.value is error
    refusal = exc_info.value.__context__
    assert isinstance(refusal, ScriptError)
    assert refusal.code is ScriptErrorCode.OP_RETURN


def test_a_callback_exception_leaves_a_tapscript_unconverted() -> None:
    """The tapscript loop carries it out too."""
    prevout, witness = _tapscript_spend(["OP_2"], [])
    error = IndexError("callback")

    def step(
        index: int,
        op_code: int | None,
        executing: bool,
        stack: tuple[bytes, ...],
        altstack: tuple[bytes, ...],
    ) -> None:
        # OP_2, which only the tapscript holds
        if op_code == 0x52:
            raise error

    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, Witness(witness))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    with pytest.raises(IndexError) as exc_info:
        verify_input([prevout], tx, 0, ALL_FLAGS, step=step)
    assert exc_info.value is error


def _legacy_spend() -> tuple[list[TxOut], Tx, int]:
    """Return a spend of OP_1 by OP_1, and the op code the callback trips on."""
    prevouts, tx = _spend(b"\x51")
    return prevouts, tx, 0x51


def _tapscript_spend_of_op_2() -> tuple[list[TxOut], Tx, int]:
    """Return a spend of the tapscript OP_2, and the op code to trip on."""
    prevout, witness = _tapscript_spend(["OP_2"], [])
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, Witness(witness))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    # OP_2, which only the tapscript holds
    return [prevout], tx, 0x52


@pytest.mark.parametrize("chained", ["cause", "context", "interrupt"])
@pytest.mark.parametrize("spend", [_legacy_spend, _tapscript_spend_of_op_2])
def test_a_callback_exception_keeps_its_cause_and_ends_the_calls(
    spend: Callable[[], tuple[list[TxOut], Tx, int]], chained: str
) -> None:
    """Its `__cause__` as raised, and no call after it.

    Its `__context__` too, the test handling no exception around the call.

    A KeyboardInterrupt, which is no Exception, included.
    """
    prevouts, tx, trip = spend()
    calls: list[int | None] = []
    first = KeyError("first")
    raised: list[BaseException] = []

    def step(
        index: int,
        op_code: int | None,
        executing: bool,
        stack: tuple[bytes, ...],
        altstack: tuple[bytes, ...],
    ) -> None:
        calls.append(op_code)
        if op_code != trip:
            return
        if chained == "interrupt":
            interrupt = KeyboardInterrupt()
            raised.append(interrupt)
            raise interrupt
        if chained == "cause":
            error = ValueError("from")
            raised.append(error)
            raise error from first
        try:
            raise first
        except KeyError:
            error = ValueError("during")
            raised.append(error)
            raise error  # noqa: B904

    expected = KeyboardInterrupt if chained == "interrupt" else ValueError
    with pytest.raises(expected) as exc_info:
        verify_input(prevouts, tx, 0, ALL_FLAGS, step=step)
    assert exc_info.value is raised[0]
    if chained == "interrupt":
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
    elif chained == "cause":
        assert exc_info.value.__cause__ is first
        assert exc_info.value.__context__ is None
    else:
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is first
    assert calls[-1] == trip
