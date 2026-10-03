# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The work validating a tapscript does grows with its size, not its square.

BIP342 lifted the 201 op code and 10,000 byte limits, so a leaf can nest
OP_IF as deep as the weight limit allows, repeat an OP_EQUALVERIFY as often,
and hold as many signature checks as its sigops budget pays for. Each test
spends a real P2TR output through `verify_transaction`, on a leaf that is
consensus-valid, and fails by timing out where the work per op code is
proportional to what came before it (GHSA-9fr5-46w5-5f9r).

The signature-check tests answer true to every verification: the hashing a
check commits to is what they time and count, and a valid signature per
check would cost far more than the hashing.
"""

import itertools
import time
from collections.abc import Callable

import pytest
from btclib_ecc.ecc import ssa

from btclib import var_bytes
from btclib.exceptions import BTClibValueError, ScriptError, ScriptErrorCode
from btclib.hashes import sha256
from btclib.script import Witness, sig_hash
from btclib.script.engine import script_op_codes, tapscript, verify_transaction
from btclib.script.engine.script_op_codes import ConditionStack
from btclib.script.taproot import leaf_hash, output_pubkey_from_merkle_root
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_G_X = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

_OP_0 = b"\x00"
_OP_1 = b"\x51"
_OP_IF = b"\x63"
_OP_ENDIF = b"\x68"
_OP_EQUALVERIFY = b"\x88"
_OP_2DUP = b"\x6e"
_OP_CHECKSIGVERIFY = b"\xad"
_OP_2DROP = b"\x6d"

# a hundred times what 201 op codes let a leaf nest, and enough that the
# quadratic version needs minutes where this one needs seconds. The bound
# is generous against a slow runner: the time a linear run takes is a
# fraction of it
_DEEP = 100_000
_BOUND = 60


def _spend(leaf: bytes, stack: list[bytes] | None = None) -> tuple[TxOut, Tx]:
    """Return a P2TR output committing to `leaf` and the spend of it."""
    output_key, parity = output_pubkey_from_merkle_root(_G_X, leaf_hash(0xC0, leaf))
    prevout = TxOut(10_000, b"\x51\x20" + output_key)
    control = bytes([0xC0 | parity]) + _G_X
    witness = Witness([*(stack or []), leaf, control])
    tx_in = TxIn(OutPoint("01" * 32, 0), b"", 0xFFFFFFFF, witness)
    return prevout, Tx(2, 0, [tx_in], [TxOut(9_000, b"\x6a")])


def _seconds(leaf: bytes) -> float:
    prevout, tx = _spend(leaf)
    start = time.perf_counter()
    verify_transaction([prevout], tx)
    return time.perf_counter() - start


def _nested_if(depth: int) -> bytes:
    return (_OP_1 + _OP_IF) * depth + _OP_1 + _OP_ENDIF * depth


def _equalverifies(count: int) -> bytes:
    return (_OP_1 + _OP_1 + _OP_EQUALVERIFY) * count + _OP_1


@pytest.mark.timeout(_BOUND)
def test_a_deeply_nested_if_is_validated_in_time() -> None:
    """`(OP_1 OP_IF)*n OP_1 OP_ENDIF*n`, the reproduction of the advisory."""
    prevout, tx = _spend(_nested_if(_DEEP))
    verify_transaction([prevout], tx)


@pytest.mark.timeout(_BOUND)
def test_many_equalverifies_are_validated_in_time() -> None:
    """`(OP_1 OP_1 OP_EQUALVERIFY)*n OP_1`, the second reproduction."""
    prevout, tx = _spend(_equalverifies(_DEEP))
    verify_transaction([prevout], tx)


def _checks(
    count: int, *, annex: bytes = b"", output: bytes = b"\x6a", hashtype: int = 0
) -> tuple[TxOut, Tx]:
    """Return the spend of a leaf making `count` signature checks.

    The signature is not valid: the tests using this one answer true to
    every verification. An unexecuted push gives the witness the weight the
    sigops budget wants, 50 for each check.
    """
    chunks = b"\x4d" + (500).to_bytes(2, "little") + bytes(500)
    padding = _OP_0 + _OP_IF + chunks * (50 * count // 500 + 1) + _OP_ENDIF
    leaf = padding + (_OP_2DUP + _OP_CHECKSIGVERIFY) * count + _OP_2DROP + _OP_1
    signature = bytes(64) + (bytes([hashtype]) if hashtype else b"")
    prevout, tx = _spend(leaf, [signature, _G_X])
    if annex:
        tx.vin[0].script_witness = Witness([*tx.vin[0].script_witness.stack, annex])
    tx.vout[0] = TxOut(9_000, output)
    return prevout, tx


def _checks_with_annex(count: int) -> tuple[TxOut, Tx]:
    return _checks(count, annex=b"\x50" + bytes(50 * count))


def _checks_with_output(count: int) -> tuple[TxOut, Tx]:
    return _checks(count, output=b"\x6a" + bytes(50 * count), hashtype=3)


def _checks_alone(count: int) -> tuple[TxOut, Tx]:
    return _checks(count)


def _seconds_of(prevout: TxOut, tx: Tx) -> float:
    start = time.perf_counter()
    verify_transaction([prevout], tx)
    return time.perf_counter() - start


@pytest.mark.timeout(_BOUND * 5)
@pytest.mark.parametrize("make", [_nested_if, _equalverifies])
def test_four_times_the_script_takes_about_four_times_as_long(
    make: Callable[[int], bytes],
) -> None:
    """Four times the script: 16 times as long if quadratic, 4 if linear."""
    small, large = make(_DEEP // 4), make(_DEEP)
    # the best of five: a slow moment on the small run would hide the growth
    ratio = min(_seconds(large) for _ in range(5)) / min(
        _seconds(small) for _ in range(5)
    )
    assert ratio < 10, f"{ratio:.1f} times as long for four times the script"


@pytest.mark.timeout(_BOUND * 5)
@pytest.mark.parametrize(
    "make", [_checks_alone, _checks_with_annex, _checks_with_output]
)
def test_four_times_the_signature_checks_take_about_four_times_as_long(
    make: Callable[[int], tuple[TxOut, Tx]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The annex and the output a check commits to cost their size once."""
    monkeypatch.setattr(tapscript, "ssa_verify", lambda *_: True)
    small, large = make(2_000), make(8_000)
    ratio = min(_seconds_of(*large) for _ in range(5)) / min(
        _seconds_of(*small) for _ in range(5)
    )
    assert ratio < 10, f"{ratio:.1f} times as long for four times the checks"


@pytest.mark.timeout(_BOUND)
def test_a_leaf_is_hashed_once_for_all_its_signature_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hashing the tapleaf at every signature check is quadratic."""
    count = 5
    # a push in a branch nothing takes, for the weight the sigops budget
    # pays by: 50 for each check
    padding = _OP_0 + _OP_IF + b"\x4d" + (50 * count).to_bytes(2, "little")
    padding += bytes(50 * count) + _OP_ENDIF
    leaf = padding + (_OP_2DUP + _OP_CHECKSIGVERIFY) * count + _OP_2DROP + _OP_1
    hash_ = leaf_hash(0xC0, leaf)
    prevout, tx = _spend(leaf)
    ext = hash_ + b"\x00" + (0xFFFFFFFF).to_bytes(4, "little")
    msg = sig_hash.taproot(tx, 0, [prevout], 0, 1, b"", ext)
    signature = ssa.sign_(msg, 1).serialize()
    prevout, tx = _spend(leaf, [signature, _G_X])

    calls: list[bytes] = []

    def counting_leaf_hash(version: int, script: bytes) -> bytes:
        calls.append(script)
        return leaf_hash(version, script)

    monkeypatch.setattr(tapscript, "leaf_hash", counting_leaf_hash)
    verify_transaction([prevout], tx)
    assert calls == [leaf]


def test_the_annex_is_hashed_once_for_all_the_checks_of_an_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core keeps `m_annex_hash`; hashing it per check is quadratic."""
    monkeypatch.setattr(tapscript, "ssa_verify", lambda *_: True)
    annex = b"\x50" + bytes(300)
    hashed: list[bytes] = []

    def counting_sha256(data: bytes) -> bytes:
        hashed.append(data)
        return sha256(data)

    monkeypatch.setattr(sig_hash, "sha256", counting_sha256)
    prevout, tx = _checks(5, annex=annex)
    verify_transaction([prevout], tx)
    assert hashed.count(var_bytes.serialize(annex)) == 1


def test_the_output_is_hashed_once_for_all_the_checks_of_an_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core keeps `m_output_hash`; hashing it per check is quadratic."""
    monkeypatch.setattr(tapscript, "ssa_verify", lambda *_: True)
    prevout, tx = _checks(5, output=b"\x6a" + bytes(300), hashtype=3)
    # a second output, so that the hash of all of them is not this one's
    tx.vout.append(TxOut(1, b"\x6a"))
    hashed: list[bytes] = []

    def counting_sha256(data: bytes) -> bytes:
        hashed.append(data)
        return sha256(data)

    monkeypatch.setattr(sig_hash, "sha256", counting_sha256)
    verify_transaction([prevout], tx)
    assert hashed.count(tx.vout[0].serialize()) == 1


@pytest.mark.parametrize("length", range(1, 8))
def test_the_condition_stack_answers_as_the_list_it_stands_for(length: int) -> None:
    """Every sequence of moves answers as the list of branches it replaces."""
    moves = ("push_true", "push_false", "close", "flip")
    for sequence in itertools.product(moves, repeat=length):
        stack = ConditionStack()
        model: list[bool] = []
        for move in sequence:
            if move.startswith("push"):
                stack.push(move == "push_true")
                model.append(move == "push_true")
            elif not model:
                continue
            elif move == "close":
                stack.close()
                model.pop()
            else:
                stack.flip()
                model[-1] = not model[-1]
            assert len(stack) == len(model), sequence
            assert stack.is_executing == all(model), sequence


@pytest.mark.parametrize("op", [script_op_codes.op_else, script_op_codes.op_endif])
def test_an_else_or_endif_without_a_branch_is_unbalanced(
    op: Callable[[ConditionStack], None],
) -> None:
    """The empty stack refuses both, with Core's code."""
    with pytest.raises(ScriptError) as excinfo:
        op(ConditionStack())
    assert excinfo.value.code == ScriptErrorCode.UNBALANCED_CONDITIONAL


@pytest.mark.parametrize("move", [ConditionStack.close, ConditionStack.flip])
def test_closing_or_flipping_with_no_branch_open_is_refused(
    move: Callable[[ConditionStack], None],
) -> None:
    """Core asserts it; the callers refuse first, with the script's error."""
    with pytest.raises(BTClibValueError, match="no branch open"):
        move(ConditionStack())


def test_a_branch_left_open_is_unbalanced() -> None:
    """`assert_balanced_if` counts the branches the script never closed."""
    stack = ConditionStack()
    script_op_codes.assert_balanced_if(stack)
    stack.push(True)
    stack.push(False)
    with pytest.raises(ScriptError, match="2 left open") as excinfo:
        script_op_codes.assert_balanced_if(stack)
    assert excinfo.value.code == ScriptErrorCode.UNBALANCED_CONDITIONAL
