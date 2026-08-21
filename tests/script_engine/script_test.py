# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.engine` module.

The vectors are Bitcoin Core's `src/test/data/script_tests.json`, entire
and byte for byte; tests/_data/README.md pins the revision.
"""

from io import BytesIO
from typing import Any, NamedTuple

import pytest

from btclib.alias import TaprootScriptTree
from btclib.ecc import ssa
from btclib.ecc.dsa import Sig, sign_
from btclib.exceptions import BTClibValueError, ScriptError
from btclib.hashes import hash160, sha256
from btclib.script import ScriptPubKey, sig_hash
from btclib.script.engine import (
    ALL_FLAGS,
    NO_FLAGS,
    ScriptFlag,
    validate_push_only,
    verify_input,
    verify_transaction,
)
from btclib.script.engine.script import (
    DISABLED_OP_CODES,
    calculate_script_code,
    find_and_delete,
    fix_signature,
    verify_script,
)
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.script import OP_CODE_NAME_FROM_INT, parse, serialize
from btclib.script.taproot import (
    input_script_sig,
    leaf_hash,
    output_prvkey,
    output_pubkey,
)
from btclib.script.taproot import parse as parse_tapscript
from btclib.script.taproot import serialize as serialize_tapscript
from btclib.script.witness import Witness
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from tests import load, vector_id
from tests.script_engine import parse_script


class ScriptVector(NamedTuple):
    """One vector of Bitcoin Core's script_tests.json, fields named."""

    stack: list[str]
    amount: int
    script_sig: str
    script_pub_key: str
    # Core's comma-separated flags field, passed to verify_input as it is:
    # to_script_flags splits it and looks every name up. It was annotated
    # list[str] while holding that very string, and the engine's
    # `"WITNESS" in flags` was then a substring test that "WITNESS_PUBKEYTYPE"
    # and "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" both satisfy -- no vector
    # in today's file names either without also naming WITNESS, so nothing
    # was misvalidated, which is exactly how long that would have lasted
    # (issue #145)
    flags: str
    valid: bool


SCRIPT_FLAG = "#SCRIPT#"


def taproot_placeholders(
    stack: list[Any], script_pub_key: str
) -> tuple[list[Any], str]:
    """Fill in what a tapscript vector leaves to the harness.

    The five TAPSCRIPT vectors carry three placeholders that Core's
    `script_tests.cpp` generates rather than storing: `#SCRIPT# <script>`
    is a witness element written in the vector's own script language
    instead of hex, `#CONTROLBLOCK#` is the control block spending the
    element pushed before it, and `0x51 0x20 #TAPROOTOUTPUT#` is the
    output key committing to that script.

    The internal key is Core's `key0` there and the BIP341 NUMS point
    here, which no vector can tell apart: all three values come from the
    same tree, and none of the five spends the key path. Left alone, the
    tokens reach `parse_script` as op code names -- three vectors then
    fail on `OP_#TAPROOTOUTPUT#`, and the two expecting a failure get one
    for the wrong reason, which is worse.
    """
    out: list[Any] = []
    q = b""
    for element in stack:
        if isinstance(element, str) and element.startswith(SCRIPT_FLAG):
            out.append(parse_script(element[len(SCRIPT_FLAG) :]))
        elif element == "#CONTROLBLOCK#":
            # the tapscript is the element before it, and parsing it back
            # is faithful for all five: serialize(parse(bytes)) == bytes
            script_tree: TaprootScriptTree = [
                (0xC0, parse_tapscript(bytes.fromhex(out[-1])))
            ]
            q = output_pubkey(None, script_tree)[0]
            out.append(input_script_sig(None, script_tree, 0)[1].hex())
        else:
            out.append(element)
    return out, script_pub_key.replace("#TAPROOTOUTPUT#", f"0x{q.hex()}")


def script_vectors() -> list[Any]:
    """One case per vector of Bitcoin Core's script_tests.json.

    A vector is [[witness..., amount]?, scriptSig, scriptPubKey, flags,
    expected_scripterror, comment?], interleaved with comment lines that
    are a one element array of text. The optional leading witness stack
    shifts the rest by one, and the amount is the last entry of that
    stack when it is a number.
    """
    params = []
    data = load("script_engine", "_data", "script_tests.json")
    for index, x in enumerate(data):
        if len(x) == 1 and isinstance(x[0], str):
            continue  # a comment line between two vectors

        amount = 0
        if isinstance(x[0], str):
            i = 0
            stack = []
        else:
            i = 1
            stack = x[0]
            # Core writes the amount as the last element of that array,
            # always: asserted rather than guarded, so a vector file
            # refreshed into another shape says so here rather than
            # being measured against an amount of zero
            assert isinstance(stack[-1], (int, float))
            amount = int(stack[-1] * 10**8)
            stack = stack[:-1]

        stack, script_pub_key = taproot_placeholders(stack, x[i + 1])
        vector = ScriptVector(
            stack, amount, x[i], script_pub_key, x[i + 2], x[i + 3] == "OK"
        )
        # the trailing comment of the vector says what it is testing, and
        # two thirds of them have one; the script itself for the rest
        comment = x[i + 4] if len(x) > i + 4 else ""
        params.append(
            pytest.param(vector, id=vector_id(index, comment or vector.script_pub_key))
        )
    return params


@pytest.mark.parametrize("vector", script_vectors())
def test_script(vector: ScriptVector) -> None:
    """Run each Core vector through verify_input, expecting its verdict."""

    def verify() -> None:
        coinbase_input = TxIn(
            sequence=0xFFFFFFFF, prev_out=OutPoint(), script_sig=b"\x00\x00"
        )
        script_pub_key = parse_script(vector.script_pub_key)
        coinbase_output = TxOut(
            value=vector.amount, script_pub_key=ScriptPubKey(script_pub_key)
        )
        coinbase = Tx(
            version=1, lock_time=0, vin=[coinbase_input], vout=[coinbase_output]
        )

        script_sig = parse_script(vector.script_sig)
        spending_input = TxIn(
            sequence=0xFFFFFFFF,
            prev_out=OutPoint(tx_id=coinbase.id, vout=0),
            script_sig=script_sig,
            script_witness=Witness(vector.stack),
        )
        spending = Tx(
            version=1,
            lock_time=0,
            vin=[spending_input],
            vout=[TxOut(vector.amount, ScriptPubKey(""))],
        )

        verify_input([coinbase_output], spending, 0, vector.flags)

    if vector.valid:
        verify()
    else:
        # BTClibValueError, not Exception: a vector expecting a failure
        # gets one from anything that raises, the harness included, and
        # `parse_script` raises KeyError on an op code name btclib does
        # not know. That is how the seventeen DISABLED_OPCODE vectors
        # below passed while the rule they test was missing -- the names
        # were unknown, the scripts were never built, and no engine ever
        # saw them. Everything the engine refuses is a BTClibValueError,
        # ScriptError included, so a KeyError is now a red test
        with pytest.raises(BTClibValueError):
            verify()


def test_script_error_says_what_and_where() -> None:
    """A verification failure names the failure and its position.

    The op code implementations are handed the stack alone and cannot
    know either; the interpreter loop adds the command index and the
    stack depth on the way out.
    """
    tx = Tx(check_validity=False)

    # OP_1, OP_1, OP_RETURN
    with pytest.raises(ScriptError, match="OP_RETURN") as exc_info:
        verify_script(b"\x51\x51\x6a", [], 0, tx, 0, NO_FLAGS, False)
    assert exc_info.value.index == 2
    assert exc_info.value.stack_depth == 2
    assert "command 2" in str(exc_info.value)
    assert "stack depth 2" in str(exc_info.value)

    # a ScriptError is a BTClibValueError: catching that keeps working
    with pytest.raises(BTClibValueError):
        verify_script(b"\x51\x51\x6a", [], 0, tx, 0, NO_FLAGS, False)


def test_script_error_stack_underflow() -> None:
    """An empty stack is an underflow, not a bare IndexError."""
    tx = Tx(check_validity=False)

    # OP_DUP on nothing
    with pytest.raises(ScriptError, match="stack underflow") as exc_info:
        verify_script(b"\x76", [], 0, tx, 0, NO_FLAGS, False)
    assert exc_info.value.index == 0
    assert exc_info.value.stack_depth == 0

    # OP_1, OP_EQUAL: the second pop is the one that underflows
    with pytest.raises(ScriptError, match="stack underflow") as exc_info:
        verify_script(b"\x51\x87", [], 0, tx, 0, NO_FLAGS, False)
    assert exc_info.value.index == 1


def test_unknown_op_code_is_not_a_key_error() -> None:
    """Refuse the byte 0xff as a ScriptError, not a KeyError."""
    tx = Tx(check_validity=False)
    with pytest.raises(ScriptError, match="unknown op code: 0xff"):
        verify_script(b"\xff", [], 0, tx, 0, NO_FLAGS, False)


def test_unbalanced_conditional() -> None:
    """Both halves of the rule: a branch never closed, and one never opened.

     Core has the two as two checks -- `vfExec.empty()` inside OP_ELSE and
     OP_ENDIF, `!vfExec.empty()` once the loop is over -- and counting
     OP_IF, OP_NOTIF and OP_ENDIF over the parsed script answers only the
     second. The sum is the depth the script ends at, so a script that
     closes a branch before opening one counts to zero, and popping the
     sentinel left `all([])` True: the rest ran as if the OP_ENDIF had shut
     the branch the OP_IF later opened, and the engine called valid a
     script Core answers with SCRIPT_ERR_UNBALANCED_CONDITIONAL
    .
    """
    tx = Tx(check_validity=False)

    # OP_1, OP_IF, OP_1: a branch left open
    with pytest.raises(BTClibValueError, match="unbalanced conditional"):
        verify_script(b"\x51\x63\x51", [], 0, tx, 0, NO_FLAGS, False)

    # OP_ENDIF, OP_1, OP_IF, OP_1: as many OP_ENDIF as OP_IF, wrongly ordered
    with pytest.raises(ScriptError, match="OP_ENDIF without OP_IF") as exc_info:
        verify_script(b"\x68\x51\x63\x51", [], 0, tx, 0, NO_FLAGS, False)
    assert exc_info.value.index == 0

    # OP_ELSE is the same rule and was already enforced
    with pytest.raises(ScriptError, match="OP_ELSE without OP_IF"):
        verify_script(b"\x67", [], 0, tx, 0, NO_FLAGS, False)

    # and OP_IF alone is an underflow rather than an unbalanced conditional:
    # Core reads the condition off the stack before it pushes to vfExec, so
    # this is the position where the two rules are told apart
    with pytest.raises(ScriptError, match="stack underflow"):
        verify_script(b"\x63", [], 0, tx, 0, NO_FLAGS, False)


def test_ifdup_casts_to_bool() -> None:
    """OP_IFDUP duplicates a *true* element, and `00` is not one.

    Core's `if (CastToBool(vch))`. Testing for the empty element instead
    duplicated a one-byte zero and a negative zero, which are false
    without being empty, and left every op code after one of them reading
    a stack an element deeper than Core's -- so btclib rejected a script
    Core accepts, which is the direction that costs a spend. Neither
    vendored set covers it: no vector feeds OP_IFDUP a non-empty false
    element.
    """
    tx = Tx(check_validity=False)

    for element in (b"\x00", b"\x80", b"\x00\x00", b"\x00\x80"):
        # <element>, OP_IFDUP, OP_DEPTH, OP_1, OP_NUMEQUAL: nothing was duped
        script_bytes = serialize(
            [element, "OP_IFDUP", "OP_DEPTH", "OP_1", "OP_NUMEQUAL"]
        )
        verify_script(script_bytes, [], 0, tx, 0, NO_FLAGS, False, True)

    # and a true element still is: OP_1, OP_IFDUP leaves a depth of two
    script_bytes = serialize(["OP_1", "OP_IFDUP", "OP_DEPTH", "OP_2", "OP_NUMEQUAL"])
    verify_script(script_bytes, [], 0, tx, 0, NO_FLAGS, False, True)


def test_a_serialized_zero_is_a_number_the_interpreter_reads() -> None:
    """What `serialize` writes for the integer 0, the engine reads as 0.

    The writer and the reader are `encode_num` and `_to_num`, and no
    vector puts the two together: the vendored sets spell their zero
    OP_0, so a `serialize` that wrote the push `0100` instead would pass
    every one of them and still be refused -- by btclib's own engine and
    by Core's -- at the first op code that reads a number under
    MINIMALDATA, a flag every relay path sets (issue #746).
    """
    tx = Tx(check_validity=False)

    # 0, OP_1ADD, OP_1, OP_NUMEQUAL: the number goes in through serialize
    # and comes out through _to_num, with MINIMALDATA judging it
    script_bytes = serialize([0, "OP_1ADD", "OP_1", "OP_NUMEQUAL"])
    assert script_bytes == b"\x00\x8b\x51\x9c"
    verify_script(script_bytes, [], 0, tx, 0, ScriptFlag.MINIMALDATA, False, True)

    # the same script with the zero pushed as one byte of data: a number
    # nowhere the flag is in force, and unspendable there
    non_minimal = b"\x01\x00" + script_bytes[1:]
    with pytest.raises(ScriptError, match="non-minimal encoding of 0: 00"):
        verify_script(non_minimal, [], 0, tx, 0, ScriptFlag.MINIMALDATA, False, True)

    # a script number all the same where nothing asks for minimality,
    # which is why that spelling passes the vectors it passes
    verify_script(non_minimal, [], 0, tx, 0, NO_FLAGS, False, True)


def test_negative_zero_is_refused_by_the_one_minimality_check() -> None:
    """`80` is a non-minimal zero, and the general comparison says so.

    It is the third spelling of zero and the second one MINIMALDATA
    refuses, so what is asserted here is that one check answers for both:
    `encode_num` writes the empty vector, which `80` is not, and no case
    of its own is needed to reach that verdict.
    """
    tx = Tx(check_validity=False)

    # 80, OP_1ADD, OP_1, OP_NUMEQUAL: negative zero where a number is read
    negative_zero = b"\x01\x80\x8b\x51\x9c"
    with pytest.raises(ScriptError, match="non-minimal encoding of 0: 80"):
        verify_script(negative_zero, [], 0, tx, 0, ScriptFlag.MINIMALDATA, False, True)

    # and zero it is, wherever nothing asks for the minimal spelling
    verify_script(negative_zero, [], 0, tx, 0, NO_FLAGS, False, True)


@pytest.mark.parametrize(
    "script, message",
    [
        (
            ["OP_0", "OP_1NEGATE", "OP_1NEGATE", "OP_CHECKMULTISIG"],
            "invalid number of public keys",
        ),
        (
            ["OP_0", "OP_1NEGATE", "OP_0", "OP_CHECKMULTISIG"],
            "signatures for 0 public keys",
        ),
    ],
    ids=["negative public keys", "negative signatures"],
)
def test_multisig_negative_counts(script: list[Any], message: str) -> None:
    """A negative count ends the script, as Core's two range checks do.

    SCRIPT_ERR_PUBKEY_COUNT is `nKeysCount < 0 || nKeysCount > 20` and
    SCRIPT_ERR_SIG_COUNT is `nSigsCount < 0 || nSigsCount > nKeysCount`;
    the lower bounds are the half that was missing, and a test for "more
    than twenty" cannot stand in for them. A negative count reaches
    `range` as an empty one, so nothing was popped, nothing underflowed,
    and OP_CHECKMULTISIG pushed false and let the script run on -- which
    an OP_NOT after it turns into a valid spend.
    """
    tx = Tx(check_validity=False)
    with pytest.raises(ScriptError, match=message):
        verify_script(serialize(script), [], 0, tx, 0, NO_FLAGS, False, True)


def test_fix_signature_asks_for_strict_der_as_one_mask() -> None:
    """DERSIG, LOW_S and STRICTENC each ask for strict DER, as in Core.

    CheckSignatureEncoding gates IsValidSignatureEncoding on `flags &
    (DERSIG | LOW_S | STRICTENC)`, one mask and not three rules. Gating it
    on DERSIG while letting STRICTENC *disable* it accepted, under
    STRICTENC alone, under LOW_S alone and under the two flags together,
    encodings Core answers with SCRIPT_ERR_SIG_DER; no vector could catch
    it, script_tests.json naming STRICTENC and DERSIG together in none of
    its cases.
    """
    # the signature of "P2PK with too much R padding": one leading zero byte
    # too many in r, which Core's lax parser still reads and BIP66 refuses
    signature = bytes.fromhex(
        "304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987"
        "022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c11801"
    )
    for flags in (
        ScriptFlag.DERSIG,
        ScriptFlag.LOW_S,
        ScriptFlag.STRICTENC,
        ScriptFlag.DERSIG | ScriptFlag.STRICTENC,
        ScriptFlag.DERSIG | ScriptFlag.LOW_S,
    ):
        with pytest.raises(BTClibValueError, match="padding"):
            fix_signature(signature, flags)

    # with none of the three it is normalized instead, which is what stands
    # in for Core's lax parser: one byte shorter, and the same signature
    sig = Sig.parse(signature[:-1], strict=False)
    assert fix_signature(signature, NO_FLAGS) == sig.serialize() + signature[-1:]


def test_fix_signature_high_s() -> None:
    """A high s is an error under LOW_S and negated away without it.

    Core's SCRIPT_ERR_SIG_HIGH_S, and the reason it cannot be left to the
    bindings: `CPubKey::Verify` normalizes s before verifying, so a high s
    verifies there while libsecp256k1's own verify refuses it. Refusing it
    for the flag and normalizing it otherwise is what makes both answers
    Core's.
    """
    signature = bytes.fromhex(
        "304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987"
        "022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c11801"
    )
    low = Sig.parse(signature[:-1], strict=False)
    assert low.s < low.ec.n // 2
    high_s = Sig(low.r, low.ec.n - low.s).serialize() + signature[-1:]

    with pytest.raises(BTClibValueError, match="high s"):
        fix_signature(high_s, ScriptFlag.LOW_S)
    assert fix_signature(high_s, ScriptFlag.DERSIG) == low.serialize() + signature[-1:]


def taproot_script_spend(
    script: list[Any],
    lock_time: int,
    sequence: int,
    extra_witness: tuple[str, ...] = (),
    leaf_version: int = 0xC0,
) -> tuple[list[TxOut], Tx]:
    """Build a script-path spend of the given tapscript, unsigned.

    The internal key is the BIP341 NUMS point, the default of
    output_pubkey and input_script_sig, so the key path cannot sign;
    the script path needs no signature unless the script asks for one,
    which is what lets a timelock op code run alone.

    `extra_witness` sits under the script and the control block, which is
    where the interpreter's initial stack comes from; the control block
    commits to the script alone, so adding elements breaks nothing.

    `leaf_version` other than 0xc0 is the version BIP342 left to a future
    soft fork: the commitment is still checked and the script never runs,
    so the script argument says what would have happened if it had. It
    must be even, the low bit of a control block being the parity of the
    output key rather than part of the version.
    """
    script_tree: TaprootScriptTree = [(leaf_version, script)]
    q, _ = output_pubkey(None, script_tree)
    tap_script, control = input_script_sig(None, script_tree, 0)
    prevout = TxOut(1000, ScriptPubKey(serialize(["OP_1", q])))
    tx_in = TxIn(
        OutPoint(b"\x01" * 32, 0),
        b"",
        sequence,
        # the tapscript serializer, which is the one output_pubkey and
        # input_script_sig committed to above: the two agree on every op
        # code both tables name, and only it knows OP_SUCCESSx
        Witness([*extra_witness, serialize_tapscript(tap_script).hex(), control.hex()]),
    )
    tx = Tx(
        2, lock_time, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False
    )
    return [prevout], tx


def test_tapscript_checklocktimeverify() -> None:
    """OP_CHECKLOCKTIMEVERIFY spent through a taproot script path.

    The BIP341 vectors carry no timelock op code, so the tapscript
    dispatch of OP_CLTV ran on no vector; this spend is the synthetic
    one that runs it: operand 1 against lock_time 100, same time kind,
    sequence not final.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKLOCKTIMEVERIFY"], lock_time=100, sequence=1
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_tapscript_checksequenceverify() -> None:
    """OP_CHECKSEQUENCEVERIFY spent through a taproot script path.

    Same reason as OP_CLTV above. The passing spend: operand 1 against
    an input sequence of 1, both with bit 31 clear and the same unit
    bit, on a version 2 transaction. The failing one: bit 31 set on the
    input sequence disables its relative lock time, so an OP_CSV that
    still asks for one must fail -- the one raise of the op code no
    Core vector reaches, legacy or tapscript.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKSEQUENCEVERIFY"], lock_time=0, sequence=1
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)

    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKSEQUENCEVERIFY"], lock_time=0, sequence=1 << 31
    )
    with pytest.raises(BTClibValueError, match="relative lock time disabled"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_tapscript_upgradable_nop() -> None:
    """An upgradable OP_NOPx in a tapscript is a no-op.

    BIP342 leaves OP_NOP1 and OP_NOP4-OP_NOP10 with their NOP
    semantics, and no vector spends one: this covers the dispatch, and
    ALL_FLAGS deliberately omits DISCOURAGE_UPGRADABLE_NOPS, which is
    policy rather than consensus, so op_nop stays silent.
    """
    prevouts, tx = taproot_script_spend(["OP_1", "OP_NOP4"], lock_time=0, sequence=1)
    verify_input(prevouts, tx, 0, ALL_FLAGS)


@pytest.mark.parametrize("op_code", [b"\x65", b"\x66"], ids=["OP_VERIF", "OP_VERNOTIF"])
def test_verif_in_an_unexecuted_branch(op_code: bytes) -> None:
    """OP_VERIF and OP_VERNOTIF are invalid in a branch nothing takes.

    Core reads an op code sitting in OP_IF..OP_ENDIF whether or not the
    branch executes, and gives these two no case of their own, so they
    reach `default: BAD_OPCODE` from a branch never taken. Both engines
    listed the four conditionals of that range instead of the range, so
    both skipped these two and accepted the script (issue #182).

    Neither vendored set caught it, both being green before the fix:
    the two vectors script_tests.json carries execute the op code, and
    script_assets_test.json spends nothing that hides one in a branch it
    does not take.
    """
    # OP_0, OP_IF, <op code>, OP_ENDIF, OP_1
    script_bytes = b"\x00\x63" + op_code + b"\x68\x51"

    tx = Tx(check_validity=False)
    with pytest.raises(ScriptError, match="unknown op code: OP_VER") as exc_info:
        verify_script(script_bytes, [], 0, tx, 0, NO_FLAGS, False)
    assert exc_info.value.index == 2

    prevouts, tx = taproot_script_spend(
        parse_tapscript(script_bytes), lock_time=0, sequence=1
    )
    with pytest.raises(ScriptError, match="unknown op code: OP_VER"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_disabled_op_codes() -> None:
    """The fifteen op codes CVE-2010-5137 switched off, named and refused.

    Core's own vectors cover the refusal — twenty-four DISABLED_OPCODE
    cases, seventeen of them in a branch never taken — and not one of
    them could reach the engine while the names were missing:
    `parse_script` raised KeyError, `pytest.raises(Exception)` took it
    for a verdict, and all twenty-four passed against a rule that was
    not there. What is left to pin here is the property they assume,
    which is also why the names are in the tables: every byte has one,
    the name serializes back to the byte, and the engine refuses it
    whatever the conditionals around it do.
    """
    assert len(DISABLED_OP_CODES) == 15

    tx = Tx(check_validity=False)
    for op_code in sorted(DISABLED_OP_CODES):
        name = OP_CODE_NAME_FROM_INT[op_code]
        assert serialize([name]) == bytes([op_code])
        assert parse(bytes([op_code])) == [name]

        # OP_0, OP_IF, <op code>, OP_ENDIF, OP_1: never executed
        script_bytes = b"\x00\x63" + bytes([op_code]) + b"\x68\x51"
        with pytest.raises(ScriptError, match=f"disabled op code: {name}"):
            verify_script(script_bytes, [], 0, tx, 0, NO_FLAGS, False)


def test_verif_before_an_op_success() -> None:
    """An OP_SUCCESS ahead of OP_VERIF makes the tapscript valid anyway.

    Core's pre-scan returns success at the first OP_SUCCESS whatever
    precedes it, so this spend is valid, and that is what keeps both op
    codes in the tapscript tables: without a name for 0x65, `parse`
    would raise on the byte before the pre-scan could answer, and btclib
    would reject a spendable script (issue #182).
    """
    prevouts, tx = taproot_script_spend(
        ["OP_VERIF", "OP_SUCCESS80", b""], lock_time=0, sequence=1
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_op_success_leftover_passes_cleanstack() -> None:
    """CLEANSTACK never fails a witness spend, which is Core's meaning.

    Core resizes the stack to one element after VerifyWitnessProgram, so
    the flag -- policy, off in ALL_FLAGS -- can only fail a pre-segwit
    script; what is consensus about a clean stack lives inside the
    witness execution itself. An OP_SUCCESS spend is the sharpest case:
    it answers before anything runs, leaving the witness stack as it
    came, and that leftover is the upgrade path, a success whatever sits
    under the script. Pinned with the flag on because nothing vendored
    turns it on against a taproot spend: no script_assets case carries
    CLEANSTACK, and the five TAPROOT rows of script_tests.json leave it
    off.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_SUCCESS80", b""], lock_time=0, sequence=1, extra_witness=("",)
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)
    verify_input(prevouts, tx, 0, ALL_FLAGS | ScriptFlag.CLEANSTACK)


def test_unknown_v1_program_passes_cleanstack() -> None:
    """A v1 witness program that is not 32 bytes passes, CLEANSTACK or not.

    Between "version too new" and "p2tr", which hands the witness to the
    taproot arm, sits a third case: a v1 program of the wrong size under
    flags that support v1. Nothing executes -- upgrade room, Core's
    success with no script run -- and the version push the legacy run
    left is not CLEANSTACK's to see, the flag never looking at a witness
    spend. What refuses it is the flag Core refuses it with, below.
    CLEANSTACK is what no vendored vector pairs with a taproot-era
    program: zero rows of script_assets_test.json carry it, and the five
    TAPROOT rows of script_tests.json leave it off.
    """
    prevout = TxOut(1000, ScriptPubKey(serialize(["OP_1", b"\x99" * 20])))
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 1, Witness([]))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    verify_input([prevout], tx, 0, ALL_FLAGS)
    verify_input([prevout], tx, 0, ALL_FLAGS | ScriptFlag.CLEANSTACK)


def test_discourage_reaches_every_upgradable_program() -> None:
    """One branch of Core's, so one flag answers all three shapes.

    A version above the two, a v1 program that is not 32 bytes, and a
    32-byte v1 wrapped in p2sh are the same thing to a node that does
    not know better -- valid, which is what makes them upgrade room --
    and Core refuses all three in the one `else` of
    VerifyWitnessProgram, under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
    Two vendored rows of script_tests.json reach it, both with TAPROOT
    off -- a v2 program and a v1 20-byte one -- so what is pinned here
    is the same three shapes with TAPROOT on, and the p2sh-wrapped one
    at all: no vector wraps a v1 program in p2sh.

    Two shapes stay out of it. A v0 or taproot program spent by a
    caller not enforcing that BIP is the anyone-can-spend its
    script_pub_key makes it, and Core answers success rather than
    discouragement -- BIP141 and BIP341 define those programs, so there
    is nothing left to upgrade. And pay-to-anchor is standard, relayed
    and exempt in Core, which is a arm of its own here too.
    """
    discourage = ALL_FLAGS | ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM

    def spend(script_pub_key: bytes, script_sig: bytes = b"") -> tuple[TxOut, Tx]:
        prevout = TxOut(1000, ScriptPubKey(script_pub_key))
        tx_in = TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 1, Witness([]))
        return prevout, Tx(
            2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False
        )

    # a version above the two
    prevout, tx = spend(serialize(["OP_2", b"\x99" * 32]))
    verify_input([prevout], tx, 0, ALL_FLAGS)
    with pytest.raises(BTClibValueError, match="upgradable witness program"):
        verify_input([prevout], tx, 0, discourage)

    # v1, not 32 bytes
    prevout, tx = spend(serialize(["OP_1", b"\x99" * 20]))
    verify_input([prevout], tx, 0, ALL_FLAGS)
    with pytest.raises(BTClibValueError, match="upgradable witness program"):
        verify_input([prevout], tx, 0, discourage)

    # a 32-byte v1 wrapped in p2sh: the redeem script is the program,
    # the script_sig its single push, so nothing about it is taproot
    redeem_script = serialize(["OP_1", b"\x99" * 32])
    prevout, tx = spend(
        serialize(["OP_HASH160", hash160(redeem_script), "OP_EQUAL"]),
        serialize([redeem_script]),
    )
    verify_input([prevout], tx, 0, ALL_FLAGS)
    with pytest.raises(BTClibValueError, match="upgradable witness program"):
        verify_input([prevout], tx, 0, discourage)

    # and the defined ones, spent without the rules for them: no raise.
    # The v0 one carries a script_sig no BIP141 spend may have, so it
    # also pins that the malleability rule went behind the flag with
    # the verification it belongs to
    prevout, tx = spend(serialize(["OP_1", b"\x99" * 32]))
    verify_input([prevout], tx, 0, discourage & ~ScriptFlag.TAPROOT)
    prevout, tx = spend(serialize(["OP_0", b"\x99" * 32]), serialize([b"\x01"]))
    verify_input([prevout], tx, 0, discourage & ~ScriptFlag.WITNESS)
    with pytest.raises(BTClibValueError, match="non-empty script_sig"):
        verify_input([prevout], tx, 0, discourage)

    # pay-to-anchor: OP_1 and the two bytes 0x4e73, standard since Core
    # 28 and exempt from the discouragement there, so exempt here
    prevout, tx = spend(b"\x51\x02\x4e\x73")
    verify_input([prevout], tx, 0, discourage)


def test_discourage_op_success() -> None:
    """OP_SUCCESSx: valid, and refused by the caller who will not relay it.

    Core's pre-scan answers success at the first OP_SUCCESSx whatever
    else the script holds, and the flag turns that answer into a refusal
    without touching what a block may carry -- which is the whole of
    these three flags (issue #217). No vendored vector names it: the
    eighteen members that had one are all a vector reaches, and
    `script_assets_test.json` carries no flag outside the enum.
    """
    prevouts, tx = taproot_script_spend(["OP_SUCCESS80", b""], lock_time=0, sequence=1)
    verify_input(prevouts, tx, 0, ALL_FLAGS)
    with pytest.raises(BTClibValueError, match="upgradable OP_SUCCESS"):
        verify_input(prevouts, tx, 0, ALL_FLAGS | ScriptFlag.DISCOURAGE_OP_SUCCESS)


def test_discourage_upgradable_pubkey_type() -> None:
    """A tapscript public key neither empty nor 32 bytes, signature or not.

    BIP342 verifies nothing for such a key and OP_CHECKSIG succeeds on
    it, which is the room a future key version has; the flag refuses the
    spend, and it refuses it whichever way the check would have gone --
    Core reaches its `else` before the signature is looked at, so an
    empty signature earns the discouragement rather than the plain false
    it would leave on the stack.
    """
    pub_key = b"\x02" + b"\x99" * 32  # 33 bytes: a key of no tapscript version
    discourage = ALL_FLAGS | ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE

    # a non-empty signature, never verified: OP_CHECKSIG pushes true
    prevouts, tx = taproot_script_spend(
        [pub_key, "OP_CHECKSIG"], lock_time=0, sequence=1, extra_witness=("99" * 64,)
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)
    with pytest.raises(ScriptError, match="upgradable public key type: 33 bytes"):
        verify_input(prevouts, tx, 0, discourage)

    # and an empty one, which fails either way and not for the same reason
    prevouts, tx = taproot_script_spend(
        [pub_key, "OP_CHECKSIG"], lock_time=0, sequence=1, extra_witness=("",)
    )
    with pytest.raises(BTClibValueError, match="false top stack element"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)
    with pytest.raises(ScriptError, match="upgradable public key type: 33 bytes"):
        verify_input(prevouts, tx, 0, discourage)


def test_discourage_upgradable_taproot_version() -> None:
    """A leaf version other than 0xc0: the commitment holds, nothing runs.

    The script is an OP_RETURN, so a spend that reached the interpreter
    could not pass; that it passes under ALL_FLAGS is what says the
    version was answered before the script, and the flag is what turns
    that answer into a refusal.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_RETURN"], lock_time=0, sequence=1, leaf_version=0xC2
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)
    with pytest.raises(BTClibValueError, match="upgradable taproot leaf version 0xc2"):
        verify_input(
            prevouts,
            tx,
            0,
            ALL_FLAGS | ScriptFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        )


def test_p2wsh_codeseparator_spend_is_run() -> None:
    """A v0 script carrying OP_CODESEPARATOR is executed, not waved past.

    The three BIP143 worked examples carrying one are valid spends, so
    they cannot tell a verified verdict from a skipped one; this is the
    invalid twin they lack, and tx_invalid.json has none -- a p2wsh
    script whose OP_CHECKSIG is handed an empty signature, which cannot
    verify, behind a separator that used to make the whole spend exempt.
    """
    # OP_CODESEPARATOR <33 bytes> OP_CHECKSIG, spent with an empty
    # signature: the check pushes false whatever the key, and the script
    # leaves it on the stack
    witness_script = b"\xab\x21" + b"\x02" + b"\x99" * 32 + b"\xac"
    prevout = TxOut(1000, ScriptPubKey(b"\x00\x20" + sha256(witness_script)))
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 1, Witness(["", witness_script.hex()]))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    with pytest.raises(BTClibValueError, match="false top stack element"):
        verify_input([prevout], tx, 0, ALL_FLAGS)


def test_p2wsh_unknown_op_code_is_the_interpreter_s_to_judge() -> None:
    """An op-code byte no table names costs a v0 spend only if it runs.

    Which is Core, and which is what the legacy engine already answered
    everywhere else: `EVALUATED_WHEN_UNEXECUTED` is OP_IF..OP_ENDIF and
    nothing besides, so a byte the tables do not name is refused when
    the interpreter reaches it and skipped inside a branch nothing
    takes. Nothing ahead of the interpreter may answer first: a pass
    that parses the whole witness script strictly refuses the byte
    wherever it sits, and there is no vector to say which verdict is
    Core's.
    """
    for witness_script, ok in (
        (b"\x00\x63\xbb\x68\x51", True),
        (b"\x51\x63\xbb\x68", False),
    ):
        prevout = TxOut(1000, ScriptPubKey(b"\x00\x20" + sha256(witness_script)))
        tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 1, Witness([witness_script.hex()]))
        tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
        if ok:
            verify_input([prevout], tx, 0, ALL_FLAGS)
        else:
            with pytest.raises(ScriptError, match="unknown op code"):
                verify_input([prevout], tx, 0, ALL_FLAGS)


def test_p2wsh_codeseparator_leaves_the_verdict_to_the_script() -> None:
    """Past the separator the interpreter judges, and as itself.

    The spend above earns the mildest verdict there is -- false left on
    the stack, what any script that merely does not verify gets -- and a
    guard reading the result rather than running the script could reach
    it too. These two it could not: an OP_RETURN executed, and a
    conditional left unbalanced, each of them a refusal only a run
    produces, and each behind the OP_CODESEPARATOR that used to answer
    for the whole script (#214).

    The valid script beside them is the other half. Refusing the byte
    outright would satisfy every case above and be the same bug facing
    the other way, which is not hypothetical: the guard did exactly
    that to an unknown op code, wherever it sat.
    """

    def spend(ops: list[str]) -> tuple[TxOut, Tx]:
        witness_script = serialize(ops)
        prevout = TxOut(1000, ScriptPubKey(b"\x00\x20" + sha256(witness_script)))
        tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 1, Witness([witness_script.hex()]))
        return prevout, Tx(
            2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False
        )

    for ops, message in (
        (["OP_CODESEPARATOR", "OP_RETURN"], "OP_RETURN"),
        (["OP_CODESEPARATOR", "OP_ELSE"], "OP_ELSE without OP_IF or OP_NOTIF"),
    ):
        prevout, tx = spend(ops)
        with pytest.raises(ScriptError, match=message):
            verify_input([prevout], tx, 0, ALL_FLAGS)

    prevout, tx = spend(["OP_CODESEPARATOR", "OP_1"])
    verify_input([prevout], tx, 0, ALL_FLAGS)


# nothing about it is secret; the same key sig_hash_legacy_test.py signs
# its wrapped p2pkh with
CODESEP_PRV_KEY = 0x9E5C7B3D5A0F0E4A9F1E3D2C1B0A99887766554433221100FFEEDDCCBBAA9988


def codeseparator_witness_script() -> tuple[bytes, bytes]:
    """Build a p2wsh witness script with two separators, and its code.

    The script code is the second one's, i.e. what a spend executing both
    signs: BIP143 cuts at the last executed OP_CODESEPARATOR and keeps
    the separators left in the slice, of which there are none here.

    Each half carries a non-minimal push -- an OP_PUSHDATA1 of one byte,
    which consensus allows -- so the cut is measurable twice over. The
    one *inside* the script code is what tells a byte slice from a
    re-serialization of a parse, the hazard of #176, and the one outside
    it is what a cut off by one occurrence would take in.
    """
    pub_key = pub_keyinfo_from_prv_key(CODESEP_PRV_KEY)[0]
    non_minimal = bytes.fromhex("4c01ff") + b"\x75"  # the push, then OP_DROP
    before = b"\x51\x75" + b"\xab" + non_minimal + b"\xab"
    script_code = non_minimal + b"\x21" + pub_key + b"\xac"
    return before + script_code, script_code


def p2wsh_codeseparator_spend(
    witness_script: bytes, *, wrapped: bool
) -> tuple[list[TxOut], Tx]:
    """Build the spend of that script, native or wrapped in p2sh, unsigned."""
    program = b"\x00\x20" + sha256(witness_script)
    script_pub_key = program
    script_sig = b""
    if wrapped:
        script_pub_key = serialize(["OP_HASH160", hash160(program), "OP_EQUAL"])
        # the wire form: the push of the redeem script, which is the
        # witness program itself
        script_sig = serialize([program])
    prevout = TxOut(1000, ScriptPubKey(script_pub_key))
    tx_in = TxIn(
        OutPoint(b"\x01" * 32, 0),
        script_sig,
        1,
        Witness(["", witness_script.hex()]),
    )
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    return [prevout], tx


def sign_codeseparator_spend(
    prevouts: list[TxOut], tx: Tx, witness_script: bytes, codesep_index: int
) -> bytes:
    """Sign the input at the given occurrence, and return the sig hash."""
    msg_hash = sig_hash.from_tx(
        prevouts, tx, 0, sig_hash.ALL, codesep_index=codesep_index
    )
    signature = sign_(msg_hash, CODESEP_PRV_KEY).serialize() + b"\x01"
    tx.vin[0].script_witness = Witness([signature.hex(), witness_script.hex()])
    return msg_hash


def test_p2wsh_codeseparator_cut_is_what_the_signature_commits_to() -> None:
    """The invalid twin BIP143's second rule never had (issue #221).

    Its three worked examples are all valid spends of native P2WSH, so
    nothing among them says what a *wrong* cut looks like -- where the
    no-FindAndDelete rule beside it has Core's "wrong sighash with
    FindAndDelete" vectors, which fail when the rule is not applied.

    Hand-rolled, so what it proves is bounded and worth naming: that our
    signer and our verifier agree on where the cut falls, and that a
    signature committing to any other cut is refused. Whether the
    preimage is Core's is what the three appendix vectors and the
    byte-slice property of #176 answer, and an independent oracle
    (#198) is what would settle it.
    """
    witness_script, script_code = codeseparator_witness_script()
    prevouts, tx = p2wsh_codeseparator_spend(witness_script, wrapped=False)

    # the cut is a slice of the script's own bytes, and the script code
    # holds a push no re-serialization of a parse would write back
    msg_hash = sign_codeseparator_spend(prevouts, tx, witness_script, 2)
    assert msg_hash == sig_hash.segwit_v0(
        script_code, tx, 0, sig_hash.ALL, prevouts[0].value
    )
    assert serialize(parse(script_code)) != script_code
    verify_input(prevouts, tx, 0, ALL_FLAGS)

    # the twin: signed at the first occurrence, which is the same cut one
    # push and one separator too early
    sign_codeseparator_spend(prevouts, tx, witness_script, 1)
    with pytest.raises(BTClibValueError, match="false top stack element"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)

    # and the whole script, the cut of a spend executing no separator
    sign_codeseparator_spend(prevouts, tx, witness_script, 0)
    with pytest.raises(BTClibValueError, match="false top stack element"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_wrapped_p2wsh_codeseparator_cuts_the_same_script() -> None:
    """A p2sh wrapper does not move the cut: it is the witness script's.

    All three of BIP143's separator examples are native, so which
    script the code comes out of when there is a redeem script in the
    way is untested. It comes out of the witness script, and the redeem
    script -- the witness program, which a p2wsh spend commits to by
    hashing it into the script_pub_key -- is not in the v0 preimage at
    all: the same witness script signed the same way gives the same hash
    wrapped and native, so the two spends differ in nothing but the
    script_sig that carries the wrapper.
    """
    witness_script, script_code = codeseparator_witness_script()
    prevouts, tx = p2wsh_codeseparator_spend(witness_script, wrapped=True)

    msg_hash = sign_codeseparator_spend(prevouts, tx, witness_script, 2)
    assert msg_hash == sig_hash.segwit_v0(
        script_code, tx, 0, sig_hash.ALL, prevouts[0].value
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)

    native_prevouts, native_tx = p2wsh_codeseparator_spend(
        witness_script, wrapped=False
    )
    assert msg_hash == sign_codeseparator_spend(
        native_prevouts, native_tx, witness_script, 2
    )

    # and the wrong cut is refused through the wrapper too
    sign_codeseparator_spend(prevouts, tx, witness_script, 1)
    with pytest.raises(BTClibValueError, match="false top stack element"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)


@pytest.mark.parametrize(
    "op_code",
    ["OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY"],
)
def test_const_scriptcode_refuses_signature_checks(op_code: str) -> None:
    """CONST_SCRIPTCODE refuses every signature-check op in a script_sig.

    Core watches all four through one rule -- FindAndDelete of the
    signature from the script code, an error on a match under the flag,
    before the signature is read at all -- so the class is one list of
    four names here, and a name missing from it is a rule that does not
    run rather than a rule that fails. Which is what the vectors cannot
    say: they put only OP_CHECKSIG in a script_sig under the flag, so
    three quarters of the list rest on this test alone.
    """
    prevout = TxOut(1000, ScriptPubKey(""))
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), serialize([op_code]), 1, Witness([]))
    tx = Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)
    with pytest.raises(BTClibValueError, match="signature check in the script_sig"):
        verify_input([prevout], tx, 0, ScriptFlag.CONST_SCRIPTCODE)

    # without the flag the same input reaches the interpreter and
    # underflows the empty stack instead: the refusal above is the flag's
    with pytest.raises(BTClibValueError, match="stack underflow"):
        verify_input([prevout], tx, 0, NO_FLAGS)


def test_a_truncated_script_sig_is_not_push_only() -> None:
    """Core's IsPushOnly answers false where GetOp fails, and so does this.

    The parse marks the place a push runs past the end rather than
    refusing the bytes (issue #123), and the walk stops there: the bytes
    it did not consume are not a push, so the script_sig is not
    push-only.
    """
    with pytest.raises(BTClibValueError, match="unreadable push .* at byte 1"):
        validate_push_only(b"\x51\x4c\x05\xaa\xbb")

    # a push and OP_1NEGATE are push-only; an op code is not
    validate_push_only(b"\x01\xff\x4f")
    with pytest.raises(BTClibValueError, match="non-push op code .*: 0xac at byte 2"):
        validate_push_only(b"\x01\xff\xac")


def _one_op_code_script(op_code: int) -> bytes:
    """Build that op code alone, a push carrying the data it declares."""
    if 0 < op_code < 0x4C:  # a push of its own length
        return bytes([op_code]) + b"\x2a" * op_code
    if op_code in {0x4C, 0x4D, 0x4E}:  # OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4
        return (
            bytes([op_code]) + (1).to_bytes(2 ** (op_code - 0x4C), "little") + b"\x2a"
        )
    return bytes([op_code])


def test_push_only_reads_the_op_code_and_not_its_name() -> None:
    """Core's line, over all 256 bytes: OP_16 and below push, above do not.

    The line is a comparison on the byte, and no scan of the parsed
    commands draws it, the names not being the thing compared: the 69
    bytes no op-code table names parse as `UNKNOWN_OP_CODE_n`, which
    carries no `OP_` prefix to refuse, and 0x50 parses as `OP_RESERVED`,
    which carries one where Core, 0x50 being below OP_16, takes it for a
    push. Seventy bytes, wrong in both directions (issue #220).
    """
    named = [op for op in range(0x61, 0x100) if op in OP_CODE_NAME_FROM_INT]
    assert len(named) == 256 - 0x61 - 69  # the other 69 are the unnamed ones
    assert OP_CODE_NAME_FROM_INT[0x50] == "OP_RESERVED"

    for op_code in range(0x100):
        script = _one_op_code_script(op_code)
        if op_code > 0x60:  # OP_16
            with pytest.raises(BTClibValueError, match="non-push op code"):
                validate_push_only(script)
        else:
            validate_push_only(script)


def test_an_unnamed_op_code_in_a_script_sig_is_not_a_push() -> None:
    """SIGPUSHONLY answers for 0xbb, where the interpreter would.

    Core's error is SCRIPT_ERR_SIG_PUSHONLY and it comes before the
    script_sig runs; a byte let through to the interpreter is refused as
    an unknown op code instead, which is the same verdict by the wrong
    rule -- and only until a soft fork names the byte, which is what the
    69 unnamed ones are reserved for.

    OP_RESERVED is the pair of it: push-only now says nothing about it,
    and the interpreter refuses it where Core's does, executing it.
    """
    prevout = TxOut(1000, ScriptPubKey(""))

    def spend_with(script_sig: bytes) -> Tx:
        tx_in = TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 1, Witness([]))
        return Tx(2, 0, [tx_in], [TxOut(1000, ScriptPubKey(""))], check_validity=False)

    tx = spend_with(b"\xbb")
    with pytest.raises(BTClibValueError, match="non-push op code .*: 0xbb"):
        verify_input([prevout], tx, 0, ScriptFlag.SIGPUSHONLY)

    tx = spend_with(b"\x50")
    with pytest.raises(ScriptError, match="unknown op code: OP_RESERVED"):
        verify_input([prevout], tx, 0, ScriptFlag.SIGPUSHONLY)


@pytest.mark.parametrize("skip_execution", [False, True])
def test_read_push_data_measures_before_it_skips(skip_execution: bool) -> None:
    """The interpreter refuses a push it cannot execute, branch or no branch.

    Core's two checks at the top of EvalScript, both before the fExec
    test: a push declaring more bytes than the script holds is
    SCRIPT_ERR_BAD_OPCODE, GetOp having failed on it, and one over
    MAX_SCRIPT_ELEMENT_SIZE is SCRIPT_ERR_PUSH_SIZE. Parametrized over
    the skip because that is the half a check placed after it would
    lose, and Core has a vector for exactly that shape ("520 byte push
    in non-executed IF branch").

    Called directly rather than through verify_script: the push sizes
    below are what `script.parse` refuses on the way in, so a script
    carrying one cannot reach the loop at all yet.
    """
    stack: list[bytes] = []
    args = (stack, skip_execution, NO_FLAGS, serialize)

    # OP_PUSHDATA2 of 521 bytes, all of them present
    over = MAX_SCRIPT_ELEMENT_SIZE + 1
    stream = BytesIO(over.to_bytes(2, "little") + b"\x00" * over)
    err_msg = f"pushdata longer than {MAX_SCRIPT_ELEMENT_SIZE} bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        read_push_data(0x4D, stream, *args)

    # the same push with the limit turned off, which is the tapscript arm
    stream = BytesIO(over.to_bytes(2, "little") + b"\x00" * over)
    read_push_data(0x4D, stream, *args, element_size_limit=None)
    assert stack == ([] if skip_execution else [b"\x00" * over])

    # a push of two bytes with one to read
    with pytest.raises(BTClibValueError, match="pushdata of 2 bytes, 1 in the script"):
        read_push_data(0x02, BytesIO(b"\xff"), *args)

    # and a declared length that is itself cut short
    with pytest.raises(BTClibValueError, match="pushdata length short of 2 bytes"):
        read_push_data(0x4D, BytesIO(b"\x01"), *args)


def test_find_and_delete_reads_op_codes() -> None:
    """A match inside the data of a push is not a match.

    Core's FindAndDelete tests for one only where GetOp has arrived, so a
    signature that a *push* happens to carry is left alone: this script
    is a 34-byte push whose data begins with a 33-byte push of the
    signature, and Core deletes nothing from it. Deleting by
    `bytes.replace` would take the inner copy out, leaving 0x22
    claiming 34 bytes that are no longer there -- a script code that is
    not a script, from a transaction that is perfectly valid.
    """
    signature = bytes(33 * [0xAA])
    pushed = serialize([signature])
    script = bytes([0x22, 0x00]) + pushed + b"\xac"
    assert find_and_delete(script, pushed) == (script, 0)
    assert calculate_script_code(script, 0, [signature], False, False) == script
    # and where the same bytes do begin an op code, they go
    assert find_and_delete(pushed + pushed + b"\xac", pushed) == (b"\xac", 2)


def test_find_and_delete_takes_one_pass() -> None:
    """Deleting cannot make a match that was not there.

    Core walks the script left to right once and never looks at the
    result again; a `bytes.replace` re-run until nothing matches does,
    and takes out a copy that exists only because an earlier deletion
    joined its halves. OP_1 OP_2 stands in for the signature push here
    to lay the halves out in four bytes -- what is under test is the
    walk, and it does not care what it is matching.
    """
    target = b"\x51\x52"  # OP_1 OP_2
    script = b"\x51" + target + b"\x52"
    assert find_and_delete(script, target) == (target, 1)
    # the empty target: Core returns before it can delete forever
    assert find_and_delete(script, b"") == (script, 0)


def test_hash_types_report_every_signature_the_interpreter_checked() -> None:
    """What `verify_input` reports back: three inputs, four hash types.

    A signature and not an input is what makes an entry -- the 2-of-2
    below carries two of them, with a hash type each -- and the list is
    one for the whole transaction, in input order, appended to rather
    than replaced.

    No consensus rule reads it, and the caller that does is one with a
    rule about the hash types themselves: BIP322's "all signatures MUST
    use SIGHASH_ALL" (issue #514). Why such a caller cannot pick the
    signatures out of the witness itself is the third input here -- its
    control block is 65 bytes, exactly the shape of the BIP340
    signature two elements below it.
    """
    keys = [
        0x4242424242424242424242424242424242424242424242424242424242424242,
        0x1111111111111111111111111111111111111111111111111111111111111111,
    ]
    sec_keys = [pub_keyinfo_from_prv_key(key)[0] for key in keys]

    witness_script = serialize(["OP_2", *sec_keys, "OP_2", "OP_CHECKMULTISIG"])
    script_tree: TaprootScriptTree = [(0xC0, [sec_keys[0][1:].hex(), "OP_CHECKSIG"])]
    tap_script, control = input_script_sig(None, script_tree, 0)
    leaf_script = serialize_tapscript(tap_script)
    prevouts = [
        TxOut(1000, ScriptPubKey(b"\x00\x20" + sha256(witness_script))),
        TxOut(1000, ScriptPubKey.p2tr(keys[0])),
        TxOut(
            1000, ScriptPubKey(serialize(["OP_1", output_pubkey(None, script_tree)[0]]))
        ),
    ]
    vin = [TxIn(OutPoint(b"\x01" * 32, i), b"", 1) for i in range(len(prevouts))]
    tx = Tx(2, 0, vin, [TxOut(1000, ScriptPubKey(""))], check_validity=False)

    # the 2-of-2, signed in script order and with a hash type each: the
    # signature is what carries the type, so two signatures of one input
    # can disagree about it and the report has to say so
    multisig_types = [sig_hash.SINGLE, sig_hash.ANYONECANPAY | sig_hash.ALL]
    signatures = [
        sign_(
            sig_hash.segwit_v0(witness_script, tx, 0, hash_type, prevouts[0].value), key
        ).serialize()
        + hash_type.to_bytes(1, "big")
        for key, hash_type in zip(keys, multisig_types, strict=True)
    ]
    tx.vin[0].script_witness = Witness([b"", *signatures, witness_script])

    # the key path, with the type spelled out: 65 bytes, and BIP341
    # refuses the 65th being a zero, which is the DEFAULT below
    msg_hash = sig_hash.taproot(tx, 1, prevouts, sig_hash.NONE, 0, b"", b"")
    key_path_sig = ssa.sign_(msg_hash, output_prvkey(keys[0])).serialize()
    tx.vin[1].script_witness = Witness(
        [key_path_sig + sig_hash.NONE.to_bytes(1, "big")]
    )

    # and the script path, SIGHASH_DEFAULT: 64 bytes, no type byte at
    # all, and the report says 0 for it -- the meaning BIP341 gives the
    # absence rather than a byte read off the stack
    ext = leaf_hash(0xC0, leaf_script) + b"\x00" + (0xFFFFFFFF).to_bytes(4, "little")
    msg_hash = sig_hash.taproot(tx, 2, prevouts, sig_hash.DEFAULT, 1, b"", ext)
    tx.vin[2].script_witness = Witness(
        [ssa.sign_(msg_hash, keys[0]).serialize(), leaf_script, control]
    )

    hash_types: list[int] = []
    verify_transaction(prevouts, tx, ALL_FLAGS, hash_types=hash_types)
    # the two of the multisig come back the other way round, and that is
    # the order the interpreter meets them in rather than a detail of
    # this list: OP_CHECKMULTISIG pops its keys and its signatures off
    # the stack, so it walks both from the last of the script towards
    # the first. Order within an input is worth nothing to a caller for
    # exactly this reason -- what the report answers is which types were
    # used, and by how many signatures
    assert hash_types == [*reversed(multisig_types), sig_hash.NONE, sig_hash.DEFAULT]

    # appended to, not replaced: the caller owns the list, and verifying
    # a second input into it is verifying two inputs into one report
    verify_input(prevouts, tx, 1, ALL_FLAGS, hash_types=hash_types)
    assert hash_types[-1] == sig_hash.NONE
    assert len(hash_types) == 5
