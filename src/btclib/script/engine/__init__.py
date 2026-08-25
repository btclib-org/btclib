# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The script engine: transaction verification against the consensus rules."""

from __future__ import annotations

from btclib.alias import Command, ScriptType
from btclib.exceptions import BTClibValueError
from btclib.hashes import sha256
from btclib.script.engine import tapscript
from btclib.script.engine.flags import (
    ALL_FLAGS,
    NO_FLAGS,
    ScriptFlag,
    ScriptFlags,
    to_script_flags,
)
from btclib.script.engine.script import verify_script as verify_script_legacy
from btclib.script.engine.script_op_codes import _MAX_NUM_SIZE, _to_num
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.script import op_code_spans, parse, serialize
from btclib.script.script_pub_key import is_segwit, type_and_payload
from btclib.script.sig_hash import PrecomputedTxData
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut

# the flags live in flags.py, a module of their own because the three
# modules that check them are imported here and cannot import back; they
# are re-exported so that `from btclib.script.engine import ALL_FLAGS`
# keeps working, and that re-export is what this list is for -- mypy's
# strict mode treats an imported name as private unless __all__ names it.
# The functions defined below are named too -- saving the underscore
# helpers of verify_input, whose names already say it -- __all__ being
# the public surface of the module once it exists and not a second list
# beside it
__all__ = [
    "ALL_FLAGS",
    "NO_FLAGS",
    "PAY_TO_ANCHOR",
    "ScriptFlag",
    "ScriptFlags",
    "taproot_get_annex",
    "taproot_unwrap_script",
    "to_script_flags",
    "validate_push_only",
    "verify_amounts",
    "verify_input",
    "verify_transaction",
]


def taproot_unwrap_script(
    script: bytes, stack: list[bytes]
) -> tuple[bytes, list[bytes], int]:
    """Take a script-path spend apart: (tapscript, stack, leaf version).

    The last two witness elements are the control block and the script,
    per BIP341; the control block must prove the script was committed
    to by the output key, and check_output_pubkey is what verifies that
    merkle proof. Returns the stack without the two, leaving the
    caller's list untouched.
    """
    pub_key = type_and_payload(script)[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError("invalid taproot control block")

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def taproot_get_annex(witness: Witness) -> tuple[bytes, list[bytes]]:
    """Split the annex off a taproot witness stack: (annex, the rest).

    BIP341 makes the annex the last element of a stack of at least two
    whose first byte is 0x50; the empty bytes mean there is none, no
    annex being distinguishable from an empty one by construction.
    """
    # the trimmed stack is returned, never written back: a get_ function must
    # not write, and verifying a transaction must not rewrite it. A list in
    # either branch, the stack being popped by the script interpreter.
    # A slice and not [-1][0], for the reason sig_hash.taproot_annex_and_ext
    # gives: an empty witness element has no first byte, and BIP341 makes
    # the annex the element whose first byte is 0x50. Core's vectors carry
    # the case -- two `spendpath/truncshortcontrol`, whose control block is
    # truncated to nothing -- which indexing would answer with an IndexError
    if len(witness.stack) >= 2 and witness.stack[-1][:1] == b"\x50":
        return witness.stack[-1], list(witness.stack[:-1])
    return b"", list(witness.stack)


def validate_push_only(script_sig: bytes) -> None:
    """Refuse a script_sig that is not push-only: Core's CScript::IsPushOnly.

    The rule the SIGPUSHONLY flag names and BIP16 makes consensus, and
    Core writes it as a walk over the bytes: an op code at or below OP_16
    pushes a value, every byte above it is an operator, and GetOp failing
    ends the walk with a no -- so a script_sig whose last push runs past
    the end is not push-only either, the parse marking that place rather
    than refusing the bytes (issue #123).

    Over the bytes and not over the parsed commands, because a scan of
    the commands can only test the names, and the names do not draw
    Core's line. The 69 bytes above OP_16 that no op-code table names
    parse as `UNKNOWN_OP_CODE_n`, which no test for an `OP_` prefix takes
    for an operator, and `OP_RESERVED` parses as a name where 0x50 is
    below OP_16 and pushes nothing at all -- 70 bytes answered wrongly in
    both directions (issue #220). Walking the bytes asks Core's question
    of every byte, named or not.

    No spend hangs on the difference today: the interpreter refuses every
    unnamed byte the moment it executes one, and putting one where it
    does not execute takes a conditional, which is named and refused
    here. That agreement is a coincidence between two modules, though,
    and a soft fork naming one of those 69 -- which is what they are
    reserved for -- is what ends it.
    """
    consumed = 0
    for op_code, start, stop in op_code_spans(script_sig):
        if op_code > 0x60:  # OP_16
            err_msg = (
                f"non-push op code in the script_sig: {op_code:#04x} at byte {start}"
            )
            raise BTClibValueError(err_msg)
        consumed = stop
    if consumed != len(script_sig):
        raise BTClibValueError(f"unreadable push in the script_sig at byte {consumed}")


# Core's IsPayToAnchor, spelled as the whole script because that is how
# little of it there is: OP_1 followed by the two bytes 0x4e73. An
# ephemeral-anchor output, standard and relayed since Core 28, and the
# one witness program shape that is neither defined by a BIP this engine
# implements nor upgrade room to be discouraged from
PAY_TO_ANCHOR = b"\x51\x02\x4e\x73"


def _check_script_sig_policy(script_sig: bytes, script_flags: ScriptFlag) -> None:
    """Refuse the script_sig shapes SIGPUSHONLY and CONST_SCRIPTCODE ban."""
    if ScriptFlag.SIGPUSHONLY in script_flags:
        validate_push_only(script_sig)
    if ScriptFlag.CONST_SCRIPTCODE in script_flags:
        # the four op codes Core's CONST_SCRIPTCODE watches through
        # FindAndDelete: a signature check carried in the script_sig
        # takes the script_sig as its own script code, which is exactly
        # where its signatures sit. Refused up front and as a class,
        # wherever it sits and whether or not it executes, which is
        # stricter than Core in one direction and short in another.
        # Stricter: Core's error is inside the executed branch. Short:
        # the in-loop rule closes nothing else, `op_checksig` returning
        # early on an empty signature, on a lax encoding under no
        # strict-DER flag and on a bad public key under no STRICTENC,
        # all before it builds a script code to delete from -- where
        # Core deletes and errors before reading the signature at all.
        # So a script_pub_key of that shape keeps the gap this closes
        # for the script_sig
        op_checks = (
            "OP_CHECKSIG",
            "OP_CHECKSIGVERIFY",
            "OP_CHECKMULTISIG",
            "OP_CHECKMULTISIGVERIFY",
        )
        # parsed here and only here: the push-only walk above reads the
        # bytes, so under no flag but this one is a parse of the
        # script_sig needed at all
        for x in parse(script_sig):
            if x in op_checks:
                raise BTClibValueError(f"signature check in the script_sig: {x}")


def _verify_taproot(
    script: bytes,
    witness: Witness,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
    hash_types: list[int] | None,
) -> None:
    """Verify a p2tr spend: the v1 arm of Core's VerifyWitnessProgram.

    One witness element is the key path, more are a script path. What a
    spend leaves on its stack stays here: an executed script path
    enforces its own end-of-script rules, and an OP_SUCCESS leftover is
    the upgrade path, which Core answers with success and no questions.
    """
    budget = 50 + len(witness.serialize())
    # the annex counts towards the budget, hence the order (BIP342)
    annex, stack = taproot_get_annex(witness)
    if len(stack) == 0:
        raise BTClibValueError("empty taproot witness stack")
    if len(stack) == 1:
        tapscript.verify_key_path(
            script, stack, prevouts, tx, i, annex, precomputed, hash_types
        )
        return
    script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
    if leaf_version != 0xC0:
        # an unknown leaf version passes validation, the control block
        # having committed to the script whatever the version says about
        # how to run it: BIP342's upgrade room, and refused only where
        # the caller says it does not want to relay one
        if ScriptFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION in script_flags:
            raise BTClibValueError(f"upgradable taproot leaf version {leaf_version:#x}")
        return
    tapscript.verify_script_path_vc0(
        script_bytes,
        stack,
        prevouts,
        tx,
        i,
        annex,
        budget,
        script_flags,
        precomputed,
        hash_types,
    )


def _verify_witness_v0(
    script_type: ScriptType,
    payload: bytes,
    witness: Witness,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
    hash_types: list[int] | None,
) -> None:
    """Verify a v0 spend: the v0 arm of Core's VerifyWitnessProgram.

    The script is rebuilt from the program -- p2wpkh names it, p2wsh
    carries it as the last witness element -- and runs against the rest
    of the witness stack. The one-element rule at the end is BIP141
    consensus, not the CLEANSTACK flag: it lives here as Core's lives in
    ExecuteWitnessScript, whatever the caller's flags say.
    """
    # a list of its own: the interpreter pops what it consumes, and the
    # witness stack is an immutable tuple anyway
    stack = list(witness.stack)
    if script_type == "p2wpkh":
        # serialization of p2wpkh:
        # OP_DUP OP_HASH160 payload OP_EQUALVERIFY OP_CHECKSIG
        script = b"v\xa9\x14" + payload + b"\x88\xac"
    elif script_type == "p2wsh":
        # the witness script is the last element, and there is none:
        # Core's WITNESS_PROGRAM_WITNESS_EMPTY, and the guard the taproot
        # arm already has. Without it the empty stack is an IndexError
        # out of `stack[-1]`, i.e. malformed input leaving through
        # something other than BTClibValueError
        if not stack:
            raise BTClibValueError("empty p2wsh witness stack")
        if any(len(x) > MAX_SCRIPT_ELEMENT_SIZE for x in stack[:-1]):
            err_msg = (
                f"witness stack element longer than {MAX_SCRIPT_ELEMENT_SIZE} bytes"
            )
            raise BTClibValueError(err_msg)
        script = stack[-1]
        if payload != sha256(script):
            raise BTClibValueError("invalid witness script sha256")
        stack = stack[:-1]
    else:
        raise BTClibValueError(f"invalid segwit v0 script type: {script_type}")

    verify_script_legacy(
        script,
        stack,
        prevouts[i].value,
        tx,
        i,
        script_flags,
        True,
        True,
        precomputed,
        hash_types,
    )
    # final above popped the one element the script must leave, so any
    # residue is Core's stack.size() != 1
    if stack:
        raise BTClibValueError(f"{len(stack)} elements left on the stack")


def _verify_witness_program(
    script: bytes,
    script_type: ScriptType,
    payload: bytes,
    segwit_version: int,
    p2sh: bool,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
    hash_types: list[int] | None,
) -> None:
    """Dispatch a witness program: Core's VerifyWitnessProgram.

    BIP141 and BIP341 each brought an arm, and this is Core's chain of
    them: v0 of a known size, then the non-p2sh 32-byte v1, then
    everything else -- every other version, size and p2sh combination
    together, which is upgrade room and passes unless the caller asks
    to be discouraged from spending it. Nothing comes back: a witness
    spend leaves nothing for the caller's CLEANSTACK check, which is
    Core resizing the stack to one element behind this function, and
    each arm owns the end-of-stack rule its BIP makes consensus.
    """
    if ScriptFlag.WITNESS not in script_flags:
        # Core reaches its VerifyWitnessProgram only under the flag, and
        # the discouragement below lives inside it: to a caller not
        # enforcing BIP141 a witness program is the anyone-can-spend its
        # script_pub_key alone makes it, upgradable or not
        return

    if segwit_version == 0:
        # a v0 program of any other size raises in there, Core's
        # WITNESS_PROGRAM_WRONG_LENGTH: v0 is defined, so a size it does
        # not define is an error rather than upgrade room
        _verify_witness_v0(
            script_type,
            payload,
            tx.vin[i].script_witness,
            prevouts,
            tx,
            i,
            script_flags,
            precomputed,
            hash_types,
        )
        return

    if segwit_version == 1 and script_type == "p2tr" and not p2sh:
        # taproot is defined too, so a caller not enforcing it gets the
        # anyone-can-spend and not the discouragement: Core answers
        # success here rather than falling to the branch below
        if ScriptFlag.TAPROOT in script_flags:
            _verify_taproot(
                script,
                tx.vin[i].script_witness,
                prevouts,
                tx,
                i,
                script_flags,
                precomputed,
                hash_types,
            )
        return

    if not p2sh and script == PAY_TO_ANCHOR:
        # Core's arm before the else, and the reason it is not in the
        # one below: the shape is standard and relayed, so a caller
        # asking to be discouraged from an upgradable program must not
        # be discouraged from this one
        return

    # Core's final else, and it is one branch on purpose: a version
    # above the two, a v1 program that is not 32 bytes, and a 32-byte v1
    # wrapped in p2sh are the same answer -- valid to a node that does
    # not know better, which is what makes them upgrade room, and
    # refused only where the caller says it does not want to relay one
    if ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in script_flags:
        raise BTClibValueError(f"upgradable witness program: version {segwit_version}")


def verify_input(
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    flags: ScriptFlags | None = None,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> None:
    """Verify one input of a transaction against the output it spends.

    `flags` are the rules to enforce, as a ScriptFlag or as the names of
    one: `None` is btclib's default set, ALL_FLAGS, and an unknown name is
    refused rather than ignored (issue #145). A default that says "the
    consensus rules" is what an outside caller wants, and it matches
    verify_transaction's.

    `precomputed` is the transaction-wide part of the segwit sig_hashes,
    which `verify_transaction` builds once for its whole loop; verifying a
    single input has nothing to share it with, so it defaults to None and
    each sig_hash computes what it needs (issue #164).

    `hash_types` is the list the interpreter reports into: the hash type
    of every stack element it consumed as a signature, in the order it
    met them, appended to whatever the caller passed. Which elements
    those were is what an outside caller cannot work out on its own --
    the control block of a single-leaf taproot tree is 65 bytes, exactly
    the shape of a BIP340 signature with an explicit hash type, and a
    data push in a script-path witness can be anything at all -- so a
    rule about the hash types themselves has to be enforced from here or
    guessed at. `None`, the default, collects nothing: consensus has no
    such rule, and BIP322's "all signatures MUST use SIGHASH_ALL" is the
    caller that has one (issue #514).

    The split is Core's: this function is VerifyScript -- the two legacy
    runs on one stack, the p2sh unwrap, the malleation checks, the
    CLEANSTACK check -- and the witness arms live behind
    ``_verify_witness_program``, as they live behind Core's
    VerifyWitnessProgram.
    """
    script_flags = to_script_flags(flags)
    script_sig = tx.vin[i].script_sig
    _check_script_sig_policy(script_sig, script_flags)

    stack: list[bytes] = []
    verify_script_legacy(
        script_sig,
        stack,
        prevouts[i].value,
        tx,
        i,
        script_flags,
        False,
        False,
        hash_types=hash_types,
    )
    p2sh_script = stack[-1] if stack else b"\x00"

    script = prevouts[i].script_pub_key.script
    verify_script_legacy(
        script,
        stack,
        prevouts[i].value,
        tx,
        i,
        script_flags,
        False,
        True,
        hash_types=hash_types,
    )

    script_type, payload = type_and_payload(script)

    p2sh = False
    if script_type == "p2sh" and ScriptFlag.P2SH in script_flags:
        p2sh = True
        validate_push_only(script_sig)  # BIP16 makes SIGPUSHONLY consensus here
        script = p2sh_script
        verify_script_legacy(
            script,
            stack,
            prevouts[i].value,
            tx,
            i,
            script_flags,
            False,
            True,
            hash_types=hash_types,
        )
        script_type, payload = type_and_payload(script)

    # NO_FLAGS: this reads the version out of a witness program, it does
    # not execute a script, and MINIMALDATA is the only flag _to_num looks
    # at
    segwit_version = (
        _to_num(stack[-1], NO_FLAGS, _MAX_NUM_SIZE) if is_segwit(script) else -1
    )
    # both under the flag, where Core keeps them: they are the
    # malleability rules BIP141 came with, so a caller not enforcing
    # BIP141 is not owed them and reads the script_pub_key alone
    if ScriptFlag.WITNESS in script_flags:
        if segwit_version + 1 and tx.vin[i].script_sig and not p2sh:
            raise BTClibValueError("non-empty script_sig for a native segwit input")
        if not (segwit_version + 1) and tx.vin[i].script_witness:
            raise BTClibValueError("witness for a non-segwit input")

    if segwit_version + 1:
        _verify_witness_program(
            script,
            script_type,
            payload,
            segwit_version,
            p2sh,
            prevouts,
            tx,
            i,
            script_flags,
            precomputed,
            hash_types,
        )
        # Core's stack.resize(1) after VerifyWitnessProgram: a witness
        # spend leaves nothing for CLEANSTACK to see, and v0's own
        # one-element rule lives in its arm, as Core's lives in
        # ExecuteWitnessScript
        return

    if stack and ScriptFlag.CLEANSTACK in script_flags:
        raise BTClibValueError(f"{len(stack)} elements left on the stack")


def verify_amounts(prevouts: list[TxOut], tx: Tx) -> None:
    """Refuse a transaction whose outputs exceed the outputs it spends.

    The difference is the fee, and a negative fee is money printed;
    script validation never reads the amounts except through the
    sig_hash, so this is a check of its own rather than a flag.
    """
    if sum(x.value for x in tx.vout) > sum(x.value for x in prevouts):
        raise BTClibValueError("Invalid transaction amounts")


def verify_transaction(
    prevouts: list[TxOut],
    tx: Tx,
    flags: ScriptFlags | None = None,
    check_amounts: bool = True,
    hash_types: list[int] | None = None,
) -> None:
    """Verify every input of a transaction against the outputs it spends.

    `flags` is what verify_input takes, converted once here rather than
    once per input; `hash_types` is what verify_input reports into, one
    list for the whole transaction, so the inputs' signatures arrive in
    it in input order.
    """
    script_flags = to_script_flags(flags)
    if len(prevouts) != len(tx.vin):
        raise BTClibValueError(
            f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
        )
    if check_amounts:
        verify_amounts(prevouts, tx)
    # once for the whole loop, this function owning it and holding the
    # transaction still for its duration: it is what every input's segwit
    # sig_hash commits to, and rebuilding it per input makes verifying a
    # transaction Θ(N²) in the number of inputs (issue #164). Built
    # unconditionally, being O(N) against the Θ(N²) it removes: a predicate
    # for "has a segwit input" would have to repeat verify_input's own
    # dispatch, p2sh-wrapped cases and all, and would silently restore the
    # quadratic the day the two disagreed
    precomputed = PrecomputedTxData(tx, prevouts)
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, script_flags, precomputed, hash_types)
