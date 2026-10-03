# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The tapscript interpreter loop of the script engine, per BIP342."""

from __future__ import annotations

from collections.abc import Mapping

from btclib_ecc.curves import is_libsecp256k1_serving
from btclib_ecc.ecc import ssa
from btclib_ecc.exceptions import BTClibEccValueError

from btclib.exceptions import BTClibValueError, ScriptError, ScriptErrorCode
from btclib.script.engine import script_op_codes
from btclib.script.engine.flags import ScriptFlag
from btclib.script.engine.script import (
    EVALUATED_WHEN_UNEXECUTED,
    VERIFY_CODES,
    _assert_bytes_arguments,
)
from btclib.script.engine.script_op_codes import (
    _MAX_NUM_SIZE,
    ConditionStack,
    ScriptOp,
    _assert_operands,
    _to_num,
)
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.op_codes_tapscript import OP_CODE_NAMES, OP_SUCCESS
from btclib.script.script import op_code_spans
from btclib.script.script_pub_key import type_and_payload
from btclib.script.sig_hash import PrecomputedTxData, _taproot, _TaprootInputHashes

# the bindings, imported from their own package; None where they are not
# installed, which nothing calls: what calls them here is behind
# `is_libsecp256k1_serving`, False in that configuration. Installed one
# name short, this import alone falls back to None while btclib_ecc
# keeps serving, so the call fails rather than degrading: the floor the
# `secp256k1` extra puts on the bindings is what rules that out
try:
    from btclib_secp256k1.ssa import verify as _libsecp256k1_ssa_verify
except ImportError:  # pragma: no cover -- only an install without them
    _libsecp256k1_ssa_verify = None  # type: ignore[assignment]
from btclib.script.taproot import leaf_hash
from btclib.script.taproot import serialize as serialize_script
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytesio_from_binarydata, encode_num

__all__ = [
    "OPERATIONS",
    "get_hashtype",
    "op_checksig",
    "op_checksigadd",
    "ssa_verify",
    "verify_key_path",
    "verify_script_path_vc0",
]


def ssa_verify(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """Verify a BIP340 signature, returning False if it is malformed.

    The dispatch `engine.script.dsa_verify` makes and for its reason:
    `btclib_ecc.ecc.ssa` answers the same question in Python, and the arm is
    what there is to reach with libsecp256k1 out of reach. No hybrid prefix to
    ask for here -- an x-only key is 32 bytes and BIP340 says which of
    the two points it is -- so the arm is the prepared spelling alone.

    The bindings raise a ValueError on a signature or x-only public key
    that libsecp256k1 refuses to parse, and `ssa.verify_` answers False
    for the same; the caller treats either as a failed verification and
    raises Core's SCHNORR_SIG itself.

    `bytes` and nothing wider, as in `engine.script.dsa_verify` and for
    its reason.
    """
    _assert_bytes_arguments(msg_hash=msg_hash, pub_key=pub_key, sig=sig)

    try:
        if is_libsecp256k1_serving():
            return bool(_libsecp256k1_ssa_verify(msg_hash, pub_key, sig))
        return ssa.verify_(msg_hash, pub_key, sig)
    except ValueError:
        return False


def get_hashtype(signature: bytes) -> int:
    """Read the sighash type off a taproot signature, per BIP341.

    A 64-byte signature is SIGHASH_DEFAULT; a 65th byte carries the
    type and must not spell the default explicitly, the two encodings
    of one meaning being a malleability. Any other size is no BIP340
    signature at all, Core's SCHNORR_SIG_SIZE, and is refused before a
    type is read off it.
    """
    if len(signature) not in (64, 65):
        err_msg = f"taproot signature of {len(signature)} bytes"
        raise ScriptError(err_msg, ScriptErrorCode.SCHNORR_SIG_SIZE)
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise ScriptError(
                "explicit SIGHASH_DEFAULT: a 64-byte signature is required",
                ScriptErrorCode.SCHNORR_SIG_HASHTYPE,
            )
    return sighash_type


def _check_schnorr_signature(
    signature: bytes,
    pub_key: bytes,
    tx: Tx,
    i: int,
    prevouts: list[TxOut],
    ext_flag: int,
    annex: bytes,
    ext: bytes,
    precomputed: PrecomputedTxData | None,
    hash_types: list[int] | None,
    input_hashes: _TaprootInputHashes | None,
) -> None:
    """Refuse a BIP340 signature: Core's CheckSchnorrSignature.

    The size and the explicit default are get_hashtype's; a hash type
    the sig_hash refuses -- one BIP341 does not define, SIGHASH_SINGLE
    with no output at the input's index -- is SCHNORR_SIG_HASHTYPE, as
    Core's SignatureHashSchnorr failing is, and a signature that does
    not verify is SCHNORR_SIG.
    """
    sighash_type = get_hashtype(signature)
    if hash_types is not None:
        hash_types.append(sighash_type)
    try:
        msg_hash = _taproot(
            tx,
            i,
            prevouts,
            sighash_type,
            ext_flag,
            annex,
            ext,
            precomputed,
            input_hashes or _TaprootInputHashes(),
        )
    except BTClibValueError as e:
        raise ScriptError(str(e), ScriptErrorCode.SCHNORR_SIG_HASHTYPE) from e
    if not ssa_verify(msg_hash, pub_key, signature[:64]):
        path = "script" if ext_flag else "key"
        err_msg = f"invalid signature for the taproot {path} path"
        raise ScriptError(err_msg, ScriptErrorCode.SCHNORR_SIG)


def verify_key_path(
    script_pub_key: bytes,
    stack: list[bytes],
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> None:
    """Verify a taproot key-path spend, per BIP341.

    The single witness element is a BIP340 signature by the output key
    itself over the taproot sig_hash with no script committed to, and
    `_check_schnorr_signature` has the refusals.

    `hash_types` is `verify_input`'s collector; the one element of the
    stack is the one signature to report.
    """
    pub_key = type_and_payload(script_pub_key)[1]
    _check_schnorr_signature(
        stack[0],
        pub_key,
        tx,
        i,
        prevouts,
        0,
        annex,
        b"",
        precomputed,
        hash_types,
        None,
    )


def op_checksig(
    stack: list[bytes],
    tapleaf_hash: bytes,
    codesep_pos: int,
    tx: Tx,
    i: int,
    prevouts: list[TxOut],
    annex: bytes,
    budget: int,
    flags: ScriptFlag,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
    input_hashes: _TaprootInputHashes | None = None,
) -> int:
    """Verify one BIP340 signature in a script path: BIP342's OP_CHECKSIG.

    Pops public key and signature, pushes the result, and returns what
    is left of the sigops budget, every non-empty signature costing 50
    whether or not it verifies. The refusals are BIP342's, in the order
    of Core's EvalChecksigTapscript: an exhausted budget, an empty
    public key, and a non-empty signature that does not verify -- where
    the legacy op code pushes False, tapscript fails the script, its
    NULLFAIL being consensus. A key neither empty nor 32 bytes verifies
    nothing and succeeds, which is the upgrade room, refused only under
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE. The message hash commits to
    `tapleaf_hash` and to the last executed OP_CODESEPARATOR, through the
    BIP341 extension.

    `hash_types` is `verify_input`'s collector, appended to where the
    hash type is read: an empty signature is not one, and neither is
    anything popped beside a public key BIP342 left upgradable.
    """
    pub_key = stack.pop()
    signature = stack.pop()
    if signature:
        budget -= 50
        if budget < 0:
            err_msg = "exhausted sigops budget"
            raise ScriptError(err_msg, ScriptErrorCode.TAPSCRIPT_VALIDATION_WEIGHT)
    if len(pub_key) == 0:
        raise ScriptError("empty public key", ScriptErrorCode.TAPSCRIPT_EMPTY_PUBKEY)
    if len(pub_key) == 32:
        if signature:
            ext = tapleaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
            _check_schnorr_signature(
                signature,
                pub_key,
                tx,
                i,
                prevouts,
                1,
                annex,
                ext,
                precomputed,
                hash_types,
                input_hashes,
            )
    # a key neither empty nor 32 bytes is a public key version BIP342 left
    # to a future soft fork: nothing is verified and the check succeeds,
    # which is the upgrade room, and the sigops budget was charged above
    # because Core charges it for a passing upgradable key too
    elif ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE in flags:
        err_msg = f"upgradable public key type: {len(pub_key)} bytes"
        raise ScriptError(err_msg, ScriptErrorCode.DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
    stack.append(encode_num(int(bool(signature))))
    return budget


def op_checksigadd(
    stack: list[bytes],
    tapleaf_hash: bytes,
    codesep_pos: int,
    tx: Tx,
    i: int,
    prevouts: list[TxOut],
    annex: bytes,
    budget: int,
    flags: ScriptFlag,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
    input_hashes: _TaprootInputHashes | None = None,
) -> int:
    """Run BIP342's OP_CHECKSIGADD as one op code, as Core's EvalScript does.

    Pops signature, n and public key, and pushes n plus the result of
    `op_checksig` on the signature and key. Returns what is left of the
    sigops budget.

    The number is read first, as Core builds it before the check: a bad
    one is SCRIPTNUM whatever the signature and key would answer.
    """
    _assert_operands(stack, 3, "OP_CHECKSIGADD")
    n = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    del stack[-2]
    budget = op_checksig(
        stack,
        tapleaf_hash,
        codesep_pos,
        tx,
        i,
        prevouts,
        annex,
        budget,
        flags,
        precomputed,
        hash_types,
        input_hashes,
    )
    stack.append(encode_num(n + (1 if stack.pop() else 0)))
    return budget


# the op codes that take the stack alone. Module-level because the loop
# reads it and never writes -- Mapping is what says so -- and a copy per
# call buys nothing
OPERATIONS: Mapping[str, ScriptOp] = {
    "OP_DUP": script_op_codes.op_dup,
    "OP_2DUP": script_op_codes.op_2dup,
    "OP_DROP": script_op_codes.op_drop,
    "OP_2DROP": script_op_codes.op_2drop,
    "OP_SWAP": script_op_codes.op_swap,
    "OP_1NEGATE": script_op_codes.op_1negate,
    "OP_VERIFY": script_op_codes.op_verify,
    "OP_EQUAL": script_op_codes.op_equal,
    "OP_RETURN": script_op_codes.op_return,
    "OP_SIZE": script_op_codes.op_size,
    "OP_RIPEMD160": script_op_codes.op_ripemd160,
    "OP_SHA1": script_op_codes.op_sha1,
    "OP_SHA256": script_op_codes.op_sha256,
    "OP_HASH160": script_op_codes.op_hash160,
    "OP_HASH256": script_op_codes.op_hash256,
    "OP_1ADD": script_op_codes.op_1add,
    "OP_1SUB": script_op_codes.op_1sub,
    "OP_NEGATE": script_op_codes.op_negate,
    "OP_ABS": script_op_codes.op_abs,
    "OP_NOT": script_op_codes.op_not,
    "OP_0NOTEQUAL": script_op_codes.op_0notequal,
    "OP_ADD": script_op_codes.op_add,
    "OP_SUB": script_op_codes.op_sub,
    "OP_BOOLAND": script_op_codes.op_booland,
    "OP_BOOLOR": script_op_codes.op_boolor,
    "OP_NUMEQUAL": script_op_codes.op_numequal,
    "OP_NUMNOTEQUAL": script_op_codes.op_numnotequal,
    "OP_LESSTHAN": script_op_codes.op_lessthan,
    "OP_GREATERTHAN": script_op_codes.op_greaterthan,
    "OP_LESSTHANOREQUAL": script_op_codes.op_lessthanorequal,
    "OP_GREATERTHANOREQUAL": script_op_codes.op_greaterthanorequal,
    "OP_MIN": script_op_codes.op_min,
    "OP_MAX": script_op_codes.op_max,
    "OP_WITHIN": script_op_codes.op_within,
    "OP_TOALTSTACK": script_op_codes.op_toaltstack,
    "OP_FROMALTSTACK": script_op_codes.op_fromaltstack,
    "OP_IFDUP": script_op_codes.op_ifdup,
    "OP_DEPTH": script_op_codes.op_depth,
    "OP_NIP": script_op_codes.op_nip,
    "OP_OVER": script_op_codes.op_over,
    "OP_PICK": script_op_codes.op_pick,
    "OP_ROLL": script_op_codes.op_roll,
    "OP_ROT": script_op_codes.op_rot,
    "OP_TUCK": script_op_codes.op_tuck,
    "OP_3DUP": script_op_codes.op_3dup,
    "OP_2OVER": script_op_codes.op_2over,
    "OP_2ROT": script_op_codes.op_2rot,
    "OP_2SWAP": script_op_codes.op_2swap,
}


# what the OPERATIONS table cannot hold, read against Core's tapscript
# rules: the op codes needing the engine's own state, the sigops budget
# among it
def _run_ops(  # noqa: C901, PLR0912
    script_bytes: bytes,
    stack: list[bytes],
    altstack: list[bytes],
    condition_stack: ConditionStack,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
    sigops_budget: int,
    flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
    script_index_ref: list[int],
    hash_types: list[int] | None,
) -> None:
    """Run verify_script_path_vc0's opcode dispatch loop.

    Split out of verify_script_path_vc0 so that the try/except reporting
    where a refusal happened wraps one call rather than the loop --
    script.py's `_run_ops` for the reasoning, shared rather than
    repeated. `script_index_ref` is how the failing index still reaches
    that except: set at the top of every iteration, before anything the
    iteration does that could raise.
    """
    codesep_pos = 0xFFFFFFFF
    script_index = -1
    s = bytesio_from_binarydata(script_bytes)
    # once per leaf, as Core's m_tapleaf_hash: every signature commits to it
    tapleaf_hash = leaf_hash(0xC0, script_bytes)
    input_hashes = _TaprootInputHashes()
    while True:
        script_index += 1
        script_index_ref[0] = script_index

        skip_execution = not condition_stack.is_executing

        script_op_codes.assert_stack_size(stack, altstack)

        b = s.read(1)
        if not b:
            break
        t = b[0]
        if 0 < t <= 78:  # pushdata
            script_op_codes.read_push_data(
                t, s, stack, skip_execution, flags, serialize_script
            )
            continue
        if skip_execution and t not in EVALUATED_WHEN_UNEXECUTED:
            continue
        if t not in OP_CODE_NAMES:
            # OP_INVALIDOPCODE, the one byte neither named nor an
            # OP_SUCCESSx, which the pre-scan leaves to the loop as Core's
            # does: BAD_OPCODE where it executes, nothing where it does not
            script_op_codes.unknown_op_code(f"{t:#04x}")
        op = OP_CODE_NAMES[t]
        # Core runs OP_EQUALVERIFY and its kind as one op code, which is
        # the plain one followed by the test of its result
        verify_code = VERIFY_CODES.get(op)
        plain = op.removesuffix("VERIFY") if verify_code else op

        if plain == "OP_CHECKSIG":
            sigops_budget = op_checksig(
                stack,
                tapleaf_hash,
                codesep_pos,
                tx,
                i,
                prevouts,
                annex,
                sigops_budget,
                flags,
                precomputed,
                hash_types,
                input_hashes,
            )

        elif op == "OP_CHECKSIGADD":
            sigops_budget = op_checksigadd(
                stack,
                tapleaf_hash,
                codesep_pos,
                tx,
                i,
                prevouts,
                annex,
                sigops_budget,
                flags,
                precomputed,
                hash_types,
                input_hashes,
            )
        elif op == "OP_CHECKLOCKTIMEVERIFY":
            script_op_codes.op_checklocktimeverify(stack, tx, i, flags)
        elif op == "OP_CHECKSEQUENCEVERIFY":
            script_op_codes.op_checksequenceverify(stack, tx, i, flags)
        elif op[3:].isdigit():
            stack.append(encode_num(int(op[3:])))
        elif op == "OP_CODESEPARATOR":
            codesep_pos = script_index
        elif op == "OP_IF":
            script_op_codes.op_if(stack, condition_stack, flags, 1)
        elif op == "OP_NOTIF":
            script_op_codes.op_notif(stack, condition_stack, flags, 1)
        elif op == "OP_ELSE":
            script_op_codes.op_else(condition_stack)
        elif op == "OP_ENDIF":
            script_op_codes.op_endif(condition_stack)
        elif op == "OP_NOP":
            pass
        elif "OP_NOP" in op:
            script_op_codes.op_nop(flags)
        elif op == "OP_VERIFY":
            script_op_codes.op_verify(stack, altstack, flags)
        elif plain in OPERATIONS:
            OPERATIONS[plain](stack, altstack, flags)
        elif op in {"OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY"}:
            # named, and refused under a code of their own: BIP342 took
            # them out for OP_CHECKSIGADD
            err_msg = f"{op} in a tapscript"
            raise ScriptError(err_msg, ScriptErrorCode.TAPSCRIPT_CHECKMULTISIG)
        else:
            script_op_codes.unknown_op_code(op)

        if verify_code is not None:
            script_op_codes.op_verify(stack, altstack, flags, verify_code)


def _has_op_success(script_bytes: bytes) -> bool:
    """Answer whether the script holds an OP_SUCCESSx: Core's pre-scan.

    ExecuteWitnessScript walks the script with GetOp before it runs any
    of it, and answers at the first OP_SUCCESSx; a push running past the
    end met before one is BAD_OPCODE. Nothing else is asked: an oversized
    push and an unnamed op code are the interpreter's to refuse, at the
    place they sit, so a fault met before either is that fault's code.
    """
    consumed = 0
    for op_code, _, stop in op_code_spans(script_bytes):
        if op_code in OP_SUCCESS:
            return True
        consumed = stop
    if consumed != len(script_bytes):
        err_msg = f"push running past the end of the tapscript at byte {consumed}"
        raise ScriptError(err_msg, ScriptErrorCode.BAD_OPCODE)
    return False


def verify_script_path_vc0(
    script_bytes: bytes,
    stack: list[bytes],
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
    sigops_budget: int,
    flags: ScriptFlag,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> None:
    """Execute a leaf-version-0xc0 tapscript, per BIP342.

    The loop is the legacy engine's with BIP342's differences: no op
    code count and no script size limit, a sigops budget spent by
    signature instead, an OP_SUCCESSx that ends validation with
    success before anything runs, MINIMALIF as consensus, and the
    CHECKMULTISIGs gone in favour of OP_CHECKSIGADD. Refusals leave as
    ScriptError, as they do from the legacy loop, and the script must
    end with exactly one true element on the stack. The checks before
    and after the loop are Core's ExecuteWitnessScript, in its order.

    `hash_types` is `verify_input`'s collector, threaded to
    `op_checksig` as the legacy loop threads it to its own.
    """
    if _has_op_success(script_bytes):
        # the op code BIP342 reserved for a future soft fork, and until
        # then a spend of anything it appears in: refused only where the
        # caller says it does not want to relay one
        if ScriptFlag.DISCOURAGE_OP_SUCCESS in flags:
            err_msg = "upgradable OP_SUCCESS op code"
            raise ScriptError(err_msg, ScriptErrorCode.DISCOURAGE_OP_SUCCESS)
        return

    script_op_codes.assert_stack_size(stack, [])
    if any(len(x) > MAX_SCRIPT_ELEMENT_SIZE for x in stack):
        err_msg = f"witness stack element longer than {MAX_SCRIPT_ELEMENT_SIZE} bytes"
        raise ScriptError(err_msg, ScriptErrorCode.PUSH_SIZE)

    altstack: list[bytes] = []
    condition_stack = ConditionStack()

    script_index_ref = [-1]
    try:
        _run_ops(
            script_bytes,
            stack,
            altstack,
            condition_stack,
            prevouts,
            tx,
            i,
            annex,
            sigops_budget,
            flags,
            precomputed,
            script_index_ref,
            hash_types,
        )
    # the three arms are script.py's verify_script's, and so is the reason
    except ScriptError as e:
        raise ScriptError(e.args[0], e.code, script_index_ref[0], len(stack)) from e
    except (BTClibValueError, BTClibEccValueError) as e:
        code = ScriptErrorCode.UNKNOWN_ERROR
        raise ScriptError(str(e), code, script_index_ref[0], len(stack)) from e
    except IndexError as e:
        code = ScriptErrorCode.INVALID_STACK_OPERATION
        raise ScriptError(
            "stack underflow", code, script_index_ref[0], len(stack)
        ) from e

    script_op_codes.assert_balanced_if(condition_stack)

    # BIP342's one true element, and the size first: Core's order, so an
    # empty stack is CLEANSTACK and not EVAL_FALSE
    if len(stack) != 1:
        err_msg = f"{len(stack)} elements left on the stack"
        raise ScriptError(err_msg, ScriptErrorCode.CLEANSTACK)
    script_op_codes.op_verify(stack, [], flags, ScriptErrorCode.EVAL_FALSE)
