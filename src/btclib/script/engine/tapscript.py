# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The tapscript interpreter loop of the script engine, per BIP342."""

from __future__ import annotations

from collections.abc import Mapping

from btclib import var_bytes
from btclib._libsecp256k1 import ssa_verify as _libsecp256k1_ssa_verify
from btclib.alias import ScriptList
from btclib.curves import secp256k1
from btclib.curves.curve import _libsecp256k1_serves
from btclib.ecc import ssa
from btclib.exceptions import BTClibValueError, ScriptError
from btclib.hashes import tagged_hash
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.flags import ScriptFlag
from btclib.script.engine.script import (
    EVALUATED_WHEN_UNEXECUTED,
    _assert_bytes_arguments,
)
from btclib.script.engine.script_op_codes import ScriptOp
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.op_codes_tapscript import OP_CODE_NAMES
from btclib.script.script_pub_key import type_and_payload
from btclib.script.sig_hash import PrecomputedTxData
from btclib.script.taproot import parse
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
    `ecc.ssa` answers the same question in Python, and the arm is what
    there is to reach with libsecp256k1 out of reach. No hybrid prefix to
    ask for here -- an x-only key is 32 bytes and BIP340 says which of
    the two points it is -- so the arm is the prepared spelling alone.

    The bindings raise a ValueError on a signature or x-only public key
    that libsecp256k1 refuses to parse, and `ssa.verify_` answers False
    for the same; the caller treats either as a failed verification and
    raises BTClibValueError itself.

    `bytes` and nothing wider, as in `engine.script.dsa_verify` and for
    its reason.
    """
    _assert_bytes_arguments(msg_hash=msg_hash, pub_key=pub_key, sig=sig)

    try:
        if _libsecp256k1_serves(secp256k1, None):
            return bool(_libsecp256k1_ssa_verify(msg_hash, pub_key, sig))
        return ssa.verify_(msg_hash, pub_key, sig)
    except ValueError:
        return False


def get_hashtype(signature: bytes) -> int:
    """Read the sighash type off a taproot signature, per BIP341.

    A 64-byte signature is SIGHASH_DEFAULT; a 65th byte carries the
    type and must not spell the default explicitly, the two encodings
    of one meaning being a malleability.
    """
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise BTClibValueError(
                "explicit SIGHASH_DEFAULT: a 64-byte signature is required"
            )
    return sighash_type


def op_checksigadd(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    """Expand OP_CHECKSIGADD to OP_CHECKSIG OP_ADD, per BIP342.

    The op code pops signature, n and public key, and pushes n plus
    the check's result; the swap puts n out of OP_CHECKSIG's way, and
    the returned pair is re-run by the loop as the ``*VERIFY``
    expansions are. BIP342 defines it as this composition,
    batch-verifiable where the CHECKMULTISIGs it replaces are not.
    """
    stack[-2], stack[-3] = stack[-3], stack[-2]
    return ["OP_CHECKSIG", "OP_ADD"]


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
    itself over the taproot sig_hash with no script committed to; a
    signature that does not verify is the only refusal, get_hashtype's
    aside.

    `hash_types` is `verify_input`'s collector; the one element of the
    stack is the one signature to report.
    """
    sighash_type = get_hashtype(stack[0])
    if hash_types is not None:
        hash_types.append(sighash_type)
    signature = stack[0][:64]
    pub_key = type_and_payload(script_pub_key)[1]
    msg_hash = sig_hash.taproot(
        tx, i, prevouts, sighash_type, 0, annex, b"", precomputed
    )

    if not ssa_verify(msg_hash, pub_key, signature[:64]):
        raise BTClibValueError("invalid signature for the taproot key path")


def op_checksig(
    stack: list[bytes],
    script_bytes: bytes,
    codesep_pos: int,
    tx: Tx,
    i: int,
    prevouts: list[TxOut],
    annex: bytes,
    budget: int,
    flags: ScriptFlag,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> int:
    """Verify one BIP340 signature in a script path: BIP342's OP_CHECKSIG.

    Pops public key and signature, pushes the result, and returns what
    is left of the sigops budget, every non-empty signature costing 50
    whether or not it verifies. The refusals are BIP342's: an empty
    public key, an exhausted budget, and a non-empty signature that
    does not verify -- where the legacy op code pushes False, tapscript
    fails the script, its NULLFAIL being consensus. A key neither empty
    nor 32 bytes verifies nothing and succeeds, which is the upgrade
    room, refused only under DISCOURAGE_UPGRADABLE_PUBKEYTYPE. The
    message hash commits to the tapleaf and to the last executed
    OP_CODESEPARATOR through the BIP341 extension.

    `hash_types` is `verify_input`'s collector, appended to where the
    hash type is read: an empty signature is not one, and neither is
    anything popped beside a public key BIP342 left upgradable.
    """
    pub_key = stack.pop()
    signature = stack.pop()
    if len(pub_key) == 0:
        raise BTClibValueError("empty public key")
    if signature:
        budget -= 50
        if budget < 0:
            raise BTClibValueError("exhausted sigops budget")
    if len(pub_key) == 32:
        if signature:
            sighash_type = get_hashtype(signature)
            if hash_types is not None:
                hash_types.append(sighash_type)
            preimage = b"\xc0"
            preimage += var_bytes.serialize(script_bytes)
            tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
            ext = tapleaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
            msg_hash = sig_hash.taproot(
                tx, i, prevouts, sighash_type, 1, annex, ext, precomputed
            )
            if not ssa_verify(msg_hash, pub_key, signature[:64]):
                raise BTClibValueError("invalid signature for the taproot script path")
    # a key neither empty nor 32 bytes is a public key version BIP342 left
    # to a future soft fork: nothing is verified and the check succeeds,
    # which is the upgrade room, and the sigops budget was charged above
    # because Core charges it for a passing upgradable key too
    elif ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE in flags:
        raise BTClibValueError(f"upgradable public key type: {len(pub_key)} bytes")
    stack.append(encode_num(int(bool(signature))))
    return budget


# the legacy engine's table with OP_CHECKSIGADD in and
# OP_CHECKMULTISIGVERIFY out: BIP342 disables both CHECKMULTISIGs and
# adds the batch-verifiable OP_CHECKSIGADD in their stead. Module-level
# because the loop reads it and never writes -- Mapping is what says so
# -- and a copy per call buys nothing
OPERATIONS: Mapping[str, ScriptOp] = {
    "OP_DUP": script_op_codes.op_dup,
    "OP_2DUP": script_op_codes.op_2dup,
    "OP_DROP": script_op_codes.op_drop,
    "OP_2DROP": script_op_codes.op_2drop,
    "OP_SWAP": script_op_codes.op_swap,
    "OP_1NEGATE": script_op_codes.op_1negate,
    "OP_VERIFY": script_op_codes.op_verify,
    "OP_EQUAL": script_op_codes.op_equal,
    "OP_CHECKSIGVERIFY": script_op_codes.op_checksigverify,
    "OP_CHECKSIGADD": op_checksigadd,
    "OP_EQUALVERIFY": script_op_codes.op_equalverify,
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
    "OP_NUMEQUALVERIFY": script_op_codes.op_numequalverify,
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
    condition_stack: list[bool],
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
    while True:
        script_index += 1
        script_index_ref[0] = script_index

        skip_execution = not all(condition_stack)

        script_op_codes.assert_stack_size(stack, altstack)

        b = s.read(1)
        if not b:
            break
        t = b[0]
        if 0 < t <= 78:  # pushdata
            script_op_codes.read_push_data(
                # the element limit is taproot.parse's here, deferred
                # to the end of the walk so that an OP_SUCCESSx met
                # first forgives an oversized push, as Core's
                # pre-scan does. Measured again in the loop it would
                # refuse what that parse has already forgiven
                t,
                s,
                stack,
                skip_execution,
                flags,
                serialize_script,
                element_size_limit=None,
            )
            continue
        if skip_execution and t not in EVALUATED_WHEN_UNEXECUTED:
            continue
        op = OP_CODE_NAMES[t]

        if op == "OP_CHECKSIG":
            sigops_budget = op_checksig(
                stack,
                script_bytes,
                codesep_pos,
                tx,
                i,
                prevouts,
                annex,
                sigops_budget,
                flags,
                precomputed,
                hash_types,
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
        elif op in OPERATIONS:
            r = OPERATIONS[op](stack, altstack, flags)
            if r:
                script_index -= len(r)
                s = bytesio_from_binarydata(serialize_script(r) + s.read())
        else:
            script_op_codes.unknown_op_code(op)


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
    end with exactly one true element on the stack.

    `hash_types` is `verify_input`'s collector, threaded to
    `op_checksig` as the legacy loop threads it to its own.
    """
    if any(len(x) > MAX_SCRIPT_ELEMENT_SIZE for x in stack):
        err_msg = f"witness stack element longer than {MAX_SCRIPT_ELEMENT_SIZE} bytes"
        raise BTClibValueError(err_msg)

    script = parse(script_bytes, exit_on_op_success=True)

    if script == ["OP_SUCCESS"]:
        # the op code BIP342 reserved for a future soft fork, and until
        # then a spend of anything it appears in: refused only where the
        # caller says it does not want to relay one
        if ScriptFlag.DISCOURAGE_OP_SUCCESS in flags:
            raise BTClibValueError("upgradable OP_SUCCESS op code")
        return

    altstack: list[bytes] = []
    condition_stack: list[bool] = [True]

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
    except BTClibValueError as e:
        raise ScriptError(str(e), script_index_ref[0], len(stack)) from e
    except IndexError as e:
        # what the loop indexes and pops is the stack and the altstack,
        # so an IndexError out of it is an underflow; the chained
        # exception is there for the cases in which it is not
        raise ScriptError("stack underflow", script_index_ref[0], len(stack)) from e

    script_op_codes.assert_balanced_if(condition_stack)

    if not stack:
        raise BTClibValueError("empty stack at the end of the script")
    script_op_codes.op_verify(stack, [], flags)

    if stack:
        raise BTClibValueError(f"{len(stack)} elements left on the stack")
