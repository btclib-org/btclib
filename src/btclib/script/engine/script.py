# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The legacy and segwit v0 interpreter loop of the script engine."""

from __future__ import annotations

from collections.abc import Mapping

from btclib._libsecp256k1 import dsa_verify as _libsecp256k1_dsa_verify
from btclib.alias import ScriptList
from btclib.curves import point_from_octets, secp256k1
from btclib.curves.curve import _libsecp256k1_serves
from btclib.ecc import dsa
from btclib.ecc.dsa import Sig
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibValueError,
    ScriptError,
)
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.flags import ScriptFlag
from btclib.script.engine.script_op_codes import _MAX_NUM_SIZE, ScriptOp, _to_num
from btclib.script.limits import (
    MAX_OPS_PER_SCRIPT,
    MAX_PUBKEYS_PER_MULTISIG,
    MAX_SCRIPT_SIZE,
)
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    OP_CODE_NAME_FROM_INT,
    op_code_spans,
    parse,
    read_op_code,
)
from btclib.script.script import serialize as serialize_script
from btclib.script.sig_hash import SIG_HASH_TYPES, PrecomputedTxData
from btclib.tx.tx import Tx
from btclib.utils import assert_type, bytesio_from_binarydata, encode_num

__all__ = [
    "DISABLED_OP_CODES",
    "EVALUATED_WHEN_UNEXECUTED",
    "OPERATIONS",
    "STRICT_DER_FLAGS",
    "assert_not_disabled",
    "assert_nulldummy",
    "assert_nullfail",
    "assert_pub_key_num",
    "assert_signature_num",
    "calculate_script_code",
    "check_pub_key",
    "dsa_verify",
    "find_and_delete",
    "fix_signature",
    "op_checksig",
    "op_code_name",
    "prepare_script",
    "script_op_count",
    "verify_script",
]


def _assert_bytes_arguments(**arguments: object) -> None:
    """Refuse an argument that is not `bytes`, naming the parameter.

    The two signature adapters of this package declare `bytes` exactly
    and hand it straight to the bindings, whose own message would name a
    C parameter -- "the message hash must be bytes" is true and is not
    btclib saying it (issue #814). Keyword arguments, so that what comes
    out names the one that was wrong.
    """
    for what, value in arguments.items():
        assert_type(value, bytes, what)


def dsa_verify(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """Verify an ECDSA signature, returning False if it is malformed.

    The dispatch every delegation in this library makes, and this one has
    a second implementation to reach when it declines: `ecc.dsa` answers
    the same question in Python, so libsecp256k1 out of reach leaves an
    arm to take rather than an ImportError to raise.

    `hybrid=True` is what the Python arm needs and the bindings do not:
    `ec_pubkey_parse` takes the 0x06/0x07 prefixes always (eckey_impl.h)
    while `point_from_octets` takes them only when asked, and consensus
    wants CHECKSIG to succeed for a hybrid key wherever STRICTENC is off.
    Both defects of issue #129 were in that arm and neither was a lax
    function -- one was `Sig.parse` dropping a byte, the other this very
    prefix -- so what the arm has to agree with the bindings about is the
    verdict on a whole transaction.

    One try around both arms, because the contract is one: a signature or
    a public key that cannot be parsed is a failed verification, not an
    exception the interpreter loop sees. The bindings raise ValueError
    for it, `point_from_octets` raises BTClibValueError, which is one,
    and `dsa.verify_` catches its own. DER strictness is enforced
    upstream either way, by fix_signature under the STRICT_DER_FLAGS
    below -- and so is the lower-s form, which is what keeps the two arms
    from disagreeing about a high s: the bindings' `dsa.verify` refuses
    one where `_assert_as_valid_(..., lower_s=False)` accepts it, and by
    the time either is asked fix_signature has already negated a high s
    wherever no flag refuses the signature outright, which is Core's own
    behaviour.

    `bytes` and nothing wider, which is what the three declare: the
    bindings would answer a float with "the message hash must be bytes",
    which is true and is not btclib saying it. Every caller here hands
    stack elements, so the check costs a few nanoseconds of a
    microsecond-scale verification (issue #814).
    """
    _assert_bytes_arguments(msg_hash=msg_hash, pub_key=pub_key, sig=sig)

    try:
        if _libsecp256k1_serves(secp256k1, None):
            return bool(_libsecp256k1_dsa_verify(msg_hash, pub_key, sig))
        return dsa.verify_(msg_hash, point_from_octets(pub_key, hybrid=True), sig)
    except ValueError:
        return False


# the flags Core's CheckSignatureEncoding tests for as one mask, and the
# reason it is a mask and not three rules: `flags & (SCRIPT_VERIFY_DERSIG |
# SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)` gates
# IsValidSignatureEncoding, so any one of the three asks for strict DER and
# only their absence leaves ecdsa_signature_parse_der_lax to accept a
# sloppy encoding
STRICT_DER_FLAGS = ScriptFlag.DERSIG | ScriptFlag.LOW_S | ScriptFlag.STRICTENC


def fix_signature(signature: bytes, flags: ScriptFlag) -> bytes:
    """Return the signature the bindings can be asked to verify.

    The bindings parse strict DER and refuse a high s, which is two rules
    where Core has none: `CPubKey::Verify` parses laxly and normalizes s
    before verifying, and it is CheckSignatureEncoding above it that
    refuses either -- under the flags for it and not otherwise. So both
    are answered here, each in the direction its flags ask for: a lax
    encoding is re-serialized strict when no flag wants it refused, and a
    high s is negated when no flag wants it refused.
    """
    signature_suffix = signature[-1:]
    if ScriptFlag.STRICTENC in flags and signature_suffix[0] not in SIG_HASH_TYPES:
        raise BTClibValueError(f"invalid sighash type: {hex(signature_suffix[0])}")
    signature = signature[:-1]
    if not flags & STRICT_DER_FLAGS:
        signature = Sig.parse(signature, strict=False).serialize()
    # strict, so that this is what enforces DER for the three flags above:
    # a lax encoding was normalized already, and one that was not has to be
    # refused here rather than reach the bindings, which answer a parse
    # failure the way they answer a wrong signature
    sig = Sig.parse(signature)
    if sig.s > sig.ec.n // 2:
        # Core's SCRIPT_ERR_SIG_HIGH_S, an error under LOW_S alone: without
        # it a high s is not merely tolerated but normalized away, so
        # leaving it for the bindings to refuse would report a signature
        # that does not verify where Core reports one that does
        if ScriptFlag.LOW_S in flags:
            raise BTClibValueError(f"high s: {hex(sig.s)}")
        signature = Sig(sig.r, sig.ec.n - sig.s).serialize()
    return signature + signature_suffix


def check_pub_key(pub_key: bytes, segwit: bool, flags: ScriptFlag) -> bool:
    """Answer whether the public key is well-formed enough to verify with.

    Core's CheckPubKeyEncoding, split the way Core splits it: a wrong
    length or prefix returns False, which op_checksig turns into a
    failed signature check rather than a script error, while the two
    flags that make the encoding itself the offence raise -- STRICTENC
    for a hybrid 0x06/0x07 prefix, WITNESS_PUBKEYTYPE for an
    uncompressed key in a segwit script.
    """
    assert_type(segwit, bool, "segwit")
    if not pub_key:
        return False
    if pub_key[0] in {4, 6, 7}:
        if pub_key[0] in {6, 7} and ScriptFlag.STRICTENC in flags:
            raise BTClibValueError(f"hybrid public key prefix: {hex(pub_key[0])}")
        if segwit and ScriptFlag.WITNESS_PUBKEYTYPE in flags:
            raise BTClibValueError("uncompressed public key in a segwit script")
        return len(pub_key) == 65
    return len(pub_key) == 33 if pub_key[0] in {2, 3} else False


def find_and_delete(script: bytes, target: bytes) -> tuple[bytes, int]:
    """Delete every occurrence of target from script: (result, how many).

    Core's `FindAndDelete`, matched op code boundary by op code boundary
    and in one left-to-right pass, both of which are load-bearing. A
    `bytes.replace` loop is neither: it deletes a match lying inside the
    data of a push, which Core's walk never reaches, and re-running it
    over the result deletes matches that only exist because an earlier
    deletion joined their halves. Either turns a script code Core leaves
    alone into one that is shorter, differently signed, or no longer a
    script at all.

    Once a match is taken the walk resumes from just past it, wherever
    that lands — Core resumes its GetOp there too, which is how a deletion
    can leave the rest of the script read as something else. Bug for bug:
    the script code is consensus, not taste.
    """
    if not target:  # Core returns early rather than delete forever
        return script, 0
    kept: list[bytes] = []
    found = 0
    pc = pc2 = 0
    while True:
        kept.append(script[pc2:pc])
        while script[pc : pc + len(target)] == target:
            pc += len(target)
            found += 1
        pc2 = pc
        span = read_op_code(script, pc)
        if span is None:
            break
        pc = span[1]
    if not found:
        return script, 0
    kept.append(script[pc2:])
    return b"".join(kept), found


def calculate_script_code(
    script_bytes: bytes,
    codesep_offset: int,
    signatures: list[bytes],
    const_scriptcode: bool,
    segwit: bool,
) -> bytes:
    """Return the script code the signature under check commits to.

    Core's two steps and in its order: `CScript
    scriptCode(pbegincodehash, pend)`, a slice of the script's own bytes
    from just past the last executed OP_CODESEPARATOR, and then — for a
    pre-segwit signature only — FindAndDelete of the signature itself,
    which BIP143 dropped for segwit v0 and which is why `segwit` is a
    parameter rather than a fact about the script.

    The OP_CODESEPARATORs left in the slice stay in it. Eliding them is
    the legacy serializer's, `sig_hash.legacy` doing it there because
    that is where Core does it, and doing it here as well would elide
    them before FindAndDelete rather than after.
    """
    assert_type(const_scriptcode, bool, "const_scriptcode")
    assert_type(segwit, bool, "segwit")

    script_code = script_bytes[codesep_offset:]

    if not segwit:
        for signature in signatures:
            script_code, found = find_and_delete(
                script_code, serialize_script([signature])
            )
            # Core's SCRIPT_ERR_SIG_FINDANDDELETE, and it errors on having
            # found rather than refusing to look: a script code that
            # carries the signature checked against it is the case the
            # flag exists to make unspendable
            if found and const_scriptcode:
                raise BTClibValueError("signature found in the script code")

    return script_code


def op_checksig(
    signature: bytes,
    signatures: list[bytes],
    pub_key: bytes,
    script_bytes: bytes,
    codesep_offset: int,
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: ScriptFlag,
    segwit: bool,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> bool:
    """Verify one ECDSA signature over the script code it commits to.

    Returns the boolean the op code pushes rather than raising: an
    empty signature, one that fails to verify, or a key or encoding
    refused under lax rules are all False, and an error only where a
    flag makes the encoding the offence -- DERSIG/LOW_S/STRICTENC for
    the signature, STRICTENC/WITNESS_PUBKEYTYPE for the key.

    `signatures` is what FindAndDelete removes from a pre-segwit
    script code: the whole set under check when called from
    OP_CHECKMULTISIG, the signature itself otherwise. The message hash
    is BIP143's for a segwit v0 input and the legacy per-input
    serialization for the rest; tapscript signatures never reach here,
    tapscript.py verifying BIP340 on its own.

    `hash_types` is `verify_input`'s collector, appended to here
    because this is where the last byte of a stack element is known to
    be a hash type at all.
    """
    assert_type(segwit, bool, "segwit")
    if not signature:
        return False
    try:
        signature = fix_signature(signature, flags)
    except (BTClibValueError, BTClibRuntimeError):
        # under any of the three, CheckSignatureEncoding is what failed and
        # Core ends the script; under none of them the lax parse failed,
        # which is a signature that does not verify and nothing more
        if flags & STRICT_DER_FLAGS:
            raise
        return False

    if not check_pub_key(pub_key, segwit, flags):
        if ScriptFlag.STRICTENC in flags:
            raise BTClibValueError(f"invalid public key: {pub_key.hex()}")
        return False

    if hash_types is not None:
        # after the two encoding gates and before the verification: what
        # is reported is what the interpreter took for a signature, and
        # whether it verifies is a separate answer -- OP_CHECKMULTISIG
        # tries one signature against several keys, so a report made
        # only on success would leave out the very element under check
        hash_types.append(signature[-1])

    script_code = calculate_script_code(
        script_bytes,
        codesep_offset,
        signatures,
        ScriptFlag.CONST_SCRIPTCODE in flags,
        segwit,
    )
    if segwit:
        msg_hash = sig_hash.segwit_v0(
            script_code, tx, i, signature[-1], prevout_value, precomputed
        )
    else:
        # the legacy sig_hash preimage is the transaction itself, blanked
        # and re-serialized per input: there is no transaction-wide part of
        # it to share, here or in Bitcoin Core
        msg_hash = sig_hash.legacy(script_code, tx, i, signature[-1])
    return bool(dsa_verify(msg_hash, pub_key, signature[:-1]))


def op_code_name(op_code: int) -> str:
    """Name an op code, rather than answer a missing key with a KeyError."""
    if op_code not in OP_CODE_NAME_FROM_INT:
        raise BTClibValueError(f"unknown op code: {hex(op_code)}")
    return OP_CODE_NAME_FROM_INT[op_code]


def assert_nullfail(
    flags: ScriptFlag, verified: bool, signatures: list[bytes], op: str
) -> None:
    """Reject a signature that failed to verify and was not empty.

    `verified` is refused rather than read for its truth, which is what
    separates it from `verify_script`'s `final` next door: every wrong
    value is true, so the misreading a non-bool makes is always the one
    the flag's `True` stands for. `final=True` demands a true stack, so
    a non-bool there fails a script that would have passed; `True` here
    *suppresses* this refusal, so `verified="false"` lets a non-empty
    signature that failed to verify through a consensus rule.
    CONTRIBUTING.md has that as the polarity a truth needs and this one
    has not (issue #884).
    """
    assert_type(verified, bool, "verified")
    if ScriptFlag.NULLFAIL in flags and not verified and any(signatures):
        raise BTClibValueError(f"non-empty signature for a failed {op}")


def assert_nulldummy(dummy: bytes, flags: ScriptFlag) -> None:
    """Reject a non-empty dummy, the element OP_CHECKMULTISIG pops too many."""
    if dummy != b"" and ScriptFlag.NULLDUMMY in flags:
        raise BTClibValueError("non-empty OP_CHECKMULTISIG dummy element")


def assert_pub_key_num(pub_key_num: int) -> None:
    """Reject a public key count outside 0..20, before the keys are read.

    Core's SCRIPT_ERR_PUBKEY_COUNT, and the lower bound is the half that
    is not decoration: a negative count reaches `range` as an empty one,
    so nothing is popped, nothing underflows, and a count of -1 sails
    through a test for "more than twenty" -- which left
    `-1 -1 OP_CHECKMULTISIG` pushing false and the script running on where
    Core ends it.
    """
    if not 0 <= pub_key_num <= MAX_PUBKEYS_PER_MULTISIG:
        raise BTClibValueError(f"invalid number of public keys: {pub_key_num}")


def assert_signature_num(signature_num: int, pub_key_num: int) -> None:
    """Reject a signature count outside 0..pub_key_num.

    Core's SCRIPT_ERR_SIG_COUNT, negative for the same reason as above.
    """
    if not 0 <= signature_num <= pub_key_num:
        raise BTClibValueError(
            f"{signature_num} signatures for {pub_key_num} public keys"
        )


def script_op_count(count: int, increment: int) -> int:
    """Add to the op code count, bounded by MAX_OPS_PER_SCRIPT.

    Core's accounting: pushes are free, every other op code costs one,
    and OP_CHECKMULTISIG adds its public key count on top.
    """
    count += increment
    if count > MAX_OPS_PER_SCRIPT:
        raise BTClibValueError(f"more than {MAX_OPS_PER_SCRIPT} op codes: {count}")
    return count


# The op codes Core reads even inside an unexecuted branch: `fExec ||
# (OP_IF <= opcode && opcode <= OP_ENDIF)` in interpreter.cpp. It is a
# range and not the four conditionals in it, and that is the whole of
# what makes OP_VERIF (0x65) and OP_VERNOTIF (0x66) invalid whether they
# execute or not -- Core gives them no case of their own, so they fall
# to `default: BAD_OPCODE` from inside a branch that is never taken.
# Enumerating the four skipped them instead, and both engines then
# accepted a script Core rejects.
#
# Rejecting them here rather than in a pass over the parsed script is
# also what keeps tapscript faithful: Core's OP_SUCCESS pre-scan returns
# success at the first OP_SUCCESS whatever precedes it, so `OP_VERIF
# OP_SUCCESS80` is valid and must stay so (issue #182).
EVALUATED_WHEN_UNEXECUTED = range(0x63, 0x69)  # OP_IF..OP_ENDIF

# The op codes Satoshi switched off for CVE-2010-5137, which Core refuses
# earlier still: `if (opcode == OP_CAT || ...) return DISABLED_OPCODE`
# sits above the fExec test, so one of these anywhere in a script -- in a
# branch never taken, after an OP_RETURN, wherever -- makes it unspendable
# and its error DISABLED_OPCODE rather than BAD_OPCODE. Read from the
# table by name, so that a name that stops existing fails at import rather
# than leaving a rule that quietly stops matching.
#
# Only this engine needs them: BIP342 turns every one of these bytes into
# an OP_SUCCESSx, so in tapscript they are the opposite of disabled and
# the pre-scan answers before the interpreter sees one.
DISABLED_OP_CODES = frozenset(
    BYTE_FROM_OP_CODE_NAME[name][0]
    for name in (
        "OP_CAT",
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_2MUL",
        "OP_2DIV",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
    )
)


def assert_not_disabled(op_code: int) -> None:
    """Reject an op code disabled by CVE-2010-5137, executed or not."""
    if op_code in DISABLED_OP_CODES:
        raise BTClibValueError(f"disabled op code: {op_code_name(op_code)}")


def prepare_script(script: ScriptList, flags: ScriptFlag, segwit: bool) -> None:
    """Refuse OP_CODESEPARATOR in a legacy script under CONST_SCRIPTCODE.

    Only legacy: BIP143 keeps the op code meaningful in segwit v0, so
    the pre-segwit script code is the one the flag freezes.
    """
    # `verify_script` reaches this before it reads its own `segwit`, so
    # this is where the flag of a whole script evaluation is asked for
    assert_type(segwit, bool, "segwit")
    if (
        "OP_CODESEPARATOR" in script
        and ScriptFlag.CONST_SCRIPTCODE in flags
        and not segwit
    ):
        raise BTClibValueError("OP_CODESEPARATOR in a non-segwit script")


# what one signature can drive: every entry takes (stack, altstack,
# flags) and nothing else, so the loop dispatches them blind and
# verify_script holds only the op codes that need more. Module-level
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
    "OP_CHECKMULTISIGVERIFY": script_op_codes.op_checkmultisigverify,
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


# what the OPERATIONS table cannot hold, read against Core's EvalScript:
# the op codes needing the engine's own state, and the pushes matched by
# shape rather than by name
def _run_ops(  # noqa: C901, PLR0912
    script_bytes: bytes,
    stack: list[bytes],
    altstack: list[bytes],
    condition_stack: list[bool],
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: ScriptFlag,
    segwit: bool,
    precomputed: PrecomputedTxData | None,
    op_code_stops: list[int],
    script_index_ref: list[int],
    hash_types: list[int] | None,
) -> None:
    """Run verify_script's opcode dispatch loop.

    Split out of verify_script so that the try/except reporting where a
    refusal happened wraps one call rather than the loop -- the loop
    itself is the C901/PLR0912 this carries, the shape Core's own
    EvalScript has for the same dispatch, and moving it here does not
    make it smaller. `script_index_ref` is how the failing index still
    reaches that except: set at the top of every iteration, before
    anything the iteration does that could raise.
    """
    segwit_version = 0 if segwit else -1
    op_code_num = 0
    codesep_offset = 0
    script_index = -1
    s = bytesio_from_binarydata(script_bytes)
    while True:
        script_index += 1
        script_index_ref[0] = script_index

        script_op_codes.assert_stack_size(stack, altstack)

        skip_execution = not all(condition_stack)

        b = s.read(1)
        if not b:
            break
        t = b[0]
        if 0 < t <= 78:  # pushdata
            script_op_codes.read_push_data(
                t, s, stack, skip_execution, flags, serialize_script
            )
            continue

        if t > 96:  # OP_16
            op_code_num = script_op_count(op_code_num, 1)

        assert_not_disabled(t)

        if skip_execution and t not in EVALUATED_WHEN_UNEXECUTED:
            continue
        op = op_code_name(t)

        if op == "OP_CHECKSIG":
            pub_key = stack.pop()
            signature = stack.pop()
            result = op_checksig(
                signature,
                [signature],
                pub_key,
                script_bytes,
                codesep_offset,
                prevout_value,
                tx,
                i,
                flags,
                segwit,
                precomputed,
                hash_types,
            )
            assert_nullfail(flags, result, [signature], "OP_CHECKSIG")
            stack.append(encode_num(int(result)))

        elif op == "OP_CHECKMULTISIG":
            # Core's order, and it is the order that makes the two
            # counts safe to build a `range` out of: each is bounded
            # before anything is popped with it
            pub_key_num = _to_num(stack.pop(), flags, _MAX_NUM_SIZE)
            assert_pub_key_num(pub_key_num)
            op_code_num = script_op_count(op_code_num, pub_key_num)
            pub_keys = [stack.pop() for _ in range(pub_key_num)]
            signature_num = _to_num(stack.pop(), flags, _MAX_NUM_SIZE)
            assert_signature_num(signature_num, pub_key_num)
            signatures = [stack.pop() for _ in range(signature_num)]

            assert_nulldummy(stack.pop(), flags)  # dummy value
            signature_index = 0
            for pub_key_index in range(pub_key_num):
                if signature_index == signature_num:
                    break
                if pub_key_num - pub_key_index < signature_num - signature_index:
                    break
                pub_key = pub_keys[pub_key_index]
                signature = signatures[signature_index]
                signature_index += op_checksig(
                    signature,
                    signatures,
                    pub_key,
                    script_bytes,
                    codesep_offset,
                    prevout_value,
                    tx,
                    i,
                    flags,
                    segwit,
                    precomputed,
                    hash_types,
                )

            if signature_index == signature_num:
                stack.append(b"\x01")
            else:
                assert_nullfail(flags, False, signatures, "OP_CHECKMULTISIG")
                stack.append(b"")

        elif op == "OP_CHECKLOCKTIMEVERIFY":
            script_op_codes.op_checklocktimeverify(stack, tx, i, flags)
        elif op == "OP_CHECKSEQUENCEVERIFY":
            script_op_codes.op_checksequenceverify(stack, tx, i, flags)
        elif op[3:].isdigit():
            stack.append(encode_num(int(op[3:])))
        elif op == "OP_CODESEPARATOR":
            codesep_offset = op_code_stops[script_index]
        elif op == "OP_IF":
            script_op_codes.op_if(stack, condition_stack, flags, segwit_version)
        elif op == "OP_NOTIF":
            script_op_codes.op_notif(stack, condition_stack, flags, segwit_version)
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
                op_code_num -= len(r)
                s = bytesio_from_binarydata(serialize_script(r) + s.read())
        else:
            script_op_codes.unknown_op_code(op)


def verify_script(
    script_bytes: bytes,
    stack: list[bytes],
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: ScriptFlag,
    segwit: bool,
    final: bool = False,
    precomputed: PrecomputedTxData | None = None,
    hash_types: list[int] | None = None,
) -> None:
    """Execute the script over the caller's stack, as Core's EvalScript.

    The stack is mutated in place, which is how the callers chain
    scripts: script_sig leaves what script_pub_key then reads. Any
    refusal -- a BTClibValueError out of an op code, an IndexError out
    of a pop on a short stack -- is re-raised as ScriptError carrying
    the index of the failing command and the stack depth. With `final`
    the script must end on a non-empty stack with a true top element,
    which is the caller saying no script runs after this one.

    `hash_types` is `verify_input`'s collector, threaded through to
    `op_checksig`; chaining scripts over one stack is chaining them
    over one collector too.
    """
    if len(script_bytes) > MAX_SCRIPT_SIZE:
        err_msg = f"script longer than {MAX_SCRIPT_SIZE} bytes: {len(script_bytes)}"
        raise BTClibValueError(err_msg)

    script = parse(script_bytes)
    prepare_script(script, flags, segwit)

    # Core's pbegincodehash, an offset into script_bytes and not an index
    # into the parse: a script code is a slice of the script's own bytes,
    # and measuring where to cut it by re-serializing the op codes before
    # the cut moved it by whatever a non-minimal push there lost in the
    # round trip (issue #176). s.tell() cannot answer either — a *VERIFY
    # op code below rebuilds the stream out of the two it stands for, so
    # after one of those the stream is no longer the script. The op code
    # index survives that rebuild, which winds it back by the two it
    # injects, and neither of those two is ever an OP_CODESEPARATOR, so
    # the index is the right one wherever it is read below. Hence this:
    # the byte one past each op code, walked once and only for a script
    # that has a separator to cut at
    op_code_stops = (
        [stop for _, _, stop in op_code_spans(script_bytes)]
        if "OP_CODESEPARATOR" in script
        else []
    )

    altstack: list[bytes] = []
    condition_stack: list[bool] = [True]

    script_index_ref = [-1]
    try:
        _run_ops(
            script_bytes,
            stack,
            altstack,
            condition_stack,
            prevout_value,
            tx,
            i,
            flags,
            segwit,
            precomputed,
            op_code_stops,
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

    script_op_codes.assert_stack_size(stack, altstack)
    script_op_codes.assert_balanced_if(condition_stack)

    if final:
        if not stack:
            raise BTClibValueError("empty stack at the end of the script")
        script_op_codes.op_verify(stack, [], flags)
