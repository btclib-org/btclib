# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The signature check operation counts of a script and of an input.

Bitcoin Core's `CScript::GetSigOpCount`, both overloads, in
src/script/script.cpp, and `CountWitnessSigOps` in
src/script/interpreter.cpp: the terms `GetTransactionSigOpCost`, in
src/consensus/tx_verify.cpp, adds up, and `script.engine.sig_op_cost` is
that sum.

`sig_op_count` of a script_sig or a script_pub_key is the legacy term, the
one a transaction answers from its own bytes. `Tx.sig_op_count` is Core's
`GetLegacySigOpCount`, and `Block.sig_op_count` is the sum `CheckBlock`
bounds by `MAX_BLOCK_SIGOPS_COST`. The other two terms read the output an
input spends, which a transaction does not carry: `p2sh_sig_op_count`
counts the redeem script a p2sh input pushes, and `witness_sig_op_count`
the witness program it spends, bare or nested in p2sh.

`accurate` is Core's `fAccurate`: with it an `OP_CHECKMULTISIG` right
after `OP_1` to `OP_16` costs that many keys, where without it every one
costs `MAX_PUBKEYS_PER_MULTISIG`. The legacy term is counted without it,
and the redeem script and the witness script with it.

A module of its own rather than the bottom of `script.py`, which is the
encoding and reads no limit: `MAX_PUBKEYS_PER_MULTISIG` is a rule about
executing a script, and a decoder that need not import the limits is what
`script/limits.py` exists to say. What it does share with the decoder is
the walk -- `op_code_spans`, i.e. Core's `GetOp` -- because the boundary
between one op code and the next is the only thing the count depends on.
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG
from btclib.script.script import BYTE_FROM_OP_CODE_NAME, op_code_spans
from btclib.script.script_pub_key import is_p2sh, is_segwit
from btclib.script.witness import Witness
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "p2sh_sig_op_count",
    "sig_op_count",
    "witness_sig_op_count",
]

# read out of the table rather than written as bytes, so that these stay
# the op codes those names stand for
_CHECKSIG = {
    BYTE_FROM_OP_CODE_NAME[name][0] for name in ("OP_CHECKSIG", "OP_CHECKSIGVERIFY")
}
_CHECKMULTISIG = {
    BYTE_FROM_OP_CODE_NAME[name][0]
    for name in ("OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY")
}
_OP_PUSHDATA1 = BYTE_FROM_OP_CODE_NAME["OP_PUSHDATA1"][0]
_OP_PUSHDATA4 = BYTE_FROM_OP_CODE_NAME["OP_PUSHDATA4"][0]
_OP_1 = BYTE_FROM_OP_CODE_NAME["OP_1"][0]
_OP_16 = BYTE_FROM_OP_CODE_NAME["OP_16"][0]


def _sig_op_count(script: bytes, accurate: bool) -> int:
    count = 0
    # no op code read yet, and so no OP_n: Core's lastOpcode starts as
    # OP_INVALIDOPCODE for the same reason
    last_op_code = -1
    for op_code, _, _ in op_code_spans(script):
        if op_code in _CHECKSIG:
            count += 1
        elif op_code in _CHECKMULTISIG:
            if accurate and _OP_1 <= last_op_code <= _OP_16:
                count += last_op_code - _OP_1 + 1
            else:
                count += MAX_PUBKEYS_PER_MULTISIG
        last_op_code = op_code
    return count


def sig_op_count(script: Octets, *, accurate: bool = False) -> int:
    """Return the number of signature checks a script announces.

    One for `OP_CHECKSIG` and `OP_CHECKSIGVERIFY`, and nothing for the
    rest but `OP_CHECKMULTISIG` and `OP_CHECKMULTISIGVERIFY`. Those cost
    `MAX_PUBKEYS_PER_MULTISIG` however many keys the script actually
    pushes, unless `accurate` is asked for and the op code right before
    is `OP_1` to `OP_16`, whose number is then the cost. The count is
    announced by the bytes and is not what executing them would do, and a
    byte pushed as data is not the op code it would spell: `0160ae` costs
    `MAX_PUBKEYS_PER_MULTISIG` even accurately counted.

    Where the script stops parsing the count stops too, and no exception
    is raised: Core's loop `break`s when `GetOp` returns false, which is a
    push running past the end, and `op_code_spans` ends the same way. The
    coinbase output script of testnet block 987,876 is that case on chain
    -- it ends `...d8 3d 0aa68688ac`, and the `OP_CHECKSIG` of that final
    `ac` is five bytes inside the 61-byte push `3d` announces, so neither
    implementation ever reaches it and the answer for that script is zero.
    """
    assert_type(accurate, bool, "accurate")
    return _sig_op_count(bytes_from_octets(script), accurate)


def _last_push(script_sig: bytes) -> bytes | None:
    """Return what a push-only script_sig pushes last, None for any other.

    Core reads it this way in both places: `GetSigOpCount(scriptSig)`
    answers zero where `GetOp` fails or reads an op code above `OP_16`,
    and `CountWitnessSigOps` asks `IsPushOnly`, which refuses the same
    two. An op code carrying no data -- `OP_0`, `OP_1NEGATE`,
    `OP_RESERVED`, `OP_1` to `OP_16` -- leaves the data empty, as
    `GetScriptOp` clears it before each op code it reads.
    """
    data = b""
    end = 0
    for op_code, start, stop in op_code_spans(script_sig):
        if op_code > _OP_16:
            return None
        # the op code, and the length bytes an OP_PUSHDATAn reads after
        # it; an op code carrying no data is one byte, so its slice is
        # empty
        header = 1
        if _OP_PUSHDATA1 <= op_code <= _OP_PUSHDATA4:
            header += 1 << (op_code - _OP_PUSHDATA1)
        data = script_sig[start + header : stop]
        end = stop
    return data if end == len(script_sig) else None


def p2sh_sig_op_count(script_sig: Octets, script_pub_key: Octets) -> int:
    """Return the p2sh count of an input, Core's `GetSigOpCount(scriptSig)`.

    For a p2sh script_pub_key, the accurate count of the redeem script,
    which is the last push of the script_sig; zero where the script_sig
    is not push-only or stops parsing. For any other script_pub_key the
    answer is that script's own accurate count, as it is in Core, whose
    `GetP2SHSigOpCount` asks only of a p2sh one, as
    `script.engine.sig_op_cost` does.
    """
    script_sig_ = bytes_from_octets(script_sig)
    script_pub_key_ = bytes_from_octets(script_pub_key)
    if not is_p2sh(script_pub_key_):
        return _sig_op_count(script_pub_key_, accurate=True)
    redeem_script = _last_push(script_sig_)
    if redeem_script is None:
        return 0
    return _sig_op_count(redeem_script, accurate=True)


def _witness_program_sig_op_count(program: bytes, witness: Witness) -> int:
    """Return Core's `WitnessSigOps` of a witness program's script."""
    if program[0] == 0:
        if len(program) == 22:  # a 20-byte key hash
            return 1
        if len(program) == 34 and witness.stack:  # a 32-byte script hash
            return _sig_op_count(witness.stack[-1], accurate=True)
    # anything else counts nothing, taproot included: BIP342 keeps the
    # tapscript sigops out of the block-wide limit and gives each input a
    # budget of its own instead
    return 0


def witness_sig_op_count(
    script_sig: Octets, script_pub_key: Octets, witness: Witness
) -> int:
    """Return the witness count of an input, Core's `CountWitnessSigOps`.

    One for a version-0 key hash program, and the accurate count of the
    witness script, the last witness element, for a version-0 script hash
    program with a non-empty witness; zero for any other program and for
    a script that is no program. The program is the script_pub_key, or
    where that is p2sh the last push of a push-only script_sig: that is
    what BIP141's p2sh-nested outputs spend. The program is read and not
    verified, so a script hash is not checked against the witness script
    it counts.

    Core answers zero where its flags leave `SCRIPT_VERIFY_WITNESS` out;
    `script.engine.sig_op_cost` is where this library reads that flag.
    """
    script_sig_ = bytes_from_octets(script_sig)
    script_pub_key_ = bytes_from_octets(script_pub_key)
    assert_type(witness, Witness, "witness")
    if is_segwit(script_pub_key_):
        return _witness_program_sig_op_count(script_pub_key_, witness)
    if is_p2sh(script_pub_key_):
        redeem_script = _last_push(script_sig_)
        if redeem_script is not None and is_segwit(redeem_script):
            return _witness_program_sig_op_count(redeem_script, witness)
    return 0
