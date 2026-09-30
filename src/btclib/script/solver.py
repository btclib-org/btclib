# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's `Solver`: the classification a standardness check reads.

A port of `Solver` and `GetTxnOutputType` from `script/solver.cpp`, read at
bitcoin/bitcoin@9be056a8a7 (v31.1), with the helpers it calls in
`script/script.cpp`. Where `script_pub_key.type_and_payload` answers one
payload and names its types its own way, this answers Core's types and the
list of solutions Core fills, which is what `IsStandardTx`,
`AreInputsStandard` and the wallet read.

The two differ on purpose (issue #211), and on more than names:

* p2pk and p2ms keys are checked only for `CPubKey::ValidSize` here, as
  Core does, and parsed as curve points by `type_and_payload`;
* nulldata is an OP_RETURN followed by push-only bytes of any size, where
  `type_and_payload` takes one push of at most 80 bytes: the size cap is
  relay policy, not classification;
* a witness program is tested before nulldata, p2pk, p2pkh and p2ms, so a
  v0 program of a length other than 20 or 32 is "nonstandard" and nothing
  else is tried on it;
* the anchor output `OP_1 <0x4e73>` has a type.
"""

from __future__ import annotations

from typing import get_args

from btclib.alias import Octets, TxoutType
from btclib.exceptions import BTClibValueError
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG
from btclib.script.script import read_op_code
from btclib.utils import bytes_from_octets, decode_num

__all__ = ["get_txn_output_type", "solver"]

_OP_RETURN = 0x6A
_OP_16 = 0x60
_OP_CHECKMULTISIG = 0xAE

# CPubKey::SIZE and CPubKey::COMPRESSED_SIZE
_PUB_KEY_SIZE = 65
_COMPRESSED_PUB_KEY_SIZE = 33

# WITNESS_V0_KEYHASH_SIZE, WITNESS_V0_SCRIPTHASH_SIZE and
# WITNESS_V1_TAPROOT_SIZE, in script/interpreter.h
_WITNESS_V0_KEYHASH_SIZE = 20
_WITNESS_V0_SCRIPTHASH_SIZE = 32
_WITNESS_V1_TAPROOT_SIZE = 32


def get_txn_output_type(tx_out_type: TxoutType) -> str:
    """Return the name of a type, as Core's `GetTxnOutputType` does.

    `TxoutType` is a `Literal` of those names (issue #216), so the name
    is the value itself; this refuses a string that is none of them.
    """
    if tx_out_type not in get_args(TxoutType):
        raise BTClibValueError(f"invalid TxoutType: {tx_out_type!r}")
    return tx_out_type


def _valid_pub_key_size(data: bytes) -> bool:
    """Answer `CPubKey::ValidSize`: the length the first byte calls for."""
    if not data:
        return False
    if data[0] in {0x02, 0x03}:
        return len(data) == _COMPRESSED_PUB_KEY_SIZE
    if data[0] in {0x04, 0x06, 0x07}:
        return len(data) == _PUB_KEY_SIZE
    return False


def _is_pay_to_script_hash(script: bytes) -> bool:
    return (
        len(script) == 23
        and script[0] == 0xA9
        and script[1] == 0x14
        and script[22] == 0x87
    )


def _is_pay_to_anchor(script: bytes) -> bool:
    return script == b"\x51\x02\x4e\x73"


def _witness_program(script: bytes) -> tuple[int, bytes] | None:
    """Return (version, program), as `CScript::IsWitnessProgram` does."""
    if not 4 <= len(script) <= 42:
        return None
    if script[0] != 0 and not 0x51 <= script[0] <= _OP_16:
        return None
    if script[1] + 2 != len(script):
        return None
    version = 0 if script[0] == 0 else script[0] - 0x50
    return version, script[2:]


def _op_data(script: bytes, start: int, op_code: int, stop: int) -> bytes:
    """Return the data `GetOp` hands back for the op code at `start`."""
    if 0 < op_code <= 75:
        return script[start + 1 : stop]
    if 76 <= op_code <= 78:
        return script[start + 1 + 2 ** (op_code - 76) : stop]
    return b""


def _is_push_only(script: bytes, start: int) -> bool:
    """Answer `CScript::IsPushOnly` from `start`: nothing above OP_16."""
    while start < len(script):
        span = read_op_code(script, start)
        if span is None or span[0] > _OP_16:
            return False
        start = span[1]
    return True


def _check_minimal_push(data: bytes, op_code: int) -> bool:
    """Answer Core's `CheckMinimalPush`."""
    size = len(data)
    if size == 0:
        return op_code == 0
    if size == 1 and (1 <= data[0] <= 16 or data[0] == 0x81):
        return False
    if size <= 75:
        return op_code == size
    if size <= 255:
        return op_code == 0x4C
    if size <= 65535:
        return op_code == 0x4D
    return True


def _script_number(op_code: int, data: bytes, low: int, high: int) -> int | None:
    """Return the number an op code or a push holds, in [low, high].

    Core's `GetScriptNumber`: OP_1..OP_16 by the op code, a push only if
    minimal, and None for anything else. The four-byte bound of
    `CScriptNum` is not written out: a number of more than four bytes is
    beyond any range asked for here.
    """
    if 0x51 <= op_code <= _OP_16:
        count = op_code - 0x50
    elif 0 < op_code <= 78:
        if not _check_minimal_push(data, op_code):
            return None
        count = decode_num(data)
        if data and data[-1] & 0x7F == 0 and (len(data) == 1 or not data[-2] & 0x80):
            return None  # CScriptNum refuses a non-minimal encoding
    else:
        return None
    return count if low <= count <= high else None


def _match_pay_to_pub_key(script: bytes) -> bytes | None:
    for size in (_PUB_KEY_SIZE, _COMPRESSED_PUB_KEY_SIZE):
        if len(script) == size + 2 and script[0] == size and script[-1] == 0xAC:
            pub_key = script[1 : size + 1]
            return pub_key if _valid_pub_key_size(pub_key) else None
    return None


def _match_pay_to_pub_key_hash(script: bytes) -> bytes | None:
    if (
        len(script) == 25
        and script[:3] == b"\x76\xa9\x14"
        and script[23:] == b"\x88\xac"
    ):
        return script[3:23]
    return None


def _match_multisig(script: bytes) -> tuple[int, list[bytes]] | None:
    """Read m, the keys and n, as Core's `MatchMultisig` does."""
    if not script or script[-1] != _OP_CHECKMULTISIG:
        return None

    span = read_op_code(script, 0)
    if span is None:
        return None
    required = _script_number(
        span[0], _op_data(script, 0, *span), 1, MAX_PUBKEYS_PER_MULTISIG
    )
    if required is None:
        return None
    position = span[1]

    pub_keys: list[bytes] = []
    # the op that ends the loop is the candidate for n: one read and not a
    # key, or none that could be read, which GetOp leaves as
    # OP_INVALIDOPCODE and no data
    op_code, data = 0xFF, b""
    while (span := read_op_code(script, position)) is not None:
        op_code, data = span[0], _op_data(script, position, *span)
        position = span[1]
        if not _valid_pub_key_size(data):
            break
        pub_keys.append(data)
    else:
        op_code, data = 0xFF, b""

    count = _script_number(op_code, data, required, MAX_PUBKEYS_PER_MULTISIG)
    if count is None or len(pub_keys) != count:
        return None
    # only OP_CHECKMULTISIG is left
    if position + 1 != len(script):
        return None
    return required, pub_keys


def _solve_witness_program(
    script: bytes, version: int, program: bytes
) -> tuple[TxoutType, list[bytes]]:
    """Classify a witness program, in Core's order."""
    if version == 0 and len(program) == _WITNESS_V0_KEYHASH_SIZE:
        return "witness_v0_keyhash", [program]
    if version == 0 and len(program) == _WITNESS_V0_SCRIPTHASH_SIZE:
        return "witness_v0_scripthash", [program]
    if version == 1 and len(program) == _WITNESS_V1_TAPROOT_SIZE:
        return "witness_v1_taproot", [program]
    if _is_pay_to_anchor(script):
        return "anchor", []
    if version != 0:
        return "witness_unknown", [bytes([version]), program]
    return "nonstandard", []


def solver(script_pub_key: Octets) -> tuple[TxoutType, list[bytes]]:  # noqa: PLR0911
    """Classify a script_pub_key as Core's `Solver` does.

    Returns the type and the solutions Core fills for it: the script hash
    for "scripthash"; the key or key hash for "pubkey" and "pubkeyhash";
    m, each key and n for "multisig", m and n as one byte each; the
    program for the three witness types whose version is implied, and
    the version byte then the program for "witness_unknown". "nulldata",
    "anchor" and "nonstandard" have none.

    The checks run in Core's order, which decides the answer: a witness
    program of v0 and a length other than 20 or 32 is "nonstandard" and
    no later shape is tried on it. Keys are checked for their size and
    prefix only, never parsed as points, and nulldata has no size cap
    (that one is relay policy, which `IsStandardTx` applies).
    """
    script = bytes_from_octets(script_pub_key)

    if _is_pay_to_script_hash(script):
        return "scripthash", [script[2:22]]

    if (witness := _witness_program(script)) is not None:
        return _solve_witness_program(script, *witness)

    # any data after the OP_RETURN, so long as it is push-only
    if script and script[0] == _OP_RETURN and _is_push_only(script, 1):
        return "nulldata", []

    if (pub_key := _match_pay_to_pub_key(script)) is not None:
        return "pubkey", [pub_key]

    if (pub_key_hash := _match_pay_to_pub_key_hash(script)) is not None:
        return "pubkeyhash", [pub_key_hash]

    if (multisig := _match_multisig(script)) is not None:
        required, pub_keys = multisig
        return "multisig", [bytes([required]), *pub_keys, bytes([len(pub_keys)])]

    return "nonstandard", []
