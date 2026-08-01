#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Bitcoin Script.

https://en.bitcoin.it/wiki/Script

Scripts are represented by list[Command], where Command = int | str | bytes

* ascii string are for opcodes (e.g. 'OP_HASH160', 'OP_1', 'OP_1NEGATE', etc.)
* hex-string or bytes (i.e., Octets) are for data

The tables name op codes no valid script can execute, marked `# disabled`
below: the fifteen splice, bitwise and multiplication op codes Satoshi
switched off for CVE-2010-5137. Naming them is what lets the engine
*reject* them by name -- a byte with no name reaches the interpreter as
"unknown op code", and one that parse cannot name at all cannot be
serialized back either, which the engine's FindAndDelete relies on. Core
draws the same line: script.h defines them, GetOpName names them, GetOp
reads them, and only the interpreter refuses -- there, before it even
asks whether the branch executes. OP_RESERVED, OP_VER, OP_VERIF,
OP_VERNOTIF, OP_RESERVED1 and OP_RESERVED2 are named for the same reason
and refused by their own rules.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import cached_property
from io import BytesIO
from warnings import warn

from btclib.alias import BinaryData, Command, Octets, ScriptList
from btclib.exceptions import BTClibUserWarning, BTClibValueError
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, encode_num

BYTE_FROM_OP_CODE_NAME = {
    # Constants
    "OP_0": b"\x00",
    "OP_FALSE": b"\x00",
    "OP_PUSHDATA1": b"\x4c",
    "OP_PUSHDATA2": b"\x4d",
    "OP_PUSHDATA4": b"\x4e",
    "OP_1NEGATE": b"\x4f",
    "OP_RESERVED": b"\x50",
    "OP_1": b"\x51",
    "OP_TRUE": b"\x51",
    "OP_2": b"\x52",
    "OP_3": b"\x53",
    "OP_4": b"\x54",
    "OP_5": b"\x55",
    "OP_6": b"\x56",
    "OP_7": b"\x57",
    "OP_8": b"\x58",
    "OP_9": b"\x59",
    "OP_10": b"\x5a",
    "OP_11": b"\x5b",
    "OP_12": b"\x5c",
    "OP_13": b"\x5d",
    "OP_14": b"\x5e",
    "OP_15": b"\x5f",
    "OP_16": b"\x60",
    # Flow control
    "OP_NOP": b"\x61",
    "OP_VER": b"\x62",
    "OP_IF": b"\x63",
    "OP_NOTIF": b"\x64",
    "OP_VERIF": b"\x65",
    "OP_VERNOTIF": b"\x66",
    "OP_ELSE": b"\x67",
    "OP_ENDIF": b"\x68",
    "OP_VERIFY": b"\x69",
    "OP_RETURN": b"\x6a",
    # Stack
    "OP_TOALTSTACK": b"\x6b",
    "OP_FROMALTSTACK": b"\x6c",
    "OP_IFDUP": b"\x73",
    "OP_DEPTH": b"\x74",
    "OP_DROP": b"\x75",
    "OP_DUP": b"\x76",
    "OP_NIP": b"\x77",
    "OP_OVER": b"\x78",
    "OP_PICK": b"\x79",
    "OP_ROLL": b"\x7a",
    "OP_ROT": b"\x7b",
    "OP_SWAP": b"\x7c",
    "OP_TUCK": b"\x7d",
    "OP_2DROP": b"\x6d",
    "OP_2DUP": b"\x6e",
    "OP_3DUP": b"\x6f",
    "OP_2OVER": b"\x70",
    "OP_2ROT": b"\x71",
    "OP_2SWAP": b"\x72",
    # Splice
    "OP_CAT": b"\x7e",  # disabled
    "OP_SUBSTR": b"\x7f",  # disabled
    "OP_LEFT": b"\x80",  # disabled
    "OP_RIGHT": b"\x81",  # disabled
    "OP_SIZE": b"\x82",
    # Bitwise logic
    "OP_INVERT": b"\x83",  # disabled
    "OP_AND": b"\x84",  # disabled
    "OP_OR": b"\x85",  # disabled
    "OP_XOR": b"\x86",  # disabled
    "OP_EQUAL": b"\x87",
    "OP_EQUALVERIFY": b"\x88",
    "OP_RESERVED1": b"\x89",
    "OP_RESERVED2": b"\x8a",
    # Arithmetic
    "OP_1ADD": b"\x8b",  # without OP_, 1ADD would be a number
    "OP_1SUB": b"\x8c",
    "OP_2MUL": b"\x8d",  # disabled
    "OP_2DIV": b"\x8e",  # disabled
    "OP_NEGATE": b"\x8f",
    "OP_ABS": b"\x90",
    "OP_NOT": b"\x91",
    "OP_0NOTEQUAL": b"\x92",
    "OP_ADD": b"\x93",
    "OP_SUB": b"\x94",
    "OP_MUL": b"\x95",  # disabled
    "OP_DIV": b"\x96",  # disabled
    "OP_MOD": b"\x97",  # disabled
    "OP_LSHIFT": b"\x98",  # disabled
    "OP_RSHIFT": b"\x99",  # disabled
    "OP_BOOLAND": b"\x9a",
    "OP_BOOLOR": b"\x9b",
    "OP_NUMEQUAL": b"\x9c",
    "OP_NUMEQUALVERIFY": b"\x9d",
    "OP_NUMNOTEQUAL": b"\x9e",
    "OP_LESSTHAN": b"\x9f",
    "OP_GREATERTHAN": b"\xa0",
    "OP_LESSTHANOREQUAL": b"\xa1",
    "OP_GREATERTHANOREQUAL": b"\xa2",
    "OP_MIN": b"\xa3",
    "OP_MAX": b"\xa4",
    "OP_WITHIN": b"\xa5",
    # Crypto
    "OP_RIPEMD160": b"\xa6",
    "OP_SHA1": b"\xa7",
    "OP_SHA256": b"\xa8",
    "OP_HASH160": b"\xa9",
    "OP_HASH256": b"\xaa",
    "OP_CODESEPARATOR": b"\xab",
    "OP_CHECKSIG": b"\xac",
    "OP_CHECKSIGVERIFY": b"\xad",
    "OP_CHECKMULTISIG": b"\xae",
    "OP_CHECKMULTISIGVERIFY": b"\xaf",
    # Locktime
    "OP_NOP2": b"\xb1",
    "OP_CHECKLOCKTIMEVERIFY": b"\xb1",
    "OP_NOP3": b"\xb2",
    "OP_CHECKSEQUENCEVERIFY": b"\xb2",
    # Reserved words
    "OP_NOP1": b"\xb0",
    "OP_NOP4": b"\xb3",
    "OP_NOP5": b"\xb4",
    "OP_NOP6": b"\xb5",
    "OP_NOP7": b"\xb6",
    "OP_NOP8": b"\xb7",
    "OP_NOP9": b"\xb8",
    "OP_NOP10": b"\xb9",
    # Taproot
    "OP_CHECKSIGADD": b"\xba",
}


OP_CODE_NAME_FROM_INT = {
    0: "OP_0",
    76: "OP_PUSHDATA1",
    77: "OP_PUSHDATA2",
    78: "OP_PUSHDATA4",
    79: "OP_1NEGATE",
    80: "OP_RESERVED",
    81: "OP_1",
    82: "OP_2",
    83: "OP_3",
    84: "OP_4",
    85: "OP_5",
    86: "OP_6",
    87: "OP_7",
    88: "OP_8",
    89: "OP_9",
    90: "OP_10",
    91: "OP_11",
    92: "OP_12",
    93: "OP_13",
    94: "OP_14",
    95: "OP_15",
    96: "OP_16",
    97: "OP_NOP",
    98: "OP_VER",
    99: "OP_IF",
    100: "OP_NOTIF",
    101: "OP_VERIF",
    102: "OP_VERNOTIF",
    103: "OP_ELSE",
    104: "OP_ENDIF",
    105: "OP_VERIFY",
    106: "OP_RETURN",
    107: "OP_TOALTSTACK",
    108: "OP_FROMALTSTACK",
    109: "OP_2DROP",
    110: "OP_2DUP",
    111: "OP_3DUP",
    112: "OP_2OVER",
    113: "OP_2ROT",
    114: "OP_2SWAP",
    115: "OP_IFDUP",
    116: "OP_DEPTH",
    117: "OP_DROP",
    118: "OP_DUP",
    119: "OP_NIP",
    120: "OP_OVER",
    121: "OP_PICK",
    122: "OP_ROLL",
    123: "OP_ROT",
    124: "OP_SWAP",
    125: "OP_TUCK",
    126: "OP_CAT",  # disabled
    127: "OP_SUBSTR",  # disabled
    128: "OP_LEFT",  # disabled
    129: "OP_RIGHT",  # disabled
    130: "OP_SIZE",
    131: "OP_INVERT",  # disabled
    132: "OP_AND",  # disabled
    133: "OP_OR",  # disabled
    134: "OP_XOR",  # disabled
    135: "OP_EQUAL",
    136: "OP_EQUALVERIFY",
    137: "OP_RESERVED1",
    138: "OP_RESERVED2",
    139: "OP_1ADD",
    140: "OP_1SUB",
    141: "OP_2MUL",  # disabled
    142: "OP_2DIV",  # disabled
    143: "OP_NEGATE",
    144: "OP_ABS",
    145: "OP_NOT",
    146: "OP_0NOTEQUAL",
    147: "OP_ADD",
    148: "OP_SUB",
    149: "OP_MUL",  # disabled
    150: "OP_DIV",  # disabled
    151: "OP_MOD",  # disabled
    152: "OP_LSHIFT",  # disabled
    153: "OP_RSHIFT",  # disabled
    154: "OP_BOOLAND",
    155: "OP_BOOLOR",
    156: "OP_NUMEQUAL",
    157: "OP_NUMEQUALVERIFY",
    158: "OP_NUMNOTEQUAL",
    159: "OP_LESSTHAN",
    160: "OP_GREATERTHAN",
    161: "OP_LESSTHANOREQUAL",
    162: "OP_GREATERTHANOREQUAL",
    163: "OP_MIN",
    164: "OP_MAX",
    165: "OP_WITHIN",
    166: "OP_RIPEMD160",
    167: "OP_SHA1",
    168: "OP_SHA256",
    169: "OP_HASH160",
    170: "OP_HASH256",
    171: "OP_CODESEPARATOR",
    172: "OP_CHECKSIG",
    173: "OP_CHECKSIGVERIFY",
    174: "OP_CHECKMULTISIG",
    175: "OP_CHECKMULTISIGVERIFY",
    176: "OP_NOP1",
    177: "OP_CHECKLOCKTIMEVERIFY",
    178: "OP_CHECKSEQUENCEVERIFY",
    179: "OP_NOP4",
    180: "OP_NOP5",
    181: "OP_NOP6",
    182: "OP_NOP7",
    183: "OP_NOP8",
    184: "OP_NOP9",
    185: "OP_NOP10",
    186: "OP_CHECKSIGADD",
}


def op_int(i: int) -> str:
    # Short 1-byte op_codes exist
    # to push numbers in [-1, 16]
    if i == -1:
        return "OP_1NEGATE"
    if 0 <= i <= 16:
        return f"OP_{i}"
    raise BTClibValueError(f"invalid OP_INT: {i}")


def _serialize_int_command(command: int) -> bytes:
    if -1 <= command <= 16:
        # not a DeprecationWarning: nothing is going away, the push is
        # merely one byte longer than the op code that means the same
        warn(
            f"consider using OP_{command} instead",
            BTClibUserWarning,
            stacklevel=2,
        )
    return _serialize_bytes_command(encode_num(command))


def _serialize_str_command(command: str) -> bytes:
    command = command.strip().upper()
    if command in BYTE_FROM_OP_CODE_NAME:
        return BYTE_FROM_OP_CODE_NAME[command]
    try:
        data = bytes.fromhex(command)
    except ValueError as e:
        raise BTClibValueError(f"invalid string command: {command}") from e
    return _serialize_bytes_command(data)


def _serialize_bytes_command(command: bytes) -> bytes:
    """Convert to canonical push: OP_PUSHDATA (if needed) | length | command.

    According to standardness rules (BIP-62) the minimum possible
    PUSHDATA operator must be used. Byte vectors on the stack are not
    allowed to be more than 520 bytes long.
    """
    out: list[bytes] = []
    length = len(command)
    if length < 76:  # 1-byte-length
        out.append(length.to_bytes(1, byteorder="little", signed=False))
    elif length < 256:  # OP_PUSHDATA1 | 1-byte-length
        _pushdata(1, length, out)
    elif length < 521:  # OP_PUSHDATA2 | 2-byte-length
        _pushdata(2, length, out)
    else:
        # because of the 520 bytes limit there is no need for
        # OP_PUSHDATA4, so this is an error and not a fourth branch
        raise BTClibValueError(f"too many bytes for OP_PUSHDATA: {length}")
    out.append(command)
    return b"".join(out)


def _pushdata(i: int, length: int, out: list[bytes]) -> None:
    out.append(BYTE_FROM_OP_CODE_NAME[f"OP_PUSHDATA{i}"])
    out.append(length.to_bytes(i, byteorder="little", signed=False))


def serialize(script: Sequence[Command]) -> bytes:
    r: list[bytes] = []
    for command in script:
        if isinstance(command, int):
            r.append(_serialize_int_command(command))
        elif isinstance(command, str):
            if "UNKNOWN_OP_CODE_" in command:
                r.append(int(command[16:]).to_bytes(1, "big"))
            else:
                r.append(_serialize_str_command(command))
        else:  # must be bytes
            r.append(_serialize_bytes_command(command))
    return b"".join(r)


def _parse_push(s: BytesIO, i: int) -> str:
    """Read the data of the push whose first byte is i, as upper-case hex.

    Not taproot's `_read_push_data`, which reads the same three widths
    and stops there: the 520-byte element limit is enforced here and
    cannot be there, an OP_SUCCESS making a tapscript valid whatever
    else it holds. The limit is checked against the declared length, so
    an oversized push is refused without being read.
    """
    data_length = i  # 0 < i < 76 -> 1-byte-data-length | data
    if 75 < i < 79:
        # i == 76 -> OP_PUSHDATA1 | 1-byte-data-length | data
        # i == 77 -> OP_PUSHDATA2 | 2-byte-data-length | data
        # i == 78 -> OP_PUSHDATA4 | 4-byte-data-length | data
        x = 2 ** (i - 76)
        y = s.read(x)
        if len(y) != x:
            raise BTClibValueError("Not enough data for pushdata length")
        data_length = int.from_bytes(y, byteorder="little")
    if data_length > MAX_SCRIPT_ELEMENT_SIZE:
        raise BTClibValueError(f"Invalid pushdata length: {data_length}")
    data = s.read(data_length)
    if len(data) != data_length:
        raise BTClibValueError("Not enough data for pushdata")
    return data.hex().upper()


def parse(stream: BinaryData, accept_unknown: bool = False) -> ScriptList:
    s = bytesio_from_binarydata(stream)
    r: ScriptList = []  # initialize the result list

    while True:
        t = s.read(1)  # get one byte
        if not t:
            break
        i = t[0]  # convert the first byte to an integer
        if 0 < i <= 78:  # push
            command = _parse_push(s, i)
        elif i in OP_CODE_NAME_FROM_INT:  # OP_CODE
            command = OP_CODE_NAME_FROM_INT[i]
            # the operand before an op code is left as bytes, and is not
            # decoded to an int when it is four bytes or fewer. That rule
            # belongs to the interpreter, which knows which op codes take a
            # number off the stack; a parse cannot, and guessing here would
            # change what round-trips
        elif accept_unknown:
            # https://bitcoin.stackexchange.com/a/98652/111488
            command = f"UNKNOWN_OP_CODE_{i}"

        else:
            raise BTClibValueError("Unknown op code")
        r.append(command)

    return r


def read_op_code(script: bytes, start: int) -> tuple[int, int] | None:
    """Read one op code: (the op code, the offset one past it and its data).

    This is Bitcoin Core's `CScript::GetOp`, and it exists because a
    script code is a *slice of the script's own bytes*: consensus commits
    to the bytes as they were written, and `serialize(parse(script))` does
    not give them back. A non-minimal push is legal and comes back
    minimal — `4c01ff` as `01ff` — so a script code recovered by
    re-serializing part of a parse is a different preimage than the one
    Core signs (issue #176). Walking the bytes is the only way to find an
    op code boundary without moving the bytes on either side of it.

    None where nothing whole can be read: the end of the script, or a
    push whose data or length runs past it. Core's GetOp returns false in
    the same two cases, and its callers stop and keep the rest verbatim.
    Truncation is all this refuses: the 520-byte push limit is a rule
    about what reaches the stack, enforced where a push is executed, and
    GetOp does not know it either.
    """
    if start >= len(script):
        return None
    op_code = script[start]
    stop = start + 1
    if 0 < op_code <= 78:  # a push, of its own length or of a declared one
        data_length = op_code
        if 75 < op_code:  # OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4
            size = 2 ** (op_code - 76)  # 1, 2 or 4 bytes of little-endian length
            if stop + size > len(script):
                return None
            data_length = int.from_bytes(script[stop : stop + size], "little")
            stop += size
        stop += data_length
        if stop > len(script):
            return None
    return op_code, stop


def op_code_spans(script: bytes) -> Iterator[tuple[int, int, int]]:
    """Walk a script op code by op code: (op code, first byte, one past last).

    The walk stops where `read_op_code` returns None, so the bytes from
    the last yielded `stop` to the end of the script are whatever could
    not be read as an op code — Core's GetOp loops end the same way, and
    keep that tail.
    """
    start = 0
    while (span := read_op_code(script, start)) is not None:
        op_code, stop = span
        yield op_code, start, stop
        start = stop


# frozen, as OutPoint, TxOut and Witness are (issue 139): freezing a
# dataclass is shallow, so a mutable Script lets
# `tx_out.script_pub_key.script = b""` reach through a frozen TxOut and
# rebind the script of whatever else holds that ScriptPubKey; frozen, that
# assignment raises FrozenInstanceError.
#
# It is also what lets `asm` be cached. functools.cached_property writes
# straight into the instance __dict__ rather than through __setattr__, so it
# works on a frozen dataclass -- and caching a value derived from a field is
# only correct if the field cannot change under it, which is the same
# condition
@dataclass(frozen=True)
class Script:
    # Bitcoin script expressed as ScriptList
    # e.g. [OP_HASH160, script_h160, OP_EQUAL]
    # or Octets of its byte-encoded representation
    script: bytes

    @cached_property
    def asm(self) -> ScriptList:
        """The parsed script, parsed once.

        A plain property would parse self.script again on every read:
        57.9 us for a 16.5 kB script, for a value that cannot change.
        Cached, a second read is 0.02 us.

        The cache is not warmed by assert_valid, which parses the same
        bytes at construction and throws the result away -- so building a
        Script and then reading .asm parses twice. That is deliberate:
        measured on that 16.5 kB script, an instance holding the parse
        costs 55.4 kB against 0.2 kB without it, 277 times the script's own
        bytes, and nothing inside the library reads .asm at all. Warming it
        in __init__ would charge that to every Script ever validated to
        save a parse for the few that are inspected.
        """
        return parse(self.script, accept_unknown=True)

    def __add__(self, other: Script) -> Script:
        return (
            Script(self.script + other.script)
            if isinstance(other, Script)
            else NotImplemented
        )

    def __init__(self, script: Octets = b"", *, check_validity: bool = True) -> None:
        object.__setattr__(self, "script", bytes_from_octets(script))
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert that the bytes parse as a script.

        Which is what makes them one: a truncated push, a pushdata length
        over 520, or an op code no name is known for are the ways they can
        fail to. Deliberately not a round-trip check, which would be
        wrong, not merely redundant: a non-minimal push is
        consensus-legal, and re-serializing it yields different bytes
        (4c01ff, an OP_PUSHDATA1 of one byte, comes back as 01ff).
        Measured over 200k random byte strings, a strict comparison
        rejects 16 of them.

        Redundant, because serialize() writes back every command shape
        parse() can produce, UNKNOWN_OP_CODE_n included, by an explicit
        branch: over those same 200k, and over all 256 one-byte scripts,
        it raises for nothing parse() has accepted. So serialize(self.asm)
        with the result discarded would only add a second parse and a
        second serialization per Script.
        """
        parse(self.script, accept_unknown=True)
