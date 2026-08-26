# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Script.

https://en.bitcoin.it/wiki/Script

Scripts are represented by list[Command], where Command = int | str | bytes

* an ascii string is an op code name (e.g. 'OP_HASH160', 'OP_1NEGATE')
* a hex-string or bytes (i.e., Octets) are data

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

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import cached_property
from io import BytesIO
from typing import cast
from warnings import warn

from btclib.alias import BinaryData, Command, Octets, ScriptList
from btclib.exceptions import BTClibTypeError, BTClibUserWarning, BTClibValueError
from btclib.utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    encode_num,
    fields_from_json_object,
    is_octets,
)

__all__ = [
    "BYTE_FROM_OP_CODE_NAME",
    "ERROR_COMMAND",
    "OP_CODE_NAME_FROM_INT",
    "Script",
    "op_code_spans",
    "op_int",
    "parse",
    "push_int",
    "read_op_code",
    "script_from_dict",
    "script_to_dict",
    "serialize",
]

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


# What parse appends where the bytes stop being a script, spelled as
# Bitcoin Core's ScriptToAsmStr spells it. Display-only, deliberately: it
# marks a place in the script rather than an instruction, so serialize
# refuses it -- "invalid string command: [ERROR]" -- where
# UNKNOWN_OP_CODE_n must and does round-trip, being a legitimate byte of
# an executable script. Nothing is lost by that: a Script is its bytes,
# and Core's asm is not invertible either, printing a short push as a
# decimal number and a non-minimal push as a minimal one.
ERROR_COMMAND = "[error]"


def op_int(i: int) -> str:
    """Name the one-byte op code that pushes the number i, -1 to 16.

    OP_0..OP_16 and OP_1NEGATE are the only numbers with an op code of
    their own; any other integer is refused, a caller wanting it pushed
    passing the integer itself to serialize.
    """
    # Short 1-byte op_codes exist
    # to push numbers in [-1, 16]
    if i == -1:
        return "OP_1NEGATE"
    if 0 <= i <= 16:
        return f"OP_{i}"
    raise BTClibValueError(f"invalid OP_INT: {i}")


def push_int(i: int) -> str:
    """Return the shortest command that pushes the number i.

    The op code where the number has one -- `op_int`, -1 to 16 -- and the
    CScriptNum encoding of it otherwise, as the hex a data push is
    written as. Both halves are here already; this is the choice between
    them, which is what a caller assembling a script by hand writes out
    every time it puts a number in one: a threshold, a relative timelock,
    a size. Which half applies is a property of the value and not of what
    the number means, so a script template holding 16 and one holding 17
    are written the same way and serialize differently.

    `serialize` reaches the same bytes from the integer itself for
    everything above 16, and warns for -1 to 16 that the op code is one
    byte shorter: this is that op code, so the warning is the caller
    being told to write this instead. Minimal because the consumers are:
    `miniscript.from_script` refuses a push written the long way, and the
    interpreter refuses it too under MINIMALDATA, so a number pushed with
    a byte to spare is a script that reads as nothing and may not spend.
    """
    return op_int(i) if -1 <= i <= 16 else encode_num(i).hex()


def _serialize_int_command(command: int) -> bytes:
    if -1 <= command <= 16 and command != 0:
        # not a DeprecationWarning: nothing is going away, the push is
        # merely one byte longer than the op code that means the same.
        # Zero is not among them: its encoding is the empty vector, so
        # the push of it is OP_0 already and there is nothing to suggest
        warn(
            f"consider using {op_int(command)} instead",
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


def _serialize_bytes_command(command: bytes | bytearray | memoryview) -> bytes:
    """Convert to canonical push: OP_PUSHDATA (if needed) | length | command.

    According to standardness rules (BIP62) the minimum possible
    PUSHDATA operator must be used.

    The minimal push *operator*, and never the one-byte op code that
    pushes the same value: a bytes command holding the single byte 0x01
    is written ``0101``, as every other one-byte push is, and not OP_1
    (issue #646). Core's own split, and for Core's reason: its
    `AppendDataSize` writes a length for whatever vector it is handed,
    and `push_int64` -- reached from `CScriptNum` and from an integer,
    never from a byte vector -- is the only thing that reaches for OP_0,
    OP_1NEGATE or OP_1..OP_16. It has to be that way here too, because
    only the caller knows whether those bytes mean a number: `push_int`
    is where one that means a number says so, and `op_int` is the op
    code it names.

    Three readers depend on it, each measuring a push against what this
    writes for its data: `engine.script_op_codes.assert_minimal_push`,
    `miniscript._assert_minimal_push`, and -- differently --
    `engine.script.calculate_script_code`, which builds the needle
    FindAndDelete searches for as Core builds it, `CScript() << vchSig`.
    A one-byte push of 0x00 is what the first two hand this, Core's
    `CheckMinimalPush` accepting it as data of one byte where OP_0
    pushes no bytes at all; substituting the op code would refuse the
    push Core accepts, and would have FindAndDelete search for bytes the
    script code cannot hold.

    All four widths, OP_PUSHDATA4 included, because what parse reads
    serialize must be able to write back: a push over 520 bytes is one
    the stack cannot hold, i.e. a script no one can spend, and not one
    that cannot be encoded -- there are such pushes on chain (issue
    #123). The last branch is Core's own bound, `CScript::operator<<`
    having nothing wider than a four-byte length either.
    """
    out: list[bytes | bytearray | memoryview] = []
    length = len(command)
    if length < 76:  # 1-byte-length
        out.append(length.to_bytes(1, byteorder="little", signed=False))
    elif length < 256:  # OP_PUSHDATA1 | 1-byte-length
        _pushdata(1, length, out)
    elif length < 65536:  # OP_PUSHDATA2 | 2-byte-length
        _pushdata(2, length, out)
    elif length < 4294967296:  # OP_PUSHDATA4 | 4-byte-length
        _pushdata(4, length, out)
    else:
        raise BTClibValueError(f"too many bytes for OP_PUSHDATA: {length}")
    out.append(command)
    return b"".join(out)


def _pushdata(i: int, length: int, out: list[bytes | bytearray | memoryview]) -> None:
    out.extend(
        (
            BYTE_FROM_OP_CODE_NAME[f"OP_PUSHDATA{i}"],
            length.to_bytes(i, byteorder="little", signed=False),
        )
    )


def serialize(script: Sequence[Command]) -> bytes:
    """Serialize a script from its commands.

    An integer is encoded as the number it pushes -- with a warning
    where a one-byte op code means the same, and a refusal outside the
    int64 a script number is -- a string is an op code name, an
    UNKNOWN_OP_CODE_n byte, or hex data, and bytes are data; data is
    always the minimal push operator, per BIP62. What parse returns
    round-trips, ERROR_COMMAND excepted, that marker being a place in
    the bytes rather than an instruction.

    The minimal *operator* and not the minimal *command*: data is data,
    so the bytes 0x01 are pushed with a length of one and not with OP_1,
    and the same goes for an integer command, which is the number's
    bytes and is warned about for exactly this. `push_int` is what
    writes a number the shortest way there is, and what every caller in
    this library that means one uses.

    Zero is where the two coincide and the warning therefore stops: the
    empty vector is what `encode_num` writes for it, and the push of an
    empty vector is OP_0, so `serialize([0])` is the op code -- as Core's
    `CScript() << 0` is -- with nothing shorter left to suggest.

    A sequence of commands and not one command: `Sequence[Command]`
    accepts a `str` and a `bytes`, each of them being a sequence of
    `Command` as far as the type goes, so `serialize("OP_DUP")` was six
    one-character commands and a `bytes` handed here a script of one
    integer command per byte -- the first refused for a character it
    could not read as an op code, the second accepted and wrong. What
    is not a sequence at all was "not iterable" from underneath the
    library.
    """
    # `is_octets` is the four spellings named once, so a spelling
    # `Octets` gains later is refused here too (issue #1420)
    if is_octets(script) or not isinstance(script, Sequence):
        err_msg = f"invalid script commands type: {type(script).__name__}"
        raise BTClibTypeError(err_msg)

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


def _parse_push(s: BytesIO, i: int) -> str | None:
    """Read the data of the push whose first byte is i, as upper-case hex.

    None where nothing whole can be read -- a declared length cut short,
    or data short of it -- which is where Core's GetOp returns false, and
    it is all this refuses. No element limit: 520 bounds what reaches the
    stack, so a longer push is a script no one can spend and not one that
    cannot be read, which is issue #123 and the five transactions in it.
    Taproot's `_read_push_data` reads the same three widths, and refuses
    an oversized element at the end of its own walk instead: there an
    OP_SUCCESSx met first makes the script valid whatever else it holds.
    """
    data_length = i  # 0 < i < 76 -> 1-byte-data-length | data
    if 75 < i < 79:
        # i == 76 -> OP_PUSHDATA1 | 1-byte-data-length | data
        # i == 77 -> OP_PUSHDATA2 | 2-byte-data-length | data
        # i == 78 -> OP_PUSHDATA4 | 4-byte-data-length | data
        x = 2 ** (i - 76)
        y = s.read(x)
        if len(y) != x:
            return None
        data_length = int.from_bytes(y, byteorder="little")
    data = s.read(data_length)
    if len(data) != data_length:
        return None
    return data.hex().upper()


def parse(stream: BinaryData) -> ScriptList:
    """Decode a script, as Bitcoin Core decodes one.

    Which is to say: whatever the bytes are. Core's only decoder is
    `GetScriptOp`, it reads one instruction at a time, and the sole thing
    it refuses is a push running past the end of the script -- where the
    walk stops, and ERROR_COMMAND is appended in the place Core's
    `ScriptToAsmStr` writes the same "[error]". Every other question,
    the element limit and the op codes no valid script may execute among
    them, belongs to the interpreter and is asked there; a script it
    would refuse still decodes, exactly as one that is in a block must
    (issue #123).
    """
    s = bytesio_from_binarydata(stream)
    r: ScriptList = []  # initialize the result list

    while True:
        t = s.read(1)  # get one byte
        if not t:
            break
        i = t[0]  # convert the first byte to an integer
        if 0 < i <= 78:  # push
            data = _parse_push(s, i)
            if data is None:
                # the terminal sentinel: what follows is not a script,
                # and there is nothing after it to decode
                r.append(ERROR_COMMAND)
                break
            command = data
        elif i in OP_CODE_NAME_FROM_INT:  # OP_CODE
            command = OP_CODE_NAME_FROM_INT[i]
            # the operand before an op code is left as bytes, and is not
            # decoded to an int when it is four bytes or fewer. That rule
            # belongs to the interpreter, which knows which op codes take a
            # number off the stack; a parse cannot, and guessing here would
            # change what round-trips
        else:
            # https://bitcoin.stackexchange.com/a/98652/111488
            # A byte no table names is an op code all the same, and one
            # the interpreter refuses when it executes it; naming it here
            # is what lets serialize write it back unchanged
            command = f"UNKNOWN_OP_CODE_{i}"
        r.append(command)

    return r


def script_to_dict(script: bytes) -> dict[str, str]:
    """Render a script as Bitcoin Core's RPC renders one: `asm` and `hex`.

    The two renderings of the same bytes, which is what
    `getrawtransaction` and `decodepsbt` hand back for every script they
    report. `hex` is the script; `asm` is `parse` joined by spaces, i.e.
    a reading aid, and the only thing `script_from_dict` will believe is
    the `hex`.

    Not Core's asm byte for byte, and it cannot be: btclib prints a push
    as upper-case hex where Core prints one under 5 bytes as a decimal
    number, and neither spelling is invertible -- see ERROR_COMMAND
    above. What this is, exactly, is `Script.asm` with a space between
    its commands.
    """
    # a cast rather than a str() per command: parse appends nothing but
    # strings -- an op code name, upper-case hex, UNKNOWN_OP_CODE_n or
    # ERROR_COMMAND -- and its return type is the wider ScriptList only
    # because that alias is shared with serialize, which does take ints
    # and bytes. str() would silently render a bytes command as "b'..'"
    # instead, and an isinstance filter would be a branch no input takes
    commands: list[str] = cast("list[str]", parse(script))
    return {"asm": " ".join(commands), "hex": script.hex()}


def script_from_dict(value: Mapping[str, str] | Octets) -> bytes:
    """Read back what `script_to_dict` wrote: the `hex`, and only it.

    `asm` is derived from `hex`, so there is nothing in it to read. It is
    still not ignored: a dict carrying an `asm` that the `hex` does not
    produce is refused, naming both. Ignoring it would let a hand-edited
    `asm` sit in a stored dict describing a script that is not the one
    the bytes hold, and every consumer that reads the human-readable
    field -- a diff, a review, an explorer -- would then be reading a
    lie, silently. Believing the `asm` instead is not on offer: it is
    lossy (a non-minimal push comes back minimal, `[error]` comes back
    not at all), so it cannot name every script `hex` can.

    A bare hex string is accepted as well, which is the shape `to_dict`
    emitted before it emitted this one. Every constructor downstream
    already takes `Octets`, so accepting it costs one branch and keeps a
    dict stored by an older btclib readable -- the emission is what
    changed, and a reader that refused the old spelling would break
    round trips that never had an `asm` to disagree with.
    """
    if not isinstance(value, Mapping):
        return bytes_from_octets(value)

    value = fields_from_json_object(value, "script")
    script = bytes_from_octets(value["hex"])
    asm = value.get("asm")
    # compared against what to_dict would emit, not against a second
    # renderer: one function decides the spelling, so the check cannot
    # drift away from what it checks
    if asm is not None and asm != (expected := script_to_dict(script)["asm"]):
        err_msg = f"asm does not match hex: {asm!r} instead of {expected!r}"
        raise BTClibValueError(err_msg)
    return script


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
        if op_code > 75:  # OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4
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
    """A Bitcoin script, held as its bytes.

    The bytes are the script -- assert_valid asks nothing else of them
    -- and `asm` is their parse, computed on first read and cached.
    Immutable, so a Script can be shared and concatenated (`+`) without
    aliasing surprises; ScriptPubKey extends it with a network.
    """

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

        Nothing warms the cache: construction does not parse, and
        __init__ filling the cache in would be the wrong trade --
        measured on that 16.5 kB script, an instance holding the parse
        costs 55.4 kB against 0.2 kB without it, 277 times the script's
        own bytes, and nothing inside the library reads .asm.
        """
        return parse(self.script)

    def __add__(self, other: Script) -> Script:
        return (
            Script(self.script + other.script)
            if isinstance(other, Script)  # type: ignore[redundant-expr]
            else NotImplemented
        )

    def __init__(self, script: Octets = b"", *, check_validity: bool = True) -> None:
        object.__setattr__(self, "script", bytes_from_octets(script))
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert that the script is bytes, which is all a script is.

        There is no other question to ask: Bitcoin Core has no validity
        notion for a script either -- a CScript is a vector of bytes,
        and the only script-level predicate it offers is
        IsUnspendable(), for pruning the UTXO set. Whether a script can
        be *executed* is the interpreter's answer, given by executing
        it, and the limits it enforces depend on the sigversion the
        script is spent under: in tapscript an OP_SUCCESSx makes a
        script valid however malformed the rest of it is, so no
        predicate on the bytes alone could answer for both.

        Not a parse, refusing what the parse refuses -- a push over 520
        bytes, a truncated push, an op code no table names: five
        transactions in blocks 251718 to 299571 carry such scripts, so
        that predicate leaves Tx.parse unable to read them and `.asm`
        raising for the scripts an explorer prints (issue #123).

        The coercion is the check, as it is in Witness.assert_valid: a
        Script built through __init__ has been through bytes_from_octets
        already, and this is what answers for one reached any other way.
        """
        bytes(self.script)
