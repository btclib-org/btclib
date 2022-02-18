#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin Script.

https://en.bitcoin.it/wiki/Script

Scripts are represented by List[Command], where Command = Union[int, str, bytes]

* ascii string are for opcodes (e.g. 'OP_HASH160', 'OP_1', 'OP_1NEGATE', etc.)
* hex-string or bytes (i.e., Octets) are for data
"""

from dataclasses import dataclass
from typing import List, Sequence, Union
from warnings import warn

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, encode_num

BYTE_FROM_OP_CODE_NAME = {
    # Constants
    "OP_0": b"\x00",
    "OP_FALSE": b"\x00",
    "OP_PUSHDATA1": b"\x4c",
    "OP_PUSHDATA2": b"\x4d",
    "OP_PUSHDATA4": b"\x4e",
    "OP_1NEGATE": b"\x4f",
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
    "OP_SIZE": b"\x82",
    # Bitwise logic
    "OP_EQUAL": b"\x87",
    "OP_EQUALVERIFY": b"\x88",
    "OP_RESERVED1": b"\x89",
    "OP_RESERVED2": b"\x8a",
    # Arithmetic
    "OP_1ADD": b"\x8b",  # without OP_, 1ADD would be a number
    "OP_1SUB": b"\x8c",
    "OP_NEGATE": b"\x8f",
    "OP_ABS": b"\x90",
    "OP_NOT": b"\x91",
    "OP_0NOTEQUAL": b"\x92",
    "OP_ADD": b"\x93",
    "OP_SUB": b"\x94",
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
    130: "OP_SIZE",
    135: "OP_EQUAL",
    136: "OP_EQUALVERIFY",
    137: "OP_RESERVED1",
    138: "OP_RESERVED2",
    139: "OP_1ADD",
    140: "OP_1SUB",
    143: "OP_NEGATE",
    144: "OP_ABS",
    145: "OP_NOT",
    146: "OP_0NOTEQUAL",
    147: "OP_ADD",
    148: "OP_SUB",
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


Command = Union[int, str, bytes]


def _serialize_int_command(command: int) -> bytes:
    if -1 <= command <= 16:
        warn(f"consider using OP_{command} instead")
    return _serialize_bytes_command(encode_num(command))


def _serialize_str_command(command: str) -> bytes:
    command = command.strip().upper()
    if command in BYTE_FROM_OP_CODE_NAME:
        return BYTE_FROM_OP_CODE_NAME[command]
    if command[:10] == "OP_SUCCESS":
        x = int(command[10:])
        if x in OP_CODE_NAME_FROM_INT or 0 < x < 76:
            raise BTClibValueError(f"invalid OP_SUCCESS number: {x}")
        return x.to_bytes(1, "little")
    try:
        data = bytes.fromhex(command)
    except ValueError as e:
        raise BTClibValueError(f"invalid string command: {command}") from e
    return _serialize_bytes_command(data)


def _serialize_bytes_command(command: bytes) -> bytes:
    """Convert to canonical push: OP_PUSHDATA (if needed) | length | command.

    According to standardness rules (BIP-62) the
    minimum possible PUSHDATA operator must be used.
    Byte vectors on the stack are not allowed to be more than 520 bytes long.
    """

    out: List[bytes] = []
    length = len(command)
    if length < 76:  # 1-byte-length
        out.append(length.to_bytes(1, byteorder="little", signed=False))
    elif length < 256:  # OP_PUSHDATA1 | 1-byte-length
        out.append(BYTE_FROM_OP_CODE_NAME["OP_PUSHDATA1"])
        out.append(length.to_bytes(1, byteorder="little", signed=False))
    elif length < 521:  # OP_PUSHDATA2 | 2-byte-length
        out.append(BYTE_FROM_OP_CODE_NAME["OP_PUSHDATA2"])
        out.append(length.to_bytes(2, byteorder="little", signed=False))
    else:
        # because of the 520 bytes limit
        # there is no need to use OP_PUSHDATA4
        # out.append(BYTE_FROM_OP_CODE_NAME['OP_PUSHDATA4'])
        # out.append(length.to_bytes(4, byteorder="little", signed=False))
        raise BTClibValueError(f"too many bytes for OP_PUSHDATA: {length}")
    out.append(command)
    return b"".join(out)


def serialize(script: Sequence[Command]) -> bytes:
    r: List[bytes] = []
    for command in script:
        if isinstance(command, int):
            r.append(_serialize_int_command(command))
        elif isinstance(command, str):
            r.append(_serialize_str_command(command))
        else:  # must be bytes
            r.append(_serialize_bytes_command(command))
    return b"".join(r)


def parse(stream: BinaryData, exit_on_op_success: bool = False) -> List[Command]:

    s = bytesio_from_binarydata(stream)
    r: List[Command] = []  # initialize the result list

    while True:

        t = s.read(1)  # get one byte
        if not t:
            break
        i = t[0]  # convert the first byte to an integer
        if 0 < i <= 78:  # push
            data_length = i  # 0 < i < 76 -> 1-byte-data-length | data
            if 75 < i < 79:
                # i == 76 -> OP_PUSHDATA1 | 1-byte-data-length | data
                # i == 77 -> OP_PUSHDATA2 | 2-byte-data-length | data
                x = i - 75
                if i == 78:  # OP_PUSHDATA4 | 4-byte-data-length | data
                    x = 4
                y = s.read(x)
                if len(y) != x:
                    raise BTClibValueError("Not enough data for pushdata length")
                data_length = int.from_bytes(y, byteorder="little")
                if data_length > 520:
                    raise BTClibValueError(f"Invalid pushdata length: {data_length}")
            data = s.read(data_length)
            if len(data) != data_length:
                raise BTClibValueError("Not enough data for pushdata")
            command = data.hex().upper()
        elif i in OP_CODE_NAME_FROM_INT:  # OP_CODE
            command = OP_CODE_NAME_FROM_INT[i]
            # Opcodes which take integers and bools off the stack require
            # that they be no more than 4 bytes long.
            # If this is the case, parse that command as int
            # t = r[-1]
            # if isinstance(t, bytes) and len(t) <= 4:
            #    r[-1] = decode_num(t)
        else:  # OP_SUCCESSx
            command = f"OP_SUCCESS{i}"
            if exit_on_op_success:
                return ["OP_SUCCESS"]

        r.append(command)

    return r


@dataclass
class Script:
    # Bitcoin script expressed as List[Command]
    # e.g. [OP_HASH160, script_h160, OP_EQUAL]
    # or Octets of its byte-encoded representation
    script: bytes

    @property
    def asm(self) -> List[Command]:
        return parse(self.script)

    def __add__(self, other: object):

        if not isinstance(other, Script):
            return NotImplemented

        return Script(self.script + other.script)

    def __init__(self, script: Octets = b"", check_validity: bool = True) -> None:
        self.script = bytes_from_octets(script)
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        serialize(self.asm)
