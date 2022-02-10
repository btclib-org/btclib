#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tapscript OP_CODES"""

from btclib.exceptions import BTClibValueError
from btclib.script.op_codes import (  # noqa pylint: disable=unused-import
    op_int,
    op_num,
    op_pushdata,
)

OP_CODES = {
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
    "OP_IF": b"\x63",
    "OP_NOTIF": b"\x64",
    "OP_VERIF": b"\x65",  # TODO: should remove?
    "OP_VERNOTIF": b"\x66",  # TODO: should remove?
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

OP_CODE_NAMES = {
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
    99: "OP_IF",
    100: "OP_NOTIF",
    101: "OP_VERIF",  # TODO: should remove?
    102: "OP_VERNOTIF",  # TODO: should remove?
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

OP_SUCCESS = [
    80,
    98,
    126,
    127,
    128,
    129,
    131,
    132,
    133,
    134,
    137,
    138,
    141,
    142,
    149,
    150,
    151,
    152,
    153,
    *range(187, 255),
]


def op_str(command: str) -> bytes:
    command = command.strip().upper()
    if command in OP_CODES:
        return OP_CODES[command]
    if command[:10] == "OP_SUCCESS":
        x = int(command[10:])
        if x not in OP_SUCCESS:
            raise BTClibValueError(f"invalid OP_SUCCESS number: {x}")
        return x.to_bytes(1, "little")
    try:
        data = bytes.fromhex(command)
    except ValueError as e:
        raise BTClibValueError(f"invalid string command: {command}") from e
    return op_pushdata(data)
