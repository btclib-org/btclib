#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin Script.

https://en.bitcoin.it/wiki/Script

Scripts are represented by List[ScriptToken], where ScriptToken = Union[int, str, bytes]:

* int [-1, 16] are shorcuts for 'OP_1NEGATE', 'OP_0' - 'OP_16'
* str are for opcodes (e.g. 'OP_HASH160') or hexstring data
* bytes are for data (but integers are often casted to int)
"""

from typing import List

from .alias import BinaryData, Octets, ScriptToken
from .exceptions import BTClibValueError
from .utils import bytes_from_octets, bytesio_from_binarydata

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

SIGHASHES = [
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY + SIGHASH_ALL,
    SIGHASH_ANYONECANPAY + SIGHASH_NONE,
    SIGHASH_ANYONECANPAY + SIGHASH_SINGLE,
]

OP_CODES = {
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
}

OP_CODE_NAMES = {
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
}


def _op_pushdata(data: Octets) -> bytes:
    """Convert to canonical push: OP_PUSHDATA (if needed) | length | data.

    According to standardness rules (BIP-62) the
    minimum possible PUSHDATA operator must be used.
    Byte vectors on the stack are not allowed to be more than 520 bytes long.
    """

    data = bytes_from_octets(data)
    r = b""
    length = len(data)
    if length < 76:  # 1-byte-length
        r += length.to_bytes(1, byteorder="little")
    elif length < 256:  # OP_PUSHDATA1 | 1-byte-length
        r += OP_CODES["OP_PUSHDATA1"]
        r += length.to_bytes(1, byteorder="little")
    elif length < 521:  # OP_PUSHDATA2 | 2-byte-length
        r += OP_CODES["OP_PUSHDATA2"]
        r += length.to_bytes(2, byteorder="little")
    else:
        # because of the 520 bytes limit
        # there is no need to use OP_PUSHDATA4
        # r += OP_CODES['OP_PUSHDATA4']
        # r += length.to_bytes(4, byteorder='little')
        raise BTClibValueError(f"Too many bytes for OP_PUSHDATA: {length}")
    r += data
    return r


def _op_int(token: int) -> bytes:
    # Short 1-byte opcodes exist
    # to push numbers in [-1, 16]
    if 0 <= token <= 16:
        return OP_CODES["OP_" + str(token)]
    if token == -1:
        return OP_CODES["OP_1NEGATE"]
    # Pushing any other number requires an
    # explicit push operation of its bytes encoding
    # FIXME: negative numbers?

    v = token
    # Convert number to bitcoin-specific little endian format
    # We need v.bit_length() bits, plus a sign bit for every nonzero number.
    n_bits = v.bit_length() + (v != 0)
    # The number of bytes for that is:
    n_bytes = (n_bits + 7) // 8
    # Convert number to absolute value + sign in top bit.
    encoded_v = 0 if v == 0 else abs(v) | ((v < 0) << (n_bytes * 8 - 1))
    # Serialize to bytes
    data = encoded_v.to_bytes(n_bytes, "little")
    return _op_pushdata(data)


def _op_str(token: str) -> bytes:
    token = token.strip().upper()
    if token in OP_CODES:
        return OP_CODES[token]
    try:
        data = bytes.fromhex(token)
    except ValueError as e:
        raise BTClibValueError(f"invalid string token: {token}") from e
    return _op_pushdata(data)


def serialize(script: List[ScriptToken]) -> bytes:
    r = b""
    for token in script:
        if isinstance(token, int):
            r += _op_int(token)
        elif isinstance(token, str):
            r += _op_str(token)
        elif isinstance(token, bytes):
            r += _op_pushdata(token)
        else:
            raise BTClibValueError(f"Unmanaged {type(token)} token type")
    return r


def deserialize(stream: BinaryData) -> List[ScriptToken]:

    s = bytesio_from_binarydata(stream)
    # initialize the result list
    r: List[ScriptToken] = []
    while True:
        # get one byte
        t = s.read(1)
        if not t:
            break
        # convert it to an integer
        i = t[0]
        if i == 0:
            # numeric value 0 (OP_0)
            # r.append(OP_CODE_NAMES[i])
            r.append(i)
        elif i == 79:
            # numeric value -1 (OP_1NEGATE)
            r.append(-1)
        elif 80 < i < 97:
            # numeric values 1-16 (OP_1-OP_16)
            # r.append(OP_CODE_NAMES[i])
            r.append(i - 80)
        elif i < 76:
            # 1-byte-data-length | data
            data = s.read(i)
            r.append(data.hex().upper())
        elif i == 76:
            # OP_PUSHDATA1 | 1-byte-data-length | data
            data_length = int.from_bytes(s.read(1), byteorder="little")
            data = s.read(data_length)
            r.append(data.hex().upper())
        elif i == 77:
            # OP_PUSHDATA2 | 2-byte-data-length | data
            data_length = int.from_bytes(s.read(2), byteorder="little")
            data = s.read(data_length)
            r.append(data.hex().upper())
        elif i == 78:
            # OP_PUSHDATA4 | 4-byte-data-length | data
            data_length = int.from_bytes(s.read(4), byteorder="little")
            data = s.read(data_length)
            r.append(data.hex().upper())
        else:
            # OP_CODE
            r.append(OP_CODE_NAMES[i])

    return r
