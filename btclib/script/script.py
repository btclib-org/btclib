#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin Script.

https://en.bitcoin.it/wiki/Script

Scripts are represented by List[Command], where Command = Union[int, str, bytes]

* int -1 and 0-16 are shorcuts for 'OP_1NEGATE' and 'OP_0'-'OP_16';
  anyway, the use of the corresponding operator is to be preferred.
* ascii str are for opcodes (e.g. 'OP_HASH160', 'OP_1', 'OP_1NEGATE', etc.)
* hex-string or bytes (i.e., Octets) are for data
"""

from dataclasses import dataclass
from typing import List, Sequence, Union

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.script.op_codes import (
    OP_CODE_NAMES,
    decode_num,
    op_num,
    op_pushdata,
    op_str,
)
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

Command = Union[int, str, bytes]


def serialize(script: Sequence[Command]) -> bytes:
    r: List[bytes] = []
    for command in script:
        if isinstance(command, int):
            r.append(op_num(command))
            # err_msg = f"ints are not allowed, use OP_X instead: {command}"
            # raise BTClibValueError(err_msg)
        elif isinstance(command, str):
            r.append(op_str(command))
        else:  # must be bytes
            r.append(op_pushdata(command))
    return b"".join(r)


def parse(stream: BinaryData, exit_on_op_success: bool = False) -> List[Command]:

    s = bytesio_from_binarydata(stream)
    r: List[Command] = []  # initialize the result list

    while True:

        t = s.read(1)  # get one byte
        if not t:
            break
        i = t[0]  # convert the byte to an integer
        if 0 < i <= 78:  # push
            if 0 < i < 76:  # 1-byte-data-length | data
                data_length = i
            if 76 <= i <= 78:
                if i == 76:  # OP_PUSHDATA1 | 1-byte-data-length | data
                    x = 1
                elif i == 77:  # OP_PUSHDATA2 | 2-byte-data-length | data
                    x = 2
                elif i == 78:  # OP_PUSHDATA4 | 4-byte-data-length | data
                    x = 4
                y = s.read(x)
                if len(y) != x:
                    raise BTClibValueError("Invalid pushdata length")
                data_length = int.from_bytes(y, byteorder="little")
            if data_length > 520:
                raise BTClibValueError("Invalid pushdata length")
            data = s.read(data_length)
            if len(data) != data_length:
                raise BTClibValueError("Invalid pushdata length")
            # if <= 0xFFFFFFFF, parse it as integer
            if i < 6 and decode_num(data) <= 0xFFFFFFFF:
                new_op_code: Command = decode_num(data)
            else:
                new_op_code = data.hex().upper()
        elif i in OP_CODE_NAMES:  # OP_CODE
            new_op_code = OP_CODE_NAMES[i]
        else:  # OP_SUCCESSx
            new_op_code = f"OP_SUCCESS{i}"
            if exit_on_op_success:
                return ["OP_SUCCESS"]

        r.append(new_op_code)

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
