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

Scripts are represented by List[Command], where Command = Union[int, str, bytes]:

* int [-1, 16] are shorcuts for 'OP_1NEGATE', 'OP_0' - 'OP_16'
* str are for opcodes (e.g. 'OP_HASH160') or hexstring data
* bytes are for data (but integers are often casted to int)
"""

from dataclasses import dataclass
from typing import List, Optional, Sequence, Type, TypeVar, Union

from btclib.alias import BinaryData
from btclib.script.op_codes import OP_CODE_NAMES, op_int, op_pushdata, op_str
from btclib.utils import bytesio_from_binarydata

# the integers [0-16] are shorcuts for 'OP_0'-'OP_16'
# the integer -1 is a shorcut for 'OP_1NEGATE'
# other integers are bytes encoded (require push operation)
# ascii str are for opcodes (e.g. 'OP_HASH160')
# Octets are for data to be pushed
Command = Union[int, str, bytes]


def serialize(script: Sequence[Command]) -> bytes:
    r: List[bytes] = []
    for command in script:
        if isinstance(command, int):
            r.append(op_int(command))
        elif isinstance(command, str):
            r.append(op_str(command))
        else:  # must be bytes
            r.append(op_pushdata(command))
    return b"".join(r)


def parse(stream: BinaryData) -> List[Command]:

    s = bytesio_from_binarydata(stream)
    # initialize the result list
    r: List[Command] = []
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
            data_length = int.from_bytes(s.read(1), byteorder="little", signed=False)
            data = s.read(data_length)
            r.append(data.hex().upper())
        elif i == 77:
            # OP_PUSHDATA2 | 2-byte-data-length | data
            data_length = int.from_bytes(s.read(2), byteorder="little", signed=False)
            data = s.read(data_length)
            r.append(data.hex().upper())
        elif i == 78:
            # OP_PUSHDATA4 | 4-byte-data-length | data
            data_length = int.from_bytes(s.read(4), byteorder="little", signed=False)
            data = s.read(data_length)
            r.append(data.hex().upper())
        else:
            # OP_CODE
            r.append(OP_CODE_NAMES[i])

    return r


_Script = TypeVar("_Script", bound="Script")


@dataclass
class Script:
    # Bitcoin script expressed as List[Command]
    # e.g. [OP_HASH160, script_h160, OP_EQUAL]
    # or Octets of its byte-encoded representation
    commands: List[Command]

    def __init__(
        self, commands: Optional[Sequence[Command]] = None, check_validity: bool = True
    ) -> None:

        if commands:
            if check_validity:
                self.commands = parse(serialize(commands))
            else:
                # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
                self.commands = list(commands)
        else:
            self.commands = []

    def __len__(self):
        return len(self.commands)

    def assert_valid(self) -> None:
        self.commands = parse(serialize(self.commands))

    def serialize(self, check_validity: bool = True) -> bytes:
        "Return the Script serialization."

        if check_validity:
            self.assert_valid()

        return serialize(self.commands)

    @classmethod
    def parse(
        cls: Type[_Script], stream: BinaryData, check_validity: bool = True
    ) -> _Script:
        "Return a Script from its serialization."

        commands = parse(stream)
        return cls(commands, check_validity)
