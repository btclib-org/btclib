#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.script import (OP_CODE_NAMES, OP_CODES, decode, deserialize,
                           encode, serialize)


class TestScript(unittest.TestCase):

    def test_operators(self):
        for i in OP_CODE_NAMES.keys():
            b = OP_CODES[OP_CODE_NAMES[i]]
            self.assertEqual(i, b[0])
        for name in OP_CODES.keys():
            # skip duplicated
            if name in ('OP_FALSE', 'OP_TRUE', 'OP_NOP2', 'OP_NOP3'):
                continue
            i = OP_CODES[name][0]
            self.assertEqual(name, OP_CODE_NAMES[i])
        for i in range(76, 186):
            # skip disabled 'splice' opcodes
            if i in (126, 127, 128, 129):
                continue
            # skip disabled 'bitwise logic' opcodes
            if i in (131, 132, 133, 134):
                continue
            # skip disabled 'splice' opcodes
            if i in (141, 142, 149, 150, 151, 152, 152, 153):
                continue
            # skip 'reserved' opcodes
            if i in (80, 98, 101, 102, 137, 138):
                continue
            self.assertTrue(i in OP_CODE_NAMES.keys())

    def test_simple(self):
        script_list = [2, 3, 'OP_ADD', 5, 'OP_EQUAL']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes)
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized)
        self.assertEqual(script_list, script_list2)

        script_list = ['1ADD', 'OP_1ADD', '1ADE', 'OP_EQUAL']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes)
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized)
        self.assertEqual(script_list, script_list2)

        script_list = [hex(26)[2:].upper(), -1, 'OP_ADD', hex(26)[2:].upper(), 'OP_EQUAL']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes)
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized)
        self.assertEqual(script_list, script_list2)

        script_list = [hex(0xffffffff)[2:].upper(), -1, 'OP_ADD', hex(0xffffffff)[2:].upper(), 'OP_EQUAL']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes)
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized)
        self.assertEqual(script_list, script_list2)

        script_list = ["1F"*250, 'OP_DROP']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes)
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized)
        self.assertEqual(script_list, script_list2)

        script_list = ["1F"*520, 'OP_DROP']
        script_bytes = encode(script_list)
        script_list2 = decode(script_bytes.hex())
        self.assertEqual(script_list, script_list2)
        script_bytes2 = encode(script_list2)
        self.assertEqual(script_bytes, script_bytes2)

        script_serialized = serialize(script_list)
        script_list2 = deserialize(script_serialized.hex())
        self.assertEqual(script_list, script_list2)

    def test_exceptions(self):

        # Script: invalid OP_VERIF opcode
        script = [2, 3, 'OP_ADD', 5, 'OP_VERIF']
        self.assertRaises(ValueError, encode, script)
        # encode(script)

        # Script: unmanaged <class 'function'> token type
        script = [2, 3, 'OP_ADD', 5, encode]
        self.assertRaises(ValueError, encode, script)
        # encode(script)

        # Script: Cannot push 521 bytes on the stack
        script = ['1f'*521, 'OP_DROP']
        self.assertRaises(ValueError, encode, script)
        # encode(script)

        # A script with OP_PUSHDATA4 can be decoded
        script_bytes = '4e09020000' + '00'*521 + '75'  # ['00'*521, 'OP_DROP']
        script = decode(script_bytes)
        # but it cannot be encoded
        # Cannot push 521 bytes on the stack
        self.assertRaises(ValueError, encode, script)
        #encode(script)

    def test_nulldata(self):

        script = ['OP_RETURN', '11'*79]
        bscript = encode(script)
        self.assertEqual(script, decode(bscript))

        script2 = ['OP_RETURN', b'\x11'*79]
        bscript = encode(script2)
        self.assertEqual(script, decode(bscript))

        script = ['OP_RETURN', '00'*79]
        bscript = encode(script)
        self.assertEqual(script, decode(bscript))

        script2 = ['OP_RETURN', b'\x11'*79]
        bscript = encode(script)
        self.assertEqual(script, decode(bscript))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
