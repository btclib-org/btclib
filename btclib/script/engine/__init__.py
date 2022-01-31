#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Bitcoin Script engine
"""

from typing import List, Tuple

import btclib_libsecp256k1.ssa

from btclib import var_bytes
from btclib.ecc import ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script import Command, parse, sig_hash
from btclib.script.engine import tapscript
from btclib.script.script_pub_key import (
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_octets

# from btclib.script.engine import script


def taproot_unwrap_script(
    script: bytes, stack: List[bytes]
) -> Tuple[bytes, List[bytes], int]:

    pub_key = type_and_payload(script)[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError()

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def taproot_get_annex(witness: Witness) -> bytes:
    annex = b""
    if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
        annex = witness.stack[-1]
        witness.stack = witness.stack[:-1]
    return annex


def verify_input(prevouts: List[TxOut], tx: Tx, i: int) -> None:

    script = prevouts[i].script_pub_key.script

    if is_p2tr(script):
        witness = tx.vin[i].script_witness
        annex = taproot_get_annex(witness)
        stack = witness.stack
        if len(stack) == 0:
            raise BTClibValueError()
        elif len(stack) == 1:
            return tapscript.verify_key_path(script, stack, prevouts, tx, i, annex)
        else:
            script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
            if leaf_version == 0xC0:
                args = [script_bytes, stack, prevouts, tx, i, annex]
                return tapscript.verify_script_path_vc0(*args)
            else:
                return  # unknown leaf version type

    pass


def verify_transaction(prevouts: List[TxOut], tx: Tx) -> None:
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i)
