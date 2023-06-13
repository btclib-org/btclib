#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Module btclib.script."""

from btclib.script.script import Command, Script, op_int, parse, serialize
from btclib.script.script_pub_key import (
    ScriptPubKey,
    address,
    assert_nulldata,
    assert_p2ms,
    assert_p2pk,
    assert_p2pkh,
    assert_p2sh,
    assert_p2tr,
    assert_p2wpkh,
    assert_p2wsh,
    is_nulldata,
    is_p2ms,
    is_p2pk,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.script.taproot import (
    TaprootScriptTree,
    check_output_pubkey,
    input_script_sig,
    output_prvkey,
    output_pubkey,
)
from btclib.script.witness import Witness

__all__ = [
    "Command",
    "Script",
    "op_int",
    "parse",
    "serialize",
    "ScriptPubKey",
    "address",
    "assert_p2ms",
    "is_p2ms",
    "assert_p2pk",
    "is_p2pk",
    "assert_p2pkh",
    "is_p2pk",
    "assert_p2sh",
    "is_p2sh",
    "assert_p2tr",
    "is_p2tr",
    "assert_p2wpkh",
    "is_p2wpkh",
    "assert_p2wsh",
    "is_p2wsh",
    "assert_nulldata",
    "is_nulldata",
    "type_and_payload",
    "Witness",
    "TaprootScriptTree",
    "check_output_pubkey",
    "input_script_sig",
    "output_prvkey",
    "output_pubkey",
]
