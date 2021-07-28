#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.sig_hash` module.

test vector at https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
"""

import json
from os import path

import pytest

from btclib.ecc import ssa
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.script import sig_hash
from btclib.script.script_pub_key import is_p2tr, type_and_payload
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


def test_valid_taproot_key_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "final" in x.keys(), data):

        tx = Tx.parse(x["tx"])

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        script_sig = x["success"]["scriptSig"]
        assert not script_sig

        witness = Witness(x["success"]["witness"])
        annex = b""
        if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
            annex = witness.stack[-1]
            witness.stack = witness.stack[:-1]

        # check only key paths
        if len(witness.stack) == 1:

            sighash_type = 0  # all
            signature = witness.stack[0][:64]
            if len(witness.stack[0]) == 65:
                sighash_type = witness.stack[0][-1]
                assert sighash_type != 0

            msg_hash = sig_hash.taproot(
                tx,
                index,
                [x.value for x in prevouts],
                [x.script_pub_key for x in prevouts],
                sighash_type,
                0,
                annex,
                b"",
            )

            pub_key = type_and_payload(prevouts[index].script_pub_key.script)[1]

            ssa.assert_as_valid_(msg_hash, pub_key, signature)


def test_invalid_taproot_key_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "failure" in x.keys(), data):

        tx = Tx.parse(x["tx"])
        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        script_sig = x["failure"]["scriptSig"]
        assert not script_sig

        witness = Witness(x["failure"]["witness"])
        annex = b""
        if not witness.stack or not witness.stack[-1]:
            continue  # invalid taproot witness stack
        if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
            annex = witness.stack[-1]
            witness.stack = witness.stack[:-1]

        # check only key paths
        if len(witness.stack) == 1:

            with pytest.raises((BTClibRuntimeError, BTClibValueError)):

                sighash_type = 0  # all
                signature = witness.stack[0][:64]
                if len(witness.stack[0]) == 65:
                    sighash_type = witness.stack[0][-1]
                    if sighash_type == 0:
                        raise BTClibValueError(
                            "invalid sighash 0 in 65 bytes signature"
                        )

                msg_hash = sig_hash.taproot(
                    tx,
                    index,
                    [x.value for x in prevouts],
                    [x.script_pub_key for x in prevouts],
                    sighash_type,
                    0,
                    annex,
                    b"",
                )

                pub_key = type_and_payload(prevouts[index].script_pub_key.script)[1]

                ssa.assert_as_valid_(msg_hash, pub_key, signature)


def test_taproot_script_path() -> None:
    assert False


def test_invalid_taproot_script_path() -> None:
    assert False
