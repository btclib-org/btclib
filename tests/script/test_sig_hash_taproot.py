#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
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
from btclib.hashes import hash160
from btclib.script import sig_hash
from btclib.script.script import parse, serialize
from btclib.script.script_pub_key import is_p2tr, type_and_payload
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_in import OutPoint, TxIn
from btclib.tx.tx_out import TxOut


def test_valid_taproot_key_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "TAPROOT" in x["flags"], data):

        tx = Tx.parse(x["tx"])

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        assert not x["success"]["scriptSig"]

        witness = Witness(x["success"]["witness"])
        tx.vin[index].script_witness = witness

        if (
            len(witness.stack) == 1
            or len(witness.stack) == 2
            and witness.stack[-1][0] == 0x50
        ):

            sighash_type = 0  # all
            signature = witness.stack[0][:64]
            if len(witness.stack[0]) == 65:
                sighash_type = witness.stack[0][-1]
                assert sighash_type != 0

            msg_hash = sig_hash.from_tx(prevouts, tx, index, sighash_type)

            pub_key = type_and_payload(prevouts[index].script_pub_key.script)[1]

            ssa.assert_as_valid_(msg_hash, pub_key, signature)


def test_invalid_taproot_key_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "failure" in x.keys(), data):

        tx = Tx.parse(x["tx"])
        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        witness = Witness(x["failure"]["witness"])
        tx.vin[index].script_witness = witness

        # check only key paths
        if (
            len(witness.stack) == 1
            or len(witness.stack) == 2
            and witness.stack[-1][0] == 0x50
        ):

            with pytest.raises((BTClibRuntimeError, BTClibValueError, AssertionError)):

                assert not x["failure"]["scriptSig"]

                sighash_type = 0  # all
                signature = witness.stack[0][:64]
                if len(witness.stack[0]) == 65:
                    sighash_type = witness.stack[0][-1]
                    if sighash_type == 0:
                        raise BTClibValueError(
                            "invalid sighash 0 in 65 bytes signature"
                        )

                msg_hash = sig_hash.from_tx(prevouts, tx, index, sighash_type)

                pub_key = type_and_payload(prevouts[index].script_pub_key.script)[1]

                ssa.assert_as_valid_(msg_hash, pub_key, signature)


def test_valid_taproot_script_path() -> None:
    tx_data = "26dc279d02d8b1a203b653fc4e0f27f408432f3f540136d33f8f930eaeba655910095142980402000000fd697cd4eb5278f1e34545cd57b6670df806fa3a0a064fd8e385a19f1a53d9ce8d8971a30f02000000378d5fb502335dbe02000000001976a9140053a23441c8478caac4c6b769c51f8476cd4b4b88ac58020000000000001976a914f2aae94a43e0d173354201d7832b46c5269c8a2488ac4a08671e"
    prevouts_data = [
        "91ca4c010000000017a9145658b58602cdf7b7e962cfe44e024cb0e366f27087",
        "cb127401000000002251201ebe8b90363bd097aa9f352c8b21914e1886bc09fe9e70c09f33ef2d2abdf4bc",
    ]
    witness_data = [
        "9675a9982c6398ea9d441cb7a943bcd6ff033cc3a2e01a0178a7d3be4575be863871c6bf3eef5ecd34721c784259385ca9101c3a313e010ac942c99de05aaaa602",
        "5799cf4b193b730fb99580b186f7477c2cca4d28957326f6f1a5d14116438530e7ec0ce1cd465ad96968ae8a6a09d4d37a060a115919f56fcfebe7b2277cc2df5cc08fb6cda9105ee2512b2e22635aba",
        "7520c7b5db9562078049719228db2ac80cb9643ec96c8055aa3b29c2c03d4d99edb0ac",
        "c1a7957acbaaf7b444c53d9e0c9436e8a8a3247fd515095d66ddf6201918b40a3668f9a4ccdffcf778da624dca2dda0b08e763ec52fd4ad403ec7563a3504d0cc168b9a77a410029e01dac89567c9b2e6cd726e840351df3f2f58fefe976200a19244150d04153909f660184d656ee95fa7bf8e1d4ec83da1fca34f64bc279b76d257ec623e08baba2cfa4ea9e99646e88f1eb1668c00c0f15b7443c8ab83481611cc3ae85eb89a7bfc40067eb1d2e6354a32426d0ce710e88bc4cc0718b99c325509c9d02a6a980d675a8969be10ee9bef82cafee2fc913475667ccda37b1bc7f13f64e56c449c532658ba8481631c02ead979754c809584a875951619cec8fb040c33f06468ae0266cd8693d6a64cea5912be32d8de95a6da6300b0c50fdcd6001ea41126e7b7e5280d455054a816560028f5ca53c9a50ee52f10e15c5337315bad1f5277acb109a1418649dc6ead2fe14699742fee7182f2f15e54279c7d932ed2799d01d73c97e68bbc94d6f7f56ee0a80efd7c76e3169e10d1a1ba3b5f1eb02369dc43af687461c7a2a3344d13eb5485dca29a67f16b4cb988923060fd3b65d0f0352bb634bcc44f2fe668836dcd0f604150049835135dc4b4fbf90fb334b3938a1f137eb32f047c65b85e6c1173b890b6d0162b48b186d1f1af8521945924ac8ac8efec321bf34f1d4b3d4a304a10313052c652d53f6ecb8a55586614e8950cde9ab6fe8e22802e93b3b9139112250b80ebc589aba231af535bb20f7eeec2e412f698c17f3fdc0a2e20924a5e38b21a628a9e3b2a61e35958e60c7f5087c",
    ]

    tx = Tx.parse(tx_data)
    prevouts = [TxOut.parse(prevout) for prevout in prevouts_data]
    index = 1
    witness = Witness(witness_data)
    tx.vin[index].script_witness = witness

    sighash_type = 0  # all
    signature = witness.stack[0][:64]
    if len(witness.stack[0]) == 65:
        sighash_type = witness.stack[0][-1]
        assert sighash_type != 0

    msg_hash = sig_hash.from_tx(prevouts, tx, index, sighash_type)

    tapscript = parse(witness.stack[-2])
    pub_key = bytes.fromhex(str(tapscript[1]))

    ssa.assert_as_valid_(msg_hash, pub_key, signature)


def test_valid_sighash_type() -> None:

    for hash_type in range(256):
        if hash_type in sig_hash.SIG_HASH_TYPES:
            sig_hash.assert_valid_hash_type(hash_type)
        else:
            err_msg = "invalid sig_hash type:"
            with pytest.raises(BTClibValueError, match=err_msg):
                sig_hash.assert_valid_hash_type(hash_type)


def test_empty_stack() -> None:

    utxo = TxOut(
        100000000,
        serialize(
            ["OP_1", "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"]
        ),
    )
    tx_in = TxIn(OutPoint(), "", 1, Witness([]))
    tx = Tx(vin=[tx_in], vout=[TxOut(100000000, "")])

    err_msg = "Empty stack"
    with pytest.raises(BTClibValueError, match=err_msg):
        sig_hash.from_tx([utxo], tx, 0, 0)


def test_wrapped_p2tr() -> None:

    script = [
        "OP_1",
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf",
    ]
    utxo = TxOut(
        100000000, serialize(["OP_HASH160", hash160(serialize(script)), "OP_EQUAL"])
    )
    tx_in = TxIn(OutPoint(), serialize(script), 1, Witness(["0A" * 32]))
    tx = Tx(vin=[tx_in], vout=[TxOut(100000000, "")])

    err_msg = "Taproot scripts cannot be wrapped in p2sh"
    with pytest.raises(BTClibValueError, match=err_msg):
        sig_hash.from_tx([utxo], tx, 0, 0)


def test_bip_test_vector():

    fname = "taproot_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)["keyPathSpending"][0]

    unsigned_tx = Tx.parse(data["given"]["rawUnsignedTx"])

    utxos = []
    for utxo in data["given"]["utxosSpent"]:
        utxos.append(TxOut(utxo["amountSats"], utxo["scriptPubKey"]))

    for vin in unsigned_tx.vin:
        vin.script_witness.stack.append(["00"])

    for test in data["inputSpending"]:
        index = test["given"]["txinIndex"]
        hash_type = test["given"]["hashType"]
        signature_hash = sig_hash.from_tx(utxos, unsigned_tx, index, hash_type)
        assert signature_hash.hex() == test["intermediary"]["sigHash"]
