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
    tx_in = TxIn(OutPoint(), serialize(script), 1, Witness(["00" * 32]))
    tx = Tx(vin=[tx_in], vout=[TxOut(100000000, "")])

    err_msg = "Taproot scripts cannot be wrapped in p2sh"
    with pytest.raises(BTClibValueError, match=err_msg):
        sig_hash.from_tx([utxo], tx, 0, 0)


def test_bip_test_vector():
    unsigned_tx_hex = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffff0c638ca38362001f5e128a01ae2b379288eb22cfaf903652b2ec1c88588f487a0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd05000000000000000000081efa267f1f0e46e054ecec01773de7c844721e010c2db5d5864a6a6b53e013a010000000000000000a690669c3c4a62507d93609810c6de3f99d1a6e311fe39dd23683d695c07bdee0000000000ffffffff727ab5f877438496f8613ca84002ff38e8292f7bd11f0a9b9b83ebd16779669e0100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d"
    unsigned_tx = Tx.parse(unsigned_tx_hex, taproot=True)

    utxo_0 = TxOut(
        420000000,
        "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
    )
    utxo_1 = TxOut(
        462000000,
        "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
    )
    utxo_2 = TxOut(
        294000000,
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    )
    utxo_3 = TxOut(
        504000000,
        "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
    )
    utxo_4 = TxOut(
        630000000,
        "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
    )
    utxo_5 = TxOut(
        378000000,
        "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
    )
    utxo_6 = TxOut(
        672000000,
        "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
    )
    utxo_7 = TxOut(
        546000000,
        "51200f63ca2c7639b9bb4be0465cc0aa3ee78a0761ba5f5f7d6ff8eab340f09da561",
    )
    utxo_8 = TxOut(
        588000000,
        "5120053690babeabbb7850c32eead0acf8df990ced79f7a31e358fabf2658b4bc587",
    )
    utxos = [utxo_0, utxo_1, utxo_2, utxo_3, utxo_4, utxo_5, utxo_6, utxo_7, utxo_8]
    for vin in unsigned_tx.vin:
        vin.script_witness.stack.append(["00"])

    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 0, 0x03).hex()
        == "7e584883b084ace0469c6962a9a7d2a9060e1f3c218ab40d32c77651482122bc"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 1, 0x83).hex()
        == "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 3, 0x01).hex()
        == "6ffd256e108685b41831385f57eebf2fca041bc6b5e607ea11b3e03d4cf9d9ba"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 4, 0x00).hex()
        == "9f90136737540ccc18707e1fd398ad222a1a7e4dd65cbfd22dbe4660191efa58"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 6, 0x02).hex()
        == "835c9ab6084ed9a8ae9b7cda21e0aa797aca3b76a54bd1e3c7db093f6c57e23f"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 7, 0x82).hex()
        == "df1cca638283c667084b8ffe6bf6e116cc5a53cf7ae1202c5fee45a9085f1ba5"
    )
    assert (
        sig_hash.from_tx(utxos, unsigned_tx, 8, 0x81).hex()
        == "30319859ca79ea1b7a9782e9daebc46e4ca4ca2bc04c9c53b2ec87fa83a526bd"
    )
