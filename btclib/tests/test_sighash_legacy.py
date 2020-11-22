#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for `btclib.sighash` module.

test vector from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
"""

import json
from os import path

from btclib import dsa, script
from btclib.sighash import _get_legacy_scriptCodes, get_sighash, legacy
from btclib.tx import Tx
from btclib.tx_in import OutPoint, TxIn
from btclib.tx_out import TxOut

# from btclib.curve import mult
# from btclib.secpoint import bytes_from_point
# from btclib.script import deserialize


# block 170
def test_first_transaction():
    transaction = Tx.deserialize(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    )
    previous_txout = TxOut(
        value=5000000000,
        scriptPubKey=bytes.fromhex(
            "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
        ),
    )
    sighash = get_sighash(transaction, previous_txout, 0, 0x01)
    assert (
        sighash.hex()
        == "7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19"
    )
    pubkey = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
    signature = "304402204E45E16932B8AF514961A1D3A1A25FDF3F4F7732E9D624C6C61548AB5FB8CD410220181522EC8ECA07DE4860A4ACDD12909D831CC56CBBAC4622082221A8768D1D0901"
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


# 8fea2a92db2940ebce62610b162bfe0ca13229e08cb384a886a6f677e2812e52
def test_legacy_p2pkh():
    pubkey = "04280c8f66bf2ccaeb3f60a19ad4a06365f8bd6178aab0e709df2173df8f553366549aec336aae8742a84702b6c7c3052d89f5d76d535ec3716e72187956351613"
    signature = "3045022100ea43c4800d1a860ec89b5273898a146cfb01d34ff4c364d24a110c480d0e3f7502201c82735577f932f1ca8e1c54bf653e0f8e74e408fe83666bc85cac4472ec950801"
    scriptSig = [signature, pubkey]
    previous_txout = TxOut(
        value=1051173696,
        scriptPubKey=script.serialize(
            [
                "OP_DUP",
                "OP_HASH160",
                "82ac30f58baf99ec9d14e6181eee076f4e27f69c",
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )
    tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint(
                    bytes.fromhex(
                        "d8343a35ba951684f2969eafe833d9e6fe436557b9707ae76802875952e860fc"
                    ),
                    1,
                ),
                scriptSig,
                0xFFFFFFFF,
                [],
            )
        ],
        vout=[
            TxOut(
                2017682,
                bytes.fromhex("76a91413bd20236d0da56492c325dce289b4da35b4b5bd88ac"),
            ),
            TxOut(
                1049154982,
                bytes.fromhex("76a914da169b45781ca210f8c11617ba66bd843da76b1688ac"),
            ),
        ],
    )
    sighash = get_sighash(tx, previous_txout, 0, 0x01)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


# the following tests are taken from python-bitcoinlib tests
def test_p2pk():
    pubkey = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    signature = "304402200A5C6163F07B8D3B013C4D1D6DBA25E780B39658D79BA37AF7057A3B7F15FFA102201FD9B4EAA9943F734928B99A83592C2E7BF342EA2680F6A2BB705167966B742001"
    scriptPubKey = script.serialize([pubkey, "OP_CHECKSIG"])
    scriptSig = script.serialize([signature])

    founding_tx_script = script.serialize([0, 0])
    founding_tx = Tx(
        1,
        0,
        vin=[
            TxIn(OutPoint(b"\x00" * 32, 0xFFFFFFFF), founding_tx_script, 0xFFFFFFFF, [])
        ],
        vout=[TxOut(0, scriptPubKey)],
    )
    receiving_tx = Tx(
        1,
        0,
        vin=[TxIn(OutPoint(founding_tx.txid, 0), scriptSig, 0xFFFFFFFF, [])],
        vout=[TxOut(0, b"")],
    )
    sighash = get_sighash(receiving_tx, founding_tx.vout[0], 0, 0x01)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


def test_p2pkh():
    pubkey = "038282263212C609D9EA2A6E3E172DE238D8C39CABD5AC1CA10646E23FD5F51508"
    signature = "304402206E05A6FE23C59196FFE176C9DDC31E73A9885638F9D1328D47C0C703863B8876022076FEB53811AA5B04E0E79F938EB19906CC5E67548BC555A8E8B8B0FC603D840C01"
    scriptPubKey = script.serialize(
        [
            "OP_DUP",
            "OP_HASH160",
            "1018853670F9F3B0582C5B9EE8CE93764AC32B93",
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
    )
    scriptSig = script.serialize([signature, pubkey])

    founding_tx_script = script.serialize([0, 0])
    founding_tx = Tx(
        1,
        0,
        vin=[
            TxIn(OutPoint(b"\x00" * 32, 0xFFFFFFFF), founding_tx_script, 0xFFFFFFFF, [])
        ],
        vout=[TxOut(0, scriptPubKey)],
    )
    receiving_tx = Tx(
        1,
        0,
        vin=[TxIn(OutPoint(founding_tx.txid, 0), scriptSig, 0xFFFFFFFF, [])],
        vout=[TxOut(0, b"")],
    )
    sighash = get_sighash(receiving_tx, founding_tx.vout[0], 0, 0x01)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


def test_p2pk_anyonecanpay():
    pubkey = "048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"
    signature = "304402204710a85181663b32d25c70ec2bbd14adff5ddfff6cb50d09e155ef5f541fc86c0220056b0cc949be9386ecc5f6c2ac0493269031dbb185781db90171b54ac127790281"
    scriptPubKey = script.serialize([pubkey, "OP_CHECKSIG"])
    scriptSig = script.serialize([signature])

    founding_tx_script = script.serialize([0, 0])
    founding_tx = Tx(
        1,
        0,
        vin=[
            TxIn(OutPoint(b"\x00" * 32, 0xFFFFFFFF), founding_tx_script, 0xFFFFFFFF, [])
        ],
        vout=[TxOut(0, scriptPubKey)],
    )
    receiving_tx = Tx(
        1,
        0,
        vin=[TxIn(OutPoint(founding_tx.txid, 0), scriptSig, 0xFFFFFFFF, [])],
        vout=[TxOut(0, b"")],
    )
    sighash = get_sighash(receiving_tx, founding_tx.vout[0], 0, 0x81)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


def test_sighashsingle_bug():
    pubkey = "02D5C25ADB51B61339D2B05315791E21BBE80EA470A49DB0135720983C905AACE0"
    signature = "3045022100C9CDD08798A28AF9D1BAF44A6C77BCC7E279F47DC487C8C899911BC48FEAFFCC0220503C5C50AE3998A733263C5C0F7061B483E2B56C4C41B456E7D2F5A78A74C07703"
    scriptPubKey = script.serialize(
        [
            "OP_DUP",
            "OP_HASH160",
            "5b6462475454710f3c22f5fdf0b40704c92f25c3",
            "OP_EQUALVERIFY",
            "OP_CHECKSIGVERIFY",
            1,
        ]
    )

    previous_txout = TxOut(0, scriptPubKey)
    tx = Tx.deserialize(
        "01000000020002000000000000000000000000000000000000000000000000000000000000000000000151ffffffff0001000000000000000000000000000000000000000000000000000000000000000000006b483045022100c9cdd08798a28af9d1baf44a6c77bcc7e279f47dc487c8c899911bc48feaffcc0220503c5c50ae3998a733263c5c0f7061b483e2b56c4c41b456e7d2f5a78a74c077032102d5c25adb51b61339d2b05315791e21bbe80ea470a49db0135720983c905aace0ffffffff010000000000000000015100000000"
    )
    sighash = get_sighash(tx, previous_txout, 1, 0x03)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


def test_sighash_json():
    fname = "sighash_legacy.json"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "r") as file_:
        data = json.load(file_)
    data = data[1:]  # skip column headers
    for raw_transaction, raw_script, input_index, hashType, sighash in data:
        scriptCode = _get_legacy_scriptCodes(raw_script)[0]
        tx = Tx.deserialize(raw_transaction)
        if hashType < 0:
            hashType = 0xFFFFFFFF + 1 + hashType
        actual_sighash = legacy(scriptCode, tx, input_index, hashType)
        expected_sighash = bytes.fromhex(sighash)[::-1]
        assert expected_sighash == actual_sighash
