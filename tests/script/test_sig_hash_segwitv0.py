#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.sig_hash` module.

test vector at https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
"""

from btclib.script import sig_hash
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


def test_native_p2wpkh() -> None:
    tx_bytes = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    tx = Tx.parse(tx_bytes)

    utxo_0 = TxOut(
        625000000,
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
    )
    utxo_1 = TxOut(600000000, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")

    hash_ = sig_hash.from_tx([utxo_0, utxo_1], tx, 1, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )


def test_wrapped_p2wpkh() -> None:
    tx_bytes = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    tx = Tx.parse(tx_bytes)
    tx.vin[0].script_sig = bytes.fromhex("001479091972186c449eb1ded22b78e40d009bdf0089")

    utxo = TxOut(1000000000, "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")

    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    )


def test_native_p2wsh() -> None:
    tx_bytes = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
    tx = Tx.parse(tx_bytes)
    tx.vin[1].script_witness = Witness(
        [
            "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
        ]
    )

    utxo_0 = TxOut(
        156250000,
        "21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac",
    )
    utxo_1 = TxOut(
        4900000000,
        "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0",
    )

    hash_ = sig_hash.from_tx([utxo_0, utxo_1], tx, 1, sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )

    script_ = sig_hash.witness_v0_script(tx.vin[1].script_witness.stack[-1])[1]
    hash_ = sig_hash.segwit_v0(script_, tx, 1, sig_hash.SINGLE, utxo_1.value)
    assert hash_ == bytes.fromhex(
        "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"
    )


def test_native_p2wsh_2() -> None:
    tx_bytes = "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000"
    tx = Tx.parse(tx_bytes)
    tx.vin[0].script_witness = Witness(
        [
            "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        ]
    )
    tx.vin[1].script_witness = Witness(
        [
            "5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        ]
    )

    previous_txout_1 = TxOut(
        16777215, "0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d"
    )
    previous_txout_2 = TxOut(
        16777215, "0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537"
    )
    hash_ = sig_hash.from_tx(
        [previous_txout_1, previous_txout_2],
        tx,
        0,
        sig_hash.ANYONECANPAY | sig_hash.SINGLE,
    )
    assert hash_ == bytes.fromhex(
        "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a"
    )

    script_ = sig_hash.witness_v0_script(tx.vin[1].script_witness.stack[-1])[1]
    hash_ = sig_hash.segwit_v0(
        script_,
        tx,
        1,
        sig_hash.ANYONECANPAY | sig_hash.SINGLE,
        previous_txout_2.value,
    )
    assert hash_ == bytes.fromhex(
        "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54"
    )


def test_wrapped_p2wsh() -> None:
    tx_bytes = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
    tx = Tx.parse(tx_bytes)
    stack = [
        "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
    ]
    tx.vin[0].script_witness = Witness(stack)

    utxo = TxOut(
        987654321,
        "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54",
    )

    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.NONE)
    assert hash_ == bytes.fromhex(
        "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.NONE)
    assert hash_ == bytes.fromhex(
        "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"
    )
