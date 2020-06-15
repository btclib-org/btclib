#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.signtransactions` module."

# test vector at https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
from btclib import tx, tx_out, dsa, script
from btclib.signtransactions import get_sighash


def test_native_p2wpkh():
    transaction = tx.deserialize(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    )

    previous_txout = tx.TxOut(
        value=6,
        scriptPubKey=script.decode("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
    )

    sighash = get_sighash(transaction, previous_txout, 1, 1)[0]

    assert (
        sighash.hex()
        == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )

    # prvkey = 0x619C335025C7F4012E556C2A58B2506E30B8511B53ADE95EA316FD8C3286FEB9
    # signature = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
    #
    # assert dsa._verify(sighash, prvkey, signature)


def test_wrapped_p2wpkh():
    transaction = tx.deserialize(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    )
    transaction["vin"][0]["scriptSig"] = script.decode(
        "001479091972186c449eb1ded22b78e40d009bdf0089"
    )

    previous_txout = tx.TxOut(
        value=10,
        scriptPubKey=script.decode("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"),
    )

    sighash = get_sighash(transaction, previous_txout, 0, 1)[0]

    assert (
        sighash.hex()
        == "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    )


def test_native_p2wsh():
    transaction = tx.deserialize(
        "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
    )
    transaction["vin"][1]["txinwitness"] = [
        "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
    ]
    transaction["witness_flag"] = True

    previous_txout = tx.TxOut(
        value=49,
        scriptPubKey=script.decode(
            "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
        ),
    )

    sighash = get_sighash(transaction, previous_txout, 1, 3)

    assert (
        sighash[0].hex()
        == "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )

    assert (
        sighash[1].hex()
        == "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"
    )
