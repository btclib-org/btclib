#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.to_pubkey` module."

from btclib.transactions import (
    tx_out_serialize,
    tx_out_deserialize,
    tx_in_serialize,
    tx_in_deserialize,
    transaction_serialize,
    transaction_deserialize,
)


def test_coinbase_1():
    block_1_coinbase_bytes = b'\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x07\x04\xff\xff\x00\x1d\x01\x04\xff\xff\xff\xff\x01\x00\xf2\x05*\x01\x00\x00\x00CA\x04\x96\xb58\xe8SQ\x9crj,\x91\xe6\x1e\xc1\x16\x00\xae\x13\x90\x81:b|f\xfb\x8b\xe7\x94{\xe6<R\xdau\x897\x95\x15\xd4\xe0\xa6\x04\xf8\x14\x17\x81\xe6"\x94r\x11f\xbfb\x1es\xa8,\xbf#B\xc8X\xee\xac\x00\x00\x00\x00'

    block_1_coinbase_input_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x07\x04\xff\xff\x00\x1d\x01\x04\xff\xff\xff\xff"

    block_1_coinbase_output_bytes = b'\x00\xf2\x05*\x01\x00\x00\x00CA\x04\x96\xb58\xe8SQ\x9crj,\x91\xe6\x1e\xc1\x16\x00\xae\x13\x90\x81:b|f\xfb\x8b\xe7\x94{\xe6<R\xdau\x897\x95\x15\xd4\xe0\xa6\x04\xf8\x14\x17\x81\xe6"\x94r\x11f\xbfb\x1es\xa8,\xbf#B\xc8X\xee\xac'

    tx_in = tx_in_deserialize(block_1_coinbase_input_bytes)
    tx_out = tx_out_deserialize(block_1_coinbase_output_bytes)
    tx = transaction_deserialize(block_1_coinbase_bytes)

    assert tx["tx_inputs"][0]["signature_script"] == tx_in["signature_script"]
    assert tx["tx_outputs"][0]["pk_script"] == tx_out["pk_script"]

    assert transaction_serialize(tx) == block_1_coinbase_bytes
    assert tx_in_serialize(tx_in) == block_1_coinbase_input_bytes
    assert tx_out_serialize(tx_out) == block_1_coinbase_output_bytes


# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def test_wiki_transaction():
    tx_bytes = b'\x01\x00\x00\x00\x01m\xbd\xdb\x08[\x1d\x8a\xf7Q\x84\xf0\xbc\x01\xfa\xd5\x8d\x12f\xe9\xb6;P\x88\x19\x90\xe4\xb4\rj\xee6)\x00\x00\x00\x00\x8bH0E\x02!\x00\xf3X\x1e\x19r\xae\x8a\xc7\xc76zz%;\xc1\x13R#\xad\xb9\xa4h\xbb:Y#?E\xbcW\x83\x80\x02 Y\xaf\x01\xca\x17\xd0\x0eA\x83z\x1dX\xe9z\xa3\x1b\xaeXN\xde\xc2\x8d5\xbd\x96\x926\x90\x91;\xae\x9a\x01A\x04\x9c\x02\xbf\xc9~\xf26\xcem\x8f\xe5\xd9@\x13\xc7!\xe9\x15\x98*\xcd+\x12\xb6]\x9b}Y\xe2\n\x84 \x05\xf8\xfcN\x02S.\x87=7\xb9o\t\xd6\xd4Q\x1a\xda\x8f\x14\x04/FaJLp\xc0\xf1K\xef\xf5\xff\xff\xff\xff\x02@KL\x00\x00\x00\x00\x00\x19v\xa9\x14\x1a\xa0\xcd\x1c\xbe\xa6\xe7E\x8az\xba\xd5\x12\xa9\xd9\xea\x1a\xfb"^\x88\xac\x80\xfa\xe9\xc7\x00\x00\x00\x00\x19v\xa9\x14\x0e\xab[\xeaCj\x04\x84\xcf\xab\x12H^\xfd\xa0\xb7\x8bN\xccR\x88\xac\x00\x00\x00\x00'

    tx = transaction_deserialize(tx_bytes)

    assert tx["input_count"] == 1
    assert tx["output_count"] == 2
    assert tx["tx_outputs"][0]["value"] == 5000000
    assert tx["tx_outputs"][1]["value"] == 3354000000


# 4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c
def test_single_witness():
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
    tx_bytes = bytes.fromhex(tx_bytes)

    tx = transaction_deserialize(tx_bytes)

    assert transaction_serialize(tx) == tx_bytes

    assert tx["input_count"] == 1
    assert tx["output_count"] == 2
    assert tx["lock_time"] == 0


# a4b76807519aba5740f7865396bc4c5ca0eb8aa7c3744ca2db88fcc9e345424c
def test_double_witness():
    tx_bytes = "01000000000102322d4f05c3a4f78e97deda01bd8fc5ff96777b62c8f2daa72b02b70fa1e3e1051600000017160014e123a5263695be634abf3ad3456b4bf15f09cc6afffffffffdfee6e881f12d80cbcd6dc54c3fe390670678ebd26c3ae2dd129f41882e3efc25000000171600145946c8c3def6c79859f01b34ad537e7053cf8e73ffffffff02c763ac050000000017a9145ffd6df9bd06dedb43e7b72675388cbfc883d2098727eb180a000000001976a9145f9e96f739198f65d249ea2a0336e9aa5aa0c7ed88ac024830450221009b364c1074c602b2c5a411f4034573a486847da9c9c2467596efba8db338d33402204ccf4ac0eb7793f93a1b96b599e011fe83b3e91afdc4c7ab82d765ce1da25ace01210334d50996c36638265ad8e3cd127506994100dd7f24a5828155d531ebaf736e160247304402200c6dd55e636a2e4d7e684bf429b7800a091986479d834a8d462fbda28cf6f8010220669d1f6d963079516172f5061f923ef90099136647b38cc4b3be2a80b820bdf90121030aa2a1c2344bc8f38b7a726134501a2a45db28df8b4bee2df4428544c62d731400000000"
    tx_bytes = bytes.fromhex(tx_bytes)

    tx = transaction_deserialize(tx_bytes)

    assert transaction_serialize(tx) == tx_bytes

    assert tx["input_count"] == 2
    assert tx["output_count"] == 2
    assert tx["lock_time"] == 0
