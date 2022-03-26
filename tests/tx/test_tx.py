#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.tx` module."

import json
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_in import OutPoint, TxIn
from btclib.tx.tx_out import TxOut


def test_tx() -> None:
    # default constructor
    tx = Tx()
    assert not tx.is_segwit()
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase()
    assert tx.version == 1
    assert tx.lock_time == 0
    assert not tx.vin
    assert not tx.vout
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 10
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4

    tx_2 = Tx.from_dict(tx.to_dict())
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=True))
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=False))
    assert not tx_2.is_segwit()
    assert tx_2 == tx

    # non-default constructor, no segwit
    prev_out = OutPoint(
        "9dcfdb5836ecfe146bdaa896605ba21222f83cd014dd47adde14fab2aba7de9b", 1
    )
    script_sig = b""
    sequence = 0xFFFFFFFF
    tx_in = TxIn(prev_out, script_sig, sequence)

    tx_out1 = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    tx_out2 = TxOut(
        6381891, "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
    )
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    assert not tx.is_segwit()
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase()
    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 126
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4

    tx_2 = Tx.from_dict(tx.to_dict())
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=True))
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=False))
    assert not tx_2.is_segwit()
    assert tx_2 == tx

    # non-default constructor, with segwit
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    stack = [
        "",
        "30440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01",
        "30440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f4401",
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    ]
    tx.vin[0].script_witness = Witness(stack)
    assert tx.is_segwit()
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase()
    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    hash_ = "d39eb3e3954be4bdc0b3be2d980124b1e1e11fb414b886b52939b07d95a58a8f"
    assert tx.hash.hex() == hash_
    assert tx.size == 380
    assert tx.vsize == 190
    assert tx.weight == 758

    tx_2 = Tx.from_dict(tx.to_dict())
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=True))
    assert tx_2.is_segwit() == tx.is_segwit()
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=False))
    assert not tx_2.is_segwit()
    assert tx_2 != tx

    tx.version = 0
    tx.assert_valid()


def test_exceptions() -> None:
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_valid()

    tx = Tx.parse(tx_bytes)
    tx.lock_time = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid lock time: "):
        tx.assert_valid()


def test_standard() -> None:
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_standard()

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF
    tx.assert_valid()

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_standard()


def test_coinbase_block_1() -> None:

    coinbase_out = "00f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac"
    tx_out = TxOut.parse(coinbase_out)
    assert tx_out.serialize().hex() == coinbase_out

    coinbase_inp = (  # prev_out
        "0000000000000000000000000000000000000000000000000000000000000000ffffffff"
        "0704ffff001d0104"  # script_sig
        "ffffffff"  # sequence
    )
    tx_in = TxIn.parse(coinbase_inp)
    assert tx_in.serialize().hex() == coinbase_inp
    assert tx_in.prev_out.is_coinbase

    coinbase = "01000000" "01" + coinbase_inp + "01" + coinbase_out + "00000000"
    tx = Tx.parse(coinbase)
    assert tx.serialize(include_witness=True).hex() == coinbase
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 1

    assert tx.vin[0].script_sig == tx_in.script_sig
    assert tx.vout[0].script_pub_key == tx_out.script_pub_key

    tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    assert tx.id.hex() == tx_id
    assert tx.id == tx.hash

    assert tx.size == 134
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4
    assert not tx.is_segwit()
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert tx.is_coinbase()


# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def test_wiki_transaction() -> None:
    tx_bytes = "01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.vout[0].value == 5000000
    assert tx.vout[1].value == 3354000000

    tx_id = "d4a73f51ab7ee7acb4cf0505d1fab34661666c461488e58ec30281e2becd93e2"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 258
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4
    assert not tx.is_segwit()
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase()


def test_single_witness() -> None:
    # 4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2

    stack = [
        "",
        "30440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01",
        "30440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f4401",
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    ]
    witness = Witness(stack)
    assert tx.vin[0].script_witness == witness

    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    hash_ = "d39eb3e3954be4bdc0b3be2d980124b1e1e11fb414b886b52939b07d95a58a8f"
    assert tx.hash.hex() == hash_
    assert tx.size == 380
    assert tx.vsize == 190
    assert tx.weight == 758
    assert tx.is_segwit()
    assert any(bool(w) for w in tx.vwitness)
    assert not tx.is_coinbase()


def test_double_witness() -> None:
    tx_bytes = "01000000000102322d4f05c3a4f78e97deda01bd8fc5ff96777b62c8f2daa72b02b70fa1e3e1051600000017160014e123a5263695be634abf3ad3456b4bf15f09cc6afffffffffdfee6e881f12d80cbcd6dc54c3fe390670678ebd26c3ae2dd129f41882e3efc25000000171600145946c8c3def6c79859f01b34ad537e7053cf8e73ffffffff02c763ac050000000017a9145ffd6df9bd06dedb43e7b72675388cbfc883d2098727eb180a000000001976a9145f9e96f739198f65d249ea2a0336e9aa5aa0c7ed88ac024830450221009b364c1074c602b2c5a411f4034573a486847da9c9c2467596efba8db338d33402204ccf4ac0eb7793f93a1b96b599e011fe83b3e91afdc4c7ab82d765ce1da25ace01210334d50996c36638265ad8e3cd127506994100dd7f24a5828155d531ebaf736e160247304402200c6dd55e636a2e4d7e684bf429b7800a091986479d834a8d462fbda28cf6f8010220669d1f6d963079516172f5061f923ef90099136647b38cc4b3be2a80b820bdf90121030aa2a1c2344bc8f38b7a726134501a2a45db28df8b4bee2df4428544c62d731400000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 2
    assert len(tx.vout) == 2

    stack1 = [
        "30450221009b364c1074c602b2c5a411f4034573a486847da9c9c2467596efba8db338d33402204ccf4ac0eb7793f93a1b96b599e011fe83b3e91afdc4c7ab82d765ce1da25ace01",
        "0334d50996c36638265ad8e3cd127506994100dd7f24a5828155d531ebaf736e16",
    ]
    witness1 = Witness(stack1)
    assert tx.vin[0].script_witness == witness1

    stack2 = [
        "304402200c6dd55e636a2e4d7e684bf429b7800a091986479d834a8d462fbda28cf6f8010220669d1f6d963079516172f5061f923ef90099136647b38cc4b3be2a80b820bdf901",
        "030aa2a1c2344bc8f38b7a726134501a2a45db28df8b4bee2df4428544c62d7314",
    ]
    witness2 = Witness(stack2)
    assert tx.vin[1].script_witness == witness2

    tx_id = "a4b76807519aba5740f7865396bc4c5ca0eb8aa7c3744ca2db88fcc9e345424c"
    assert tx.id.hex() == tx_id
    hash_ = "0936cb8dba90e11345b9c05f457f139ddce4a5329701af4708b2cf4a02d75adb"
    assert tx.hash.hex() == hash_
    assert tx.size == 421
    assert tx.vsize == 259
    assert tx.weight == 1033
    assert tx.is_segwit()
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase()


def test_dataclasses_json_dict() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as binary_file_:
        tx = Tx.parse(binary_file_.read())

    # Tx dataclass
    assert isinstance(tx, Tx)
    assert tx.is_segwit()
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert tx.vin[0].script_witness
    assert tx.vin[0].script_witness.stack

    # Tx dataclass to dict
    tx_dict = tx.to_dict()
    assert isinstance(tx_dict, dict)
    assert tx_dict["vin"][0]["txinwitness"]["stack"]  # type: ignore

    # Tx dataclass dict to file
    datadir = path.join(path.dirname(__file__), "_generated_files")
    filename = path.join(datadir, "tx.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(tx_dict, file_, indent=4)

    # Tx dataclass dict from file
    with open(filename, "r", encoding="ascii") as file_:
        tx_dict2 = json.load(file_)
    assert isinstance(tx_dict2, dict)
    assert tx_dict2["vin"][0]["txinwitness"]["stack"]  # type: ignore

    assert tx_dict == tx_dict2

    # Tx dataclass from dict
    tx2 = Tx.from_dict(tx_dict)
    assert isinstance(tx2, Tx)
    assert tx.vin[0] == tx2.vin[0]
    assert tx2.vin[0].script_witness
    assert tx2.vin[0].script_witness.stack
    assert tx2.is_segwit()
    assert any(bool(w) for w in tx2.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx2.vin)

    assert tx == tx2
