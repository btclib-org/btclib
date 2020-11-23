#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.scriptpubkey` module."

import json
from os import path

import pytest

from btclib import base58address, bech32address, script
from btclib.base58address import b58address_from_h160, b58address_from_witness
from btclib.bech32address import b32address_from_witness
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib.scriptpubkey import (
    nulldata,
    p2ms,
    p2pk,
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    payload_from_script_pubkey,
    script_pubkey_from_payload,
)
from btclib.scriptpubkey_address import (
    address_from_script_pubkey,
    script_pubkey_from_address,
)
from btclib.utils import hash160, sha256


def test_nulldata() -> None:

    # self-consistency
    string = "time-stamped data"
    payload = string.encode()
    script_pubkey = script.serialize(["OP_RETURN", payload])
    assert script_pubkey == nulldata(string)

    # to the script_pubkey in two steps (through payload)
    script_type = "nulldata"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)

    # back from the script_pubkey to the payload
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # data -> payload in this case is invertible (no hash functions)
    assert payload.decode("ascii") == string

    err_msg = "no address for null data script"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_script_pubkey(script_pubkey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "hello world"
    payload = string.encode()
    assert payload.hex() == "68656c6c6f20776f726c64"  # pylint: disable=no-member
    script_pubkey = b"\x6a\x0b" + payload
    assert script_pubkey == nulldata(string)
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "charley loves heidi"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "636861726c6579206c6f766573206865696469"
    )
    script_pubkey = b"\x6a\x13" + payload
    assert script_pubkey == nulldata(string)
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "家族も友達もみんなが笑顔の毎日がほしい"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184"
    )
    script_pubkey = b"\x6a\x39" + payload
    assert script_pubkey == nulldata(string)
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)


def test_nulldata2() -> None:

    script_type = "nulldata"

    # max length case
    byte = b"\x00"
    for length in (0, 1, 16, 17, 74, 75, 76, 77, 78, 79, 80):
        payload = byte * length
        script_pubkey = script.serialize(["OP_RETURN", payload])
        assert script_pubkey == script_pubkey_from_payload(script_type, payload)

        # back from the script_pubkey to the payload
        assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)
        assert (script_type, payload, 0) == payload_from_script_pubkey(
            script.deserialize(script_pubkey)
        )


def test_nulldata3() -> None:

    err_msg = "invalid nulldata script length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload = "00" * 81
        script_pubkey_from_payload("nulldata", payload)

    # wrong data length: 32 in 35-bytes nulldata script;
    # it should have been 33
    script_pubkey = script.serialize(["OP_RETURN", b"\x00" * 33])
    script_pubkey = script_pubkey[:1] + b"\x20" + script_pubkey[2:]
    err_msg = "wrong data length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    # wrong data length: 32 in 83-bytes nulldata script;
    # it should have been 80
    script_pubkey = script.serialize(["OP_RETURN", b"\x00" * 80])
    script_pubkey = script_pubkey[:2] + b"\x20" + script_pubkey[3:]
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    # missing OP_PUSHDATA1 (0x4c) in 83-bytes nulldata script,
    # got 0x20 instead
    script_pubkey = script.serialize(["OP_RETURN", b"\x00" * 80])
    script_pubkey = script_pubkey[:1] + b"\x20" + script_pubkey[2:]
    err_msg = "missing OP_PUSHDATA1 "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    assert len(script.serialize(["OP_RETURN", b"\x00" * 75])) == 77
    assert len(script.serialize(["OP_RETURN", b"\x00" * 76])) == 79
    script_pubkey = script.serialize(["OP_RETURN", b"\x00" * 76])[:-1]
    err_msg = "invalid 78 bytes nulldata script length"
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)


def test_p2pk() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    script_pubkey = script.serialize([pubkey, "OP_CHECKSIG"])
    assert script_pubkey == p2pk(pubkey)

    # to the script_pubkey in two steps (through payload)
    script_type = "p2pk"
    assert script_pubkey == script_pubkey_from_payload(script_type, pubkey)

    # back from the script_pubkey to the payload
    assert (script_type, bytes.fromhex(pubkey), 0) == payload_from_script_pubkey(
        script_pubkey
    )

    err_msg = "no address for p2pk script_pubkey"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_script_pubkey(script_pubkey)

    # documented test case: https://learnmeabitcoin.com/guide/p2pk
    pubkey = (
        "04"
        "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
        "e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
    )
    script_pubkey = "41" + pubkey + "ac"
    assert script_pubkey == p2pk(pubkey).hex()

    # invalid size: 34 bytes instead of (33, 65)
    pubkey = "03 ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414 14"
    err_msg = "not a private or public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2pk(pubkey)


def test_p2pkh() -> None:

    # self-consistency
    pubkey = (
        "04 "
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    )
    payload = hash160(pubkey)
    script_pubkey = script.serialize(
        ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    assert script_pubkey == p2pkh(pubkey)

    # to the script_pubkey in two steps (through payload)
    script_type = "p2pkh"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)

    # back from the script_pubkey to the payload
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # base58 address
    network = "mainnet"
    address = base58address.p2pkh(pubkey, network)
    assert address == address_from_script_pubkey(script_pubkey, network)
    prefix = NETWORKS[network].p2pkh
    assert address == b58address_from_h160(prefix, payload, network)

    # back from the address to the script_pubkey
    assert (script_pubkey, network) == script_pubkey_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2pkh
    payload = "12ab8dc588ca9d5787dde7eb29569da63c3a238c"
    script_pubkey = "76a914" + payload + "88ac"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload).hex()
    address = b"12higDjoCCNXSA95xZMWUdPvXNmkAduhWv"
    assert address == address_from_script_pubkey(script_pubkey, network)
    assert (bytes.fromhex(script_pubkey), network) == script_pubkey_from_address(
        address
    )

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload(script_type, "00" * 11)


def test_p2wpkh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    payload = hash160(pubkey)
    script_pubkey = script.serialize([0, payload])
    assert script_pubkey == p2wpkh(pubkey)

    # to the script_pubkey in two steps (through payload)
    script_type = "p2wpkh"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)

    # back from the script_pubkey to the payload
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # bech32 address
    network = "mainnet"
    address = bech32address.p2wpkh(pubkey, network)
    assert address == address_from_script_pubkey(script_pubkey, network)
    wit_ver = 0
    assert address == b32address_from_witness(wit_ver, payload, network)

    # back from the address to the script_pubkey
    assert (script_pubkey, network) == script_pubkey_from_address(address)

    # p2sh-wrapped base58 address
    address = base58address.p2wpkh_p2sh(pubkey, network)
    assert address == b58address_from_witness(payload, network)


def test_p2sh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pubkey_hash = hash160(pubkey)
    redeem_script = script_pubkey_from_payload("p2pkh", pubkey_hash)
    payload = hash160(redeem_script)
    script_pubkey = script.serialize(["OP_HASH160", payload, "OP_EQUAL"])
    assert script_pubkey == p2sh(redeem_script)

    # to the script_pubkey in two steps (through payload)
    script_type = "p2sh"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)

    # back from the script_pubkey to the payload
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # base58 address
    network = "mainnet"
    address = base58address.p2sh(script.deserialize(redeem_script), network)
    assert address == address_from_script_pubkey(script_pubkey, network)
    prefix = NETWORKS[network].p2sh
    assert address == b58address_from_h160(prefix, payload, network)

    # back from the address to the script_pubkey
    assert (script_pubkey, network) == script_pubkey_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2sh
    payload = "748284390f9e263a4b766a75d0633c50426eb875"
    script_pubkey = "a914" + payload + "87"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload).hex()
    address = b"3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
    assert address == address_from_script_pubkey(script_pubkey, network)
    assert (bytes.fromhex(script_pubkey), network) == script_pubkey_from_address(
        address
    )

    # invalid size: 21 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload(script_type, "00" * 21)


def test_p2wsh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pubkey_hash = hash160(pubkey)
    redeem_script = script_pubkey_from_payload("p2pkh", pubkey_hash)
    payload = sha256(redeem_script)
    script_pubkey = script.serialize([0, payload])
    assert script_pubkey == p2wsh(script.deserialize(redeem_script))

    # to the script_pubkey in two steps (through payload)
    script_type = "p2wsh"
    assert script_pubkey == script_pubkey_from_payload(script_type, payload)

    # back from the script_pubkey to the payload
    assert (script_type, payload, 0) == payload_from_script_pubkey(script_pubkey)

    # bech32 address
    network = "mainnet"
    address = bech32address.p2wsh(redeem_script, network)
    assert address == address_from_script_pubkey(script_pubkey, network)
    wit_ver = 0
    assert address == b32address_from_witness(wit_ver, payload, network)

    # back from the address to the script_pubkey
    assert (script_pubkey, network) == script_pubkey_from_address(address)

    # p2sh-wrapped base58 address
    address = base58address.p2wsh_p2sh(redeem_script, network)
    assert address == b58address_from_witness(payload, network)


def test_exceptions() -> None:

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload("p2wpkh", "00" * 11)

    # invalid size: 33 bytes instead of 32
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload("p2wsh", "00" * 33)

    err_msg = "unknown script_pubkey type: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload("p2unkn", "00" * 32)

    err_msg = "unknown script_pubkey: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey = [16, 20 * b"\x00"]
        address_from_script_pubkey(script_pubkey)

    # Unhandled witness version (16)
    err_msg = "unmanaged witness version: "
    address = b32address_from_witness(16, 20 * b"\x00")
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_address(address)


def test_p2ms() -> None:

    script_type = "p2ms"

    # self-consistency
    pubkey1 = (
        "04"
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    )
    pubkey2 = (
        "04"
        "61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
        "19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    )
    pubkeys = [bytes.fromhex(pubkey1), bytes.fromhex(pubkey2)]
    m = 1

    # straight to the script_pubkey
    payload = sorted(pubkeys)
    n = len(pubkeys)
    script_pubkey = script.serialize([m] + payload + [n, "OP_CHECKMULTISIG"])
    assert script_pubkey == p2ms(pubkeys, m)

    # to the script_pubkey in two steps (through payload)
    assert script_pubkey == script_pubkey_from_payload(script_type, pubkeys, m)

    # back from the script_pubkey to the payload
    assert (script_type, payload, m) == payload_from_script_pubkey(script_pubkey)

    err_msg = "no address for p2ms script_pubkey"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_script_pubkey(script_pubkey)

    # documented test case: https://learnmeabitcoin.com/guide/p2ms
    pubkeys = [bytes.fromhex(pubkey1), bytes.fromhex(pubkey2)]
    m = 1
    n = 2
    script_pubkey = (  # fmt: off
        "51"  # OP_1
        "41"  # canonical 65-bytes push
        + pubkey1
        + "41"  # noqa E148  # canonical 65-bytes push
        + pubkey2
        + "52"  # noqa E148  # OP_2
        "ae"  # OP_CHECKMULTISIG
    )  # fmt: on
    assert script_pubkey == p2ms(pubkeys, 1, lexicographic_sort=False).hex()

    err_msg = "number-of-pubkeys < m in "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(pubkeys, 3)

    err_msg = "invalid m for p2ms script_pubkey: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(pubkeys, 0)

    err_msg = "not a private or public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms([pubkey1 + "00", pubkey2], 1)

    err_msg = "too many pubkeys in m-of-n multisignature: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms([pubkey1] * 17, 3)

    err_msg = "invalid size: "
    badpubkeys = sorted(pubkeys)
    badpubkeys[0] = badpubkeys[0] + b"\x00"
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload(script_type, badpubkeys, m)

    script_pubkey = script.serialize([m] + sorted(badpubkeys) + [n, "OP_CHECKMULTISIG"])
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    err_msg = "invalid key in p2ms"
    script_pubkey = script.serialize([m] + [0, pubkeys[1]] + [n, "OP_CHECKMULTISIG"])
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    err_msg = "invalid m in m-of-n multisignature: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload(script_type, pubkeys, 17)


def test_p2ms_2() -> None:

    pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    pubkey3 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    pubkeys = [pubkey1, pubkey2, pubkey3]
    m = 1
    n = len(pubkeys)
    script_pubkey = [m] + pubkeys + [n, "OP_CHECKMULTISIG"]
    payload_from_script_pubkey(script_pubkey)
    script_pubkey_from_payload("p2ms", pubkeys, m)

    err_msg = "invalid list of Octets for p2sh script_pubkey"
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pubkey_from_payload("p2sh", pubkeys, 0)

    err_msg = "invalid number of pubkeys in "
    script_pubkey = [1, 3, "OP_CHECKMULTISIG"]
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    err_msg = "wrong number of pubkeys in "
    script_pubkey = [1, pubkey1, pubkey2, 3, "OP_CHECKMULTISIG"]
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    err_msg = "invalid number of pubkeys in "
    script_pubkey = [3, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    err_msg = "invalid m in m-of-n multisignature: "
    script_pubkey = [0, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)

    script_pubkey = script.serialize(
        [1, pubkey1, pubkey2, pubkey3, 3, "OP_CHECKMULTISIG"]
    )
    script_pubkey = script_pubkey[:133] + b"\x40" + script_pubkey[134:]
    err_msg = "wrong number of pubkeys in "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload_from_script_pubkey(script_pubkey)


def test_p2ms_3() -> None:

    # mixed compressed / uncompressed public keys
    pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pubkey2 = "03 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
    pubkey3 = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    pubkeys = [
        bytes.fromhex(pubkey1),
        bytes.fromhex(pubkey2),
        bytes.fromhex(pubkey3),
    ]
    m = 1
    n = len(pubkeys)
    script_pubkey = script_pubkey_from_payload("p2ms", pubkeys, m)
    pubkeys.sort()
    exp_script = script.serialize([m] + pubkeys + [n, "OP_CHECKMULTISIG"])
    assert script_pubkey.hex() == exp_script.hex()
    script_type, payload, m2 = payload_from_script_pubkey(script_pubkey)
    assert script_type == "p2ms"
    assert m == m2
    assert pubkeys == payload


def test_p2ms_p2sh() -> None:
    "BIP67 test vectors https://en.bitcoin.it/wiki/BIP_0067"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip67_test_vectors.json")
    with open(filename, "r") as file_:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(file_)

    m = 2
    for i in test_vectors:
        keys, address = test_vectors[i]
        errmsg = f"Test vector #{i}"
        script_pubkey = p2ms(keys, m)
        addr = base58address.p2sh(script_pubkey)
        assert addr.decode("ascii") == address, errmsg

        script_pubkey = script_pubkey_from_payload("p2ms", keys, m)
        addr = base58address.p2sh(script_pubkey)
        assert addr.decode("ascii") == address, errmsg

        script_type, payload, m2 = payload_from_script_pubkey(script_pubkey)
        assert script_type == "p2ms", errmsg
        for key, k in zip(sorted(keys), payload):
            assert key == k.hex(), errmsg
        assert m2 == m, errmsg


def test_non_standard_script() -> None:

    network = "mainnet"

    fed_pubkeys = [b"\x00" * 33, b"\x11" * 33, b"\x22" * 33]
    rec_pubkeys = [b"\x77" * 33, b"\x88" * 33, b"\x99" * 33]
    # fmt: off
    redeem_script = script.serialize(
        [
            "OP_IF",
                2, *fed_pubkeys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ELSE",
                500, "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",  # noqa E131
                2, *rec_pubkeys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ENDIF",
        ]
    )
    # fmt: on
    payload = sha256(redeem_script)
    script_pubkey = (
        "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708"
    )
    assert script_pubkey == p2wsh(redeem_script).hex()
    assert script_pubkey == script_pubkey_from_payload("p2wsh", payload).hex()

    address = b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj"
    assert address == address_from_script_pubkey(script_pubkey, network)
    assert address == b32address_from_witness(0, payload, network)
