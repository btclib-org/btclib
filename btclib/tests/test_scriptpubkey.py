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
from btclib.network import NETWORKS
from btclib.scriptpubkey import (
    nulldata,
    p2ms,
    p2pk,
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    payload_from_scriptPubKey,
    scriptPubKey_from_payload,
)
from btclib.scriptpubkey_address import (
    address_from_scriptPubKey,
    scriptPubKey_from_address,
)
from btclib.utils import hash160, sha256


def test_nulldata() -> None:

    # self-consistency
    string = "time-stamped data"
    payload = string.encode()
    scriptPubKey = script.encode(["OP_RETURN", payload])
    assert scriptPubKey == nulldata(string)

    # to the scriptPubKey in two steps (through payload)
    script_type = "nulldata"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # data -> payload in this case is invertible (no hash functions)
    assert payload.decode() == string

    err_msg = "no address for null data script"
    with pytest.raises(ValueError, match=err_msg):
        address_from_scriptPubKey(scriptPubKey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "hello world"
    payload = string.encode()
    assert payload.hex() == "68656c6c6f20776f726c64"  # pylint: disable=no-member
    scriptPubKey = b"\x6a\x0b" + payload
    assert scriptPubKey == nulldata(string)
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "charley loves heidi"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "636861726c6579206c6f766573206865696469"
    )
    scriptPubKey = b"\x6a\x13" + payload
    assert scriptPubKey == nulldata(string)
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "家族も友達もみんなが笑顔の毎日がほしい"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184"
    )
    scriptPubKey = b"\x6a\x39" + payload
    assert scriptPubKey == nulldata(string)
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)


def test_nulldata2() -> None:

    script_type = "nulldata"

    # max length case
    byte = b"\x00"
    for length in (0, 1, 16, 17, 74, 75, 76, 77, 78, 79, 80):
        payload = byte * length
        scriptPubKey = script.encode(["OP_RETURN", payload])
        assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

        # back from the scriptPubKey to the payload
        assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)
        assert (script_type, payload, 0) == payload_from_scriptPubKey(
            script.decode(scriptPubKey)
        )


def test_nulldata3() -> None:

    err_msg = "invalid nulldata script lenght: "
    with pytest.raises(ValueError, match=err_msg):
        payload = "00" * 81
        scriptPubKey_from_payload("nulldata", payload)

    # wrong data lenght: 32 in 35-bytes nulldata script;
    # it should have been 33
    scriptPubKey = script.encode(["OP_RETURN", b"\x00" * 33])
    scriptPubKey = scriptPubKey[:1] + b"\x20" + scriptPubKey[2:]
    err_msg = "wrong data lenght: "
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    # wrong data lenght: 32 in 83-bytes nulldata script;
    # it should have been 80
    scriptPubKey = script.encode(["OP_RETURN", b"\x00" * 80])
    scriptPubKey = scriptPubKey[:2] + b"\x20" + scriptPubKey[3:]
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    # missing OP_PUSHDATA1 (0x4c) in 83-bytes nulldata script,
    # got 0x20 instead
    scriptPubKey = script.encode(["OP_RETURN", b"\x00" * 80])
    scriptPubKey = scriptPubKey[:1] + b"\x20" + scriptPubKey[2:]
    err_msg = "missing OP_PUSHDATA1 "
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    assert len(script.encode(["OP_RETURN", b"\x00" * 75])) == 77
    assert len(script.encode(["OP_RETURN", b"\x00" * 76])) == 79
    scriptPubKey = script.encode(["OP_RETURN", b"\x00" * 76])[:-1]
    err_msg = "invalid 78 bytes nulldata script length"
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)


def test_p2pk() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    scriptPubKey = script.encode([pubkey, "OP_CHECKSIG"])
    assert scriptPubKey == p2pk(pubkey)

    # to the scriptPubKey in two steps (through payload)
    script_type = "p2pk"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, pubkey)

    # back from the scriptPubKey to the payload
    assert (script_type, bytes.fromhex(pubkey), 0) == payload_from_scriptPubKey(
        scriptPubKey
    )

    err_msg = "no address for p2pk scriptPubKey"
    with pytest.raises(ValueError, match=err_msg):
        address_from_scriptPubKey(scriptPubKey)

    # documented test case: https://learnmeabitcoin.com/guide/p2pk
    pubkey = (
        "04"
        "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
        "e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
    )
    scriptPubKey = "41" + pubkey + "ac"
    assert scriptPubKey == p2pk(pubkey).hex()

    # invalid size: 34 bytes instead of (33, 65)
    pubkey = (  # fmt: off
        "03" "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414" "14"
    )  # fmt: on
    err_msg = "not a private or public key: "
    with pytest.raises(ValueError, match=err_msg):
        p2pk(pubkey)


def test_p2pkh() -> None:

    # self-consistency
    pubkey = (
        "04 "
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    )
    payload = hash160(pubkey)
    scriptPubKey = script.encode(
        ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    assert scriptPubKey == p2pkh(pubkey)

    # to the scriptPubKey in two steps (through payload)
    script_type = "p2pkh"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # base58 address
    network = "mainnet"
    address = base58address.p2pkh(pubkey, network)
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    prefix = NETWORKS[network]["p2pkh"]
    assert address == b58address_from_h160(prefix, payload, network)

    # back from the address to the scriptPubKey
    assert (scriptPubKey, network) == scriptPubKey_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2pkh
    payload = "12ab8dc588ca9d5787dde7eb29569da63c3a238c"
    scriptPubKey = "76a914" + payload + "88ac"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload).hex()
    address = b"12higDjoCCNXSA95xZMWUdPvXNmkAduhWv"
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    assert (bytes.fromhex(scriptPubKey), network) == scriptPubKey_from_address(address)

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload(script_type, "00" * 11)


def test_p2wpkh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    payload = hash160(pubkey)
    scriptPubKey = script.encode([0, payload])
    assert scriptPubKey == p2wpkh(pubkey)

    # to the scriptPubKey in two steps (through payload)
    script_type = "p2wpkh"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # bech32 address
    network = "mainnet"
    address = bech32address.p2wpkh(pubkey, network)
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    wit_ver = 0
    assert address == b32address_from_witness(wit_ver, payload, network)

    # back from the address to the scriptPubKey
    assert (scriptPubKey, network) == scriptPubKey_from_address(address)

    # p2sh-wrapped base58 address
    address = base58address.p2wpkh_p2sh(pubkey, network)
    assert address == b58address_from_witness(payload, network)


def test_p2sh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pubkey_hash = hash160(pubkey)
    redeem_script = scriptPubKey_from_payload("p2pkh", pubkey_hash)
    payload = hash160(redeem_script)
    scriptPubKey = script.encode(["OP_HASH160", payload, "OP_EQUAL"])
    assert scriptPubKey == p2sh(redeem_script)

    # to the scriptPubKey in two steps (through payload)
    script_type = "p2sh"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # base58 address
    network = "mainnet"
    address = base58address.p2sh(script.decode(redeem_script), network)
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    prefix = NETWORKS[network]["p2sh"]
    assert address == b58address_from_h160(prefix, payload, network)

    # back from the address to the scriptPubKey
    assert (scriptPubKey, network) == scriptPubKey_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2sh
    payload = "748284390f9e263a4b766a75d0633c50426eb875"
    scriptPubKey = "a914" + payload + "87"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload).hex()
    address = b"3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    assert (bytes.fromhex(scriptPubKey), network) == scriptPubKey_from_address(address)

    # invalid size: 21 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload(script_type, "00" * 21)


def test_p2wsh() -> None:

    # self-consistency
    pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pubkey_hash = hash160(pubkey)
    redeem_script = scriptPubKey_from_payload("p2pkh", pubkey_hash)
    payload = sha256(redeem_script)
    scriptPubKey = script.encode([0, payload])
    assert scriptPubKey == p2wsh(script.decode(redeem_script))

    # to the scriptPubKey in two steps (through payload)
    script_type = "p2wsh"
    assert scriptPubKey == scriptPubKey_from_payload(script_type, payload)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, 0) == payload_from_scriptPubKey(scriptPubKey)

    # bech32 address
    network = "mainnet"
    address = bech32address.p2wsh(redeem_script, network)
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    wit_ver = 0
    assert address == b32address_from_witness(wit_ver, payload, network)

    # back from the address to the scriptPubKey
    assert (scriptPubKey, network) == scriptPubKey_from_address(address)

    # p2sh-wrapped base58 address
    address = base58address.p2wsh_p2sh(redeem_script, network)
    assert address == b58address_from_witness(payload, network)


def test_exceptions() -> None:

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload("p2wpkh", "00" * 11)

    # invalid size: 33 bytes instead of 32
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload("p2wsh", "00" * 33)

    err_msg = "unknown scriptPubKey type: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload("p2unkn", "00" * 32)

    err_msg = "unknown scriptPubKey: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey = [16, 20 * b"\x00"]
        address_from_scriptPubKey(scriptPubKey)

    # Unhandled witness version (16)
    err_msg = "unmanaged witness version: "
    address = b32address_from_witness(16, 20 * b"\x00")
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_address(address)


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

    # straight to the scriptPubKey
    payload = sorted(pubkeys)
    n = len(pubkeys)
    scriptPubKey = script.encode([m] + payload + [n, "OP_CHECKMULTISIG"])
    assert scriptPubKey == p2ms(pubkeys, m)

    # to the scriptPubKey in two steps (through payload)
    assert scriptPubKey == scriptPubKey_from_payload(script_type, pubkeys, m)

    # back from the scriptPubKey to the payload
    assert (script_type, payload, m) == payload_from_scriptPubKey(scriptPubKey)

    err_msg = "no address for p2ms scriptPubKey"
    with pytest.raises(ValueError, match=err_msg):
        address_from_scriptPubKey(scriptPubKey)

    # documented test case: https://learnmeabitcoin.com/guide/p2ms
    pubkeys = [bytes.fromhex(pubkey1), bytes.fromhex(pubkey2)]
    m = 1
    n = 2
    scriptPubKey = (  # fmt: off
        "51"  # OP_1
        "41"  # canonical 65-bytes push
        + pubkey1
        + "41"  # noqa E148  # canonical 65-bytes push
        + pubkey2
        + "52"  # noqa E148  # OP_2
        "ae"  # OP_CHECKMULTISIG
    )  # fmt: on
    assert scriptPubKey == p2ms(pubkeys, 1, lexicographic_sort=False).hex()

    err_msg = "number-of-pubkeys < m in "
    with pytest.raises(ValueError, match=err_msg):
        p2ms(pubkeys, 3)

    err_msg = "invalid m for p2ms scriptPubKey: "
    with pytest.raises(ValueError, match=err_msg):
        p2ms(pubkeys, 0)

    err_msg = "not a private or public key: "
    with pytest.raises(ValueError, match=err_msg):
        p2ms([pubkey1 + "00", pubkey2], 1)

    err_msg = "too many pubkeys in m-of-n multisignature: "
    with pytest.raises(ValueError, match=err_msg):
        p2ms([pubkey1] * 17, 3)

    err_msg = "invalid size: "
    badpubkeys = sorted(pubkeys)
    badpubkeys[0] = badpubkeys[0] + b"\x00"
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload(script_type, badpubkeys, m)

    scriptPubKey = script.encode([m] + sorted(badpubkeys) + [n, "OP_CHECKMULTISIG"])
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    err_msg = "invalid key in p2ms"
    scriptPubKey = script.encode([m] + [0, pubkeys[1]] + [n, "OP_CHECKMULTISIG"])
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    err_msg = "invalid m in m-of-n multisignature: "
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload(script_type, pubkeys, 17)


def test_p2ms_2() -> None:

    pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    pubkey3 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    pubkeys = [pubkey1, pubkey2, pubkey3]
    m = 1
    n = len(pubkeys)
    scriptPubKey = [m] + pubkeys + [n, "OP_CHECKMULTISIG"]
    payload_from_scriptPubKey(scriptPubKey)
    scriptPubKey_from_payload("p2ms", pubkeys, m)

    err_msg = "invalid list of Octets for p2sh scriptPubKey"
    with pytest.raises(ValueError, match=err_msg):
        scriptPubKey_from_payload("p2sh", pubkeys, 0)

    err_msg = "invalid number of pubkeys in "
    scriptPubKey = [1, 3, "OP_CHECKMULTISIG"]
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    err_msg = "wrong number of pubkeys in "
    scriptPubKey = [1, pubkey1, pubkey2, 3, "OP_CHECKMULTISIG"]
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    err_msg = "invalid number of pubkeys in "
    scriptPubKey = [3, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    err_msg = "invalid m in m-of-n multisignature: "
    scriptPubKey = [0, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)

    scriptPubKey = script.encode([1, pubkey1, pubkey2, pubkey3, 3, "OP_CHECKMULTISIG"])
    scriptPubKey = scriptPubKey[:133] + b"\x40" + scriptPubKey[134:]
    err_msg = "wrong number of pubkeys in "
    with pytest.raises(ValueError, match=err_msg):
        payload_from_scriptPubKey(scriptPubKey)


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
    scriptPubKey = scriptPubKey_from_payload("p2ms", pubkeys, m)
    pubkeys.sort()
    exp_script = script.encode([m] + pubkeys + [n, "OP_CHECKMULTISIG"])
    assert scriptPubKey.hex() == exp_script.hex()
    script_type, payload, m2 = payload_from_scriptPubKey(scriptPubKey)
    assert script_type == "p2ms"
    assert m == m2
    assert pubkeys == payload


def test_p2ms_p2sh() -> None:
    "BIP67 test vectors https://en.bitcoin.it/wiki/BIP_0067"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip67_test_vectors.json")
    with open(filename, "r") as f:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(f)

    m = 2
    for i in test_vectors:
        keys, address = test_vectors[i]
        errmsg = f"Test vector #{int(i)}"
        scriptPubKey = p2ms(keys, m)
        addr = base58address.p2sh(scriptPubKey)
        assert addr.decode() == address, errmsg

        scriptPubKey = scriptPubKey_from_payload("p2ms", keys, m)
        addr = base58address.p2sh(scriptPubKey)
        assert addr.decode() == address, errmsg

        script_type, payload, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == "p2ms", errmsg
        for key, k in zip(sorted(keys), payload):
            assert key == k.hex(), errmsg
        assert m2 == m, errmsg


def test_CLT() -> None:

    network = "mainnet"

    fed_pubkeys = [b"\x00" * 33, b"\x11" * 33, b"\x22" * 33]
    rec_pubkeys = [b"\x77" * 33, b"\x88" * 33, b"\x99" * 33]
    # fmt: off
    redeem_script = script.encode(
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
    scriptPubKey = (
        "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708"
    )
    assert scriptPubKey == p2wsh(redeem_script).hex()
    assert scriptPubKey == scriptPubKey_from_payload("p2wsh", payload).hex()

    address = b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj"
    assert address == address_from_scriptPubKey(scriptPubKey, network)
    assert address == b32address_from_witness(0, payload, network)
