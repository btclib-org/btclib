#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script_pub_key` module."

import json
from os import path
from typing import List

import pytest

from btclib import base58_address, bech32_address, script, var_bytes
from btclib.base58_address import (
    base58_address_from_h160,
    base58_address_from_witness,
)
from btclib.bech32_address import bech32_address_from_witness
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib.script import Script
from btclib.script_pub_key import (
    assert_p2ms,
    assert_p2pk,
    assert_p2pkh,
    assert_p2sh,
    assert_p2wpkh,
    assert_p2wsh,
    is_nulldata,
    is_p2ms,
    nulldata,
    p2ms,
    p2pk,
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    payload_from_script_pub_key,
    script_pub_key_from_payload,
)
from btclib.script_pub_key_address import (
    address_from_script_pub_key,
    script_pub_key_from_address,
)
from btclib.to_pub_key import Key
from btclib.utils import hash160, sha256


def test_nulldata() -> None:

    OP_RETURN = b"\x6a"  # pylint: disable=invalid-name

    # self-consistency
    string = "time-stamped data"
    payload = string.encode()
    script_pub_key = script.serialize(["OP_RETURN", payload])
    assert script_pub_key == nulldata(string)

    # to the script_pub_key in two steps (through payload)
    script_type = "nulldata"
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)

    # back from the script_pub_key to the payload
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # data -> payload in this case is invertible (no hash functions)
    assert payload.decode("ascii") == string

    assert address_from_script_pub_key(script_pub_key) == ""

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "hello world"
    payload = string.encode()
    assert payload.hex() == "68656c6c6f20776f726c64"  # pylint: disable=no-member
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == nulldata(string)
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "charley loves heidi"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "636861726c6579206c6f766573206865696469"
    )
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == nulldata(string)
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "家族も友達もみんなが笑顔の毎日がほしい"
    payload = string.encode()
    assert (
        payload.hex()  # pylint: disable=no-member
        == "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184"
    )
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == nulldata(string)
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)


def test_nulldata2() -> None:

    script_type = "nulldata"

    # max length case
    byte = b"\x00"
    for length in (0, 1, 16, 17, 74, 75, 76, 77, 78, 79, 80):
        payload = byte * length
        script_pub_key = script.serialize(["OP_RETURN", payload])
        assert script_pub_key == script_pub_key_from_payload(script_type, payload)

        # back from the script_pub_key to the payload
        assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)


def test_nulldata3() -> None:

    err_msg = "invalid nulldata script length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload = "00" * 81
        script_pub_key_from_payload("nulldata", payload)

    # wrong data length: 32 in 35-bytes nulldata script;
    # it should have been 33
    script_pub_key = script.serialize(["OP_RETURN", b"\x00" * 33])
    script_pub_key = script_pub_key[:1] + b"\x20" + script_pub_key[2:]
    assert not is_nulldata(script_pub_key)

    # wrong data length: 32 in 83-bytes nulldata script;
    # it should have been 80
    script_pub_key = script.serialize(["OP_RETURN", b"\x00" * 80])
    script_pub_key = script_pub_key[:2] + b"\x20" + script_pub_key[3:]
    assert not is_nulldata(script_pub_key)

    # missing OP_PUSHDATA1 (0x4c) in 83-bytes nulldata script,
    # got 0x20 instead
    script_pub_key = script.serialize(["OP_RETURN", b"\x00" * 80])
    script_pub_key = script_pub_key[:1] + b"\x20" + script_pub_key[2:]
    assert not is_nulldata(script_pub_key)

    assert len(script.serialize(["OP_RETURN", b"\x00" * 75])) == 77
    assert len(script.serialize(["OP_RETURN", b"\x00" * 76])) == 79
    script_pub_key = script.serialize(["OP_RETURN", b"\x00" * 76])[:-1]
    assert not is_nulldata(script_pub_key)


def test_nulldata4() -> None:

    script_: Script = ["OP_RETURN", "OP_RETURN", 3, 1, "OP_VERIF", 0, 3]
    # FIXME: serialization is not 0x6A{1 byte data-length}{data 6 bytes)}
    script_pub_key = script.serialize(script_)
    assert len(script_pub_key) == 7
    assert script.deserialize(script_pub_key) == script_
    script_type, _ = payload_from_script_pub_key(script_pub_key)
    # FIXME: it should be "nulldata"
    assert script_type == "unknown"
    # assert is_nulldata(script_pub_key)


def test_p2pk() -> None:

    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    script_pub_key = script.serialize([pub_key, "OP_CHECKSIG"])
    assert_p2pk(script_pub_key)
    assert script_pub_key == p2pk(pub_key)

    script_type = "p2pk"
    assert script_pub_key == script_pub_key_from_payload(script_type, pub_key)

    # back from the script_pub_key to the payload
    assert (script_type, bytes.fromhex(pub_key)) == payload_from_script_pub_key(
        script_pub_key
    )

    assert address_from_script_pub_key(script_pub_key) == ""

    err_msg = "invalid pub_key length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(b"\x31" + script_pub_key[1:])

    # documented test case: https://learnmeabitcoin.com/guide/p2pk
    pub_key = (
        "04"
        "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
        "e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
    )
    script_pub_key = bytes.fromhex("41" + pub_key + "ac")
    assert_p2pk(script_pub_key)
    assert script_pub_key == p2pk(pub_key)

    err_msg = "missing final OP_CHECKSIG"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(script_pub_key[:-1] + b"\x00")

    err_msg = "invalid pub_key length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(b"\x31" + script_pub_key[1:])

    # invalid size: 34 bytes instead of (33, 65)
    pub_key = "03 ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414 14"
    err_msg = "not a private or public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2pk(pub_key)


def test_p2pkh() -> None:

    # self-consistency
    pub_key = (
        "04 "
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    )
    payload = hash160(pub_key)
    script_pub_key = script.serialize(
        ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    assert_p2pkh(script_pub_key)
    assert script_pub_key == p2pkh(pub_key)

    # to the script_pub_key in two steps (through payload)
    script_type = "p2pkh"
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)

    # back from the script_pub_key to the payload
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # base58 address
    network = "mainnet"
    address = base58_address.p2pkh(pub_key, network)
    assert address == address_from_script_pub_key(script_pub_key, network)
    prefix = NETWORKS[network].p2pkh
    assert address == base58_address_from_h160(prefix, payload, network)

    # back from the address to the script_pub_key
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2pkh
    payload = bytes.fromhex("12ab8dc588ca9d5787dde7eb29569da63c3a238c")
    script_pub_key = bytes.fromhex("76a914") + payload + bytes.fromhex("88ac")
    assert_p2pkh(script_pub_key)
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)
    address = "12higDjoCCNXSA95xZMWUdPvXNmkAduhWv"
    assert address == address_from_script_pub_key(script_pub_key, network)
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    err_msg = "missing final OP_EQUALVERIFY, OP_CHECKSIG"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(script_pub_key[:-2] + b"\x40\x40")

    err_msg = "missing leading OP_DUP, OP_HASH160"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(b"\x40\x40" + script_pub_key[2:])

    err_msg = "invalid pub_key hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(script_pub_key[:2] + b"\x40" + script_pub_key[3:])

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_payload(script_type, "00" * 11)


def test_p2wpkh() -> None:

    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    payload = hash160(pub_key)
    script_pub_key = script.serialize([0, payload])
    assert_p2wpkh(script_pub_key)
    assert script_pub_key == p2wpkh(pub_key)

    # to the script_pub_key in two steps (through payload)
    script_type = "p2wpkh"
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)

    # back from the script_pub_key to the payload
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # bech32 address
    network = "mainnet"
    address = bech32_address.p2wpkh(pub_key, network)
    assert address == address_from_script_pub_key(script_pub_key, network)
    wit_ver = 0
    assert address == bech32_address_from_witness(wit_ver, payload, network)

    # back from the address to the script_pub_key
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    # p2sh-wrapped base58 address
    address = base58_address.p2wpkh_p2sh(pub_key, network)
    assert address == base58_address_from_witness(payload, network)

    err_msg = "invalid witness version: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wpkh(b"\x33" + script_pub_key[1:])

    err_msg = "invalid pub_key hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wpkh(script_pub_key[:1] + b"\x00" + script_pub_key[2:])


def test_p2sh() -> None:

    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pub_key_hash = hash160(pub_key)
    redeem_script = script_pub_key_from_payload("p2pkh", pub_key_hash)
    payload = hash160(redeem_script)
    script_pub_key = script.serialize(["OP_HASH160", payload, "OP_EQUAL"])
    assert_p2sh(script_pub_key)
    assert script_pub_key == p2sh(redeem_script)

    # to the script_pub_key in two steps (through payload)
    script_type = "p2sh"
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)

    # back from the script_pub_key to the payload
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # base58 address
    network = "mainnet"
    address = base58_address.p2sh(redeem_script, network)
    assert address == address_from_script_pub_key(script_pub_key, network)
    prefix = NETWORKS[network].p2sh
    assert address == base58_address_from_h160(prefix, payload, network)

    # back from the address to the script_pub_key
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    # documented test case: https://learnmeabitcoin.com/guide/p2sh
    payload = bytes.fromhex("748284390f9e263a4b766a75d0633c50426eb875")
    script_pub_key = bytes.fromhex("a914") + payload + bytes.fromhex("87")
    assert_p2sh(script_pub_key)
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)
    address = "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
    assert address == address_from_script_pub_key(script_pub_key, network)
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    err_msg = "missing final OP_EQUAL"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(script_pub_key[:-1] + b"\x40")

    err_msg = "missing leading OP_HASH160"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(b"\x40" + script_pub_key[1:])

    err_msg = "invalid redeem script hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(script_pub_key[:1] + b"\x40" + script_pub_key[2:])

    # invalid size: 21 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_payload(script_type, "00" * 21)


def test_p2wsh() -> None:

    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    pub_key_hash = hash160(pub_key)
    redeem_script = script_pub_key_from_payload("p2pkh", pub_key_hash)
    payload = sha256(redeem_script)
    script_pub_key = script.serialize([0, payload])
    assert_p2wsh(script_pub_key)
    assert script_pub_key == p2wsh(redeem_script)

    script_type = "p2wsh"
    assert script_pub_key == script_pub_key_from_payload(script_type, payload)

    # back from the script_pub_key to the payload
    assert (script_type, payload) == payload_from_script_pub_key(script_pub_key)

    # bech32 address
    network = "mainnet"
    address = bech32_address.p2wsh(redeem_script, network)
    assert address == address_from_script_pub_key(script_pub_key, network)
    wit_ver = 0
    assert address == bech32_address_from_witness(wit_ver, payload, network)

    # back from the address to the script_pub_key
    assert (script_pub_key, network) == script_pub_key_from_address(address)

    # p2sh-wrapped base58 address
    address = base58_address.p2wsh_p2sh(redeem_script, network)
    assert address == base58_address_from_witness(payload, network)

    err_msg = "invalid witness version: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wsh(b"\x33" + script_pub_key[1:])

    err_msg = "invalid redeem script hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wsh(script_pub_key[:1] + b"\x00" + script_pub_key[2:])


def test_unknown() -> None:

    script_pub_key = script.serialize([16, 20 * b"\x00"])
    assert address_from_script_pub_key(script_pub_key) == ""
    assert payload_from_script_pub_key(script_pub_key) == ("unknown", script_pub_key)


def test_exceptions() -> None:

    # invalid size: 11 bytes instead of 20
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_payload("p2wpkh", "00" * 11)

    # invalid size: 33 bytes instead of 32
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_payload("p2wsh", "00" * 33)

    err_msg = "unknown script_pub_key type: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_payload("p2unkn", "00" * 32)

    # Unhandled witness version (16)
    err_msg = "unmanaged witness version: "
    address = bech32_address_from_witness(16, 20 * b"\x00")
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key_from_address(address)


def test_p2ms_1() -> None:

    # self-consistency
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"

    # documented test case: https://learnmeabitcoin.com/guide/p2ms
    script_pub_key = bytes.fromhex(  # fmt: off
        "51"  # OP_1
        "41"  # canonical 65-bytes push
        + pub_key0
        + "41"  # noqa E148  # canonical 65-bytes push
        + pub_key1
        + "52"  # noqa E148  # OP_2
        "ae"  # OP_CHECKMULTISIG
    )  # fmt: on
    assert is_p2ms(script_pub_key)
    assert address_from_script_pub_key(script_pub_key) == ""
    script_type, payload = payload_from_script_pub_key(script_pub_key)
    assert script_type == "p2ms"
    assert payload == script_pub_key[:-1]
    assert script_pub_key == script_pub_key_from_payload("p2ms", payload)

    pub_keys: List[Key] = [pub_key0, pub_key1]
    err_msg = "invalid p2ms payload"
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(4, pub_keys)
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(4, [pub_key0] * 17)
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(0, pub_keys)
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(17, pub_keys)

    err_msg = "not a private or public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2ms(1, [pub_key0 + "00", pub_key1])

    script_: Script = [1, pub_key0 + "00", pub_key1, 2, "OP_CHECKMULTISIG"]
    script_pub_key = script.serialize(script_)
    assert not is_p2ms(script_pub_key)

    err_msg = "invalid key in p2ms"
    script_pub_key = script.serialize([1, pub_key0, "00", 2, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = script.serialize([1, pub_key0, pub_key1, 2, "OP_CHECKMULTISIG"])
    assert is_p2ms(script_pub_key)

    script_pub_key = script.serialize([2, pub_key0, pub_key1, 2, "OP_CHECKMULTISIG"])
    assert is_p2ms(script_pub_key)

    script_pub_key = script.serialize([0, pub_key0, pub_key1, 2, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = script.serialize([3, pub_key0, pub_key1, 2, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = script.serialize([1, 2, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = script.serialize([1, pub_key0, 2, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = script.serialize([1, pub_key0, pub_key1, 3, "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    pub_key2 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    script_pub_key = script.serialize(
        [1, pub_key0, pub_key1, pub_key2, 3, "OP_CHECKMULTISIG"]
    )
    assert_p2ms(script_pub_key)

    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2ms(script_pub_key[:133] + b"\x40" + script_pub_key[134:])

    err_msg = "invalid extra data"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2ms(script_pub_key[:-2] + b"\x00" + script_pub_key[-2:])


def test_p2ms_2() -> None:

    m = 1

    # all uncompressed
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    pub_key2 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    uncompressed_pub_keys: List[Key] = [pub_key0, pub_key1, pub_key2]
    # mixed compressed / uncompressed public keys
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "03 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
    pub_key2 = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    mixed_pub_keys: List[Key] = [pub_key0, pub_key1, pub_key2]

    for pub_keys in (uncompressed_pub_keys, mixed_pub_keys):
        for lexi_sort in (True, False):
            script_pub_key = p2ms(m, pub_keys, lexi_sort=lexi_sort)
            assert is_p2ms(script_pub_key)
            assert address_from_script_pub_key(script_pub_key) == ""
            script_type, payload = payload_from_script_pub_key(script_pub_key)
            assert script_type == "p2ms"
            assert payload == script_pub_key[:-1]
            assert script_pub_key == script_pub_key_from_payload("p2ms", payload)


def test_bip67() -> None:
    "BIP67 test vectors https://en.bitcoin.it/wiki/BIP_0067"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip67_test_vectors.json")
    with open(filename, "r") as file_:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(file_)

    m = 2
    for i in test_vectors:
        keys, address = test_vectors[i]

        script_pub_key = p2ms(m, keys, lexi_sort=True)
        assert is_p2ms(script_pub_key)
        assert address_from_script_pub_key(script_pub_key) == ""
        script_type, payload = payload_from_script_pub_key(script_pub_key)
        assert script_type == "p2ms"
        assert payload == script_pub_key[:-1]
        assert script_pub_key == script_pub_key_from_payload("p2ms", payload)

        errmsg = f"Test vector #{i}"
        assert address == base58_address.p2sh(script_pub_key), errmsg


def test_non_standard_script_in_p2wsh() -> None:

    network = "mainnet"

    fed_pub_keys = [b"\x00" * 33, b"\x11" * 33, b"\x22" * 33]
    rec_pub_keys = [b"\x77" * 33, b"\x88" * 33, b"\x99" * 33]
    # fmt: off
    redeem_script = script.serialize(
        [
            "OP_IF",
                2, *fed_pub_keys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ELSE",
                500, "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",  # noqa E131
                2, *rec_pub_keys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ENDIF",
        ]
    )
    # fmt: on
    payload = sha256(redeem_script)
    script_pub_key = (
        "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708"
    )
    assert script_pub_key == p2wsh(redeem_script).hex()
    assert script_pub_key == script_pub_key_from_payload("p2wsh", payload).hex()

    address = "bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj"
    assert address == address_from_script_pub_key(script_pub_key, network)
    assert address == bech32_address_from_witness(0, payload, network)
