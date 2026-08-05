# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.script_pub_key` module."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from btclib import b32, b58, var_bytes
from btclib.alias import ScriptList
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.script import (
    Script,
    ScriptPubKey,
    address,
    assert_p2ms,
    assert_p2pk,
    assert_p2pkh,
    assert_p2sh,
    assert_p2tr,
    assert_p2wpkh,
    assert_p2wsh,
    is_nulldata,
    is_p2ms,
    is_p2pk,
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    output_pubkey,
    parse,
    serialize,
    type_and_payload,
)
from btclib.script import script as script_module
from btclib.script.script import ERROR_COMMAND
from btclib.script.script_pub_key import (
    assert_nulldata,
    assert_segwit,
    is_segwit,
)
from tests import load, vector_id


def test_eq() -> None:
    """Verify equality reads script and network, and the class too."""
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    script_pub_key = ScriptPubKey.p2pkh(pub_key)

    addr = b58.p2pkh(pub_key)
    assert ScriptPubKey.from_address(addr) == script_pub_key

    addr = b58.p2pkh(pub_key, "testnet")
    assert ScriptPubKey.from_address(addr) != script_pub_key

    assert Script(script_pub_key.script) != script_pub_key
    assert script_pub_key != Script(script_pub_key.script)


def test_unknown_network() -> None:
    """Refuse an unknown network name at construction."""
    with pytest.raises(BTClibValueError, match="unknown network: "):
        ScriptPubKey(b"", "no_network")


def test_nulldata() -> None:
    """Round-trip nulldata payloads, learnmeabitcoin's cases included."""
    OP_RETURN = b"\x6a"

    # self-consistency
    string = "time-stamped data"
    payload = string.encode()
    script_pub_key = serialize(["OP_RETURN", payload])
    assert script_pub_key == ScriptPubKey.nulldata(string).script

    # back from the script_pub_key to the payload
    assert ("nulldata", payload) == type_and_payload(script_pub_key)

    # data -> payload in this case is invertible (no hash functions)
    assert payload.decode("ascii") == string

    assert address(script_pub_key) == ""

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "hello world"
    payload = string.encode()
    assert payload.hex() == "68656c6c6f20776f726c64"
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == ScriptPubKey.nulldata(string).script
    assert ("nulldata", payload) == type_and_payload(script_pub_key)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "charley loves heidi"
    payload = string.encode()
    assert payload.hex() == "636861726c6579206c6f766573206865696469"
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == ScriptPubKey.nulldata(string).script
    assert ("nulldata", payload) == type_and_payload(script_pub_key)

    # documented test cases: https://learnmeabitcoin.com/guide/nulldata
    string = "家族も友達もみんなが笑顔の毎日がほしい"
    payload = string.encode()
    assert (
        payload.hex()
        == "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184"
    )
    script_pub_key = OP_RETURN + var_bytes.serialize(payload)
    assert script_pub_key == ScriptPubKey.nulldata(string).script
    assert ("nulldata", payload) == type_and_payload(script_pub_key)


def test_nulldata2() -> None:
    """Verify every payload length up to the 80-byte cap parses back."""
    for length in (0, 1, 16, 17, 74, 75, 76, 77, 78, 79, 80):
        payload = b"\x00" * length
        script_pub_key = serialize(["OP_RETURN", payload])
        assert ("nulldata", payload) == type_and_payload(script_pub_key)


def test_nulldata3() -> None:
    """Refuse an oversized payload and malformed length markers."""
    err_msg = "invalid nulldata payload length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        payload = "0A" * 81
        ScriptPubKey.nulldata(payload)

    # wrong data length: 32 in 35-bytes nulldata script;
    # it should have been 33
    script_pub_key = serialize(["OP_RETURN", b"\x00" * 33])
    script_pub_key = script_pub_key[:1] + b"\x20" + script_pub_key[2:]
    assert not is_nulldata(script_pub_key)

    # wrong data length: 32 in 83-bytes nulldata script;
    # it should have been 80
    script_pub_key = serialize(["OP_RETURN", b"\x00" * 80])
    script_pub_key = script_pub_key[:2] + b"\x20" + script_pub_key[3:]
    assert not is_nulldata(script_pub_key)

    # missing OP_PUSHDATA1 (0x4c) in 83-bytes nulldata script,
    # got 0x20 instead
    script_pub_key = serialize(["OP_RETURN", b"\x00" * 80])
    script_pub_key = script_pub_key[:1] + b"\x20" + script_pub_key[2:]
    assert not is_nulldata(script_pub_key)

    assert len(serialize(["OP_RETURN", b"\x00" * 75])) == 77
    assert len(serialize(["OP_RETURN", b"\x00" * 76])) == 79
    script_pub_key = serialize(["OP_RETURN", b"\x00" * 76])[:-1]
    assert not is_nulldata(script_pub_key)


def test_nulldata4() -> None:
    """OP_RETURN followed by opcodes is not a nulldata (issue #178).

    The serialization is `6a6a5351650053`, not `0x6A{1 byte data-length}
    {data 6 bytes}`: a script serializer writes each token as itself,
    and six opcodes are six opcodes and not six bytes of data. Wrapping
    them in a push would be a *different* script -- one whose OP_RETURN
    is followed by data that happens to spell them.

    And `type_and_payload` answers "unknown", not "nulldata". Bitcoin
    Core's Solver says so, and it is the rule everybody else applies:
    NULL_DATA is OP_RETURN followed by push-only bytes, and
    `CScript::IsPushOnly` refuses any opcode above OP_16 -- both the
    second OP_RETURN (0x6a) and OP_VERIF (0x65) are above it.
    """
    script_: ScriptList = [
        "OP_RETURN",
        "OP_RETURN",
        "OP_3",
        "OP_1",
        "OP_VERIF",
        "OP_0",
        "OP_3",
    ]
    script_pub_key = serialize(script_)
    assert len(script_pub_key) == 7
    assert script_pub_key.hex() == "6a6a5351650053"
    assert parse(script_pub_key) == script_
    script_type, _ = type_and_payload(script_pub_key)
    assert script_type == "unknown"

    # btclib is narrower than Core's classification, and deliberately so:
    # assert_nulldata takes OP_RETURN and *one* push, which is the shape a
    # wallet writes, while Solver would call this NULL_DATA -- two pushes
    # of one byte each, push-only throughout
    assert not is_nulldata(bytes.fromhex("6a0101010102"))


def test_nulldata_is_narrower_than_solver() -> None:
    """Every shape Core calls NULL_DATA and btclib does not (issue #211).

    The divergence is a decision -- `assert_nulldata`'s docstring says
    which question it answers -- so it is pinned here rather than left to
    be rediscovered by measurement. `Solver` classifies an OP_RETURN
    whose remaining bytes pass `IsPushOnly`, which refuses only an opcode
    above OP_16; the 83-byte cap btclib applies is `MAX_OP_RETURN_RELAY`,
    relay policy that classifier never consults.
    """
    for hex_string in (
        "6a",  # a bare OP_RETURN: push-only remainder, empty
        "6a51",  # OP_1, a push to IsPushOnly and an opcode here
        "6a0101010102",  # two pushes of one byte
        "6a4b" + "99" * 75 + "0100",  # a push and a push
        "6a4c50" + "99" * 80 + "00",  # 84 bytes, above MAX_OP_RETURN_RELAY
        "6a4c4b" + "99" * 75,  # 78 bytes, a non-minimal OP_PUSHDATA1
    ):
        script_pub_key = bytes.fromhex(hex_string)
        assert not is_nulldata(script_pub_key)
        assert type_and_payload(script_pub_key) == ("unknown", script_pub_key)

    # and the one that agrees by arithmetic rather than by rule: `00` is
    # read here as a zero-length push's marker, by Core as OP_0
    assert is_nulldata(bytes.fromhex("6a00"))
    assert type_and_payload(bytes.fromhex("6a00")) == ("nulldata", b"")


def test_p2pk() -> None:
    """Round-trip p2pk scripts and refuse malformed ones."""
    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    script_pub_key = serialize([pub_key, "OP_CHECKSIG"])
    assert_p2pk(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2pk(pub_key).script
    assert ("p2pk", bytes.fromhex(pub_key)) == type_and_payload(script_pub_key)

    assert address(script_pub_key) == ""

    err_msg = "invalid pub_key length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(b"\x31" + script_pub_key[1:])

    # documented test case: https://learnmeabitcoin.com/guide/p2pk
    pub_key = (
        "04"
        "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
        "e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
    )
    script_pub_key = bytes.fromhex(f"41{pub_key}ac")
    assert_p2pk(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2pk(pub_key).script

    err_msg = "missing final OP_CHECKSIG"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(script_pub_key[:-1] + b"\x00")

    err_msg = "invalid pub_key length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pk(b"\x31" + script_pub_key[1:])

    # invalid size: 34 bytes instead of (33, 65)
    pub_key = "03 ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414 14"
    err_msg = "not a private or public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        ScriptPubKey.p2pk(pub_key)


def test_p2pkh() -> None:
    """Round-trip p2pkh script and address; refuse malformed scripts."""
    # self-consistency
    pub_key = (
        "04 "
        "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    )
    payload = hash160(pub_key)
    script_pub_key = serialize(
        ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    assert_p2pkh(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2pkh(pub_key).script
    assert ("p2pkh", payload) == type_and_payload(script_pub_key)

    # base58 address
    network = "mainnet"
    addr = b58.p2pkh(pub_key, network)
    assert addr == address(script_pub_key, network)
    assert addr == b58.address_from_h160("p2pkh", payload, network)

    # back from the address to the script_pub_key
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    # documented test case: https://learnmeabitcoin.com/guide/p2pkh
    payload = bytes.fromhex("12ab8dc588ca9d5787dde7eb29569da63c3a238c")
    script_pub_key = bytes.fromhex("76a914") + payload + bytes.fromhex("88ac")
    assert_p2pkh(script_pub_key)
    addr = "12higDjoCCNXSA95xZMWUdPvXNmkAduhWv"
    assert addr == address(script_pub_key, network)
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    err_msg = "missing final OP_EQUALVERIFY, OP_CHECKSIG"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(script_pub_key[:-2] + b"\x40\x40")

    err_msg = "missing leading OP_DUP, OP_HASH160"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(b"\x40\x40" + script_pub_key[2:])

    err_msg = "invalid pub_key hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2pkh(script_pub_key[:2] + b"\x40" + script_pub_key[3:])


def test_p2wpkh() -> None:
    """Round-trip p2wpkh script and address; refuse bad markers."""
    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    payload = hash160(pub_key)
    script_pub_key = serialize(["OP_0", payload])
    assert_p2wpkh(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2wpkh(pub_key).script
    assert ("p2wpkh", payload) == type_and_payload(script_pub_key)

    # bech32 address
    network = "mainnet"
    addr = b32.p2wpkh(pub_key, network)
    assert addr == address(script_pub_key, network)
    assert addr == b32.address_from_witness(0, payload, network)

    # back from the address to the script_pub_key
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    # p2sh-wrapped base58 address
    addr = b58.p2wpkh_p2sh(pub_key, network)
    assert addr == "3BJxz2r8zY7LxJfdGjUpjjHNh6YEiitvf2"

    err_msg = "invalid witness version: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wpkh(b"\x33" + script_pub_key[1:])

    err_msg = "invalid pub_key hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wpkh(script_pub_key[:1] + b"\x00" + script_pub_key[2:])


def test_p2sh() -> None:
    """Round-trip p2sh script and address; refuse malformed scripts."""
    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    redeem_script = ScriptPubKey.p2pkh(pub_key).script
    payload = hash160(redeem_script)
    script_pub_key = serialize(["OP_HASH160", payload, "OP_EQUAL"])
    assert_p2sh(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2sh(redeem_script).script
    assert ("p2sh", payload) == type_and_payload(script_pub_key)

    # base58 address
    network = "mainnet"
    addr = b58.p2sh(redeem_script, network)
    assert addr == address(script_pub_key, network)
    assert addr == b58.address_from_h160("p2sh", payload, network)

    # back from the address to the script_pub_key
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    # documented test case: https://learnmeabitcoin.com/guide/p2sh
    payload = bytes.fromhex("748284390f9e263a4b766a75d0633c50426eb875")
    script_pub_key = bytes.fromhex("a914") + payload + bytes.fromhex("87")
    assert_p2sh(script_pub_key)
    addr = "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
    assert addr == address(script_pub_key, network)
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    err_msg = "missing final OP_EQUAL"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(script_pub_key[:-1] + b"\x40")

    err_msg = "missing leading OP_HASH160"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(b"\x40" + script_pub_key[1:])

    err_msg = "invalid redeem script hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2sh(script_pub_key[:1] + b"\x40" + script_pub_key[2:])


def test_p2wsh() -> None:
    """Round-trip p2wsh script and address; refuse bad markers."""
    # self-consistency
    pub_key = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    redeem_script = ScriptPubKey.p2pkh(pub_key).script
    payload = sha256(redeem_script)
    script_pub_key = serialize(["OP_0", payload])
    assert_p2wsh(script_pub_key)
    assert script_pub_key == ScriptPubKey.p2wsh(redeem_script).script
    assert ("p2wsh", payload) == type_and_payload(script_pub_key)

    # bech32 address
    network = "mainnet"
    addr = b32.p2wsh(redeem_script, network)
    assert addr == address(script_pub_key, network)
    assert addr == b32.address_from_witness(0, payload, network)

    # back from the address to the script_pub_key
    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert network == ScriptPubKey.from_address(addr).network

    # p2sh-wrapped base58 address
    addr = b58.p2wsh_p2sh(redeem_script, network)
    assert addr == "39GUePMSQ4mADpihVLd8cFQ2tih9Fy4qkz"

    err_msg = "invalid witness version: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wsh(b"\x33" + script_pub_key[1:])

    err_msg = "invalid redeem script hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2wsh(script_pub_key[:1] + b"\x00" + script_pub_key[2:])


def test_unknown() -> None:
    """A script of no type at all: no address, and the whole of it back.

    Not a witness program of an unnamed version, which is a type and
    has an address -- see the two tests below. This one is OP_16
    followed by 41 bytes, one past the longest program segwit defines,
    so it is not a witness program at all and no address can carry it.
    """
    script_pub_key = serialize(["OP_16", 41 * b"\x00"])
    assert address(script_pub_key) == ""
    assert type_and_payload(script_pub_key) == ("unknown", script_pub_key)


def test_a_witness_program_of_an_unnamed_version_has_an_address() -> None:
    """Versions 2 to 16 round trip, as versions 0 and 1 do (issue #251).

    Each address here is one btclib itself writes and reads; answering
    "" for the script it decodes to broke the round trip in the middle,
    and did so with a value indistinguishable from "this script has no
    address" -- the right answer for a nulldata output and the wrong
    one where the address exists and btclib can spell it. Bitcoin Core
    renders them, `EncodeDestination` having a `WitnessUnknown` case,
    and `witness_unknown` is Core's own name for the type.
    """
    program = bytes(range(2, 22))
    for version in range(2, 17):
        addr = b32.address_from_witness(version, program)
        script_pub_key = ScriptPubKey.from_address(addr)
        assert script_pub_key.type == "witness_unknown"
        assert script_pub_key.address == addr
        assert type_and_payload(script_pub_key.script) == (
            "witness_unknown",
            program,
        )

    # the version is the op code the program follows, and it is not
    # implied by the type: the two extremes are told apart
    assert address(serialize(["OP_2", program])) != address(
        serialize(["OP_16", program])
    )


def test_where_witness_unknown_begins_and_ends() -> None:
    """Verify btclib draws Core's line, `Solver`'s (issue #251).

    Any version but 0 that is not p2tr is `witness_unknown`, a v1
    program that is not 32 bytes included. A version *0* program of an
    unexpected length is not: `Solver` calls it NONSTANDARD, and there
    is no upgrade room left in v0 for a spend to be defined for it, so
    it has no address to render.
    """
    v1_not_32 = serialize(["OP_1", bytes(20)])
    assert type_and_payload(v1_not_32) == ("witness_unknown", bytes(20))
    assert address(v1_not_32) == b32.address_from_witness(1, bytes(20))

    # the shortest and the longest program a witness address can carry
    for length in (2, 40):
        script_pub_key = serialize(["OP_2", bytes(length)])
        assert type_and_payload(script_pub_key)[0] == "witness_unknown"
        assert address(script_pub_key) == b32.address_from_witness(2, bytes(length))

    v0_not_20_or_32 = serialize(["OP_0", bytes(21)])
    assert type_and_payload(v0_not_20_or_32) == ("unknown", v0_not_20_or_32)
    assert address(v0_not_20_or_32) == ""


def test_p2ms_1() -> None:
    """Verify p2ms classification; refuse invalid m, n and keys."""
    # self-consistency
    # documented test case: https://learnmeabitcoin.com/guide/p2ms
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    script_pub_key = bytes.fromhex(
        "51"  # OP_1
        "41"  # canonical 65-bytes push
        f"{pub_key0}"
        "41"  # canonical 65-bytes push
        f"{pub_key1}"
        "52"  # OP_2
        "ae"  # OP_CHECKMULTISIG
    )
    assert is_p2ms(script_pub_key)
    assert address(script_pub_key) == ""
    script_type, payload = type_and_payload(script_pub_key)
    assert script_type == "p2ms"
    assert payload == script_pub_key[:-1]
    pub_keys = [pub_key0, pub_key1]
    assert (
        script_pub_key
        == ScriptPubKey.p2ms(1, pub_keys, lexicographic_sorting=False).script
    )

    err_msg = "invalid m in m-of-n: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ScriptPubKey.p2ms(4, pub_keys)
    err_msg = "invalid n in m-of-n: "
    with pytest.raises(BTClibValueError, match=err_msg):
        # pylance cannot grok the following line
        ScriptPubKey.p2ms(4, [pub_key0] * 17)
    err_msg = "invalid m in m-of-n: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ScriptPubKey.p2ms(0, pub_keys)
    err_msg = "invalid m in m-of-n: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ScriptPubKey.p2ms(17, pub_keys)

    err_msg = "not a private or public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        ScriptPubKey.p2ms(1, [f"{pub_key0}00", pub_key1])

    script_: ScriptList = [
        "OP_1",
        f"{pub_key0}00",
        pub_key1,
        "OP_2",
        "OP_CHECKMULTISIG",
    ]

    script_pub_key = serialize(script_)
    assert not is_p2ms(script_pub_key)

    err_msg = "invalid key in p2ms"
    script_pub_key = serialize(["OP_1", pub_key0, "0A", "OP_2", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_1", pub_key0, pub_key1, "OP_2", "OP_CHECKMULTISIG"])
    assert is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_2", pub_key0, pub_key1, "OP_2", "OP_CHECKMULTISIG"])
    assert is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_0", pub_key0, pub_key1, "OP_2", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_3", pub_key0, pub_key1, "OP_2", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_1", "OP_2", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_1", pub_key0, "OP_2", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    script_pub_key = serialize(["OP_1", pub_key0, pub_key1, "OP_3", "OP_CHECKMULTISIG"])
    assert not is_p2ms(script_pub_key)

    pub_key2 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    script_pub_key = serialize(
        ["OP_1", pub_key0, pub_key1, pub_key2, "OP_3", "OP_CHECKMULTISIG"]
    )
    assert_p2ms(script_pub_key)

    err_msg = "invalid p2ms script_pub_key size"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2ms(script_pub_key[:133] + b"\x40" + script_pub_key[134:])
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2ms(script_pub_key[:-2] + b"\x00" + script_pub_key[-2:])


def test_p2ms_2() -> None:
    """Verify p2ms with uncompressed and mixed keys, sorted or not."""
    m = 1

    # all uncompressed
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
    pub_key2 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    uncompressed_pub_keys = [pub_key0, pub_key1, pub_key2]
    # mixed compressed / uncompressed public keys
    pub_key0 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pub_key1 = "03 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
    pub_key2 = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    mixed_pub_keys = [pub_key0, pub_key1, pub_key2]

    for pub_keys in (uncompressed_pub_keys, mixed_pub_keys):
        for lexicographic_sorting in (True, False):
            script_pub_key = ScriptPubKey.p2ms(
                m, pub_keys, lexicographic_sorting=lexicographic_sorting
            ).script
            assert is_p2ms(script_pub_key)
            assert address(script_pub_key) == ""
            script_type, payload = type_and_payload(script_pub_key)
            assert script_type == "p2ms"
            assert payload == script_pub_key[:-1]


def test_p2ms_3() -> None:
    """Reproduce a mainnet p2ms output and its per-key addresses."""
    # tx_id 33ac2af1a6f894276713b59ed09ce1a20fed5b36d169f20a3fe831dc45564d57
    # output n 0
    keys: ScriptList = [
        "036D568125A969DC78B963B494FA7ED5F20EE9C2F2FC2C57F86C5DF63089F2ED3A",
        "03FE4E6231D614D159741DF8371FA3B31AB93B3D28A7495CDAA0CD63A2097015C7",
    ]
    cmds: ScriptList = ["OP_1", *keys, "OP_2", "OP_CHECKMULTISIG"]
    script_pub_key = ScriptPubKey(serialize(cmds))
    assert script_pub_key == ScriptPubKey.p2ms(1, keys)

    pub_keys = script_pub_key.addresses
    exp_pub_keys = [
        "1Ng4YU2e2H3E86syX2qrsmD9opBHZ42vCF",
        "14XufxyGiY6ZBJsFYHJm6awdzpJdtsP1i3",
    ]
    for pub_key, key, exp_pub_key in zip(pub_keys, keys, exp_pub_keys, strict=True):
        assert pub_key == b58.p2pkh(key)
        assert pub_key == exp_pub_key

    # tx 56214420a7c4dcc4832944298d169a75e93acf9721f00656b2ee0e4d194f9970
    # input n 1
    cmds_sig: ScriptList = [
        "OP_0",
        "3045022100dba1e9b1c8477fd364edcc1f81845928202daf465a1e2d92904c13c88761cbd002200add6af863dfdb7efb95f334baec041e90811ae9d81624f9f87f33a56761f29401",
    ]
    script_sig = Script(serialize(cmds_sig))
    script = script_sig + script_pub_key
    # parse(serialize(*)) is to enforce same string case convention
    assert script.asm == parse(serialize(cmds_sig + cmds))


BIP67_VECTORS = load("script", "_data", "bip67_test_vectors.json")


@pytest.mark.parametrize(
    "keys, addr",
    [
        pytest.param(keys, addr, id=vector_id(int(i), addr))
        for i, (keys, addr) in BIP67_VECTORS.items()
    ],
)
def test_bip67(keys: list[str], addr: str) -> None:
    """BIP67 test vectors, from bip-0067.mediawiki in bitcoin/bips.

    Not en.bitcoin.it/wiki/BIP_0067: a wiki page is neither versioned
    nor authoritative. tests/_data/README.md pins the BIP revision the
    vectors were transcribed from.
    """
    m = 2
    script_pub_key = ScriptPubKey.p2ms(m, keys, lexicographic_sorting=True).script
    assert is_p2ms(script_pub_key)
    assert address(script_pub_key) == ""
    script_type, payload = type_and_payload(script_pub_key)
    assert script_type == "p2ms"
    assert payload == script_pub_key[:-1]
    assert addr == b58.p2sh(script_pub_key)


def test_non_standard_script_in_p2wsh() -> None:
    """Round-trip a non-standard redeem script through its address."""
    network = "mainnet"

    addr = "bc1qqst9un5sz8576fy2nnqkpm4rpfh0weveqwtt8zxgjp02g2mx5q7s2vresu"
    script_pub_key = ScriptPubKey.from_address(addr)
    assert addr == address(script_pub_key.script, network)

    fed_pub_keys: ScriptList = [
        "03356aeda9c56586fe1e4a63d5118ffa3bf29bd91c6323e31de113a500a1ffe441".upper(),
        "0339f970e066a3efe1787722bd9cd59f69f1cf5cd29cb39fdec845415d8dbcb7a6".upper(),
        "0346f1233885981cc50b4064b6ed27174a149ac0842a25941f280302ddd7d2153d".upper(),
        "035d237b0807dd736cf4f3ab9c093bae2ccd128596dca883d3470f6327e6551688".upper(),
        "037b5acce33944ae02454c65011ffb04e604f36f685c474134e8874ddac45ff7c8".upper(),
        "03a88488e5ab6ae35c7d22d76efb9578e4a71b59c2ff0bd3cc3277e3a60717f3d6".upper(),
    ]

    rec_pub_keys: ScriptList = [
        "02219c3f199942fdd37a88065a8a8333189aadb5667a7c27681f66952fddf0eea4".upper(),
        "034c52cdf0125e50a53556c3f7586245f3f556bf26a80a4dae0ea6d0c81c11ebef".upper(),
        "03e8abfc4e3dcd5be461e79c9fa68a4d657b344391d7fd65ed40aaa56f584c7711".upper(),
    ]

    # fmt: off
    redeem_script_cmds: ScriptList = [
        "OP_IF",
            "OP_3", *fed_pub_keys, "OP_6", "OP_CHECKMULTISIG",
        "OP_ELSE",
            5184, "OP_CHECKSEQUENCEVERIFY", "OP_DROP",  # E131
            "OP_2", *rec_pub_keys, "OP_3", "OP_CHECKMULTISIG",  # E131
        "OP_ENDIF",
    ]
    # fmt: on
    redeem_script = serialize(redeem_script_cmds)
    assert redeem_script == serialize(parse(redeem_script))

    assert addr == b32.address_from_witness(0, sha256(redeem_script), network)
    assert script_pub_key == ScriptPubKey.p2wsh(redeem_script)


def test_p2tr() -> None:
    """Round-trip p2tr script and address; refuse a bad length marker."""
    pub_key = "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    out_pubkey = output_pubkey(pub_key)[0]
    script_pub_key = serialize(["OP_1", out_pubkey])
    assert_p2tr(script_pub_key)
    assert ("p2tr", out_pubkey) == type_and_payload(script_pub_key)

    network = "mainnet"
    addr = b32.p2tr(out_pubkey, network=network)
    assert addr == address(script_pub_key, network)

    assert script_pub_key == ScriptPubKey.from_address(addr).script
    assert script_pub_key == ScriptPubKey.p2tr(pub_key).script

    err_msg = "invalid redeem script hash length marker: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_p2tr(script_pub_key[:1] + b"\x00" + script_pub_key[2:])


def test_script_pub_key_is_a_dataclass() -> None:
    """Verify network is a field, one dataclasses sees.

    Guards against ScriptPubKey extending the Script dataclass without
    being one: with network a bare annotation, dataclasses.fields would
    report only script, and dataclasses.replace would rebuild the
    instance through ScriptPubKey(script=...) alone — returning a
    *mainnet* ScriptPubKey from a testnet one, silently.
    """
    pub_key = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    testnet = ScriptPubKey.p2pkh(pub_key, network="testnet")
    assert testnet.network == "testnet"

    assert [f.name for f in dataclasses.fields(testnet)] == ["script", "network"]

    same = dataclasses.replace(testnet)
    assert same.network == "testnet"
    assert same == testnet
    assert same.address == testnet.address

    # and the network can be replaced
    mainnet = dataclasses.replace(testnet, network="mainnet")
    assert mainnet.network == "mainnet"
    assert mainnet.script == testnet.script
    assert mainnet != testnet
    assert mainnet.address != testnet.address

    # the generated repr names both fields; Script's would show a
    # testnet and a mainnet ScriptPubKey identically
    assert "network='testnet'" in repr(testnet)


def test_script_pub_key_construction_parses_nothing() -> None:
    """Validation does not parse, and .asm parses once.

    assert_valid asks whether the script is bytes and, here, whether the
    network is known: whether the bytes can be executed is the
    interpreter's question (issue #123), so no parse happens at
    construction whatever check_validity says. The one that does is
    `.asm`, cached.
    """
    calls = []
    real_parse = script_module.parse

    def counting_parse(*args: Any, **kwargs: Any) -> ScriptList:
        calls.append(1)
        return real_parse(*args, **kwargs)

    script = bytes.fromhex("76a91438971f73930f6c141d977ac4fd4a727c854935b388ac")
    script_module.parse = counting_parse
    try:
        for check_validity in (True, False):
            calls.clear()
            script_pub_key = ScriptPubKey(
                script, "testnet", check_validity=check_validity
            )
            assert not calls
            # and the parse .asm does is not repeated on a second read
            assert script_pub_key.asm[0] == "OP_DUP"
            assert script_pub_key.asm[0] == "OP_DUP"
            assert len(calls) == 1
    finally:
        script_module.parse = real_parse

    # what is left of the check, and the network half of it
    with pytest.raises(BTClibValueError, match="unknown network: mainet"):
        ScriptPubKey(script, "mainet")


def test_script_assert_valid_asks_only_whether_it_is_bytes() -> None:
    """A script is its bytes, and nothing about them makes it not a script.

    Core has no validity notion for a CScript either. A round-trip check
    would be wrong rather than merely redundant -- a non-minimal push is
    consensus-legal and comes back minimal -- and a parse was wrong too:
    it refused pushes that are in blocks (issue #123).
    """
    # OP_PUSHDATA1 of a single byte: legal, and re-serializing it yields
    # the minimal 01ff instead
    non_minimal = bytes.fromhex("4c01ff")
    script = Script(non_minimal)
    assert script.script == non_minimal
    assert script.asm == ["FF"]
    assert serialize(script.asm) == bytes.fromhex("01ff")
    script.assert_valid()

    # a truncated push is a Script, and its asm says where it stopped
    for bad in (bytes.fromhex("0201"), bytes.fromhex("4c05aabb")):
        assert Script(bad).asm == [ERROR_COMMAND]

    # an op code with no name of its own parses as UNKNOWN_OP_CODE_n and
    # serializes back to the same byte
    unknown = bytes([0xBB])
    assert Script(unknown).asm == ["UNKNOWN_OP_CODE_187"]
    assert serialize(Script(unknown).asm) == unknown


def test_is_p2_functions_answer_about_bytes_not_about_types() -> None:
    """A wrong type is a caller error, not "not a p2sh script".

    _is_funct caught Exception, so every one of the thirteen is_p2* answered
    False for a TypeError as readily as for bytes that really were not the
    script asked about.
    """
    is_functions = [
        is_nulldata,
        is_p2ms,
        is_p2pk,
        is_p2pkh,
        is_p2sh,
        is_p2tr,
        is_p2wpkh,
        is_p2wsh,
    ]

    # bytes that are not the script asked about: still False
    for func in is_functions:
        assert func(b"\x00" * 3) is False

    # and a caller passing the wrong thing hears about it
    for func in is_functions:
        with pytest.raises(TypeError):
            func(None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            func(42)  # type: ignore[arg-type]

    # a bad hex-string is a ValueError, so it stays False: the question is
    # about bytes, and those are not bytes anyone could have meant
    for func in is_functions:
        assert func("not hex at all") is False


def test_the_two_index_errors_the_broad_catch_was_hiding() -> None:
    """assert_nulldata and assert_segwit indexed past the end.

    Both were reachable, both left the library as IndexError -- outside its
    exception contract -- and _is_funct turned both into a plain False by
    catching Exception. Narrowing the catch to ValueError needed them fixed
    first, or is_nulldata(b"\\x6a") would have started raising.
    """
    # a lone OP_RETURN: no data length marker to read
    with pytest.raises(BTClibValueError, match="missing data length marker"):
        assert_nulldata(b"\x6a")
    assert is_nulldata(b"\x6a") is False

    # an empty script: no witness version byte to read
    with pytest.raises(BTClibValueError, match="null length"):
        assert_segwit(b"")
    assert is_segwit(b"") is False


def test_script_is_frozen_and_asm_is_cached() -> None:
    """The two halves of issue 165 that outlived its first fix.

    Script was the one dataclass left unfrozen after issue 139, which is
    what let `tx_out.script_pub_key.script = b""` reach through a frozen
    TxOut; and `asm` re-parsed on every read. Freezing is what makes the
    cache correct, so they are one change.
    """
    script = Script("0014751e76e8199196d454941c45d1b3a323f1433bd6")

    with pytest.raises(dataclasses.FrozenInstanceError):
        script.script = b""  # type: ignore[misc]

    spk = ScriptPubKey.p2pkh(
        "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",
        network="testnet",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        spk.script = b""  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spk.network = "mainnet"  # type: ignore[misc]

    # frozen and eq, so Script gets a generated __hash__ and can be a dict
    # key or a set member. ScriptPubKey cannot: it defines __eq__, which
    # leaves __hash__ None
    assert len({Script(script.script), Script(script.script)}) == 1
    with pytest.raises(TypeError, match="unhashable type"):
        hash(spk)

    # and dataclasses.replace still works through the written-out __init__
    assert dataclasses.replace(spk).network == "testnet"


def test_asm_parses_once_per_script() -> None:
    """Verify three .asm reads cost one parse, cached in __dict__."""
    calls = []
    real_parse = script_module.parse

    def counting_parse(*args: Any, **kwargs: Any) -> ScriptList:
        calls.append(1)
        return real_parse(*args, **kwargs)

    script = Script("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    original = script_module.parse
    script_module.parse = counting_parse
    try:
        first = script.asm
        second = script.asm
        third = script.asm
    finally:
        script_module.parse = original

    assert first == second == third
    # one parse for three reads, not one per read
    assert len(calls) == 1

    # the cache lives in the instance __dict__, which is how a frozen
    # dataclass can hold one at all: cached_property writes there directly
    # rather than through __setattr__
    assert script.__dict__["asm"] == first


def test_equality_is_by_network_type() -> None:
    """A signet ScriptPubKey equals the address it renders.

    from_address answers "testnet" for a `tb1` address, three chains
    sharing that hrp, so comparing network *names* would make a signet
    ScriptPubKey unequal to its own address -- identical script bytes and
    all. Comparing the network type keeps the distinction that matters,
    mainnet against the test chains, and drops the one an address cannot
    carry: issue #207.
    """
    addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    decoded = ScriptPubKey.from_address(addr)
    assert decoded.network == "testnet"

    for network in ("testnet", "regtest", "signet", "testnet4"):
        declared = ScriptPubKey(decoded.script, network)
        assert declared == decoded
        assert decoded == declared  # both directions, as equality goes

    # mainnet is not among them: the funds-relevant comparison stands
    mainnet = ScriptPubKey(decoded.script, "mainnet")
    assert mainnet != decoded
    assert decoded != mainnet

    # a different script is still a different script, same network type
    other = ScriptPubKey.from_address(
        b32.p2wsh(b"\x51", "testnet")  # any other witness program
    )
    assert other != decoded
    assert ScriptPubKey(other.script, "signet") != decoded

    # and a non-ScriptPubKey is still NotImplemented, i.e. not equal
    assert decoded != decoded.script
