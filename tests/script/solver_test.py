# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.solver` module.

The first two groups are Core's `script_standard_Solver_success` and
`script_standard_Solver_failure` (src/test/script_standard_tests.cpp at
bitcoin/bitcoin@9be056a8a7), case by case, with fixed keys where Core
generates them. The rest are the edges of the port.
"""

from __future__ import annotations

from typing import get_args

import pytest

from btclib.alias import TxoutType
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.script import push_int, serialize
from btclib.script.solver import get_txn_output_type, solver

# compressed G, 2G and 3G, and G uncompressed
KEY_1 = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
KEY_2 = bytes.fromhex(
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
KEY_3 = bytes.fromhex(
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)
KEY_1_UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
    "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
# valid size and prefix, and an x no curve point has: Core checks no more
OFF_CURVE = b"\x02" + b"\xff" * 32

ANCHOR_BYTES = bytes([0x4E, 0x73])
UINT256_ZERO = bytes(32)
UINT256_ONE = bytes([1]) + bytes(31)

PKH = hash160(KEY_1)
P2PKH = serialize(["OP_DUP", "OP_HASH160", PKH, "OP_EQUALVERIFY", "OP_CHECKSIG"])
REDEEM_SCRIPT_HASH = hash160(P2PKH)


def _check(script: bytes, type_: TxoutType, solutions: list[bytes]) -> None:
    assert solver(script) == (type_, solutions)


def test_core_success_pubkey() -> None:
    """TxoutType::PUBKEY."""
    _check(serialize([KEY_1, "OP_CHECKSIG"]), "pubkey", [KEY_1])


def test_core_success_pubkeyhash() -> None:
    """TxoutType::PUBKEYHASH."""
    _check(P2PKH, "pubkeyhash", [PKH])


def test_core_success_scripthash() -> None:
    """TxoutType::SCRIPTHASH."""
    script = serialize(["OP_HASH160", REDEEM_SCRIPT_HASH, "OP_EQUAL"])
    _check(script, "scripthash", [REDEEM_SCRIPT_HASH])


def test_core_success_multisig() -> None:
    """TxoutType::MULTISIG: 1-of-2 and 2-of-3."""
    script = serialize(["OP_1", KEY_1, KEY_2, "OP_2", "OP_CHECKMULTISIG"])
    _check(script, "multisig", [b"\x01", KEY_1, KEY_2, b"\x02"])
    script = serialize(["OP_2", KEY_1, KEY_2, KEY_3, "OP_3", "OP_CHECKMULTISIG"])
    _check(script, "multisig", [b"\x02", KEY_1, KEY_2, KEY_3, b"\x03"])


def test_core_success_nulldata() -> None:
    """TxoutType::NULL_DATA: three pushes of one byte each."""
    script = serialize(["OP_RETURN", b"\x00", b"\x4b", b"\xff"])
    _check(script, "nulldata", [])


def test_core_success_witness_v0_keyhash() -> None:
    """TxoutType::WITNESS_V0_KEYHASH."""
    _check(serialize(["OP_0", PKH]), "witness_v0_keyhash", [PKH])


def test_core_success_witness_v0_scripthash() -> None:
    """TxoutType::WITNESS_V0_SCRIPTHASH."""
    script_hash = sha256(P2PKH)
    _check(serialize(["OP_0", script_hash]), "witness_v0_scripthash", [script_hash])


def test_core_success_witness_v1_taproot() -> None:
    """TxoutType::WITNESS_V1_TAPROOT."""
    _check(serialize(["OP_1", UINT256_ZERO]), "witness_v1_taproot", [UINT256_ZERO])


def test_core_success_witness_unknown() -> None:
    """TxoutType::WITNESS_UNKNOWN: the version byte, then the program."""
    script = serialize(["OP_16", UINT256_ONE])
    _check(script, "witness_unknown", [b"\x10", UINT256_ONE])


def test_core_success_anchor() -> None:
    """TxoutType::ANCHOR, and no solutions."""
    _check(serialize(["OP_1", ANCHOR_BYTES]), "anchor", [])


def test_core_success_nonstandard() -> None:
    """TxoutType::NONSTANDARD."""
    _check(serialize(["OP_9", "OP_ADD", "OP_11", "OP_EQUAL"]), "nonstandard", [])


def test_core_failure_pubkey_with_wrong_size() -> None:
    """A 30-byte push is no pub key."""
    _check(serialize([b"\x01" * 30, "OP_CHECKSIG"]), "nonstandard", [])


def test_core_failure_pubkeyhash_with_wrong_size() -> None:
    """A pub key where the hash goes."""
    script = serialize(["OP_DUP", "OP_HASH160", KEY_1, "OP_EQUALVERIFY", "OP_CHECKSIG"])
    _check(script, "nonstandard", [])


def test_core_failure_scripthash_with_wrong_size() -> None:
    """A 21-byte hash."""
    script = serialize(["OP_HASH160", b"\x01" * 21, "OP_EQUAL"])
    _check(script, "nonstandard", [])


@pytest.mark.parametrize(
    "commands",
    [
        pytest.param(["OP_0", KEY_1, "OP_1", "OP_CHECKMULTISIG"], id="0-of-1"),
        pytest.param(["OP_2", KEY_1, "OP_1", "OP_CHECKMULTISIG"], id="2-of-1"),
        pytest.param(["OP_1", KEY_1, "OP_2", "OP_CHECKMULTISIG"], id="n=2, 1 key"),
        pytest.param(["OP_1", "OP_1", "OP_CHECKMULTISIG"], id="n=1, 0 keys"),
    ],
)
def test_core_failure_multisig(commands: list[str | bytes]) -> None:
    """The counts Core refuses."""
    _check(serialize(commands), "nonstandard", [])


def test_core_failure_nulldata_with_other_opcodes() -> None:
    """OP_ADD is no push."""
    _check(serialize(["OP_RETURN", b"\x4b", "OP_ADD"]), "nonstandard", [])


def test_core_failure_witness_v0_with_wrong_program_size() -> None:
    """A v0 program of 19 bytes is consensus-invalid, hence nonstandard."""
    _check(serialize(["OP_0", b"\x01" * 19]), "nonstandard", [])


@pytest.mark.parametrize("size", [31, 33])
def test_core_failure_taproot_with_wrong_program_size(size: int) -> None:
    """A v1 program that is not 32 bytes is undefined, and standard."""
    program = b"\x01" * size
    _check(serialize(["OP_1", program]), "witness_unknown", [b"\x01", program])


def test_core_failure_anchor_with_wrong_version() -> None:
    """OP_2 and the anchor bytes."""
    script = serialize(["OP_2", ANCHOR_BYTES])
    _check(script, "witness_unknown", [b"\x02", ANCHOR_BYTES])


def test_core_failure_anchor_with_wrong_data() -> None:
    """OP_1 and another two bytes."""
    program = b"\xff\xff"
    _check(serialize(["OP_1", program]), "witness_unknown", [b"\x01", program])


def test_anchor_is_tested_before_witness_unknown() -> None:
    """The anchor program is a v1 one of two bytes, and is not "unknown"."""
    assert solver(b"\x51\x02\x4e\x73")[0] == "anchor"
    assert solver(b"\x51\x02\x4e\x74")[0] == "witness_unknown"
    assert solver(b"\x51\x03\x4e\x73\x00")[0] == "witness_unknown"


@pytest.mark.parametrize("size", [21, 31, 33])
def test_a_v0_program_of_another_size_is_nonstandard(size: int) -> None:
    """Nothing but 20 and 32 bytes is a v0 type, and nothing is tried after."""
    _check(serialize(["OP_0", b"\x01" * size]), "nonstandard", [])


def test_the_witness_program_bounds() -> None:
    """Two to 40 bytes of program, pushed by its own length."""
    assert solver(serialize(["OP_2", b"\x01" * 2]))[0] == "witness_unknown"
    assert solver(serialize(["OP_2", b"\x01" * 40]))[0] == "witness_unknown"
    assert solver(serialize(["OP_2", b"\x01" * 41]))[0] == "nonstandard"
    assert solver(serialize(["OP_2", b"\x01"]))[0] == "nonstandard"
    # the length byte names more than the script holds
    assert solver(b"\x52\x05\x01\x01\x01")[0] == "nonstandard"
    # the first byte is OP_RESERVED, which is no version
    assert solver(b"\x50\x02\x01\x01")[0] == "nonstandard"


@pytest.mark.parametrize(
    "script",
    [
        pytest.param(b"\x6a", id="a bare OP_RETURN"),
        pytest.param(b"\x6a\x51", id="OP_RETURN OP_1"),
        pytest.param(b"\x6a\x00", id="OP_RETURN OP_0"),
        pytest.param(b"\x6a\x50", id="OP_RETURN OP_RESERVED, which is a push"),
        pytest.param(b"\x6a\x60", id="OP_RETURN OP_16"),
        pytest.param(b"\x6a\x01\x01\x01\x02", id="two pushes"),
        pytest.param(b"\x6a\x4c\x4b" + bytes(75) + b"\x01\x00", id="a push and a push"),
        pytest.param(b"\x6a\x4c\x51" + bytes(81), id="81 bytes, over the relay cap"),
        pytest.param(b"\x6a\x4d\x10\x27" + bytes(10_000), id="a push of 10000 bytes"),
        pytest.param(b"\x6a\x4e\x03\x00\x00\x00abc", id="OP_PUSHDATA4"),
        pytest.param(b"\x6a\x4f", id="OP_RETURN OP_1NEGATE"),
    ],
)
def test_nulldata_is_op_return_then_push_only(script: bytes) -> None:
    """Every shape type_and_payload does not take, with no size cap."""
    _check(script, "nulldata", [])


@pytest.mark.parametrize(
    "script",
    [
        pytest.param(b"\x6a\x61", id="OP_RETURN OP_NOP"),
        pytest.param(b"\x6a\x01\x01\x61", id="a push, then OP_NOP"),
        pytest.param(b"\x6a\x02\x01", id="a push cut short"),
        pytest.param(b"\x6a\x4c", id="OP_PUSHDATA1 with no length"),
        pytest.param(b"\x6a\x4d\x01", id="OP_PUSHDATA2 with half a length"),
        pytest.param(b"\x6a\x4e\x01\x00\x00\x00", id="OP_PUSHDATA4 with no data"),
        pytest.param(b"\x6b\x01\x01", id="not OP_RETURN"),
        pytest.param(b"\x01\x6a", id="OP_RETURN inside a push"),
    ],
)
def test_nulldata_refusals(script: bytes) -> None:
    """A non-push, a truncated push, and an OP_RETURN that does not lead."""
    _check(script, "nonstandard", [])


def test_the_empty_script_is_nonstandard() -> None:
    """No first byte to read."""
    _check(b"", "nonstandard", [])


def test_a_key_is_checked_for_its_size_and_never_parsed() -> None:
    """Core's ValidSize: an off-curve key of the right form is a key."""
    _check(serialize([OFF_CURVE, "OP_CHECKSIG"]), "pubkey", [OFF_CURVE])
    script = serialize(["OP_1", OFF_CURVE, KEY_1, "OP_2", "OP_CHECKMULTISIG"])
    _check(script, "multisig", [b"\x01", OFF_CURVE, KEY_1, b"\x02"])


@pytest.mark.parametrize("prefix", [0x02, 0x03])
def test_a_33_byte_key_takes_a_compressed_prefix(prefix: int) -> None:
    """Two and three."""
    key = bytes([prefix]) + KEY_1[1:]
    _check(serialize([key, "OP_CHECKSIG"]), "pubkey", [key])


@pytest.mark.parametrize("prefix", [0x04, 0x06, 0x07])
def test_a_65_byte_key_takes_an_uncompressed_or_hybrid_prefix(prefix: int) -> None:
    """Four, six and seven."""
    key = bytes([prefix]) + KEY_1_UNCOMPRESSED[1:]
    _check(serialize([key, "OP_CHECKSIG"]), "pubkey", [key])
    script = serialize(["OP_1", key, "OP_1", "OP_CHECKMULTISIG"])
    _check(script, "multisig", [b"\x01", key, b"\x01"])


@pytest.mark.parametrize(
    "key",
    [
        pytest.param(b"\x05" + KEY_1[1:], id="33 bytes, prefix 5"),
        pytest.param(b"\x00" + KEY_1[1:], id="33 bytes, prefix 0"),
        pytest.param(b"\x04" + KEY_1[1:], id="33 bytes, an uncompressed prefix"),
        pytest.param(b"\x02" + KEY_1_UNCOMPRESSED[1:], id="65 bytes, prefix 2"),
        pytest.param(b"\x05" + KEY_1_UNCOMPRESSED[1:], id="65 bytes, prefix 5"),
        pytest.param(KEY_1[:-1], id="32 bytes"),
    ],
)
def test_a_key_of_the_wrong_size_or_prefix_is_no_key(key: bytes) -> None:
    """Both the length and the first byte are read."""
    _check(serialize([key, "OP_CHECKSIG"]), "nonstandard", [])
    script = serialize(["OP_1", key, "OP_1", "OP_CHECKMULTISIG"])
    _check(script, "nonstandard", [])


def test_a_pubkey_is_the_push_of_33_or_65_and_the_checksig() -> None:
    """The script length and the length byte both have to agree."""
    # the 65-byte form, through its own length byte
    _check(
        serialize([KEY_1_UNCOMPRESSED, "OP_CHECKSIG"]),
        "pubkey",
        [KEY_1_UNCOMPRESSED],
    )
    # no OP_CHECKSIG
    _check(serialize([KEY_1, "OP_CHECKSIGVERIFY"]), "nonstandard", [])
    # an extra byte
    _check(serialize([KEY_1, "OP_CHECKSIG", "OP_NOP"]), "nonstandard", [])
    # a 33-byte key pushed by OP_PUSHDATA1
    _check(b"\x4c\x21" + KEY_1 + b"\xac", "nonstandard", [])


def test_a_pubkeyhash_is_its_exact_shape() -> None:
    """One wrong byte of the five is enough."""
    good = P2PKH
    for i in (0, 1, 2, 23, 24):
        bad = bytearray(good)
        bad[i] ^= 0x01
        assert solver(bytes(bad))[0] == "nonstandard"
    assert solver(good + b"\x00")[0] == "nonstandard"


def test_a_scripthash_is_its_exact_shape() -> None:
    """One wrong byte of the three is enough."""
    good = serialize(["OP_HASH160", REDEEM_SCRIPT_HASH, "OP_EQUAL"])
    for i in (0, 1, 22):
        bad = bytearray(good)
        bad[i] ^= 0x01
        assert solver(bytes(bad))[0] == "nonstandard"


def _multisig(m: int, keys: list[bytes], n: int) -> bytes:
    """Write m keys n OP_CHECKMULTISIG, each count as a number is pushed."""
    return serialize([push_int(m), *keys, push_int(n), "OP_CHECKMULTISIG"])


def test_a_16_of_16_multisig() -> None:
    """OP_16 twice."""
    keys = [KEY_1] * 16
    script = _multisig(16, keys, 16)
    assert script[0] == 0x60
    _check(script, "multisig", [b"\x10", *keys, b"\x10"])


@pytest.mark.parametrize("count", [17, 20])
def test_a_multisig_count_above_16_is_a_push(count: int) -> None:
    """One byte pushed, up to 20."""
    keys = [KEY_1] * count
    script = _multisig(count, keys, count)
    assert script[:2] == bytes([1, count])
    _check(script, "multisig", [bytes([count]), *keys, bytes([count])])
    _check(_multisig(1, keys, count), "multisig", [b"\x01", *keys, bytes([count])])


def test_a_multisig_of_more_than_20_keys_is_nonstandard() -> None:
    """21 is beyond MAX_PUBKEYS_PER_MULTISIG, for n and for m."""
    keys = [KEY_1] * 21
    _check(_multisig(1, keys, 21), "nonstandard", [])
    _check(_multisig(21, keys[:20], 20), "nonstandard", [])


def test_a_0_of_1_multisig_is_nonstandard() -> None:
    """M starts at 1, whichever way it is written."""
    _check(_multisig(0, [KEY_1], 1), "nonstandard", [])
    # a push of the byte 0 is the number zero, which CScriptNum refuses
    _check(b"\x01\x00" + bytes([0x21]) + KEY_1 + b"\x51\xae", "nonstandard", [])


def test_a_count_pushed_where_an_op_code_exists_is_refused() -> None:
    """Core's CheckMinimalPush: 2 is OP_2, not 0x01 0x02, nor OP_PUSHDATA1."""
    key_push = bytes([0x21]) + KEY_1
    _check(b"\x01\x01" + key_push + b"\x51\xae", "nonstandard", [])
    _check(b"\x4c\x01\x01" + key_push + b"\x51\xae", "nonstandard", [])
    _check(b"\x51" + key_push + b"\x01\x01\xae", "nonstandard", [])
    # a push of the right size and a number that is not minimal
    _check(b"\x02\x11\x00" + key_push + b"\x51\xae", "nonstandard", [])
    _check(b"\x02\x01\x80" + key_push + b"\x51\xae", "nonstandard", [])


def test_n_is_bounded_below_by_m() -> None:
    """1 <= m <= n."""
    _check(
        _multisig(2, [KEY_1, KEY_2], 2), "multisig", [b"\x02", KEY_1, KEY_2, b"\x02"]
    )
    _check(_multisig(3, [KEY_1, KEY_2], 2), "nonstandard", [])


def test_n_is_the_number_of_keys() -> None:
    """Fewer or more keys than n says."""
    _check(_multisig(1, [KEY_1, KEY_2], 3), "nonstandard", [])
    _check(_multisig(1, [KEY_1, KEY_2, KEY_3], 2), "nonstandard", [])


def test_a_multisig_is_refused_where_it_does_not_end_after_n() -> None:
    """Nothing between n and the final OP_CHECKMULTISIG, nothing after."""
    base = serialize(["OP_1", KEY_1, "OP_1"])
    _check(base + b"\xae", "multisig", [b"\x01", KEY_1, b"\x01"])
    _check(base + b"\x61\xae", "nonstandard", [])
    _check(base + b"\xae\x61", "nonstandard", [])
    _check(base + b"\xaf", "nonstandard", [])
    # n is followed by a key
    _check(base + bytes([0x21]) + KEY_2 + b"\xae", "nonstandard", [])


def test_a_multisig_with_a_push_that_is_no_key_is_refused() -> None:
    """The first such push is read as n."""
    _check(
        serialize(["OP_1", KEY_1, b"\x01" * 33, "OP_2", "OP_CHECKMULTISIG"]),
        "nonstandard",
        [],
    )
    _check(
        serialize(["OP_1", b"\x01" * 33, KEY_1, "OP_2", "OP_CHECKMULTISIG"]),
        "nonstandard",
        [],
    )


def test_a_multisig_that_cannot_be_read_is_refused() -> None:
    """A push cut short, where Core's GetOp answers false."""
    _check(b"\x51" + bytes([0x21]) + KEY_1 + b"\x4c\xae", "nonstandard", [])
    _check(b"\x4c\xae", "nonstandard", [])
    _check(b"\xae", "nonstandard", [])
    _check(b"\x51\xae", "nonstandard", [])
    # no n: the last op before OP_CHECKMULTISIG is a key
    _check(serialize(["OP_1", KEY_1, "OP_CHECKMULTISIG"]), "nonstandard", [])


def test_the_input_is_octets() -> None:
    """A hex-string is read, and something else refused."""
    assert solver(P2PKH.hex()) == ("pubkeyhash", [PKH])
    assert solver(bytearray(P2PKH)) == ("pubkeyhash", [PKH])
    with pytest.raises(BTClibTypeError):
        solver(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError):
        solver("not hex")


def test_get_txn_output_type() -> None:
    """Core's names, and a refusal of any other."""
    names = get_args(TxoutType)
    assert names == (
        "nonstandard",
        "anchor",
        "pubkey",
        "pubkeyhash",
        "scripthash",
        "multisig",
        "nulldata",
        "witness_v0_keyhash",
        "witness_v0_scripthash",
        "witness_v1_taproot",
        "witness_unknown",
    )
    for name in names:
        assert get_txn_output_type(name) == name
    with pytest.raises(BTClibValueError, match="invalid TxoutType"):
        get_txn_output_type("p2pkh")  # type: ignore[arg-type]


def test_every_type_is_reached() -> None:
    """The vocabulary has no member the classifier never answers."""
    answered = {
        solver(script)[0]
        for script in (
            b"",
            b"\x51\x02\x4e\x73",
            serialize([KEY_1, "OP_CHECKSIG"]),
            P2PKH,
            serialize(["OP_HASH160", REDEEM_SCRIPT_HASH, "OP_EQUAL"]),
            serialize(["OP_1", KEY_1, "OP_1", "OP_CHECKMULTISIG"]),
            b"\x6a",
            serialize(["OP_0", PKH]),
            serialize(["OP_0", sha256(P2PKH)]),
            serialize(["OP_1", UINT256_ZERO]),
            serialize(["OP_2", UINT256_ZERO]),
        )
    }
    assert answered == set(get_args(TxoutType))
