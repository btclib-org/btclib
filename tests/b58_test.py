# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.b58` module."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import b32, b58, slip132
from btclib.alias import ScriptList, ScriptType
from btclib.base58 import encode as b58encode
from btclib.bip32 import bip32
from btclib.curves import bytes_from_point, point_from_octets, secp256k1
from btclib.exceptions import (
    BTClibValueError,
    InvalidPrvKeyError,
    NotAPrvKeyError,
)
from btclib.hashes import hash160, sha256
from btclib.script.script import serialize
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_key

ec = secp256k1


def test_wif_from_prv_key() -> None:
    """Verify WIF encoding from a scalar, and the malformed scalars.

    A WIF is not among `wif_from_prv_key`'s own inputs any more: it is
    what the function writes, and what `prv_key_data_from_wif` below
    reads back, never what either takes as the other's spelling
    (issue #1188).
    """
    q_prv_key = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    q_int = int(q_prv_key, 16)

    test_vectors = [
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", "mainnet", True),
        ("cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx", "testnet", True),
        ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "mainnet", False),
        ("91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2", "testnet", False),
    ]
    for wif, network, compressed in test_vectors:
        assert wif == b58.wif_from_prv_key(q_prv_key, network, compressed)
        assert wif == b58.wif_from_prv_key(q_int, network, compressed)
        data = b58.prv_key_data_from_wif(wif)
        assert (data.q, data.network, data.compressed) == (q_int, network, compressed)

    bad_q = ec.n.to_bytes(ec.n_size, byteorder="big", signed=False)
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        b58.wif_from_prv_key(bad_q, "mainnet", True)

    # not a private key: 33 bytes, not the 32 a scalar's octets are
    bad_q = 33 * b"\x02"
    with pytest.raises(BTClibValueError, match="invalid size: 33 bytes"):
        b58.wif_from_prv_key(bad_q, "mainnet", True)


def test_prv_key_data_from_wif() -> None:
    """The malformed WIFs, and the two error classes they fall into."""
    bad_q = ec.n.to_bytes(ec.n_size, byteorder="big", signed=False)
    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    # a well-formed WIF -- base58, checksum, 0x80 prefix, right size --
    # carrying a scalar equal to n. The format is recognised, so the
    # fault in it is reported rather than swallowed as "not a WIF"
    with pytest.raises(InvalidPrvKeyError, match="private key not in 1..n-1"):
        b58.prv_key_data_from_wif(badwif)

    # not a WIF at all: 33 bytes wrapped as if it were a scalar's payload
    bad_q = 33 * b"\x02"
    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    # 34 bytes is the compressed-WIF size, so the trailing byte is what is
    # wrong with it, and 0x80 makes it a fault in a WIF rather than a
    # reason to try the string as something else
    err_msg = "not a compressed WIF: missing trailing 0x01"
    with pytest.raises(InvalidPrvKeyError, match=err_msg):
        b58.prv_key_data_from_wif(badwif)

    # Not a WIF: missing leading 0x80
    good_q = 32 * b"\x02"
    payload = b"\x81" + good_q
    badwif = b58encode(payload)
    with pytest.raises(NotAPrvKeyError, match="not a WIF") as exc_info:
        b58.prv_key_data_from_wif(badwif)
    assert "invalid prefix 0x81" in str(exc_info.value)

    # Not a compressed WIF: missing trailing 0x01
    payload = b"\x80" + good_q + b"\x00"
    badwif = b58encode(payload)
    with pytest.raises(InvalidPrvKeyError, match=err_msg):
        b58.prv_key_data_from_wif(badwif)

    # Not a WIF: wrong size (35)
    payload = b"\x80" + good_q + b"\x01\x00"
    badwif = b58encode(payload)
    with pytest.raises(InvalidPrvKeyError, match="wrong WIF size: 35"):
        b58.prv_key_data_from_wif(badwif)

    # leading/trailing spaces in a str are stripped; a WIF is also read
    # from bytes, base58's own alphabet excluding the space either way
    wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    for alt in (f" {wif}", f"{wif} ", wif.encode("ascii")):
        assert b58.prv_key_data_from_wif(alt) == b58.prv_key_data_from_wif(wif)

    # a mainnet WIF asked for as a testnet one: the prefix is recognised,
    # so the fault is reported as the wrong network rather than "not a
    # WIF"
    with pytest.raises(InvalidPrvKeyError, match="not a testnet wif: prefix 0x80"):
        b58.prv_key_data_from_wif(wif, "testnet")


def test_a_mistyped_wif_is_reported_as_one() -> None:
    """The headline case: one wrong character in a WIF.

    The checksum failure must not be swallowed, and never as "not a
    private key": a WIF is the one format `prv_key_data_from_wif` reads,
    so there is nothing else left to try it as.
    """
    good = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    assert b58.prv_key_data_from_wif(good).network == "mainnet"

    mistyped = f"{good[:-1]}8"
    with pytest.raises(NotAPrvKeyError, match="not a WIF") as exc_info:
        b58.prv_key_data_from_wif(mistyped)
    message = str(exc_info.value)
    assert "invalid checksum" in message
    # never the input itself, which is candidate key material
    assert mistyped not in message

    # the address functions answer otherwise, and that is the contract
    # rather than a gap: the checksum is verified before any prefix is
    # read, so nothing there knows a WIF was meant, and there are other
    # spellings left to try the text as
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        b58.p2pkh(mistyped)


def test_a_faulty_wif_keeps_its_diagnosis_through_an_address() -> None:
    """A WIF a network has claimed does not degrade to "not a key".

    `NotAPrvKeyError` says another spelling is worth trying and
    `_pub_keyinfo_from_key` tries it. `InvalidPrvKeyError` says the
    format was recognised, so there is nothing left to try and the
    diagnosis already computed is the answer.
    """
    uncompressed = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
    with pytest.raises(InvalidPrvKeyError, match="compression requirement mismatch"):
        b58.p2wpkh_p2sh(uncompressed)

    testnet_wif = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
    with pytest.raises(InvalidPrvKeyError, match="not a mainnet wif"):
        b58.p2pkh(testnet_wif, network="mainnet")


def test_address_from_h160() -> None:
    """Round-trip three published addresses, refusing a p2pk type."""
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    with pytest.raises(BTClibValueError, match="invalid script type: "):
        b58.address_from_h160("p2pk", b"\x00" * 20)


def test_p2pkh_from_wif() -> None:
    """Verify the p2pkh of a derived WIF, and refuse an xpub as a key.

    `wif_from_prv_key` takes the scalar an xprv resolves to, not the
    xprv itself: `to_prv_key` is what still resolves one, `b58` having
    no way to reach `bip32` for it (issue #1188).
    """
    seed = b"\x00" * 32  # better be a documented test case
    rxprv = bip32.rootxprv_from_seed(seed)
    path = "m/0h/0h/12"
    xprv = bip32.derive(rxprv, path)
    q, network, compressed = prv_keyinfo_from_prv_key(xprv)
    wif = b58.wif_from_prv_key(q, network, compressed)
    assert wif == "L2L1dqRmkmVtwStNf5wg8nnGaRn3buoQr721XShM4VwDbTcn9bpm"
    pub_key = b58.prv_key_data_from_wif(wif).pub.sec
    address = b58.p2pkh(pub_key)
    xpub = bip32.xpub_from_xprv(xprv)
    assert address == slip132.address_from_xpub(xpub)

    err_msg = "not a private key"
    with pytest.raises(BTClibValueError, match=err_msg):
        prv_keyinfo_from_prv_key(xpub)


def test_p2pkh_from_pub_key() -> None:
    """Reproduce the bitcoin wiki's p2pkh example, both compressions."""
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert address == b58.p2pkh(pub_key)
    assert address == b58.p2pkh(pub_key, compressed=True)
    _, h160, _ = b58.h160_from_address(address)
    assert h160 == hash160(pub_key)

    # trailing/leading spaces in address string
    assert address == b58.p2pkh(f" {pub_key}")
    assert h160 == hash160(f" {pub_key}")
    assert address == b58.p2pkh(f"{pub_key} ")
    assert h160 == hash160(f"{pub_key} ")

    uncompr_pub_key = bytes_from_point(point_from_octets(pub_key), compressed=False)
    uncompr_address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    assert uncompr_address == b58.p2pkh(uncompr_pub_key, compressed=False)
    assert uncompr_address == b58.p2pkh(uncompr_pub_key)
    _, uncompr_h160, _ = b58.h160_from_address(uncompr_address)
    assert uncompr_h160 == hash160(uncompr_pub_key)

    err_msg = "not a private or uncompressed public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert uncompr_address == b58.p2pkh(pub_key, compressed=False)

    err_msg = "not a private or compressed public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert address == b58.p2pkh(uncompr_pub_key, compressed=True)


def test_p2sh() -> None:
    """Reproduce a published p2sh address from its redeem script."""
    # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
    network = "mainnet"
    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    script_pub_key = serialize(
        [
            "OP_2DUP",
            "OP_EQUAL",
            "OP_NOT",
            "OP_VERIFY",
            "OP_SHA1",
            "OP_SWAP",
            "OP_SHA1",
            "OP_EQUAL",
        ]
    )

    assert script_pub_key.hex() == "6e879169a77ca787"
    assert address == b58.p2sh(script_pub_key, network)

    script_hash = hash160(script_pub_key)
    assert ("p2sh", script_hash, network) == b58.h160_from_address(address)
    assert ("p2sh", script_hash, network) == b58.h160_from_address(f" {address} ")

    assert script_hash.hex() == "4266fc6f2c2861d7fe229b279a79803afca7ba34"
    script_sig: ScriptList = ["OP_HASH160", script_hash.hex(), "OP_EQUAL"]
    serialize(script_sig)


def test_p2w_p2sh() -> None:
    """Verify p2wpkh-p2sh and p2wsh-p2sh addresses from one public key."""
    pub_key_str = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    pub_key, network = pub_keyinfo_from_key(pub_key_str, compressed=True)
    witness_program = hash160(pub_key)
    b58addr = b58.p2wpkh_p2sh(pub_key, network)
    assert b58addr == "36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g"

    script_pub_key = serialize(
        ["OP_DUP", "OP_HASH160", witness_program, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    b58addr = b58.p2wsh_p2sh(script_pub_key, network)
    assert b58addr == "3QHRam4Hvp1GZVkgjoKWUC1GEd8ck8e4WX"


def test_v0_witness_redeem_script() -> None:
    """The p2sh-wrapped redeem script is the one script.serialize builds.

    b58 spells [OP_0, witness program] out rather than calling serialize,
    which would import btclib.script and close the cycle of issue #147.
    This is what keeps the two spellings from drifting apart, and it covers
    both witness program sizes v0 admits: it is their being below the 76
    bytes at which a push grows an OP_PUSHDATA that makes the short form
    right.
    """
    pub_key = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    wit_prg = hash160(pub_key)
    assert len(wit_prg) == 20
    assert b58.p2wpkh_p2sh(pub_key) == b58.p2sh(serialize(["OP_0", wit_prg]))

    redeem_script = serialize(["OP_1", "OP_CHECKSIG"])
    wit_prg = sha256(redeem_script)
    assert len(wit_prg) == 32
    assert b58.p2wsh_p2sh(redeem_script) == b58.p2sh(serialize(["OP_0", wit_prg]))


def test_address_from_wif() -> None:
    """Verify addresses from WIFs, segwit refused when uncompressed."""
    q = 0x19E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

    test_cases = [
        (
            False,
            "mainnet",
            "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW",
            "1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig",
        ),
        (
            True,
            "mainnet",
            "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162",
            "1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB",
        ),
        (
            False,
            "testnet",
            "91nKEXyJCPYaK9maw7bTJ7ZcCu6dy2gybvNtUWF1LTCYggzhZgy",
            "mzuJRVe3ERecM6F6V4R6GN9B5fKiPC9HxF",
        ),
        (
            True,
            "testnet",
            "cNT1UjhUuGWN37hnmr754XxvPWwtAJTSq8bcCQ4pUrdxqxbA1iU1",
            "mwp9QoLuLK65XZUFKhPtvfujBjmgkZnmPx",
        ),
    ]
    for compressed, network, wif, address in test_cases:
        assert wif == b58.wif_from_prv_key(q, network, compressed)
        data = b58.prv_key_data_from_wif(wif)
        assert (data.q, data.network, data.compressed) == (q, network, compressed)
        assert address == b58.p2pkh(wif)
        script_type, payload, net = b58.h160_from_address(address)
        assert net == network
        assert script_type == "p2pkh"

        if compressed:
            # b58 reads the WIF itself; b32 sits below it and cannot, so
            # the pub key it derives is handed over instead (issue #1188)
            pub_key = data.pub.sec
            b32_address = b32.p2wpkh(pub_key, network)
            assert (0, payload, net) == b32.witness_from_address(b32_address)

            b58_address = b58.p2wpkh_p2sh(wif)
            script_bin = hash160(b"\x00\x14" + payload)
            assert ("p2sh", script_bin, net) == b58.h160_from_address(b58_address)

        else:
            # b32 cannot read a WIF, so an uncompressed one reaches it as
            # text no spelling resolves; b58 reads it, finds a WIF that a
            # p2wpkh cannot use, and says which of the two it is
            err_msg = "not a private or compressed public key"
            with pytest.raises(BTClibValueError, match=err_msg):
                b32.p2wpkh(wif)
            err_msg = "compression requirement mismatch"
            with pytest.raises(InvalidPrvKeyError, match=err_msg):
                b58.p2wpkh_p2sh(wif)


def test_exceptions() -> None:
    """Refuse an unknown address prefix and a key of the wrong size."""
    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    payload = b"\xf5" + hash160(pub_key)
    invalid_address = b58encode(payload)
    with pytest.raises(BTClibValueError, match="invalid base58 address prefix: "):
        b58.h160_from_address(invalid_address)

    with pytest.raises(BTClibValueError, match="not a private or public key"):
        b58.p2pkh(f"{pub_key}0A")


@given(
    script_type=st.sampled_from(["p2pkh", "p2sh"]),
    h160=st.binary(min_size=20, max_size=20),
    network=st.sampled_from(["mainnet", "testnet"]),
)
def test_round_trip_address(script_type: ScriptType, h160: bytes, network: str) -> None:
    """The payload and its script type survive the encoding.

    regtest is not among the networks: it shares testnet's version
    bytes, so a base58 address does not carry which of the two it is and
    h160_from_address answers testnet for both. The bech32 addresses of
    b32_test.py have no such ambiguity, their hrp being distinct, and
    are round-tripped over all three.
    """
    address = b58.address_from_h160(script_type, h160, network)
    assert b58.h160_from_address(address) == (script_type, h160, network)


@given(prv_key=st.integers(min_value=1, max_value=ec.n - 1), compressed=st.booleans())
def test_round_trip_wif(prv_key: int, compressed: bool) -> None:
    """A WIF decodes to the key it was made from, and to its compression."""
    wif = b58.wif_from_prv_key(prv_key, "mainnet", compressed)
    data = b58.prv_key_data_from_wif(wif)
    assert (data.q, data.network, data.compressed) == (prv_key, "mainnet", compressed)
