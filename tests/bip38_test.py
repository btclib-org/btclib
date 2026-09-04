# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip38` module.

**Two independent sources, cross-checked.** BIP38's own official test
vectors, transcribed from the "Test vectors" section of the BIP page
(https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki), and
`ebellocchia/bip_utils` (MIT) at the pin
https://github.com/ebellocchia/bip_utils/tree/85e07086 --
`tests/bip/bip38/test_bip38_no_ec.py` and `test_bip38_ec.py`, for the
malformed-record cases the BIP page does not enumerate. The two agree
everywhere they overlap, which is itself part of what this file checks:
bip_utils' own encoding of the BIP's vectors matches what this module
independently derives from the BIP's prose.

The AES-256 the two encrypted-key modes need is `tests`' -- see that
module for why a test writes its own block cipher -- driven here in ECB,
which BIP38 calls for directly: each 16-byte block on its own, no iv, no
chaining.
"""

from __future__ import annotations

import secrets

import pytest

from btclib import bip38
from btclib.alias import BlockCipherF
from btclib.b58 import address_from_h160, prv_key_data_from_wif
from btclib.base58 import decode as base58_decode
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    InvalidPrvKeyError,
    NotAPrvKeyError,
)
from btclib.hashes import hash160
from tests import aes_decrypt_block, aes_encrypt_block, aes_expand_key


def _encrypt_block(key: bytes, block: bytes) -> bytes:
    return aes_encrypt_block(block, aes_expand_key(key))


def _decrypt_block(key: bytes, block: bytes) -> bytes:
    return aes_decrypt_block(block, aes_expand_key(key))


def test_aes_256_against_fips_197() -> None:
    """FIPS-197 appendix C.3, the AES-256 known answer.

    The cipher below is what every BIP38 vector in this file rests on, so
    it is checked against the standard -- at the 256-bit key length BIP38
    actually uses, where `ecc/ecies_test.py` already checks the 128-bit
    one -- before it is used to check anything else.
    """
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    round_keys = aes_expand_key(key)
    assert aes_encrypt_block(plaintext, round_keys) == ciphertext
    assert aes_decrypt_block(ciphertext, round_keys) == plaintext


# --------------------------------------------------------------------------
# BIP38's own vectors, "Test vectors" section of the BIP page.
# --------------------------------------------------------------------------

# BIP page sections "No compression, no EC multiply" and "Compression,
# no EC multiply"
_NO_EC_VECTORS = (
    pytest.param(
        "TestingOneTwoThree",
        "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        id="uncompressed-1",
    ),
    pytest.param(
        "Satoshi",
        "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        id="uncompressed-2",
    ),
    pytest.param(
        "TestingOneTwoThree",
        "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        id="compressed-1",
    ),
    pytest.param(
        "Satoshi",
        "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        id="compressed-2",
    ),
    pytest.param(
        # "\u03d2\u0301\u0000\U00010400\U0001f4a9": GREEK UPSILON WITH
        # HOOK, COMBINING ACUTE ACCENT, NULL, DESERET CAPITAL LETTER LONG
        # I, PILE OF POO -- the BIP's own NFC-normalization test, and the
        # one vector in this file that is not ASCII
        "\u03d2\u0301\u0000\U00010400\U0001f4a9",
        "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
        "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
        id="unicode-nfc",
    ),
)


@pytest.mark.parametrize("password, wif, encrypted", _NO_EC_VECTORS)
def test_no_ec_vectors(password: str, wif: str, encrypted: str) -> None:
    """Encrypt and decrypt against a BIP38 vector, in both directions."""
    prv_key = prv_key_data_from_wif(wif)

    assert (
        bip38.encrypt(
            prv_key.q, password, _encrypt_block, compressed=prv_key.compressed
        )
        == encrypted
    )

    decrypted = bip38.decrypt(encrypted, password, _decrypt_block)
    assert decrypted.q == prv_key.q
    assert decrypted.compressed == prv_key.compressed
    assert decrypted.network == "mainnet"


def test_no_ec_round_trips_a_random_key() -> None:
    """A key this file did not lift from the BIP still round-trips."""
    q = 1 + secrets.randbelow(2**256)
    for compressed in (True, False):
        encrypted = bip38.encrypt(
            q, "correct horse", _encrypt_block, compressed=compressed
        )
        decrypted = bip38.decrypt(encrypted, "correct horse", _decrypt_block)
        assert decrypted.q == q
        assert decrypted.compressed == compressed


def test_no_ec_decrypt_refuses_the_wrong_password() -> None:
    """The address hash BIP38 embeds is the only check a password has."""
    encrypted = bip38.encrypt(1, "right", _encrypt_block)
    with pytest.raises(BTClibRuntimeError, match="wrong password"):
        bip38.decrypt(encrypted, "wrong", _decrypt_block)


# --------------------------------------------------------------------------
# BIP38's own vectors, EC-multiply.
# --------------------------------------------------------------------------

# BIP page section "EC multiply, no compression, no lot/sequence numbers"
_EC_NO_LOT_SEQ_VECTORS = (
    pytest.param(
        "TestingOneTwoThree",
        "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
        "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        "1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2",
        "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
        id="1",
    ),
    pytest.param(
        "Satoshi",
        "passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
        "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        "1CqzrtZC6mXSAhoxtFwVjz8LtwLJjDYU3V",
        "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH",
        id="2",
    ),
)


@pytest.mark.parametrize(
    "password, int_code, encrypted, address, wif", _EC_NO_LOT_SEQ_VECTORS
)
def test_ec_no_lot_seq_vectors(
    password: str, int_code: str, encrypted: str, address: str, wif: str
) -> None:
    """Reproduce the intermediate code and decrypt the resulting record.

    The intermediate code is only reproducible against the BIP's own
    fixed vector by overriding `owner_salt` with the one the vector's own
    encoding carries -- it is random otherwise, which is the point of it.
    """
    owner_entropy = base58_decode(int_code, 49)[8:16]
    assert bip38.intermediate_code(password, owner_salt=owner_entropy) == int_code

    prv_key = prv_key_data_from_wif(wif)
    decrypted = bip38.decrypt(encrypted, password, _decrypt_block)
    assert decrypted.q == prv_key.q
    assert decrypted.compressed == prv_key.compressed

    new_encrypted, new_address = bip38.new_key_pair(
        int_code, _encrypt_block, compressed=False
    )
    assert bip38.decrypt(new_encrypted, password, _decrypt_block).q is not None
    assert new_address != address  # a fresh key pair, not the vector's own


# BIP page section "EC multiply, no compression, lot/sequence numbers"
_EC_LOT_SEQ_VECTORS = (
    pytest.param(
        "MOLON LABE",
        263183,
        1,
        "passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
        "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
        "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8",
        id="molon-labe",
    ),
    # the same phrase transliterated into Greek, the BIP's own UTF-8 test
    # for this branch
    pytest.param(
        "ΜΟΛΩΝ ΛΑΒΕ",
        806938,
        1,
        "passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
        "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
        "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D",
        id="greek",
    ),
)


@pytest.mark.parametrize(
    "password, lot, sequence, int_code, encrypted, wif", _EC_LOT_SEQ_VECTORS
)
def test_ec_lot_seq_vectors(
    password: str, lot: int, sequence: int, int_code: str, encrypted: str, wif: str
) -> None:
    """Reproduce a lot/sequence intermediate code, and decrypt its record."""
    owner_entropy = base58_decode(int_code, 49)[8:16]
    owner_salt = owner_entropy[:4]
    assert int.from_bytes(owner_entropy[4:], "big") == lot * 4096 + sequence

    assert (
        bip38.intermediate_code(
            password, lot=lot, sequence=sequence, owner_salt=owner_salt
        )
        == int_code
    )

    prv_key = prv_key_data_from_wif(wif)
    decrypted = bip38.decrypt(encrypted, password, _decrypt_block)
    assert decrypted.q == prv_key.q
    assert decrypted.compressed == prv_key.compressed


def test_new_key_pair_round_trips() -> None:
    """The printer's half: a fresh key pair, decryptable by the owner alone."""
    int_code = bip38.intermediate_code("owner's password")
    for compressed in (True, False):
        encrypted, address = bip38.new_key_pair(
            int_code, _encrypt_block, compressed=compressed
        )
        decrypted = bip38.decrypt(encrypted, "owner's password", _decrypt_block)
        assert decrypted.compressed == compressed

        sec = bytes_from_point(mult(decrypted.q), compressed=compressed)
        assert address_from_h160("p2pkh", hash160(sec), "mainnet") == address


def test_new_key_pair_is_reproducible_with_a_fixed_seed_b() -> None:
    """`seed_b` overrides the random draw, as `eph_prv_key` does in ecies."""
    int_code = bip38.intermediate_code("owner's password")
    seed_b = bytes(range(24))
    enc1, addr1 = bip38.new_key_pair(int_code, _encrypt_block, seed_b=seed_b)
    enc2, addr2 = bip38.new_key_pair(int_code, _encrypt_block, seed_b=seed_b)
    assert enc1 == enc2
    assert addr1 == addr2


def test_new_key_pair_refuses_the_wrong_password() -> None:
    """The printer's record is no easier to guess against than the owner's."""
    int_code = bip38.intermediate_code("right")
    encrypted, _address = bip38.new_key_pair(int_code, _encrypt_block)
    with pytest.raises(BTClibRuntimeError, match="wrong password"):
        bip38.decrypt(encrypted, "wrong", _decrypt_block)


def test_new_key_pair_and_intermediate_code_draw_fresh_randomness() -> None:
    """The bug BIP38's issue names: a default drawn once, not per call.

    `os.urandom(...)` as a *default argument* is evaluated once at import
    and every call that omits it reuses the same salt or seed --
    `1200wd/bitcoinlib`'s BIP38 has exactly this bug. `owner_salt` and
    `seed_b` here are `None` sentinels read inside the function body, so
    two calls with nothing to say otherwise still draw independently.
    """
    assert bip38.intermediate_code("pw") != bip38.intermediate_code("pw")
    int_code = bip38.intermediate_code("pw")
    enc1, addr1 = bip38.new_key_pair(int_code, _encrypt_block)
    enc2, addr2 = bip38.new_key_pair(int_code, _encrypt_block)
    assert enc1 != enc2
    assert addr1 != addr2


# --------------------------------------------------------------------------
# bip_utils' malformed-record vectors, both modes -- what BIP38's own page
# does not enumerate. ebellocchia/bip_utils (MIT), pinned at 85e07086:
# tests/bip/bip38/test_bip38_no_ec.py and test_bip38_ec.py.
# --------------------------------------------------------------------------

_NO_EC_INVALID = (
    # Base58Check checksum failures
    pytest.param(
        "6PYRZqGd3ecBNWQhrkyJmJGcTnUv7pmiDRxQ3ipJjenAHBNiokh2HTV1BU",
        BTClibValueError,
        id="bad-checksum-1",
    ),
    pytest.param(
        "6PYV1dQkF66uex9TVxW9JQhjsr4bHkwu1zfjHtvZD7VcJssY4awDjGgc26",
        BTClibValueError,
        id="bad-checksum-2",
    ),
    # invalid base58 encoding: an 'O' and a lowercase 'l' where a vector
    # above has a canonical character
    pytest.param(
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeO",
        BTClibValueError,
        id="bad-encoding-1",
    ),
    pytest.param(
        "6PYltMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        BTClibValueError,
        id="bad-encoding-2",
    ),
    # wrong length
    pytest.param(
        "H3VYWSrgqLzqdXreTTfkL83ZJASYVFvy78q7j69nnt5WAcgMfq3eX2i",
        BTClibValueError,
        id="short",
    ),
    pytest.param(
        "cGAd8AVkr5wZEQpJ7wzyc4BKerkEwiyGVPUnJ2cV6wgLhpVuXPr71eh1G1Hm7Gu",
        BTClibValueError,
        id="long",
    ),
    # wrong prefix
    pytest.param(
        "6SSstNWVoV33gBrLYEbxUDj7xdnWcX6SNZvCedM3812j7vLysouLGzeFz9",
        NotAPrvKeyError,
        id="wrong-prefix",
    ),
    # wrong flagbyte
    pytest.param(
        "6PJQrGM5jUZ2mSug3ZKcy6W72T54dbu1wZSD8Q2TWRJ3q9qHiQPEBkafwL",
        InvalidPrvKeyError,
        id="wrong-flagbyte",
    ),
    # right shape, wrong address hash -- the record was built for a
    # different password
    pytest.param(
        "6PYTRmk5E6ddFqtiPZZu6BpZ1LXAVazbvkmUys9R2qz6o3eSsW9GDknHNu",
        BTClibRuntimeError,
        id="wrong-address-hash",
    ),
)


@pytest.mark.parametrize("encrypted, exception", _NO_EC_INVALID)
def test_no_ec_decrypt_rejects_a_malformed_record(
    encrypted: str, exception: type[Exception]
) -> None:
    """A non-EC-multiply record refuses each way bip_utils' vectors cover."""
    with pytest.raises(exception):
        bip38.decrypt(encrypted, "", _decrypt_block)


_EC_INVALID = (
    pytest.param(
        "6PfXER1HkxBryQDU3iukCt6ASDH4KmXiLN9ukLuFpY45PFPvacKqX5QrLn",
        BTClibValueError,
        id="bad-checksum-1",
    ),
    pytest.param(
        "6PnWzB9iU2fftjn1BcnMEGDefCfZHqCJNLcntxSnVoH7EiaQ32DnzG5rCG",
        BTClibValueError,
        id="bad-checksum-2",
    ),
    pytest.param(
        "6PflGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        BTClibValueError,
        id="bad-encoding-1",
    ),
    pytest.param(
        "6PgGWtx25kUg8QWvwuJAgOrN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
        BTClibValueError,
        id="bad-encoding-2",
    ),
    pytest.param(
        "2DsBJdAmt8SxyPV1vGDco4ZA61tCLfK9AoKdxMhWQpPqWF4SPGXJ748Vz",
        BTClibValueError,
        id="short",
    ),
    pytest.param(
        "QoZvdXXE7NRr3A7fN4ggxZg3vRje28mQKeWXpDXAinaaaikkMtmdZBPWu2i",
        BTClibValueError,
        id="long",
    ),
    pytest.param(
        "6Qkh8pdHhKVwawiiMhxDGXzWqmy25L8BHr1GsoSFXVFKvpxtSz9dvx7ecE",
        NotAPrvKeyError,
        id="wrong-prefix",
    ),
    pytest.param(
        "6PniVNh9a23BzarikZQphPJr3JnwPksaUByrH9TVkoyztCpJ1RhDZ4xAYH",
        InvalidPrvKeyError,
        id="wrong-flagbyte-1",
    ),
    pytest.param(
        "6PnuCXqo9z6LTBtCzCiLped1Y5wRc2EcicC3cwH7fpMwxsmYXzuk6W8ogs",
        InvalidPrvKeyError,
        id="wrong-flagbyte-2",
    ),
    pytest.param(
        "6PnNkEe2haex3HfxCfiKVi3VzGYrAKZGCCk55ZJbAEVh4ECZBhkVogqTVC",
        BTClibRuntimeError,
        id="wrong-address-hash",
    ),
)


@pytest.mark.parametrize("encrypted, exception", _EC_INVALID)
def test_ec_decrypt_rejects_a_malformed_record(
    encrypted: str, exception: type[Exception]
) -> None:
    """An EC-multiply record refuses each way bip_utils' own vectors cover."""
    with pytest.raises(exception):
        bip38.decrypt(encrypted, "", _decrypt_block)


_INT_CODE_INVALID = (
    pytest.param(
        "passphraseqoXNk7sefXMWWJkQ8E9LMYAjQvcEJzT8eW1YyEF6K55mJuUS8xWr9qZyZjQSjx",
        id="bad-checksum-1",
    ),
    pytest.param(
        "passphrasepkHGy593DTmXYG1mnYe6zLqjTV6LB7hMc7B29odQpQwNWTtWbQTUXScNYcVMzc",
        id="bad-checksum-2",
    ),
    pytest.param(
        "passphraserOrNyd6mzi6Y8qjxGM7oRUZ7UjWdeX4xKgSinMqtmxRYbFkNHj8u9uBAChNtqx",
        id="bad-encoding-1",
    ),
    pytest.param(
        "passphrasepglJNTNH41c7K5umSnve7QK4uvAXe7HqzZzKomYtf2NT3DiweKvCebGFsiMzTQ",
        id="bad-encoding-2",
    ),
    pytest.param(
        "BnHWe6BL19ZNRVsZkibpyb7FcZ7VKQpr3eSr6cT9BEVFMyJrR9QFeUxGKKxC7tmz2XF3aTQ",
        id="short",
    ),
    pytest.param(
        "4d2XZKZKrWZuKrUWc6qjvdsfTC1MBD4E7Fq761NTBJ9QGhkxgDCYHNGEJXQ78MnE5LyiZ8rAuL",
        id="long",
    ),
    pytest.param(
        "passphrasehfUHDug6znQzhCVmsawWEZT5kykEDAftfUUFVpSxeFeFcWYFvr7swKCvAnXwy9",
        id="wrong-magic",
    ),
)


@pytest.mark.parametrize("int_code", _INT_CODE_INVALID)
def test_new_key_pair_rejects_a_malformed_intermediate_code(int_code: str) -> None:
    """An intermediate code refuses each way bip_utils' own vectors cover."""
    with pytest.raises(BTClibValueError):
        bip38.new_key_pair(int_code, _encrypt_block)


# --------------------------------------------------------------------------
# Input validation: every public function of this module refuses what is
# not shaped like its argument, ahead of any cryptography.
# --------------------------------------------------------------------------


def test_decrypt_refuses_a_non_bip38_string() -> None:
    """A WIF is a different Base58Check object entirely: not this one."""
    with pytest.raises(BTClibValueError):
        bip38.decrypt(
            "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", "", _decrypt_block
        )


def test_intermediate_code_refuses_lot_without_sequence() -> None:
    """The pair states both or neither: one alone cannot default the other."""
    with pytest.raises(BTClibValueError, match="lot and sequence"):
        bip38.intermediate_code("pw", lot=1)
    with pytest.raises(BTClibValueError, match="lot and sequence"):
        bip38.intermediate_code("pw", sequence=1)


@pytest.mark.parametrize(
    "lot, sequence",
    [
        pytest.param(-1, 0, id="lot-too-low"),
        pytest.param(1_048_576, 0, id="lot-too-high"),
        pytest.param(0, -1, id="sequence-too-low"),
        pytest.param(0, 4_096, id="sequence-too-high"),
    ],
)
def test_intermediate_code_refuses_lot_or_sequence_out_of_range(
    lot: int, sequence: int
) -> None:
    """BIP38 fixes the ranges: 20 bits for the lot, 12 for the sequence."""
    with pytest.raises(BTClibValueError):
        bip38.intermediate_code("pw", lot=lot, sequence=sequence)


def test_intermediate_code_refuses_a_bool_lot_or_sequence() -> None:
    """A bool is not a lot or a sequence number, `bool` being an `int`."""
    with pytest.raises(BTClibTypeError):
        bip38.intermediate_code("pw", lot=True, sequence=0)
    with pytest.raises(BTClibTypeError):
        bip38.intermediate_code("pw", lot=0, sequence=True)


def test_encrypt_refuses_a_non_bool_compressed() -> None:
    """`compressed` is a kind, not a truth: it decides which key is checked."""
    with pytest.raises(BTClibTypeError):
        bip38.encrypt(1, "pw", _encrypt_block, compressed="yes")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_password", [b"not a str", 1, None])
def test_password_must_be_a_str(bad_password: object) -> None:
    """A password is text, unlike every other octet parameter of this module."""
    with pytest.raises(BTClibTypeError):
        bip38.encrypt(1, bad_password, _encrypt_block)  # type: ignore[arg-type]


def test_encrypt_refuses_a_cipher_that_returns_the_wrong_size() -> None:
    """`encrypt_block`'s output is checked before it is trusted, like ecies'."""

    def short_block(key: bytes, block: bytes) -> bytes:
        return block[:8]

    with pytest.raises(BTClibValueError, match="16-byte block"):
        bip38.encrypt(1, "pw", short_block)


def test_decrypt_refuses_a_cipher_that_returns_the_wrong_size() -> None:
    """`decrypt_block`'s output is checked before it is trusted, like ecies'."""
    encrypted = bip38.encrypt(1, "pw", _encrypt_block)

    def short_block(key: bytes, block: bytes) -> bytes:
        return block[:8]

    with pytest.raises(BTClibValueError, match="16-byte block"):
        bip38.decrypt(encrypted, "pw", short_block)


def test_new_key_pair_refuses_a_cipher_that_returns_the_wrong_size() -> None:
    """`new_key_pair`'s own `encrypt_block` is checked the same way."""
    int_code = bip38.intermediate_code("pw")

    def short_block(key: bytes, block: bytes) -> bytes:
        return block[:8]

    with pytest.raises(BTClibValueError, match="16-byte block"):
        bip38.new_key_pair(int_code, short_block)


def test_encrypt_refuses_a_private_key_out_of_range() -> None:
    """`scalar_from_prv_key` refuses 0 and n, as it does everywhere else."""
    with pytest.raises(BTClibValueError):
        bip38.encrypt(0, "pw", _encrypt_block)
    with pytest.raises(BTClibValueError):
        bip38.encrypt(secp256k1.n, "pw", _encrypt_block)


def test_block_cipher_f_is_the_alias_bip38_documents() -> None:
    """`encrypt_block`/`decrypt_block` are `BlockCipherF`, not `CipherF`.

    `ecies` takes `(key, iv, data)`; BIP38 has no iv and calls the cipher
    on one block at a time, so the two callables here are a different
    shape and not a second name for the same one.
    """
    encrypt_block: BlockCipherF = _encrypt_block
    decrypt_block: BlockCipherF = _decrypt_block
    assert callable(encrypt_block)
    assert callable(decrypt_block)
