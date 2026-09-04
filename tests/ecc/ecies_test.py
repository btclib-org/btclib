# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.ecies` module.

**This file drives an AES-128, and it is here because tests are not
shipped.** `tests/__init__.py` has why a test writes its own block cipher
rather than taking a dependency, AES-256 for `bip38_test.py` beside this
module's AES-128: the keys below are fixed test vectors published in
Electrum's own test suite, so there is no secret for a timing side
channel to leak. What this cipher buys is the only evidence that matters
for a scheme with no specification: btclib decrypting ciphertexts that
Electrum really produced.

The CBC chaining and the PKCS#7 padding are this module's own: BIE1
names both, where BIP38 names neither, so they stay beside the vectors
that need them rather than in the shared block cipher.
"""

import base64
import hashlib
import string
from typing import Any

import pytest

from btclib.alias import Point
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.ecc import ecies
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)
from tests import aes_decrypt_block, aes_encrypt_block, aes_expand_key, aes_xor

# --------------------------------------------------------------------------
# AES-128-CBC with PKCS#7, for this file alone. The block cipher itself is
# `tests`', shared with `bip38_test.py`'s AES-256-ECB; the chaining and the
# padding are BIE1's own and stay here. See the module docstring.
# --------------------------------------------------------------------------

_BLOCK_SIZE = 16


def aes_128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-CBC, applying PKCS#7 padding."""
    round_keys = aes_expand_key(key)
    # PKCS#7 always adds between 1 and 16 bytes, a whole block when the
    # plaintext is already aligned: that is what makes the padding
    # unambiguous to strip
    pad = _BLOCK_SIZE - len(plaintext) % _BLOCK_SIZE
    data = plaintext + bytes([pad]) * pad
    out = bytearray()
    previous = iv
    for i in range(0, len(data), _BLOCK_SIZE):
        previous = aes_encrypt_block(
            aes_xor(data[i : i + _BLOCK_SIZE], previous), round_keys
        )
        out += previous
    return bytes(out)


def aes_128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-128-CBC, stripping and checking PKCS#7 padding."""
    round_keys = aes_expand_key(key)
    out = bytearray()
    previous = iv
    for i in range(0, len(ciphertext), _BLOCK_SIZE):
        block = ciphertext[i : i + _BLOCK_SIZE]
        out += aes_xor(aes_decrypt_block(block, round_keys), previous)
        previous = block
    pad = out[-1]
    if not 1 <= pad <= _BLOCK_SIZE or bytes(out[-pad:]) != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return bytes(out[:-pad])


def test_aes_against_fips_197() -> None:
    """FIPS-197 appendix C.1, the AES-128 known answer.

    The cipher above is what every interoperability claim in this file
    rests on, so it is checked against the standard before it is used to
    check anything else.
    """
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    round_keys = aes_expand_key(key)
    assert aes_encrypt_block(plaintext, round_keys) == ciphertext
    assert aes_decrypt_block(ciphertext, round_keys) == plaintext


def test_aes_cbc_pads_a_whole_block_when_aligned() -> None:
    """PKCS#7 grows an aligned plaintext by a full block, and round-trips."""
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    for size in (0, 1, 15, 16, 17, 32):
        plaintext = bytes(range(size))
        ciphertext = aes_128_cbc_encrypt(key, iv, plaintext)
        assert len(ciphertext) % _BLOCK_SIZE == 0
        assert len(ciphertext) > size
        assert aes_128_cbc_decrypt(key, iv, ciphertext) == plaintext


def test_aes_cbc_rejects_broken_padding() -> None:
    """A CBC ciphertext is malleable, and the padding check is what notices.

    Flipping bits in one block flips them in the next block of plaintext,
    so the last byte can be forced to zero, which no PKCS#7 padding ever
    is. This is also why `decrypt` verifies the MAC before it calls the
    cipher: the tampering below is exactly what the MAC is there to catch,
    and reaching it requires calling the cipher directly.
    """
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = bytes(range(20))
    ciphertext = bytearray(aes_128_cbc_encrypt(key, iv, plaintext))
    # the last plaintext byte is 12, the PKCS#7 pad of a 20-byte message;
    # xoring the matching byte of the previous block turns it into 0
    ciphertext[_BLOCK_SIZE - 1] ^= 12
    with pytest.raises(ValueError, match="invalid PKCS#7 padding"):
        aes_128_cbc_decrypt(key, iv, bytes(ciphertext))


# --------------------------------------------------------------------------
# Electrum's own vectors
# --------------------------------------------------------------------------


def _electrum_key_from_password(password: bytes) -> int:
    """Compute the private key Electrum derives from a storage password.

    `WalletStorage.get_eckey_from_password` in electrum/storage.py: 1024
    rounds of PBKDF2-HMAC-SHA512 over the utf-8 password with an empty
    salt, then `ECPrivkey.from_arbitrary_size_secret`, which is
    `normalize_secret_bytes` in electrum_ecc/keys.py, i.e. the 64 bytes
    read big-endian and reduced mod n.

    Reproduced here rather than hardcoded as an integer: it is the
    provenance of the vectors below, and a hardcoded scalar would be a
    number nobody could check against Electrum.
    """
    secret = hashlib.pbkdf2_hmac("sha512", password, b"", 1024)
    return int.from_bytes(secret, "big") % secp256k1.n


# tests/test_bitcoin.py in spesmilo/electrum, `test_decrypt_message`: real
# BIE1 ciphertexts, produced by Electrum, with the plaintext each decrypts
# to. The key is the one the password 'pw123' derives above.
_ELECTRUM_PASSWORD = b"pw123"
_ELECTRUM_SHORT_PLAINTEXT = b"me<(s_s)>age"
_ELECTRUM_SHORT_ARMOR = "QklFMQMDFtgT3zWSQsa+Uie8H/WvfUjlu9UN9OJtTt3KlgKeSTi6SQfuhcg1uIz9hp3WIUOFGTLr4RNQBdjPNqzXwhkcPi2Xsbiw6UCNJncVPJ6QBg=="
_ELECTRUM_VECTORS = [
    pytest.param(_ELECTRUM_SHORT_PLAINTEXT, _ELECTRUM_SHORT_ARMOR, id="short"),
    pytest.param(
        b"me<(s_s)>age",
        "QklFMQKXOXbylOQTSMGfo4MFRwivAxeEEkewWQrpdYTzjPhqjHcGBJwdIhB7DyRfRQihuXx1y0ZLLv7XxLzrILzkl/H4YUtZB4uWjuOAcmxQH4i/Og==",
        id="short-again",
    ),
    pytest.param(
        b"hey_there" * 100,
        "QklFMQLOOsabsXtGQH8edAa6VOUa5wX8/DXmxX9NyHoAx1a5bWgllayGRVPeI2bf0ZdWK0tfal0ap0ZIVKbd2eOJybqQkILqT6E1/Syzq0Zicyb/AA1eZNkcX5y4gzloxinw00ubCA8M7gcUjJpOqbnksATcJ5y2YYXcHMGGfGurWu6uJ/UyrNobRidWppRMW5yR9/6utyNvT6OHIolCMEf7qLcmtneoXEiz51hkRdZS7weNf9mGqSbz9a2NL3sdh1A0feHIjAZgcCKcAvksNUSauf0/FnIjzTyPRpjRDMeDC8Ci3sGiuO3cvpWJwhZfbjcS26KmBv2CHWXfRRNFYOInHZNIXWNAoBB47Il5bGSMd+uXiGr+SQ9tNvcu+BiJNmFbxYqg+oQ8dGAl1DtvY2wJVY8k7vO9BIWSpyIxfGw7EDifhc5vnOmGe016p6a01C3eVGxgl23UYMrP7+fpjOcPmTSF4rk5U5ljEN3MSYqlf1QEv0OqlI9q1TwTK02VBCjMTYxDHsnt04OjNBkNO8v5uJ4NR+UUDBEp433z53I59uawZ+dbk4v4ZExcl8EGmKm3Gzbal/iJ/F7KQuX2b/ySEhLOFVYFWxK73X1nBvCSK2mC2/8fCw8oI5pmvzJwQhcCKTdEIrz3MMvAHqtPScDUOjzhXxInQOCb3+UBj1PPIdqkYLvZss1TEaBwYZjLkVnK2MBj7BaqT6Rp6+5A/fippUKHsnB6eYMEPR2YgDmCHL+4twxHJG6UWdP3ybaKiiAPy2OHNP6PTZ0HrqHOSJzBSDD+Z8YpaRg29QX3UEWlqnSKaan0VYAsV1VeaN0XFX46/TWO0L5tjhYVXJJYGqo6tIQJymxATLFRF6AZaD1Mwd27IAL04WkmoQoXfO6OFfwdp/shudY/1gBkDBvGPICBPtnqkvhGF+ZF3IRkuPwiFWeXmwBxKHsRx/3+aJu32Ml9+za41zVk2viaxcGqwTc5KMexQFLAUwqhv+aIik7U+5qk/gEVSuRoVkihoweFzKolNF+BknH2oB4rZdPixag5Zje3DvgjsSFlOl69W/67t/Gs8htfSAaHlsB8vWRQr9+v/lxTbrAw+O0E+sYGoObQ4qQMyQshNZEHbpPg63eWiHtJJnrVBvOeIbIHzoLDnMDsWVWZSMzAQ1vhX1H5QLgSEbRlKSliVY03kDkh/Nk/KOn+B2q37Ialq4JcRoIYFGJ8AoYEAD0tRuTqFddIclE75HzwaNG7NyKW1plsa72ciOPwsPJsdd5F0qdSQ3OSKtooTn7uf6dXOc4lDkfrVYRlZ0PX",
        id="long",
    ),
]


@pytest.mark.parametrize("plaintext, armor", _ELECTRUM_VECTORS)
def test_decrypt_electrum_ciphertext(plaintext: bytes, armor: str) -> None:
    """Verify btclib reads what Electrum wrote.

    BIE1 has no specification, so this is the whole of the interoperability
    claim: ciphertexts lifted from Electrum's test suite, decrypted here.
    """
    prv_key = _electrum_key_from_password(_ELECTRUM_PASSWORD)
    assert ecies.decrypt(armor, prv_key, aes_128_cbc_decrypt) == plaintext


@pytest.mark.parametrize("plaintext, armor", _ELECTRUM_VECTORS)
def test_rebuild_electrum_ciphertext(plaintext: bytes, armor: str) -> None:
    """Verify btclib writes what Electrum wrote, byte for byte.

    The ephemeral private key of a published envelope cannot be recovered,
    so `encrypt` cannot be pointed at one of these vectors directly. It can
    be reproduced from the outside, though: the ephemeral *public* key is
    in the envelope, and with the recipient's private key that is enough to
    re-derive the same iv, key_e and key_m and rebuild every other byte --
    the ciphertext under the caller's AES, the MAC over the framing, and
    the base64 armor. Getting the identical string back exercises the
    encrypt direction against real Electrum output, which a round-trip
    against btclib itself could never do.
    """
    prv_key = _electrum_key_from_password(_ELECTRUM_PASSWORD)
    envelope = ecies.Envelope.b64decode(armor)
    iv, key_e, key_m = ecies.derive_keys(prv_key, envelope.eph_pub_key)

    ciphertext = aes_128_cbc_encrypt(key_e, iv, plaintext)
    assert ciphertext == envelope.ciphertext

    rebuilt = ecies.Envelope.from_ciphertext(envelope.eph_pub_key, ciphertext, key_m)
    assert rebuilt == envelope
    assert rebuilt.b64encode() == armor


def test_decrypt_with_the_wrong_key() -> None:
    """The MAC is what says "not for you", and it cannot say more.

    A wrong private key derives a wrong key_m, which is indistinguishable
    from a forged MAC: the error names both causes because the scheme
    cannot tell them apart.
    """
    wrong_key = _electrum_key_from_password(b"pw124")
    with pytest.raises(BTClibRuntimeError, match="invalid MAC"):
        ecies.decrypt(_ELECTRUM_SHORT_ARMOR, wrong_key, aes_128_cbc_decrypt)


# --------------------------------------------------------------------------
# the scheme, with the cipher supplied
# --------------------------------------------------------------------------


def test_round_trip() -> None:
    """Round-trip messages of several sizes, block-aligned included."""
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    pub_key = mult(prv_key)
    for msg in (b"", b"short", b"a" * 16, b"a" * 17, bytes(555)):
        armor = ecies.encrypt(msg, pub_key, aes_128_cbc_encrypt)
        assert ecies.decrypt(armor, prv_key, aes_128_cbc_decrypt) == msg


def test_a_fresh_ephemeral_key_every_time() -> None:
    """Two encryptions of one message to one key differ, as Electrum's do."""
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    pub_key = mult(prv_key)
    first = ecies.encrypt(b"same message", pub_key, aes_128_cbc_encrypt)
    second = ecies.encrypt(b"same message", pub_key, aes_128_cbc_encrypt)
    assert first != second
    assert ecies.decrypt(first, prv_key, aes_128_cbc_decrypt) == b"same message"
    assert ecies.decrypt(second, prv_key, aes_128_cbc_decrypt) == b"same message"


def test_chosen_ephemeral_key_is_deterministic() -> None:
    """Verify a caller-supplied ephemeral key fixes the whole envelope."""
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    pub_key = mult(prv_key)
    eph_prv_key = 0x1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C
    armor = ecies.encrypt(
        b"deterministic", pub_key, aes_128_cbc_encrypt, eph_prv_key=eph_prv_key
    )
    assert armor == ecies.encrypt(
        b"deterministic", pub_key, aes_128_cbc_encrypt, eph_prv_key=eph_prv_key
    )
    # the envelope names the ephemeral public key it was built from
    envelope = ecies.Envelope.b64decode(armor)
    assert envelope.eph_pub_key == bytes_from_point(mult(eph_prv_key))
    assert ecies.decrypt(armor, prv_key, aes_128_cbc_decrypt) == b"deterministic"


def test_encrypt_refuses_a_cipher_that_does_not_pad() -> None:
    """The one contract breach that would otherwise ship a broken envelope.

    A cipher without PKCS#7 round-trips against itself and against nothing
    else, and on an aligned plaintext it does not even change the length.
    """

    def no_padding(key: bytes, iv: bytes, data: bytes) -> bytes:
        round_keys = aes_expand_key(key)
        out = bytearray()
        previous = iv
        for i in range(0, len(data), _BLOCK_SIZE):
            previous = aes_encrypt_block(
                aes_xor(data[i : i + _BLOCK_SIZE], previous), round_keys
            )
            out += previous
        return bytes(out)

    pub_key = mult(0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D)
    with pytest.raises(BTClibValueError, match="encrypt_f did not pad"):
        ecies.encrypt(bytes(32), pub_key, no_padding)


def test_magic_is_a_parameter() -> None:
    """Electrum varies the magic over an otherwise identical layout."""
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    pub_key = mult(prv_key)
    armor = ecies.encrypt(b"xpub", pub_key, aes_128_cbc_encrypt, magic=b"BIE2")
    assert ecies.decrypt(armor, prv_key, aes_128_cbc_decrypt, magic=b"BIE2") == b"xpub"
    with pytest.raises(BTClibValueError, match="invalid magic bytes"):
        ecies.decrypt(armor, prv_key, aes_128_cbc_decrypt)


# --------------------------------------------------------------------------
# the layers that need no cipher at all
# --------------------------------------------------------------------------


def test_derive_keys_is_the_same_on_both_sides() -> None:
    """ECDH: the sender and the recipient reach the same three values."""
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    eph_prv_key = 0x1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C
    sender = ecies.derive_keys(eph_prv_key, mult(prv_key))
    recipient = ecies.derive_keys(prv_key, mult(eph_prv_key))
    assert sender == recipient
    iv, key_e, key_m = sender
    assert (len(iv), len(key_e), len(key_m)) == (16, 16, 32)


def test_derive_keys_is_the_sha512_of_the_compressed_point() -> None:
    """The split is 16 | 16 | 32 of one sha512, and the point is compressed.

    Compressed is the part with no second chance: the uncompressed form of
    the same point hashes to something else entirely, so getting it wrong
    is an implementation that talks to nobody.
    """
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    eph_prv_key = 0x1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C
    shared_point: Point = mult(eph_prv_key, mult(prv_key))
    digest = hashlib.sha512(bytes_from_point(shared_point)).digest()
    assert ecies.derive_keys(eph_prv_key, mult(prv_key)) == (
        digest[:16],
        digest[16:32],
        digest[32:],
    )


def test_envelope_round_trips_through_its_serializations() -> None:
    """Round-trip an envelope through bytes, hex and base64."""
    key_m = bytes(range(32))
    eph_pub_key = bytes_from_point(mult(42))
    envelope = ecies.Envelope.from_ciphertext(eph_pub_key, bytes(48), key_m)
    envelope.assert_valid_mac(key_m)
    assert ecies.Envelope.parse(envelope.serialize()) == envelope
    assert ecies.Envelope.b64decode(envelope.b64encode()) == envelope
    # a hex string is octets too, for both of the octets parameters
    assert envelope.mac_from_key(key_m.hex()) == envelope.mac
    assert ecies.Envelope.parse(envelope.serialize().hex()) == envelope


def test_envelope_fields_are_octets_like_every_other_field() -> None:
    """The four fields coerce and refuse as `Octets` does everywhere else.

    They were declared `bytes` and assigned as they came, which is what
    made two answers wrong: a value with no `len` left `assert_valid` as a
    TypeError about a builtin, and a value *with* one was reported as a
    size -- a two-character str is not a two-byte magic, it is not a magic
    at all. Every other octet field of the library coerces in its
    constructor, so a hex string is what a caller may hold here too.
    """
    key_m = bytes(range(32))
    envelope = ecies.Envelope.from_ciphertext(
        bytes_from_point(mult(42)), bytes(48), key_m
    )
    assert (
        ecies.Envelope(
            envelope.magic.hex(),
            envelope.eph_pub_key.hex(),
            envelope.ciphertext.hex(),
            envelope.mac.hex(),
        )
        == envelope
    )

    wrong_types: tuple[Any, ...] = (None, 1.5, [1, 2])
    for wrong in wrong_types:
        for field in ("magic", "eph_pub_key", "ciphertext", "mac"):
            fields: dict[str, Any] = {
                "magic": envelope.magic,
                "eph_pub_key": envelope.eph_pub_key,
                "ciphertext": envelope.ciphertext,
                "mac": envelope.mac,
            }
            fields[field] = wrong
            with pytest.raises(BTClibTypeError, match="invalid octets type"):
                ecies.Envelope(**fields)
        # and the factory, which concatenates before it builds: a magic
        # of no octet type failed on the `+` rather than as an argument
        with pytest.raises(BTClibTypeError, match="invalid octets type"):
            ecies.Envelope.from_ciphertext(
                bytes_from_point(mult(42)), bytes(48), key_m, magic=wrong
            )


def test_envelope_b64decode_tolerates_surrounding_whitespace() -> None:
    """Verify b64decode strips the whitespace around the armor."""
    key_m = bytes(range(32))
    envelope = ecies.Envelope.from_ciphertext(
        bytes_from_point(mult(42)), bytes(48), key_m
    )
    armor = envelope.b64encode()
    assert ecies.Envelope.b64decode(f"  {armor}\n") == envelope
    assert ecies.Envelope.b64decode(f" {armor} ".encode()) == envelope


def test_envelope_mac_check_notices_a_flipped_bit() -> None:
    """Refuse a tampered ciphertext through assert_valid_mac."""
    key_m = bytes(range(32))
    eph_pub_key = bytes_from_point(mult(42))
    envelope = ecies.Envelope.from_ciphertext(eph_pub_key, bytes(48), key_m)
    tampered = ecies.Envelope(
        envelope.magic,
        envelope.eph_pub_key,
        b"\x01" + envelope.ciphertext[1:],
        envelope.mac,
    )
    with pytest.raises(BTClibRuntimeError, match="invalid MAC"):
        tampered.assert_valid_mac(key_m)


def test_envelope_skips_validation_when_told_to() -> None:
    """check_validity=False is what lets an invalid envelope be built at all."""
    envelope = ecies.Envelope(b"BIE1", b"", b"", b"", check_validity=False)
    assert envelope.serialize(check_validity=False) == b"BIE1"
    with pytest.raises(BTClibValueError, match="invalid ephemeral public key size"):
        envelope.assert_valid()
    with pytest.raises(BTClibValueError, match="invalid ephemeral public key size"):
        envelope.b64encode()


def _valid_parts() -> tuple[bytes, bytes, bytes, bytes]:
    """Provide the four fields of a well-formed envelope."""
    return b"BIE1", bytes_from_point(mult(42)), bytes(48), bytes(32)


@pytest.mark.parametrize(
    "field, value, err_msg",
    [
        (0, b"BIE", "invalid magic size"),
        (1, bytes(32), "invalid ephemeral public key size"),
        (2, bytes(15), "invalid ciphertext size"),
        (2, bytes(24), "not a whole number of 16-byte blocks"),
        (3, bytes(31), "invalid MAC size"),
    ],
)
def test_envelope_rejects_a_malformed_field(
    field: int, value: bytes, err_msg: str
) -> None:
    """Refuse each malformed envelope field with the message naming it."""
    magic, eph_pub_key, ciphertext, mac = _valid_parts()
    parts = [magic, eph_pub_key, ciphertext, mac]
    parts[field] = value
    with pytest.raises(BTClibValueError, match=err_msg):
        ecies.Envelope(parts[0], parts[1], parts[2], parts[3])


def test_envelope_rejects_an_ephemeral_key_that_is_not_a_point() -> None:
    """33 bytes of the right shape, naming no point on the curve."""
    magic, _, ciphertext, mac = _valid_parts()
    with pytest.raises(BTClibValueError, match="not a public key"):
        ecies.Envelope(magic, b"\x02" + bytes(32), ciphertext, mac)


def test_parse_rejects_a_truncated_envelope() -> None:
    """Refuse an envelope too short to hold its fixed-size fields."""
    with pytest.raises(BTClibValueError, match="invalid envelope size"):
        ecies.Envelope.parse(b"BIE1" + bytes(80))


def test_parse_rejects_the_wrong_magic() -> None:
    """Refuse an envelope whose magic is not the one asked for."""
    envelope = ecies.Envelope(*_valid_parts(), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid magic bytes"):
        ecies.Envelope.parse(envelope.serialize(check_validity=False), magic=b"BIE2")


@pytest.mark.parametrize(
    "armor, err_msg",
    [
        ("not base64 at all!", "invalid base64 encoding"),
        ("QklFMQ", "invalid base64 encoding"),
        ("é", "invalid base64 encoding"),
    ],
)
def test_b64decode_rejects_bad_armor(armor: str, err_msg: str) -> None:
    """Refuse armor that is not valid base64."""
    with pytest.raises(BTClibValueError, match=err_msg):
        ecies.Envelope.b64decode(armor)


def test_b64decode_requires_the_canonical_encoding() -> None:
    """Non-canonical padding decodes, and would make one envelope many.

    b64decode discards the bits a non-final group leaves over, so a string
    that is not what b64encode gives back still decodes to something: the
    round-trip comparison is what rejects it, as it does in bms.
    """
    # 4 + 33 + 16 + 32 is 85 bytes, which is 1 modulo 3: the base64 of it
    # ends in "==", and the character before them carries four bits that
    # encode nothing. A 48-byte ciphertext would make the total a multiple
    # of 3 and leave no slack to tamper with
    envelope = ecies.Envelope.from_ciphertext(
        bytes_from_point(mult(42)), bytes(16), bytes(range(32))
    )
    armor = envelope.b64encode()
    assert armor.endswith("==")
    alphabet = f"{string.ascii_uppercase}{string.ascii_lowercase}{string.digits}+/"
    # the canonical character has those four bits clear, so the next one
    # along decodes to the very same byte
    tweaked = f"{armor[:-3]}{alphabet[alphabet.index(armor[-3]) + 1]}=="
    assert tweaked != armor
    assert base64.b64decode(tweaked, validate=True) == envelope.serialize()
    with pytest.raises(BTClibValueError, match="not canonical"):
        ecies.Envelope.b64decode(tweaked)
