# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP38: a password-protected private key.

The block cipher is supplied by the caller.
https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

A BIP38 record is a 58-character Base58Check string starting "6P", built
from a private key, a password, and `scrypt` -- slow on purpose, so that
trying one guessed password costs an attacker what it costs the owner.
Two modes:

- **non-EC-multiply** (:func:`encrypt`, and :func:`decrypt` on the result):
  a known private key is encrypted under a password, and only the same
  password decrypts it back. The party doing the encrypting sees the key.
- **EC-multiply** (:func:`intermediate_code`, :func:`new_key_pair`, and
  :func:`decrypt` on the result): the *owner*, who holds the password,
  hands a *printer* an ``intermediate_code`` derived from it, and the
  printer draws a new key pair and an encrypted record from that code
  alone, never learning the password or the private key. Only the owner's
  password decrypts the record back to the same key. An intermediate code
  optionally embeds a *lot* and *sequence* number (0..1048575 and
  0..4095), which lets an owner requesting a batch of keys tell them apart
  and, later, confirm none was substituted.

`decrypt` reads the two-byte prefix that opens every record --
``0x0142`` or ``0x0143`` -- and answers either mode from one call; a
caller does not choose which decryption to run, the record says. What it
returns is a :class:`btclib.key.PrvKeyData`, the shape a parsed private
key takes everywhere else in this library since issue #1188's WIF row
landed: this module has no format of its own to hand back, `network` is
always "mainnet" for it, since nothing in a BIP38 record names one.

**Why the cipher is a parameter.** BIP38 encrypts with AES-256 in ECB --
each 16-byte block on its own, no chaining -- and `btclib.ecc.ecies`'s
module docstring has the argument in full for why btclib ships none of
its own: a table-driven block cipher leaks its key through cache timing,
and shipping one anyway is a worse answer than shipping none. `encrypt`
and `decrypt` here take `encrypt_block` / `decrypt_block` callables for
that reason, the same shape `ecies.encrypt` and `ecies.decrypt` take for
AES-128-CBC. `new_key_pair`, the printer's half of EC-multiply, takes
`encrypt_block` too, being the one function of the four that calls the
cipher forward rather than back.

**The contract those callables must honour.** Both are called
positionally, as ``f(key, block)``, with a 32-byte key and a 16-byte
block, and return a 16-byte block: no iv, no padding, no chaining --
ECB is the absence of a mode, not one to add, and BIP38 never encrypts
more than two blocks at a time. Anything other than AES-256 will
round-trip against itself and produce a record no other implementation
of BIP38 can read, which is the whole point of the algorithm; the
callables are a way to source AES, not a choice of cipher.

**No MAC, unlike BIE1.** `ecies.decrypt` checks an HMAC before it ever
calls the caller's cipher, so a wrong key never reaches it. BIP38 has no
such check: decryption runs the cipher first and only then re-derives
the Bitcoin address the record's four-byte `addresshash` names, so a
wrong password still calls `decrypt_block` before `decrypt` can tell the
password was wrong. `SECURITY.md` carries this as its own point, next to
`ecies`'s.

**The address hash is always mainnet P2PKH.** BIP38 predates every other
network this library knows and has one encoding, not one per network:
the record's `addresshash` is always the double-SHA256 of a mainnet P2PKH
address (compressed or not, per the record's own flag byte), whatever
network the caller means to spend the recovered key on. That address is
BIP38's own checksum against the wrong password, not a claim about where
the key is used.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata

from btclib.alias import BlockCipherF, Integer, Octets, String
from btclib.b58 import address_from_h160
from btclib.base58 import decode as base58_decode
from btclib.base58 import encode as base58_encode
from btclib.curves import bytes_from_point, mult, point_from_octets, secp256k1
from btclib.curves import scalar_from_prv_key as _scalar
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    InvalidPrvKeyError,
    NotAPrvKeyError,
)
from btclib.hashes import hash160, hash256
from btclib.key import PrvKeyData
from btclib.utils import assert_type, bytes_from_octets, is_integer

__all__ = [
    "decrypt",
    "encrypt",
    "intermediate_code",
    "new_key_pair",
]

_BLOCK_SIZE = 16

_NO_EC_PREFIX = b"\x01\x42"
_EC_PREFIX = b"\x01\x43"
_ENC_KEY_SIZE = 39

# non-EC flagbyte: the top two bits ("11") plus, optionally, the
# compression bit -- no other bit is ever legitimately set
_FLAG_UNCOMPRESSED_NO_EC = 0xC0
_FLAG_COMPRESSED_NO_EC = 0xE0

# EC-multiply flagbyte bits: the top two bits are "00" by construction
# (neither is in this mask), compression and lot/sequence are the only
# two a valid record may set
_FLAG_BIT_COMPRESSED = 0x20
_FLAG_BIT_LOT_SEQ = 0x04
_FLAG_EC_RESERVED_MASK = ~(_FLAG_BIT_COMPRESSED | _FLAG_BIT_LOT_SEQ) & 0xFF

_MAGIC_LOT_SEQ = bytes.fromhex("2ce9b3e1ff39e251")
_MAGIC_NO_LOT_SEQ = bytes.fromhex("2ce9b3e1ff39e253")
_INT_CODE_SIZE = 49

_LOT_MAX = 1_048_575
_SEQ_MAX = 4_095
_OWNER_SALT_LOT_SEQ_SIZE = 4
_OWNER_SALT_NO_LOT_SEQ_SIZE = 8
_SEED_B_SIZE = 24


def _password_bytes(password: str) -> bytes:
    """Return a BIP38 password as the octets scrypt is stretched over.

    UTF-8, NFC-normalized: the BIP's own words, and what its third test
    vector exists to check -- a passphrase of five characters outside
    ASCII, one of them combining and one of them astride the Basic
    Multilingual Plane, that a decomposed or a re-composed rendering of
    the same string must stretch to the same key.
    """
    assert_type(password, str, "password")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _block_cipher(f: BlockCipherF, key: bytes, block: bytes, what: str) -> bytes:
    """Call a caller-supplied block cipher and check its output is a block.

    `ecies.encrypt` has the same check on the other end of a different
    contract -- padding there, a bare size here -- for the same reason:
    a cipher that does not honour its contract is refused where it was
    called instead of three steps later, on a record no other
    implementation could have produced either.
    """
    out = f(key, block)
    if len(out) != _BLOCK_SIZE:
        raise BTClibValueError(
            f"{what} did not return a {_BLOCK_SIZE}-byte block: {len(out)} bytes"
        )
    return out


def _mainnet_address_hash(sec: bytes) -> bytes:
    """Return the addresshash BIP38 embeds: hash256 of the ASCII address."""
    h160 = hash160(sec)
    address = address_from_h160("p2pkh", h160, "mainnet")
    return hash256(address.encode("ascii"))[:4]


def encrypt(
    prv_key: Integer,
    password: str,
    encrypt_block: BlockCipherF,
    *,
    compressed: bool = True,
) -> str:
    """Return the BIP38 non-EC-multiply encryption of a known private key.

    `encrypt_block` must be AES-256 as a single block, key then block;
    the module docstring has the contract in full. `compressed` decides
    the public key form the record's `addresshash` is checked against,
    which `decrypt` reads back off the record and does not need restated.
    """
    assert_type(compressed, bool, "compressed")
    q = _scalar(prv_key)
    priv_key_bytes = q.to_bytes(secp256k1.n_size, byteorder="big")

    sec = bytes_from_point(mult(q), compressed=compressed)
    address_hash = _mainnet_address_hash(sec)

    # BIP38 "Derive a key from the passphrase using scrypt", n=16384,
    # r=8, p=8, length=64, salt=addresshash
    derived = hashlib.scrypt(
        _password_bytes(password), salt=address_hash, n=16384, r=8, p=8, dklen=64
    )
    derived_half_1, derived_half_2 = derived[:32], derived[32:]

    encrypted_half_1 = _block_cipher(
        encrypt_block,
        derived_half_2,
        _xor(priv_key_bytes[:16], derived_half_1[:16]),
        "encrypt_block",
    )
    encrypted_half_2 = _block_cipher(
        encrypt_block,
        derived_half_2,
        _xor(priv_key_bytes[16:], derived_half_1[16:]),
        "encrypt_block",
    )

    flagbyte = _FLAG_COMPRESSED_NO_EC if compressed else _FLAG_UNCOMPRESSED_NO_EC
    payload = (
        _NO_EC_PREFIX
        + bytes([flagbyte])
        + address_hash
        + encrypted_half_1
        + encrypted_half_2
    )
    return base58_encode(payload).decode("ascii")


def _decrypt_no_ec(
    payload: bytes, password: str, decrypt_block: BlockCipherF
) -> PrvKeyData:
    flagbyte = payload[2]
    if flagbyte not in (_FLAG_UNCOMPRESSED_NO_EC, _FLAG_COMPRESSED_NO_EC):
        raise InvalidPrvKeyError(f"invalid flagbyte: 0x{flagbyte:02x}")
    compressed = flagbyte == _FLAG_COMPRESSED_NO_EC
    address_hash = payload[3:7]
    encrypted_half_1, encrypted_half_2 = payload[7:23], payload[23:39]

    derived = hashlib.scrypt(
        _password_bytes(password), salt=address_hash, n=16384, r=8, p=8, dklen=64
    )
    derived_half_1, derived_half_2 = derived[:32], derived[32:]

    half_1 = _xor(
        _block_cipher(decrypt_block, derived_half_2, encrypted_half_1, "decrypt_block"),
        derived_half_1[:16],
    )
    half_2 = _xor(
        _block_cipher(decrypt_block, derived_half_2, encrypted_half_2, "decrypt_block"),
        derived_half_1[16:],
    )
    q = _scalar(half_1 + half_2)

    sec = bytes_from_point(mult(q), compressed=compressed)
    if _mainnet_address_hash(sec) != address_hash:
        raise BTClibRuntimeError("wrong password: address hash does not match")

    return PrvKeyData(q, "mainnet", compressed, check_validity=False)


def intermediate_code(
    password: str,
    *,
    lot: int | None = None,
    sequence: int | None = None,
    owner_salt: Octets | None = None,
) -> str:
    """Return the intermediate code an owner hands a printer, from a password.

    `lot` and `sequence` are given together or not at all: an owner
    requesting a batch of keys states both, to tell the resulting keys
    apart and later confirm none was substituted, and the record carries
    a bit saying whether it was given either. `owner_salt` overrides the
    random one, which is what makes a fixed test vector reproducible --
    reusing one across two intermediate codes for the same password
    reuses the whole derivation, so leave it alone outside of tests.
    """
    if (lot is None) != (sequence is None):
        raise BTClibValueError("lot and sequence must both be given, or neither")
    if lot is not None and sequence is not None:
        if not is_integer(lot):
            raise BTClibTypeError("lot number must be an int")
        if not is_integer(sequence):
            raise BTClibTypeError("sequence number must be an int")
        if not 0 <= lot <= _LOT_MAX:
            raise BTClibValueError(f"lot number out of range: {lot}")
        if not 0 <= sequence <= _SEQ_MAX:
            raise BTClibValueError(f"sequence number out of range: {sequence}")
        salt_size = _OWNER_SALT_LOT_SEQ_SIZE
    else:
        salt_size = _OWNER_SALT_NO_LOT_SEQ_SIZE

    if owner_salt is None:
        owner_salt = secrets.token_bytes(salt_size)
    else:
        owner_salt = bytes_from_octets(owner_salt, salt_size)

    if lot is not None and sequence is not None:
        lot_sequence = (lot * (_SEQ_MAX + 1) + sequence).to_bytes(4, byteorder="big")
        owner_entropy = owner_salt + lot_sequence
        magic = _MAGIC_LOT_SEQ
    else:
        owner_entropy = owner_salt
        magic = _MAGIC_NO_LOT_SEQ

    # BIP38 "Derive a key from the passphrase using scrypt", n=16384,
    # r=8, p=8, length=32, salt=ownersalt -- "prefactor"
    prefactor = hashlib.scrypt(
        _password_bytes(password), salt=owner_salt, n=16384, r=8, p=8, dklen=32
    )
    passfactor = (
        hash256(prefactor + owner_entropy) if magic == _MAGIC_LOT_SEQ else prefactor
    )
    passpoint = bytes_from_point(mult(_scalar(passfactor)), compressed=True)

    return base58_encode(magic + owner_entropy + passpoint).decode("ascii")


def new_key_pair(
    int_code: String,
    encrypt_block: BlockCipherF,
    *,
    compressed: bool = True,
    seed_b: Octets | None = None,
) -> tuple[str, str]:
    """Return a new (encrypted_key, address) pair from an intermediate code.

    The printer's half of EC-multiply: draws a fresh key pair from
    `int_code` alone and encrypts it, never learning the password or the
    private key it just created. `encrypt_block` must be AES-256 as a
    single block, key then block; the module docstring has the contract
    in full. `seed_b` overrides the random key material, which is what
    makes a fixed test vector reproducible -- leave it alone outside of
    tests, since two calls sharing one reuse the same key.
    """
    assert_type(compressed, bool, "compressed")
    payload = base58_decode(int_code, _INT_CODE_SIZE)
    magic, owner_entropy, passpoint_sec = payload[:8], payload[8:16], payload[16:49]
    if magic not in (_MAGIC_NO_LOT_SEQ, _MAGIC_LOT_SEQ):
        raise BTClibValueError(f"invalid intermediate code magic: 0x{magic.hex()}")
    has_lot_seq = magic == _MAGIC_LOT_SEQ
    passpoint = point_from_octets(passpoint_sec, secp256k1)

    if seed_b is None:
        seed_b = secrets.token_bytes(_SEED_B_SIZE)
    else:
        seed_b = bytes_from_octets(seed_b, _SEED_B_SIZE)
    factorb = _scalar(hash256(seed_b))

    sec = bytes_from_point(mult(factorb, passpoint), compressed=compressed)
    address_hash = _mainnet_address_hash(sec)

    # BIP38 "Derive a second key from passpoint using scrypt", n=1024,
    # r=1, p=1, length=64, salt=addresshash+ownerentropy
    derived = hashlib.scrypt(
        passpoint_sec,
        salt=address_hash + owner_entropy,
        n=1024,
        r=1,
        p=1,
        dklen=64,
    )
    derived_half_1, derived_half_2 = derived[:32], derived[32:]

    encrypted_part_1 = _block_cipher(
        encrypt_block,
        derived_half_2,
        _xor(seed_b[:16], derived_half_1[:16]),
        "encrypt_block",
    )
    encrypted_part_2 = _block_cipher(
        encrypt_block,
        derived_half_2,
        _xor(encrypted_part_1[8:16] + seed_b[16:24], derived_half_1[16:]),
        "encrypt_block",
    )

    flagbyte = (_FLAG_BIT_COMPRESSED if compressed else 0) | (
        _FLAG_BIT_LOT_SEQ if has_lot_seq else 0
    )
    out_payload = (
        _EC_PREFIX
        + bytes([flagbyte])
        + address_hash
        + owner_entropy
        + encrypted_part_1[:8]
        + encrypted_part_2
    )
    address = address_from_h160("p2pkh", hash160(sec), "mainnet")
    return base58_encode(out_payload).decode("ascii"), address


def _decrypt_ec(
    payload: bytes, password: str, decrypt_block: BlockCipherF
) -> PrvKeyData:
    flagbyte = payload[2]
    if flagbyte & _FLAG_EC_RESERVED_MASK:
        raise InvalidPrvKeyError(f"invalid flagbyte: 0x{flagbyte:02x}")
    compressed = bool(flagbyte & _FLAG_BIT_COMPRESSED)
    has_lot_seq = bool(flagbyte & _FLAG_BIT_LOT_SEQ)

    address_hash = payload[3:7]
    owner_entropy = payload[7:15]
    encrypted_part_1_lo = payload[15:23]
    encrypted_part_2 = payload[23:39]

    owner_salt = owner_entropy[:4] if has_lot_seq else owner_entropy
    prefactor = hashlib.scrypt(
        _password_bytes(password), salt=owner_salt, n=16384, r=8, p=8, dklen=32
    )
    passfactor = hash256(prefactor + owner_entropy) if has_lot_seq else prefactor
    passfactor_q = _scalar(passfactor)
    passpoint_sec = bytes_from_point(mult(passfactor_q), compressed=True)

    derived = hashlib.scrypt(
        passpoint_sec,
        salt=address_hash + owner_entropy,
        n=1024,
        r=1,
        p=1,
        dklen=64,
    )
    derived_half_1, derived_half_2 = derived[:32], derived[32:]

    part_2 = _xor(
        _block_cipher(decrypt_block, derived_half_2, encrypted_part_2, "decrypt_block"),
        derived_half_1[16:],
    )
    encrypted_part_1_hi, seed_b_part_2 = part_2[:8], part_2[8:]
    part_1 = _xor(
        _block_cipher(
            decrypt_block,
            derived_half_2,
            encrypted_part_1_lo + encrypted_part_1_hi,
            "decrypt_block",
        ),
        derived_half_1[:16],
    )
    seed_b = part_1 + seed_b_part_2
    factorb_q = _scalar(hash256(seed_b))

    q = _scalar((passfactor_q * factorb_q) % secp256k1.n)
    sec = bytes_from_point(mult(q), compressed=compressed)
    if _mainnet_address_hash(sec) != address_hash:
        raise BTClibRuntimeError("wrong password: address hash does not match")

    return PrvKeyData(q, "mainnet", compressed, check_validity=False)


def decrypt(
    encrypted_key: String, password: str, decrypt_block: BlockCipherF
) -> PrvKeyData:
    """Return the private key a BIP38 record decrypts to, given the password.

    Reads both modes from one call: the record's own two-byte prefix says
    whether it is non-EC-multiply or EC-multiply, and this dispatches
    rather than asking the caller to know which. `decrypt_block` must be
    AES-256 as a single block, key then block; the module docstring has
    the contract in full, including the one way this differs from
    `ecies.decrypt` -- there is no MAC, so a wrong password still calls
    the cipher before the mismatch is caught.

    Raises `NotAPrvKeyError` for a prefix no BIP38 record has,
    `InvalidPrvKeyError` for a recognised record with an invalid flag
    byte, and `BTClibRuntimeError` for a password that does not match --
    the same two-class split `b58.prv_key_data_from_wif` makes for a WIF,
    plus the runtime check a password has and a WIF does not.
    """
    payload = base58_decode(encrypted_key, _ENC_KEY_SIZE)
    prefix = payload[:2]
    if prefix == _NO_EC_PREFIX:
        return _decrypt_no_ec(payload, password, decrypt_block)
    if prefix == _EC_PREFIX:
        return _decrypt_ec(payload, password, decrypt_block)
    raise NotAPrvKeyError(f"not a BIP38 record (invalid prefix 0x{prefix.hex()})")
