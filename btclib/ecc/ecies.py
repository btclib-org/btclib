# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ECIES in the BIE1 layout, with the block cipher supplied by the caller.

BIE1 is the ECIES variant the bitcoin world converged on: Electrum's
`encrypt` / `decrypt` commands, bitcore and bitcoinjs all speak it, and it
is what turns the shared secret of :mod:`btclib.ecc.dh` into an actual
encrypted message. A sender who has the recipient's public key:

- generates an ephemeral key pair and runs ECDH against that public key
- takes the sha512 of the *compressed* shared point and splits the 64
  bytes into iv | key_e | key_m, 16 | 16 | 32
- encrypts the message with AES-128-CBC and PKCS#7 padding, under key_e
  and that iv
- frames it as ``b"BIE1" + ephemeral pub key + ciphertext``, appends the
  HMAC-SHA256 of that framing under key_m, and base64-encodes the lot

The recipient re-derives the same three values from the ephemeral public
key carried in the envelope, so nothing but the envelope has to travel.

**Why the cipher is a parameter.** btclib has no cryptographic dependency:
hashlib and the secp256k1 bindings are the whole of it, and its install
story is "Python plus the bindings". AES is not in the standard library,
so shipping BIE1 whole would mean taking `cryptography` or `pycryptodome`
for one convenience function, on every user, forever. A pure-Python AES
inside btclib is the worse answer rather than the cheaper one: a
table-driven block cipher leaks its key through cache timing, and a
timing-vulnerable cipher is a worse thing to ship than no cipher at all.
So this module implements the half that is btclib's business -- the key
agreement, the derivation, the framing, the MAC and the armor -- and takes
the other half as two callables. Interoperability is preserved for anyone
who brings their own AES, and the dependency is theirs to choose.

**The contract those callables must honour.** Both are called
positionally, as ``f(key, iv, data)``, with a 16-byte key_e and a 16-byte
iv:

- ``encrypt_f(key, iv, plaintext)`` returns AES-128-CBC ciphertext with
  PKCS#7 padding already applied. The padding is not optional and not
  btclib's to add: it is what makes the result a whole number of 16-byte
  blocks, and PKCS#7 appends a *full* block when the plaintext is already
  block-aligned, so the ciphertext is always strictly longer than the
  plaintext. :func:`encrypt` checks both of those and refuses a cipher
  that does not pad, which is the mistake that otherwise ships an envelope
  no other implementation can read back.
- ``decrypt_f(key, iv, ciphertext)`` is the inverse, and strips the
  padding. It is called only after the MAC has verified, so it is never
  handed a ciphertext this library has not authenticated.

Anything other than AES-128-CBC with PKCS#7 will round-trip against
itself and interoperate with nothing, which is the whole point of the
scheme; the callables are a way to source AES, not a choice of cipher.

**What BIE1 is not.** It is not a BIP and has no specification: its
definition is its implementations, of which Electrum's is the most read.
This module is written against `ecies_encrypt_message` and
`ecies_decrypt_message` in electrum/crypto.py and matches them byte for
byte, and the test suite decrypts ciphertexts taken from Electrum's own
test vectors. That is also why nothing here is parameterized by curve or
hash function, unlike the rest of :mod:`btclib.ecc`: every implementation
that exists is secp256k1 with sha512 and HMAC-SHA256, so a parameter would
advertise an interoperability that has no other end.

The magic bytes are a parameter, though, because Electrum itself varies
them: `BIE1` for a user password and `BIE2` for an xpub-derived one, over
an otherwise identical layout.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass
from hashlib import sha256, sha512

from btclib.alias import CipherF, Integer, Octets, String
from btclib.curves import bytes_from_point, mult, scalar_from_prv_key, secp256k1
from btclib.curves.sec_point import _mult_sec_var
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.to_pub_key import PubKey, point_from_pub_key, pub_keyinfo_from_pub_key
from btclib.utils import assert_type, bytes_from_octets, str_from_string

__all__ = [
    "MAGIC",
    "Envelope",
    "decrypt",
    "derive_keys",
    "encrypt",
]

# the four bytes Electrum writes for a user-password envelope, and the name
# the scheme goes by. A comment and not an attribute docstring: the
# check-docstring-first hook reads the second string literal of a module as
# a second module docstring, whatever indentation it has
MAGIC = b"BIE1"

_MAGIC_SIZE = 4
# compressed secp256k1 SEC point: BIE1 never carries the uncompressed form,
# and the offsets below are fixed because of it
_EPH_PUB_KEY_SIZE = 33
_MAC_SIZE = 32
# the AES block, which the layout inherits from the cipher it names even
# though this module does not run it
_BLOCK_SIZE = 16


def derive_keys(prv_key: Integer, pub_key: PubKey) -> tuple[bytes, bytes, bytes]:
    """Return the (iv, key_e, key_m) triple BIE1 derives from an ECDH exchange.

    The shared point is serialized compressed and hashed with sha512; the
    64 bytes are cut 16 | 16 | 32. Both ends call this: the sender with the
    ephemeral private key and the recipient's public key, the recipient
    with its own private key and the ephemeral public key from the
    envelope.

    The multiplication is delegated and the derivation is not, which is
    :mod:`btclib.ecc.dh`'s verdict for every ECDH-shaped computation here:
    `ecdh.shared_secret` of the bindings hashes with SHA256 and BIE1 wants
    sha512 cut three ways.

    No infinity check on the shared point, unlike
    :func:`btclib.ecc.dh.diffie_hellman`, which takes a bare int: the
    scalars that could produce one are exactly those `scalar_from_prv_key`
    rejects, and both inputs here go through a validating conversion.
    """
    q = scalar_from_prv_key(prv_key)
    # the public key stays octets: no coordinate of it is read here, and
    # `_mult_sec_var` is the multiplication without the point in between
    sec = pub_keyinfo_from_pub_key(pub_key)[0]
    shared_point_bytes = bytes_from_point(
        _mult_sec_var(sec, q, secp256k1), compressed=True
    )
    digest = sha512(shared_point_bytes).digest()
    return digest[:16], digest[16:32], digest[32:]


@dataclass(frozen=True, init=False)
class Envelope:
    """The BIE1 framing: magic, ephemeral public key, ciphertext, MAC.

    Everything here is cipher-free. The ciphertext is carried as opaque
    bytes, so an envelope can be parsed, validated, MAC-checked and
    re-serialized by code that has no AES at all.
    """

    magic: bytes
    eph_pub_key: bytes
    ciphertext: bytes
    mac: bytes

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self,
        magic: Octets,
        eph_pub_key: Octets,
        ciphertext: Octets,
        mac: Octets,
        *,
        check_validity: bool = True,
    ) -> None:
        # `Octets` and the coercion every other octet field of this
        # library has in its constructor -- OutPoint's tx_id, a header's
        # merkle root, a witness element, a bip32 key. These four were
        # assigned as they came, so a value with no `len` left
        # `assert_valid` as a TypeError about a builtin, and one with a
        # `len` was reported as a *size*: a two-character str is not a
        # two-byte magic, it is not a magic at all. Hex is what a caller
        # holds as often as bytes, an envelope being copied and pasted
        object.__setattr__(self, "magic", bytes_from_octets(magic))
        object.__setattr__(self, "eph_pub_key", bytes_from_octets(eph_pub_key))
        object.__setattr__(self, "ciphertext", bytes_from_octets(ciphertext))
        object.__setattr__(self, "mac", bytes_from_octets(mac))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Raise unless every field has the size and shape BIE1 gives it.

        This is the structure alone: whether the MAC is the *right* MAC is
        :meth:`assert_valid_mac`, which needs a key this object does not
        have.
        """
        if len(self.magic) != _MAGIC_SIZE:
            raise BTClibValueError(f"invalid magic size: {len(self.magic)} bytes")
        if len(self.eph_pub_key) != _EPH_PUB_KEY_SIZE:
            raise BTClibValueError(
                f"invalid ephemeral public key size: {len(self.eph_pub_key)} bytes"
            )
        # on the curve, and compressed: point_from_pub_key would take the
        # uncompressed form too, and the size check above is what rules it out
        point_from_pub_key(self.eph_pub_key)
        # a CBC ciphertext is whole blocks, and PKCS#7 makes it a non-empty
        # number of them even for an empty message. Stricter than Electrum,
        # which checks the total length alone: a misaligned ciphertext
        # cannot have come from the cipher BIE1 names, and saying so here
        # beats handing it to the caller's AES to fail on
        if len(self.ciphertext) < _BLOCK_SIZE:
            raise BTClibValueError(
                f"invalid ciphertext size: {len(self.ciphertext)} bytes"
            )
        if len(self.ciphertext) % _BLOCK_SIZE:
            raise BTClibValueError(
                f"ciphertext is not a whole number of {_BLOCK_SIZE}-byte blocks: "
                f"{len(self.ciphertext)} bytes"
            )
        if len(self.mac) != _MAC_SIZE:
            raise BTClibValueError(f"invalid MAC size: {len(self.mac)} bytes")

    def mac_from_key(self, key_m: Octets) -> bytes:
        """Return the HMAC-SHA256 the framed envelope has under key_m."""
        key_m = bytes_from_octets(key_m)
        framing = self.magic + self.eph_pub_key + self.ciphertext
        return hmac.digest(key_m, framing, sha256)

    def assert_valid_mac(self, key_m: Octets) -> None:
        """Raise unless the MAC is the one key_m produces over this envelope.

        A failure here is the one error the scheme reports for two
        different causes, and it cannot tell them apart: the envelope was
        tampered with, or it was addressed to somebody else. A wrong
        private key derives a wrong key_m, and a wrong key_m is exactly
        what a forged MAC looks like.
        """
        # compare_digest and not ==: the MAC is checked before anything is
        # decrypted, so the comparison is the gate, and a byte-at-a-time
        # early exit is what lets a forgery be searched for one byte at a time
        if not hmac.compare_digest(self.mac, self.mac_from_key(key_m)):
            raise BTClibRuntimeError(
                "invalid MAC: wrong private key, or tampered envelope"
            )

    @classmethod
    def from_ciphertext(
        cls,
        eph_pub_key: Octets,
        ciphertext: Octets,
        key_m: Octets,
        *,
        magic: Octets = MAGIC,
    ) -> Envelope:
        """Frame an already-encrypted ciphertext and MAC it under key_m.

        The magic is coerced here and not left to the constructor below,
        which would take it: this method concatenates before it builds,
        so a magic that is not bytes failed on the `+` rather than as the
        argument it is.
        """
        magic = bytes_from_octets(magic)
        ciphertext = bytes_from_octets(ciphertext)
        eph_pub_key = bytes_from_octets(eph_pub_key)
        # the MAC covers the magic and the ephemeral key as well as the
        # ciphertext, so the envelope has to exist before its own MAC does:
        # build it with a placeholder, read the MAC off that framing, and
        # re-build it with the real one. check_validity waits for the
        # second, the first being a correct framing under a MAC known to be
        # wrong -- and mac_from_key reads the framing alone, never self.mac
        placeholder = cls(
            magic, eph_pub_key, ciphertext, bytes(_MAC_SIZE), check_validity=False
        )
        return cls(magic, eph_pub_key, ciphertext, placeholder.mac_from_key(key_m))

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the envelope as the octets that go under the base64."""
        if check_validity:
            self.assert_valid()

        return self.magic + self.eph_pub_key + self.ciphertext + self.mac

    @classmethod
    def parse(
        cls, data: Octets, *, magic: bytes = MAGIC, check_validity: bool = True
    ) -> Envelope:
        """Return the envelope the octets carry, at BIE1's fixed offsets.

        The magic is compared here rather than left to the caller: the
        first four bytes are what answer "is this a BIE1 envelope at all",
        and every offset below is meaningless if they do not.

        Its type is asked before that comparison, and `b64decode` is
        covered by the same question, handing this one what it was given:
        a magic of no bytes type is unequal to whatever the buffer starts
        with, so every envelope would have been refused for the bytes it
        does carry rather than for the argument that cannot be any.
        """
        assert_type(magic, bytes, "magic")

        data = bytes_from_octets(data)
        # the shortest envelope there can be: the four fixed-size fields
        # with a single block of ciphertext between them
        min_size = _MAGIC_SIZE + _EPH_PUB_KEY_SIZE + _BLOCK_SIZE + _MAC_SIZE
        if len(data) < min_size:
            raise BTClibValueError(
                f"invalid envelope size: {len(data)} bytes, not at least {min_size}"
            )
        magic_found = data[:_MAGIC_SIZE]
        if magic_found != magic:
            raise BTClibValueError(
                f"invalid magic bytes: {magic_found!r}, not {magic!r}"
            )
        eph_pub_key_end = _MAGIC_SIZE + _EPH_PUB_KEY_SIZE
        return cls(
            magic_found,
            data[_MAGIC_SIZE:eph_pub_key_end],
            data[eph_pub_key_end:-_MAC_SIZE],
            data[-_MAC_SIZE:],
            check_validity=check_validity,
        )

    def b64encode(self, *, check_validity: bool = True) -> str:
        """Return the envelope as its base64 armor."""
        return base64.b64encode(self.serialize(check_validity=check_validity)).decode(
            "ascii"
        )

    @classmethod
    def b64decode(
        cls, data: String, *, magic: bytes = MAGIC, check_validity: bool = True
    ) -> Envelope:
        """Return the envelope a base64 armor carries."""
        # b64decode discards whatever is not in the base64 alphabet, which
        # would make one envelope reachable from unboundedly many strings;
        # validate=True rejects that junk, and requiring the canonical
        # re-encoding covers what validate leaves to the interpreter --
        # see the same reasoning, at length, on bms.Sig.b64decode.
        # The coercion before the strip, as that method does it and for
        # the reason issue #814 gives: what is neither text nor bytes
        # reached `.strip` untouched and left as an AttributeError about
        # a missing method. Stripping covers bytes as well as str: the
        # whitespace around a copied and pasted envelope is the one
        # laxity worth tolerating
        text = str_from_string(data, "base64 envelope").strip()
        try:
            data_bin = text.encode("ascii")
            data_decoded = base64.b64decode(data_bin, validate=True)
        except ValueError as e:  # binascii.Error and UnicodeEncodeError
            raise BTClibValueError(f"invalid base64 encoding: {e}") from e
        if base64.b64encode(data_decoded) != data_bin:
            raise BTClibValueError("invalid base64 encoding: not canonical")
        return cls.parse(data_decoded, magic=magic, check_validity=check_validity)


def encrypt(
    msg: bytes,
    pub_key: PubKey,
    encrypt_f: CipherF,
    *,
    eph_prv_key: Integer | None = None,
    magic: bytes = MAGIC,
) -> str:
    """Encrypt a message to a public key, returning the BIE1 base64 armor.

    `encrypt_f` must be AES-128-CBC with PKCS#7 padding; the module
    docstring has the contract in full. `eph_prv_key` overrides the random
    ephemeral key, which is what makes a fixed test vector reproducible --
    reusing one across two messages to the same recipient reuses the whole
    key stream, so leave it alone outside of tests.

    The plaintext is bytes and not Octets, alone among the message
    parameters of this library: a hex string is how btclib spells binary
    everywhere else, and reading `"deadbeef"` as four bytes rather than as
    the eight characters somebody meant to hide is not a mistake the
    recipient can notice.
    """
    if eph_prv_key is None:
        # in the range [1, n-1], as everywhere else a key is generated here
        eph_prv_key = 1 + secrets.randbelow(secp256k1.n - 1)
    q = scalar_from_prv_key(eph_prv_key)

    iv, key_e, key_m = derive_keys(q, pub_key)
    ciphertext = encrypt_f(key_e, iv, msg)
    # the padding check the contract promises: PKCS#7 always grows the
    # plaintext, by a whole block when it is already aligned. A cipher
    # handed through without padding fails here rather than three
    # implementations later, and the aligned case is the one that would
    # otherwise slip past a length check that only looked at the remainder
    if len(ciphertext) <= len(msg):
        raise BTClibValueError(
            f"encrypt_f did not pad: {len(ciphertext)} bytes of ciphertext "
            f"for {len(msg)} bytes of plaintext"
        )

    eph_pub_key = bytes_from_point(mult(q), compressed=True)
    envelope = Envelope.from_ciphertext(eph_pub_key, ciphertext, key_m, magic=magic)
    return envelope.b64encode()


def decrypt(
    armor: String,
    prv_key: Integer,
    decrypt_f: CipherF,
    *,
    magic: bytes = MAGIC,
) -> bytes:
    """Decrypt a BIE1 base64 armor with the recipient private key.

    `decrypt_f` must be AES-128-CBC with PKCS#7 padding; the module
    docstring has the contract in full. It is reached only once the MAC
    has verified, so a wrong key or a tampered envelope raises
    BTClibRuntimeError and the caller's cipher never runs.
    """
    envelope = Envelope.b64decode(armor, magic=magic)
    iv, key_e, key_m = derive_keys(prv_key, envelope.eph_pub_key)
    envelope.assert_valid_mac(key_m)
    return decrypt_f(key_e, iv, envelope.ciphertext)
