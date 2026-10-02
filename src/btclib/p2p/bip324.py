# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP324's v2 transport: the key schedule, the packet cipher and the framing.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki

This module needs the `bip324` extra, `pip install "btclib[bip324]"`,
which brings in `cryptography`. Issue 1066 keeps a hand-written cipher
out of btclib, and none is written here: the ciphers are
`cryptography`'s. The rest of btclib does not import this module and
answers without the extra.

What is here is the part of the transport that is a function of bytes:

- `Cipher`, the key schedule and the encryption of a connection's
  packets, as Bitcoin Core's `BIP324Cipher`;
- `FSChaCha20` and `FSChaCha20Poly1305`, the two ciphers it holds, each
  rekeying every `REKEY_INTERVAL` packets;
- `MESSAGE_IDS`, `contents_from_message` and `message_from_contents`,
  how a message's type is spelled inside a packet.

The handshake, the garbage, the version packet and every limit are the
caller's. This module derives the garbage terminators and the session
id, and reads and writes no socket.

Decrypting fails with `BTClibValueError`, and Core closes the connection
on it. The failed packet is still counted, as in Core.

BIP324 also asks for the key material to be wiped once it is not needed,
which Python cannot do: the keys live in `cryptography`'s objects and in
immutable `bytes`.
"""

from hashlib import sha256
from typing import Any

from btclib_ecc.kdf import hkdf_expand, hkdf_extract
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher as _StreamCipher
from cryptography.hazmat.primitives.ciphers import CipherContext
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from btclib.alias import Integer, Octets
from btclib.ecc.ellswift import xdh
from btclib.exceptions import BTClibValueError
from btclib.p2p.message import _command_from_bytes
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "EXPANSION",
    "GARBAGE_TERMINATOR_LEN",
    "HEADER_LEN",
    "IGNORE_BIT",
    "KEY_LEN",
    "LENGTH_LEN",
    "MAGIC_LEN",
    "MAX_CONTENTS_LEN",
    "MESSAGE_IDS",
    "REKEY_INTERVAL",
    "SALT_PREFIX",
    "SESSION_ID_LEN",
    "TAG_LEN",
    "Cipher",
    "FSChaCha20",
    "FSChaCha20Poly1305",
    "contents_from_message",
    "message_from_contents",
]

# packets (or, for the length cipher, chunks) between two rekeyings
REKEY_INTERVAL = 224
KEY_LEN = 32
SESSION_ID_LEN = 32
GARBAGE_TERMINATOR_LEN = 16
# the encrypted length of a packet's contents, little-endian
LENGTH_LEN = 3
MAX_CONTENTS_LEN = 2 ** (8 * LENGTH_LEN) - 1
# the header is one byte, of which the top bit says "ignore this packet"
HEADER_LEN = 1
IGNORE_BIT = 0x80
# Poly1305's tag
TAG_LEN = 16
# what a packet adds to its contents: the length, the header and the tag
EXPANSION = LENGTH_LEN + HEADER_LEN + TAG_LEN
# the network's message start, which the key schedule's salt ends with
MAGIC_LEN = 4
SALT_PREFIX = b"bitcoin_v2_shared_secret"

_MESSAGE_TYPE_LEN = 12
# the bytes Core's v2 reader accepts in a long type: ' ' to 0x7F
_FIRST_TYPE_BYTE = 0x20
_LAST_TYPE_BYTE = 0x7F

# Core's V2_MESSAGE_IDS (src/net.cpp, v31.1): the type of each short id,
# "" for id 0, which announces 12 bytes of type, and for ids 29 to 32,
# which the table holds without a type
MESSAGE_IDS = (
    "",
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
    "",
    "",
    "",
    "",
)
_SHORT_ID = {t: i for i, t in enumerate(MESSAGE_IDS) if t}


def _assert_bytes(value: Any, what: str) -> None:
    """Refuse what is not `bytes`: the ciphers' own errors are not ours."""
    assert_type(value, bytes, what)


def _assert_key(key: bytes) -> bytes:
    """Return the key, refusing anything but 32 bytes."""
    _assert_bytes(key, "key")
    if len(key) != KEY_LEN:
        err_msg = f"invalid key size: {len(key)} instead of {KEY_LEN} bytes"
        raise BTClibValueError(err_msg)
    return key


class FSChaCha20:
    """The stream cipher the packet lengths go through, forward secure.

    One stream under one key is used for `REKEY_INTERVAL` calls of
    `crypt`; the next 32 bytes of it are then the new key, and the nonce
    counts the rekeyings. Encrypting and decrypting are the same call.
    """

    def __init__(self, key: bytes) -> None:
        self._key = _assert_key(key)
        self._chunks = 0
        self._rekeyings = 0
        self._stream = self._new_stream()

    def _new_stream(self) -> CipherContext:
        """Return the keystream of the current key, from its block 0.

        `cryptography` takes ChaCha20's 16 bytes of counter and nonce as
        one: the block counter in little-endian, then 4 zero bytes, then
        the rekeying count in little-endian.
        """
        counter_and_nonce = bytes(8) + self._rekeyings.to_bytes(8, "little")
        return _StreamCipher(ChaCha20(self._key, counter_and_nonce), None).encryptor()

    def crypt(self, chunk: bytes) -> bytes:
        """Return the chunk XORed with the next bytes of the keystream."""
        _assert_bytes(chunk, "chunk")
        out = self._stream.update(chunk)
        self._chunks += 1
        if self._chunks == REKEY_INTERVAL:
            # XOR with zeros reads the keystream out
            self._key = self._stream.update(bytes(KEY_LEN))
            self._rekeyings += 1
            self._chunks = 0
            self._stream = self._new_stream()
        return out


class FSChaCha20Poly1305:
    """The AEAD the packets go through, forward secure.

    The nonce is the packet count under the current key, 4 bytes, then
    the rekeying count, 8 bytes, both little-endian. After
    `REKEY_INTERVAL` packets the key becomes the first 32 bytes of the
    encryption of 32 zero bytes under the nonce whose count is
    `0xffffffff`.
    """

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(_assert_key(key))
        self._packets = 0
        self._rekeyings = 0

    def _nonce(self, packets: int) -> bytes:
        return packets.to_bytes(4, "little") + self._rekeyings.to_bytes(8, "little")

    def _advance(self) -> None:
        self._packets += 1
        if self._packets == REKEY_INTERVAL:
            nonce = self._nonce(0xFFFFFFFF)
            key = self._aead.encrypt(nonce, bytes(KEY_LEN), b"")[:KEY_LEN]
            self._aead = ChaCha20Poly1305(key)
            self._packets = 0
            self._rekeyings += 1

    def encrypt(self, aad: bytes, plaintext: bytes) -> bytes:
        """Return the ciphertext and the tag."""
        _assert_bytes(aad, "aad")
        _assert_bytes(plaintext, "plaintext")
        out = self._aead.encrypt(self._nonce(self._packets), plaintext, aad)
        self._advance()
        return out

    def decrypt(self, aad: bytes, ciphertext: bytes) -> bytes:
        """Return the plaintext, or raise `BTClibValueError` if the tag fails.

        The packet is counted either way.
        """
        _assert_bytes(aad, "aad")
        _assert_bytes(ciphertext, "ciphertext")
        try:
            out = self._aead.decrypt(self._nonce(self._packets), ciphertext, aad)
        except InvalidTag:
            out = None
        self._advance()
        if out is None:
            raise BTClibValueError("authentication failed")
        return out


class Cipher:
    """The encryption of one connection's packets, in both directions.

    The shared secret is `ellswift.xdh`'s over our private key and the
    two encodings, and the keys, the garbage terminators and the session
    id are HKDF-SHA256 of it, salted with `SALT_PREFIX` and the network's
    message start `magic`. `initiator` is whether we opened the
    connection.

    `self_decrypt` swaps the two directions' keys, so that a second
    `Cipher` built with it decrypts what this one encrypts. Core's tests
    use it to read our packets without the peer's private key.

    `session_id`, `send_garbage_terminator` and `recv_garbage_terminator`
    are the attributes the handshake reads.
    """

    def __init__(
        self,
        prv_key: Integer,
        ell_ours: Octets,
        ell_theirs: Octets,
        initiator: bool,
        magic: Octets,
        *,
        self_decrypt: bool = False,
    ) -> None:
        assert_type(initiator, bool, "initiator")
        assert_type(self_decrypt, bool, "self_decrypt")
        magic = bytes_from_octets(magic)
        if len(magic) != MAGIC_LEN:
            err_msg = f"invalid magic size: {len(magic)} instead of {MAGIC_LEN} bytes"
            raise BTClibValueError(err_msg)
        if initiator:
            secret = xdh(ell_ours, ell_theirs, prv_key, 0)
        else:
            secret = xdh(ell_theirs, ell_ours, prv_key, 1)

        prk = hkdf_extract(secret, SALT_PREFIX + magic, sha256)

        def expand(label: bytes, size: int = KEY_LEN) -> bytes:
            return hkdf_expand(prk, size, sha256, label)

        initiator_l = FSChaCha20(expand(b"initiator_L"))
        initiator_p = FSChaCha20Poly1305(expand(b"initiator_P"))
        responder_l = FSChaCha20(expand(b"responder_L"))
        responder_p = FSChaCha20Poly1305(expand(b"responder_P"))
        # ours is the initiator's half when we initiate, or when we
        # decrypt our own packets as the peer would
        if initiator != self_decrypt:
            self._send_l, self._send_p = initiator_l, initiator_p
            self._recv_l, self._recv_p = responder_l, responder_p
        else:
            self._send_l, self._send_p = responder_l, responder_p
            self._recv_l, self._recv_p = initiator_l, initiator_p

        terminators = expand(b"garbage_terminators", 2 * GARBAGE_TERMINATOR_LEN)
        first, second = (
            terminators[:GARBAGE_TERMINATOR_LEN],
            terminators[GARBAGE_TERMINATOR_LEN:],
        )
        self.send_garbage_terminator = first if initiator else second
        self.recv_garbage_terminator = second if initiator else first
        self.session_id = expand(b"session_id", SESSION_ID_LEN)

    def encrypt(
        self, contents: bytes, aad: bytes = b"", *, ignore: bool = False
    ) -> bytes:
        """Return the packet: its encrypted length, then the AEAD of the rest.

        `aad` is authenticated with the packet and not sent. A packet with
        `ignore` set is to be dropped by the receiver, which is how the
        decoy packets are sent.
        """
        assert_type(ignore, bool, "ignore")
        _assert_bytes(contents, "contents")
        _assert_bytes(aad, "aad")
        if len(contents) > MAX_CONTENTS_LEN:
            err_msg = f"contents too long: {len(contents)} bytes"
            err_msg += f" instead of at most {MAX_CONTENTS_LEN}"
            raise BTClibValueError(err_msg)
        header = bytes([IGNORE_BIT if ignore else 0])
        length = self._send_l.crypt(len(contents).to_bytes(LENGTH_LEN, "little"))
        return length + self._send_p.encrypt(aad, header + contents)

    def decrypt_length(self, encrypted_length: bytes) -> int:
        """Return the length of the contents of the packet that starts so.

        The packet's remaining `HEADER_LEN` plus this plus `TAG_LEN` bytes
        are then what `decrypt` takes. It is called once per packet.
        """
        _assert_bytes(encrypted_length, "encrypted_length")
        if len(encrypted_length) != LENGTH_LEN:
            err_msg = f"invalid length size: {len(encrypted_length)} instead of {LENGTH_LEN} bytes"
            raise BTClibValueError(err_msg)
        return int.from_bytes(self._recv_l.crypt(encrypted_length), "little")

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> tuple[bytes, bool]:
        """Return the contents and whether the packet is to be ignored.

        `ciphertext` is the packet after its length. The `BTClibValueError`
        of a failed tag is the end of the connection.
        """
        _assert_bytes(ciphertext, "ciphertext")
        _assert_bytes(aad, "aad")
        if len(ciphertext) < HEADER_LEN + TAG_LEN:
            err_msg = f"packet too short: {len(ciphertext)} bytes"
            raise BTClibValueError(err_msg)
        plaintext = self._recv_p.decrypt(aad, ciphertext)
        return plaintext[HEADER_LEN:], bool(plaintext[0] & IGNORE_BIT)


def contents_from_message(command: str, payload: bytes) -> bytes:
    """Return a packet's contents: the type, then the payload.

    The type is the 1-byte short id when `MESSAGE_IDS` has one, and
    otherwise a NUL and the command padded with NULs to 12 bytes. A
    command with a 0x7F byte is refused on send, as Core's v1 check
    refuses it.
    """
    assert_type(command, str, "command")
    _assert_bytes(payload, "payload")
    short_id = _SHORT_ID.get(command)
    if short_id is not None:
        return bytes([short_id]) + payload
    octets = command.encode("utf-8")
    if len(octets) > _MESSAGE_TYPE_LEN:
        err_msg = f"invalid command: {len(octets)} bytes"
        raise BTClibValueError(err_msg)
    padded = octets.ljust(_MESSAGE_TYPE_LEN, b"\x00")
    _command_from_bytes(padded)
    return b"\x00" + padded + payload


def message_from_contents(contents: bytes) -> tuple[str, bytes]:
    """Return the command and the payload of a packet's contents.

    The command is "" for a short id in the table without a type, as in
    Core, whose caller has no handler for it.
    Contents without a type, a short id beyond the table and a long type
    that is not ' ' to 0x7F padded with NULs raise `BTClibValueError`.
    Core's v2 reader accepts 0x7F, which its v1 header check does not,
    and so does this on receive. Such a raise is a message Core
    rejects: the caller drops the message, and the connection is not
    ended by it.
    """
    _assert_bytes(contents, "contents")
    if not contents:
        raise BTClibValueError("empty contents")
    first, rest = contents[0], contents[1:]
    if first:
        if first >= len(MESSAGE_IDS):
            err_msg = f"unknown short message id: {first}"
            raise BTClibValueError(err_msg)
        return MESSAGE_IDS[first], rest
    if len(rest) < _MESSAGE_TYPE_LEN:
        err_msg = f"long message type too short: {len(rest)} bytes"
        raise BTClibValueError(err_msg)
    field = rest[:_MESSAGE_TYPE_LEN]
    padding_at = field.find(b"\x00")
    if padding_at < 0:
        padding_at = _MESSAGE_TYPE_LEN
    command, padding = field[:padding_at], field[padding_at:]
    if padding.strip(b"\x00"):
        err_msg = f"invalid command padding: {field.hex()}"
        raise BTClibValueError(err_msg)
    if any(o < _FIRST_TYPE_BYTE or o > _LAST_TYPE_BYTE for o in command):
        err_msg = f"non-printable command: {field.hex()}"
        raise BTClibValueError(err_msg)
    return command.decode("ascii"), rest[_MESSAGE_TYPE_LEN:]
