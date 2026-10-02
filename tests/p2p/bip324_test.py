# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.bip324` module.

BIP324's packet vectors drive the cipher end to end, and Bitcoin Core's
`src/test/bip324_tests.cpp` is the model for what is then done to each
row: decrypting it as itself, as the wrong side, with a bit of the
ciphertext or the AAD changed, and at the wrong packet index. The rows'
`in_idx` are 1, 999, 0, 223, 448, 673 and 1024. Packets 0 and 1 come before any
rekeying and 223 is the last before the first. 448, 673, 999 and 1024 come
after two, three, four and four rekeyings, 448 being the first packet
under the third key.

The module needs `cryptography`, and a run without it skips this file.
"""

from __future__ import annotations

import contextlib
import csv
import random
import secrets
from pathlib import Path
from typing import Any

import pytest
from btclib_ecc.curves import secp256k1
from btclib_ecc.ecc import ellswift

from btclib.exceptions import BTClibTypeError, BTClibValueError
from tests import vector_id

pytest.importorskip("cryptography")

from btclib.p2p import bip324

_VECTORS = (
    Path(__file__).parent.parent / "ecc" / "_data" / "packet_encoding_test_vectors.csv"
)
# the message start the vectors' salt was made with
_MAGIC = bytes.fromhex("f9beb4d9")


def _rows() -> list[Any]:
    with _VECTORS.open(encoding="ascii", newline="") as file_:
        rows = list(csv.DictReader(file_))
    return [
        pytest.param(row, id=vector_id(i, "idx", row["in_idx"]))
        for i, row in enumerate(rows)
    ]


def _cipher(
    row: dict[str, str], *, wrong_side: bool = False, self_decrypt: bool = False
) -> bip324.Cipher:
    # the default is what the vectors hold the constructor to
    options = {"self_decrypt": True} if self_decrypt else {}
    return bip324.Cipher(
        int(row["in_priv_ours"], 16),
        bytes.fromhex(row["in_ellswift_ours"]),
        bytes.fromhex(row["in_ellswift_theirs"]),
        (row["in_initiating"] == "1") != wrong_side,
        _MAGIC,
        **options,
    )


def _contents(row: dict[str, str]) -> bytes:
    return bytes.fromhex(row["in_contents"]) * int(row["in_multiply"])


def _seek(cipher: bip324.Cipher, index: int) -> list[bytes]:
    """Encrypt `index` empty ignored packets, and return them."""
    return [cipher.encrypt(b"", ignore=True) for _ in range(index)]


@pytest.mark.parametrize("row", _rows())
def test_the_packet_vectors(row: dict[str, str]) -> None:
    """The keys, terminators and ciphertext are BIP324's, at every index."""
    cipher = _cipher(row)
    assert cipher.session_id.hex() == row["out_session_id"]
    assert cipher.send_garbage_terminator.hex() == row["mid_send_garbage_terminator"]
    assert cipher.recv_garbage_terminator.hex() == row["mid_recv_garbage_terminator"]

    _seek(cipher, int(row["in_idx"]))
    packet = cipher.encrypt(
        _contents(row), bytes.fromhex(row["in_aad"]), ignore=row["in_ignore"] == "1"
    )
    if row["out_ciphertext"]:
        assert packet.hex() == row["out_ciphertext"]
    if row["out_ciphertext_endswith"]:
        assert packet.hex().endswith(row["out_ciphertext_endswith"])


def _decrypt(
    row: dict[str, str],
    packet: bytes,
    aad: bytes,
    dummies: list[bytes],
    index: int,
    *,
    wrong_side: bool = False,
) -> tuple[bytes, bool]:
    """Decrypt `packet` as its own sender would, after `index` packets.

    The packets before it are the `dummies`, the first one again where
    `index` runs past them, as in Core's test; what they decrypt to is of
    no interest, and a wrong side fails them.
    """
    decipher = _cipher(row, wrong_side=wrong_side, self_decrypt=True)
    for i in range(index):
        dummy = dummies[i] if i < len(dummies) else dummies[0]
        decipher.decrypt_length(dummy[: bip324.LENGTH_LEN])
        with contextlib.suppress(BTClibValueError):
            decipher.decrypt(dummy[bip324.LENGTH_LEN :])
    length = decipher.decrypt_length(packet[: bip324.LENGTH_LEN])
    # resized to the length decrypted, zeros appended if it is longer
    size = bip324.HEADER_LEN + length + bip324.TAG_LEN
    body = packet[bip324.LENGTH_LEN :][:size].ljust(size, b"\x00")
    return decipher.decrypt(body, aad)


def _packet(row: dict[str, str]) -> tuple[bytes, bytes, list[bytes]]:
    """Return the vector's packet, its AAD and the packets before it."""
    aad = bytes.fromhex(row["in_aad"])
    cipher = _cipher(row)
    dummies = _seek(cipher, int(row["in_idx"]))
    packet = cipher.encrypt(_contents(row), aad, ignore=row["in_ignore"] == "1")
    return packet, aad, dummies


@pytest.mark.parametrize("row", _rows())
def test_the_packet_vectors_decrypt_as_themselves(row: dict[str, str]) -> None:
    """Each vector's packet decrypts to its contents and ignore bit."""
    packet, aad, dummies = _packet(row)

    got = _decrypt(row, packet, aad, dummies, int(row["in_idx"]))

    assert got == (_contents(row), row["in_ignore"] == "1")


@pytest.mark.parametrize("row", _rows())
def test_the_packet_vectors_refuse_what_core_damages(row: dict[str, str]) -> None:
    """The errors of Core's test: the wrong side, a bit flipped, an index."""
    index = int(row["in_idx"])
    packet, aad, dummies = _packet(row)
    rng = random.Random(index)

    with pytest.raises(BTClibValueError):
        _decrypt(row, packet, aad, dummies, index, wrong_side=True)
    for bit in range(8):
        damaged = bytearray(packet)
        damaged[rng.randrange(len(damaged))] ^= 1 << bit
        with pytest.raises(BTClibValueError):
            _decrypt(row, bytes(damaged), aad, dummies, index)
    if aad:
        damaged_aad = bytearray(aad)
        damaged_aad[rng.randrange(len(aad))] ^= 1 << rng.randrange(8)
        with pytest.raises(BTClibValueError, match="authentication failed"):
            _decrypt(row, packet, bytes(damaged_aad), dummies, index)
    with pytest.raises(BTClibValueError, match="authentication failed"):
        _decrypt(row, packet, aad + b"\x00", dummies, index)
    if index:
        with pytest.raises(BTClibValueError, match="authentication failed"):
            _decrypt(row, packet, aad, dummies, index ^ (1 << rng.randrange(16)))


def _peers() -> tuple[bip324.Cipher, bip324.Cipher]:
    """Return an initiator's cipher and its responder's, on fresh keys."""
    prv_a = secrets.randbelow(secp256k1.n - 1) + 1
    prv_b = secrets.randbelow(secp256k1.n - 1) + 1
    ell_a, ell_b = ellswift.create_var(prv_a), ellswift.create_var(prv_b)
    return (
        bip324.Cipher(prv_a, ell_a, ell_b, True, _MAGIC),
        bip324.Cipher(prv_b, ell_b, ell_a, False, _MAGIC),
    )


def _receive(
    cipher: bip324.Cipher, packet: bytes, aad: bytes = b""
) -> tuple[bytes, bool]:
    length = cipher.decrypt_length(packet[: bip324.LENGTH_LEN])
    assert len(packet) == length + bip324.EXPANSION
    return cipher.decrypt(packet[bip324.LENGTH_LEN :], aad)


def test_two_peers_agree_in_both_directions_across_rekeyings() -> None:
    """Peers share a session and decrypt each other across rekeyings."""
    initiator, responder = _peers()
    assert initiator.session_id == responder.session_id
    assert initiator.send_garbage_terminator == responder.recv_garbage_terminator
    assert initiator.recv_garbage_terminator == responder.send_garbage_terminator
    assert initiator.send_garbage_terminator != initiator.recv_garbage_terminator

    for i in range(2 * bip324.REKEY_INTERVAL + 2):
        contents = i.to_bytes(2, "big") * (i % 5)
        packet = initiator.encrypt(contents, b"aad")
        assert _receive(responder, packet, b"aad") == (contents, False)
        packet = responder.encrypt(contents, ignore=True)
        assert _receive(initiator, packet) == (contents, True)


def test_the_magic_is_part_of_the_salt() -> None:
    """Another network's message start derives another session."""
    row = _rows()[0].values[0]
    mainnet = _cipher(row)
    other = bip324.Cipher(
        int(row["in_priv_ours"], 16),
        bytes.fromhex(row["in_ellswift_ours"]),
        bytes.fromhex(row["in_ellswift_theirs"]),
        row["in_initiating"] == "1",
        bytes.fromhex("0b110907"),
    )
    assert mainnet.session_id != other.session_id


def test_a_packet_that_fails_is_counted() -> None:
    """The next packet decrypts, as in Core: a failure still counts."""
    initiator, responder = _peers()
    first, second = initiator.encrypt(b"first"), initiator.encrypt(b"second")
    damaged = first[:-1] + bytes([first[-1] ^ 1])

    with pytest.raises(BTClibValueError, match="authentication failed"):
        _receive(responder, damaged)

    assert _receive(responder, second) == (b"second", False)


@pytest.mark.parametrize(
    "header, ignore",
    [(0x00, False), (0x01, False), (0x7F, False), (0x80, True), (0xFF, True)],
)
def test_the_ignore_bit_is_the_top_bit_of_the_header(header: int, ignore: bool) -> None:
    """Core reads the one bit and not the byte: the others carry no meaning."""
    initiator, responder = _peers()
    # a header the public `encrypt` cannot make, built from the sender's AEAD
    length = initiator._send_l.crypt((1).to_bytes(bip324.LENGTH_LEN, "little"))
    packet = length + initiator._send_p.encrypt(b"", bytes([header]) + b"x")

    assert _receive(responder, packet) == (b"x", ignore)


def test_the_limits_are_refused() -> None:
    """The sizes the packet format bounds, at and past each bound."""
    initiator, _ = _peers()
    assert len(initiator.encrypt(bytes(bip324.MAX_CONTENTS_LEN))) == (
        bip324.MAX_CONTENTS_LEN + bip324.EXPANSION
    )
    with pytest.raises(BTClibValueError, match="contents too long"):
        initiator.encrypt(bytes(bip324.MAX_CONTENTS_LEN + 1))
    for size in (bip324.LENGTH_LEN - 1, bip324.LENGTH_LEN + 1):
        with pytest.raises(BTClibValueError, match="invalid length size"):
            initiator.decrypt_length(bytes(size))
    with pytest.raises(BTClibValueError, match="packet too short"):
        initiator.decrypt(bytes(bip324.HEADER_LEN + bip324.TAG_LEN - 1))
    row = _rows()[0].values[0]
    for magic in (_MAGIC[:-1], _MAGIC + b"\x00"):
        with pytest.raises(BTClibValueError, match="invalid magic size"):
            bip324.Cipher(
                int(row["in_priv_ours"], 16),
                bytes.fromhex(row["in_ellswift_ours"]),
                bytes.fromhex(row["in_ellswift_theirs"]),
                True,
                magic,
            )


@pytest.mark.parametrize("cls", [bip324.FSChaCha20, bip324.FSChaCha20Poly1305])
@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_key_is_32_bytes(cls: Any, size: int) -> None:
    """Both ciphers refuse a key of another size."""
    with pytest.raises(BTClibValueError, match="invalid key size"):
        cls(bytes(size))


def test_the_length_cipher_is_its_own_inverse_across_rekeyings() -> None:
    """Encrypting and decrypting are one call, across three rekeyings."""
    key = secrets.token_bytes(bip324.KEY_LEN)
    sender, receiver = bip324.FSChaCha20(key), bip324.FSChaCha20(key)
    for i in range(3 * bip324.REKEY_INTERVAL + 1):
        chunk = i.to_bytes(3, "little")
        assert receiver.crypt(sender.crypt(chunk)) == chunk


def test_the_message_ids_are_core_s() -> None:
    """The table's ends and its unassigned ids, as in Core."""
    assert bip324.MESSAGE_IDS[0] == ""
    assert bip324.MESSAGE_IDS[1:4] == ("addr", "block", "blocktxn")
    assert bip324.MESSAGE_IDS[28] == "addrv2"
    assert set(bip324.MESSAGE_IDS[29:]) == {""}
    named = [t for t in bip324.MESSAGE_IDS if t]
    assert len(set(named)) == len(named)


@pytest.mark.parametrize("command", [t for t in bip324.MESSAGE_IDS if t])
def test_a_short_id_message_is_one_byte_of_type(command: str) -> None:
    """A command with a short id is that id and the payload."""
    contents = bip324.contents_from_message(command, b"payload")

    assert contents == bytes([bip324.MESSAGE_IDS.index(command)]) + b"payload"
    assert bip324.message_from_contents(contents) == (command, b"payload")


@pytest.mark.parametrize(
    "command", ["", "version", "verack", "sendaddrv2", "abcdefghijkl"]
)
def test_any_other_message_is_a_nul_and_twelve_bytes(command: str) -> None:
    """A command without one is a NUL and its 12 bytes, padded."""
    contents = bip324.contents_from_message(command, b"payload")

    assert contents == b"\x00" + command.encode().ljust(12, b"\x00") + b"payload"
    assert bip324.message_from_contents(contents) == (command, b"payload")


def test_a_long_type_may_spell_a_short_id_command() -> None:
    """The long spelling of a short-id command is read as the command."""
    contents = b"\x00" + b"ping".ljust(12, b"\x00") + b"nonce"

    assert bip324.message_from_contents(contents) == ("ping", b"nonce")


@pytest.mark.parametrize("command", ["abcdefghijklm", "t\u00e9st", "a\x00b", "a\nb"])
def test_a_command_that_is_not_twelve_printable_bytes_is_refused(command: str) -> None:
    """A command too long or not printable ASCII is not written."""
    with pytest.raises(BTClibValueError):
        bip324.contents_from_message(command, b"")


@pytest.mark.parametrize(
    "contents, match",
    [
        (b"", "empty contents"),
        (b"\x21", "unknown short message id"),
        (b"\xff", "unknown short message id"),
        (b"\x00" + b"ping", "long message type too short"),
        (b"\x00" + b"pi\x00ng".ljust(12, b"\x00"), "invalid command padding"),
        (b"\x00" + b"p\x1fng".ljust(12, b"\x00"), "non-printable"),
        (b"\x00" + b"p\x80ng".ljust(12, b"\x00"), "non-printable"),
    ],
)
def test_contents_without_a_type_are_refused(contents: bytes, match: str) -> None:
    """Contents with no readable type raise `BTClibValueError`."""
    with pytest.raises(BTClibValueError, match=match):
        bip324.message_from_contents(contents)


@pytest.mark.parametrize("short_id", [29, 30, 31, 32])
def test_an_unimplemented_short_id_has_no_command(short_id: int) -> None:
    """An id BIP324 assigns and Core does not implement reads as `""`."""
    assert bip324.message_from_contents(bytes([short_id]) + b"x") == ("", b"x")


@pytest.mark.parametrize("command", ["p\x7fng", " ng", "p ng"])
def test_core_s_v2_reader_accepts_the_ends_of_its_range(command: str) -> None:
    """' ' and 0x7F are in Core's range for a long type; v1's stops at 0x7E."""
    contents = b"\x00" + command.encode().ljust(12, b"\x00") + b"x"

    assert bip324.message_from_contents(contents) == (command, b"x")


def _wrong_types() -> list[Any]:
    """Return calls with an argument of a type no signature declares."""
    key = bytes(bip324.KEY_LEN)
    cipher, _ = _peers()
    fs_length = bip324.FSChaCha20(key)
    fs_aead = bip324.FSChaCha20Poly1305(key)
    return [
        (bip324.FSChaCha20, ("a" * 32,)),
        (fs_length.crypt, ("abc",)),
        (bip324.FSChaCha20Poly1305, ("a" * 32,)),
        (fs_aead.encrypt, ("x", b"y")),
        (fs_aead.encrypt, (b"x", "y")),
        (fs_aead.decrypt, ("x", b"y")),
        (fs_aead.decrypt, (b"x", "y")),
        (cipher.encrypt, ("abc",)),
        (cipher.encrypt, (b"abc", "x")),
        (cipher.decrypt_length, ("abc",)),
        (cipher.decrypt, ("a" * 20,)),
        (cipher.decrypt, (bytes(20), "x")),
        (bip324.contents_from_message, (123, b"")),
        (bip324.contents_from_message, ("ping", "x")),
        (bip324.message_from_contents, ("abc",)),
    ]


def test_an_argument_of_the_wrong_type_is_a_btclib_error() -> None:
    """No built-in exception leaves, and no cipher's own."""
    for function, args in _wrong_types():
        with pytest.raises(BTClibTypeError, match="invalid .* type"):
            function(*args)
