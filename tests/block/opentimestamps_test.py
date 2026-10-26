# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""OpenTimestamps proofs replayed against btclib's block headers.

The proofs are the Bitcoin-attested examples of opentimestamps-client's
`examples/`, and `incomplete.txt.ots`, kept under their upstream names in
`tests/block/_data/opentimestamps/`, with upstream's licence beside them.
The headers of the blocks they attest are in
`tests/block/_data/opentimestamps_headers.json`.
`tests/_data/README.md` records both.

A proof starts from a file's digest and applies hash, append and
prepend operations to it. A Bitcoin attestation names a block height,
and the message it is reached with must be the merkle root of that
block's header, in the byte order the header serializes it in. Each
header is checked against the hash recorded for its height and for its
proof of work.

The reader below follows python-opentimestamps' `opentimestamps/core`,
which defines the format. It reads the operations the vendored proofs
use and refuses any other. keccak256 is read and not computed: it leads
only to an Ethereum attestation, and the attestations under it are
reported without a message, which no merkle root equals.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from btclib.block import BlockHeader
from btclib.hashes import ripemd160, sha256
from tests import load, load_bin

_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
_MAJOR_VERSION = 1
# the file hash operations of the vendored proofs, by tag, and their size
_DIGEST_SIZE = {0x02: 20, 0x08: 32}

_ATTESTATION = 0x00
_FORK = 0xFF
_APPEND = 0xF0
_PREPEND = 0xF1
_KECCAK256 = 0x67
_OPS: dict[int, Callable[[bytes, bytes], bytes]] = {
    0x03: lambda msg, _: ripemd160(msg),
    0x08: lambda msg, _: sha256(msg),
    _APPEND: lambda msg, arg: msg + arg,
    _PREPEND: lambda msg, arg: arg + msg,
}

_BITCOIN = bytes.fromhex("0588960d73d71901")
_PENDING = bytes.fromhex("83dfe30d2ef90c8e")

_HEADERS: dict[str, dict[str, str]] = load(
    "block", "_data", "opentimestamps_headers.json"
)

# each Bitcoin-attested proof, and the height it attests
_ATTESTED = {
    "a-or-b.ots": 466906,
    "bitcoin.pdf.ots": 465751,
    "different-blockchains.txt.ots": 455605,
    "empty.ots": 129405,
    "gdp2q25-2nd.pdf.ots": 912095,
    "hello-world.txt.ots": 358391,
}


def _proof(name: str) -> bytes:
    return load_bin("block", "_data", "opentimestamps", name)


class _Reader:
    """The bytes of a proof, read front to back."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, size: int) -> bytes:
        if self._pos + size > len(self._data):
            raise ValueError("truncated proof")
        self._pos += size
        return self._data[self._pos - size : self._pos]

    def byte(self) -> int:
        return self.take(1)[0]

    def varuint(self) -> int:
        value = shift = 0
        while (byte := self.byte()) & 0x80:
            value |= (byte & 0x7F) << shift
            shift += 7
        return value | byte << shift

    def varbytes(self) -> bytes:
        return self.take(self.varuint())

    def at_end(self) -> bool:
        return self._pos == len(self._data)


def _apply(tag: int, msg: bytes | None, reader: _Reader) -> bytes | None:
    """Return the message the operation `tag` makes of `msg`."""
    if tag != _KECCAK256 and tag not in _OPS:
        raise ValueError(f"unknown operation: {tag:#04x}")
    arg = reader.varbytes() if tag in (_APPEND, _PREPEND) else b""
    if msg is None or tag == _KECCAK256:
        return None
    return _OPS[tag](msg, arg)


def _attestations(proof: bytes) -> list[tuple[bytes, bytes, bytes | None]]:
    """Return the tag, payload and message of each attestation of `proof`."""
    reader = _Reader(proof)
    if reader.take(len(_MAGIC)) != _MAGIC:
        raise ValueError("not an OpenTimestamps proof")
    if reader.byte() != _MAJOR_VERSION:
        raise ValueError("unknown major version")
    file_hash = reader.byte()
    if file_hash not in _DIGEST_SIZE:
        raise ValueError(f"unknown file hash: {file_hash:#04x}")

    found = []
    # the messages whose operations are still to be read, depth first:
    # a fork mark puts the message back, for the operation after it
    stack: list[bytes | None] = [reader.take(_DIGEST_SIZE[file_hash])]
    while stack:
        msg = stack.pop()
        tag = reader.byte()
        if tag == _FORK:
            stack.append(msg)
            tag = reader.byte()
        if tag == _ATTESTATION:
            found.append((reader.take(len(_BITCOIN)), reader.varbytes(), msg))
        else:
            stack.append(_apply(tag, msg, reader))
    if not reader.at_end():
        raise ValueError("trailing bytes")
    return found


def _verify(proof: bytes, headers: dict[str, dict[str, str]]) -> list[int]:
    """Return the heights `proof` is attested at, each checked.

    A proof whose operations cannot be read, or whose Bitcoin
    attestation is not answered by the header at its height, raises
    ValueError.
    """
    heights = []
    for tag, payload, msg in _attestations(proof):
        if tag != _BITCOIN:
            continue
        height = _Reader(payload).varuint()
        if str(height) not in headers:
            raise ValueError(f"no header at height {height}")
        entry = headers[str(height)]
        header = BlockHeader.parse(bytes.fromhex(entry["header"]))
        if header.hash.hex() != entry["hash"]:
            raise ValueError(f"not the block at height {height}")
        header.assert_valid_pow()
        if msg != header.merkle_root[::-1]:
            raise ValueError(f"not the merkle root at height {height}")
        heights.append(height)
    return heights


def _refused(proof: bytes, headers: dict[str, dict[str, str]]) -> bool:
    try:
        return not _verify(proof, headers)
    except ValueError:
        return True


def _flipped(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


@pytest.mark.parametrize("name, height", _ATTESTED.items())
def test_a_proof_commits_to_the_merkle_root_of_its_block(
    name: str, height: int
) -> None:
    """Every Bitcoin-attested example is answered by its block's header."""
    assert _verify(_proof(name), _HEADERS) == [height]


def test_bad_stamp_is_refused() -> None:
    """bad-stamp.txt.ots misses the merkle root of the block it names."""
    with pytest.raises(ValueError, match="not the merkle root at height 358391"):
        _verify(_proof("bad-stamp.txt.ots"), _HEADERS)


def test_incomplete_is_pending() -> None:
    """incomplete.txt.ots has no Bitcoin attestation, only a calendar's."""
    proof = _proof("incomplete.txt.ots")
    assert _verify(proof, _HEADERS) == []
    uris = [
        _Reader(payload).varbytes().decode()
        for tag, payload, _ in _attestations(proof)
        if tag == _PENDING
    ]
    assert uris == ["https://alice.btc.calendar.opentimestamps.org"]


# The byte positions where a changed byte encodes the same computation.
# a-or-b.ots and different-blockchains.txt.ots are left out: they carry
# other attestations too, and a byte that leads only to one of those is
# not read by the Bitcoin check.
_SAME_COMPUTATION = {
    "bitcoin.pdf.ots": [1661],
    "empty.ots": [],
    "gdp2q25-2nd.pdf.ots": [],
    "hello-world.txt.ots": [603],
}


@pytest.mark.parametrize("name, same", _SAME_COMPUTATION.items())
def test_one_changed_byte_of_a_proof_is_refused(name: str, same: list[int]) -> None:
    """Each byte of the proof, changed in turn, makes it fail.

    The exceptions are the bytes `_SAME_COMPUTATION` lists.
    """
    proof = _proof(name)
    kept = [i for i in range(len(proof)) if not _refused(_flipped(proof, i), _HEADERS)]
    assert kept == same
    for i in same:
        assert proof[i] == _APPEND
        assert _attestations(_flipped(proof, i)) == _attestations(proof)


@pytest.mark.parametrize("name, height", _ATTESTED.items())
def test_one_changed_byte_of_a_header_is_refused(name: str, height: int) -> None:
    """Each byte of the header, changed in turn, makes the proof fail."""
    proof = _proof(name)
    entry = _HEADERS[str(height)]
    header = bytes.fromhex(entry["header"])

    def changed(i: int) -> dict[str, dict[str, str]]:
        return {**_HEADERS, str(height): {**entry, "header": _flipped(header, i).hex()}}

    kept = [i for i in range(len(header)) if not _refused(proof, changed(i))]
    assert kept == []


# A header with valid proof of work on the real genesis at nBits 1d00ffff
# that is not block 1, built to check opentimestamps/opentimestamps-client#164
_NOT_BLOCK_1 = bytes.fromhex(
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
    "bb4cf72d2a4d02fa1a292d1243895bda6551bac7f836a5bdf11e70fa2ec8e44a"
    "b0bd6649ffff001d68311c21"
)


def _stamped_at_1(header: BlockHeader) -> bytes:
    """Return a proof whose digest is `header`'s merkle root, at height 1."""
    return (
        _MAGIC
        + bytes([_MAJOR_VERSION, 0x08])
        + header.merkle_root[::-1]
        + bytes([_ATTESTATION])
        + _BITCOIN
        + bytes([1, 1])
    )


def test_a_header_with_valid_proof_of_work_off_the_chain_is_refused() -> None:
    """The recorded hash, not proof of work, binds the header to its height."""
    header = BlockHeader.parse(_NOT_BLOCK_1)
    header.assert_valid_pow()
    proof = _stamped_at_1(header)
    own_hash = {"1": {"hash": header.hash.hex(), "header": _NOT_BLOCK_1.hex()}}
    assert _verify(proof, own_hash) == [1]

    block_1 = BlockHeader.parse(load_bin("block", "_data", "block_1.bin")[:80])
    on_chain = {"1": {"hash": block_1.hash.hex(), "header": _NOT_BLOCK_1.hex()}}
    with pytest.raises(ValueError, match="not the block at height 1"):
        _verify(proof, on_chain)


def test_a_header_recorded_under_its_own_hash_needs_proof_of_work() -> None:
    """The recorded hash does not stand in for the proof of work."""
    # the last byte of the nonce, changed, takes the hash above the target
    no_work = _flipped(_NOT_BLOCK_1, 79)
    header = BlockHeader.parse(no_work)
    own_hash = {"1": {"hash": header.hash.hex(), "header": no_work.hex()}}
    with pytest.raises(ValueError, match="invalid proof-of-work"):
        _verify(_stamped_at_1(header), own_hash)


def test_a_proof_cut_short_or_running_on_is_refused() -> None:
    """A proof is read to its last byte and no further."""
    proof = _proof("hello-world.txt.ots")
    with pytest.raises(ValueError, match="truncated proof"):
        _verify(proof[:-1], _HEADERS)
    with pytest.raises(ValueError, match="trailing bytes"):
        _verify(proof + b"\x00", _HEADERS)
