# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Message dataclass; the class docstring has the contract.

The layout is Bitcoin Core's `CMessageHeader`, of src/protocol.h: four
octets of message start, twelve of message type, four of payload size
little-endian and four of checksum, followed by the payload the last two
describe. Core's own test framework writes the same header by hand, in
`test/functional/test_framework/p2p.py`.

"command" is what the wire documentation, the BIPs and every other
implementation call the second field; Core renamed its own spelling to
`m_msg_type` and kept the field where it was. The name here is the one a
reader of the protocol meets.
"""

from __future__ import annotations

from dataclasses import dataclass

from btclib.alias import BinaryData, Octets, String
from btclib.exceptions import BTClibValueError, IncompleteMessageError
from btclib.hashes import hash256
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    str_from_string,
)

__all__ = [
    "Message",
]

# CMessageHeader's four fields, in the order it serializes them. The first
# is a MessageStartChars, which is Core's own alias for four octets
_MAGIC_SIZE = 4
_COMMAND_SIZE = 12
_LENGTH_SIZE = 4
_CHECKSUM_SIZE = 4
_HEADER_SIZE = _MAGIC_SIZE + _COMMAND_SIZE + _LENGTH_SIZE + _CHECKSUM_SIZE

# where the last two start in it, which is what reading the header whole
# costs over reading it field by field: Core writes the same two as
# MESSAGE_SIZE_OFFSET and CHECKSUM_OFFSET
_LENGTH_AT = _MAGIC_SIZE + _COMMAND_SIZE
_CHECKSUM_AT = _LENGTH_AT + _LENGTH_SIZE

# the printable ascii range Core's IsMessageTypeValid accepts, ' ' to '~'
_FIRST_PRINTABLE = 0x20
_LAST_PRINTABLE = 0x7E


def _command_from_bytes(octets: bytes) -> str:
    """Return the command the twelve octets spell, refusing what none does.

    Core's `CMessageHeader::IsMessageTypeValid`, of src/protocol.cpp:
    every octet before the first NUL is printable ascii, ' ' to '~', and
    every octet from the first NUL on is NUL.

    The padding rule is what makes the encoding one-to-one, and it is
    `assert_no_trailing`'s argument one field down: without it "ping" and
    "ping" with anything at all after its NUL both read as the one
    command, and only one of them serializes back, so a peer could send
    the same message in as many spellings as the padding has octets.

    A command of no octets at all is accepted, `IsMessageTypeValid`
    accepting an all-NUL field: refusing it here would be btclib holding a
    rule Core does not have, and what answers such a message is the
    absence of a handler for it rather than a parse failure.
    """
    padding_at = octets.find(b"\x00")
    if padding_at < 0:
        padding_at = len(octets)
    command, padding = octets[:padding_at], octets[padding_at:]
    if padding.strip(b"\x00"):
        err_msg = f"invalid command padding: {octets.hex()}"
        raise BTClibValueError(err_msg)
    if any(o < _FIRST_PRINTABLE or o > _LAST_PRINTABLE for o in command):
        err_msg = f"non-printable character in command: {octets.hex()}"
        raise BTClibValueError(err_msg)
    return command.decode("ascii")


@dataclass(frozen=True)
class Message:
    """One p2p message: which network it is for, what it is, and its payload.

    The header has four fields and this has three, because two of them
    are not the object's to hold. The checksum is the first
    `_CHECKSUM_SIZE` octets of `hash256(payload)` and is a property, so
    that no instance can carry one disagreeing with the payload beside
    it; the payload length is `len(payload)` for the same reason. What is
    left is what the payload does not determine.

    `magic` is four octets and is looked up nowhere: an unfamiliar one
    round-trips, a custom signet's being derived from its challenge
    rather than tabulated -- `btclib.p2p.magic` is where a caller gets
    one and where that decision is argued.

    It is a field of the message and not something a connection puts in
    front of it, which is where this departs from btclib_node: there
    `messages.add_headers` writes the other three fields and
    `p2p.connection.Connection._send` prepends the magic, so what the
    codec serializes is not a message and is not what its own
    `verify_headers` reads back -- that one indexes the length at 16,
    which is where it sits once the magic is there. One header across two
    layers is also the one shape unavailable to a package that holds no
    connection.

    `command` is the message type as text, "version" or "verack", without
    the NUL padding the wire puts after it, and an unknown one round-trips
    as opaque bytes do: this class is the envelope, and it knows no
    payload type (issue #1083).

    Text and not the twelve octets verbatim, which is the choice a
    round-trip is usually the argument against: strip the padding and two
    wire values decode to one object, which is the malleability
    `assert_no_trailing` is spent on one field down. What answers it is
    not keeping the octets but refusing the ones Core refuses --
    `_command_from_bytes` is `IsMessageTypeValid` -- so the twelve octets
    and the text are one to one in both directions, and every value this
    accepts serializes back to the value it was read from. Keeping the
    field verbatim would do the opposite of what it looks like: it would
    round-trip a "ping" with a stray octet after its NUL faithfully, and
    that is a header Core drops the sender for, so btclib would be
    reading and re-emitting a message no peer accepts. It would also put
    the padding in every caller's hands, where `String` and
    `str_from_string` are what the rest of this library uses for a field
    that is ascii text.

    Frozen, all three fields being immutable: a message is a value, and
    `dataclasses.replace` is what retargets one at another network.

    No `to_dict` and no `from_dict`, where the other wire-format classes
    of this library have both: those agree with a json shape somebody else
    writes too -- Core's rpc for a transaction, BIP174's for a psbt -- and
    nothing renders a p2p envelope as json, so the pair would be inventing
    a shape rather than reading one, over a payload that is opaque octets
    either way.
    """

    magic: bytes
    command: str
    payload: bytes

    def __init__(
        self,
        magic: Octets,
        command: String,
        payload: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "magic", bytes_from_octets(magic))
        object.__setattr__(self, "command", str_from_string(command, "message command"))
        object.__setattr__(self, "payload", bytes_from_octets(payload))

        if check_validity:
            self.assert_valid()

    @property
    def checksum(self) -> bytes:
        """Return the four octets the header carries: hash256(payload)[:4].

        Bitcoin Core's `V1Transport::GetMessageHash`. It is what the
        payload says it is, so it is derived here and never stored;
        `parse` is the one place the two can disagree, and it refuses the
        octets rather than building the disagreement.
        """
        return hash256(self.payload)[:_CHECKSUM_SIZE]

    def assert_valid(self) -> None:
        """Refuse a magic, a command or a payload no message carries.

        The payload bound is `MAX_PROTOCOL_MESSAGE_LENGTH`: a message
        above it is one no peer accepts, so serializing one would be
        writing octets with nowhere to go. `parse` refuses the same bound
        and it is not the same check -- there it is read off the length
        field before the payload is allocated, and it cannot be turned
        off.
        """
        if len(self.magic) != _MAGIC_SIZE:
            err_msg = f"invalid magic: {len(self.magic)}"
            err_msg += f" instead of {_MAGIC_SIZE} bytes"
            raise BTClibValueError(err_msg)

        if len(self.command) > _COMMAND_SIZE:
            err_msg = f"invalid command: {len(self.command)}"
            err_msg += f" characters instead of at most {_COMMAND_SIZE}"
            raise BTClibValueError(err_msg)
        # the same range _command_from_bytes reads, asked of the text: a
        # character outside printable ascii is one no header can spell,
        # NUL included -- it is the padding, and a command holding one
        # would serialize into something parse reads as a shorter command
        if any(
            ord(c) < _FIRST_PRINTABLE or ord(c) > _LAST_PRINTABLE for c in self.command
        ):
            err_msg = f"non-printable character in command: {self.command!r}"
            raise BTClibValueError(err_msg)

        if len(self.payload) > MAX_PROTOCOL_MESSAGE_LENGTH:
            err_msg = f"invalid payload length: {len(self.payload)}"
            err_msg += f" instead of at most {MAX_PROTOCOL_MESSAGE_LENGTH} bytes"
            raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the wire serialization: the header, then the payload."""
        if check_validity:
            self.assert_valid()

        out = self.magic
        out += self.command.encode("ascii").ljust(_COMMAND_SIZE, b"\x00")
        out += len(self.payload).to_bytes(
            _LENGTH_SIZE, byteorder="little", signed=False
        )
        out += self.checksum
        out += self.payload
        return out

    @classmethod
    def parse(
        cls: type[Message], data: BinaryData, *, check_validity: bool = True
    ) -> Message:
        """Return one message, telling "not all there yet" from "never".

        A `BytesIO` is the caller's stream and may hold part of the next
        message, or several whole ones: what is consumed is this message,
        and the stream is left on the octet after it, which is how a
        caller reading off a socket takes them one at a time -- the
        position being what says how much was consumed. Octets are one
        whole object and what follows the message in them is refused, as
        everywhere in this library; `btclib.utils` states both halves.

        **Octets that end inside the message raise
        `IncompleteMessageError`, and the stream is rewound to where the
        message started.** It is the one refusal here that more octets
        can answer, so the caller reads `missing` more, appends them and
        calls again on a stream still positioned at the start. Every
        other refusal is final and none of them rewinds: a peer whose
        header does not decode is a peer Core disconnects rather than
        resynchronizes with, and what to do about it is the caller's
        policy, not this package's.

        The header is read as one unit rather than field by field, which
        is Bitcoin Core's own split -- `V1Transport` has a header phase
        and a body phase -- and is what makes `missing` exact: the
        octets still wanted are the rest of the header, and once the
        header is in hand, the rest of the payload. A field-by-field
        read can only report what the field it stopped in was short of,
        which is not a number the caller can ask its socket for.

        The payload length is compared with `MAX_PROTOCOL_MESSAGE_LENGTH`
        before the payload is asked for: the field is the peer's to
        choose, and the whole of what the bound is for is that nothing
        allocates on it first. That check does not answer to
        `check_validity` -- a defence a caller can turn off is not one --
        and neither does the checksum, which is what tells this payload
        from the octets a link corrupted: skipped, two buffers would
        decode to the one object that serializes back to only one of
        them.

        The magic is read and not checked, no argument here naming the
        network expected. A caller that means to refuse another chain's
        message compares `message.magic` with what it expects, which is
        the one line an optional `magic=None` here would replace with a
        defence that is off unless asked for; and a magic no table holds
        is a custom signet's, which must round-trip rather than be
        refused.
        """
        stream = bytesio_from_binarydata(data)
        start = stream.tell()

        header = stream.read(_HEADER_SIZE)
        if len(header) < _HEADER_SIZE:
            stream.seek(start)
            err_msg = "incomplete message header"
            raise IncompleteMessageError(err_msg, _HEADER_SIZE - len(header))

        magic = header[:_MAGIC_SIZE]
        command = _command_from_bytes(header[_MAGIC_SIZE : _MAGIC_SIZE + _COMMAND_SIZE])
        length = int.from_bytes(
            header[_LENGTH_AT : _LENGTH_AT + _LENGTH_SIZE],
            byteorder="little",
            signed=False,
        )
        if length > MAX_PROTOCOL_MESSAGE_LENGTH:
            err_msg = f"invalid payload length: {length}"
            err_msg += f" instead of at most {MAX_PROTOCOL_MESSAGE_LENGTH} bytes"
            raise BTClibValueError(err_msg)
        checksum = header[_CHECKSUM_AT:]

        payload = stream.read(length)
        if len(payload) < length:
            stream.seek(start)
            err_msg = "incomplete message payload"
            raise IncompleteMessageError(err_msg, length - len(payload))

        expected = hash256(payload)[:_CHECKSUM_SIZE]
        if checksum != expected:
            err_msg = f"invalid checksum: {checksum.hex()}"
            err_msg += f" instead of {expected.hex()}"
            raise BTClibValueError(err_msg)
        assert_no_trailing(data, stream, "p2p message")

        return cls(magic, command, payload, check_validity=check_validity)
