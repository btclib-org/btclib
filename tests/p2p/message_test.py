# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.message` module.

**The authority here is weaker than a vendored vector set, and this is
where that is said.** Bitcoin Core publishes no file of envelope vectors:
there is no `message.json` to pin the way `tests/_data/README.md` pins
`siphash.json` and `blockfilters.json`, the header being exercised in
Core through `test/functional/test_framework/p2p.py`, which builds it in
Python and reads it back -- a round trip, which is what these tests are
too. So nothing here is vendored, and nothing is claimed to be.

What stands in for it are the two messages the Bitcoin Wiki's Protocol
documentation publishes with their octets -- a `version` a
`/Satoshi:0.7.2/` node sent on mainnet and the `verack` beside it --
cited by revision:
https://en.bitcoin.it/w/index.php?title=Protocol_documentation&oldid=68832

That citation is weaker than the pins in `tests/_data/README.md` in two
ways worth stating rather than glossing. It names a wiki revision and not
a commit in a repository anybody can clone, and the page could not be
re-read from the environment these tests were written in -- an
interstitial stands in front of it -- so the octets below were not
compared against it byte for byte the way a vendored file is.

What makes them evidence all the same is that they authenticate
themselves. The checksum each header carries is recomputed here from the
payload beside it, so a mistranscription of either half fails; and the
payload decodes as the `version` body its own fields describe, protocol
60002 with the user agent and the block height the page annotates. A
vendored file would add somebody else's opinion of the same octets, which
for this header nobody has published.

The layout is checked against Core's `CMessageHeader` by reading, and the
refusals against `IsMessageTypeValid` and `MAX_PROTOCOL_MESSAGE_LENGTH`
the same way.
"""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from io import BytesIO

import pytest

from btclib.exceptions import (
    BTClibException,
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    IncompleteMessageError,
)
from btclib.p2p import Message, magic_from_chain
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH

# The Bitcoin Wiki's Protocol documentation, "version" section: a message
# a Satoshi:0.7.2 node sent on mainnet, hex dumped there with the fields
# annotated. Split at the field boundaries it annotates.
_VERSION_PAYLOAD = bytes.fromhex(
    "62ea0000"  # protocol version 60002
    "0100000000000000"  # services: NODE_NETWORK
    "11b2d05000000000"  # timestamp
    "010000000000000000000000000000000000ffff000000000000"  # addr_recv
    "010000000000000000000000000000000000ffff000000000000"  # addr_from
    "3b2eb35d8ce61765"  # nonce
    "0f2f5361746f7368693a302e372e322f"  # user agent "/Satoshi:0.7.2/"
    "c03e0300"  # start height 212672
)
_VERSION = (
    bytes.fromhex(
        "f9beb4d9"  # mainnet
        "76657273696f6e0000000000"  # "version", NUL padded to twelve
        "64000000"  # payload length, 100 little-endian
        "3b648d5a"  # checksum
    )
    + _VERSION_PAYLOAD
)

# the same page's "verack" section: the whole message is the header, the
# checksum being that of the empty payload
_VERACK = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")

_MAINNET = bytes.fromhex("f9beb4d9")
_HEADER_SIZE = 24


def test_captured_version_message() -> None:
    """Parse the captured `version`, field by field, and write it back."""
    message = Message.parse(_VERSION)
    assert message.magic == _MAINNET
    assert message.command == "version"
    assert message.payload == _VERSION_PAYLOAD
    # the length and the checksum the header carries are not fields: the
    # payload is what says what they are, and this is what they say
    assert len(message.payload) == 100
    assert message.checksum == bytes.fromhex("3b648d5a")
    assert message.serialize() == _VERSION

    # the magic is mainnet's, which is where a caller gets one
    assert message.magic == magic_from_chain("main")


def test_captured_verack_message() -> None:
    """Parse the captured `verack`: a header, and no payload at all."""
    message = Message.parse(_VERACK)
    assert message.command == "verack"
    assert message.payload == b""
    assert message.checksum == bytes.fromhex("5df6e0e2")
    assert message.serialize() == _VERACK
    assert Message(_MAINNET, "verack").serialize() == _VERACK


def test_unknown_command_round_trips() -> None:
    """A command this library knows nothing about is octets like any other.

    The envelope knows no payload type, so the parser cannot be the thing
    that decides a message is unrecognized: `Message.parse` reads a
    command of a future BIP as it reads "version", and answering it is
    the caller's.
    """
    message = Message(_MAINNET, "notaBIPyet", b"\x00\xff" * 8)
    assert Message.parse(message.serialize()) == message
    assert Message.parse(message.serialize()).command == "notaBIPyet"


def test_empty_command_round_trips() -> None:
    """Twelve NUL octets are a command Core accepts, so this does too.

    `CMessageHeader::IsMessageTypeValid` runs its printable-ascii test
    over the octets before the first NUL, and an all-NUL field has none:
    it is valid there, and a message no handler answers. Refusing it here
    would be btclib holding a rule Core has not got.
    """
    message = Message(_MAINNET, "")
    assert message.serialize()[4:16] == bytes(12)
    assert Message.parse(message.serialize()) == message


def test_a_stream_may_hold_more_than_one_message() -> None:
    """Read two messages off one stream, and stop where the second ends.

    What a caller reading from a socket has: a buffer holding whatever
    arrived. Each `parse` consumes exactly its own message and leaves the
    stream on the octet after it, which is how many are taken one at a
    time -- and the position is what says how much was consumed.
    """
    stream = BytesIO(_VERSION + _VERACK)

    first = Message.parse(stream)
    assert first.command == "version"
    assert stream.tell() == len(_VERSION)

    second = Message.parse(stream)
    assert second.command == "verack"
    assert stream.tell() == len(_VERSION) + len(_VERACK)


def test_octets_holding_a_second_message_are_refused() -> None:
    """Octets are one whole object, and a stream is the caller's.

    `btclib.utils.assert_no_trailing`'s rule, which the envelope is under
    like every other parser here: two messages in one buffer are read one
    at a time off a stream, and handed over as octets they are what no
    single message serializes back to.
    """
    with pytest.raises(BTClibValueError, match="bytes after the p2p message"):
        Message.parse(_VERSION + _VERACK)


@pytest.mark.parametrize(
    "kept, missing, what",
    [
        (0, _HEADER_SIZE, "an empty buffer"),
        (2, _HEADER_SIZE - 2, "half the magic"),
        (10, _HEADER_SIZE - 10, "half the command"),
        (17, _HEADER_SIZE - 17, "half the payload length"),
        (21, _HEADER_SIZE - 21, "half the checksum"),
        (_HEADER_SIZE, 100, "the header and no payload"),
        (len(_VERSION) - 1, 1, "all but the last octet of the payload"),
    ],
)
def test_an_incomplete_message_says_how_much_is_missing(
    kept: int, missing: int, what: str
) -> None:
    """The refusal more octets can answer, with the number to ask for.

    `missing` takes the next call past where this one stopped: the rest
    of the header, or the rest of the payload once the header has been
    read. The rewind is what makes it usable -- the caller appends what
    its socket gave it to the same stream and calls again, rather than
    tracking where the message it could not read had started.
    """
    stream = BytesIO(_VERSION[:kept])
    with pytest.raises(IncompleteMessageError) as refusal:
        Message.parse(stream)
    assert refusal.value.missing == missing, what
    assert stream.tell() == 0, what
    assert f"{missing} more bytes wanted" in str(refusal.value)

    # and the number is honest: exactly that many more octets take the
    # parse past where it stopped, which for the payload is the whole
    # message and for the header is the header
    resumed = BytesIO(_VERSION[: kept + missing])
    if kept + missing < len(_VERSION):
        with pytest.raises(IncompleteMessageError) as again:
            Message.parse(resumed)
        assert again.value.missing == len(_VERSION) - _HEADER_SIZE
    else:
        assert Message.parse(resumed).serialize() == _VERSION


def test_incomplete_is_told_from_invalid_by_class_and_not_by_message() -> None:
    """A socket caller branches on the class, which is what it is for.

    `BTClibRuntimeError` and not `BTClibValueError`: nothing handed to
    `parse` is wrong, and reading more is what fixes it. So an `except
    BTClibValueError` written for the disconnect half does not swallow
    the read-more half, and `except BTClibException` still catches both.
    """
    assert issubclass(IncompleteMessageError, BTClibRuntimeError)
    assert not issubclass(IncompleteMessageError, BTClibValueError)
    assert issubclass(IncompleteMessageError, BTClibException)

    with pytest.raises(BTClibRuntimeError):
        Message.parse(_VERSION[:20])
    # the pair, one buffer each: incomplete, and invalid beyond repair
    corrupt = bytearray(_VERSION)
    corrupt[4] = 0x7F
    with pytest.raises(BTClibValueError):
        Message.parse(bytes(corrupt))


def test_the_rewind_is_to_the_message_and_not_to_the_stream() -> None:
    """A message read out of the middle of a stream rewinds to its start."""
    stream = BytesIO(_VERACK + _VERSION[:-1])
    assert Message.parse(stream).command == "verack"

    with pytest.raises(IncompleteMessageError) as refusal:
        Message.parse(stream)
    assert refusal.value.missing == 1
    assert stream.tell() == len(_VERACK)

    # what the caller does about it: append what arrived, and ask again
    stream = BytesIO(_VERACK + _VERSION)
    stream.seek(len(_VERACK))
    assert Message.parse(stream).command == "version"


def test_a_wrong_checksum_is_final_and_does_not_rewind() -> None:
    """The one refusal telling a corrupt message from an incomplete one.

    Nothing more the peer sends can make these octets check out, so the
    stream is not rewound: there is nothing to retry. What a node does
    next -- Core disconnects -- is policy, and this package holds none.
    """
    corrupt = bytearray(_VERSION)
    corrupt[-1] ^= 0xFF
    stream = BytesIO(bytes(corrupt))

    with pytest.raises(BTClibValueError, match="invalid checksum") as refusal:
        Message.parse(stream)
    assert not isinstance(refusal.value, IncompleteMessageError)
    assert stream.tell() == len(_VERSION)


def test_a_payload_length_no_network_would_send_is_refused() -> None:
    """The bound is read before the payload is, which is what it is for.

    The length field is the peer's to choose, so a parser that waits for
    the octets it announces has already let the peer decide how much this
    process holds. Core caps it at `MAX_PROTOCOL_MESSAGE_LENGTH`, and the
    refusal here is not "not yet" though the payload is absent: no
    further octet makes such a header acceptable.
    """
    header = bytearray(_VERSION[:_HEADER_SIZE])
    header[16:20] = (MAX_PROTOCOL_MESSAGE_LENGTH + 1).to_bytes(4, "little")

    with pytest.raises(BTClibValueError, match="invalid payload length"):
        Message.parse(BytesIO(bytes(header)))

    header[16:20] = (0xFFFFFFFF).to_bytes(4, "little")
    with pytest.raises(BTClibValueError, match="invalid payload length"):
        Message.parse(BytesIO(bytes(header)))


def test_the_bound_is_the_one_core_publishes() -> None:
    """Core's src/net.h, spelled as Core spells it."""
    assert MAX_PROTOCOL_MESSAGE_LENGTH == 4 * 1000 * 1000


@pytest.mark.parametrize(
    "command, match",
    [
        (b"version\x00\x00\x00x\x00", "invalid command padding"),
        (b"ping\x00\x00\x00\x00\x00\x00\x00\x01", "invalid command padding"),
        (b"ver\x7fsion\x00\x00\x00\x00", "non-printable character"),
        (b"\xffersion\x00\x00\x00\x00\x00", "non-printable character"),
        (b"ver\x1fsion\x00\x00\x00\x00", "non-printable character"),
    ],
)
def test_a_command_no_header_spells_is_refused(command: bytes, match: str) -> None:
    """Core's `IsMessageTypeValid`, both halves of it.

    The padding half is what keeps the encoding one to one: without it
    "ping" and "ping" followed by anything at all read as the same
    command, and only one of them serializes back -- the malleability
    `assert_no_trailing` refuses one field down.
    """
    header = bytearray(_VERACK)
    header[4:16] = command
    with pytest.raises(BTClibValueError, match=match):
        Message.parse(bytes(header))


def test_the_object_refuses_what_the_header_cannot_carry() -> None:
    """`assert_valid` over the three fields, at the object boundary."""
    with pytest.raises(BTClibValueError, match="invalid magic"):
        Message(b"\xf9\xbe\xb4", "verack")
    with pytest.raises(BTClibValueError, match="invalid magic"):
        Message(_MAINNET + b"\x00", "verack")

    with pytest.raises(BTClibValueError, match="invalid command"):
        Message(_MAINNET, "thirteenchars")
    with pytest.raises(BTClibValueError, match="non-printable character"):
        Message(_MAINNET, "ver\x00sion")
    with pytest.raises(BTClibValueError, match="non-printable character"):
        Message(_MAINNET, "verzión")

    # twelve characters is a command and thirteen is not; one filling the
    # field leaves no padding, which is the other side of the rule above
    full = Message(_MAINNET, "a" * 12)
    assert full.serialize()[4:16] == b"a" * 12
    assert Message.parse(full.serialize()) == full


def test_an_oversize_payload_is_refused_at_both_boundaries() -> None:
    """What no peer accepts is not serialized either.

    The object check and the parse check are the same bound and not the
    same check: this one answers to `check_validity`, and the one in
    `parse` -- which runs before the payload is read -- does not.
    """
    payload = bytes(MAX_PROTOCOL_MESSAGE_LENGTH + 1)
    with pytest.raises(BTClibValueError, match="invalid payload length"):
        Message(_MAINNET, "block", payload)

    message = Message(_MAINNET, "block", payload, check_validity=False)
    assert len(message.payload) == MAX_PROTOCOL_MESSAGE_LENGTH + 1
    with pytest.raises(BTClibValueError, match="invalid payload length"):
        message.serialize()


def test_a_wrong_type_is_a_type_error() -> None:
    """A value of a type the signature does not declare, at every field."""
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Message(1, "verack")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid message command type"):
        Message(_MAINNET, 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Message(_MAINNET, "verack", 1)  # type: ignore[arg-type]


def test_the_hex_spelling_of_every_octets_field() -> None:
    """`Octets` is hex or the octets it spells, here as everywhere."""
    message = Message("f9beb4d9", "ping", "00" * 8)
    assert message.magic == _MAINNET
    assert message.payload == bytes(8)
    assert message == Message(_MAINNET, b"ping", bytes(8))


def test_frozen() -> None:
    """Refuse assignment to any field: a Message is a value.

    All three fields are immutable, so a frozen Message is hashable, and
    `dataclasses.replace` is what retargets one at another network.
    """
    message = Message(_MAINNET, "verack")

    with pytest.raises(FrozenInstanceError):
        message.command = "version"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        message.magic = _MAINNET  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        message.payload = b""  # type: ignore[misc]

    assert hash(message) == hash(Message(_MAINNET, "verack"))
    assert len({message, copy.copy(message)}) == 1

    regtest = Message(magic_from_chain("regtest"), "verack")
    assert regtest != message
    assert regtest.serialize()[4:] == message.serialize()[4:]
