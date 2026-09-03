# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.negotiation` module.

**No capture stands behind these, and for this module there is nothing
a capture would settle.** All but `feefilter` and `sendtxrcncl` are the
empty payload, whose whole content is the command in the envelope --
`tests/p2p/message_test.py` is where the command's octets are driven --
`feefilter` is eight octets of a little-endian integer, and
`sendtxrcncl` is a `uint32` and a `uint64`, both little-endian. The
traps a captured message exists to catch in `tests/p2p/address_test.py`
are the one big-endian field of this protocol and a sixteen-octet
address with a narrower one inside it; neither shape is in this format.
`sendtxrcncl`'s own vector is hand-built from BIP330's field table
rather than captured, for the same reason: Bitcoin Core's functional
test drives it through Python objects
(`test/functional/p2p_sendtxrcncl.py`) rather than fixing octets, and
the version and salt it uses to do so -- 1 and 2 -- are what the vector
here reuses.

What is worth asserting instead is what this module decides: that each
command is spelled the way Bitcoin Core's `NetMsgType` spells it -- a
misspelling round-trips as well as the real thing, which is how
btclib_node sent "sendcmpt" to the whole network -- that a `feefilter`
outside the money range is parsed rather than refused, Core asking
`MoneyRange` about a value it has already read, and that a
`sendtxrcncl` version below BIP330's floor of 1 is parsed rather than
refused too, that floor being a fact about the pair of versions two
peers offer each other and not about one message's own octets.

`feature` is the one here whose bounds go the other way, and the tests
below drive both edges of each: BIP434 writes its two lengths as a MUST
on the encoding, so what falls outside them is refused where a fee rate
outside the money range is not. The edges are the boundary cases Core's
`p2p_bip434_feature.py` asks a node for -- an identifier of nothing, of
one octet below the minimum, of the minimum, of the maximum and of one
past it, and data of nothing, of the maximum and of one past it -- read
here against the same accept-or-refuse answer.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO

import pytest

from btclib import var_bytes
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.p2p import (
    Feature,
    FeeFilter,
    GetAddr,
    Mempool,
    Message,
    SendHeaders,
    SendTxRcncl,
    WtxidRelay,
)
from btclib.p2p.limits import (
    MAX_FEATUREDATA_LENGTH,
    MAX_FEATUREID_LENGTH,
    MIN_FEATUREID_LENGTH,
)

_MAINNET = bytes.fromhex("f9beb4d9")

# the empty-payload classes as one type, rather than `type[Payload]`:
# the base declares no constructor and no `parse`, so a parametrized
# test typed against it could not build one of these or read one back
_Empty = type[GetAddr] | type[Mempool] | type[SendHeaders] | type[WtxidRelay]

# Bitcoin Core's NetMsgType, which is the authority on each of these:
# the command is the whole of what an empty payload carries, so a name
# only this library agrees with is a message nobody answers
_EMPTY: tuple[tuple[_Empty, str], ...] = (
    (GetAddr, "getaddr"),
    (Mempool, "mempool"),
    (SendHeaders, "sendheaders"),
    (WtxidRelay, "wtxidrelay"),
)
_EMPTY_IDS = tuple(command for _, command in _EMPTY)


@pytest.mark.parametrize("cls, command", _EMPTY, ids=_EMPTY_IDS)
def test_an_empty_payload_travels_under_core_s_name(cls: _Empty, command: str) -> None:
    """The command is the message, so the spelling is the whole of it."""
    assert cls.command == command
    assert cls().to_message(_MAINNET).command == command
    assert Message.parse(cls().to_message(_MAINNET).serialize()).command == command


@pytest.mark.parametrize("cls, command", _EMPTY, ids=_EMPTY_IDS)
def test_an_empty_payload_is_no_octets_at_all(cls: _Empty, command: str) -> None:
    """Nothing out, and nothing is what parses back."""
    assert cls().serialize() == b""
    assert cls().serialize(check_validity=False) == b""
    assert cls.parse(b"") == cls()
    assert cls.parse(b"", check_validity=False) == cls()
    assert cls(check_validity=False) == cls()


@pytest.mark.parametrize("cls, command", _EMPTY, ids=_EMPTY_IDS)
def test_an_octet_after_an_empty_payload_is_refused(cls: _Empty, command: str) -> None:
    """Core ignores what such a message carries; this refuses it.

    The rule this library keeps everywhere: a buffer that deserializes
    to an object serializing back to less than the buffer is
    malleability, and a `getaddr` with a payload is exactly that.
    """
    for trailing in (b"\x00", b"junk"):
        with pytest.raises(
            BTClibValueError, match=f"bytes after the {command} payload"
        ):
            cls.parse(trailing)


@pytest.mark.parametrize("cls, command", _EMPTY, ids=_EMPTY_IDS)
def test_an_empty_payload_consumes_nothing_from_a_stream(
    cls: _Empty, command: str
) -> None:
    """A caller's stream is left where it was: there is nothing to read."""
    stream = BytesIO(b"junk")
    assert cls.parse(stream) == cls()
    assert stream.read() == b"junk"


def test_an_empty_payload_is_its_own_class() -> None:
    """One shape, several message types, and the command is which.

    A `command` field on one class would let a caller build a `getaddr`
    that serializes under "mempool"; a class apiece makes that
    unsayable, and the generated `__eq__` compares the class, so objects
    of no octets at all are still distinct values.
    """
    payloads = [cls() for cls, _ in _EMPTY]
    assert len(set(payloads)) == len(_EMPTY)
    assert len({payload.serialize() for payload in payloads}) == 1

    # through `object`, because mypy refuses the direct comparison as
    # non-overlapping -- which is the property being asserted, said
    # statically; what runs here is the runtime half of it
    getaddr: object = GetAddr()
    assert getaddr != Mempool()


@pytest.mark.parametrize("cls, command", _EMPTY, ids=_EMPTY_IDS)
def test_an_empty_payload_is_frozen(cls: _Empty, command: str) -> None:
    """A message is a value, and one with no fields is still one."""
    with pytest.raises(FrozenInstanceError):
        cls().command = "other"  # type: ignore[misc]

    assert hash(cls()) == hash(cls())
    assert replace(cls()) == cls()


@pytest.mark.parametrize(
    "feerate",
    [0, 1, 1000, 21_000_000 * 100_000_000, -1, -(2**63), 2**63 - 1],
)
def test_the_fee_rate_round_trips(feerate: int) -> None:
    """Eight octets, little-endian and signed, and back.

    A negative rate and one above the money supply among them: BIP133's
    field is a `CAmount`, Core reads it and *then* asks `MoneyRange`, so
    what it declines to act on is still what it parsed.
    """
    message = FeeFilter(feerate)
    assert len(message.serialize()) == 8
    assert FeeFilter.parse(message.serialize()) == message
    assert FeeFilter.parse(message.serialize()).feerate == feerate


def test_the_fee_rate_is_satoshi_per_kvb_and_the_command_is_core_s() -> None:
    """BIP133's units, and the name the message goes out under."""
    assert FeeFilter.command == "feefilter"
    assert FeeFilter(48_508).serialize().hex() == "7cbd000000000000"
    assert FeeFilter().feerate == 0
    assert FeeFilter(1).to_message(_MAINNET).command == "feefilter"


def test_what_no_signed_eight_octets_hold_is_refused() -> None:
    """`assert_valid` at the object boundary, and the type rule with it."""
    with pytest.raises(BTClibValueError, match="invalid feerate"):
        FeeFilter(2**63)
    with pytest.raises(BTClibValueError, match="invalid feerate"):
        FeeFilter(-(2**63) - 1)

    with pytest.raises(BTClibTypeError, match="invalid feerate type"):
        FeeFilter(1.5)  # type: ignore[arg-type]
    # a bool is an int and would read as the fee rate one or zero, which
    # the range check cannot tell from one whose value that is
    with pytest.raises(BTClibTypeError, match="invalid feerate type"):
        FeeFilter(True)

    # and what is refused at the object boundary is refused on the way
    # out too, an unchecked object being one a caller may hold
    unchecked = FeeFilter(2**63, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid feerate"):
        unchecked.serialize()
    # what turning the check off buys is skipping the check, and not
    # octets for a value there are none of: an unchecked object whose
    # rate does fit writes exactly what a checked one writes
    assert FeeFilter(1).serialize(check_validity=False) == FeeFilter(1).serialize()
    assert FeeFilter.parse(FeeFilter(1).serialize(), check_validity=False) == FeeFilter(
        1
    )


def test_the_fee_rate_octets_end_where_the_field_does() -> None:
    """A short read is a truncation, and what follows is refused."""
    for size in range(8):
        with pytest.raises(BTClibValueError, match="not enough data for the feerate"):
            FeeFilter.parse(bytes(size))

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the feefilter payload"):
            FeeFilter.parse(bytes(8) + trailing)

    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        FeeFilter.parse(None)  # type: ignore[arg-type]


def test_a_fee_filter_leaves_a_stream_after_its_own_octets() -> None:
    """Eight octets wide, so a stream reads one message and stops."""
    stream = BytesIO(FeeFilter(7).serialize() + b"junk")
    assert FeeFilter.parse(stream) == FeeFilter(7)
    assert stream.read() == b"junk"


def test_a_fee_filter_is_frozen() -> None:
    """Refuse assignment to the rate: a message is a value."""
    fee_filter = FeeFilter(1)

    with pytest.raises(FrozenInstanceError):
        fee_filter.feerate = 2  # type: ignore[misc]

    assert replace(fee_filter, feerate=2) == FeeFilter(2)
    assert isinstance(replace(fee_filter, feerate=2), FeeFilter)
    assert hash(fee_filter) == hash(FeeFilter(1))


@pytest.mark.parametrize(
    "version, salt",
    [(0, 0), (1, 2), (0, 2**64 - 1), (2**32 - 1, 0), (2**32 - 1, 2**64 - 1)],
)
def test_sendtxrcncl_round_trips(version: int, salt: int) -> None:
    """Twelve octets, little-endian and unsigned, and back.

    A version below BIP330's floor of 1 among the cases: the floor is
    what the module docstring says this codec does not enforce, so `0`
    is a value that parses rather than one that is refused.
    """
    message = SendTxRcncl(version, salt)
    assert len(message.serialize()) == 12
    assert SendTxRcncl.parse(message.serialize()) == message
    assert SendTxRcncl.parse(message.serialize()).version == version
    assert SendTxRcncl.parse(message.serialize()).salt == salt


def test_sendtxrcncl_hand_built_vector_and_the_command_is_core_s() -> None:
    """BIP330's field table, hand-built, and the name Core sends it under.

    Bitcoin Core's own functional test builds a `sendtxrcncl` with
    `version = 1` and `salt = 2`
    (`test/functional/p2p_sendtxrcncl.py`'s `create_sendtxrcncl_msg`);
    those are the values encoded here, by BIP330's field table rather
    than from a capture -- `uint32 version` then `uint64 salt`, both
    little-endian.
    """
    assert SendTxRcncl.command == "sendtxrcncl"
    assert SendTxRcncl(1, 2).serialize().hex() == "010000000200000000000000"
    assert SendTxRcncl().version == 0
    assert SendTxRcncl().salt == 0
    assert SendTxRcncl(1, 2).to_message(_MAINNET).command == "sendtxrcncl"


def test_what_no_unsigned_sendtxrcncl_field_holds_is_refused() -> None:
    """`assert_valid` at the object boundary, and the type rule with it."""
    with pytest.raises(BTClibValueError, match="invalid version"):
        SendTxRcncl(2**32)
    with pytest.raises(BTClibValueError, match="invalid version"):
        SendTxRcncl(-1)
    with pytest.raises(BTClibValueError, match="invalid salt"):
        SendTxRcncl(0, 2**64)
    with pytest.raises(BTClibValueError, match="invalid salt"):
        SendTxRcncl(0, -1)

    with pytest.raises(BTClibTypeError, match="invalid version type"):
        SendTxRcncl(1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid salt type"):
        SendTxRcncl(0, 1.5)  # type: ignore[arg-type]
    # a bool is an int and would read as the field one or zero, which the
    # range check cannot tell from a value that is one or zero
    with pytest.raises(BTClibTypeError, match="invalid version type"):
        SendTxRcncl(True)
    with pytest.raises(BTClibTypeError, match="invalid salt type"):
        SendTxRcncl(0, True)

    # and what is refused at the object boundary is refused on the way
    # out too, an unchecked object being one a caller may hold
    unchecked = SendTxRcncl(2**32, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid version"):
        unchecked.serialize()
    # what turning the check off buys is skipping the check, and not
    # octets for a value there are none of: an unchecked object whose
    # fields do fit writes exactly what a checked one writes
    assert (
        SendTxRcncl(1, 2).serialize(check_validity=False)
        == SendTxRcncl(1, 2).serialize()
    )
    assert SendTxRcncl.parse(
        SendTxRcncl(1, 2).serialize(), check_validity=False
    ) == SendTxRcncl(1, 2)


def test_sendtxrcncl_octets_end_where_the_fields_do() -> None:
    """A short read is a truncation, and what follows is refused."""
    for size in range(12):
        with pytest.raises(
            BTClibValueError, match="not enough data for the sendtxrcncl"
        ):
            SendTxRcncl.parse(bytes(size))

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(
            BTClibValueError, match="bytes after the sendtxrcncl payload"
        ):
            SendTxRcncl.parse(bytes(12) + trailing)

    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        SendTxRcncl.parse(None)  # type: ignore[arg-type]


def test_a_sendtxrcncl_leaves_a_stream_after_its_own_octets() -> None:
    """Twelve octets wide, so a stream reads one message and stops."""
    stream = BytesIO(SendTxRcncl(1, 2).serialize() + b"junk")
    assert SendTxRcncl.parse(stream) == SendTxRcncl(1, 2)
    assert stream.read() == b"junk"


def test_a_sendtxrcncl_is_frozen() -> None:
    """Refuse assignment to either field: a message is a value."""
    sendtxrcncl = SendTxRcncl(1, 2)

    with pytest.raises(FrozenInstanceError):
        sendtxrcncl.version = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        sendtxrcncl.salt = 3  # type: ignore[misc]

    assert replace(sendtxrcncl, salt=3) == SendTxRcncl(1, 3)
    assert isinstance(replace(sendtxrcncl, salt=3), SendTxRcncl)
    assert hash(sendtxrcncl) == hash(SendTxRcncl(1, 2))


@pytest.mark.parametrize(
    "feature_id, feature_data",
    [
        (b"BIP434", b""),
        (b"BIP434", b"\x01"),
        (b"a" * MIN_FEATUREID_LENGTH, b""),
        (b"a" * MAX_FEATUREID_LENGTH, bytes(MAX_FEATUREDATA_LENGTH)),
        # BIP434 asks for printable ASCII with a SHOULD, and Core's
        # `test_non_ascii_feature_id_accepted` is a node taking one that
        # is not: what this codec answers has to be the same
        (b"\x00\xff\x01\x7f", b"\xff" * 8),
    ],
)
def test_a_feature_round_trips_identifier_and_data(
    feature_id: bytes, feature_data: bytes
) -> None:
    """Two lengths and two fields, and back to the same value."""
    feature = Feature(feature_id, feature_data)
    assert Feature.parse(feature.serialize()) == feature
    assert feature.feature_id == feature_id
    assert feature.feature_data == feature_data


def test_the_feature_octets_are_the_two_fields_behind_their_lengths() -> None:
    """BIP434's own encoding: a CompactSize apiece, then that many."""
    assert Feature.command == "feature"
    assert Feature(b"BIP434").feature_data == b""
    assert Feature(b"BIP434").serialize().hex() == "0642495034333400"
    assert Feature(b"BIP434", b"\x01").serialize().hex() == "064249503433340101"
    assert Feature(b"BIP434").to_message(_MAINNET).command == "feature"
    assert (
        Message.parse(Feature(b"BIP434").to_message(_MAINNET).serialize()).command
        == "feature"
    )


def test_a_feature_names_something_or_is_no_message() -> None:
    """No default identifier, as `Message`'s command has none.

    The name is the whole of what the message says, so an object without
    one could not be a valid message of any kind.
    """
    with pytest.raises(TypeError):
        Feature()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "length", [0, MIN_FEATUREID_LENGTH - 1, MAX_FEATUREID_LENGTH + 1]
)
def test_an_identifier_length_bip434_excludes_is_refused(length: int) -> None:
    """Core answers a payload outside the bounds with a disconnect."""
    with pytest.raises(BTClibValueError, match="invalid feature id length"):
        Feature(b"a" * length)

    # and the octets carrying it are refused on the way in, where the
    # bound is the same rule read off the wire rather than off a value
    payload = var_bytes.serialize(b"a" * length) + var_bytes.serialize(b"")
    with pytest.raises(BTClibValueError, match="invalid feature id length"):
        Feature.parse(payload)


def test_a_data_length_bip434_excludes_is_refused() -> None:
    """The other bound, and the one the BIP states only as a maximum."""
    with pytest.raises(BTClibValueError, match="invalid feature data length"):
        Feature(b"BIP434", bytes(MAX_FEATUREDATA_LENGTH + 1))

    payload = var_bytes.serialize(b"BIP434") + var_bytes.serialize(
        bytes(MAX_FEATUREDATA_LENGTH + 1)
    )
    with pytest.raises(BTClibValueError, match="invalid feature data length"):
        Feature.parse(payload)


def test_what_a_feature_refuses_it_refuses_on_the_way_out_too() -> None:
    """An unchecked object is one a caller may hold, so `serialize` asks."""
    unchecked = Feature(b"abc", check_validity=False)
    assert unchecked.feature_id == b"abc"
    with pytest.raises(BTClibValueError, match="invalid feature id length"):
        unchecked.serialize()

    long_data = Feature(
        b"BIP434", bytes(MAX_FEATUREDATA_LENGTH + 1), check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid feature data length"):
        long_data.serialize()

    # what turning the check off buys is skipping the check, and not
    # octets for a value there are none of
    valid = Feature(b"BIP434", b"\x01")
    assert valid.serialize(check_validity=False) == valid.serialize()
    assert Feature.parse(valid.serialize(), check_validity=False) == valid


def test_the_feature_octets_end_where_the_two_fields_do() -> None:
    """A truncation is refused, and so is anything after the second field."""
    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the feature payload"):
            Feature.parse(Feature(b"BIP434").serialize() + trailing)

    # an identifier whose length is longer than the octets that follow
    with pytest.raises(BTClibRuntimeError, match="not enough binary data"):
        Feature.parse(var_bytes.serialize(b"BIP434")[:-1])
    # and the same truncation in the second field
    with pytest.raises(BTClibRuntimeError, match="not enough binary data"):
        Feature.parse(var_bytes.serialize(b"BIP434") + b"\x08xx")

    with pytest.raises(BTClibValueError, match="not enough binary data for var_int"):
        Feature.parse(b"")

    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Feature.parse(None)  # type: ignore[arg-type]


def test_a_feature_length_that_is_not_minimally_encoded_is_refused() -> None:
    """BIP434 uses only the shortest CompactSize, and so does this.

    The bound is `btclib.var_int`'s own canonicality rule, reached here
    through `var_bytes`: the same identifier behind a three-octet length
    is a second encoding of one message.
    """
    non_canonical = b"\xfd\x06\x00" + b"BIP434" + b"\x00"
    assert Feature.parse(b"\x06BIP434\x00") == Feature(b"BIP434")
    with pytest.raises(BTClibValueError, match="non-canonical var_int"):
        Feature.parse(non_canonical)


def test_a_feature_leaves_a_stream_after_its_own_octets() -> None:
    """Two length-prefixed fields wide, so a stream reads one and stops."""
    stream = BytesIO(Feature(b"BIP434", b"\x01").serialize() + b"junk")
    assert Feature.parse(stream) == Feature(b"BIP434", b"\x01")
    assert stream.read() == b"junk"


def test_a_feature_is_frozen() -> None:
    """Refuse assignment to either field: a message is a value."""
    feature = Feature(b"BIP434")

    with pytest.raises(FrozenInstanceError):
        feature.feature_id = b"BIP999"  # type: ignore[misc]

    assert replace(feature, feature_id=b"BIP999") == Feature(b"BIP999")
    assert hash(feature) == hash(Feature(b"BIP434"))
