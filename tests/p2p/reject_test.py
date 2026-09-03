# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.reject` module.

**No capture stands behind these, and there is none to be had.** BIP61
carries a field table and no worked example, and Bitcoin Core removed
both directions of the message in `bitcoin/bitcoin#15437` -- there is no
`reject.json` to pin the way `tests/_data/README.md` pins `siphash.json`,
and no running node left to capture one from. What is below is btclib's
own round trips against BIP61's field table, and the refusals its
`assert_no_trailing`/`read_exactly` idiom is held to everywhere else in
this package.
"""

from __future__ import annotations

from io import BytesIO

import pytest

from btclib import var_bytes
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.p2p import Message, Reject, RejectCode

_MAINNET = bytes.fromhex("f9beb4d9")

_TXID = bytes(range(32))  # not a palindrome: a symmetric hash tells nothing


def test_a_version_reject_carries_no_hash_and_round_trips() -> None:
    """BIP61's common payload alone, the shape a `version` reject is."""
    reject = Reject("version", RejectCode.obsolete, "too old")
    assert reject.data == b""

    octets = reject.serialize()
    assert Reject.parse(octets) == reject


def test_a_tx_reject_carries_the_hash_and_round_trips() -> None:
    """The common payload plus the hash a `tx`/`block` reject appends."""
    reject = Reject("tx", RejectCode.insufficientfee, "min relay fee not met", _TXID)
    assert reject.data == _TXID

    octets = reject.serialize()
    assert Reject.parse(octets) == reject


def test_the_hash_is_reversed_on_the_wire_the_way_an_inventory_is() -> None:
    """`Reject.data`'s byte order on the wire matches `Inventory.hash`'s.

    Both classes hold a hash displayed, as everywhere else in this
    library, and both reverse it on serialization: the trailing
    thirty-two octets of a `tx` reject are `_TXID` read backwards.
    """
    reject = Reject("tx", RejectCode.invalid, "", _TXID)
    assert reject.serialize()[-32:] == _TXID[::-1]


def test_every_named_code_round_trips() -> None:
    """The eight codes BIP61's own tables name."""
    for code in RejectCode:
        reject = Reject("tx", code, "reason", _TXID)
        parsed = Reject.parse(reject.serialize())
        assert parsed.code == code
        assert isinstance(parsed.code, RejectCode)


def test_a_code_no_member_names_round_trips_as_a_plain_int() -> None:
    """BIP61 reserves ranges without naming every member, keeping this one.

    0x02 is inside "Protocol syntax errors" (0x01-0x0f) and is not one of
    the eight named codes: an implementation may use it, and refusing it
    would refuse a message BIP61 allows.
    """
    reject = Reject("version", 0x02, "reserved but unnamed")
    parsed = Reject.parse(reject.serialize())
    assert parsed.code == 0x02
    assert not isinstance(parsed.code, RejectCode)


@pytest.mark.parametrize("length", [1, 31, 33])
def test_a_hash_neither_absent_nor_whole_is_refused(length: int) -> None:
    """What follows `reason` is a 32-octet hash or nothing at all.

    A hash cut short would otherwise parse as the absent one a `version`
    reject carries, and octets past it as a payload that reserializes to
    less than the peer sent.
    """
    common = Reject("version", RejectCode.obsolete, "too old").serialize()
    payload = common + _TXID[:length] if length < 32 else common + _TXID + b"\x00"
    with pytest.raises(BTClibValueError, match="invalid data length"):
        Reject.parse(payload)


def test_a_payload_cut_short_is_refused_field_by_field() -> None:
    """No prefix of a `reject` with a hash is refused, but for one length.

    A short read answers with what is left rather than raising, so each
    field's own read is what has to refuse the payload that does not
    hold it -- except at the one length where the cut lands exactly on
    the hash's own boundary, which is the no-hash `Reject` of the same
    `message`, `code` and `reason` and a complete object rather than a
    truncation of this one; this module's last test is that property on
    its own.
    """
    reject = Reject("tx", RejectCode.invalid, "bad", _TXID)
    octets = reject.serialize()
    no_hash_length = len(Reject("tx", RejectCode.invalid, "bad").serialize())
    for i in range(len(octets)):
        if i == no_hash_length:
            continue
        with pytest.raises((BTClibValueError, BTClibRuntimeError, BTClibTypeError)):
            Reject.parse(octets[:i])


@pytest.mark.parametrize("field", ["message", "reason"])
def test_a_field_no_utf8_decodes_is_refused(field: str) -> None:
    """Both `message` and `reason` refuse octets no utf-8 decodes.

    The two octets 0xff 0xfe are what `bytes.decode` raises
    `UnicodeDecodeError` on; this parser turns it into the family every
    other refusal in this package raises.
    """
    bad = b"\xff\xfe"
    if field == "message":
        payload = var_bytes.serialize(bad) + bytes([RejectCode.malformed])
        payload += var_bytes.serialize(b"ok")
    else:
        payload = var_bytes.serialize(b"ok") + bytes([RejectCode.malformed])
        payload += var_bytes.serialize(bad)
    with pytest.raises(BTClibValueError, match=f"invalid {field}"):
        Reject.parse(payload)


def test_a_code_past_one_octet_is_refused() -> None:
    """`code` is `uint8_t`; a value past 0xff is refused, not truncated."""
    with pytest.raises(BTClibValueError, match="invalid code"):
        Reject("version", 256, "")
    with pytest.raises(BTClibTypeError, match="invalid code type"):
        Reject("version", 1.5, "")  # type: ignore[arg-type]


def test_a_non_string_message_or_reason_is_refused() -> None:
    """`message` and `reason` are `str`; a wrong type is a `BTClibTypeError`."""
    with pytest.raises(BTClibTypeError, match="invalid message type"):
        Reject(b"tx", RejectCode.invalid, "reason")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid reason type"):
        Reject("tx", RejectCode.invalid, b"reason")  # type: ignore[arg-type]


def test_a_data_length_no_hash_is_refused_on_construction() -> None:
    """`assert_valid` refuses a `data` neither empty nor thirty-two octets."""
    with pytest.raises(BTClibValueError, match="invalid data length"):
        Reject("version", RejectCode.obsolete, "too old", b"\x01")


def test_check_validity_false_skips_the_construction_time_checks() -> None:
    """An invalid `Reject` can still be built, as every payload here allows."""
    reject = Reject("version", 256, "", b"\x01", check_validity=False)
    assert reject.code == 256
    assert reject.data == b"\x01"


def test_the_payload_travels_under_the_command_bip61_names() -> None:
    """The round trip through an envelope, which is what a payload adds."""
    reject = Reject("tx", RejectCode.dust, "below dust threshold", _TXID)
    octets = reject.to_message(_MAINNET).serialize()
    message = Message.parse(octets)

    assert message.command == "reject"
    assert Reject.command == "reject"
    assert message.payload == reject.serialize()
    assert Reject.parse(message.payload) == reject


def test_reject_parse_takes_octets_and_not_a_callers_stream() -> None:
    """A `BytesIO` is refused, the same shape `Version.parse` is held to.

    The hash is optional and of fixed width, so a no-hash payload for one
    `message`, `code` and `reason` is a byte-for-byte prefix of the
    with-hash payload carrying the same three: only the whole payload,
    which the envelope's length field bounds, says whether the hash is
    there. `parse` takes `Octets` for that reason, and a stream is
    refused by the coercion rather than by a check of its own.
    """
    payload = Reject("version", RejectCode.obsolete, "too old").serialize()
    with pytest.raises(BTClibTypeError):
        Reject.parse(BytesIO(payload))  # type: ignore[arg-type]


def test_reject_is_not_prefix_free_and_that_is_not_malleability() -> None:
    """Two objects, each serializing back to the buffer it came from.

    The no-hash payload for one `message`, `code` and `reason` is a
    proper prefix of the with-hash payload carrying the same three, and
    each still writes back only the octets it was parsed from.
    """
    no_hash = Reject("tx", RejectCode.invalid, "bad")
    with_hash = Reject("tx", RejectCode.invalid, "bad", _TXID)

    assert no_hash.serialize() == with_hash.serialize()[: -len(_TXID)]
    assert Reject.parse(no_hash.serialize()) == no_hash
    assert Reject.parse(with_hash.serialize()) == with_hash
    assert Reject.parse(no_hash.serialize()).serialize() == no_hash.serialize()
    assert Reject.parse(with_hash.serialize()).serialize() == with_hash.serialize()
