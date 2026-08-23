# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The messages by which a peer says what it wants sent to it.

`getaddr` wants addresses, `mempool` wants what is in the mempool,
`sendheaders` wants a new block announced as a header rather than as an
inventory, `wtxidrelay` wants transactions announced by wtxid, and
`feefilter` wants nothing below a fee rate. That is the one idea they
share, and the module is named for the larger half of it: three of them
negotiate how the rest of the connection is written, and two are
one-off requests. Issue #1119 is titled for both -- "the p2p negotiation
and request messages" -- and a filename cannot be.

**Why they are together, and it is not that they answer to nothing.**
Every other request in this package sits beside the message that
answers it: `getdata` beside `inv`, `getcfilters` beside `cfilter`,
`getblocktxn` beside `blocktxn`. The two requests here cannot follow
that rule. A `getaddr` is answered by an `addr` *or* by an `addrv2`,
which are two modules, so sitting beside its answer means picking one of
them; a `mempool` is answered by an `inv`, and `inventory` is the module
about inventories rather than about what a peer holds. The three that
negotiate have the opposite problem: they turn nothing on that this
package encodes, so there is no codec for them to sit beside at all.

`sendaddrv2` and `sendcmpct` are not here for the reason the three
negotiators are: each is about a message this package *does* encode --
an `addrv2` and a `cmpctblock` -- so each lives beside the codec it
turns on, which is where a reader of that codec looks.

**All but `feefilter` carry no octets at all**, which makes them the
shape `Verack` and `SendAddrV2` already are, down to the one thing an
empty payload has to get right: `parse` refuses trailing octets rather
than ignoring them, a message this class could not have written not
being one it may answer. They repeat those lines rather than share a
base, for the reason `addrv2.SendAddrV2` states:
`keepalive._NoncePayload` is a base because two commands have one
*body*, and the absence of a body is not a body to share. The
alternative -- one class with `command` as a field -- is refused across
this package and argued in `payload.py`: the command is the message's
identity, and a field would let a caller build a `getaddr` that
serializes under "mempool".

**`feefilter` is a signed `int64_t`**, and signed is not an accident of
the type Core happened to declare. BIP133 defines the message as one
"containing an int64_t", to be "interpreted as satoshis per
kilobyte"; it states the type and the units and not the encoding. The
octets are the Bitcoin Wiki's Protocol documentation, which publishes
the payload as eight bytes of that integer, LSB first, cited by
revision as the envelope's tests cite it:
https://en.bitcoin.it/w/index.php?title=Protocol_documentation&oldid=68832

Core reads it into a `CAmount` -- which is `int64_t` -- and asks
`MoneyRange(newFeeFilter)` only after the read. So a negative fee rate
is octets Core parses and declines to use, not octets it refuses, and
this codec parses them too: the money range is policy about a value, and
this package holds no policy. What it does refuse is a value no eight
octets hold, which is the field boundary rather than a judgement.

**What is not modelled** is placement, and the rules are not the same
for all of them. `wtxidrelay` must arrive before the `verack` and Core
disconnects a peer that sends one after it; `sendheaders` has no such
rule and Core honours one whenever it arrives; `getaddr` is answered
once per connection and only to an inbound peer; `mempool` is served
only where Core advertises `NODE_BLOOM` or the peer is permitted; and
Core sends a `feefilter` from protocol version 70013, unless it is
running with transactions ignored, the peer has the force-relay
permission, or the connection is block-relay-only. Every one of those is
a rule about *when* or *to whom*, which needs a connection to hold, and
this package has none -- the same line `SendAddrV2` draws for BIP155's
placement rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import override

from btclib.alias import BinaryData
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "FeeFilter",
    "GetAddr",
    "Mempool",
    "SendHeaders",
    "WtxidRelay",
]

# the int64_t BIP133 defines the message as containing, whose eight
# octets the wiki page the module docstring cites publishes
_FEERATE_SIZE = 8

# Core's CAmount is int64_t, and the message carries one: see the module
# docstring for why a negative fee rate is parsed rather than refused
_MIN_INT64 = -(1 << (8 * _FEERATE_SIZE - 1))
_MAX_INT64 = (1 << (8 * _FEERATE_SIZE - 1)) - 1


@dataclass(frozen=True)
class GetAddr(Payload):
    """The `getaddr` message: send me the peers you know of.

    Bitcoin Core's `msg_getaddr`, and the whole of that command: the
    answer is an `addr`, or an `addrv2` where the peer asked for one.

    Core answers at most once per connection and only an inbound peer --
    `ProcessMessage` returns early on `pfrom.IsInboundConn()` false and
    on `peer->m_getaddr_recvd` -- and it caps and shuffles what it sends.
    All three are policy a connection carries out, and none of them is
    visible in the octets, which is why none of them is here.
    """

    command = "getaddr"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `getaddr` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[GetAddr], data: BinaryData, *, check_validity: bool = True
    ) -> GetAddr:
        """Return a `GetAddr`, refusing any octet at all."""
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "getaddr payload")

        return cls(check_validity=check_validity)


@dataclass(frozen=True)
class Mempool(Payload):
    """The `mempool` message: send me what your mempool holds.

    BIP35, and Bitcoin Core's `msg_mempool`: the answer is an `inv` of
    the transactions in the peer's mempool, or several, bounded the way
    any `inv` is.

    Core serves one only where it advertises `NODE_BLOOM` *itself*, or
    where the asking peer holds the mempool permission -- the check is
    on the answering node's own services and not on the asker's -- and
    it drops a peer that asks otherwise unless that peer may not be
    banned. That is policy about who may ask and about what this node
    offers; the octets of the question are the same either way.
    """

    command = "mempool"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `mempool` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[Mempool], data: BinaryData, *, check_validity: bool = True
    ) -> Mempool:
        """Return a `Mempool`, refusing any octet at all."""
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "mempool payload")

        return cls(check_validity=check_validity)


@dataclass(frozen=True)
class SendHeaders(Payload):
    """The `sendheaders` message: announce a new block as a header.

    BIP130, and Bitcoin Core's `msg_sendheaders`: a peer that sends one
    is asking to be told about a new block with a `headers` message
    rather than with an `inv` it would then have to ask about. The
    saving is the round trip, which is BIP130's own argument.

    There is no message that turns it off again, and no rule that it be
    honoured either. BIP130 is permissive in both directions: the
    receiving node "will be permitted, but not required, to announce new
    blocks by sending the header", and implementations "may also
    optionally impose additional constraints, such as only honoring
    sendheaders messages shortly after a connection is established".
    Core imposes none of them -- `m_prefers_headers = true` is the only
    write there is, and it happens whenever the message arrives.
    """

    command = "sendheaders"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `sendheaders` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[SendHeaders], data: BinaryData, *, check_validity: bool = True
    ) -> SendHeaders:
        """Return a `SendHeaders`, refusing any octet at all."""
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "sendheaders payload")

        return cls(check_validity=check_validity)


@dataclass(frozen=True)
class WtxidRelay(Payload):
    """The `wtxidrelay` message: announce transactions by wtxid.

    BIP339, and Bitcoin Core's `msg_wtxidrelay`: a peer that sends one is
    asking for `MSG_WTX` in the inventories it is sent, so that a
    transaction is named by the hash that commits to its witness and a
    witness-malleated copy is a different announcement rather than the
    same one.

    One message enables one direction. BIP339: "After a node has
    received a wtxidrelay message from a peer, the node MUST use the
    MSG_WTX inv type when announcing transactions to that peer" -- so a
    peer that sends one has said how it wants to be announced to, and
    said nothing about how it will announce. Core matches, setting
    `m_wtxid_relay` on receipt alone and never consulting whether it
    sent its own; two Core nodes both send one, which makes the
    connection symmetric in practice and is a fact about Core rather
    than about the message.

    Like BIP155's `sendaddrv2`, it belongs between the `version` and the
    `verack`, and Core disconnects a peer that sends one after. That is
    a rule about when, and holding it needs a connection this package
    does not have.
    """

    command = "wtxidrelay"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `wtxidrelay` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[WtxidRelay], data: BinaryData, *, check_validity: bool = True
    ) -> WtxidRelay:
        """Return a `WtxidRelay`, refusing any octet at all."""
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "wtxidrelay payload")

        return cls(check_validity=check_validity)


@dataclass(frozen=True)
class FeeFilter(Payload):
    """The `feefilter` message: do not announce below this fee rate.

    BIP133, and Bitcoin Core's `msg_feefilter`: eight octets of a fee
    rate, little-endian, "interpreted as satoshis per kilobyte", and a
    peer that sends one is asking not to be told about a transaction
    paying less. It is a request and not a rule, in BIP133's own words:
    the receiving node "will be permitted, but not required, to filter
    transaction invs for transactions that fall below the feerate
    provided". The one thing the BIP says about the filter's reach is
    that it does not stop at newly relayed transactions -- "Inv's
    generated from a mempool message are also subject to a fee filter if
    it exists".

    The rate is signed, `CAmount` being `int64_t`, and a value outside
    the money range is parsed rather than refused: Core asks
    `MoneyRange` before it acts on one, which is what to do with a value
    rather than whether the octets decode. The module docstring is the
    whole of that argument.

    Frozen and hashable, the one field being immutable.
    """

    command = "feefilter"

    feerate: int

    def __init__(self, feerate: int = 0, *, check_validity: bool = True) -> None:
        object.__setattr__(self, "feerate", feerate)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a fee rate no signed eight octets hold."""
        # a bool is an int and would read as the fee rate one or zero,
        # which the range check cannot tell from one whose value that is
        if not is_integer(self.feerate):
            err_msg = f"invalid feerate type: {type(self.feerate).__name__}"
            raise BTClibTypeError(err_msg)
        if not _MIN_INT64 <= self.feerate <= _MAX_INT64:
            raise BTClibValueError(f"invalid feerate: {self.feerate}")

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the eight octets of the fee rate, little-endian."""
        if check_validity:
            self.assert_valid()

        return self.feerate.to_bytes(_FEERATE_SIZE, byteorder="little", signed=True)

    @classmethod
    def parse(
        cls: type[FeeFilter], data: BinaryData, *, check_validity: bool = True
    ) -> FeeFilter:
        """Return the fee rate the eight octets carry."""
        stream = bytesio_from_binarydata(data)

        feerate = int.from_bytes(
            read_exactly(stream, _FEERATE_SIZE, "feerate"),
            byteorder="little",
            signed=True,
        )
        assert_no_trailing(data, stream, "feefilter payload")

        return cls(feerate, check_validity=check_validity)
