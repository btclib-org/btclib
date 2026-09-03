# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The messages by which a peer says what it wants sent to it.

`getaddr` wants addresses, `mempool` wants what is in the mempool,
`sendheaders` wants a new block announced as a header rather than as an
inventory, `wtxidrelay` wants transactions announced by wtxid,
`sendtxrcncl` says this peer would reconcile its transaction set rather
than have every one announced, `feefilter` wants nothing below a fee
rate, and `feature` names a feature whose messages may then be sent to
it. That is the one idea they share, and the module is named for the
larger half of it: `getaddr` and `mempool` are one-off requests, and the
rest negotiate how the connection is written from there on. Issue #1119
is titled for both -- "the p2p negotiation and request messages" -- and
a filename cannot be.

**Why they are together, and it is not that they answer to nothing.**
Every other request in this package sits beside the message that
answers it: `getdata` beside `inv`, `getcfilters` beside `cfilter`,
`getblocktxn` beside `blocktxn`. The two requests here cannot follow
that rule. A `getaddr` is answered by an `addr` *or* by an `addrv2`,
which are two modules, so sitting beside its answer means picking one of
them; a `mempool` is answered by an `inv`, and `inventory` is the module
about inventories rather than about what a peer holds. Those that
negotiate have the opposite problem: they turn nothing on that this
package encodes, so there is no codec for them to sit beside at all.

`sendaddrv2` and `sendcmpct` are not here for the reason the
negotiators are: each is about a message this package *does* encode --
an `addrv2` and a `cmpctblock` -- so each lives beside the codec it
turns on, which is where a reader of that codec looks.

**`getaddr`, `mempool`, `sendheaders` and `wtxidrelay` carry no octets
at all**, which makes them the shape `Verack` and `SendAddrV2` already
are, down to the one thing an empty payload has to get right: `parse`
refuses trailing octets rather than ignoring them, a message this class
could not have written not being one it may answer. They repeat those
lines rather than share a base, for the reason `addrv2.SendAddrV2`
states:
`keepalive._NoncePayload` is a base because two commands have one
*body*, and the absence of a body is not a body to share. The
alternative -- one class with `command` as a field -- is refused across
this package and argued in `payload.py`: the command is the message's
identity, and a field would let a caller build a `getaddr` that
serializes under "mempool".

**`feature` is the general case of the negotiators beside it.** BIP434
generalises what `sendaddrv2` and `wtxidrelay` each do with a command of
their own: one message carries a `featureid` naming the feature and a
`featuredata` holding whatever that feature's own specification puts
there, so that the next feature needs neither a command minted for it
nor a protocol version number agreed on -- "there is no longer a
question whether version 'n+1' belongs to Alice's new feature, or Bob's
new feature".

What a `featureid` names is therefore not this package's to know, and
there is no table of them here. BIP434 has a node "ignore feature
messages specifying a featureid they do not support, so long as the
payload conforms to the requirements above", which makes the identifier
something a caller matches on and this codec merely carries -- the same
`if` `payload.py` leaves it for a command.

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

**`sendtxrcncl` is BIP330's Erlay negotiation and none of Erlay's
reconciliation.** The message itself is two unsigned fields, a `uint32`
protocol version and a `uint64` salt; BIP330's own table and Core's
`test/functional/test_framework/messages.py` `msg_sendtxrcncl` agree on
that layout field for field. `node/txreconciliation.h` declares
`TXRECONCILIATION_VERSION` 1, matching BIP330's "Sender must set this
to 1 currently" -- so both sources name the same one value a peer
sends today, and this codec fixes neither: a version below 1 is a
protocol violation BIP330 states and Core enforces in
`TxReconciliationTracker::RegisterPeer`, after the parse and against
the *pair* of versions the two peers offered, which is a connection's
state and not a fact the four octets of `version` carry alone; a salt
is entropy, and every value its width holds is one a peer may have
picked.

Erlay itself -- the sketches, the Minisketch library, the
request-and-response round that follows a successful negotiation -- is
not modelled here and is not going to be. BIP330's own list of the new
messages the protocol adds is `sendtxrcncl` and four more --
`reqrecon`, `sketch`, `reqsketchext`, `reconcildiff` -- and this module
carries the first and none of the rest; carrying it and stopping is the
shape every other module in this package already has, codecs and no
behaviour, stated once so that the absence of the other four reads as
the boundary it is rather than as an unfinished job. Issue #1066 is
what decides it and how: "what btclib can build out of the Python
standard library is in scope, what would need a hand-rolled
[construction] is not" -- `hashlib` and `hmac` back HKDF, and nothing in
the standard library backs a PinSketch over `GF(2**32)`. Minisketch is
C++ behind a C API for the reason `btclib_secp256k1` wraps a C library,
and a pure-Python sketch would be the only implementation on a relay
path rather than a documented slow arm behind a fast default, which is
the asymmetry issue #1066 states for a cipher and which holds here too.

**What is not modelled** is placement, and the rules are not the same
for all of them. `wtxidrelay` must arrive before the `verack` and Core
disconnects a peer that sends one after it; `sendheaders` has no such
rule and Core honours one whenever it arrives; `getaddr` is answered
once per connection and only to an inbound peer; `mempool` is served
only where Core advertises `NODE_BLOOM` or the peer is permitted; Core
sends a `feefilter` from protocol version 70013, unless it is running
with transactions ignored, the peer has the force-relay permission, or
the connection is block-relay-only; and `sendtxrcncl`, like
`wtxidrelay`, belongs between `version` and `verack` -- BIP330 says a
peer that sends one after `verack` should be disconnected, and Core's
`net_processing.cpp` does exactly that, along with disconnecting a peer
that offers reconciliation while either side's `version` declined
transaction relay; and BIP434 forbids a `feature` after the `verack` and
to a peer advertising a protocol version below 70017, requiring one that
arrives between the `version` and the `verack` be accepted. Every one of
those is a rule about *when* or *to whom*, which needs a connection to
hold, and this package has none -- the same line `SendAddrV2` draws for
BIP155's placement rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import override

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.limits import (
    MAX_FEATUREDATA_LENGTH,
    MAX_FEATUREID_LENGTH,
    MIN_FEATUREID_LENGTH,
)
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "Feature",
    "FeeFilter",
    "GetAddr",
    "Mempool",
    "SendHeaders",
    "SendTxRcncl",
    "WtxidRelay",
]

# the int64_t BIP133 defines the message as containing, whose eight
# octets the wiki page the module docstring cites publishes
_FEERATE_SIZE = 8

# Core's CAmount is int64_t, and the message carries one: see the module
# docstring for why a negative fee rate is parsed rather than refused
_MIN_INT64 = -(1 << (8 * _FEERATE_SIZE - 1))
_MAX_INT64 = (1 << (8 * _FEERATE_SIZE - 1)) - 1

# BIP330's sendtxrcncl fields, both unsigned: `uint32 version` and
# `uint64 salt`, in that order -- see the module docstring for why
# neither bound below refuses a value BIP330 and Core parse
_RECON_VERSION_SIZE = 4
_SALT_SIZE = 8

_MAX_RECON_VERSION = (1 << (8 * _RECON_VERSION_SIZE)) - 1
_MAX_SALT = (1 << (8 * _SALT_SIZE)) - 1


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


@dataclass(frozen=True)
class SendTxRcncl(Payload):
    """The `sendtxrcncl` message: this peer would reconcile, not announce.

    BIP330, and Bitcoin Core's `msg_sendtxrcncl`: a `uint32` protocol
    version and a `uint64` salt, this peer's half of the entropy the two
    sides combine -- `TaggedHash("Tx Relay Salting", salt1, salt2)`, the
    lower salt first -- to key the short transaction IDs a reconciliation
    round exchanges. The module docstring has the whole of what this
    message is the negotiation for and is not the codec of.

    `version` is 1 for every peer running the protocol BIP330 and
    `node/txreconciliation.h` describe today, and this class does not
    enforce that: a version below 1 is what Core's
    `TxReconciliationTracker::RegisterPeer` calls a protocol violation,
    after comparing the two peers' versions against each other, which
    this codec never sees. `salt` is entropy, and every value its width
    holds is one a peer may have chosen.

    Frozen and hashable, both fields being immutable.
    """

    command = "sendtxrcncl"

    version: int
    salt: int

    def __init__(
        self, version: int = 0, salt: int = 0, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "salt", salt)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a field no unsigned wire value of its own width holds."""
        # a bool is an int and would read as the field one or zero, which
        # the range check cannot tell from a value that is one or zero
        if not is_integer(self.version):
            err_msg = f"invalid version type: {type(self.version).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.version <= _MAX_RECON_VERSION:
            raise BTClibValueError(f"invalid version: {self.version}")

        if not is_integer(self.salt):
            err_msg = f"invalid salt type: {type(self.salt).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.salt <= _MAX_SALT:
            raise BTClibValueError(f"invalid salt: {self.salt}")

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the version and the salt, both little-endian."""
        if check_validity:
            self.assert_valid()

        out = self.version.to_bytes(
            _RECON_VERSION_SIZE, byteorder="little", signed=False
        )
        out += self.salt.to_bytes(_SALT_SIZE, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[SendTxRcncl], data: BinaryData, *, check_validity: bool = True
    ) -> SendTxRcncl:
        """Return the version and the salt the twelve octets carry."""
        stream = bytesio_from_binarydata(data)

        version = int.from_bytes(
            read_exactly(stream, _RECON_VERSION_SIZE, "sendtxrcncl version"),
            byteorder="little",
            signed=False,
        )
        salt = int.from_bytes(
            read_exactly(stream, _SALT_SIZE, "sendtxrcncl salt"),
            byteorder="little",
            signed=False,
        )
        assert_no_trailing(data, stream, "sendtxrcncl payload")

        return cls(version, salt, check_validity=check_validity)


@dataclass(frozen=True)
class Feature(Payload):
    """The `feature` message: a feature this peer supports, and its data.

    BIP434, and Bitcoin Core's `msg_feature`: a `featureid` and a
    `featuredata`, each a length and that many octets. The identifier is
    what the feature is negotiated under -- the BIP number for one
    published as a BIP, "some other unique identifier" such as a URL or
    a digest for one that is not -- and the data is whatever that
    feature's own specification puts there, empty where it wants none.

    `feature_id` has no default, as `Message`'s command and
    `CmpctBlock`'s header have none: an identifier is the whole of what
    this message says, so an object without one could not be valid.

    `feature_id` is octets and not text, as `Version.user_agent` is.
    BIP434 asks for printable ASCII with a SHOULD rather than a MUST,
    and Core's `p2p_bip434_feature.py` asserts a node accepts an
    identifier that is not -- `test_non_ascii_feature_id_accepted` -- so
    decoding here would refuse a message Core answers. A caller that
    wants to show one decodes it, with the error handling it wants.

    Both lengths are refused rather than parsed, which is the opposite
    of what `FeeFilter` does with the money range: BIP434 writes them as
    a MUST on the encoding and Core answers a payload outside them with
    a disconnect, where `MoneyRange` is asked about a value already
    read. `btclib.p2p.limits` holds the numbers and the citation.

    Frozen and hashable, both fields being immutable.
    """

    command = "feature"

    feature_id: bytes
    feature_data: bytes

    def __init__(
        self,
        feature_id: Octets,
        feature_data: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "feature_id", bytes_from_octets(feature_id))
        object.__setattr__(self, "feature_data", bytes_from_octets(feature_data))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse an identifier or a payload BIP434's lengths exclude."""
        if not MIN_FEATUREID_LENGTH <= len(self.feature_id) <= MAX_FEATUREID_LENGTH:
            err_msg = f"invalid feature id length: {len(self.feature_id)}"
            err_msg += f" instead of {MIN_FEATUREID_LENGTH}"
            err_msg += f" to {MAX_FEATUREID_LENGTH} bytes"
            raise BTClibValueError(err_msg)

        if len(self.feature_data) > MAX_FEATUREDATA_LENGTH:
            err_msg = f"invalid feature data length: {len(self.feature_data)}"
            err_msg += f" instead of at most {MAX_FEATUREDATA_LENGTH} bytes"
            raise BTClibValueError(err_msg)

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the identifier and the data, each behind its length."""
        if check_validity:
            self.assert_valid()

        return var_bytes.serialize(self.feature_id) + var_bytes.serialize(
            self.feature_data
        )

    @classmethod
    def parse(
        cls: type[Feature], data: BinaryData, *, check_validity: bool = True
    ) -> Feature:
        """Return the identifier and the data the two fields carry."""
        stream = bytesio_from_binarydata(data)

        feature_id = var_bytes.parse(stream)
        feature_data = var_bytes.parse(stream)
        assert_no_trailing(data, stream, "feature payload")

        return cls(feature_id, feature_data, check_validity=check_validity)
