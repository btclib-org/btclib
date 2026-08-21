# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP152's four messages, and the block a compact one is put back into.

`sendcmpct` negotiates, `cmpctblock` announces a block as a header and a
vector of six-octet short ids, and `getblocktxn`/`blocktxn` are the round
trip that fills what the receiver had not got. BIP152 is the
specification and its field tables are the wire form; Core's
src/blockencodings.h and .cpp are the implementation, and its
test/functional/test_framework/messages.py's `msg_sendcmpct`,
`msg_cmpctblock`, `msg_getblocktxn` and `msg_blocktxn` the layout.

**This is the one module of the package that carries an algorithm**, and
the algorithm rather than the layout is where a compact block goes wrong:
an encoder and a decoder that agree with each other and disagree with
every peer is what a format built out of a keyed hash and a differential
encoding invites, and no round-trip test can see it. So each of the three
pieces below says where its answer comes from.

**The short id key is derived per message, from the header and the
nonce.** BIP152: single-SHA256 of the block header serialization with the
nonce appended little-endian, and "the first two little-endian 64-bit
integers from the above hash" are the SipHash-2-4 key. Core's
`CBlockHeaderAndShortTxIDs::FillShortTxIDSelector` is those three lines,
`shorttxidhash.GetUint64(0)` and `GetUint64(1)` being the two words.
`short_id_key` is the pair, and `btclib.hashes.siphash` takes exactly it.

**A short id is the low 48 bits of the siphash of a wtxid**, not of a
transaction id, and the octets hashed are the hash in its internal order:
Core's `GetShortID` hashes `wtxid.ToUint256()`, which is what `Wtxid`
serializes, and this package holds every hash in the order a block
explorer prints -- so `short_id` reverses what it is handed, as
everything else here reverses on the wire. Getting either of the two
wrong produces a library that reconstructs its own blocks and no peer's,
which is why the vectors are a mainnet block already in the tree with its
short ids computed a second way.

**Every index is differentially encoded**, in `prefilledtxn` and in
`getblocktxn` alike: BIP152 writes "the difference between the current
index and the previous index, minus one", so a first index of 0 is index
0 and a second 0 after it is index 1. The fields below hold the
**absolute** index, which is what BIP152's own Purpose column says the
field is -- "The index into the block at which this transaction is" --
and the difference is taken and undone in `serialize` and `parse`. The
alternative, holding the wire's own value, is what Core's
`PrefilledTransaction::index` does, and its comment is the reason not to:
"Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
as a proper transaction-in-block-index in PartiallyDownloadedBlock" --
one field, two meanings, told apart by which object is holding it.
Nothing is lost by storing the absolute index: over indexes that
strictly increase the two are the same sequence written twice, so the
octets round-trip either way. btclib_node holds the wire's value and
never undoes the difference, which is a decoder that agrees with its own
encoder and with nothing else (btclib_node issue #20).

**Version 2 alone is implemented, and version 1 is not.** The two differ
in one field and one hash: version 2 writes the transactions inside
`cmpctblock` and `blocktxn` with their witnesses, "using the same format
as responses to getdata MSG_WITNESS_TX", and computes short ids over the
wtxid where version 1 computes them over the txid. Core's
`CMPCTBLOCKS_VERSION` is 2 and `ProcessMessage` answers a `sendcmpct` of
any other version by ignoring it -- `if (sendcmpct_version !=
CMPCTBLOCKS_VERSION) return;` -- so version 1 is a dialect no current
peer will speak, and offering it would be the library offering what no
peer accepts.

What that costs is less than it reads, and saying so is the honest half
of the decision. A version 1 message's octets still round-trip here
unchanged, because a version 1 sender writes no witness and
`Tx.serialize(include_witness=True)` writes none either where there is
none to write -- the marker goes in only when a witness follows it, so
the two encodings are the same octets for every transaction a version 1
peer sends. There is therefore no `include_witness` field here, where
`btclib.p2p.data` has one on `tx` and `block`: there the two encodings
are both live today, `MSG_TX` and `MSG_WITNESS_TX` being two things a
peer may ask for, and here the stripped one belongs to a version Core no
longer speaks. And `short_id` takes a hash rather than a transaction, so
the version 1 derivation is the same method over `Tx.id` for a caller who
has a use for it: the derivation is one, and which hash goes into it is
the version's to say.

**Reconstruction is a module function and not a payload method**, and
what it answers with when the pool is short is a list of indexes rather
than an exception. `reconstruct` takes a compact block and a pool of
candidate transactions and returns a `PartialBlock`, whose
`missing_indexes` is exactly what a `getblocktxn` is built from and whose
`fill` takes the `blocktxn` that answers it. Putting it on `CmpctBlock`
was the other shape and is refused: every method of a payload type in
this package is about the payload's own octets, and matching a mempool
against a block is not serialization -- it is the one thing here that
takes something the message did not carry. Core splits it the same way
and in the same two steps, `PartiallyDownloadedBlock::InitData` and
`::FillBlock`; the class here is not called partially *downloaded*,
which is a word for a package that opens no socket.

**Short ids collide, and the two collisions are two different answers.**
A `cmpctblock` whose own short ids are not unique cannot be reconstructed
at all -- there is no index to ask for, because two positions want one
transaction -- so `reconstruct` refuses it and BIP152's answer is to
re-request the block. Core's is `if (shorttxids.size() !=
cmpctblock.shorttxids.size()) return READ_STATUS_FAILED; // Short ID
collision`. That refusal is `reconstruct`'s and not `assert_valid`'s: a
message whose short ids collide is a message a peer legitimately sends,
BIP152 saying that nodes "MUST NOT be penalized for such collisions", so
it has to parse and serialize back. The other collision is two *pool*
transactions answering one short id, and there the answer is that the
index stays missing and is requested -- Core drops both and says why,
"eating a round-trip due to FillBlock failure would be annoying". A
reconstructor that takes the first match instead is wrong in a way its
own tests cannot see.

**The bound is one number under two roles, which is Core's own
spelling.** `limits.MAX_BLOCK_TX_INDEX` bounds the count in front of
every vector here and the value of every index, because Core writes
`std::numeric_limits<uint16_t>::max()` at both: once in
`CBlockHeaderAndShortTxIDs`'s deserializer, which throws "indexes
overflowed 16 bits" on a `BlockTxCount()` past it, and once in
`DifferenceFormatter::Unser`, which throws "differential value overflow"
on an index past it. Core applies a second bound in `InitData`,
`MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT`, and it is not
published here because it is the weaker of the two and would be a dead
constant: a hundred thousand is more than sixteen bits hold.

**What no message here is refused for** is worth naming, each being a
rule about a peer rather than about octets. A `getblocktxn` with an empty
index vector is a peer Core disconnects -- "No legitimate reason to send
indexes empty" -- and is a well-formed message. A `sendcmpct` naming a
version this library does not speak is the whole point of the field, and
is read and written unchanged. And whether a `blocktxn` answers the
`getblocktxn` that was sent is a question about a connection, which this
package does not hold.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import siphash

# the thirty-two octets of a hash256 and the two checks over them, which
# is one fact for this package and lives where the first module needing
# it put them, as `btclib.p2p.block_filters` imports the same three
from btclib.p2p.inventory import _HASH_SIZE, _assert_valid_hash, _sequence_of
from btclib.p2p.limits import MAX_BLOCK_TX_INDEX
from btclib.p2p.payload import Payload
from btclib.tx.tx import Tx
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "CMPCTBLOCKS_VERSION",
    "BlockTxn",
    "CmpctBlock",
    "GetBlockTxn",
    "PartialBlock",
    "PrefilledTransaction",
    "SendCmpct",
    "reconstruct",
]

# The compact block encoding this module implements, Core's name for it
# and Core's value: `inline constexpr uint64_t CMPCTBLOCKS_VERSION{2}` of
# src/net_processing.h, which is the only version its `ProcessMessage`
# does not ignore. The module docstring has what version 1 would be and
# why it is not here.
CMPCTBLOCKS_VERSION = 2

# BIP152's fixed-width fields: the eight octets of a nonce, the six of a
# short id, and the eight of the version a `sendcmpct` names. The eighty
# of a header are `BlockHeader`'s and the thirty-two of a hash are
# `_HASH_SIZE`, imported above
_NONCE_SIZE = 8
_SHORT_ID_SIZE = 6
_VERSION_SIZE = 8

_MAX_NONCE = (1 << (8 * _NONCE_SIZE)) - 1
_MAX_SHORT_ID = (1 << (8 * _SHORT_ID_SIZE)) - 1
_MAX_VERSION = (1 << (8 * _VERSION_SIZE)) - 1

# what a first index is measured from: BIP152's differential encoding is
# "the difference between the current index and the previous index, minus
# one", so the value in front of the first index is the one that makes a
# written zero mean index zero
_NO_PREVIOUS_INDEX = -1


def _assert_valid_index(index: int, what: str) -> None:
    """Refuse an index sixteen bits do not hold.

    Private and unvalidated of `what`, as a private twin is: every caller
    hands it a literal of this module.
    """
    # a bool is an int and would read as index one or zero, which the
    # range check below cannot tell from an index whose value that is
    if not is_integer(index):
        raise BTClibTypeError(f"invalid {what} type: {type(index).__name__}")
    if not 0 <= index <= MAX_BLOCK_TX_INDEX:
        raise BTClibValueError(f"invalid {what}: {index}")


def _assert_previous_index(previous_index: int) -> None:
    """Refuse what no index of a preceding entry could be.

    One below zero is the value in front of a first entry and is the only
    negative one there is; the top is an index's own, a previous entry
    being an entry.
    """
    if not is_integer(previous_index):
        err_msg = f"invalid previous_index type: {type(previous_index).__name__}"
        raise BTClibTypeError(err_msg)
    if not _NO_PREVIOUS_INDEX <= previous_index <= MAX_BLOCK_TX_INDEX:
        raise BTClibValueError(f"invalid previous_index: {previous_index}")


def _assert_increasing(indexes: Sequence[int], what: str) -> None:
    """Refuse indexes the differential encoding could not write.

    `DifferenceFormatter::Ser` throws "differential value overflow" on a
    value not past the last, the difference it writes being unsigned:
    indexes that do not strictly increase are a vector this library can
    read back but not send, so they are refused where a caller builds one
    rather than where it is written.
    """
    previous = _NO_PREVIOUS_INDEX
    for index in indexes:
        if index <= previous:
            err_msg = f"{what} out of order: {index} after {previous}"
            raise BTClibValueError(err_msg)
        previous = index


def _assert_valid_count(count: int, what: str) -> None:
    """Refuse a vector longer than a block's transaction count can be."""
    if count > MAX_BLOCK_TX_INDEX:
        err_msg = f"invalid {what} count: {count}"
        err_msg += f" instead of at most {MAX_BLOCK_TX_INDEX}"
        raise BTClibValueError(err_msg)


def _short_id(key: tuple[int, int], wtxid: Octets) -> int:
    """Return BIP152's second and third steps over one hash, under a key.

    Written once because it is asked for twice: `CmpctBlock.short_id` is
    a caller's way in and derives the key for itself, and `reconstruct`
    derives the key once and then asks this of every transaction of a
    pool -- which for a real mempool is the header re-serialized and
    re-hashed tens of thousands of times if the two share the method
    rather than the derivation.

    The key is not cached on the message instead, and that is the reason
    for a function rather than a `cached_property`: `BlockHeader` is a
    mutable dataclass, so a pair cached off one would go on answering
    after a caller changed the header it was taken from.
    """
    k0, k1 = key
    digest = siphash(k0, k1, bytes_from_octets(wtxid, _HASH_SIZE)[::-1])
    return digest & _MAX_SHORT_ID


def _assert_valid_transaction(tx: Tx, what: str) -> None:
    """Refuse what is no transaction, and no valid transaction."""
    if not isinstance(tx, Tx):
        raise BTClibTypeError(f"invalid {what} type: {type(tx).__name__}")
    tx.assert_valid()


def _assert_positions(prefilled: Sequence[PrefilledTransaction], count: int) -> None:
    """Refuse prefilled indexes that do not name positions of the block.

    The three rules Core's `InitData` applies to the prefilled vector,
    which are two here because the third follows from the others. Core
    checks, for the i-th prefilled transaction, that its index is at most
    `shorttxids.size() + i`; over indexes that strictly increase that is
    the same as asking it of the last one alone, since the i-th is at
    least `count - 1 - (last - i)` below the last. So what is left is
    that the indexes increase and that the last of them is inside the
    block, and both are checked over the whole vector rather than one
    entry at a time.

    Core does this in `InitData` and not in its deserializer, having no
    index map to build while reading; here it is what `assert_valid`
    asks, so that a `cmpctblock` naming a position no transaction can
    occupy is refused where it is read rather than where it is used.
    """
    _assert_increasing([prefilled_tx.index for prefilled_tx in prefilled], "prefilled")
    if prefilled and prefilled[-1].index >= count:
        err_msg = f"prefilled index past the block: {prefilled[-1].index}"
        err_msg += f" of {count} transactions"
        raise BTClibValueError(err_msg)


@dataclass(frozen=True)
class SendCmpct(Payload):
    """The `sendcmpct` message: whether to announce, and in which version.

    Bitcoin Core's `msg_sendcmpct`: one octet read as a boolean and eight
    of version, little-endian. `announce` set is BIP152's high-bandwidth
    mode, "the node SHOULD announce new blocks by sending a cmpctblock
    message"; cleared is the low-bandwidth mode, where blocks are
    announced with `inv` or `headers` and a compact one is asked for.

    `version` defaults to `CMPCTBLOCKS_VERSION`, which is the encoding
    this module implements and the only one Core answers to -- and the
    field is written and read unchanged whatever it says, that being what
    it is for: BIP152 negotiates by each side naming the versions it will
    speak, so a message naming a version this library does not is a
    message it must still be able to read.

    Frozen and hashable, both fields being immutable.
    """

    command = "sendcmpct"

    announce: bool
    version: int

    def __init__(
        self,
        announce: bool = False,
        version: int = CMPCTBLOCKS_VERSION,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "announce", announce)
        object.__setattr__(self, "version", version)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a non-bool announce, or a version no eight octets hold."""
        # a kind and not a truth: it decides which of two octets is
        # written, so `"no"` would write the one that asks a peer to
        # push every new block
        assert_type(self.announce, bool, "announce")

        # a bool is an int and would read as version one or zero, which
        # the range check cannot tell from a version whose value that is
        if not is_integer(self.version):
            err_msg = f"invalid version type: {type(self.version).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.version <= _MAX_VERSION:
            raise BTClibValueError(f"invalid version: {self.version}")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the announce octet, then the eight of the version."""
        if check_validity:
            self.assert_valid()

        out = int(self.announce).to_bytes(1, byteorder="little")
        out += self.version.to_bytes(_VERSION_SIZE, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[SendCmpct], data: BinaryData, *, check_validity: bool = True
    ) -> SendCmpct:
        """Return what the peer announced, the first octet being one or zero.

        BIP152: the first integer "SHALL be interpreted as a boolean (and
        MUST have a value of either 1 or 0)", so anything else is refused
        rather than read as true. Core reads the octet through its own
        `bool` deserialization, which takes any non-zero value and
        cannot write back what it read either; refusing is the reading
        that keeps the octets a caller sends the octets that arrived.
        """
        stream = bytesio_from_binarydata(data)

        announce = read_exactly(stream, 1, "announce")[0]
        if announce > 1:
            raise BTClibValueError(f"invalid announce octet: {announce}")
        version = int.from_bytes(
            read_exactly(stream, _VERSION_SIZE, "version"),
            byteorder="little",
            signed=False,
        )
        assert_no_trailing(data, stream, "sendcmpct payload")

        return cls(
            announce=bool(announce), version=version, check_validity=check_validity
        )


@dataclass(frozen=True)
class PrefilledTransaction:
    """One transaction a `cmpctblock` carries whole, and where it belongs.

    BIP152's PrefilledTransaction and Core's struct of that name: an
    index and the transaction at it. The sender puts here what it expects
    the receiver has not got -- always the coinbase, which is in no
    mempool, and "a select few which we expect a peer may be missing".

    `index` is the **absolute** index into the block, which is BIP152's
    own description of the field; the wire carries the difference from
    the previous one, minus one, and `previous_index` is what `serialize`
    and `parse` take that difference against. `_NO_PREVIOUS_INDEX` is its
    default and is what makes a standalone one the first of a list: a
    written zero is index zero. The module docstring is where holding the
    absolute index rather than the wire's own is argued.

    Not a `Payload`: no command carries a prefilled transaction on its
    own, `cmpctblock` being the message and this a structure inside it.

    Frozen, and not hashable: `Tx` is a mutable dataclass, so the field
    cannot be hashed and `dataclasses.replace` is what moves one.
    """

    index: int
    tx: Tx

    def __init__(self, index: int, tx: Tx, *, check_validity: bool = True) -> None:
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "tx", tx)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse an index sixteen bits do not hold, and what is no valid tx."""
        _assert_valid_index(self.index, "index")
        _assert_valid_transaction(self.tx, "tx")

    def serialize(
        self,
        previous_index: int = _NO_PREVIOUS_INDEX,
        *,
        check_validity: bool = True,
    ) -> bytes:
        """Return the difference from the previous index, then the transaction.

        The transaction is written with its witness, BIP152 version 2's
        "same format as responses to getdata MSG_WITNESS_TX" -- which for
        a transaction that has no witness is the same octets version 1
        would have written, the marker going in only where there is
        something to mark.
        """
        if check_validity:
            self.assert_valid()

        _assert_previous_index(previous_index)
        difference = self.index - previous_index - 1
        if difference < 0:
            err_msg = f"index {self.index} not past previous_index {previous_index}"
            raise BTClibValueError(err_msg)

        out = var_int.serialize(difference)
        out += self.tx.serialize(include_witness=True, check_validity=check_validity)
        return out

    @classmethod
    def parse(
        cls: type[PrefilledTransaction],
        data: BinaryData,
        previous_index: int = _NO_PREVIOUS_INDEX,
        *,
        check_validity: bool = True,
    ) -> PrefilledTransaction:
        """Return the transaction and the index the difference names.

        The difference is bounded before it is added, and the sum after:
        both are `MAX_BLOCK_TX_INDEX`, which is what Core's
        `DifferenceFormatter::Unser` refuses a running index past.
        """
        stream = bytesio_from_binarydata(data)
        _assert_previous_index(previous_index)

        difference = var_int.parse(stream, MAX_BLOCK_TX_INDEX)
        index = previous_index + 1 + difference
        _assert_valid_index(index, "index")
        tx = Tx.parse(stream, check_validity=check_validity)
        assert_no_trailing(data, stream, "prefilled transaction")

        return cls(index, tx, check_validity=check_validity)


@dataclass(frozen=True)
class CmpctBlock(Payload):
    """The `cmpctblock` message: a header, short ids, and a few transactions.

    BIP152's HeaderAndShortIDs, which is the whole of the payload -- so
    there is one class here and not a message wrapping a structure, as
    there is for `getblocktxn` and `blocktxn` too. Core's
    `CBlockHeaderAndShortTxIDs` is the same five fields, the two vector
    lengths being what `var_int` writes rather than fields of their own.

    `short_ids` are the six-octet integers of the transactions the sender
    expects the receiver to have, in block order with the prefilled
    positions taken out; `prefilled_txns` are the ones it sends whole.
    Together they are the block: `tx_count` is their sum, which is
    BIP152's "block tx count" read off either vector.

    `short_id` is the derivation the ids come from and `short_id_key` the
    key it runs under, both of them functions of the header and the nonce
    and therefore of this message alone. The module docstring is where
    the derivation is stated and where what a wrong one would cost is.

    Frozen, and not hashable: a `PrefilledTransaction` holds a mutable
    `Tx`. `dataclasses.replace` is what changes a vector.
    """

    command = "cmpctblock"

    header: BlockHeader
    nonce: int
    short_ids: tuple[int, ...]
    prefilled_txns: tuple[PrefilledTransaction, ...]

    def __init__(
        self,
        header: BlockHeader,
        nonce: int = 0,
        short_ids: Sequence[int] = (),
        prefilled_txns: Sequence[PrefilledTransaction] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "header", header)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(
            self, "short_ids", tuple(_sequence_of(short_ids, "short_ids"))
        )
        object.__setattr__(
            self,
            "prefilled_txns",
            tuple(_sequence_of(prefilled_txns, "prefilled_txns")),
        )

        if check_validity:
            self.assert_valid()

    @property
    def tx_count(self) -> int:
        """Return how many transactions the block this announces holds.

        Core's `BlockTxCount()`, and BIP152's own arithmetic read off
        either vector: shortids_length is "block tx count -
        prefilledtxn_length", so the two vectors partition the block.
        """
        return len(self.short_ids) + len(self.prefilled_txns)

    @property
    def short_id_key(self) -> tuple[int, int]:
        """Return the (k0, k1) the short ids of this message are keyed on.

        BIP152: single-SHA256 of the header serialization with the nonce
        appended little-endian, and the first two little-endian 64-bit
        integers of it. Core's `FillShortTxIDSelector` is these lines,
        and the pair is what `btclib.hashes.siphash` takes.

        Per message and not per block: the nonce is in the digest, so two
        senders announcing one block under two nonces produce two sets of
        short ids, which is what BIP152 asks for -- "Nodes SHOULD NOT use
        the same nonce across multiple different blocks" -- so that a
        collision is one peer's and not the network's.
        """
        preimage = self.header.serialize(check_validity=False)
        preimage += self.nonce.to_bytes(_NONCE_SIZE, byteorder="little", signed=False)
        digest = hashlib.sha256(preimage).digest()
        k0 = int.from_bytes(digest[:8], byteorder="little", signed=False)
        k1 = int.from_bytes(digest[8:16], byteorder="little", signed=False)
        return k0, k1

    def short_id(self, wtxid: Octets) -> int:
        """Return the six-octet short id this message would carry for a hash.

        The hash is a wtxid in BIP152 version 2, `Tx.hash`, and it is
        taken in the order this package holds every hash in -- the order
        a block explorer prints -- and reversed here, Core hashing the
        `uint256` its own way round. What comes back is the siphash with
        its two most significant octets dropped, BIP152's step three.

        A hash and not a transaction, which is what leaves version 1
        reachable without being offered: the same derivation over `Tx.id`
        is the version 1 short id, and which of the two hashes goes in is
        the negotiated version's to say rather than this method's.
        """
        return _short_id(self.short_id_key, wtxid)

    def assert_valid(self) -> None:
        """Refuse a header, a nonce, a short id or an index the fields lack."""
        if not isinstance(self.header, BlockHeader):
            err_msg = f"invalid header type: {type(self.header).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        self.header.assert_valid()

        # a bool is an int and would read as the nonce one or zero, which
        # the range check cannot tell from a nonce whose value that is
        if not is_integer(self.nonce):
            raise BTClibTypeError(f"invalid nonce type: {type(self.nonce).__name__}")
        if not 0 <= self.nonce <= _MAX_NONCE:
            raise BTClibValueError(f"invalid nonce: {self.nonce}")

        for short_id in self.short_ids:
            if not is_integer(short_id):
                err_msg = f"invalid short id type: {type(short_id).__name__}"
                raise BTClibTypeError(err_msg)
            if not 0 <= short_id <= _MAX_SHORT_ID:
                raise BTClibValueError(f"invalid short id: {short_id}")

        for prefilled_tx in self.prefilled_txns:
            if not isinstance(prefilled_tx, PrefilledTransaction):
                err_msg = "invalid prefilled transaction type: "  # type: ignore[unreachable]
                err_msg += type(prefilled_tx).__name__
                raise BTClibTypeError(err_msg)
            prefilled_tx.assert_valid()

        # Core's own check, on the sum rather than on either vector:
        # "indexes overflowed 16 bits", thrown while reading
        _assert_valid_count(self.tx_count, "transaction")
        _assert_positions(self.prefilled_txns, self.tx_count)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the header, the nonce, then the two vectors."""
        if check_validity:
            self.assert_valid()

        out = self.header.serialize(check_validity=check_validity)
        out += self.nonce.to_bytes(_NONCE_SIZE, byteorder="little", signed=False)
        out += var_int.serialize(len(self.short_ids))
        for short_id in self.short_ids:
            out += short_id.to_bytes(_SHORT_ID_SIZE, byteorder="little", signed=False)
        out += var_int.serialize(len(self.prefilled_txns))
        previous_index = _NO_PREVIOUS_INDEX
        for prefilled_tx in self.prefilled_txns:
            out += prefilled_tx.serialize(previous_index, check_validity=check_validity)
            previous_index = prefilled_tx.index
        return out

    @classmethod
    def parse(
        cls: type[CmpctBlock], data: BinaryData, *, check_validity: bool = True
    ) -> CmpctBlock:
        """Return the block this announces, both counts bounded first.

        Each vector's length is read against `MAX_BLOCK_TX_INDEX` before
        the loop that allocates on it, btclib's `var_int.parse` allowing
        33,554,432 of anything; the sum is what `assert_valid` holds to
        the same bound afterwards, which is where Core checks it too.
        """
        stream = bytesio_from_binarydata(data)

        header = BlockHeader.parse(stream, check_validity=check_validity)
        nonce = int.from_bytes(
            read_exactly(stream, _NONCE_SIZE, "nonce"),
            byteorder="little",
            signed=False,
        )

        count = var_int.parse(stream, MAX_BLOCK_TX_INDEX)
        short_ids = [
            int.from_bytes(
                read_exactly(stream, _SHORT_ID_SIZE, "short id"),
                byteorder="little",
                signed=False,
            )
            for _ in range(count)
        ]

        count = var_int.parse(stream, MAX_BLOCK_TX_INDEX)
        prefilled_txns = []
        previous_index = _NO_PREVIOUS_INDEX
        for _ in range(count):
            prefilled_tx = PrefilledTransaction.parse(
                stream, previous_index, check_validity=check_validity
            )
            prefilled_txns.append(prefilled_tx)
            previous_index = prefilled_tx.index
        assert_no_trailing(data, stream, "cmpctblock payload")

        return cls(
            header, nonce, short_ids, prefilled_txns, check_validity=check_validity
        )


@dataclass(frozen=True)
class GetBlockTxn(Payload):
    """The `getblocktxn` message: which transactions of a block are wanted.

    BIP152's BlockTransactionsRequest and Core's class of that name: the
    block hash and the indexes, differentially encoded. `block_hash` is
    in display order, `BlockHeader.hash`'s; `indexes` are absolute, and
    the module docstring is where that is argued.

    What builds one is `PartialBlock.missing_indexes`, which is the list
    a reconstruction that came up short answers with -- `GetBlockTxn(
    partial.header.hash, partial.missing_indexes)` is the whole of it.

    An empty `indexes` is not refused: Core disconnects the peer that
    sends one -- "No legitimate reason to send indexes empty" -- which is
    a rule about a peer and not about a message, and this package holds
    none of the first kind.

    Frozen and hashable, every field being immutable.
    """

    command = "getblocktxn"

    block_hash: bytes
    indexes: tuple[int, ...]

    def __init__(
        self,
        block_hash: Octets = b"\x00" * _HASH_SIZE,
        indexes: Sequence[int] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "block_hash", bytes_from_octets(block_hash))
        object.__setattr__(self, "indexes", tuple(_sequence_of(indexes, "indexes")))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a hash, a count, or an index the differences cannot write."""
        _assert_valid_hash(self.block_hash, "block_hash length")

        _assert_valid_count(len(self.indexes), "indexes")
        for index in self.indexes:
            _assert_valid_index(index, "index")
        _assert_increasing(self.indexes, "indexes")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the block hash, the count, then the differences."""
        if check_validity:
            self.assert_valid()

        out = self.block_hash[::-1]
        out += var_int.serialize(len(self.indexes))
        previous_index = _NO_PREVIOUS_INDEX
        for index in self.indexes:
            out += var_int.serialize(index - previous_index - 1)
            previous_index = index
        return out

    @classmethod
    def parse(
        cls: type[GetBlockTxn], data: BinaryData, *, check_validity: bool = True
    ) -> GetBlockTxn:
        """Return the absolute indexes the differences name."""
        stream = bytesio_from_binarydata(data)

        block_hash = read_exactly(stream, _HASH_SIZE, "block hash")[::-1]
        count = var_int.parse(stream, MAX_BLOCK_TX_INDEX)
        indexes = []
        previous_index = _NO_PREVIOUS_INDEX
        for _ in range(count):
            index = previous_index + 1 + var_int.parse(stream, MAX_BLOCK_TX_INDEX)
            _assert_valid_index(index, "index")
            indexes.append(index)
            previous_index = index
        assert_no_trailing(data, stream, "getblocktxn payload")

        return cls(block_hash, indexes, check_validity=check_validity)


@dataclass(frozen=True)
class BlockTxn(Payload):
    """The `blocktxn` message: the transactions a `getblocktxn` asked for.

    BIP152's BlockTransactions and Core's class of that name: the block
    hash and the transactions, "exactly and only each transaction which
    is present in the appropriate block at the index specified in the
    getblocktxn indexes list, in the order requested". `block_hash` is in
    display order; the transactions are written with their witnesses,
    which is BIP152 version 2 and what the module docstring argues.

    That the transactions are the ones that were asked for is a property
    of a connection and not of these octets, so nothing here checks it:
    what does is `PartialBlock.fill`, which puts them in the positions
    the same reconstruction found missing and hands back a `Block` whose
    merkle root either commits to them or does not.

    Frozen, and not hashable: `Tx` is a mutable dataclass.
    """

    command = "blocktxn"

    block_hash: bytes
    transactions: tuple[Tx, ...]

    def __init__(
        self,
        block_hash: Octets = b"\x00" * _HASH_SIZE,
        transactions: Sequence[Tx] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "block_hash", bytes_from_octets(block_hash))
        object.__setattr__(
            self,
            "transactions",
            tuple(_sequence_of(transactions, "transactions")),
        )

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a hash, a count, or what is no valid transaction."""
        _assert_valid_hash(self.block_hash, "block_hash length")

        _assert_valid_count(len(self.transactions), "transactions")
        for tx in self.transactions:
            _assert_valid_transaction(tx, "transaction")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the block hash, the count, then the transactions."""
        if check_validity:
            self.assert_valid()

        out = self.block_hash[::-1]
        out += var_int.serialize(len(self.transactions))
        for tx in self.transactions:
            out += tx.serialize(include_witness=True, check_validity=check_validity)
        return out

    @classmethod
    def parse(
        cls: type[BlockTxn], data: BinaryData, *, check_validity: bool = True
    ) -> BlockTxn:
        """Return the transactions carried, the count bounded first."""
        stream = bytesio_from_binarydata(data)

        block_hash = read_exactly(stream, _HASH_SIZE, "block hash")[::-1]
        count = var_int.parse(stream, MAX_BLOCK_TX_INDEX)
        transactions = [
            Tx.parse(stream, check_validity=check_validity) for _ in range(count)
        ]
        assert_no_trailing(data, stream, "blocktxn payload")

        return cls(block_hash, transactions, check_validity=check_validity)


@dataclass(frozen=True)
class PartialBlock:
    """A block with the transactions found so far in it, and gaps for the rest.

    What `reconstruct` answers with, and Core's
    `PartiallyDownloadedBlock` without the word this package cannot use:
    the header, and one entry per transaction of the block, each either a
    transaction or `None`. `missing_indexes` is what is still wanted and
    `fill` is what finishes the block once it has arrived.

    Frozen, and not hashable: the entries are mutable `Tx` objects.
    """

    header: BlockHeader
    transactions: tuple[Tx | None, ...]

    def __init__(
        self,
        header: BlockHeader,
        transactions: Sequence[Tx | None] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "header", header)
        object.__setattr__(
            self,
            "transactions",
            tuple(_sequence_of(transactions, "transactions")),
        )

        if check_validity:
            self.assert_valid()

    @property
    def missing_indexes(self) -> list[int]:
        """Return the indexes of the transactions still wanted, in order.

        Exactly what a `getblocktxn` names, and in the order a `blocktxn`
        answers in: `GetBlockTxn(partial.header.hash,
        partial.missing_indexes)` is the request, and `fill` takes what
        comes back.

        A list rather than an exception, which is the whole of the
        decision `reconstruct` owes: a reconstruction that came up short
        has an answer worth having, and it is this one.
        """
        return [index for index, tx in enumerate(self.transactions) if tx is None]

    def assert_valid(self) -> None:
        """Refuse a header, or an entry that is no transaction and not None."""
        if not isinstance(self.header, BlockHeader):
            err_msg = f"invalid header type: {type(self.header).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        self.header.assert_valid()

        for tx in self.transactions:
            if tx is not None:
                _assert_valid_transaction(tx, "transaction")

    def fill(
        self, transactions: Sequence[Tx] = (), *, check_validity: bool = True
    ) -> Block:
        """Return the block, the gaps filled with the transactions supplied.

        `transactions` are a `blocktxn`'s, in the order
        `missing_indexes` asked for them, and there must be exactly as
        many: a shorter answer leaves a position empty and a longer one
        names a position nothing asked about, which is what Core's
        `FillBlock` refuses on both sides of its loop.

        What is *not* checked here is that they are the right
        transactions, and the block is where that shows: a short id
        collision that survived the pool puts a wrong transaction in a
        position, and the merkle root `Block.assert_valid` recomputes is
        what does not then commit to it -- Core reaches for the same
        answer, calling `IsBlockMutated` at the end of `FillBlock` and
        calling what it catches "Possible Short ID collision".

        `check_validity` is passed to `Block`, whose `assert_valid` is
        Core's `CheckBlock` with mainnet's target: a block of another
        network is built with it cleared and asked afterwards, which is
        the two steps `btclib.p2p.data`'s `BlockPayload` asks of a caller
        too.
        """
        supplied = _sequence_of(transactions, "transactions")
        missing = self.missing_indexes
        if len(supplied) != len(missing):
            err_msg = f"invalid transactions count: {len(supplied)}"
            err_msg += f" instead of the {len(missing)} still missing"
            raise BTClibValueError(err_msg)

        # built rather than patched in place, so that every entry is a
        # `Tx` and none of them an `Optional` mypy has to be told about:
        # the supplied ones are taken in order, which is the order
        # `missing_indexes` asked for them in
        supplied_iterator = iter(supplied)
        filled = [
            next(supplied_iterator) if tx is None else tx for tx in self.transactions
        ]

        return Block(self.header, filled, check_validity=check_validity)


def reconstruct(compact_block: CmpctBlock, pool: Sequence[Tx] = ()) -> PartialBlock:
    """Return the block a compact one and a pool of transactions make.

    The prefilled transactions go in the positions they name, and every
    short id is looked for among the pool; what is left over is
    `PartialBlock.missing_indexes`, which is what a `getblocktxn` asks
    for. Core's `PartiallyDownloadedBlock::InitData` is the same walk,
    over a mempool and an extra pool rather than over one sequence: which
    transactions are candidates is the caller's to decide, this package
    holding no mempool.

    The pool is matched by wtxid, `Tx.hash`, which is BIP152 version 2's
    short id input; the module docstring has why version 1 is not offered
    and what it would change.

    Two refusals, and they are BIP152's rather than this library's:

    - a compact block of no transactions is no block, there being no
      block without a coinbase. Core's `InitData` answers
      `READ_STATUS_INVALID` for it;
    - a compact block whose own short ids are not unique cannot be
      reconstructed, two positions wanting one transaction, and BIP152's
      answer is to ask for the block the ordinary way. Core's is
      `READ_STATUS_FAILED` with "Short ID collision" beside it. It is
      refused here and not in `CmpctBlock.assert_valid`, such a message
      being one a peer legitimately sends.

    A *pool* collision is the third case and is not a refusal: where two
    different transactions of the pool answer one short id, the position
    is left missing and is asked for, which is what Core does and why --
    "eating a round-trip due to FillBlock failure would be annoying".
    Taking the first match instead is the bug this shape exists to
    refuse.
    """
    count = compact_block.tx_count
    if not count:
        raise BTClibValueError("a compact block of no transactions")

    _assert_positions(compact_block.prefilled_txns, count)
    available: list[Tx | None] = [None] * count
    for prefilled_tx in compact_block.prefilled_txns:
        available[prefilled_tx.index] = prefilled_tx.tx

    short_ids = compact_block.short_ids
    if len(set(short_ids)) != len(short_ids):
        raise BTClibValueError("short ids are not unique: re-request the block")

    # the positions the short ids fill are the ones the prefilled
    # transactions left, in order: BIP152 says to place each "in the
    # first available position in the block"
    position_of = dict(
        zip(
            short_ids,
            (index for index in range(count) if available[index] is None),
            strict=True,
        )
    )

    # derived once for the whole pool: it is a function of the header
    # and the nonce, so `CmpctBlock.short_id` per transaction would be
    # one SHA-256 of the header per transaction of a mempool
    key = compact_block.short_id_key

    wtxid_of: dict[int, bytes] = {}
    collided: set[int] = set()
    for tx in pool:
        short_id = _short_id(key, tx.hash)
        if short_id not in position_of or short_id in collided:
            continue
        if short_id not in wtxid_of:
            wtxid_of[short_id] = tx.hash
            available[position_of[short_id]] = tx
        elif wtxid_of[short_id] != tx.hash:
            collided.add(short_id)
            available[position_of[short_id]] = None

    return PartialBlock(compact_block.header, available)
