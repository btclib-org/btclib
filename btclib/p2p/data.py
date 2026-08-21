# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`tx` and `block`: the two messages that deliver what a `getdata` named.

Bitcoin Core's `msg_tx` and `msg_block`, of
test/functional/test_framework/messages.py: one transaction and one
block, each serialized exactly as it is serialized anywhere else. So the
wire format is `btclib.tx`'s and `btclib.block`'s, and what is left for
this module is the one thing those two leave open.

**`include_witness` is a field of the payload, not an argument of
`serialize`.** `Tx.serialize` and `Block.serialize` take it, and on the
wire the answer is the connection's rather than the transaction's:
BIP144 gives it to the peer that negotiated `NODE_WITNESS`, and Core
answers a `getdata` for `MSG_TX` with the stripped encoding and one for
`MSG_WITNESS_TX` with the full one -- the same transaction, two
messages. Something in this package has to hold that answer, and the
three places it could go were:

- **a field of the payload**, which is what is below: a `tx` message is a
  transaction *and* the encoding chosen for it, `Payload.serialize` keeps
  the one signature every payload type here has, and `to_message` needs
  nothing new;
- **an argument of `serialize`**, which is the encoding supplied at the
  moment it is written. Refused: `Payload.serialize` is declared in
  `btclib.p2p.payload` because `to_message` calls it, so an argument here
  is an argument there too -- and then either `to_message` grows one for
  every payload type or these two override it, which is the uniformity
  that module was written to get;
- **always the witness**, on the grounds that `MSG_WTX` and BIP339 made
  witness-stripped relay the exception. Refused for what it cannot write:
  a peer that did not negotiate the witness is answered with the stripped
  encoding or not at all, so a payload without the flag is a library that
  cannot serve one.

**`parse` answers the flag from the object it just built, and the
asymmetry is here rather than left to be discovered.** BIP144's marker
and flag say whether a witness rode, and `Tx.parse` and `Block.parse`
already read them, so `is_segwit` is that answer without a second reader
of the same octets. What it cannot answer is which flag a sender held for
a transaction that has no witness: both write the same octets, the marker
being written only where there is something to mark, so `parse` says
`False` and a `TxPayload(tx, include_witness=True)` over a transaction
with no witness is a payload that parses back as `False`. The
*encoding* round-trips exactly either way, which is the property this
package keeps; the object round-trips exactly wherever the wire can tell
the two apart, and where it cannot there is nothing to keep.

BIP144's superfluous witness record -- a marker over witnesses that are
all empty -- is the encoding neither class could reproduce, and neither
has to: `Tx.parse` refuses it where it is read, as Core's
`UnserializeTransaction` does, so no payload here holds one (issue
#1104). It is `btclib.tx`'s answer and is not repeated here.

**The flag is stored as it was given, never reduced against the
object.** `include_witness=True` over a transaction with no witness could
be recorded as the `False` it will serialize as, and must not be: `Tx`
and `Block` are mutable dataclasses, so a flag reduced when the payload
was built is a flag that lies the moment a caller signs an input. It is
read where it is used, which is where `Tx.serialize` reads its own.

**`TxPayload` and `BlockPayload`, and the suffix is the point.** These
are the only payload types whose command names a class this library
already has, and `from btclib.p2p import Tx` shadowing `btclib.tx.Tx` is
a collision a caller pays for silently. btclib_node has it -- its
`p2p/messages/data.py` declares `Tx` and `Block` and imports btclib's as
`TxData` and `BlockData` -- and it is the reader of the two modules
together who cannot then say which is which.

**Nothing here bounds a message length.**
`btclib.p2p.limits.MAX_PROTOCOL_MESSAGE_LENGTH` is the envelope's,
checked off the header's length field before a payload is allocated and
again in `Message.assert_valid`, and a block satisfying
`btclib.block.limits.MAX_BLOCK_WEIGHT` is always under it: the weight is
`3 * stripped_size + size` and the stripped size is at least the header
and the transaction count, so `size` falls short of the cap by three
times that. The two constants hold the same number today and are not the
same constant, which is the coincidence `btclib.p2p.limits` exists to
keep from becoming an import; a second bound here would be a third place
for it to be wrong.

**Which encoding answers which request is the caller's**, as it is one
layer up: `Inventory.is_witness` reads BIP144's bit off a `getdata` entry
and this package holds no policy that turns it into a flag. Nothing here
refuses a `block` whose transactions carry witnesses to a peer that asked
for none, because nothing here knows what the peer asked.
"""

from __future__ import annotations

from dataclasses import dataclass

from btclib.alias import BinaryData
from btclib.block.block import Block
from btclib.exceptions import BTClibTypeError
from btclib.p2p.payload import Payload
from btclib.tx.tx import Tx
from btclib.utils import assert_type

__all__ = [
    "BlockPayload",
    "TxPayload",
]


@dataclass(frozen=True)
class TxPayload(Payload):
    """The `tx` message: one transaction, and the encoding chosen for it.

    Bitcoin Core's `msg_tx`. `tx` is the transaction and `include_witness`
    is what `Tx.serialize` takes -- BIP144's question, answered by the
    connection and held here so that `Payload.serialize` keeps one
    signature; the module docstring is where that is argued and where
    what `parse` can and cannot recover is written down.

    `include_witness` has no default, where `Block.serialize`'s has one:
    a message is written for a peer, and which encoding that peer
    negotiated is not a value this package can pick on its behalf.

    Frozen, and not hashable: `Tx` is a mutable dataclass, so the field
    cannot be hashed and `dataclasses.replace` is what re-encodes a
    payload for another peer.
    """

    command = "tx"

    tx: Tx
    include_witness: bool

    def __init__(
        self, tx: Tx, include_witness: bool, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "tx", tx)
        object.__setattr__(self, "include_witness", include_witness)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse what is no transaction, no bool, and no valid transaction."""
        if not isinstance(self.tx, Tx):
            err_msg = f"invalid tx type: {type(self.tx).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        # a kind and not a truth: it decides which of two serializations
        # is written, so `"no"` would answer the wire one where the
        # stripped one was meant -- a different transaction id
        assert_type(self.include_witness, bool, "include_witness")

        self.tx.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the transaction, witness or not as the field says."""
        if check_validity:
            self.assert_valid()

        return self.tx.serialize(self.include_witness, check_validity=check_validity)

    @classmethod
    def parse(
        cls: type[TxPayload], data: BinaryData, *, check_validity: bool = True
    ) -> TxPayload:
        """Return the transaction the payload carries, and how it was written.

        `Tx.parse` reads BIP144's marker, so `is_segwit` is what the
        octets said; the module docstring has what that answer cannot
        distinguish and why nothing here reads the marker a second time.
        """
        tx = Tx.parse(data, check_validity=check_validity)
        return cls(tx, tx.is_segwit, check_validity=check_validity)


@dataclass(frozen=True)
class BlockPayload(Payload):
    """The `block` message: one block, and the encoding chosen for it.

    Bitcoin Core's `msg_block`, and `TxPayload`'s two fields over a
    `Block`: a `getdata` for `MSG_BLOCK` is answered with every witness
    stripped and one for `MSG_WITNESS_BLOCK` with them, which is the same
    block written twice.

    `Block.assert_valid` is `CheckBlock`, proof of work included and
    mainnet's target by default, and it is what `assert_valid` here asks
    of the block: a `block` message of another network is built with
    `check_validity=False` and asked afterwards, which is the same two
    steps `Block.assert_valid` already asks of a caller holding one.

    Frozen, and not hashable, for the reason `TxPayload` is not.
    """

    command = "block"

    block: Block
    include_witness: bool

    def __init__(
        self, block: Block, include_witness: bool, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "block", block)
        object.__setattr__(self, "include_witness", include_witness)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse what is no block, no bool, and no valid block."""
        if not isinstance(self.block, Block):
            err_msg = f"invalid block type: {type(self.block).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        assert_type(self.include_witness, bool, "include_witness")

        self.block.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the block, its witnesses written or stripped."""
        if check_validity:
            self.assert_valid()

        return self.block.serialize(self.include_witness, check_validity=check_validity)

    @classmethod
    def parse(
        cls: type[BlockPayload], data: BinaryData, *, check_validity: bool = True
    ) -> BlockPayload:
        """Return the block the payload carries, and how it was written.

        `Block.is_segwit` is any transaction carrying a witness, which is
        exactly when `Block.serialize` writes a marker: the flag answers
        for the message the way each transaction's marker answers for
        itself.
        """
        block = Block.parse(data, check_validity=check_validity)
        return cls(block, block.is_segwit, check_validity=check_validity)
