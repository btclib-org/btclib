# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a payload type meets `Message`, decided here for every payload.

`btclib.p2p.message` knows no payload type and reads a command it has
never heard of exactly as it reads "version" (issue #1082). This module
is the other side of that: a payload is an ordinary btclib wire class --
`parse` reads it, `serialize` writes it -- that additionally knows *which
command carries it*, and `to_message` is the one line that puts the two
together.

Three shapes were open when this was written, and the other two are the
reason for the one above (issue #1098):

- **a registry mapping a command to its payload type**, so that
  `Message.parse` could hand back a typed payload. It is refused, and not
  narrowly: `message.py` would import every payload module -- `tx` and
  `block` among them once issue #1083's fourth child lands -- so an
  envelope would cost the whole library to parse, and an unrecognized
  command would stop being octets and start being an error. The envelope
  round-tripping what it does not recognize is the property that let it
  be written before any of this, and a table is what takes it away.
- **payload classes alone, with the caller writing the command**, which
  is btclib_node's shape: `add_headers("addr", payload)` is a string
  literal inside each `serialize`, and nothing anywhere compares it with
  the table the receiving side dispatches on. That is how `"sendcmpt"`
  and `"cmptblock"` -- both misspelled, both sent to the whole network --
  survive there. One constant per class, used by both directions, is the
  whole of the difference.

**There is no reverse of `to_message` here, and the asymmetry is the
decision rather than an omission.** Writing a message needs no table: the
payload knows its own command. Reading one back into a typed payload does
need a table, so the caller writes it -- `if message.command ==
Version.command: Version.parse(message.payload)` -- and what to do with a
command nobody wrote a branch for stays the caller's, as it is in Core,
where `net_processing.cpp` is a chain of `if (msg_type == ...)` and an
unknown type falls off the end. A `payload_from_message` here would be
that table under another name, in a package that would then hold one.

What this costs issue #1083's remaining children, which inherit it: each
of them writes one class per command rather than one entry in a table,
and none of them touches `message.py`. `tx` and `block` are thin wrappers
over classes that already parse and serialize themselves; `addrv2` is a
second address class beside the first rather than a flag on it; the
inventory and compact-block payloads are ordinary dataclasses. What none
of them gets for free is dispatch, which is the line above.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from btclib.alias import Octets
from btclib.p2p.message import Message

__all__ = [
    "Payload",
]


class Payload(ABC):
    """What a p2p message carries, and which command carries it.

    A subclass is a wire class of this library like any other -- a
    dataclass with `parse`, `serialize` and `assert_valid` -- plus
    `command`, the message type its octets travel under. `to_message`
    is what the pair buys: the command is read off the class instead of
    being written out at the call, so the name a payload serializes under
    and the name a caller matches on are one constant.

    `serialize` is declared here and `parse` is not, which is a fact about
    the two boundaries rather than an oversight. `to_message` calls
    `serialize`, so the contract has to be stated where it is called;
    `parse` is a classmethod every subclass declares for its own return
    type, and nothing here calls it -- this module's docstring is why
    there is no `from_message` to call it from.

    An ABC and not a `Protocol`: `to_message` is behaviour to inherit
    rather than a shape to match, and the subclasses are this package's
    own. `btclib.psbt_signer`'s `PsbtSigner` is the Protocol in this
    library, and it is one because its implementations are other
    people's.
    """

    # the message type these octets travel under, "version" or "ping":
    # `Message.command`'s value, and the one this class serializes into
    command: ClassVar[str]

    @abstractmethod
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the wire serialization of the payload alone.

        The payload and not the message: what the envelope's four header
        fields put in front of it is `to_message`'s, and a caller holding
        a `Message` already has these octets as `message.payload`.
        """

    def to_message(self, magic: Octets, *, check_validity: bool = True) -> Message:
        """Return this payload framed for a network, ready to send.

        `magic` is the four octets of the message start, which
        `btclib.p2p.magic` is where a caller gets and which this library
        holds no table of; `command` is the class's own, so the one thing
        a caller cannot get wrong here is the name the payload travels
        under.
        """
        return Message(
            magic,
            self.command,
            self.serialize(check_validity=check_validity),
            check_validity=check_validity,
        )
