# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP61's `reject`: what a peer refused, and why, and this library parses it.

Sent, per the BIP, in response to a `version`, a `tx` or a `block` that
the peer would not accept -- and not sent by Bitcoin Core, which removed
both directions of it in `bitcoin/bitcoin#15437`, merged 2019-10-09 and
first released in v0.20.0: the pull request's own words are "parsing of
reject messages... completely meaningless" and "the sending of reject
messages... a burden", `NetMsgType` naming no `REJECT` since. Core is
one peer among the ones that still speak this protocol, and an
implementation that has not followed it off the wire sends one all the
same -- this module is the parser side of BIP37's own line, issue
#1120's: what a peer sends is parsed, because parsing is not endorsing,
and nothing here constructs one to send.

**The common payload, and the hash the tx and block cases append to
it.** `message` names the command that provoked the reject -- "tx",
"block" or "version" -- `code` is BIP61's one-octet reason, and `reason`
is a human-readable string Core's own comment already called "for
debugging" and never for a caller to act on. A `tx` or a `block` reject
appends the 32-octet hash of what was refused; a `version` reject appends
nothing, which is the one place a naive parser reads the boundary wrong
-- the octets that follow `reason` are either exactly a hash or not there
at all, and `parse` refuses anything between the two.

**`message` and `reason` are `str`, decoded as BIP61's own `var_str`
names them rather than held as `user_agent`'s raw octets are.** The two
are not the same decision for the same reason to differ: `handshake.py`
keeps `user_agent` undecoded because Core itself sends arbitrary bytes in
it today and a refusal here would refuse a message Core accepts. Core
sends no `reject` at all any more, so there is no live sender this parser
must not refuse, and `message` is structurally the same field
`Message.command` already is -- a command name, ASCII in every
implementation that still emits one, decoded the same way. A peer whose
octets are not valid UTF-8 is refused rather than handed back as bytes a
caller has to decode with its own error handling.

**`code` is `RejectCode` where a member names it and the plain `int`
where none does**, the same reading `btclib.p2p.addrv2._bip155_network_from_int`
and `btclib.p2p.inventory._inventory_type_from_int` give a byte-sized code:
BIP61 names the codes below and reserves the rest of each range --
0x01-0x0f, 0x10-0x1f, 0x40-0x4f -- to "Protocol syntax errors",
"Protocol semantic errors" and "Server policy rule" without naming every
member of any of them, so a code no member here has is not malformed, and
refusing it would refuse a message BIP61 itself allows.

**The refusals that remain are `BTClibValueError` and
`BTClibRuntimeError`, the family every payload in this package raises,
and never a bare exception from underneath it.** A receiver holding this
codec in front of a socket sorts a peer's malformed payload from its own
defect by that family -- a truncated field, an unrecognized command
padding, a hash of the wrong length -- exactly as it would for any other
message this library parses.

**`data` is a `hash256`, held displayed and reversed on the wire**, the
convention `btclib.p2p.inventory.Inventory.hash` already carries: what a
`tx` or `block` reject names is the transaction id or block hash a block
explorer prints, not the internal byte order the wire happens to use.

**`Reject.parse` takes `Octets` rather than `BinaryData`, for
`handshake.Version.parse`'s own reason.** The hash is optional and of
fixed width, so a no-hash payload for one `message`, `code` and `reason`
is a byte-for-byte prefix of the with-hash payload carrying the same
three -- "where the octets end" is a question about the whole payload,
which only the envelope's length field answers, and a stream holding a
`reject` followed by another message could not tell a present hash from
the next message's first thirty-two octets. `Message.parse(...).payload`
is what a caller already has; `tests/parse_contract_test.py` names the
exclusion this shares with `Version`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO

from typing_extensions import override

from btclib import var_bytes
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.payload import Payload
from btclib.utils import bytes_from_octets, is_integer, read_exactly

__all__ = [
    "Reject",
    "RejectCode",
]

_CODE_SIZE = 1
_MAX_CODE = (1 << (8 * _CODE_SIZE)) - 1
_HASH_SIZE = 32


class RejectCode(IntEnum):
    """BIP61's named reject codes, `Reject.code` where a member names it.

    Every code the BIP's tables give a description to, spelled after that
    description: `malformed` is the one code common to every message
    type ("Message could not be decoded"), `obsolete` and `duplicate` are
    `version`'s own, and the rest answer a `tx` or a `block` -- `invalid`
    covers both of the BIP's own "is invalid for some reason" rows, one
    per message type and one number between them. A code this class does
    not name is not an error: the module docstring is why.
    """

    malformed = 0x01
    invalid = 0x10
    obsolete = 0x11
    duplicate = 0x12
    nonstandard = 0x40
    dust = 0x41
    insufficientfee = 0x42
    checkpoint = 0x43


def _reject_code_from_int(code: int) -> RejectCode | int:
    """Return the member a code names, leaving a code no member has alone.

    `_bip155_network_from_int`'s reading of `_inventory_type_from_int`'s
    idea, for the third byte-sized code this package holds: a value no
    member has is not this parser's to refuse, being reserved by BIP61
    for a code table this class does not exhaust.
    """
    if not is_integer(code):
        return code
    try:
        return RejectCode(code)
    except ValueError:
        return code


def _var_str(octets: bytes, what: str) -> str:
    """Return the text a var_bytes field decodes to, refusing what is not utf-8.

    The module docstring is why `message` and `reason` are decoded here
    rather than held as octets: BIP61 states each as a `var_str`, and
    Core sends neither any more for a refusal to cost.
    """
    try:
        return octets.decode()
    except UnicodeDecodeError as e:
        raise BTClibValueError(f"invalid {what}: {e}") from e


@dataclass(frozen=True)
class Reject(Payload):
    """BIP61's `reject` message: what a peer refused, and why.

    The module docstring has the wire layout, the codec's own reasons for
    `message` and `reason` being `str`, and why `code` round-trips a
    value BIP61 reserves without naming.

    Frozen and hashable, every field being immutable: this is a value, as
    every payload this package holds is one.
    """

    command = "reject"

    message: str
    code: RejectCode | int
    reason: str
    data: bytes

    def __init__(
        self,
        message: str = "",
        code: int = RejectCode.malformed,
        reason: str = "",
        data: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "code", _reject_code_from_int(code))
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "data", bytes_from_octets(data))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a wrong type, an out-of-range code, or a bad data length."""
        if not isinstance(self.message, str):
            err_msg = f"invalid message type: {type(self.message).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        if not isinstance(self.reason, str):
            err_msg = f"invalid reason type: {type(self.reason).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)

        # a bool is an int and would read as the code one or zero, which
        # the range check cannot tell from a code whose value that is
        if not is_integer(self.code):
            err_msg = f"invalid code type: {type(self.code).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.code <= _MAX_CODE:
            raise BTClibValueError(f"invalid code: {self.code}")

        if len(self.data) not in (0, _HASH_SIZE):
            err_msg = f"invalid data length: {len(self.data)} bytes"
            err_msg += f" instead of 0 or {_HASH_SIZE}"
            raise BTClibValueError(err_msg)

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the payload, the hash last, reversed and only if present."""
        if check_validity:
            self.assert_valid()

        out = var_bytes.serialize(self.message.encode())
        out += int(self.code).to_bytes(_CODE_SIZE, byteorder="little", signed=False)
        out += var_bytes.serialize(self.reason.encode())
        out += self.data[::-1]
        return out

    @classmethod
    def parse(
        cls: type[Reject], data: Octets, *, check_validity: bool = True
    ) -> Reject:
        """Return the `reject` the payload describes, its hash read if present.

        `Octets` and not `BinaryData`: the module docstring is why, and it
        is `handshake.Version.parse`'s own reason.
        """
        # `BytesIO(bytes_from_octets(...))` and not
        # `bytesio_from_binarydata`, which hands a caller's stream back as
        # it came: a stream is the whole of what this must not accept, so
        # the refusal is the coercion's rather than a check of its own --
        # `handshake.Version.parse`'s own reasoning, for the same shape
        stream = BytesIO(bytes_from_octets(data))

        message = _var_str(var_bytes.parse(stream), "message")
        code = read_exactly(stream, _CODE_SIZE, "code")[0]
        reason = _var_str(var_bytes.parse(stream), "reason")

        # what is left is the whole of the question `parse` answers for
        # this field: BIP61 gives it no length prefix of its own, so
        # "is it there" is read off how much of the payload is left
        # rather than off a flag, the way handshake.Version reads relay
        tail = stream.read()
        if len(tail) not in (0, _HASH_SIZE):
            err_msg = f"invalid data length: {len(tail)} bytes"
            err_msg += f" instead of 0 or {_HASH_SIZE}"
            raise BTClibValueError(err_msg)
        hash_data = tail[::-1]

        return cls(message, code, reason, hash_data, check_validity=check_validity)
