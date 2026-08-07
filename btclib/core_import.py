# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The requests Bitcoin Core's `importdescriptors` takes.

https://github.com/bitcoin/bitcoin/blob/master/src/wallet/rpc/backup.cpp

What a wallet does with the descriptors `descriptors.account_descriptors`
builds: hand them to a node, which then watches every script they
describe. A request is one json object per descriptor, and this module is
the object -- no rpc call and no client, deliberately. The caller already
has one, `bitcoin-core-rpc` being a package of its own that
`btclib.fetch.bitcoin_core` builds on, and a second way to reach a node
would be a second thing to keep working.

`import_request` is one object; `account_import_requests` is the pair a
BIP44 account is, the receiving chain and the change chain marked
`internal`. That mark is why the pair is a function of its own: change
imported as a receiving chain is money the wallet reports as incoming
payments, and the mistake is invisible until a balance is wrong.

Every rule Core enforces on a request is enforced here, where the error
can still say which field it was rather than arriving as an rpc failure
half a rescan later:

- the descriptor carries its checksum, `Parse` being called there with
  ``require_checksum = true``;
- an `active` descriptor is ranged, an unranged one having no keypool to
  be the active source of;
- a `range` belongs to a ranged descriptor and to no other;
- both ends of a `range` are what `ParseRange` and `ParseDescriptorRange`
  in `src/rpc/util.cpp` take: ordered, non-negative, an end below 2**31,
  and fewer than a million indexes between them;
- `next_index` is inside that range;
- a `label` goes with neither `internal` nor a range;
- a `timestamp` is a number or the exact string `now`, which is what
  `GetImportTimestamp` accepts and nothing else -- `"NOW"` is not it.

Two things are not written, where HWI's `getkeypool` writes them:
`watchonly` and `keypool` are `importmulti` fields -- the other rpc that
dict targets -- and `importdescriptors` defines neither. A descriptor
wallet is watch-only by holding no private key, which `descriptors.parse`
guarantees of every descriptor it returns.

A multipath descriptor is not built here either: Core takes one and reads
the second element of a two-element step as the internal descriptor, while
`descriptors.parse` refuses a ``<a;b>`` step outright and
`multipath_descriptors` is what expands one. So the pair of requests is
what this module has, and it says the same thing in two objects.
"""

from __future__ import annotations

from typing import Any

from btclib.descriptors import Descriptor, add_checksum, parse
from btclib.exceptions import BTClibValueError
from btclib.utils import is_integer

__all__ = [
    "DEFAULT_RANGE",
    "NOW",
    "account_import_requests",
    "import_request",
]

# what Core substitutes the current chain time for, and what a caller
# means by "these scripts were never used": the string bypasses the
# rescan, where a timestamp of 0 scans the whole chain
NOW = "now"

# Core's own default keypool size, which is what it falls back to for a
# ranged descriptor imported without a range. Written out rather than left
# out: a request with no range makes Core answer "Range not given, using
# default keypool range" as a warning, and a caller reading that back
# cannot tell which indexes were imported
DEFAULT_RANGE = (0, 999)

# `high >= low + 1000000` is "Range is too large" in ParseDescriptorRange,
# so a million indexes is what a range may hold and 999_999 the widest
# gap between its inclusive ends
_MAX_RANGE_SPAN = 1_000_000


def _is_ranged(descriptor: Descriptor | str) -> bool:
    """Answer whether the descriptor describes a range of scripts.

    A `Descriptor` answers for itself; text is parsed for the answer, and
    that parse is also what refuses text which is no descriptor at all --
    a request built around it would be refused by the node instead, which
    is a rescan away.
    """
    if isinstance(descriptor, Descriptor):
        return descriptor.is_ranged
    return parse(descriptor).is_ranged


def _assert_timestamp(timestamp: int | str) -> None:
    """Refuse a timestamp Core's GetImportTimestamp would refuse.

    A number, or the string `now` and no other string: Core compares the
    text against "now" and answers `Expected number or "now" timestamp
    value for key` to everything else, so `"NOW"` and `"yesterday"` fail
    the whole request. A refusal here names the field, where the rpc
    error names the key it was importing.

    `is_integer` rather than `isinstance(timestamp, int)`, which is the
    predicate every integer field of the library is held to: `True` is an
    `int` to Python and a boolean to json, and Core reads a json boolean
    as neither a number nor a string.
    """
    if is_integer(timestamp):
        return
    if timestamp == NOW:
        return
    err_msg = f'expected a number or "{NOW}" as timestamp: {timestamp!r}'
    raise BTClibValueError(err_msg)


def _assert_no_label(label: str, why: str) -> None:
    """Refuse a label where Core refuses one, naming which rule it was."""
    if label:
        raise BTClibValueError(f"a {why} descriptor takes no label")


def _range_fields(
    key_range: tuple[int, int] | None, next_index: int | None
) -> dict[str, Any]:
    """Return the range fields of a request, checked against each other.

    Both ends of the range are inclusive, which is how Core reads them --
    it adds one to the second itself -- and `next_index` is where the
    wallet carries on from, so it is inside the range or it is nothing.

    The two bounds are `ParseDescriptorRange`'s, which `importdescriptors`
    calls on this field: an end of 2**31 or above is "End of range is too
    high", and a span of a million indexes or more is "Range is too
    large". Neither is a shape a keypool has any use for -- Core's own
    default is a thousand -- so what they catch is an argument computed
    wrongly, and catching it here is the difference between naming the
    field and reading an rpc failure after a rescan.

    A rule of Core's that is deliberately not repeated: every numeric
    field arrives through `UniValue::getInt<int64_t>`, which refuses what
    does not fit. After the bounds above, `start` and `end` are inside
    [0, 2**31) and `next_index` is between them, so nothing here can
    reach it.
    """
    if key_range is None:
        if next_index is not None:
            raise BTClibValueError("next_index without a range to be inside of")
        return {}

    start, end = key_range
    if not 0 <= start <= end:
        raise BTClibValueError(f"invalid range: [{start}, {end}]")
    if end >> 31:
        raise BTClibValueError(f"end of range is too high: {end}")
    if end - start >= _MAX_RANGE_SPAN:
        err_msg = f"range is too large: {end - start + 1} indexes, "
        err_msg += f"max is {_MAX_RANGE_SPAN}"
        raise BTClibValueError(err_msg)
    fields: dict[str, Any] = {"range": [start, end]}
    if next_index is not None:
        if not start <= next_index <= end:
            err_msg = f"next_index {next_index} is not in [{start}, {end}]"
            raise BTClibValueError(err_msg)
        fields["next_index"] = next_index
    return fields


def import_request(
    descriptor: Descriptor | str,
    timestamp: int | str = NOW,
    *,
    internal: bool = False,
    active: bool = True,
    key_range: tuple[int, int] | None = DEFAULT_RANGE,
    next_index: int | None = None,
    label: str = "",
) -> dict[str, Any]:
    """Return the `importdescriptors` request for one descriptor.

    `descriptor` is a `Descriptor` or the text of one; either way what the
    request carries is the checksummed text, which is what Core requires of
    a descriptor it imports.

    `timestamp` is where the rescan starts, in Unix time, `NOW` being
    Core's own way of saying "do not rescan": right for a descriptor whose
    scripts have never been used, and wrong for one being restored, where
    the time of the wallet's first use is what finds its history. `NOW` is
    the default for the reason there is no default restore date -- this
    module cannot know one, and a silent 0 would rescan the whole chain.
    A number or `NOW` itself, and no other string: Core takes those two
    and refuses the rest, `"NOW"` included.

    `internal` marks the change chain, which Core then keeps out of what
    it reports as incoming payments.

    `active` makes the descriptor the wallet's source of new addresses for
    that output type and externality, which is what an import for spending
    wants and a bare watch of some scripts does not. Core requires an
    active descriptor to be ranged, so this does too.

    `key_range` is the inclusive pair Core takes, both ends included --
    Core adds one to the second itself. None leaves the field out, which
    is what an unranged descriptor takes. Ordered, non-negative, an end
    below 2**31 and fewer than a million indexes wide, which are
    `ParseDescriptorRange`'s bounds.

    `next_index` is where an active ranged descriptor hands out its next
    address, and has to be inside the range, as Core checks.

    `label` names the address, and Core allows one only for a single
    unranged receiving descriptor: not for change, and not for a range.
    """
    text = add_checksum(descriptor if isinstance(descriptor, str) else str(descriptor))
    is_ranged = _is_ranged(descriptor)

    _assert_timestamp(timestamp)

    if active and not is_ranged:
        err_msg = "an active descriptor must be ranged: one script is no keypool"
        raise BTClibValueError(err_msg)
    if key_range is not None and not is_ranged:
        raise BTClibValueError("an unranged descriptor takes no range")
    if internal:
        _assert_no_label(label, "change")
    if is_ranged:
        _assert_no_label(label, "ranged")

    request: dict[str, Any] = {
        "desc": text,
        "timestamp": timestamp,
        "internal": internal,
        "active": active,
        **_range_fields(key_range, next_index),
    }
    if label:
        request["label"] = label
    return request


def account_import_requests(
    receive: Descriptor,
    change: Descriptor,
    timestamp: int | str = NOW,
    *,
    active: bool = True,
    key_range: tuple[int, int] = DEFAULT_RANGE,
) -> list[dict[str, Any]]:
    """Return the two requests a BIP44 account is imported with.

    The pair `descriptors.account_descriptors` builds, with the second
    marked `internal`: that mark is what keeps a wallet from reporting its
    own change as incoming payments, and it is the one thing a caller
    writing the two requests by hand gets wrong.

    Both chains or neither: a wallet holding the receiving chain alone
    cannot recognize the change it makes itself, which is an output it
    stops seeing rather than a feature it lacks.
    """
    return [
        import_request(
            receive, timestamp, internal=False, active=active, key_range=key_range
        ),
        import_request(
            change, timestamp, internal=True, active=active, key_range=key_range
        ),
    ]
