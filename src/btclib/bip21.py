# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP21 payment URI: bitcoin:<address>[?amount=&label=&message=].

https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki

The gap between what a user pastes or scans and the typed surface this
library offers. It is pure string handling and it sits above the
encodings: the address goes to `b32`/`b58`, the amount to `amount`, the
network type to `network`, and a `lightning=` parameter to `bolt11`;
nothing else in btclib imports this module, so the dependency graph the
README draws gains no edge from it, only the one edge into it.

Four rules carry the whole of it, and each is the thing an
implementation gets wrong:

- an unknown parameter whose name starts with `req-` makes the URI
  invalid, and *only* those: an unknown parameter without the prefix is
  ignored. That is the entire forward-compatibility story of the scheme
- `amount` is decimal BTC, not satoshi and never a float
- a repeated key is an error, not last-one-wins
- `label` and `message` are percent-encoded, and a bech32 address is
  legally uppercase -- the QR-code case -- so nothing here lowercases
  what it hands to the address decoders

`lightning` is the one parameter this module gives its own type rather
than leaving in `others`: a BOLT11 invoice, cross-checked against the
address it rides beside wherever the two state the same fact -- the
network, and the amount where both give one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from urllib.parse import quote, unquote

from btclib import b32, b58
from btclib.alias import NetworkType
from btclib.amount import valid_btc_amount
from btclib.bolt11 import Bolt11Invoice
from btclib.exceptions import BTClibValueError
from btclib.network import network_type_from_network
from btclib.utils import assert_type

__all__ = [
    "Bip21",
]

_SCHEME = "bitcoin"

# BIP21's own grammar for the amount: `*digit [ "." *digit ]`, and the
# reason to spell it out rather than hand the string straight to
# valid_btc_amount is what Decimal() would otherwise take -- "1e5",
# "+1", "Infinity", " 1 ". Two of those are refused downstream for being
# out of range, and the other two would silently mean something the URI
# does not say
_AMOUNT = re.compile(r"\A(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")

# what percent-encoding must leave alone in a value this module writes.
# "/" and ":" are legal in a query and common in a message; "&", "=",
# "?" and "#" are the delimiters and must stay encoded
_SAFE = "/:@!$'()*+,;"

# a `%` that is not RFC 3986's pct-encoded, i.e. not followed by exactly
# two hexadecimal digits. `unquote` leaves such a `%` as literal text --
# "%ZZ" decodes to "%ZZ" -- and `errors="strict"` does not see it, being
# the error handler of the utf-8 decode that happens *after* the
# unescaping. Malformed syntax is therefore not what that flag catches:
# "%FF" is an escape of an octet that is no text and is refused by it,
# where "%ZZ" is not an escape at all.
#
# Left as text, it would not round trip: serialize writes a literal
# percent sign as "%25", so "label=%ZZ" would come back out as
# "label=%25ZZ" -- two URIs meaning one request, with only one of them
# written, which is the canonical-form rule the binary parsers of this
# library are held to as well
_MALFORMED_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _network_from_address(address: str) -> str:
    """Return the network of an address, raising if it is not one."""
    if b32.is_segwit_prefixed(address):
        return b32.witness_from_address(address)[2]
    return b58.h160_from_address(address)[2]


def _decode(value: str, what: str) -> str:
    """Percent-decode a URI query value.

    unquote and not unquote_plus: `+` means a plus sign here. Reading it
    as a space is the HTML form convention, which a payment URI is not
    -- a label of "Alice+Bob" is two names, and a space is "%20".
    """
    if "%" in value:
        # the syntax first, and separately: a `%` that escapes nothing is a
        # different fault from an escape of octets that are not utf-8, and
        # only the second is what errors="strict" answers
        if _MALFORMED_ESCAPE.search(value):
            raise BTClibValueError(f"malformed percent escape in {what}")
        # errors="strict", because a mangled percent escape in a payment
        # request is not a label with a replacement character in it
        try:
            return unquote(value, errors="strict")
        except UnicodeDecodeError as e:
            raise BTClibValueError(f"invalid percent-encoding in {what}") from e
    return value


@dataclass(frozen=True)
class Bip21:
    """A parsed `bitcoin:` payment URI.

    `others` holds the parameters BIP21 says to ignore: kept rather than
    dropped, because "ignore" is a rule about not *rejecting* them, and
    a caller that recognises one is better served by being handed it.
    Nothing here treats them as meaningful.

    `lightning` is the one parameter this module does treat as
    meaningful: a BOLT11 invoice, typed rather than left in `others`, and
    cross-checked against the on-chain half of the same request wherever
    both state a fact -- the network, and the amount where both give one.
    Electrum's `bip21.py` does the same pairing, which is why the two
    land in one change.
    """

    address: str
    amount: Decimal | None
    label: str | None
    message: str | None
    others: Mapping[str, str] = field(default_factory=dict)
    lightning: Bolt11Invoice | None = None

    @property
    def network_type(self) -> NetworkType:
        """Return "main" or "test", what the address says about its chain.

        Not the network, which this was called and could not deliver: a
        `tb1` address is testnet, signet and testnet4 at once, and a
        `0x6f` base58 one is those three and regtest. "main or test" is
        the whole of what an address carries -- issue #207 -- and it is
        the question a payment URI actually raises, a payer needing to
        know that a request is not for real bitcoin.
        """
        return network_type_from_network(_network_from_address(self.address))

    def __init__(
        self,
        address: str,
        amount: Any = None,
        label: str | None = None,
        message: str | None = None,
        others: Mapping[str, str] | None = None,
        lightning: Bolt11Invoice | str | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "address", address)
        object.__setattr__(
            self, "amount", None if amount is None else valid_btc_amount(amount)
        )
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "others", dict(others or {}))
        object.__setattr__(
            self,
            "lightning",
            Bolt11Invoice.from_invoice(lightning, check_validity=check_validity)
            if isinstance(lightning, str)
            else lightning,
        )

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a bad address, a bad amount, or an inconsistent invoice."""
        if not isinstance(self.address, str) or not self.address:  # type: ignore[redundant-expr]
            raise BTClibValueError("missing address in the bip21 URI")
        # the decoders *are* the validation, and each says what is wrong
        # with the string it refused, which is more than this module
        # could add. Which of the two applies is decided on the untouched
        # address: a bech32 one may be uppercase and a base58 one may not
        _network_from_address(self.address)

        if self.amount is not None:
            valid_btc_amount(self.amount)

        for key in self.others:
            if not key:
                raise BTClibValueError("empty parameter name in the bip21 URI")
            if key.lower().startswith("req-"):
                raise BTClibValueError(f"unknown required parameter: {key}")

        if self.lightning is not None:
            self.lightning.assert_valid()
            if network_type_from_network(self.lightning.network) != self.network_type:
                err_msg = "the lightning invoice's network does not match the address"
                raise BTClibValueError(err_msg)
            if self.amount is not None and self.lightning.amount_msat is not None:
                invoice_amount = Decimal(self.lightning.amount_msat) / Decimal(10**11)
                if invoice_amount != self.amount:
                    err_msg = "the lightning invoice's amount does not match the URI"
                    raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> str:
        """Return the `bitcoin:` URI of this payment request."""
        if check_validity:
            self.assert_valid()

        params = []
        if self.amount is not None:
            # never the exponent notation Decimal reaches for above 1e6
            # digits or after normalize(): BIP21's amount is digits and
            # at most one dot, so `1E+2` would not be a valid amount at
            # all. The trailing zeros go, 0.10000000 and 0.1 being the
            # same request
            amount = f"{self.amount:f}"
            if "." in amount:
                amount = amount.rstrip("0").rstrip(".")
            params.append(f"amount={amount or '0'}")
        if self.label is not None:
            params.append(f"label={quote(self.label, safe=_SAFE)}")
        if self.message is not None:
            params.append(f"message={quote(self.message, safe=_SAFE)}")
        if self.lightning is not None:
            params.append(f"lightning={quote(self.lightning.to_invoice(), safe=_SAFE)}")
        params.extend(
            f"{quote(key, safe=_SAFE)}={quote(value, safe=_SAFE)}"
            for key, value in self.others.items()
        )

        uri = f"{_SCHEME}:{self.address}"
        return f"{uri}?{'&'.join(params)}" if params else uri

    @classmethod
    def parse(cls, uri: str, *, check_validity: bool = True) -> Bip21:
        """Return the Bip21 of a `bitcoin:` URI.

        A `str` and not the `String` the octet decoders take: a URI is
        text, and a `BTClibTypeError` for what is not it -- the rule
        CONTRIBUTING.md states, this parameter declaring one type.
        """
        assert_type(uri, str, "uri")

        scheme, separator, rest = uri.partition(":")
        # RFC 3986 makes a scheme case-insensitive, and a QR code writes
        # the whole URI uppercase to stay in alphanumeric mode
        if not separator or scheme.lower() != _SCHEME:
            raise BTClibValueError(f"not a bitcoin URI: {uri[:32]!r}")

        address, _, query = rest.partition("?")
        # a fragment is not part of BIP21 and is not a parameter either
        query = query.partition("#")[0]

        amount: str | None = None
        label: str | None = None
        message: str | None = None
        lightning: str | None = None
        others: dict[str, str] = {}
        seen: set[str] = set()
        for element in query.split("&") if query else []:
            if not element:
                # BIP21's bitcoinparam admits the empty element
                continue
            key, _, raw_value = element.partition("=")
            key = _decode(key, "a parameter name")
            if key in seen:
                # not last-one-wins: two amounts are two requests, and
                # picking one of them is picking for the payer
                raise BTClibValueError(f"repeated parameter: {key}")
            seen.add(key)

            if key == "amount":
                amount = _valid_amount_field(raw_value)
            elif key == "label":
                label = _decode(raw_value, "label")
            elif key == "message":
                message = _decode(raw_value, "message")
            elif key == "lightning":
                # typed below, in __init__: not one of "the parameters
                # BIP21 says to ignore" any more, so it does not join
                # `others`
                lightning = _decode(raw_value, "the lightning parameter")
            else:
                others[key] = _decode(raw_value, f"the {key} parameter")

        return cls(
            # not percent-decoded: BIP21 spells the address as bare
            # base58 or bech32, neither alphabet has a character needing
            # an escape, and decoding one would turn a string that is
            # not an address into something that might be
            address,
            amount,
            label,
            message,
            others,
            lightning,
            check_validity=check_validity,
        )


def _valid_amount_field(raw_value: str) -> str:
    """Return the amount field, refused unless it is BIP21's own grammar."""
    if not _AMOUNT.match(raw_value):
        raise BTClibValueError(f"invalid bip21 amount: {raw_value[:32]!r}")
    return raw_value
