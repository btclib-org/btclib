# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BOLT11: Lightning Network payment invoices.

https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

A BOLT11 invoice is bech32 over a human-readable part (network and
optional amount) and a data part (timestamp, tagged fields, recoverable
ECDSA signature) -- every piece of which is arithmetic this tree already
has: `bech32` for the codec, `b32` and `b58` for the fallback on-chain
address, `ecc.dsa` for the signature and payee recovery, `hashes.sha256`
for the message digest.

**Explicit `m`, always.** `bech32.decode`'s default picks bech32 against
bech32m off the first data word as if it were a witness version
(`_m_from_wit_ver`); an invoice's first data words are timestamp bits,
which is not a witness version at all, so the default would misread most
invoices. BOLT11 is bech32 alone -- BIP350 (bech32m) postdates it and the
BOLT never adopted it -- so both directions here call `bech32.decode` and
`bech32.encode` with `m=1` explicitly. The 90-character bound BIP173
addresses carry is not a concern either: `bech32.py` never enforced it,
`b32.py` does, and this module imports `bech32` and not `b32`'s bound.

**The wire format's own source of truth is `tagged_fields`, in the order
the invoice carried them.** BOLT11 does not fix an order across different
tag types -- only same-tag repeats have to be most-preferred first -- so
two spec-compliant writers can place, say, the description before or
after the payment secret. Reproducing an invoice's own bytes on
`to_invoice` therefore keeps the tagged fields exactly as parsed, unknown
tags included, the way `bip21.Bip21.others` keeps a parameter it does not
recognise rather than dropping it. Every other attribute --
`payment_hash`, `description`, `fallback_addresses` and the rest -- is a
property computed from that list, picking the first well-formed
occurrence of its own tag: BOLT11's own "fields which must be ignored"
example duplicates `p`, `h`, `s`, `n` and an `f` field of unknown version
with the wrong length on purpose, and a reader is required to skip each
malformed repeat rather than fail the whole invoice over it.

**Millisatoshi is a plain `int`, named for its unit rather than a new
`btclib.amount` type.** The human-readable part's amount is BTC with a
multiplier down to pico-BTC, and the pico rule (the last decimal must be
zero) exists to keep the result an integer number of millisatoshi, which
is the unit HTLCs are denominated in. A dedicated physical-quantity type
is a larger surface than one invoice codec needs on its own; `amount_msat`
is a decision this module states rather than one the maintainer inherits
unstated.

**Network is the human-readable part's own prefix, not `b32`'s hrp.** BIP173's
per-network bech32 prefixes ("bc", "tb", "bcrt") are what an on-chain
address carries; BOLT11 defines its own four -- `lnbc`, `lntb`, `lntbs`,
`lnbcrt` -- and none of them is "ln" plus that prefix: testnet and
signet share "tb" on-chain but not here, where signet is "tbs".
There is no fifth prefix for testnet4: the BOLT does not define one, so
an `lntb` invoice is exactly as ambiguous between testnet and testnet4 as
a base58 address sharing their version byte is, and `network_from_key_value`'s
own convention -- the oldest of the networks a prefix names -- is what
this module resolves it to as well: `"testnet"`, never `"testnet4"`.

**A reader that finds a stated payee never trusts recovery over it.**
BOLT11 requires the opposite of what would be cheaper: an `n` field, when
present, is verified directly and demands a canonical low-s signature: a
high-s signature naming a payee is invalid even though recovery alone
would accept it, and `ecc.dsa.verify_` accepts both forms with no flag to
narrow it, so the low-s check here is this module's own, not delegated.
Only where no `n` field was stated is `ecc.dsa.recover_pub_key_` asked at
all, and it accepts either form -- which is why the BOLT's own "public-key
recovery with high-S signature" example decodes and the "non canonical
signature ... with 'n' field defined" one does not.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from btclib.alias import Integer, Octets
from btclib.b32 import (
    address_from_witness,
    is_segwit_prefixed,
    power_of_2_base_conversion,
    witness_from_address,
)
from btclib.b58 import address_from_h160, h160_from_address
from btclib.bech32 import decode as _bech32_decode
from btclib.bech32 import encode as _bech32_encode
from btclib.bolt9 import FEATURE_NAMES, unknown_even_bits, unmet_dependencies
from btclib.curves import bytes_from_point, secp256k1
from btclib.ecc.dsa import Sig, gen_keys, recover_pub_key_, sign_recoverable_, verify_
from btclib.exceptions import BTClibValueError
from btclib.hashes import sha256
from btclib.utils import assert_type, bytes_from_octets, int_from_integer, is_integer

__all__ = [
    "Bolt11Invoice",
    "RouteHintHop",
]

# BOLT11's own currency prefixes, "ln" plus a per-network code that is
# not b32's on-chain hrp: testnet and signet share "tb" on-chain and do
# not here, and there is no fifth code for testnet4 -- see the module
# docstring
_CURRENCY_FROM_NETWORK = {
    "mainnet": "bc",
    "testnet": "tb",
    "regtest": "bcrt",
    "signet": "tbs",
}
_NETWORK_FROM_CURRENCY = {v: k for k, v in _CURRENCY_FROM_NETWORK.items()}
# longest currency code first, so that "bcrt" is not shadowed by "bc" nor
# "tbs" by "tb" when matching a hrp's tail
_CURRENCIES_BY_LENGTH = sorted(_NETWORK_FROM_CURRENCY, key=len, reverse=True)

_AMOUNT_RE = re.compile(r"([0-9]+)([munp]?)\Z")
# millisatoshi per unit digit, for the three multipliers that scale
# evenly; "p" (pico-BTC) is a tenth of a millisatoshi, handled on its own
# below rather than through this table
_MSAT_PER_DIGIT = {"m": 10**8, "u": 10**5, "n": 10**2}
_MSAT_PER_BTC = 10**11

# tagged field types, BOLT11's own 5-bit values -- each is the index its
# letter has in bech32's alphabet ('p' = 1, 's' = 16, ...), which is what
# lets a reader use the wire value directly instead of a name
_TAG_PAYMENT_HASH = 1
_TAG_ROUTING_INFO = 3
_TAG_FEATURES = 5
_TAG_EXPIRY = 6
_TAG_FALLBACK = 9
_TAG_DESCRIPTION = 13
_TAG_PAYMENT_SECRET = 16
_TAG_PAYEE = 19
_TAG_DESCRIPTION_HASH = 23
_TAG_MIN_FINAL_CLTV_EXPIRY = 24
_TAG_METADATA = 27

_SIGNATURE_WORDS = 104  # 520 bits: 64-byte compact signature + 1-byte recid
_HOP_SIZE = 33 + 8 + 4 + 4 + 2  # pubkey, short_channel_id, two fees, cltv delta


def _int_to_words(value: int, n_words: int) -> tuple[int, ...]:
    """Return `value` as `n_words` 5-bit groups, most significant first."""
    if not 0 <= value < (1 << (5 * n_words)):
        raise BTClibValueError(f"{value} does not fit {n_words} 5-bit words")
    return tuple((value >> (5 * (n_words - 1 - i))) & 0x1F for i in range(n_words))


def _words_to_int(words: Sequence[int]) -> int:
    value = 0
    for word in words:
        value = (value << 5) | word
    return value


def _words_to_bytes(words: Sequence[int]) -> bytes:
    """Return the byte string `words` packs, refusing non-zero padding."""
    return bytes(power_of_2_base_conversion(list(words), 5, 8, pad=False))


def _bytes_to_words(data: bytes) -> tuple[int, ...]:
    return tuple(power_of_2_base_conversion(list(data), 8, 5, pad=True))


def _minimal_int_words(value: int) -> tuple[int, ...]:
    """Return `value` with no leading zero word, one zero word if it is 0."""
    if value == 0:
        return (0,)
    n_words = (value.bit_length() + 4) // 5
    return _int_to_words(value, n_words)


def _parse_hrp(hrp: str) -> tuple[str, int | None]:
    """Return (network, amount_msat) from a BOLT11 human-readable part."""
    if not hrp.startswith("ln"):
        raise BTClibValueError(f"not a lightning invoice prefix: {hrp!r}")
    rest = hrp[2:]
    for currency in _CURRENCIES_BY_LENGTH:
        if rest.startswith(currency):
            network = _NETWORK_FROM_CURRENCY[currency]
            amount_part = rest[len(currency) :]
            break
    else:
        raise BTClibValueError(f"unknown network prefix: {hrp!r}")

    if not amount_part:
        return network, None

    match = _AMOUNT_RE.match(amount_part)
    if not match:
        raise BTClibValueError(f"invalid amount: {amount_part!r}")
    digits, multiplier = match.group(1), match.group(2)
    value = int(digits)
    if multiplier == "p":
        if value % 10:
            err_msg = "a pico-bitcoin amount must end in a 0 digit: "
            raise BTClibValueError(err_msg + amount_part)
        amount_msat = value // 10
    elif multiplier:
        amount_msat = value * _MSAT_PER_DIGIT[multiplier]
    else:
        amount_msat = value * _MSAT_PER_BTC
    return network, amount_msat


def _amount_digits(amount_msat: int) -> str:
    """Return the shortest amount+multiplier suffix for `amount_msat`.

    The largest multiplier that divides evenly, which is what BOLT11
    asks writers for ("the shortest representation possible") and what
    reproduces the BOLT's own examples byte for byte: 967878534 msat is
    not a whole multiple of a nanosatoshi digit, so it is the one example
    written in pico-bitcoin, `9678785340p`.
    """
    if amount_msat % _MSAT_PER_BTC == 0:
        return str(amount_msat // _MSAT_PER_BTC)
    for multiplier, per_digit in _MSAT_PER_DIGIT.items():
        if amount_msat % per_digit == 0:
            return f"{amount_msat // per_digit}{multiplier}"
    return f"{amount_msat * 10}p"


def _hrp(network: str, amount_msat: int | None) -> str:
    currency = _CURRENCY_FROM_NETWORK[network]
    if amount_msat is None:
        return f"ln{currency}"
    return f"ln{currency}{_amount_digits(amount_msat)}"


def _parse_tagged_fields(
    data: Sequence[int],
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    """Return the (tag, data words) pairs of a data part, in wire order."""
    fields = []
    i = 0
    n = len(data)
    while i < n:
        if i + 3 > n:
            raise BTClibValueError("truncated tagged field header")
        tag = data[i]
        data_length = data[i + 1] * 32 + data[i + 2]
        start = i + 3
        end = start + data_length
        if end > n:
            raise BTClibValueError(f"tagged field {tag} overruns the data part")
        fields.append((tag, tuple(data[start:end])))
        i = end
    return tuple(fields)


def _first(
    fields: Sequence[tuple[int, tuple[int, ...]]],
    tag: int,
    expected_length: int | None,
) -> tuple[int, ...] | None:
    """Return the first occurrence of `tag`, skipping a malformed length.

    BOLT11's own "fields which must be ignored" example repeats `p`, `h`,
    `s` and `n` with the wrong `data_length` on purpose, and a reader is
    required to skip each repeat rather than fail the invoice over it --
    the first, correctly-sized occurrence is what every typed accessor
    here reads.
    """
    for candidate_tag, words in fields:
        if candidate_tag == tag and (
            expected_length is None or len(words) == expected_length
        ):
            return words
    return None


def _fallback_field(address: str, network: str) -> tuple[int, tuple[int, ...]]:
    if is_segwit_prefixed(address):
        version, program, _network = witness_from_address(address)
    else:
        script_type, program, _network = h160_from_address(address)
        version = 17 if script_type == "p2pkh" else 18
    words = (version, *_bytes_to_words(program))
    return _TAG_FALLBACK, words


@dataclass(frozen=True)
class RouteHintHop:
    """One hop of a BOLT11 `r` field: a private channel to route through.

    `pubkey` is the node id at the start of the channel, the wire's own
    convention (`04-onion-routing.md`'s hop_payload starts each channel
    from the node the payer already reached) rather than the payee's.
    """

    pubkey: bytes
    short_channel_id: int
    fee_base_msat: int
    fee_proportional_millionths: int
    cltv_expiry_delta: int

    def __init__(
        self,
        pubkey: Octets,
        short_channel_id: Integer,
        fee_base_msat: Integer,
        fee_proportional_millionths: Integer,
        cltv_expiry_delta: Integer,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "pubkey", bytes_from_octets(pubkey, 33))
        object.__setattr__(self, "short_channel_id", int_from_integer(short_channel_id))
        object.__setattr__(self, "fee_base_msat", int_from_integer(fee_base_msat))
        object.__setattr__(
            self,
            "fee_proportional_millionths",
            int_from_integer(fee_proportional_millionths),
        )
        object.__setattr__(
            self, "cltv_expiry_delta", int_from_integer(cltv_expiry_delta)
        )
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a field that does not fit its wire width."""
        if not 0 <= self.short_channel_id < 2**64:
            raise BTClibValueError(f"invalid short_channel_id: {self.short_channel_id}")
        if not 0 <= self.fee_base_msat < 2**32:
            raise BTClibValueError(f"invalid fee_base_msat: {self.fee_base_msat}")
        if not 0 <= self.fee_proportional_millionths < 2**32:
            err_msg = "invalid fee_proportional_millionths: "
            raise BTClibValueError(err_msg + str(self.fee_proportional_millionths))
        if not 0 <= self.cltv_expiry_delta < 2**16:
            raise BTClibValueError(
                f"invalid cltv_expiry_delta: {self.cltv_expiry_delta}"
            )

    def _serialize(self) -> bytes:
        return (
            self.pubkey
            + self.short_channel_id.to_bytes(8, "big")
            + self.fee_base_msat.to_bytes(4, "big")
            + self.fee_proportional_millionths.to_bytes(4, "big")
            + self.cltv_expiry_delta.to_bytes(2, "big")
        )

    @classmethod
    def _parse(cls, data: bytes, *, check_validity: bool) -> RouteHintHop:
        return cls(
            data[0:33],
            int.from_bytes(data[33:41], "big"),
            int.from_bytes(data[41:45], "big"),
            int.from_bytes(data[45:49], "big"),
            int.from_bytes(data[49:51], "big"),
            check_validity=check_validity,
        )


@dataclass(frozen=True)
class Bolt11Invoice:
    """A BOLT11 Lightning invoice.

    `tagged_fields` is the wire's own ordered (tag, data words) list, and
    every other attribute below is a property computed from it -- see the
    module docstring for why the order is not collapsed into named
    fields. `from_invoice` parses one; `sign` builds and signs a new one;
    `to_invoice` writes either back out.
    """

    network: str
    timestamp: int
    tagged_fields: tuple[tuple[int, tuple[int, ...]], ...]
    signature: Sig
    recovery_id: int
    amount_msat: int | None = None

    def __init__(
        self,
        network: str,
        timestamp: Integer,
        tagged_fields: Sequence[tuple[int, Sequence[int]]],
        signature: Sig,
        recovery_id: Integer,
        amount_msat: Integer | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        assert_type(network, str, "network")
        object.__setattr__(self, "network", network)
        object.__setattr__(self, "timestamp", int_from_integer(timestamp))
        object.__setattr__(
            self,
            "tagged_fields",
            tuple((tag, tuple(words)) for tag, words in tagged_fields),
        )
        object.__setattr__(self, "signature", signature)
        object.__setattr__(self, "recovery_id", int_from_integer(recovery_id))
        object.__setattr__(
            self,
            "amount_msat",
            None if amount_msat is None else int_from_integer(amount_msat),
        )

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse an invoice a wallet cannot rely on.

        Beyond range and shape, this is where the acceptance criterion
        lives: the message is recomputed from every other field and the
        stored signature is checked against it, recovering the payee
        where none was stated.

        An **even** bit of the `9` field that BOLT9 does not assign
        fails the invoice, which is BOLT9's rule for a reader that meets
        a feature bit it does not know; a feature stated without the
        features BOLT9 says it depends on fails it too. `btclib.bolt9`
        carries the table that answers both.
        """
        if self.network not in _CURRENCY_FROM_NETWORK:
            raise BTClibValueError(f"not a lightning network: {self.network}")
        if not 0 <= self.timestamp < (1 << 35):
            raise BTClibValueError(f"timestamp does not fit 35 bits: {self.timestamp}")
        if self.amount_msat is not None and (
            not is_integer(self.amount_msat) or self.amount_msat <= 0
        ):
            raise BTClibValueError(f"invalid amount: {self.amount_msat} msat")
        if not 0 <= self.recovery_id <= 3:
            raise BTClibValueError(f"invalid recovery id: {self.recovery_id}")
        self.signature.assert_valid()

        # required tagged fields: raises if either is missing or malformed
        _payment_hash = self.payment_hash
        _payment_secret = self.payment_secret
        if (self.description is None) == (self.description_hash is None):
            err_msg = "exactly one of description and description_hash is required"
            raise BTClibValueError(err_msg)

        # forces every other accessor's own well-formedness check
        _expiry = self.expiry
        _min_final_cltv_expiry = self.min_final_cltv_expiry
        _metadata = self.metadata
        _fallback_addresses = self.fallback_addresses
        _route_hints = self.route_hints
        del (
            _payment_hash,
            _payment_secret,
            _expiry,
            _min_final_cltv_expiry,
            _metadata,
            _fallback_addresses,
            _route_hints,
        )

        # `features` is read here rather than among the accessors above:
        # its own well-formedness is the bits, and an even one BOLT9 does
        # not assign is a requirement no reader has been told how to meet
        features = self.features
        unknown = unknown_even_bits(features)
        if unknown:
            bits = ", ".join(str(bit) for bit in unknown)
            raise BTClibValueError(f"unknown even feature bits: {bits}")

        # the other half of a well-formed vector, and BOLT9's own word
        # for it: a feature whose dependencies are set is one a reader can
        # act on without checking them again at every gate
        unmet = unmet_dependencies(features)
        if unmet:
            missing = ", ".join(
                f"{FEATURE_NAMES[bit]} requires {FEATURE_NAMES[required]}"
                for bit, required in unmet
            )
            raise BTClibValueError(f"unmet feature dependencies: {missing}")

        # the signature itself: this is what makes an invoice acceptable
        _payee = self.payee
        del _payee

    def _message_hash(self) -> bytes:
        """Return the SHA-256 the signature is over.

        The human-readable part as UTF-8, concatenated with every 5-bit
        word before the signature and padded with zero bits to a byte
        boundary -- BOLT11's own definition, computed here rather than
        delegated because nothing else in this library has a signature
        over a bech32 human-readable part.
        """
        hrp = _hrp(self.network, self.amount_msat)
        words = list(_int_to_words(self.timestamp, 7))
        for tag, data_words in self.tagged_fields:
            words += [tag, *_int_to_words(len(data_words), 2), *data_words]
        return sha256(
            hrp.encode("ascii") + bytes(power_of_2_base_conversion(words, 5, 8))
        )

    @property
    def payment_hash(self) -> bytes:
        """Return the 32-byte `p` field, refusing an invoice without one."""
        words = _first(self.tagged_fields, _TAG_PAYMENT_HASH, 52)
        if words is None:
            raise BTClibValueError("missing payment_hash ('p') field")
        return _words_to_bytes(words)

    @property
    def payment_secret(self) -> bytes:
        """Return the 32-byte `s` field, refusing an invoice without one."""
        words = _first(self.tagged_fields, _TAG_PAYMENT_SECRET, 52)
        if words is None:
            raise BTClibValueError("missing payment_secret ('s') field")
        return _words_to_bytes(words)

    @property
    def description(self) -> str | None:
        """Return the `d` field, `None` where a `h` field stands in for it."""
        words = _first(self.tagged_fields, _TAG_DESCRIPTION, None)
        if words is None:
            return None
        try:
            return _words_to_bytes(words).decode("utf-8")
        except UnicodeDecodeError as e:
            raise BTClibValueError("description is not valid UTF-8") from e

    @property
    def description_hash(self) -> bytes | None:
        """Return the 32-byte `h` field, `None` where a `d` field stands in."""
        words = _first(self.tagged_fields, _TAG_DESCRIPTION_HASH, 52)
        return None if words is None else _words_to_bytes(words)

    @property
    def expiry(self) -> int:
        """Return the `x` field in seconds, BOLT11's default of 3600."""
        words = _first(self.tagged_fields, _TAG_EXPIRY, None)
        return 3600 if words is None else _words_to_int(words)

    @property
    def min_final_cltv_expiry(self) -> int:
        """Return the `c` field, BOLT11's default of 18."""
        words = _first(self.tagged_fields, _TAG_MIN_FINAL_CLTV_EXPIRY, None)
        return 18 if words is None else _words_to_int(words)

    @property
    def features(self) -> int:
        """Return the `9` field as a bitfield, 0 where none was stated.

        The bitfield, and not a verdict on it: `assert_valid` refuses
        an even bit BOLT9 does not assign, and a feature whose own
        dependencies the vector leaves unset. A caller acting on the
        invoice checks the assigned bits against what it has itself
        implemented, `btclib.bolt9.FEATURE_NAMES` being that table.
        """
        words = _first(self.tagged_fields, _TAG_FEATURES, None)
        return 0 if words is None else _words_to_int(words)

    @property
    def metadata(self) -> bytes | None:
        """Return the `m` field, `None` where the invoice carries none."""
        words = _first(self.tagged_fields, _TAG_METADATA, None)
        return None if words is None else _words_to_bytes(words)

    @property
    def _stated_payee(self) -> bytes | None:
        words = _first(self.tagged_fields, _TAG_PAYEE, 53)
        return None if words is None else _words_to_bytes(words)

    @property
    def payee(self) -> bytes:
        """Return the 33-byte compressed payee pubkey, stated or recovered.

        A stated `n` field is verified directly and demands a canonical
        low-s signature; absent one, the pubkey is recovered from the
        signature instead, and either form of s is accepted -- BOLT11's
        own two examples of exactly this pair, see the module docstring.

        The recovery id is always the low-s R's, whichever form of s the
        wire carries: BOLT11's "public-key recovery with high-S
        signature" example is the "please make a donation" example with
        s replaced by `n - s` and the recovery id left unchanged, which
        is malleating s alone rather than a second signature -- the same
        r and the same R, its y merely renamed by which of s and n - s
        names it. libsecp256k1's own recoverable-signature module never
        emits a high-s recid to begin with, so recovering the r and the
        low-s form of whatever s is stored is what makes both of BOLT11's
        examples resolve to the same key, and is not a normalization this
        module invented for the occasion.
        """
        msg_hash = self._message_hash()
        stated = self._stated_payee
        if stated is not None:
            if self.signature.s > secp256k1.n // 2:
                raise BTClibValueError(
                    "a stated payee ('n' field) requires a low-s signature"
                )
            if not verify_(msg_hash, stated, self.signature):
                raise BTClibValueError("signature does not match the stated payee")
            return stated
        low_s = min(self.signature.s, secp256k1.n - self.signature.s)
        recoverable = Sig(self.signature.r, low_s, check_validity=False)
        point = recover_pub_key_(self.recovery_id, msg_hash, recoverable)
        return bytes_from_point(point, secp256k1, compressed=True)

    @property
    def fallback_addresses(self) -> tuple[str, ...]:
        """Return the `f` fields as addresses, skipping unknown versions.

        BOLT11: "a reader MUST skip over f fields that use an unknown
        version" -- versions 19-31, which is what the `elif` below
        falls through on without raising.
        """
        addresses = []
        for tag, words in self.tagged_fields:
            if tag != _TAG_FALLBACK or not words:
                continue
            version = words[0]
            try:
                program = _words_to_bytes(words[1:])
                if 0 <= version <= 16:
                    addresses.append(
                        address_from_witness(version, program, self.network)
                    )
                elif version in (17, 18):
                    script_type: Literal["p2pkh", "p2sh"] = (
                        "p2pkh" if version == 17 else "p2sh"
                    )
                    addresses.append(
                        address_from_h160(script_type, program, self.network)
                    )
            except BTClibValueError:
                continue
        return tuple(addresses)

    @property
    def route_hints(self) -> tuple[tuple[RouteHintHop, ...], ...]:
        """Return the `r` fields, each as an ordered tuple of hops."""
        routes = []
        for tag, words in self.tagged_fields:
            if tag != _TAG_ROUTING_INFO:
                continue
            try:
                blob = _words_to_bytes(words)
            except BTClibValueError:
                continue
            if not blob or len(blob) % _HOP_SIZE:
                continue
            # a fixed-width byte slice, and every field of a hop reads off
            # exactly the octets its own range allows -- 8 bytes into
            # 2**64, 2 into 2**16 -- so assert_valid has nothing to
            # refuse that this slicing could not already have produced
            routes.append(
                tuple(
                    RouteHintHop._parse(blob[i : i + _HOP_SIZE], check_validity=False)
                    for i in range(0, len(blob), _HOP_SIZE)
                )
            )
        return tuple(routes)

    def to_invoice(self) -> str:
        """Return the bech32 string of this invoice, signature included."""
        hrp = _hrp(self.network, self.amount_msat)
        data_words = list(_int_to_words(self.timestamp, 7))
        for tag, words in self.tagged_fields:
            data_words += [tag, *_int_to_words(len(words), 2), *words]
        sig_bytes = (
            self.signature.r.to_bytes(32, "big")
            + self.signature.s.to_bytes(32, "big")
            + bytes([self.recovery_id])
        )
        data_words += _bytes_to_words(sig_bytes)
        return _bech32_encode(hrp, data_words, m=1).decode("ascii")

    @classmethod
    def from_invoice(
        cls, invoice: str, *, check_validity: bool = True
    ) -> Bolt11Invoice:
        """Return the Bolt11Invoice of a bech32 BOLT11 string.

        A `str` and not the `Octets` an octet-stream parser takes: an
        invoice is text, like `Bip21.parse`'s own `uri`.
        """
        assert_type(invoice, str, "invoice")
        hrp, data = _bech32_decode(invoice, m=1)
        network, amount_msat = _parse_hrp(hrp)

        if len(data) < 7 + _SIGNATURE_WORDS:
            raise BTClibValueError(f"invoice too short: {invoice[:32]!r}")

        timestamp = _words_to_int(data[:7])
        tagged_fields = _parse_tagged_fields(data[7:-_SIGNATURE_WORDS])

        sig_bytes = _words_to_bytes(data[-_SIGNATURE_WORDS:])
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        recovery_id = sig_bytes[64]
        signature = Sig(r, s, check_validity=check_validity)

        return cls(
            network,
            timestamp,
            tagged_fields,
            signature,
            recovery_id,
            amount_msat,
            check_validity=check_validity,
        )

    @classmethod
    def sign(
        cls,
        prv_key: Integer,
        network: str,
        timestamp: Integer,
        payment_hash: Octets,
        payment_secret: Octets,
        *,
        amount_msat: Integer | None = None,
        description: str | None = None,
        description_hash: Octets | None = None,
        expiry: Integer | None = None,
        min_final_cltv_expiry: Integer | None = None,
        fallback_addresses: Sequence[str] = (),
        route_hints: Sequence[Sequence[RouteHintHop]] = (),
        features: Integer = 0,
        metadata: Octets | None = None,
        extra_tags: Sequence[tuple[int, Sequence[int]]] = (),
        check_validity: bool = True,
    ) -> Bolt11Invoice:
        """Build and sign a new invoice.

        Exactly one of `description` and `description_hash` is required,
        BOLT11's own rule; the payee is always stated as an `n` field,
        derived from `prv_key`, rather than left to recovery -- a
        stronger reader check than the BOLT requires and never a weaker
        one, see the module docstring.
        """
        if (description is None) == (description_hash is None):
            err_msg = "exactly one of description and description_hash is required"
            raise BTClibValueError(err_msg)

        _, payee_point = gen_keys(prv_key, secp256k1)
        payee = bytes_from_point(payee_point, secp256k1, compressed=True)

        fields: list[tuple[int, tuple[int, ...]]] = [
            (_TAG_PAYMENT_HASH, _bytes_to_words(bytes_from_octets(payment_hash, 32))),
            (
                _TAG_PAYMENT_SECRET,
                _bytes_to_words(bytes_from_octets(payment_secret, 32)),
            ),
        ]
        if description is not None:
            fields.append(
                (_TAG_DESCRIPTION, _bytes_to_words(description.encode("utf-8")))
            )
        else:
            assert description_hash is not None  # noqa: S101 -- narrows for mypy
            fields.append(
                (
                    _TAG_DESCRIPTION_HASH,
                    _bytes_to_words(bytes_from_octets(description_hash, 32)),
                )
            )
        if metadata is not None:
            fields.append((_TAG_METADATA, _bytes_to_words(bytes_from_octets(metadata))))
        if expiry is not None:
            fields.append((_TAG_EXPIRY, _minimal_int_words(int_from_integer(expiry))))
        if min_final_cltv_expiry is not None:
            fields.append(
                (
                    _TAG_MIN_FINAL_CLTV_EXPIRY,
                    _minimal_int_words(int_from_integer(min_final_cltv_expiry)),
                )
            )
        fields.append((_TAG_PAYEE, _bytes_to_words(payee)))
        fields.extend(
            _fallback_field(address, network) for address in fallback_addresses
        )
        for hops in route_hints:
            blob = b"".join(hop._serialize() for hop in hops)
            fields.append((_TAG_ROUTING_INFO, _bytes_to_words(blob)))
        features_int = int_from_integer(features)
        if features_int:
            fields.append((_TAG_FEATURES, _minimal_int_words(features_int)))
        fields.extend((tag, tuple(words)) for tag, words in extra_tags)

        hrp = _hrp(
            network, None if amount_msat is None else int_from_integer(amount_msat)
        )
        data_words = list(_int_to_words(int_from_integer(timestamp), 7))
        for tag, words in fields:
            data_words += [tag, *_int_to_words(len(words), 2), *words]
        msg_hash = sha256(
            hrp.encode("ascii") + bytes(power_of_2_base_conversion(data_words, 5, 8))
        )
        signature, recovery_id = sign_recoverable_(msg_hash, prv_key)

        return cls(
            network,
            timestamp,
            fields,
            signature,
            recovery_id,
            amount_msat,
            check_validity=check_validity,
        )
