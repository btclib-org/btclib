# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip21` module.

The URIs of the "Examples" section of BIP21 are the vectors, transcribed
from the BIP's prose rather than pulled from a file -- so their
provenance is here and not in tests/_data/README.md, which records where
the vector *files* came from.

One character had to change on the way in, and it is worth knowing:
BIP21 prints the address `175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W` in every
example, and that string does not checksum. Its 21-byte payload is
sound -- `0042bd6b9eeb1da01504fefe014e16415246c0f66f`, a mainnet p2pkh
hash160 -- and hash256 of it begins `8a9c6111` where the address carries
`8a9c6129`, so the last base58 character should be `6` and the BIP
writes `W`. The corrected address is what these tests use;
test_bip21s_own_example_address_does_not_checksum pins the divergence,
so nothing here quietly disagrees with the document it cites.
"""

from decimal import Decimal

import pytest

from btclib.bip21 import Bip21
from btclib.bolt11 import Bolt11Invoice
from btclib.exceptions import BTClibTypeError, BTClibValueError

# BIP21's example address, with its last character corrected
ADDR = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv2456"
BIP21_ADDR = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"


def test_bip21s_own_example_address_does_not_checksum() -> None:
    """The address the BIP prints is not a valid one, by one character."""
    assert BIP21_ADDR[:-1] == ADDR[:-1]
    with pytest.raises(BTClibValueError, match="invalid checksum"):
        Bip21.parse(f"bitcoin:{BIP21_ADDR}")


def test_bip21_own_examples() -> None:
    """The "Examples" section of BIP21, in order."""
    # just the address
    uri = Bip21.parse(f"bitcoin:{ADDR}")
    assert uri.address == ADDR
    assert uri.amount is None
    assert uri.label is None
    assert uri.message is None
    assert not uri.others
    assert uri.network_type == "main"
    assert uri.serialize() == f"bitcoin:{ADDR}"

    # with a label
    uri = Bip21.parse(f"bitcoin:{ADDR}?label=Luke-Jr")
    assert uri.label == "Luke-Jr"
    assert uri.amount is None
    assert uri.serialize() == f"bitcoin:{ADDR}?label=Luke-Jr"

    # a request for 20.30 BTC to "Luke-Jr"
    uri = Bip21.parse(f"bitcoin:{ADDR}?amount=20.3&label=Luke-Jr")
    assert uri.amount == Decimal("20.3")
    assert uri.label == "Luke-Jr"
    assert uri.serialize() == f"bitcoin:{ADDR}?amount=20.3&label=Luke-Jr"

    # a request for 50 BTC with a message
    uri = Bip21.parse(
        f"bitcoin:{ADDR}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
    )
    assert uri.amount == Decimal(50)
    assert uri.label == "Luke-Jr"
    assert uri.message == "Donation for project xyz"
    assert uri.serialize() == (
        f"bitcoin:{ADDR}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
    )

    # some unknown parameters, which are to be ignored
    uri = Bip21.parse(
        f"bitcoin:{ADDR}?somethingyoudontunderstand=50&somethingelseyoudontget=999"
    )
    assert uri.others == {
        "somethingyoudontunderstand": "50",
        "somethingelseyoudontget": "999",
    }
    assert uri.amount is None

    # a required parameter that is not understood, which invalidates it
    with pytest.raises(BTClibValueError, match="unknown required parameter"):
        Bip21.parse(f"bitcoin:{ADDR}?req-somethingyoudontunderstand=50")


def test_the_req_prefix_is_the_only_thing_that_invalidates_a_parameter() -> None:
    """BIP21's whole forward-compatibility story, and both halves of it."""
    # ignored, whatever it is
    for key in ("foo", "reqfoo", "request", "-req-foo", "amountx"):
        assert Bip21.parse(f"bitcoin:{ADDR}?{key}=1").others == {key: "1"}

    # refused, whatever it is
    for key in ("req-", "req-foo", "req-amount"):
        with pytest.raises(BTClibValueError, match="unknown required parameter"):
            Bip21.parse(f"bitcoin:{ADDR}?{key}=1")

    # refused in any case: the rule is there to fail closed, and reading
    # the prefix case-sensitively would let REQ-foo through as unknown
    with pytest.raises(BTClibValueError, match="unknown required parameter"):
        Bip21.parse(f"bitcoin:{ADDR}?REQ-foo=1")

    # and refused when the prefix arrives percent-encoded
    with pytest.raises(BTClibValueError, match="unknown required parameter"):
        Bip21.parse(f"bitcoin:{ADDR}?%72eq-foo=1")


def test_the_amount_is_decimal_btc() -> None:
    """Verify the amount grammar: decimal BTC, digits and one dot only."""
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=0.00000001").amount == Decimal("1e-8")
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=21000000").amount == Decimal(21000000)
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=0").amount == Decimal(0)
    # trailing and leading zeros are the same request
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=1.").amount == Decimal(1)
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=.5").amount == Decimal("0.5")

    # satoshi are not the unit, so nine decimals is not an amount
    with pytest.raises(BTClibValueError, match="too many decimals"):
        Bip21.parse(f"bitcoin:{ADDR}?amount=0.000000001")

    # above what exists
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        Bip21.parse(f"bitcoin:{ADDR}?amount=21000001")

    # BIP21's grammar is digits and at most one dot: everything else
    # Decimal would happily take means something the URI does not say
    for bad in ("1e5", "+1", "-1", " 1", "1 ", "Infinity", "NaN", "0x1", "", "."):
        with pytest.raises(BTClibValueError, match="invalid bip21 amount"):
            Bip21.parse(f"bitcoin:{ADDR}?amount={bad}")


def test_a_repeated_key_is_an_error() -> None:
    """Two amounts are two requests, and choosing is choosing for the payer."""
    with pytest.raises(BTClibValueError, match="repeated parameter: amount"):
        Bip21.parse(f"bitcoin:{ADDR}?amount=1&amount=2")
    with pytest.raises(BTClibValueError, match="repeated parameter: label"):
        Bip21.parse(f"bitcoin:{ADDR}?label=a&label=b")
    with pytest.raises(BTClibValueError, match="repeated parameter: foo"):
        Bip21.parse(f"bitcoin:{ADDR}?foo=1&foo=2")


def test_percent_encoding() -> None:
    """Verify percent-decoding: unquote, not unquote_plus, and %FF raises."""
    uri = Bip21.parse(f"bitcoin:{ADDR}?message=100%25%20of%20it%20%26%20more")
    assert uri.message == "100% of it & more"
    assert Bip21.parse(uri.serialize()).message == uri.message

    # unquote and not unquote_plus: a plus sign is a plus sign, the
    # space-for-plus rule belonging to HTML forms and not to a URI
    assert Bip21.parse(f"bitcoin:{ADDR}?label=Alice+Bob").label == "Alice+Bob"

    # a label is any text once decoded
    label = "Nakamoto's caffè, 100% \u2014 and a ? too"
    uri = Bip21(ADDR, None, label, None)
    assert "%" in uri.serialize()
    assert Bip21.parse(uri.serialize()).label == label

    # a mangled escape is not a label with a replacement character in it
    with pytest.raises(BTClibValueError, match="invalid percent-encoding"):
        Bip21.parse(f"bitcoin:{ADDR}?label=%FF")


def test_a_percent_that_escapes_nothing_is_not_text() -> None:
    """Malformed syntax is a second fault, and `errors="strict"` misses it.

    That flag is the error handler of the utf-8 decode that follows the
    unescaping, so it answers `%FF` -- an escape of an octet that is not
    text -- and says nothing about `%ZZ`, which is not an escape: `unquote`
    leaves the percent sign as literal text. What makes that a defect and
    not a leniency is the round trip, `serialize` writing a literal percent
    sign as `%25`: `label=%ZZ` came back out as `label=%25ZZ`, two URIs
    meaning one request with only one of them written.
    """
    for escape in ("%", "%2", "%G0", "%0G", "%ZZ", "%%41", "a%b"):
        for query in (
            f"label={escape}",
            f"message={escape}",
            f"foo={escape}",
            f"{escape}=1",
        ):
            with pytest.raises(BTClibValueError, match="malformed percent escape"):
                Bip21.parse(f"bitcoin:{ADDR}?{query}")

    # and what the refusal must not take with it: either case of hex, the
    # escape of a percent sign itself, and a multi-octet character
    uri = Bip21.parse(f"bitcoin:{ADDR}?label=%2f%2F&message=100%25&foo=caff%C3%A8")
    assert uri.label == "//"
    assert uri.message == "100%"
    assert uri.others == {"foo": "caffè"}
    assert Bip21.parse(uri.serialize()) == uri


def test_the_address_is_not_lowercased() -> None:
    """A bech32 address is legally uppercase; a base58 one is not."""
    bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert Bip21.parse(f"bitcoin:{bech32}").address == bech32
    # the QR-code case: the whole URI uppercase, scheme included
    upper = f"BITCOIN:{bech32.upper()}?AMOUNT=1".replace("AMOUNT", "amount")
    parsed = Bip21.parse(upper)
    assert parsed.address == bech32.upper()
    assert parsed.network_type == "main"

    # mixed case is what bech32 refuses, and it is refused here too
    with pytest.raises(BTClibValueError, match="mixed case"):
        Bip21.parse(f"bitcoin:{bech32.capitalize()}")

    # base58 has no such licence: uppercasing breaks the checksum
    with pytest.raises(BTClibValueError, match="invalid checksum"):
        Bip21.parse(f"bitcoin:{ADDR.upper()}")


def test_networks_other_than_mainnet() -> None:
    """What a non-mainnet address says, which is "test" and no more.

    A network name would over-answer: the first address below is testnet,
    signet and testnet4 at once, and the second is those three and
    regtest. A payer needs to know the request is not for real bitcoin,
    which is exactly what "test" says.
    """
    for address in (
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc",
    ):
        assert Bip21.parse(f"bitcoin:{address}").network_type == "test"

    # and the whole point of the type: a test address is never "main"
    assert Bip21.parse(f"bitcoin:{ADDR}").network_type == "main"


def test_a_uri_that_is_not_one() -> None:
    """Refuse non-bitcoin URIs, bytes input and a missing address."""
    for uri in ("", ADDR, f"http://{ADDR}", f"bitcoincash:{ADDR}", "bitcoin"):
        with pytest.raises(BTClibValueError, match="not a bitcoin URI"):
            Bip21.parse(uri)

    # a type and not a value, `uri` declaring `str` alone: the bytes of a
    # URI are not a spelling of it, where the octets of a signature are
    with pytest.raises(BTClibTypeError, match="invalid uri type"):
        Bip21.parse(b"bitcoin:")  # type: ignore[arg-type]

    # the scheme with nothing after it
    with pytest.raises(BTClibValueError, match="missing address"):
        Bip21.parse("bitcoin:")

    with pytest.raises(BTClibValueError, match="missing address"):
        Bip21.parse("bitcoin:?amount=1")


def test_round_trip() -> None:
    """Round-trip parse and serialize; only the amount is normalized."""
    for uri in (
        f"bitcoin:{ADDR}",
        f"bitcoin:{ADDR}?amount=1",
        f"bitcoin:{ADDR}?amount=0.00000001",
        f"bitcoin:{ADDR}?label=Luke-Jr",
        f"bitcoin:{ADDR}?amount=20.3&label=Luke-Jr",
        f"bitcoin:{ADDR}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
        f"bitcoin:{ADDR}?foo=bar",
        "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.1",
    ):
        assert Bip21.parse(uri).serialize() == uri
        assert Bip21.parse(uri) == Bip21.parse(Bip21.parse(uri).serialize())

    # what a round trip normalizes rather than preserves, and why: the
    # amount is a Decimal by the time it is written back
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=1.").serialize() == (
        f"bitcoin:{ADDR}?amount=1"
    )
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=.5").serialize() == (
        f"bitcoin:{ADDR}?amount=0.5"
    )
    assert Bip21.parse(f"bitcoin:{ADDR}?amount=0.10000000").serialize() == (
        f"bitcoin:{ADDR}?amount=0.1"
    )


def test_odds_and_ends_of_the_grammar() -> None:
    """Verify empty elements, valueless keys, fragments and empty names."""
    # bitcoinparam admits the empty element
    assert Bip21.parse(f"bitcoin:{ADDR}?&amount=1&").amount == Decimal(1)
    # a parameter with no value
    assert Bip21.parse(f"bitcoin:{ADDR}?foo").others == {"foo": ""}
    # not `not label`: label is `str | None`, and this is the case of
    # an explicit but empty label, which a missing one is not
    assert Bip21.parse(f"bitcoin:{ADDR}?label=").label == ""
    # a fragment is not a parameter
    assert not Bip21.parse(f"bitcoin:{ADDR}?#foo=1").others
    # an empty parameter name is not one either
    with pytest.raises(BTClibValueError, match="empty parameter name"):
        Bip21.parse(f"bitcoin:{ADDR}?=1")


def test_built_rather_than_parsed() -> None:
    """Verify a Bip21 built from arguments validates and serializes."""
    uri = Bip21(ADDR, "20.3", "Luke-Jr", "Donation for project xyz")
    assert uri.amount == Decimal("20.3")
    assert uri.serialize() == (
        f"bitcoin:{ADDR}?amount=20.3&label=Luke-Jr&message=Donation%20for%20project%20xyz"
    )
    # the amount is whatever valid_btc_amount takes, a float excepted
    assert Bip21(ADDR, Decimal("20.3"), None, None).amount == Decimal("20.3")
    assert Bip21(ADDR, 20, None, None).amount == Decimal(20)
    with pytest.raises(BTClibValueError, match="too many decimals"):
        Bip21(ADDR, "0.000000001", None, None)
    # the address decoder is the validation, and its own message is what
    # comes out: more use than an "invalid address" wrapping it
    with pytest.raises(BTClibValueError, match="invalid characters"):
        Bip21("not an address", None, None, None)
    with pytest.raises(BTClibValueError, match="missing address"):
        Bip21("", None, None, None)


def test_the_flag_still_switches_the_check_off() -> None:
    """Verify check_validity=False builds and writes an addressless URI.

    Every URI above is built checked, so `if check_validity:` was a line
    that ran one way only, which is what branch coverage reports and
    statement coverage does not. The empty address is the invalidity to
    carry here because it is the one a serialization can still write: a
    bad amount is refused by `valid_btc_amount` on the way in, before the
    flag is read, so it could not stand in for it.
    """
    uri = Bip21("", None, None, None, check_validity=False)
    assert uri.address == ""
    assert uri.serialize(check_validity=False) == "bitcoin:"
    with pytest.raises(BTClibValueError, match="missing address"):
        uri.serialize()


# a mainnet BOLT11 invoice for 0.02 BTC (2,000,000,000 msat), payment
# hash and payment secret both zero, signed with the BOLT's own example
# `priv_key` -- Bolt11Invoice.sign is what tests/bolt11_test.py exercises
# on its own, this only needs one already-signed instance
_INVOICE = Bolt11Invoice.sign(
    "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734",
    "mainnet",
    1496314658,
    payment_hash=bytes(32),
    payment_secret=bytes(32),
    description="d",
    amount_msat=2_000_000_000,
)


def test_lightning_parameter_is_typed_not_kept_in_others() -> None:
    """A `lightning=` parameter no longer joins `others`, unlike before."""
    uri = Bip21.parse(f"bitcoin:{ADDR}?lightning={_INVOICE.to_invoice()}")
    assert isinstance(uri.lightning, Bolt11Invoice)
    assert uri.lightning.to_invoice() == _INVOICE.to_invoice()
    assert "lightning" not in uri.others


def test_lightning_round_trips_through_serialize() -> None:
    """A `Bip21` built with an invoice writes it out and reads it back."""
    uri = Bip21(ADDR, lightning=_INVOICE)
    text = uri.serialize()
    assert f"lightning={_INVOICE.to_invoice()}" in text
    parsed = Bip21.parse(text).lightning
    assert parsed is not None
    assert parsed.to_invoice() == _INVOICE.to_invoice()


def test_lightning_network_mismatch_is_refused() -> None:
    """A testnet invoice beside a mainnet address is refused."""
    testnet_invoice = Bolt11Invoice.sign(
        "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734",
        "testnet",
        1496314658,
        payment_hash=bytes(32),
        payment_secret=bytes(32),
        description="d",
    )
    with pytest.raises(BTClibValueError, match="network does not match"):
        Bip21(ADDR, lightning=testnet_invoice)


def test_lightning_amount_mismatch_is_refused() -> None:
    """A URI amount disagreeing with the invoice's own is refused."""
    with pytest.raises(BTClibValueError, match="amount does not match"):
        Bip21(ADDR, amount="1", lightning=_INVOICE)


def test_lightning_amount_consistent_is_accepted() -> None:
    """A URI amount agreeing with the invoice's own is accepted."""
    uri = Bip21(ADDR, amount="0.02", lightning=_INVOICE)
    assert uri.lightning is _INVOICE
