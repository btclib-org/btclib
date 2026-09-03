# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bolt11` module.

BOLT11's own examples (`11-payment-encoding.md`) are the vectors,
vendored at `tests/_data/bolt11_test_vectors.json` -- `tests/_data/README.md`
is where the pin lives. Every valid example is parsed, its stated facts
checked against the BOLT's own breakdown, and re-encoded byte for byte;
every invalid one is refused. All of them are signed with the BOLT's own
`priv_key`,
`e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734`.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib.b32 import power_of_2_base_conversion
from btclib.bech32 import encode as bech32_encode
from btclib.bolt11 import Bolt11Invoice, RouteHintHop
from btclib.ecc.dsa import Sig
from btclib.exceptions import BTClibTypeError, BTClibValueError
from tests import load, vector_id

_PRV_KEY = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"

_VECTORS = load("_data", "bolt11_test_vectors.json")
_VALID = _VECTORS["valid"]
_INVALID = _VECTORS["invalid"]
_VALID_IDS = [vector_id(i, v["name"]) for i, v in enumerate(_VALID)]
_INVALID_IDS = [vector_id(i, v["name"]) for i, v in enumerate(_INVALID)]


def _assert_route_hints_match(invoice: Bolt11Invoice, vector: dict[str, Any]) -> None:
    """Compare every routing hop against the vector's own breakdown."""
    expected_routes = vector["route_hints"]
    assert len(invoice.route_hints) == len(expected_routes)
    for route, expected_route in zip(invoice.route_hints, expected_routes, strict=True):
        assert len(route) == len(expected_route)
        for hop, expected_hop in zip(route, expected_route, strict=True):
            assert hop.pubkey == bytes.fromhex(expected_hop["pubkey"])
            assert hop.short_channel_id == expected_hop["short_channel_id"]
            assert hop.fee_base_msat == expected_hop["fee_base_msat"]
            assert (
                hop.fee_proportional_millionths
                == (expected_hop["fee_proportional_millionths"])
            )
            assert hop.cltv_expiry_delta == expected_hop["cltv_expiry_delta"]


@pytest.mark.parametrize("vector", _VALID, ids=_VALID_IDS)
def test_bolt11_own_valid_examples(vector: dict[str, Any]) -> None:
    """Check every field the BOLT states, then a byte-exact round trip."""
    invoice = Bolt11Invoice.from_invoice(vector["invoice"])

    assert invoice.network == vector["network"]
    assert invoice.amount_msat == vector["amount_msat"]
    assert invoice.timestamp == vector["timestamp"]
    assert invoice.payment_hash == bytes.fromhex(vector["payment_hash"])
    if "payee" in vector:
        assert invoice.payee == bytes.fromhex(vector["payee"])
    if "description" in vector:
        assert invoice.description == vector["description"]
        assert invoice.description_hash is None
    if "description_hash" in vector:
        assert invoice.description_hash == bytes.fromhex(vector["description_hash"])
        assert invoice.description is None
    if "fallback_addresses" in vector:
        assert list(invoice.fallback_addresses) == vector["fallback_addresses"]
    if "route_hints" in vector:
        _assert_route_hints_match(invoice, vector)
    if "features" in vector:
        assert invoice.features == vector["features"]
    if "metadata" in vector:
        assert invoice.metadata == bytes.fromhex(vector["metadata"])
    if "expiry" in vector:
        assert invoice.expiry == vector["expiry"]
    if "min_final_cltv_expiry" in vector:
        assert invoice.min_final_cltv_expiry == vector["min_final_cltv_expiry"]

    # BOLT11 does not fix field order across tags, so a byte-exact round
    # trip is only expected against the invoice's own case; two of the
    # vectors are the same invoice with the ascii letters upper-cased,
    # which `bech32.encode` never reproduces
    assert invoice.to_invoice() == vector["invoice"].lower()


@pytest.mark.parametrize("vector", _INVALID, ids=_INVALID_IDS)
def test_bolt11_own_invalid_examples(vector: dict[str, Any]) -> None:
    """Every invoice BOLT11's own "Examples of Invalid Invoices" refuses."""
    with pytest.raises(BTClibValueError):
        Bolt11Invoice.from_invoice(vector["invoice"])


def test_sign_and_decode_round_trip() -> None:
    """A freshly signed invoice decodes back to what it was signed with."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        1700000000,
        payment_hash=bytes(range(32)),
        payment_secret=b"\x11" * 32,
        amount_msat=250_000_000,
        description="fresh invoice",
        expiry=7200,
        min_final_cltv_expiry=40,
        fallback_addresses=[
            "1RustyRX2oai4EYYDpQGWvEL62BBGqN9T",
            "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ],
        route_hints=[
            [
                RouteHintHop(
                    bytes.fromhex(
                        "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
                    ),
                    66051 * 2**40 + 263430 * 2**16 + 1800,
                    1,
                    20,
                    3,
                )
            ]
        ],
        features=(1 << 8) | (1 << 14),
        metadata=b"\x01\xfa\xfa\xf0",
        extra_tags=[(31, (1, 2, 3))],
    )
    text = invoice.to_invoice()
    decoded = Bolt11Invoice.from_invoice(text)

    assert decoded.network == "mainnet"
    assert decoded.amount_msat == 250_000_000
    assert decoded.payment_hash == bytes(range(32))
    assert decoded.payment_secret == b"\x11" * 32
    assert decoded.description == "fresh invoice"
    assert decoded.expiry == 7200
    assert decoded.min_final_cltv_expiry == 40
    assert decoded.fallback_addresses == invoice.fallback_addresses
    assert decoded.features == (1 << 8) | (1 << 14)
    assert decoded.metadata == b"\x01\xfa\xfa\xf0"
    assert (31, (1, 2, 3)) in decoded.tagged_fields
    assert decoded.to_invoice() == text


def test_sign_derives_the_payee_from_the_private_key() -> None:
    """A signed invoice with no explicit `n` field still recovers it."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        1496314658,
        payment_hash=bytes(32),
        payment_secret=b"\x11" * 32,
        description="d",
    )
    assert invoice.payee == bytes.fromhex(
        "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
    )


def test_sign_with_description_hash() -> None:
    """`description_hash=` produces an `h` field, not a `d` one."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        1496314658,
        payment_hash=bytes(32),
        payment_secret=b"\x11" * 32,
        description_hash=bytes(32),
    )
    assert invoice.description is None
    assert invoice.description_hash == bytes(32)


def test_sign_refuses_neither_or_both_description() -> None:
    """Exactly one of `description`/`description_hash` is required."""
    with pytest.raises(BTClibValueError, match="exactly one"):
        Bolt11Invoice.sign(
            _PRV_KEY, "mainnet", 0, payment_hash=bytes(32), payment_secret=bytes(32)
        )
    with pytest.raises(BTClibValueError, match="exactly one"):
        Bolt11Invoice.sign(
            _PRV_KEY,
            "mainnet",
            0,
            payment_hash=bytes(32),
            payment_secret=bytes(32),
            description="d",
            description_hash=bytes(32),
        )


def test_bolt11_defaults_expiry_and_min_final_cltv_expiry() -> None:
    """BOLT11's own defaults stand where the tags are absent."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        0,
        payment_hash=bytes(32),
        payment_secret=bytes(32),
        description="d",
    )
    assert invoice.expiry == 3600
    assert invoice.min_final_cltv_expiry == 18
    assert invoice.features == 0
    assert invoice.metadata is None
    assert not invoice.fallback_addresses
    assert not invoice.route_hints


@pytest.mark.parametrize("network", ["testnet", "regtest", "signet"])
def test_bolt11_every_network_prefix_round_trips(network: str) -> None:
    """Every non-mainnet network prefix survives a round trip."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        network,
        0,
        payment_hash=bytes(32),
        payment_secret=bytes(32),
        description="d",
    )
    assert Bolt11Invoice.from_invoice(invoice.to_invoice()).network == network


def test_bolt11_amount_round_trips_the_shortest_multiplier() -> None:
    """Every multiplier, including the pico fallback, round trips."""
    # exact bitcoin, milli, micro, nano and a value needing pico
    for amount_msat in (10**11, 5 * 10**8, 3 * 10**5, 7 * 10**2, 1):
        invoice = Bolt11Invoice.sign(
            _PRV_KEY,
            "mainnet",
            0,
            payment_hash=bytes(32),
            payment_secret=bytes(32),
            description="d",
            amount_msat=amount_msat,
        )
        assert Bolt11Invoice.from_invoice(invoice.to_invoice()).amount_msat == (
            amount_msat
        )


def test_from_invoice_takes_text_not_octets() -> None:
    """Octets are refused: an invoice is text, not a byte stream."""
    with pytest.raises(BTClibTypeError):
        Bolt11Invoice.from_invoice(b"lnbc1...")  # type: ignore[arg-type]


def test_assert_valid_refuses_an_unknown_network() -> None:
    """A network `bech32` never issues a prefix for is refused."""
    with pytest.raises(BTClibValueError, match="not a lightning network"):
        Bolt11Invoice(
            "testnet4",
            0,
            [(1, (0,) * 52), (16, (0,) * 52), (13, _pow_2_words(b"d"))],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()


def test_assert_valid_refuses_an_out_of_range_timestamp() -> None:
    """A timestamp that does not fit 35 bits is refused."""
    with pytest.raises(BTClibValueError, match="35 bits"):
        Bolt11Invoice(
            "mainnet",
            1 << 35,
            [(1, (0,) * 52), (16, (0,) * 52), (13, _pow_2_words(b"d"))],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()


def test_assert_valid_refuses_a_non_positive_amount() -> None:
    """A zero or negative amount is refused."""
    with pytest.raises(BTClibValueError, match="invalid amount"):
        Bolt11Invoice(
            "mainnet",
            0,
            [(1, (0,) * 52), (16, (0,) * 52), (13, _pow_2_words(b"d"))],
            Sig(1, 1, check_validity=False),
            0,
            amount_msat=0,
            check_validity=False,
        ).assert_valid()


def test_assert_valid_refuses_an_out_of_range_recovery_id() -> None:
    """A recovery id outside 0-3 is refused."""
    with pytest.raises(BTClibValueError, match="recovery id"):
        Bolt11Invoice(
            "mainnet",
            0,
            [(1, (0,) * 52), (16, (0,) * 52), (13, _pow_2_words(b"d"))],
            Sig(1, 1, check_validity=False),
            4,
            check_validity=False,
        ).assert_valid()


def test_missing_payment_hash_or_secret_is_refused() -> None:
    """Either tag missing from `tagged_fields` is refused."""
    with pytest.raises(BTClibValueError, match="payment_hash"):
        Bolt11Invoice(
            "mainnet",
            0,
            [(16, (0,) * 52), (13, (0,))],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()
    with pytest.raises(BTClibValueError, match="payment_secret"):
        Bolt11Invoice(
            "mainnet",
            0,
            [(1, (0,) * 52), (13, (0,))],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()


def test_description_and_description_hash_are_mutually_required() -> None:
    """Neither present, or both present, is refused."""
    with pytest.raises(BTClibValueError, match="exactly one"):
        Bolt11Invoice(
            "mainnet",
            0,
            [(1, (0,) * 52), (16, (0,) * 52)],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()
    with pytest.raises(BTClibValueError, match="exactly one"):
        Bolt11Invoice(
            "mainnet",
            0,
            [
                (1, (0,) * 52),
                (16, (0,) * 52),
                (13, _pow_2_words(b"d")),
                (23, (0,) * 52),
            ],
            Sig(1, 1, check_validity=False),
            0,
            check_validity=False,
        ).assert_valid()


def test_description_refuses_invalid_utf8() -> None:
    """A `d` field that is not valid UTF-8 is refused."""
    # 0x80 alone is a continuation byte with nothing to continue
    words = tuple(_pow_2_words(b"\x80"))
    invoice = Bolt11Invoice(
        "mainnet",
        0,
        [(1, (0,) * 52), (16, (0,) * 52), (13, words)],
        Sig(1, 1, check_validity=False),
        0,
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="UTF-8"):
        _ = invoice.description


def _pow_2_words(data: bytes) -> tuple[int, ...]:
    return tuple(power_of_2_base_conversion(list(data), 8, 5))


def test_fallback_addresses_skips_unknown_versions_and_malformed_data() -> None:
    """An empty, unknown-version or malformed `f` field is skipped."""
    invoice = Bolt11Invoice(
        "mainnet",
        0,
        [
            (1, (0,) * 52),
            (16, (0,) * 52),
            (13, (0,)),
            (9, ()),  # empty: skipped
            (9, (19, *_pow_2_words(bytes(20)))),  # unknown version: skipped
            (9, (0, 1, 1)),  # malformed padding: skipped
        ],
        Sig(1, 1, check_validity=False),
        0,
        check_validity=False,
    )
    assert invoice.fallback_addresses == ()


def test_route_hints_skips_malformed_entries() -> None:
    """An empty or non-hop-sized `r` field is skipped."""
    invoice = Bolt11Invoice(
        "mainnet",
        0,
        [
            (1, (0,) * 52),
            (16, (0,) * 52),
            (13, (0,)),
            (3, ()),  # empty blob: skipped
            (3, (1, 1)),  # not a multiple of one hop: skipped
        ],
        Sig(1, 1, check_validity=False),
        0,
        check_validity=False,
    )
    assert invoice.route_hints == ()


def test_stated_payee_mismatch_is_refused() -> None:
    """A stated `n` field disagreeing with the signature is refused."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        1496314658,
        payment_hash=bytes(32),
        payment_secret=b"\x11" * 32,
        description="d",
    )
    other_pubkey_words = _pow_2_words(
        bytes.fromhex(
            "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
        )
    )
    tampered_fields = tuple(
        (19, other_pubkey_words) if tag == 19 else (tag, words)
        for tag, words in invoice.tagged_fields
    )
    tampered = Bolt11Invoice(
        invoice.network,
        invoice.timestamp,
        tampered_fields,
        invoice.signature,
        invoice.recovery_id,
        invoice.amount_msat,
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="does not match the stated payee"):
        _ = tampered.payee


def test_route_hint_hop_refuses_out_of_range_fields() -> None:
    """Each field of `RouteHintHop` is bound-checked on its own."""
    pubkey = bytes(33)
    with pytest.raises(BTClibValueError, match="short_channel_id"):
        RouteHintHop(pubkey, 2**64, 0, 0, 0)
    with pytest.raises(BTClibValueError, match="fee_base_msat"):
        RouteHintHop(pubkey, 0, 2**32, 0, 0)
    with pytest.raises(BTClibValueError, match="fee_proportional_millionths"):
        RouteHintHop(pubkey, 0, 0, 2**32, 0)
    with pytest.raises(BTClibValueError, match="cltv_expiry_delta"):
        RouteHintHop(pubkey, 0, 0, 0, 2**16)
    # check_validity=False skips every one of the above
    RouteHintHop(pubkey, 2**64, 0, 0, 0, check_validity=False)


def test_route_hint_hop_serialize_parse_round_trip() -> None:
    """51 bytes out, the same hop back in."""
    hop = RouteHintHop(bytes(range(33)), 1234, 5, 6, 7)
    assert RouteHintHop._parse(hop._serialize(), check_validity=True) == hop


def test_sign_refuses_a_timestamp_that_does_not_fit_35_bits() -> None:
    """`sign` refuses what `assert_valid` would refuse too."""
    with pytest.raises(BTClibValueError, match="does not fit 7 5-bit words"):
        Bolt11Invoice.sign(
            _PRV_KEY,
            "mainnet",
            1 << 35,
            payment_hash=bytes(32),
            payment_secret=bytes(32),
            description="d",
        )


def test_sign_with_an_explicit_zero_expiry() -> None:
    """`expiry=0` is not confused with the tag being absent."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        0,
        payment_hash=bytes(32),
        payment_secret=bytes(32),
        description="d",
        expiry=0,
    )
    assert invoice.expiry == 0
    assert Bolt11Invoice.from_invoice(invoice.to_invoice()).expiry == 0


def test_from_invoice_refuses_a_non_lightning_prefix() -> None:
    """A bech32 string with no `ln` prefix is refused."""
    text = bech32_encode("abc", [0] * 10, m=1).decode("ascii")
    with pytest.raises(BTClibValueError, match="not a lightning invoice prefix"):
        Bolt11Invoice.from_invoice(text)


def test_from_invoice_refuses_an_unknown_network_prefix() -> None:
    """A `ln` prefix naming no known network is refused."""
    text = bech32_encode("lnxx", [0] * 10, m=1).decode("ascii")
    with pytest.raises(BTClibValueError, match="unknown network prefix"):
        Bolt11Invoice.from_invoice(text)


def test_from_invoice_refuses_a_truncated_tagged_field_header() -> None:
    """Fewer than 3 leftover words for a tag header is refused."""
    # 7 timestamp words, 2 leftover words (a header is 3), 104 signature
    # words: long enough to pass the length check, too short to hold even
    # one tagged field header
    data = [0] * 7 + [0, 0] + [0] * 104
    text = bech32_encode("lnbc", data, m=1).decode("ascii")
    with pytest.raises(BTClibValueError, match="truncated tagged field header"):
        Bolt11Invoice.from_invoice(text)


def test_from_invoice_refuses_a_tagged_field_overrunning_the_data_part() -> None:
    """A stated data_length longer than what remains is refused."""
    # tag 1, data_length words (31, 31) = 1023, with nothing after them
    data = [0] * 7 + [1, 31, 31] + [0] * 104
    text = bech32_encode("lnbc", data, m=1).decode("ascii")
    with pytest.raises(BTClibValueError, match="overruns the data part"):
        Bolt11Invoice.from_invoice(text)


def test_an_unknown_even_feature_bit_is_refused() -> None:
    """The bit BOLT11's own invalid example sets, named in the refusal."""
    with pytest.raises(BTClibValueError, match="unknown even feature bits: 100"):
        Bolt11Invoice.sign(
            _PRV_KEY,
            "mainnet",
            0,
            payment_hash=bytes(32),
            payment_secret=bytes(32),
            description="d",
            features=1 << 100,
        )


def test_an_unknown_odd_feature_bit_is_carried() -> None:
    """It's ok to be odd: bit 99 is nobody's feature and rides along."""
    invoice = Bolt11Invoice.sign(
        _PRV_KEY,
        "mainnet",
        0,
        payment_hash=bytes(32),
        payment_secret=bytes(32),
        description="d",
        features=1 << 99,
    )
    assert Bolt11Invoice.from_invoice(invoice.to_invoice()).features == 1 << 99
