# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib.fetch.fetcher, the half no backend re-implements."""

from __future__ import annotations

import pytest

from btclib.block.block_header import BlockHeader
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    FetchError,
)
from btclib.fetch.fetcher import (
    Fetcher,
    block_header_from_raw,
    block_header_height,
    fetch_errors,
    tx_for_network,
    tx_from_raw,
    tx_id_hex,
)
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxOut
from tests.fetch import (
    TIP_HEADER_RAW,
    TIP_HEIGHT,
    TIP_ID,
    TX_ID,
    StubFetcher,
    recorded_body,
)

RAW = recorded_body("esplora_tx_hex.txt").decode().strip()
# the coinbase of the same block, which is a different transaction with
# the same provenance: what a backend answering the wrong question sends
OTHER_ID = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"


@pytest.mark.parametrize(
    "error",
    [
        ValueError("not a number"),
        TypeError("nothing to index"),
        # what the stream readers under Tx.parse raise, which is neither
        BTClibRuntimeError("not enough binary data"),
    ],
)
def test_fetch_errors_names_the_source(error: Exception) -> None:
    """Wrap parse-time exceptions in a FetchError naming the call."""
    with (
        pytest.raises(FetchError, match=f"getblockcount: {error}"),
        fetch_errors("getblockcount"),
    ):
        raise error


def test_fetch_errors_lets_a_fetch_error_through() -> None:
    """It is a RuntimeError, so a nested one is not re-wrapped."""
    with (
        pytest.raises(FetchError, match="^the node is down$"),
        fetch_errors("getblockcount"),
    ):
        raise FetchError("the node is down")


def test_fetch_errors_is_transparent_when_nothing_is_raised() -> None:
    """Run the guarded body untouched when it raises nothing."""
    with fetch_errors("getblockcount"):
        value = 481824
    assert value == 481824


def test_tx_id_hex_takes_whatever_octets_takes() -> None:
    """Accept hex, bytes, and whitespace-padded hex alike."""
    assert tx_id_hex(TX_ID) == TX_ID
    assert tx_id_hex(bytes.fromhex(TX_ID)) == TX_ID
    assert tx_id_hex(f"  {TX_ID}  ") == TX_ID


@pytest.mark.parametrize("tx_id", ["", "00", TX_ID + "00", "not hex at all"])
def test_tx_id_hex_refuses_what_is_not_an_id(tx_id: str) -> None:
    """A mistyped id is the caller's error, not the remote host's 404."""
    with pytest.raises(BTClibValueError):
        tx_id_hex(tx_id)


def test_tx_for_network_leaves_mainnet_alone() -> None:
    """Return the very same object for mainnet, not a relabelled copy."""
    tx = Tx.parse(RAW)
    assert tx_for_network(tx, "mainnet") is tx
    # and for every other spelling of it, the name being resolved and not
    # compared: " MainNet " used to fall through to the relabelling branch
    assert tx_for_network(tx, " MainNet ") is tx


def test_tx_for_network_refuses_a_network_no_table_has() -> None:
    """The label is written with check_validity=False, so nothing caught it.

    Every `ScriptPubKey`, `TxOut` and `Tx` built here is built unchecked
    -- deliberately, the relabelling touching nothing else -- so a
    network name that names nothing was baked into the transaction
    handed back, to surface as a `KeyError` from whatever went on to
    render an address, a long way from the call that caused it.
    """
    tx = Tx.parse(RAW)
    for unknown in ("mainet", "", "bitcoin"):
        with pytest.raises(BTClibValueError, match="unknown network: "):
            tx_for_network(tx, unknown)
    with pytest.raises(BTClibTypeError, match="not a network name: "):
        tx_for_network(tx, None)  # type: ignore[arg-type]


def test_tx_for_network_labels_the_outputs_and_touches_nothing_else() -> None:
    """The label is what an address is rendered from, and nothing else."""
    tx = Tx.parse(RAW)
    testnet = tx_for_network(tx, "testnet")

    assert [out.script_pub_key.network for out in testnet.vout] == ["testnet"] * 2
    assert [out.script_pub_key.network for out in tx.vout] == ["mainnet"] * 2
    # the serialization does not carry a network, so relabelling cannot
    # change it: same bytes, same id, same amounts, same scripts
    assert testnet.serialize(include_witness=True) == tx.serialize(include_witness=True)
    assert testnet.id == tx.id
    assert [out.value for out in testnet.vout] == [out.value for out in tx.vout]
    # and the two are not equal, ScriptPubKey comparing the network type
    assert testnet.vout[0].script_pub_key != tx.vout[0].script_pub_key


def test_the_label_is_what_an_address_is_rendered_from() -> None:
    """Which block 170 cannot show: both its outputs are p2pk.

    A p2pk script pays a public key and not a hash, so it has no address
    at all on either network -- `addresses` answers `[""]` for both, and
    a test written on it would pass whatever the label said. The same
    twenty bytes in a p2pkh script are a `1...` address on mainnet and an
    `m` or `n` one on testnet, and the label is the only thing that
    decides which.
    """
    tx = Tx.parse(RAW)
    p2pkh = ScriptPubKey("76a914" + "ab" * 20 + "88ac")
    tx.vout[0] = TxOut(tx.vout[0].value, p2pkh)

    assert tx.vout[0].script_pub_key.address.startswith("1")
    testnet = tx_for_network(tx, "testnet")
    assert testnet.vout[0].script_pub_key.address.startswith(("m", "n"))


def test_tx_from_raw_returns_the_transaction_asked_for() -> None:
    """Parse the raw serialization into the transaction with that id.

    However the caller holds it: the guard in front of the parse used to
    ask `isinstance(raw, (bytes, str))`, which is the packed form named
    by the types that were the packed form when the line was written, so
    a backend's answer kept in a buffer was refused as "not a
    serialization, but a bytearray" (issue #1238).
    """
    octets = bytes.fromhex(RAW)
    for spelling in (RAW, octets, bytearray(octets), memoryview(octets)):
        tx = tx_from_raw(spelling, TX_ID, "mainnet")
        assert tx.id.hex() == TX_ID
        assert len(tx.vout) == 2


def test_tx_from_raw_catches_the_answer_to_another_question() -> None:
    """The one answer a backend cannot fake, checked for both backends."""
    with pytest.raises(FetchError, match=f"transaction {OTHER_ID}: the answer is"):
        tx_from_raw(RAW, OTHER_ID, "mainnet")


def test_tx_from_raw_catches_it_on_either_side_of_the_id_requested() -> None:
    """A backend's id is refused whether it sorts above or below the ask.

    OTHER_ID above sorts below `TX_ID` (`b...` against `f...`), so that
    case alone leaves `hex() > tx_id` as good a check as `hex() != tx_id`.
    A requested id that sorts *above* the one `RAW` actually parses to is
    the other half, and it is what a byte-for-byte comparison must catch
    too -- a backend is not asked to sort correctly, only to answer for
    the id it was given.
    """
    above = "f" * 64
    with pytest.raises(FetchError, match=f"transaction {above}: the answer is"):
        tx_from_raw(RAW, above, "mainnet")


@pytest.mark.parametrize(
    "raw",
    [
        "not hex",
        # a transaction truncated in transit
        RAW[:100],
        "",
    ],
)
def test_tx_from_raw_reports_what_is_not_a_transaction(raw: str) -> None:
    """Wrap an unparsable body in a FetchError naming the transaction."""
    with pytest.raises(FetchError, match=f"transaction {TX_ID}:"):
        tx_from_raw(raw, TX_ID, "mainnet")


@pytest.mark.parametrize("height", [0, 1, TIP_HEIGHT])
def test_block_header_height_accepts_a_non_negative_int(height: int) -> None:
    """A height that is already a non-negative int passes through unchanged."""
    assert block_header_height(height) == height


def test_block_header_height_refuses_a_negative_height() -> None:
    """Refuse a negative height, both backends mapping it to a block first."""
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        block_header_height(-1)


@pytest.mark.parametrize("height", ["481824", 481824.0, None, True, False])
def test_block_header_height_refuses_a_non_integer_height(height: object) -> None:
    """Refuse anything that is not an int, a bool included."""
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        block_header_height(height)  # type: ignore[arg-type]


def test_block_header_from_raw_returns_a_checked_header() -> None:
    """Parse the serialization and pass it through assert_valid_pow."""
    header = block_header_from_raw(TIP_HEADER_RAW, TIP_HEIGHT)
    assert header.hash.hex() == TIP_ID


@pytest.mark.parametrize(
    "raw",
    [
        "not hex",
        # a header truncated in transit
        TIP_HEADER_RAW[:100],
        "",
    ],
)
def test_block_header_from_raw_reports_what_is_not_a_header(raw: str) -> None:
    """Wrap an unparsable body in a FetchError naming the height."""
    with pytest.raises(FetchError, match=f"block header {TIP_HEIGHT}:"):
        block_header_from_raw(raw, TIP_HEIGHT)


def test_block_header_from_raw_refuses_a_header_with_no_proof_of_work() -> None:
    """A well-formed header answering no real proof of work is refused too.

    Zeroing the nonce leaves every other field, and so every other check,
    untouched -- what fails is `assert_valid_pow` alone, which is the one
    this exists to enforce.
    """
    forged = TIP_HEADER_RAW[:-8] + "00000000"
    with pytest.raises(FetchError, match=f"block header {TIP_HEIGHT}: invalid proof"):
        block_header_from_raw(forged, TIP_HEIGHT)


def test_the_interface_is_abstract() -> None:
    """No answers here: a Fetcher is one of the backends, or nothing."""
    with pytest.raises(TypeError, match="abstract"):
        Fetcher()  # type: ignore[abstract]


@pytest.mark.parametrize(
    "missing",
    ["get_tx", "get_block_count", "get_best_block_id", "get_block_header"],
)
def test_leaving_any_one_of_the_four_abstract_refuses_construction(
    missing: str,
) -> None:
    """Each of the four is `abstractmethod` on its own, not by inheriting one.

    `test_the_interface_is_abstract` covers `Fetcher` itself; a subclass
    that overrides three of the four and forgets the last one is what a
    decorator removed from only one of them would let through.
    """
    methods = {
        "get_tx": lambda self, tx_id: Tx.parse(RAW),
        "get_block_count": lambda self: TIP_HEIGHT,
        "get_best_block_id": lambda self: bytes.fromhex(TIP_ID),
        "get_block_header": lambda self, height: BlockHeader.parse(TIP_HEADER_RAW),
    }
    del methods[missing]
    incomplete = type("Incomplete", (Fetcher,), methods)
    with pytest.raises(TypeError, match="abstract"):
        incomplete("mainnet")


def test_an_unknown_network_is_refused_at_construction() -> None:
    """Refuse a misspelled network before any request is made."""
    with pytest.raises(BTClibValueError, match="unknown network: mainnnet"):
        StubFetcher(Tx.parse(RAW), "mainnnet")


@pytest.mark.parametrize("network", ["mainnet", "testnet", "testnet4", "regtest"])
def test_the_network_is_the_one_it_was_given(network: str) -> None:
    """Expose the constructor's network unchanged, for all four."""
    assert StubFetcher(Tx.parse(RAW), network).network == network


def test_the_stub_answers_all_four_questions() -> None:
    """A Fetcher is the four or it is not one, so the stub must be one.

    A subclass leaving one abstract could not be instantiated at all, and
    the tests below would then be testing nothing -- which is what this
    says out loud rather than leaving to the two lines never called.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    assert fetcher.get_tx(TX_ID).id.hex() == TX_ID
    assert fetcher.get_block_count() == TIP_HEIGHT
    assert fetcher.get_best_block_id().hex() == TIP_ID
    assert fetcher.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID


def test_get_tx_out_derives_the_output_from_the_transaction() -> None:
    """Every backend gets this one for free, and gets it from get_tx."""
    fetcher = StubFetcher(Tx.parse(RAW))
    out = fetcher.get_tx_out(OutPoint(TX_ID, 1))
    assert out.value == 40_00000000
    assert fetcher.asked == [TX_ID]
    assert out == Tx.parse(RAW).vout[1]


def test_get_tx_out_answers_for_an_output_already_spent() -> None:
    """Which `gettxout` would not, and is why it is not what is called.

    Both outputs of this transaction were spent years ago; a fee is the
    inputs less the outputs, so an answer restricted to the utxo set
    could never compute one.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    assert fetcher.get_tx_out(OutPoint(TX_ID, 0)).value == 10_00000000


def test_get_tx_out_refuses_a_vout_the_transaction_does_not_have() -> None:
    """Refuse an out-of-range vout with a FetchError naming it.

    2, one past the transaction's last output, is the boundary the check
    is written on; 1000 is not, and is what tells a `>=` refusal from one
    that only catches an exact match -- and, being outside the range
    CPython interns, from one that only catches identity.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    with pytest.raises(FetchError, match="out of range vout: 2"):
        fetcher.get_tx_out(OutPoint(TX_ID, 2))
    with pytest.raises(FetchError, match="out of range vout: 1000"):
        fetcher.get_tx_out(OutPoint(TX_ID, 1000))
