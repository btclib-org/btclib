# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.silent_payments` module.

The vectors are BIP352's own `send_and_receive_test_vectors.json`,
vendored whole under `tests/_data/`; `tests/_data/README.md` pins the
revision. Every case is exercised from both ends, and every intermediate
value the file publishes is asserted at the step that produces it -- the
private key sum, the public key sum, the tweak data and the per-recipient
shared secrets -- rather than only the outputs at the end. That is what
makes a failure name the step: the 2026 revision added those fields for
exactly this, and a test that checked the outputs alone would report
"wrong output" for outpoints sorted wrongly, a missed negation and a wrong
label alike.

The receiving side goes one step further than the file: every output
found is signed with the key `prv_key_from_tweak` derives and the
signature verified against the output key, which is the only assertion
that says the output is *spendable* rather than merely predicted.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

import pytest

from btclib import silent_payments
from btclib._libsecp256k1 import silentpayments as libsecp256k1_silentpayments
from btclib.b32 import power_of_2_base_conversion
from btclib.bech32 import _BECH32_M_CONST, encode
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.ecc import ssa
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from tests import load, needs_bindings, vector_id

_VECTORS = load("_data", "send_and_receive_test_vectors.json", encoding="utf-8")

# the message and the auxiliary randomness the reference signs with, so
# that a signature here is the signature its harness produces
_MSG = sha256(b"message").digest()
_AUX = sha256(b"random auxiliary data").digest()


def _sending_params() -> tuple[list[tuple[int, Any]], list[str]]:
    """Flatten every sending sub-test into its own parametrized case."""
    params = [
        (index, test) for index, case in enumerate(_VECTORS) for test in case["sending"]
    ]
    ids = [vector_id(index, _VECTORS[index]["comment"]) for index, _ in params]
    return params, ids


def _receiving_params() -> tuple[list[tuple[int, Any]], list[str]]:
    """Flatten the receiving sub-tests, of which one case has two."""
    params = [
        (index, test)
        for index, case in enumerate(_VECTORS)
        for test in case["receiving"]
    ]
    ids = [
        vector_id(index, _VECTORS[index]["comment"], position)
        for position, (index, _) in enumerate(params)
    ]
    return params, ids


_SENDING, _SENDING_IDS = _sending_params()
_RECEIVING, _RECEIVING_IDS = _receiving_params()


def _witness(txinwitness: str) -> Witness | None:
    """Parse a witness, an empty column being a non-segwit input."""
    return Witness.parse(txinwitness) if txinwitness else None


def _outpoints(vin: list[dict[str, Any]]) -> list[OutPoint]:
    """Every outpoint of the transaction, eligible input or not."""
    return [OutPoint(v["txid"], v["vout"]) for v in vin]


def _pub_key_of(v: dict[str, Any]) -> tuple[int, int] | None:
    """Read one input's public key, or None where BIP352 skips it."""
    return silent_payments.pub_key_from_input(
        v["prevout"]["scriptPubKey"]["hex"], v["scriptSig"], _witness(v["txinwitness"])
    )


def _recipients(given: dict[str, Any]) -> list[dict[str, str]]:
    """Expand the file's `count` shorthand into one entry per payment."""
    expanded = []
    for recipient in given["recipients"]:
        expanded.extend([recipient] * recipient.get("count", 1))
    return expanded


@pytest.mark.parametrize("index,test", _SENDING, ids=_SENDING_IDS)
def test_sending_vectors(index: int, test: dict[str, Any]) -> None:
    """Derive the outputs a sender pays, and every value on the way."""
    given, expected = test["given"], test["expected"]

    prv_keys = []
    pub_keys = []
    for v in given["vin"]:
        pub_key = _pub_key_of(v)
        if pub_key is None:
            continue
        prv_keys.append((v["private_key"], v["prevout"]["scriptPubKey"]["hex"]))
        pub_keys.append(pub_key)
    assert [bytes_from_point(pk).hex() for pk in pub_keys] == expected["input_pub_keys"]

    if not pub_keys:
        # nothing eligible to derive a secret from: no outputs, and the
        # sender has to notice before it composes a transaction
        assert expected["outputs"] == [[]]
        return

    recipients = _recipients(given)
    addresses = [recipient["address"] for recipient in recipients]

    if expected.get("input_private_key_sum") is None:
        # the two keys are negatives of one another, so a is zero and the
        # shared secret would be the point at infinity
        with pytest.raises(BTClibValueError, match="sum to zero"):
            silent_payments.prv_key_sum(prv_keys)
        with pytest.raises(BTClibValueError, match="sum to zero"):
            silent_payments.output_keys(prv_keys, _outpoints(given["vin"]), addresses)
        assert expected["outputs"] == [[]]
        return

    a = silent_payments.prv_key_sum(prv_keys)
    assert a == int(expected["input_private_key_sum"], 16)

    outpoints = _outpoints(given["vin"])
    input_hash = silent_payments.input_hash(outpoints, mult(a))
    scalar = (input_hash * a) % secp256k1.n
    # one shared secret per recipient, which for a group is the same point
    # repeated: the file lists as many as it has values for
    for recipient, expected_secret in zip(
        recipients, expected["shared_secrets"], strict=False
    ):
        B_scan, B_m, network_type = silent_payments.keys_from_address(
            recipient["address"]
        )
        assert bytes_from_point(B_scan).hex() == recipient["scan_pub_key"]
        assert bytes_from_point(B_m).hex() == recipient["spend_pub_key"]
        assert network_type == "main"
        if expected_secret is None:
            # the K_MAX case, which fails before a secret is derived: the
            # file publishes the private key sum and then a null
            continue
        secret = silent_payments.shared_secret(scalar, B_scan)
        assert bytes_from_point(secret).hex() == expected_secret

    if len(recipients) > silent_payments.K_MAX:
        with pytest.raises(BTClibValueError, match="K_MAX"):
            silent_payments.output_keys(prv_keys, outpoints, addresses)
        assert expected["outputs"] == [[]]
        return

    keys = silent_payments.output_keys(prv_keys, outpoints, addresses)
    # the order of the addresses is not fixed, and a different order pays
    # the labelled addresses of one recipient different outputs, so the
    # file lists every valid set and one of them has to match
    found = {key.hex() for key in keys}
    assert any(found == set(valid) for valid in expected["outputs"])


@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_receiving_vectors(index: int, test: dict[str, Any]) -> None:
    """Scan for the outputs of one transaction, and spend each one."""
    given, expected = test["given"], test["expected"]

    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    addresses = [silent_payments.address_from_keys(mult(b_scan), B_spend)]
    addresses += [
        silent_payments.labeled_address_from_keys(b_scan, B_spend, m)
        for m in given["labels"]
    ]
    assert addresses == expected["addresses"]

    pub_keys = [
        pub_key for v in given["vin"] if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        assert expected["outputs"] == []
        return

    try:
        A_sum = silent_payments.pub_key_sum(pub_keys)
    except BTClibValueError:
        # the input keys sum to infinity: BIP352 skips the transaction,
        # which is the same fact the sending side reports as a failure
        assert expected["outputs"] == []
        return
    assert bytes_from_point(A_sum).hex() == expected["input_pub_key_sum"]

    outpoints = _outpoints(given["vin"])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    assert bytes_from_point(tweak).hex() == expected["tweak"]
    secret = silent_payments.shared_secret(b_scan, tweak)
    assert bytes_from_point(secret).hex() == expected["shared_secret"]

    labels = silent_payments.label_lookup(b_scan, given["labels"])
    found = silent_payments.scan_outputs(
        b_scan, B_spend, tweak, given["outputs"], labels
    )

    # the full-node entry point, given the same transaction data rather
    # than the already-reduced tweak: `scan_outputs`'s light-client
    # answer is what it has to match, on whichever arm this environment
    # runs -- delegated where the bindings serve, `scan_outputs` itself
    # otherwise, which is what makes this the vector this arm's own
    # entry in `tests/python_arm_authority_test.py` cites
    pub_keys_with_scripts = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    transaction_found = silent_payments.scan_transaction_outputs(
        b_scan, B_spend, outpoints, pub_keys_with_scripts, given["outputs"], labels
    )
    assert {(o.pub_key, o.prv_key_tweak) for o in transaction_found} == {
        (o.pub_key, o.prv_key_tweak) for o in found
    }

    if "n_outputs" in expected:
        # the K_MAX case, where the file counts rather than lists: the
        # transaction holds one output more than a scan is allowed to look
        assert len(found) == expected["n_outputs"]
    else:
        assert {(o.pub_key.hex(), o.prv_key_tweak) for o in found} == {
            (o["pub_key"], int(o["priv_key_tweak"], 16)) for o in expected["outputs"]
        }

    for output in found:
        d = silent_payments.prv_key_from_tweak(b_spend, output.prv_key_tweak)
        sig = ssa.sign_(_MSG, d, _AUX)
        assert ssa.verify_(_MSG, output.pub_key, sig)


# a wallet of its own for the cases the vector file has none of
_B_SCAN_PRV = 0x0F694E068028A717F8AF6B9411F9A133DD3565258714CC226594B34DB90C1F2C
_B_SPEND_PRV = 0x9D6AD855CE3417EF84E836692E31A6A11FBC69AC0C0844A2CD6F0D5ED4D3B58B

# 5 is not the x coordinate of any point of secp256k1, which is why
# btclib spells the point at infinity (5, 0): 32 bytes of it is a taproot
# output nobody can spend, and a scan has to walk past one rather than
# raise on it
_NOT_AN_X = (5).to_bytes(32, "big")


def _address(m: int | None = None, network: str = "mainnet") -> str:
    """Return the test wallet's address, labelled or not."""
    B_spend = mult(_B_SPEND_PRV)
    if m is None:
        return silent_payments.address_from_keys(mult(_B_SCAN_PRV), B_spend, network)
    return silent_payments.labeled_address_from_keys(_B_SCAN_PRV, B_spend, m, network)


def _reencoded(version: int, payload: bytes, hrp: str = "sp") -> str:
    """Compose an address out of a version and a payload, valid or not."""
    data = [version, *power_of_2_base_conversion(payload, 8, 5)]
    return encode(hrp, data, _BECH32_M_CONST).decode("ascii")


def test_the_address_round_trip_on_every_network() -> None:
    """One hrp for mainnet and one for every test network, per BIP352.

    So the answer is the network *type*: a "tsp" address says testnet,
    signet, testnet4 or regtest without saying which, and inventing one
    of the four would be inventing a fact the address does not carry.
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    for network, hrp, network_type in (
        ("mainnet", "sp", "main"),
        ("testnet", "tsp", "test"),
        ("signet", "tsp", "test"),
        ("testnet4", "tsp", "test"),
        ("regtest", "tsp", "test"),
    ):
        address = _address(network=network)
        assert address.startswith(f"{hrp}1q")
        assert silent_payments.keys_from_address(address) == (
            B_scan,
            B_spend,
            network_type,
        )

    # and the address is read back whatever the case and the spacing, as
    # every other btclib address is
    address = _address()
    assert silent_payments.keys_from_address(f"  {address.upper()} ") == (
        B_scan,
        B_spend,
        "main",
    )


def test_a_network_no_network_has_is_refused() -> None:
    """The hrp comes from the network, so the name has to be one.

    Through `network_type_from_network`, which is what refuses it: indexing
    `NETWORKS` would answer a bare `KeyError`, and being a `LookupError`
    that is an exception no caller filtering this library's bad input is
    told to expect.
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    for network in ("mainet", "", "bitcoin"):
        with pytest.raises(BTClibValueError, match="unknown network"):
            silent_payments.address_from_keys(B_scan, B_spend, network)
        with pytest.raises(BTClibValueError, match="unknown network"):
            silent_payments.labeled_address_from_keys(_B_SCAN_PRV, B_spend, 0, network)
    # and the tolerance every other network name gets is this one's too
    assert silent_payments.address_from_keys(
        B_scan, B_spend, "  MainNet "
    ) == silent_payments.address_from_keys(B_scan, B_spend)


def test_a_labeled_address_differs_in_the_spend_key_alone() -> None:
    """The scan key is shared, which is what one wallet means."""
    B_scan, B_spend, _ = silent_payments.keys_from_address(_address())
    for m in (0, 1, 0xFFFFFFFF):
        labeled_scan, labeled_spend, _ = silent_payments.keys_from_address(_address(m))
        assert labeled_scan == B_scan
        assert labeled_spend != B_spend
        # and the difference is the label tweak times G
        tweak = silent_payments.label_tweak(_B_SCAN_PRV, m)
        assert labeled_spend == secp256k1.add_var(B_spend, mult(tweak))


def test_a_label_is_a_32_bit_unsigned_integer() -> None:
    """Four bytes hold a label, so 2^32 has no serialization and nor has -1."""
    for m in (-1, 2**32):
        with pytest.raises(BTClibValueError, match="label not in"):
            silent_payments.label_tweak(_B_SCAN_PRV, m)
    # a bool is an int and would label 0 or 1 by accident, a label read
    # back from json being where that arrives
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, True)
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, 1.0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, "1")  # type: ignore[arg-type]


def test_a_hash_outside_the_scalar_range_is_refused() -> None:
    """BIP352's "fail" wherever a hash is no scalar, at all three sites.

    Not reachable through the public functions -- each of the three hashes
    is a sha256 and a preimage of 0 or of n is what nobody has -- so the
    helper the three share is what is held to it, at both ends of the
    range.
    """
    for data in (bytes(32), secp256k1.n.to_bytes(32, "big"), b"\xff" * 32):
        with pytest.raises(BTClibValueError, match="not in 1..n-1"):
            silent_payments._scalar(data, "label")


def test_an_address_no_longer_than_a_bech32m_string_should_be() -> None:
    """1023 characters, which is BIP352's bound and not BIP173's 90."""
    address = _address()
    padded = address + "q" * (1024 - len(address))
    with pytest.raises(BTClibValueError, match="invalid address length"):
        silent_payments.keys_from_address(padded)


def test_an_hrp_that_is_not_a_silent_payment_one_is_refused() -> None:
    """A segwit hrp on a silent payment payload is not an address."""
    payload = bytes_from_point(mult(_B_SCAN_PRV)) + bytes_from_point(mult(_B_SPEND_PRV))
    with pytest.raises(BTClibValueError, match="invalid hrp"):
        silent_payments.keys_from_address(_reencoded(0, payload, "bc"))


def test_an_address_with_no_data_part_is_refused() -> None:
    """`decode` does not require one when the checksum constant is given.

    Which is what passing it costs: the segwit spelling reads the witness
    version off the first data value to pick between bech32 and bech32m,
    and refuses an empty data part on the way. Here the constant is
    BIP352's whatever the version, so nothing else asks.
    """
    with pytest.raises(BTClibValueError, match="empty data"):
        silent_payments.keys_from_address(encode("sp", [], _BECH32_M_CONST))


def test_version_31_is_refused_and_the_others_are_read() -> None:
    """v31 is the version reserved for breaking exactly this compatibility.

    v1 through v30 are read as far as v0 defines them -- the first 66
    bytes, the rest discarded -- so that a v0 wallet can pay an address of
    a version it has never heard of. v31 says that reading it that way
    would be wrong, and there is nothing else a v0 wallet can do with it.
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    payload = bytes_from_point(B_scan) + bytes_from_point(B_spend)

    with pytest.raises(BTClibValueError, match="reserved silent payment version"):
        silent_payments.keys_from_address(_reencoded(31, payload))

    for version in (1, 17, 30):
        # a longer payload is what a later version is expected to bring,
        # and the extra bytes are the part v0 does not understand
        extended = _reencoded(version, payload + b"\x2a" * 7)
        assert silent_payments.keys_from_address(extended) == (B_scan, B_spend, "main")
        # too short is not forward compatibility but a broken address
        with pytest.raises(BTClibValueError, match="is less than"):
            silent_payments.keys_from_address(_reencoded(version, payload[:-1]))


def test_a_v0_payload_is_exactly_the_two_keys() -> None:
    """No truncation and no extension: v0 says 66 bytes and means it."""
    payload = bytes_from_point(mult(_B_SCAN_PRV)) + bytes_from_point(mult(_B_SPEND_PRV))
    for damaged in (payload[:-1], payload + b"\x2a"):
        with pytest.raises(BTClibValueError, match="invalid v0 payload length"):
            silent_payments.keys_from_address(_reencoded(0, damaged))


def test_an_input_of_no_eligible_type_is_skipped() -> None:
    """p2wsh, p2ms, p2pk and nulldata are not on BIP352's list.

    Each of them either has several public keys or a script that a peer
    could satisfy another way, which is the malleability the list exists
    to avoid; a p2pk has one key and is left out all the same, BIP352
    naming four types and not five.
    """
    for script_pub_key in (
        "0020" + "11" * 32,  # p2wsh
        "5121" + "02" + "11" * 32 + "51ae",  # p2ms 1-of-1
        "21" + "02" + "11" * 32 + "ac",  # p2pk
        "6a0568656c6c6f",  # nulldata
        "",  # no script at all
    ):
        assert silent_payments.pub_key_from_input(script_pub_key) is None


def test_an_eligible_input_that_carries_no_key_is_skipped() -> None:
    """The type is on the list and the spend still has no key to read."""
    p2wpkh = "0014" + "11" * 20
    p2sh = "a914" + "11" * 20 + "87"
    p2tr = "5120" + bytes_from_point(mult(3))[1:].hex()

    # a witness that is not there: a p2wpkh or a p2sh-p2wpkh input read out
    # of a transaction that has not been signed yet
    assert silent_payments.pub_key_from_input(p2wpkh) is None
    assert silent_payments.pub_key_from_input(p2sh, "16" + p2wpkh) is None
    assert silent_payments.pub_key_from_input(p2tr) is None

    # a p2sh wrapping something that is not p2wpkh: p2sh-p2wsh, and every
    # other redeem script, is not on the list
    witness = Witness(["11" * 33])
    redeem = "0020" + "11" * 32
    assert silent_payments.pub_key_from_input(p2sh, "22" + redeem, witness) is None

    # and a taproot output whose 32 bytes are no x coordinate: unspendable
    # rather than ineligible, and skipped either way
    assert (
        silent_payments.pub_key_from_input("5120" + _NOT_AN_X.hex(), "", witness)
        is None
    )


def test_a_sum_with_nothing_in_it_is_infinity() -> None:
    """Which is the answer for a transaction of only skipped inputs."""
    with pytest.raises(BTClibValueError, match="sum to infinity"):
        silent_payments.pub_key_sum([])
    with pytest.raises(BTClibValueError, match="sum to zero"):
        silent_payments.prv_key_sum([])


def test_the_input_hash_needs_an_outpoint() -> None:
    """The smallest of none is not a value, and the hash binds to it."""
    with pytest.raises(BTClibValueError, match="no outpoint"):
        silent_payments.input_hash([], mult(_B_SCAN_PRV))


def test_a_scan_walks_past_an_output_that_is_no_point() -> None:
    """A taproot output key is 32 bytes nobody checked.

    So the label subtraction has nothing to subtract, and the output is
    skipped rather than raised on -- which the direct comparison in front
    of it never needed to notice, comparing x coordinates and not points.
    """
    tweak = silent_payments.tweak_data([OutPoint(bytes(32), 0)], mult(_B_SCAN_PRV))
    labels = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    found = silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), tweak, [_NOT_AN_X], labels
    )
    assert found == []


def test_a_spending_key_of_zero_is_refused() -> None:
    """b_spend + tweak is a private key, and zero is not one."""
    tweak = secp256k1.n - _B_SPEND_PRV
    with pytest.raises(BTClibValueError, match="sum to zero"):
        silent_payments.prv_key_from_tweak(_B_SPEND_PRV, tweak)


@needs_bindings
@pytest.mark.parametrize("index,test", _SENDING, ids=_SENDING_IDS)
def test_output_keys_matches_across_arms(
    index: int, test: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delegated and the Python arm answer the same set of outputs.

    `output_keys`'s own dispatch is `_libsecp256k1_serves(secp256k1,
    None)`, imported into this module's own namespace the way `dsa` and
    `ssa` import theirs, so a vector is run twice with the predicate
    patched between the two -- the same shape `dsa_test.py`'s own
    cross-arm tests use. `test_sending_vectors` already carries every
    other assertion this file makes about a vector, including the two
    refusals (a zero private-key sum, more than K_MAX recipients sharing
    a scan key), which is why this asks only whether the two arms refuse
    together or agree on the answer.
    """
    given, expected = test["given"], test["expected"]
    prv_keys = [
        (v["private_key"], v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if _pub_key_of(v) is not None
    ]
    if not prv_keys:
        pytest.skip("nothing eligible to derive a secret from")
    addresses = [recipient["address"] for recipient in _recipients(given)]
    outpoints = _outpoints(given["vin"])

    def _keys(*, delegated: bool) -> list[bytes] | None:
        with monkeypatch.context() as arm:
            if not delegated:
                arm.setattr(silent_payments, "_libsecp256k1_serves", lambda *_a: False)
            try:
                return silent_payments.output_keys(prv_keys, outpoints, addresses)
            except BTClibValueError:
                return None

    delegated_keys = _keys(delegated=True)
    python_keys = _keys(delegated=False)
    assert (delegated_keys is None) == (python_keys is None)
    if delegated_keys is not None:
        assert python_keys is not None
        assert set(delegated_keys) == set(python_keys)
        assert expected["outputs"] and any(
            {key.hex() for key in delegated_keys} == set(valid)
            for valid in expected["outputs"]
        )


@needs_bindings
def test_output_keys_interleaved_groups_match_across_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two scan keys interleaved, one of them labelled, taproot and not.

    The vector file has no case mixing a taproot and a non-taproot input
    while addressing two recipients out of order -- X, Y, X's second
    label -- so this is the case built by hand: it is the one shape where
    a grouping mismatch between the two arms would show up as a wrong
    *set*, not merely a wrong order, because `keys_from_address(X)`'s
    second address shares X's group and gets the next k after X's first.
    """
    a_taproot = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    a_legacy = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD
    taproot_script = "5120" + bytes_from_point(mult(a_taproot))[1:].hex()
    legacy_script = "0014" + hash160(bytes_from_point(mult(a_legacy))).hex()
    prv_keys = [(a_taproot, taproot_script), (a_legacy, legacy_script)]
    outpoints = [OutPoint("00" * 31 + "01", 0), OutPoint("00" * 31 + "02", 1)]

    x_scan, x_spend = 0x11, 0x22
    y_scan, y_spend = 0x33, 0x44
    x_address = silent_payments.address_from_keys(mult(x_scan), mult(x_spend))
    y_address = silent_payments.address_from_keys(mult(y_scan), mult(y_spend))
    x_labelled = silent_payments.labeled_address_from_keys(x_scan, mult(x_spend), 1)
    addresses = [x_address, y_address, x_labelled]

    delegated = silent_payments.output_keys(prv_keys, outpoints, addresses)
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(silent_payments, "_libsecp256k1_serves", lambda *_a: False)
        python = silent_payments.output_keys(prv_keys, outpoints, addresses)
    assert len(delegated) == len(addresses)
    assert set(delegated) == set(python)


def test_output_keys_pays_nothing_for_no_addresses() -> None:
    """No recipient is nothing to derive, on either arm.

    `create_outputs` itself refuses an empty recipient list -- "at least
    one recipient is required" -- so `output_keys` answers before
    reaching it, the same `[]` the Python loop below would have built
    from an empty `groups`.
    """
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    assert (
        silent_payments.output_keys([(_B_SCAN_PRV, script_pub_key)], outpoints, [])
        == []
    )


@needs_bindings
def test_output_keys_wraps_a_delegated_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """`create_outputs`'s own ValueError still comes back a BTClibValueError.

    `prv_key_sum` and `input_hash` already cover the two refusals a real
    transaction can trigger -- a zero private-key sum, no outpoint -- so
    this is not a case the vector file has: the bindings' own message for
    whatever else `secp256k1_silentpayments_sender_create_outputs` itself
    refuses (an output landing on the point at infinity, say) is
    substituted for rather than reproduced.
    """

    def _refuse(*_args: object, **_kwargs: object) -> list[bytes]:
        raise ValueError("silent payment output creation failed")

    monkeypatch.setattr(libsecp256k1_silentpayments, "create_outputs", _refuse)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    with pytest.raises(BTClibValueError, match="silent payment output creation failed"):
        silent_payments.output_keys(
            [(_B_SCAN_PRV, script_pub_key)], outpoints, [_address()]
        )


@needs_bindings
@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_scan_transaction_outputs_matches_across_arms(
    index: int, test: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delegated and the Python arm of the full-node scan agree.

    `scan_transaction_outputs`'s own dispatch is `_libsecp256k1_serves(
    secp256k1, None)`, exactly `output_keys`'s, so a vector is run twice
    with the predicate patched between the two --
    `test_output_keys_matches_across_arms`'s own shape, now available
    because `scan_transaction_outputs` gives the recipient's side a
    dispatch to flip. `test_receiving_vectors` already checks the light
    client's `scan_outputs` against the vector file directly; this asks
    whether the full-node entry point's two arms agree with each other
    and with that same file.
    """
    given, expected = test["given"], test["expected"]
    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    pub_keys = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        pytest.skip("nothing eligible to derive a shared secret from")

    outpoints = _outpoints(given["vin"])
    labels = silent_payments.label_lookup(b_scan, given["labels"])

    def _scan(*, delegated: bool) -> list[silent_payments.SilentPaymentOutput] | None:
        with monkeypatch.context() as arm:
            if not delegated:
                arm.setattr(silent_payments, "_libsecp256k1_serves", lambda *_a: False)
            try:
                return silent_payments.scan_transaction_outputs(
                    b_scan, B_spend, outpoints, pub_keys, given["outputs"], labels
                )
            except BTClibValueError:
                return None

    delegated_found = _scan(delegated=True)
    python_found = _scan(delegated=False)
    assert (delegated_found is None) == (python_found is None)
    if delegated_found is None:
        # the input public keys sum to infinity: BIP352 skips the
        # transaction, which `test_receiving_vectors` already reads as
        # an empty outputs list for this same vector
        assert expected["outputs"] == []
        return
    assert python_found is not None

    delegated_set = {(o.pub_key.hex(), o.prv_key_tweak) for o in delegated_found}
    python_set = {(o.pub_key.hex(), o.prv_key_tweak) for o in python_found}
    assert delegated_set == python_set

    if "n_outputs" in expected:
        # the K_MAX case, where the file counts rather than lists
        assert len(delegated_found) == expected["n_outputs"]
    else:
        assert delegated_set == {
            (o["pub_key"], int(o["priv_key_tweak"], 16)) for o in expected["outputs"]
        }


@needs_bindings
@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_scan_transaction_outputs_accepts_no_labels_on_the_real_bindings(
    index: int, test: dict[str, Any]
) -> None:
    """`labels=None` reaches `silentpayments.scan_outputs` unconverted.

    Every other real-bindings call in this file always builds a
    `label_lookup(...)` map first -- `test_receiving_vectors` and
    `test_scan_transaction_outputs_matches_across_arms` both do --  and
    `test_scan_transaction_outputs_wraps_a_delegated_refusal` calls with
    `labels=None` but monkeypatches `scan_outputs` itself, so the real
    function never sees `None` in either case. This is the one test that
    does, and it asks the same question `test_receiving_vectors` asks of
    the filled-map case: that the full-node entry point's delegated arm
    agrees with the light client's own Python arm, `scan_outputs`, on the
    same input -- here, no labels at all.
    """
    given, expected = test["given"], test["expected"]
    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    pub_keys = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        pytest.skip("nothing eligible to derive a shared secret from")

    outpoints = _outpoints(given["vin"])

    try:
        delegated_found = silent_payments.scan_transaction_outputs(
            b_scan, B_spend, outpoints, pub_keys, given["outputs"], labels=None
        )
    except BTClibValueError:
        # the input public keys sum to infinity: BIP352 skips the
        # transaction, the same fact `test_receiving_vectors` reads as an
        # empty outputs list for this same vector
        assert expected["outputs"] == []
        return

    A_sum = silent_payments.pub_key_sum([pub_key for pub_key, _ in pub_keys])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    light_client_found = silent_payments.scan_outputs(
        b_scan, B_spend, tweak, given["outputs"], labels=None
    )
    assert {(o.pub_key, o.prv_key_tweak) for o in delegated_found} == {
        (o.pub_key, o.prv_key_tweak) for o in light_client_found
    }


@needs_bindings
def test_scan_transaction_outputs_wraps_a_delegated_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`silentpayments.scan_outputs`'s own ValueError comes back wrapped.

    `pub_key_sum` and `input_hash` already cover the two refusals a real
    transaction can trigger -- infinite input key sum, no outpoint -- the
    same pair `test_output_keys_wraps_a_delegated_refusal` names, so this
    is not a case the vector file has either: the bindings' own message
    for whatever else `secp256k1_silentpayments_receiver_scan_outputs`
    refuses is substituted for rather than reproduced.
    """

    def _refuse(*_args: object, **_kwargs: object) -> list[tuple[bytes, bytes, None]]:
        raise ValueError("silent payment scan failed")

    monkeypatch.setattr(libsecp256k1_silentpayments, "scan_outputs", _refuse)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    with pytest.raises(BTClibValueError, match="silent payment scan failed"):
        silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, [_NOT_AN_X]
        )


def test_the_whole_round_trip_without_a_vector() -> None:
    """Pay this wallet from one input, then find and spend the output.

    The vectors do this too, from both ends, but each end reads the
    other's answer out of the file. Here the sender's output is the
    scanner's input, so the two halves are held to each other rather than
    to a recorded value -- which is what would catch the pair drifting
    together.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 7), OutPoint("00" * 31 + "02", 0)]
    addresses = [_address(), _address(0), _address(0)]

    keys = silent_payments.output_keys([(a, script_pub_key)], outpoints, addresses)
    assert len(set(keys)) == len(addresses)

    A_sum = silent_payments.pub_key_sum([mult(a)])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    labels = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    found = silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), tweak, keys, labels
    )
    assert [output.pub_key for output in found] == keys

    for output in found:
        d = silent_payments.prv_key_from_tweak(_B_SPEND_PRV, output.prv_key_tweak)
        assert ssa.verify_(_MSG, output.pub_key, ssa.sign_(_MSG, d, _AUX))
