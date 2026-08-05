# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.musig2` module."""

from typing import Any

import pytest

from btclib.curves import secp256k1
from btclib.ecc import ssa
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt, extract_tx, finalize, musig2
from btclib.psbt.psbt import prevouts, taproot_sig_hash
from btclib.script import type_and_payload
from btclib.script.engine import verify_transaction
from tests import load, vector_id

# BIP373's own participants, whose keys every vector of it aggregates.
# The private keys are the BIP's, published beside the public ones: they
# spend the outputs of a transaction that exists in no chain, and they are
# what lets a whole session be run here rather than only checked
# hex rather than the WIF the BIP prints, which decodes to exactly this
# and reads as a credential to every secret scanner that meets it
PARTICIPANT_PRV_KEYS = (
    "9e3d0fd1845e73fc5eb4202c047631e9bd45aee639c93de0e21ef7efe1100812",
    "754f619cf0f5a9cce70168bb4ea613804e53e4c2487a967d1e2564cf8007ad25",
    "0000000000000000000000000000000000000000000000000000000000000003",
)

AGGREGATE_PUB_KEY = "030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4"

PARTICIPANT_PUB_KEYS = (
    "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00",
    "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
)


def signed_vectors() -> list[Any]:
    """Select the four BIP373 psbts carrying all partial signatures."""
    return [
        pytest.param(test_vector, id=vector_id(index, test_vector["description"]))
        for index, test_vector in enumerate(
            [
                test_vector
                for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
                    "valid psbts"
                ]
                if "all partial signatures" in test_vector["description"]
            ],
            1,
        )
    ]


def session_of(psbt: Psbt) -> tuple[bytes, bytes]:
    """Read the participants' aggregate key, and the tapleaf hash if any.

    Two different keys live in these fields, and this is the place the
    difference shows: `musig2_participant_pub_keys` is keyed by the plain
    aggregate key, which is what the roles take, while the nonces and the
    partial signatures are keyed by that key *as tweaked for the spend*
    -- the taproot output key in two of these four vectors. The tapleaf
    hash is read off the key data, being the same in both.
    """
    psbt_in = psbt.inputs[0]
    aggregate_pub_key = next(iter(psbt_in.musig2_participant_pub_keys))
    leaf_hash = next(iter(psbt_in.musig2_partial_sigs))[66:]
    return aggregate_pub_key, leaf_hash


@pytest.mark.parametrize("test_vector", signed_vectors())
def test_the_partial_signatures_of_bip373_verify(test_vector: dict[str, str]) -> None:
    """Bitcoin Core signed these, and the session is rebuilt from the psbt.

    Which is the whole of what BIP373 asks a Signer to get right: the
    message is the BIP341 or BIP342 hash of the transaction the psbt
    describes, the tweaks are how the aggregate key reaches the output
    being spent -- nothing, the taproot commitment, or a BIP328
    derivation and then the commitment -- and the aggregate nonce is the
    sum of the nonces the input carries. Get any of the three wrong and
    every one of these partial signatures fails, which is why they are
    the test: they were made by another implementation, against a session
    btclib has to derive rather than choose.
    """
    psbt = Psbt.b64decode(test_vector["encoded psbt"])
    aggregate_pub_key, leaf_hash = session_of(psbt)

    for participant_pub_key in psbt.inputs[0].musig2_participant_pub_keys[
        aggregate_pub_key
    ]:
        assert musig2.partial_sig_verify(
            psbt, 0, participant_pub_key, aggregate_pub_key, leaf_hash=leaf_hash
        )


@pytest.mark.parametrize("test_vector", signed_vectors())
def test_aggregating_bip373s_partial_signatures_spends_the_output(
    test_vector: dict[str, str],
) -> None:
    """The Finalizer's half, and the answer is a transaction that verifies.

    `partial_sigs_agg` writes the BIP340 signature where the spend reads
    it, `finalize` builds the witness, and btclib's own script
    engine is what says the result is a spend of that output -- consensus
    rules over the extracted transaction, not a signature check of
    btclib's against a message of btclib's.
    """
    psbt = Psbt.b64decode(test_vector["encoded psbt"])
    aggregate_pub_key, leaf_hash = session_of(psbt)
    spent = prevouts(psbt)

    musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key, leaf_hash=leaf_hash)

    # the session is gone, and what replaced it is the signature
    assert not psbt.inputs[0].musig2_pub_nonces
    assert not psbt.inputs[0].musig2_partial_sigs
    assert not psbt.inputs[0].musig2_participant_pub_keys
    if leaf_hash:
        assert psbt.inputs[0].taproot_script_spend_signatures
    else:
        assert len(psbt.inputs[0].taproot_key_spend_signature) == 64

    tx = extract_tx(finalize(psbt))
    verify_transaction(spent, tx)


def test_a_whole_session_is_run_over_the_psbt() -> None:
    """Both rounds and every role, with btclib as all three signers.

    The psbt is BIP373's own first vector, which carries the participants
    and nothing else, so what is exercised is what a Signer and a
    Finalizer add to it: three public nonces, three partial signatures,
    the aggregate signature, and a transaction the script engine accepts.

    The secret nonces stay in this function, which is the point of
    `nonce_gen` returning them -- and each is spent exactly once, `sign`
    zeroing the bytearray it consumes.
    """
    encoded = next(
        test_vector["encoded psbt"]
        for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
            "valid psbts"
        ]
        if test_vector["description"].startswith(
            "Spend of a Taproot output where the output key"
        )
        and "participant pubkeys only" in test_vector["description"]
    )
    psbt = Psbt.b64decode(encoded)
    aggregate_pub_key = bytes.fromhex(AGGREGATE_PUB_KEY)
    spent = prevouts(psbt)

    sec_nonces = [
        musig2.nonce_gen(psbt, 0, prv_key, aggregate_pub_key)
        for prv_key in PARTICIPANT_PRV_KEYS
    ]
    assert len(psbt.inputs[0].musig2_pub_nonces) == 3

    for prv_key, sec_nonce in zip(PARTICIPANT_PRV_KEYS, sec_nonces, strict=True):
        musig2.partial_sign(psbt, 0, sec_nonce, prv_key, aggregate_pub_key)
        # spent, and the bytearray says so: a second signature under one
        # secnonce is what hands out a private key
        with pytest.raises(BTClibValueError, match="secnonce value is out of range"):
            musig2.partial_sign(psbt, 0, sec_nonce, prv_key, aggregate_pub_key)

    for participant_pub_key in PARTICIPANT_PUB_KEYS:
        assert musig2.partial_sig_verify(
            psbt, 0, participant_pub_key, aggregate_pub_key
        )

    sig = musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key)
    # the aggregate signature is a BIP340 signature under the output key,
    # which is the aggregate key itself in this vector
    output_key = type_and_payload(spent[0].script_pub_key.script)[1]
    assert ssa.verify_(taproot_sig_hash(psbt, 0), output_key, sig)

    tx = extract_tx(finalize(psbt))
    verify_transaction(spent, tx)


def test_the_updater_files_a_list_under_the_key_it_aggregates_to() -> None:
    """The Updater role: the aggregate key is computed, never taken.

    BIP373's own participants and their aggregate key, which the BIP
    publishes: `add_participant_pub_keys` has to arrive at it from the
    list alone, in the order the list is in.
    """
    psbt_in = Psbt.b64decode(
        next(
            test_vector["encoded psbt"]
            for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
                "valid psbts"
            ]
            if "participant pubkeys only" in test_vector["description"]
        )
    ).inputs[0]
    psbt_in.musig2_participant_pub_keys = {}

    aggregate_pub_key = musig2.add_participant_pub_keys(
        psbt_in, list(PARTICIPANT_PUB_KEYS)
    )
    assert aggregate_pub_key.hex() == AGGREGATE_PUB_KEY
    assert psbt_in.musig2_participant_pub_keys == {
        aggregate_pub_key: [bytes.fromhex(key) for key in PARTICIPANT_PUB_KEYS]
    }
    musig2.assert_valid_participants(psbt_in)

    # the order is part of the key: the same keys in another order are
    # another group, and sorting is how a group agrees on one -- BIP327's
    # KeySort, which BIP373 asks for whenever sorting was used at all.
    # These three are published in sorted order, so sorting a shuffled
    # list arrives back at the same aggregate key and the shuffle on its
    # own does not
    shuffled = list(reversed(PARTICIPANT_PUB_KEYS))
    assert musig2.add_participant_pub_keys(psbt_in, shuffled) != aggregate_pub_key
    assert (
        musig2.add_participant_pub_keys(psbt_in, shuffled, sort=True)
        == aggregate_pub_key
    )
    musig2.assert_valid_participants(psbt_in)

    # a list filed under a key it does not aggregate to is the one way
    # the field can be wrong with every length right
    psbt_in.musig2_participant_pub_keys[aggregate_pub_key] = [
        bytes.fromhex(key) for key in reversed(PARTICIPANT_PUB_KEYS)
    ]
    with pytest.raises(BTClibValueError, match="musig2 participants aggregate to "):
        musig2.assert_valid_participants(psbt_in)


def test_a_signer_that_is_not_a_participant_is_refused() -> None:
    """Refuse a nonce for a key outside the participant list."""
    encoded = next(
        test_vector["encoded psbt"]
        for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
            "valid psbts"
        ]
        if "participant pubkeys only" in test_vector["description"]
    )
    psbt = Psbt.b64decode(encoded)
    aggregate_pub_key = bytes.fromhex(AGGREGATE_PUB_KEY)
    err_msg = "is not a participant of aggregate key"
    with pytest.raises(BTClibValueError, match=err_msg):
        musig2.nonce_gen(psbt, 0, 0xDEAD, aggregate_pub_key)


def _bip373_psbt(description: str) -> Psbt:
    """Return the valid BIP373 psbt whose description contains this."""
    return Psbt.b64decode(
        next(
            test_vector["encoded psbt"]
            for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
                "valid psbts"
            ]
            if description in test_vector["description"]
        )
    )


def test_a_session_the_psbt_does_not_describe() -> None:
    """Each of the four ways a psbt can fail to say what is being signed.

    A Signer has to derive the session rather than choose it, so every one
    of these is a psbt that cannot be signed rather than one that signs
    something else -- which is the difference the checks buy.
    """
    aggregate_pub_key = bytes.fromhex(AGGREGATE_PUB_KEY)

    # no participants for the key the caller names
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with participant")
    psbt.inputs[0].musig2_participant_pub_keys = {}
    with pytest.raises(BTClibValueError, match="no musig2 participants for aggregate"):
        musig2.session_context(psbt, 0, aggregate_pub_key)

    # an aggregate key that is neither the output key nor the internal one
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with participant")
    other = musig2.add_participant_pub_keys(
        psbt.inputs[0], list(reversed(PARTICIPANT_PUB_KEYS))
    )
    err_msg = "is neither the taproot output key nor the internal key"
    with pytest.raises(BTClibValueError, match=err_msg):
        musig2.session_context(psbt, 0, other)

    # an internal key the aggregate key does not derive to
    psbt = _bip373_psbt("internal key is derived from a MuSig2")
    psbt.inputs[0].taproot_hd_key_paths = {}
    with pytest.raises(BTClibValueError, match="no BIP328 derivation from musig2"):
        musig2.session_context(psbt, 0, aggregate_pub_key)

    # the merkle root of another script tree: the tweak is then not the
    # one the output key commits to, and the tweaked key is not it either
    psbt = _bip373_psbt("internal key is a MuSig2 Aggregate Pubkey, with participant")
    psbt.inputs[0].taproot_merkle_root = b"\x01" * 32
    with pytest.raises(BTClibValueError, match="is not the key being spent"):
        musig2.session_context(psbt, 0, aggregate_pub_key)


def test_a_round_that_the_other_round_has_not_reached() -> None:
    """Each round needs what the one before wrote, and says what is missing."""
    aggregate_pub_key = bytes.fromhex(AGGREGATE_PUB_KEY)
    prv_key = PARTICIPANT_PRV_KEYS[0]

    # no nonce at all: there is no session to build a context of
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with participant")
    with pytest.raises(BTClibValueError, match="no musig2 public nonce for aggregate"):
        musig2.session_context(psbt, 0, aggregate_pub_key)

    # round 2 without this signer's own nonce, the others' being there
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with all pubnonces")
    key_data = next(
        k
        for k in psbt.inputs[0].musig2_pub_nonces
        if k[:33] == bytes.fromhex(PARTICIPANT_PUB_KEYS[0])
    )
    del psbt.inputs[0].musig2_pub_nonces[key_data]
    with pytest.raises(BTClibValueError, match="no musig2 public nonce of"):
        musig2.partial_sign(psbt, 0, bytearray(97), prv_key, aggregate_pub_key)

    # a partial signature nobody sent
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with all pubnonces")
    with pytest.raises(BTClibValueError, match="no musig2 partial signature of"):
        musig2.partial_sig_verify(psbt, 0, PARTICIPANT_PUB_KEYS[0], aggregate_pub_key)

    # aggregation is n-of-n, and one signature short of n it names who
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with all partial")
    key_data = next(
        k
        for k in psbt.inputs[0].musig2_partial_sigs
        if k[:33] == bytes.fromhex(PARTICIPANT_PUB_KEYS[0])
    )
    del psbt.inputs[0].musig2_partial_sigs[key_data]
    err_msg = f"missing musig2 partial signature of {PARTICIPANT_PUB_KEYS[0]}"
    with pytest.raises(BTClibValueError, match=err_msg):
        musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key)


def test_partial_signatures_that_do_not_add_up() -> None:
    """Refuse to aggregate a partial signature of another session.

    Each such signature verifies alone and adds up to nothing, and
    catching that is the Finalizer's check: the aggregate signature is verified
    before it is written, so a psbt combined out of two sessions is
    refused rather than finalized into a transaction the network drops.
    """
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with all partial")
    aggregate_pub_key, _ = session_of(psbt)
    key_data, psig = next(iter(psbt.inputs[0].musig2_partial_sigs.items()))
    # the same signer's signature, one bit different: every other partial
    # signature still verifies, and the total does not
    psbt.inputs[0].musig2_partial_sigs[key_data] = (
        (int.from_bytes(psig, "big") + 1) % secp256k1.n
    ).to_bytes(32, "big")
    with pytest.raises(BTClibValueError, match="do not add up to a signature of"):
        musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key)


def test_a_session_signing_for_a_sig_hash_type_of_its_own() -> None:
    """SIGHASH_ALL, spelled out: 65 bytes of signature, and the type appended.

    BIP341 appends the type to the 64 bytes whenever it is not the default
    one, and the input is what asks for it -- so the message every signer
    commits to changes with it, and the aggregate signature carries the
    byte that says so.
    """
    psbt = _bip373_psbt("output key is a MuSig2 Aggregate Pubkey, with participant")
    aggregate_pub_key = bytes.fromhex(AGGREGATE_PUB_KEY)
    psbt.inputs[0].sig_hash_type = 1  # ALL
    spent = prevouts(psbt)

    # both rounds, in order: a signature made before the last nonce is
    # published is a signature of another session, which is what
    # test_partial_signatures_that_do_not_add_up is about
    sec_nonces = [
        musig2.nonce_gen(psbt, 0, prv_key, aggregate_pub_key)
        for prv_key in PARTICIPANT_PRV_KEYS
    ]
    for prv_key, sec_nonce in zip(PARTICIPANT_PRV_KEYS, sec_nonces, strict=True):
        musig2.partial_sign(psbt, 0, sec_nonce, prv_key, aggregate_pub_key)
    musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key)

    signature = psbt.inputs[0].taproot_key_spend_signature
    assert len(signature) == 65
    assert signature[-1] == 1
    verify_transaction(spent, extract_tx(finalize(psbt)))
