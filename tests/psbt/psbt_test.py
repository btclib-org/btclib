#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.psbt.psbt` module."""

import base64
import inspect
from copy import deepcopy
from io import BytesIO
from typing import Any

import pytest

from btclib.bip32 import BIP32KeyOrigin
from btclib.curves import sec_point
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.psbt import (
    Psbt,
    PsbtIn,
    PsbtOut,
    combine_psbts,
    extract_tx,
    finalize_psbt,
    join_psbts,
)
from btclib.psbt.psbt import (
    _V2_GLOBAL_FIELDS,
    HAS_SIG_HASH_SINGLE,
    INPUTS_MODIFIABLE,
    OUTPUTS_MODIFIABLE,
    _sig_hash_from_psbt_in,
    _sort_or_shuffle,
)
from btclib.psbt.psbt_in import _V2_FIELDS as _V2_INPUT_FIELDS
from btclib.psbt.psbt_in import LOCK_TIME_THRESHOLD
from btclib.psbt.psbt_out import _V2_FIELDS as _V2_OUTPUT_FIELDS
from btclib.script import ScriptPubKey, Witness, serialize, sig_hash
from btclib.script.engine import verify_transaction
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load, vector_id
from tests.conftest import JsonGolden

# first tests are part of the official BIP174 test vectors


def psbt_vectors(fname: str, kind: str) -> list[Any]:
    """The `kind` cases of a psbt vector file, named by description.

    The description is the id because a bare "case 7 failed" is not a
    report: as a test id it is there for free, with no print-and-raise
    wrapper around the decode and no interpolation into the message of
    every assert -- and for the cases that pass as well.
    """
    return [
        pytest.param(test_vector, id=vector_id(index, test_vector["description"]))
        for index, test_vector in enumerate(load("psbt", "_data", fname)[kind], 1)
    ]


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip174(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki."""
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip174(test_vector: dict[str, str]) -> None:
    """Each case must be refused, with the message this file records.

    The message is btclib's, not the BIP's, so the assert is what pins a
    rejection to its reason -- and one of the twenty is pinned to the
    wrong one: the `invalid value data` case answers "Missing inputs"
    because its unsigned tx has none, while btclib's map parser accepts
    the malformed value itself. Lifting the input check of issue 170
    turns this case red, which is where the missing size check gets
    written.
    """
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "signer check failures")
)
def test_signer_check_failure_bip174(test_vector: dict[str, str]) -> None:
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    with pytest.raises(BTClibValueError) as excinfo:
        psbt_decoded.assert_signable()
    assert test_vector["error message"] in str(excinfo.value)
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip371_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip371(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki."""
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip371_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip371(test_vector: dict[str, str]) -> None:
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip373_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip373(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki.

    Byte for byte, and with nothing left under `unknown`: these psbts
    round-tripped before the fields existed, an unknown key being given
    back exactly as it arrived, so preservation is not what the assert
    below is about. What it pins is that the four type bytes are read as
    the fields they are -- which is what makes the ten invalid psbts of
    this same file refusable at all.
    """
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)

    carried = any(
        psbt_in.musig2_participant_pub_keys
        or psbt_in.musig2_pub_nonces
        or psbt_in.musig2_partial_sigs
        for psbt_in in psbt_decoded.inputs
    ) or any(psbt_out.musig2_participant_pub_keys for psbt_out in psbt_decoded.outputs)
    assert carried
    for psbt_in in psbt_decoded.inputs:
        assert not psbt_in.unknown
    for psbt_out in psbt_decoded.outputs:
        assert not psbt_out.unknown


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip373_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip373(test_vector: dict[str, str]) -> None:
    """Each case must be refused, with the message this file records.

    Every one of the ten is a length: an x-only key where BIP373 requires
    a compressed one, in the participant list, in the nonce key data or in
    the partial signature key data, and a nonce or a signature whose value
    is the wrong size. Which is why they were all accepted while the type
    bytes were unknown -- an unknown key has no shape to be wrong.
    """
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


def _bip373_psbt(description: str) -> Psbt:
    """The valid BIP373 psbt whose description starts with this."""
    valid = load("psbt", "_data", "bip373_test_vectors.json")["valid psbts"]
    encoded = next(
        test_vector["encoded psbt"]
        for test_vector in valid
        if test_vector["description"].startswith(description)
    )
    return Psbt.b64decode(encoded)


def test_musig2_participants_keep_the_order_they_were_aggregated_in() -> None:
    """A list, not a set: KeyAgg is not symmetric in its input.

    BIP373 asks for "the order required for aggregation", so two psbts
    naming the same participants in two orders name two aggregate keys.
    The three keys below are the ones the BIP publishes for its vectors,
    in the order it publishes them.
    """
    participants = [
        bytes.fromhex(
            "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00"
        ),
        bytes.fromhex(
            "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c"
        ),
        bytes.fromhex(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        ),
    ]
    aggregate = bytes.fromhex(
        "030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4"
    )

    psbt = _bip373_psbt("Spend of a Taproot output where the output key")
    assert psbt.inputs[0].musig2_participant_pub_keys == {aggregate: participants}

    # reversed and back, which a sorted or de-duplicated field would not
    # survive: the reversal is a different psbt, and the original bytes
    # come back from the original order alone
    encoded = psbt.b64encode()
    psbt.inputs[0].musig2_participant_pub_keys[aggregate] = participants[::-1]
    assert psbt.b64encode() != encoded
    assert Psbt.b64decode(psbt.b64encode()).inputs[0].musig2_participant_pub_keys == {
        aggregate: participants[::-1]
    }


def test_a_musig2_key_must_be_a_point_and_not_merely_33_bytes() -> None:
    """What Bitcoin Core asks beyond the length, `IsFullyValid` per key.

    No vector of BIP373 carries it: all ten of its invalid psbts are
    x-only keys or wrong-sized values, so the length alone refuses them,
    and a key of the right length that is on no curve would be accepted
    by a length check on its own.
    """
    not_a_point = b"\x02" + b"\xff" * 32

    psbt = _bip373_psbt("Spend of a Taproot output where the output key")
    aggregate, participants = next(
        iter(psbt.inputs[0].musig2_participant_pub_keys.items())
    )
    psbt.inputs[0].musig2_participant_pub_keys = {aggregate: [not_a_point]}
    with pytest.raises(BTClibValueError, match="invalid musig2 participant pub key: "):
        psbt.assert_valid()

    psbt.inputs[0].musig2_participant_pub_keys = {not_a_point: participants}
    with pytest.raises(BTClibValueError, match="invalid musig2 aggregate pub key: "):
        psbt.assert_valid()


def test_an_output_participant_list_is_a_whole_number_of_keys() -> None:
    """The case BIP373's own two output vectors do not distinguish.

    "PSBT with x-only aggregate pubkey in output participant pubkeys
    keydata" and "PSBT with an x-only output participant pubkey" are one
    psbt in the BIP -- byte for byte the same base64, the x-only key in
    the key data both times -- so the second condition, an x-only key
    inside the value, is named upstream and carried by nothing. Here it
    is, on the output map of the BIP's own receiving psbt.
    """
    psbt_out = _bip373_psbt(
        "Receiving a Taproot output where the internal key is a"
    ).outputs[0]
    aggregate, participants = next(iter(psbt_out.musig2_participant_pub_keys.items()))
    # the first participant as x-only, which is a value of 98 bytes: no
    # participant list is 98 bytes long, whichever key was shortened
    psbt_out.musig2_participant_pub_keys[aggregate] = [
        participants[0][1:],
        *participants[1:],
    ]

    # the key that is 32 bytes, where the object holds them apart
    err_msg = "invalid musig2 participant pub key length: 32 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_out.assert_valid()

    # and the value that is 98, where the psbt holds them concatenated
    serialized = psbt_out.serialize(check_validity=False)
    err_msg = "invalid musig2 participant pub keys: 98 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        PsbtOut.parse(serialized)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip370_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip370(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki.

    Half of the twenty-four are a version 0 psbt carrying one of the
    twelve fields BIP370 defines, and each names the field it carries:
    that is a rule a v0 parser can apply on its own, no version 2 needed.

    The other half is a version 2 psbt, and each of those is refused for
    what the BIP says is wrong with it: the unsigned transaction version
    2 excludes, one of the three globals or the four per-map fields it
    requires, or a required lock time outside the range that makes it
    one kind of lock time. The message recorded beside each is btclib's
    own, so the file says what each case is refused for.
    """
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip370_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip370(test_vector: dict[str, str]) -> None:
    """Every valid psbt of BIP370 is read and written back byte for byte.

    Which is more than "it parses": a version 2 psbt is the fields
    themselves, so an encode that agreed with the BIP on the values and
    not on how they are written -- their order, the width of each -- is
    an encode no other implementation would take.
    """
    encoded = test_vector["encoded psbt"]
    assert Psbt.b64encode(Psbt.b64decode(encoded)) == encoded


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip370_test_vectors.json", "lock time psbts")
)
def test_lock_time_bip370(test_vector: dict[str, Any]) -> None:
    """The lock time BIP370's algorithm computes, psbt by psbt.

    The `lock time` beside each is the value the BIP publishes for it,
    and `null` is the one psbt that has no lock time at all: one input
    requires a height and another a time, and one nLockTime cannot be
    both -- so what is asserted there is the refusal, which is the same
    answer `Psbt.tx` and `Psbt.serialize` give it.
    """
    psbt = Psbt.b64decode(test_vector["encoded psbt"], check_validity=False)
    if test_vector["lock time"] is None:
        err_msg = "no lock time satisfies every input"
        with pytest.raises(BTClibValueError, match=err_msg):
            psbt.assert_valid()
        return
    assert psbt.lock_time == test_vector["lock time"]
    psbt.assert_valid()
    assert psbt.b64encode() == test_vector["encoded psbt"]


def test_the_v2_field_tables_hold_bip370s_twelve() -> None:
    """The three tables are the whole of what version 0 must exclude.

    A type byte no table names is filed under `unknown` and accepted, so
    a field missing from them is a psbt accepted that the BIP calls
    invalid -- which is what all twelve of these were. Derived from the
    vector file rather than listed again here: each of those cases is
    named after the one field it carries.
    """
    named_by_the_bip = {
        test_vector["description"].removeprefix("PSBTv0 but with ")
        for test_vector in load("psbt", "_data", "bip370_test_vectors.json")[
            "invalid psbts"
        ]
        # not "PSBTv0 but with PSBT_GLOBAL_VERSION set to 2": that case is
        # a v0 psbt claiming to be a v2 one, which the version check has
        # always refused, rather than a v2 field in a v0 psbt
        if test_vector["description"].startswith("PSBTv0 but with PSBT_")
        and " set to " not in test_vector["description"]
    }
    tabulated = (
        set(_V2_GLOBAL_FIELDS.values())
        | set(_V2_INPUT_FIELDS.values())
        | set(_V2_OUTPUT_FIELDS.values())
    )
    assert tabulated == named_by_the_bip


def test_a_v2_field_is_refused_wherever_it_sits() -> None:
    """The three maps each answer, and each says which field it found.

    One psbt per map, taken from the vectors above, so that a table
    wired into the wrong parser cannot pass on the strength of the other
    two.
    """
    per_map = {
        "PSBT_GLOBAL_INPUT_COUNT": "global",
        "PSBT_IN_SEQUENCE": "input",
        "PSBT_OUT_AMOUNT": "output",
    }
    encoded = {
        test_vector["description"].removeprefix("PSBTv0 but with "): test_vector[
            "encoded psbt"
        ]
        for test_vector in load("psbt", "_data", "bip370_test_vectors.json")[
            "invalid psbts"
        ]
    }
    for field in per_map:
        with pytest.raises(
            BTClibValueError, match=f"{field} is not allowed in a v0 psbt"
        ):
            Psbt.b64decode(encoded[field])


def _bip370_psbt(description: str) -> Psbt:
    """The valid BIP370 psbt whose description starts with this."""
    valid = load("psbt", "_data", "bip370_test_vectors.json")["valid psbts"]
    encoded = next(
        test_vector["encoded psbt"]
        for test_vector in valid
        if test_vector["description"].startswith(description)
    )
    return Psbt.b64decode(encoded)


def test_a_v2_psbt_is_read_as_the_fields_and_not_as_a_transaction() -> None:
    """The fields are what a version 2 psbt is, and `tx` is computed.

    Which is the difference the design makes visible: writing into that
    transaction writes into a copy, so the psbt is unchanged and the
    next reader sees what the fields say. An outpoint is changed on the
    input that holds it.
    """
    psbt = _bip370_psbt("1 input, 2 output PSBTv2, required fields only")
    assert psbt.version == 2
    assert psbt.tx_version == 2
    assert len(psbt.inputs) == 1
    assert len(psbt.outputs) == 2

    psbt_in = psbt.inputs[0]
    assert psbt_in.previous_tx_id.hex() == (
        "c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b"
    )
    assert psbt_in.output_index == 0
    # absent, which BIP370 reads as the final sequence
    assert psbt_in.sequence is None
    assert psbt.tx.vin[0].sequence == 0xFFFFFFFF
    assert psbt.tx.vin[0].prev_out == psbt_in.prev_out

    assert psbt.outputs[0].amount == 800_000_000
    assert psbt.tx.vout[0].value == 800_000_000
    assert psbt.tx.vout[0].script_pub_key.script == psbt.outputs[0].script_pub_key

    # the copy, which is the whole point: what is written into it is
    # written into nothing, and the outpoint is changed on the input
    tx = psbt.tx
    tx.vin[0].sequence = 0
    assert psbt.tx.vin[0].sequence == 0xFFFFFFFF
    psbt_in.sequence = 0
    assert psbt.tx.vin[0].sequence == 0


def test_the_identifier_of_a_v2_psbt_ignores_the_sequences() -> None:
    """BIP370's "Unique Identification", and why a Combiner needs it.

    An Updater may set PSBT_IN_SEQUENCE, so two psbts of one transaction
    can differ by it -- and `tx.id`, which the sequence is part of,
    would call them two transactions and refuse the combine. The
    identifier is the txid with every sequence zeroed, so it does not
    move; a psbt whose *outpoint* differs is a different transaction by
    either measure.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2")
    updated = deepcopy(psbt)
    updated.inputs[0].sequence = 0xFFFFFFFD

    assert updated.tx.id != psbt.tx.id
    assert updated.unique_id == psbt.unique_id
    # the first psbt is the one combined into, and it has no sequence of
    # its own to keep: what BIP174 lets a Combiner choose between is two
    # values, and here there is one
    combined = combine_psbts([deepcopy(psbt), updated])
    assert combined.inputs[0].sequence == 0xFFFFFFFD
    assert (
        combine_psbts([deepcopy(updated), deepcopy(psbt)]).inputs[0].sequence
        == 0xFFFFFFFD
    )

    other = deepcopy(psbt)
    other.inputs[0].output_index = 1
    with pytest.raises(BTClibValueError, match="mismatched psbt.tx.id: "):
        combine_psbts([psbt, other])

    # and the two versions are not combined into each other: which of
    # them the result would be is the caller's to say, with to_v0/to_v2
    with pytest.raises(BTClibValueError, match="mismatched psbt version: 0 vs 2"):
        combine_psbts([psbt, psbt.to_v0()])


def test_combining_keeps_the_flags_no_more_permissive_than_they_were() -> None:
    """A combine cannot hand back what a Signer took away.

    The two modifiable bits are the AND of the psbts combined and the
    Has SIGHASH_SINGLE bit their OR, each in the direction that cannot
    invent permission: a Signer clears a modifiable bit when it adds a
    signature a change would break, and sets the third when the
    signature it added is a SIGHASH_SINGLE one.
    """
    both = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with all defined PSBT_GLOBAL_TX_MODIFIABLE"
    )
    assert both.tx_modifiable == 0b111

    inputs_only = deepcopy(both)
    inputs_only.tx_modifiable = INPUTS_MODIFIABLE
    combined = combine_psbts([deepcopy(both), inputs_only])
    # the inputs stay modifiable, the outputs do not, and the
    # SIGHASH_SINGLE one of the psbt that has it survives
    assert combined.tx_modifiable == INPUTS_MODIFIABLE | HAS_SIG_HASH_SINGLE

    # an undefined bit is nobody's to drop
    undefined = deepcopy(both)
    undefined.tx_modifiable = 0b1000
    assert combine_psbts([deepcopy(both), undefined]).tx_modifiable == 0b1100

    # a psbt with no field at all is "nothing may be modified", so it
    # clears the two bits of the psbt it is combined with
    absent = deepcopy(both)
    absent.tx_modifiable = None
    assert combine_psbts([deepcopy(both), absent]).tx_modifiable == HAS_SIG_HASH_SINGLE

    # and no field on either side stays no field: a combine does not
    # invent a claim neither psbt made
    plain = _bip370_psbt("1 input, 2 output updated PSBTv2")
    assert combine_psbts([plain, deepcopy(plain)]).tx_modifiable is None


def test_tx_modifiable_is_what_allows_a_shuffle() -> None:
    """The Constructor's two bits, honoured by the three helpers.

    Reordering the inputs or the outputs changes the transaction every
    signature commits to, so a version 2 psbt is asked before it is
    done. A version 0 psbt has no such field and is not asked: BIP174
    says nothing about who may reorder what.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2")
    assert psbt.tx_modifiable is None
    with pytest.raises(BTClibValueError, match="the inputs are not modifiable"):
        psbt.sort_inputs()
    with pytest.raises(BTClibValueError, match="the outputs are not modifiable"):
        psbt.sort_outputs()

    inputs_modifiable = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with Inputs Modifiable Flag"
    )
    assert inputs_modifiable.inputs_modifiable
    assert not inputs_modifiable.outputs_modifiable
    inputs_modifiable.sort_inputs()
    with pytest.raises(BTClibValueError, match="the outputs are not modifiable"):
        inputs_modifiable.sort_outputs()

    outputs_modifiable = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with Outputs Modifiable Flag"
    )
    outputs_modifiable.sort_outputs(lambda psbt_out: psbt_out.amount or 0)
    assert [psbt_out.amount for psbt_out in outputs_modifiable.outputs] == sorted(
        psbt_out.amount or 0 for psbt_out in outputs_modifiable.outputs
    )
    with pytest.raises(BTClibValueError, match="the inputs are not modifiable"):
        outputs_modifiable.sort_inputs()

    # the third bit refuses both sides whatever the other two say: a
    # SIGHASH_SINGLE signature commits to the output at its own input's
    # index, so no permutation preserves it
    pinned = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with all defined PSBT_GLOBAL_TX_MODIFIABLE"
    )
    assert pinned.inputs_modifiable
    assert pinned.outputs_modifiable
    assert pinned.has_sig_hash_single
    err_msg = "a SIGHASH_SINGLE signature pins each input to its output"
    with pytest.raises(BTClibValueError, match=err_msg):
        pinned.sort_inputs()
    with pytest.raises(BTClibValueError, match=err_msg):
        pinned.sort_outputs()

    # a version 0 psbt shuffles as it always has
    v0 = pinned.to_v0()
    assert v0.tx_modifiable is None
    v0.sort_inputs()
    v0.sort_outputs()


def test_joining_asks_every_psbt_whether_it_may_grow() -> None:
    """A join adds inputs and outputs to each psbt, so each is asked.

    Both flags, of every psbt joined: what comes out has the inputs and
    the outputs of all of them, so a psbt that may take neither is one
    the join must refuse rather than quietly rewrite.
    """
    first = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with all possible PSBT_GLOBAL_TX_MODIFIABLE"
    )
    # the SIGHASH_SINGLE bit is set in that one, and it refuses a join
    err_msg = "a SIGHASH_SINGLE signature pins each input to its output"
    with pytest.raises(BTClibValueError, match=err_msg):
        join_psbts([first, deepcopy(first)], True, True, False, False)

    first.tx_modifiable = INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    second = deepcopy(first)
    second.inputs[0].previous_tx_id = bytes.fromhex("11" * 32)
    second.inputs[0].non_witness_utxo = None
    second.inputs[0].sequence = 0xFFFFFFFD
    joined = join_psbts([first, deepcopy(second)], True, True, False, False)
    assert len(joined.inputs) == 2
    assert len(joined.outputs) == 4
    assert joined.version == 2
    assert joined.tx_modifiable == INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE

    frozen = deepcopy(second)
    frozen.tx_modifiable = INPUTS_MODIFIABLE
    with pytest.raises(BTClibValueError, match="the outputs are not modifiable"):
        join_psbts([first, frozen], True, True, False, False)

    # the transaction version is the transaction's, not the psbt's, and
    # enforce_same_tx_version is what asks the psbts to agree on it
    other_tx_version = deepcopy(second)
    other_tx_version.tx_version = 3
    with pytest.raises(BTClibValueError, match="Version numbers are not the same"):
        join_psbts([first, other_tx_version], True, True, False, False)

    with pytest.raises(BTClibValueError, match="mismatched psbt version: 0 vs 2"):
        join_psbts([first, second.to_v0()], True, True, False, False)


def test_converting_between_the_two_versions() -> None:
    """v0 to v2 is the version number; v2 to v0 is what v0 cannot say.

    The transaction is the same on both sides of either conversion,
    which is the whole requirement: the lock time an input required
    becomes the fallback, where a version 0 psbt keeps its nLockTime, so
    what is lost is the record of which input asked for it and not the
    value it asked for.
    """
    v2 = _bip370_psbt(
        "1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE, and all"
    )
    psbt_in = v2.inputs[0]
    assert psbt_in.required_time_lock_time is not None
    assert psbt_in.required_height_lock_time is not None
    assert v2.lock_time == psbt_in.required_height_lock_time

    v0 = v2.to_v0()
    assert v0.version == 0
    assert v0.tx == v2.tx
    assert v0.fallback_lock_time == v2.lock_time
    assert v0.inputs[0].required_time_lock_time is None
    assert v0.inputs[0].required_height_lock_time is None
    assert Psbt.b64decode(v0.b64encode()) == v0

    # and back, which is the same transaction again and not the same
    # psbt: what version 0 dropped is dropped
    assert v0.to_v2().tx == v2.tx
    assert v0.to_v2() != v2

    # a psbt whose inputs cannot agree on a kind of lock time has no
    # transaction, so it has no version 0 psbt either
    unreconcilable = deepcopy(v2)
    unreconcilable.inputs[0].required_height_lock_time = None
    unreconcilable.inputs.append(deepcopy(v2.inputs[0]))
    unreconcilable.inputs[1].required_time_lock_time = None
    unreconcilable.inputs[1].previous_tx_id = bytes.fromhex("11" * 32)
    unreconcilable.inputs[1].non_witness_utxo = None
    with pytest.raises(BTClibValueError, match="no lock time satisfies every input"):
        unreconcilable.to_v0()


def test_what_each_version_may_and_must_carry() -> None:
    """The two columns BIP370 gives each of its twelve fields.

    Excluded from version 0 and required in version 2, checked where the
    version is known -- which is the psbt and not the map: an input on
    its own is asked only what its values are, so that a version 2 input
    can be built one field at a time.
    """
    v0 = _bip370_psbt("1 input, 2 output updated PSBTv2").to_v0()

    # a version 0 psbt has nowhere to write a required lock time, so
    # holding one is holding what serializing would drop
    v0.inputs[0].required_height_lock_time = 10_000
    err_msg = "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is not allowed in a v0 psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        v0.assert_valid()
    v0.inputs[0].required_height_lock_time = None
    v0.inputs[0].required_time_lock_time = 500_000_000
    err_msg = "PSBT_IN_REQUIRED_TIME_LOCKTIME is not allowed in a v0 psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        v0.assert_valid()
    v0.inputs[0].required_time_lock_time = None

    v0.tx_modifiable = 0
    err_msg = "PSBT_GLOBAL_TX_MODIFIABLE is not allowed in a v0 psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        v0.assert_valid()
    v0.tx_modifiable = None

    # the outpoint is required in both versions: without it there is no
    # transaction to build, and a version 0 psbt reads it off the
    # unsigned transaction rather than out of a field
    v0.inputs[0].output_index = None
    with pytest.raises(BTClibValueError, match="missing PSBT_IN_OUTPUT_INDEX"):
        v0.assert_valid()
    v0.inputs[0].output_index = 0
    v0.inputs[0].previous_tx_id = b""
    with pytest.raises(BTClibValueError, match="missing PSBT_IN_PREVIOUS_TXID"):
        v0.assert_valid()


def test_the_values_the_v2_fields_may_hold() -> None:
    """What a map is asked on its own: ranges, and nothing versioned.

    Each is a 4-byte field but for the amount and the flags, and each
    bound is a rule of BIP370's own -- the two lock times being the two
    halves of BIP65's threshold, which is what makes one a height and
    the other a time.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2")
    psbt_in = psbt.inputs[0]

    psbt_in.output_index = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid output index: "):
        psbt_in.assert_valid()
    psbt_in.output_index = 0

    psbt_in.sequence = -1
    with pytest.raises(BTClibValueError, match="invalid sequence: "):
        psbt_in.assert_valid()
    psbt_in.sequence = None

    psbt_in.previous_tx_id = b"\x01" * 31
    with pytest.raises(BTClibValueError, match="invalid previous txid: 31 bytes"):
        psbt_in.assert_valid()
    psbt_in.previous_tx_id = b"\x01" * 32

    # at the threshold and above it a value is a timestamp, below it a
    # height, and 0 is nLockTime's "no lock time at all"
    psbt_in.required_time_lock_time = LOCK_TIME_THRESHOLD - 1
    with pytest.raises(BTClibValueError, match="invalid required time locktime: "):
        psbt_in.assert_valid()
    psbt_in.required_time_lock_time = LOCK_TIME_THRESHOLD
    psbt_in.assert_valid()
    psbt_in.required_time_lock_time = None

    psbt_in.required_height_lock_time = LOCK_TIME_THRESHOLD
    with pytest.raises(BTClibValueError, match="invalid required height locktime: "):
        psbt_in.assert_valid()
    psbt_in.required_height_lock_time = LOCK_TIME_THRESHOLD - 1
    psbt_in.assert_valid()
    psbt_in.required_height_lock_time = None

    psbt.outputs[0].amount = -1
    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        psbt.outputs[0].assert_valid()
    psbt.outputs[0].amount = 1

    psbt.tx_modifiable = 0x100
    with pytest.raises(BTClibValueError, match="invalid tx modifiable: 256"):
        psbt.assert_valid()
    psbt.tx_modifiable = None

    psbt.fallback_lock_time = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid fallback locktime: "):
        psbt.assert_valid()


def test_from_tx_wants_one_map_per_input_and_output() -> None:
    """The maps a caller brings are matched against the transaction.

    `parse` counts them off the transaction itself, so only a caller can
    get this wrong -- and a psbt cannot hold the disagreement any more,
    its maps being what its transaction is built from. What answers is
    therefore the conversion, at the moment the two are put together.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2").to_v0()
    tx = psbt.tx
    err_msg = "mismatched number of tx.vin and psbt inputs: 1 vs 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.from_tx(tx, [*psbt.inputs, PsbtIn()], psbt.outputs)
    err_msg = "mismatched number of tx.vout and psbt outputs: 2 vs 1"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.from_tx(tx, psbt.inputs, psbt.outputs[:1])


def test_a_v2_field_of_the_wrong_size_is_refused() -> None:
    """A field is its width, and a value of another width is not it.

    Not pedantry: read leniently, a four-byte field written in five
    octets deserializes to the same integer and serializes back to four,
    so one psbt would have two encodings -- the malleability the map
    parser refuses one level up, where the length is the map's.
    """
    psbt = _bip370_psbt("1 input, 2 output PSBTv2, required fields only")
    encoded = psbt.b64encode()
    raw = base64.b64decode(encoded)

    # PSBT_IN_OUTPUT_INDEX, four octets of little-endian zero, written
    # in five: the same 0, and a psbt that is 1 byte longer
    assert raw.count(bytes.fromhex("010f0400000000")) == 1
    padded = raw.replace(
        bytes.fromhex("010f0400000000"), bytes.fromhex("010f050000000000")
    )
    err_msg = "invalid output index length: 5 bytes instead of 4"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse(padded)

    # the txid, whose 32 octets are a length rather than a width, and
    # whose key is one byte as every key of a field that occurs once is
    txid_key = bytes.fromhex("010e20")
    assert raw.count(txid_key) == 1
    short = raw.replace(
        txid_key + psbt.inputs[0].previous_tx_id[::-1],
        bytes.fromhex("010e1f") + psbt.inputs[0].previous_tx_id[:31],
    )
    err_msg = "invalid previous txid length: 31 bytes instead of 32"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse(short)

    # and the counts, which are compact size and so have no width to
    # check: what takes its place is that the value is the number and
    # nothing after it
    assert raw.count(bytes.fromhex("01040101")) == 1
    trailing = raw.replace(bytes.fromhex("01040101"), bytes.fromhex("0104020100"))
    with pytest.raises(BTClibValueError, match="invalid input count: 2 bytes"):
        Psbt.parse(trailing)

    # a key with data after the type byte, for two fields that take
    # none: what the key of such a field is, is the type byte alone
    keyed_count = raw.replace(bytes.fromhex("01040101"), bytes.fromhex("0204000101"))
    with pytest.raises(BTClibValueError, match="invalid input count key length: 2"):
        Psbt.parse(keyed_count)
    keyed_version = raw.replace(
        bytes.fromhex("01020402000000"), bytes.fromhex("0202000402000000")
    )
    with pytest.raises(BTClibValueError, match="invalid tx version key length: 2"):
        Psbt.parse(keyed_version)


# the cases below are btclib's own, and btclib_test_vectors.json is where
# they live: neither BIP publishes them, so the file name says whose they
# are, the way bip174_ and bip371_ say whose those are. Their provenance
# is in tests/_data/README.md with every other vector file's


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("btclib_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_btclib(test_vector: dict[str, str]) -> None:
    """Each case must be refused by the parse, with the message recorded."""
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


# the "invalid psbt objects" section, and the three mutations that named
# its cases, are gone with the states they described. A psbt's inputs and
# outputs are its transaction now, rather than two lists a mutation could
# put out of step, so "one input map fewer than the unsigned tx has
# inputs" is not a psbt that can be built: dropping an input drops it
# from the transaction too. What can still be written down is written
# down, in "invalid psbts" above and as bytes: an unsigned transaction
# carrying a script_sig, and a version 2 count that does not match the
# maps that follow it


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("btclib_test_vectors.json", "invalid combinations")
)
def test_invalid_combination_btclib(test_vector: dict[str, Any]) -> None:
    """Psbts a Combiner must refuse to merge."""
    psbts = [Psbt.b64decode(encoded) for encoded in test_vector["encoded psbts"]]
    with pytest.raises(BTClibValueError) as excinfo:
        combine_psbts(psbts)
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("btclib_test_vectors.json", "unfinalizable psbts")
)
def test_unfinalizable_psbt_btclib(test_vector: dict[str, str]) -> None:
    """Valid psbts a Finalizer must refuse."""
    psbt = Psbt.b64decode(test_vector["encoded psbt"])
    with pytest.raises(BTClibValueError) as excinfo:
        finalize_psbt(psbt)
    assert test_vector["error message"] in str(excinfo.value)


def test_taproot_signature_carries_its_sig_hash_type() -> None:
    """A taproot signature is 64 bytes, or 65 with its hash type (issue #122).

    BIP341 appends the sig_hash type when it is not the default one, and
    BIP371 says "64 or 65 bytes" of both PSBT_IN_TAP_KEY_SIG and
    PSBT_IN_TAP_SCRIPT_SIG. Requiring 64 here, while btclib's own script
    engine reads the 65-byte form, would leave a signature Bitcoin Core
    accepts no psbt to travel in.

    The vectors are BIP371's own valid ones, whose signatures are 64
    bytes; what is exercised is the byte appended to them. Their invalid
    counterparts are 63 and 66 bytes, so they stay invalid, and
    test_invalid_psbt_bip371 is what says so.
    """
    valid = load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"]
    psbts = [Psbt.b64decode(test_vector["encoded psbt"]) for test_vector in valid]

    psbt = next(p for p in psbts if p.inputs[0].taproot_key_spend_signature)
    signature = psbt.inputs[0].taproot_key_spend_signature
    assert len(signature) == 64

    # ALL, appended: the 65-byte form
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x01"
    psbt.assert_valid()
    assert Psbt.b64decode(psbt.b64encode()) == psbt

    # 0x00 is what the 64-byte form already means, so appending it is a
    # second spelling of one signature: BIP341 refuses it, and so does
    # the engine's get_hashtype
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x00"
    err_msg = "invalid taproot key path signature: explicit SIGHASH_DEFAULT"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # not one of the seven values SIG_HASH_TYPES holds
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x04"
    err_msg = "invalid taproot key path signature sig_hash type: 0x4"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # and the length that is neither of the two
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x01\x01"
    err_msg = "invalid taproot key path signature length: 66 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # the script path field is a map, and gets the same treatment
    psbt = next(p for p in psbts if p.inputs[0].taproot_script_spend_signatures)
    signatures = psbt.inputs[0].taproot_script_spend_signatures
    key, signature = next(iter(signatures.items()))
    assert len(signature) == 64

    # ANYONECANPAY | ALL this time
    signatures[key] = signature + b"\x81"
    psbt.assert_valid()
    assert Psbt.b64decode(psbt.b64encode()) == psbt

    signatures[key] = signature + b"\x00"
    err_msg = "invalid taproot script path signature: explicit SIGHASH_DEFAULT"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # 0x80 is ANYONECANPAY with DEFAULT, which BIP341 does not define
    signatures[key] = signature + b"\x80"
    err_msg = "invalid taproot script path signature sig_hash type: 0x80"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    signatures[key] = signature[:63]
    err_msg = "invalid taproot script path signature length: 63 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()


def test_creation() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    output_1 = TxOut(
        149990000, ScriptPubKey("0014d85c2b71d0060b09c9886aeb815e50991dda124d")
    )
    output_2 = TxOut(
        100000000, ScriptPubKey("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    input_1 = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    input_2 = TxIn(
        OutPoint("1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83", 1),
        b"",
        0xFFFFFFFF,
    )
    transaction = Tx(2, 0, [input_1, input_2], [output_1, output_2])
    psbt_from_tx_ = Psbt.from_tx(transaction)
    assert psbt_from_tx_ == psbt


# all the updater stuff are missing


def test_psbt_combination() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt == psbt


# the psbt BIP174's Combiner example produces, which its Finalizer
# example turns into the one test_finalize compares against: two inputs,
# a p2sh 2-of-2 and a p2sh-p2wsh 2-of-2, each with both signatures and
# each asking for SIGHASH_ALL. It is the fixture of every Finalizer test
# below, the checks a Finalizer makes being per input
TO_BE_FINALIZED = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"


def test_finalize() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    to_be_finalized_psbt = Psbt.b64decode(TO_BE_FINALIZED)
    finalized_psbt = finalize_psbt(to_be_finalized_psbt)
    assert finalized_psbt == psbt


def test_extract_tx() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    tx = extract_tx(psbt)
    tx_string = "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000"
    tx_bin = tx.serialize(include_witness=True)
    assert tx_bin.hex() == tx_string


def test_lexicographic_ordering() -> None:
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt == psbt
    combined_psbt = combine_psbts([psbt2, psbt1])
    assert combined_psbt == psbt


# not part of the official BIP174 test vector


def test_merge() -> None:
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)

    psbt1.inputs[0].sig_hash_type = 1
    psbt.inputs[0].sig_hash_type = 1
    combined_psbt = combine_psbts([psbt2, psbt1])
    assert combined_psbt == psbt


def test_missing_script_pub_key() -> None:
    # the unknown fields are typed 0xf0, as every other composed psbt in
    # this module types them: 0x0f is PSBT_IN_OUTPUT_INDEX, which BIP370
    # forbids in a version 0 psbt, so a fixture using it as a spare type
    # byte is refused before it reaches the question being asked here
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)

    with pytest.raises(BTClibValueError) as excinfo:
        psbt.assert_signable()
    assert str(excinfo.value) == "missing script_pub_key"


def test_an_input_may_carry_both_utxos() -> None:
    """BIP174 allows an input to hold both UTXO types, and says which wins.

    "An input can have both PSBT_IN_NON_WITNESS_UTXO and
    PSBT_IN_WITNESS_UTXO", against the earlier "if an input is a witness
    input, then it should not have a Non-Witness UTXO key-value pair" --
    the footnote on the first is what settles the two: wallets began
    requiring the full previous transaction for segwit inputs after psbt
    was in use, so both types must be allowed for the software that
    expects either one to keep working. The combination is therefore
    valid, not a redundancy to be refused, and both records have to
    survive a round trip.

    Which one a Signer reads is the second half, and the BIP's simple
    signer algorithm is unambiguous: `if witness_utxo.exists` comes
    first, `else if non_witness_utxo.exists` second. btclib's
    _signable_payload has that order.
    """
    # a p2sh-p2wpkh output, the compatibility case the footnote is about:
    # a segwit input for which a wallet also wants the whole previous
    # transaction. Built here rather than taken from BIP174, whose ten
    # valid psbts carry one UTXO type per input and none the previous
    # transaction of a segwit one
    pub_key = "02 1e0f2b3f28d7b4a4c4ae4f0b3e2c6f9e5d8a7c1b0f2e3d4c5b6a798877665544"
    redeem_script = ScriptPubKey.p2wpkh(pub_key).script
    script_pub_key = ScriptPubKey.p2sh(redeem_script)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(bytes.fromhex("11" * 32), 0))],
        vout=[TxOut(100_000, script_pub_key)],
    )
    tx = Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(90_000, script_pub_key)])
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    psbt.inputs[0].witness_utxo = prev_tx.vout[0]
    psbt.inputs[0].redeem_script = redeem_script

    psbt.assert_valid()
    psbt.assert_signable()
    round_tripped = Psbt.b64decode(psbt.b64encode())
    assert round_tripped == psbt
    assert round_tripped.inputs[0].non_witness_utxo == prev_tx
    assert round_tripped.inputs[0].witness_utxo == prev_tx.vout[0]

    # and the precedence, read off a psbt where the two branches disagree:
    # BIP174's first valid vector is a p2pkh input carrying the previous
    # transaction alone, which the non-witness branch signs. Adding the
    # very output the outpoint already names -- the same UTXO, stated
    # twice, so nothing about the psbt has become untrue -- sends the
    # signer down the witness branch, where a p2pkh output is not
    # something a witness signature can spend
    encoded = load("psbt", "_data", "bip174_test_vectors.json")["valid psbts"][0]
    psbt = Psbt.b64decode(encoded["encoded psbt"])
    psbt_in = psbt.inputs[0]
    assert psbt_in.non_witness_utxo is not None
    assert psbt_in.witness_utxo is None
    psbt.assert_signable()

    psbt_in.witness_utxo = psbt_in.non_witness_utxo.vout[psbt.tx.vin[0].prev_out.vout]
    psbt.assert_valid()
    assert Psbt.b64decode(psbt.b64encode()) == psbt
    with pytest.raises(BTClibValueError, match=r"script type not in "):
        psbt.assert_signable()


def test_psbt() -> None:
    prev_out = OutPoint(
        "9dcfdb5836ecfe146bdaa896605ba21222f83cd014dd47adde14fab2aba7de9b", 1
    )
    script_sig = b""
    sequence = 0xFFFFFFFF
    tx_in = TxIn(prev_out, script_sig, sequence)

    tx_out1 = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    tx_out2 = TxOut(
        6381891, "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
    )
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    psbt = Psbt.from_tx(tx)
    assert psbt == Psbt.parse(psbt.serialize())
    assert psbt == Psbt.from_dict(psbt.to_dict())


def test_parse_reads_a_stream() -> None:
    """A psbt is one record in a stream, not the whole of a buffer.

    It ends at the separator of its last map, so a parse reading the
    stream can leave what follows to the caller, and can start where the
    caller has got to; a parse slicing bytes can do neither, which is
    what taking BinaryData rather than Octets answers (issue 179).
    """
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    psbt = Psbt.from_tx(Tx(1, 0, [tx_in], [tx_out]))
    psbt_bin = psbt.serialize()

    tail = b"whatever the caller reads next"
    stream = BytesIO(psbt_bin + tail)
    assert Psbt.parse(stream) == psbt
    assert stream.read() == tail

    # and the psbt need not be at the start of the buffer either: what
    # says a map is missing is the position, not the size
    head = b"whatever the caller has already read"
    stream = BytesIO(head + psbt_bin)
    stream.seek(len(head))
    assert Psbt.parse(stream) == psbt

    # BinaryData is a superset of Octets: bytes and hex-string still parse
    assert Psbt.parse(psbt_bin) == psbt
    assert Psbt.parse(psbt_bin.hex()) == psbt


def test_parse_refuses_what_follows_a_psbt_in_octets() -> None:
    """Octets are a psbt whole, and a tail is malleability.

    Accepting one means two buffers deserialize to the same object, and
    that object serializes back to only the shorter of them -- the same
    thing an unchecked read length would buy, which is what #138 was.
    Bitcoin Core refuses it in DecodeRawPSBT, the entry point that takes
    a buffer, and not in the Unserialize that reads a stream.
    """
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    psbt_bin = Psbt.from_tx(Tx(1, 0, [tx_in], [tx_out])).serialize()

    err_msg = "malformed psbt: 3 bytes after the psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse(psbt_bin + b"abc")
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse((psbt_bin + b"abc").hex())
    # base64 is octets too, being decoded to them
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(base64.b64encode(psbt_bin + b"abc").decode("ascii"))


def test_explicit_version() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    # the version btclib writes is the version the psbt declares, and
    # version 2 declares itself: a version 0 psbt converted to version 2
    # is the same transaction, written the other way, and comes back
    psbt_v2 = psbt.to_v2()
    assert psbt_v2.version == 2
    assert psbt_v2.tx == psbt.tx
    assert Psbt.b64decode(psbt_v2.b64encode()) == psbt_v2
    assert psbt_v2.to_v0() == psbt

    # and a version that is neither is refused on the way out and on the
    # way in, check_validity or not: which fields a psbt is written and
    # read as *is* its version, so there is nothing to defer
    psbt.version = 10
    err_msg = "invalid psbt version: 10"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.b64encode(check_validity=False)
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.b64encode(check_validity=True)
    encoded_v2 = psbt_v2.b64encode()
    # the same psbt, its version field alone edited: 0xfb 0x04, then the
    # four little-endian bytes of the version, 2 becoming 10
    ten = base64.b64encode(
        base64.b64decode(encoded_v2).replace(
            bytes.fromhex("01fb040200"), bytes.fromhex("01fb040a00")
        )
    ).decode("ascii")
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(ten, check_validity=False)


def test_global_unknown() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_output_unknown() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.outputs[0].unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_output_scripts_serialization() -> None:
    input_1 = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    output_1 = TxOut(
        149990000, bytes.fromhex("a914256b3a9ae8145e5094329537dd4d7a25dbc9452087")
    )
    output_2 = TxOut(
        100000000, bytes.fromhex("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    tx = Tx(2, 0, [input_1], [output_1, output_2])

    psbt = Psbt.from_tx(tx)

    # p2sh-p2wsh
    psbt.outputs[0].redeem_script = bytes.fromhex(
        "003BD89EE628E6EB745F99DF1E4AEF64A0DAA814850DAA509F30C0F472E0563C7A"
    )
    psbt.outputs[0].witness_script = bytes.fromhex(
        "522103dcea327ff7b2b4449413d9dc24cef0cc9e7864bad9d6291f3f1a04b639422c312103a2c5199b333adfaed4fea7ab65485b9e23a6cb317ddae7e8c1f2bd673414bdd352ae"
    )

    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_additional_combination() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt_1 = Psbt.b64decode(psbt_str)
    psbt_2 = Psbt.b64decode(psbt_str)

    # split the hd_key_paths dict in half
    hd_key_paths = psbt_1.inputs[1].hd_key_paths
    assert len(hd_key_paths) > 1
    i = len(hd_key_paths) // 2
    half_index = list(hd_key_paths.items())

    # first half
    psbt_1.inputs[1].hd_key_paths = dict(half_index[:i])
    # second half
    psbt_2.inputs[1].hd_key_paths = dict(half_index[i:])

    combined_psbt = combine_psbts([psbt_1, psbt_2])
    assert combined_psbt == psbt


def test_valid_sign() -> None:
    psbt_str = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.assert_signable()


def test_valid_sign_2() -> None:
    psbt_str = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    transaction_input = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    assert psbt.inputs[0].witness_utxo is not None
    # pylance cannot grok the following line, even considering the above line
    transaction = Tx(1, 2, [transaction_input], [psbt.inputs[0].witness_utxo])
    # on the input, which is where the outpoint is: writing it into
    # psbt.tx would write it into a copy, that transaction being computed
    # from the inputs at every access
    psbt.inputs[0].previous_tx_id = transaction.id
    psbt.inputs[0].non_witness_utxo = transaction
    psbt.assert_signable()


def test_sig_type1() -> None:
    # psbt with a single partial sig and one single input
    psbt_check_str = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgIDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX49IMEUCIQDh6ho/n3kEkusYgQ8OSeZQszl/kfpKOAwGSeMUSUMAngIgLDbfAC4tGyEdoCVrRGsnVB4zDEb9k4a1mhYbSQLoVMsBIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    psbt_check = Psbt.b64decode(psbt_check_str)
    assert psbt_check.b64encode() == psbt_check_str

    # template psbt with no sigs and one single input
    psbt_str = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    pk1 = bytes.fromhex(
        "03 572f9af6aebd7a6764264e17abdc4fc80cf359c11f81cbbe4ecf7a2c234a5f8f"
    )
    sig1 = bytes.fromhex(
        "3045022100e1ea1a3f9f790492eb18810f0e49e650b3397f91fa4a380c0649e3144943009e02202c36df002e2d1b211da0256b446b27541e330c46fd9386b59a161b4902e854cb01"
    )
    psbt.inputs[0].partial_sigs[pk1] = sig1
    assert psbt == psbt_check
    assert psbt.inputs[0].partial_sigs[pk1] == sig1


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    # Psbt dataclass
    assert isinstance(psbt, Psbt)

    # Psbt dataclass to dict
    psbt_dict = psbt.to_dict()
    assert isinstance(psbt_dict, dict)
    assert psbt_dict["tx"]

    # against the json committed beside this module, not written to it
    json_golden("psbt.json", psbt_dict)

    # Psbt dataclass from dict
    psbt2 = Psbt.from_dict(psbt_dict)
    assert isinstance(psbt2, Psbt)

    assert psbt == psbt2


def test_encode_serialize() -> None:
    # from creator example
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt_serialized = bytes.fromhex(
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"
    )
    assert psbt == Psbt.parse(psbt_serialized)
    assert psbt_serialized == psbt.serialize()


def test_exceptions() -> None:
    # from creator example
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].redeem_script = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].witness_script = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].unknown = {"bad key": b""}  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].unknown = {b"deadbeef": "bad value"}  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].sig_hash_type = 101
    with pytest.raises(BTClibValueError, match="invalid sig_hash type: "):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].final_script_sig = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    _, Q = dsa.gen_keys()
    pub_key = sec_point.bytes_from_point(Q)
    r = s = int.from_bytes(bytes.fromhex("FF" * 32), byteorder="big", signed=False)
    sig_bytes = dsa.Sig(r, s, check_validity=False).serialize(check_validity=False)
    psbt.inputs[0].partial_sigs = {pub_key: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature: "):
        psbt.serialize()

    pub_key = bytes.fromhex("02" + 31 * "00" + "07")
    psbt.inputs[0].partial_sigs = {pub_key: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature pub_key: "):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    err_msg = "invalid version: "
    psbt.version = -1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    psbt.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    # in range, and not one of the two versions there are
    psbt.version = 3
    with pytest.raises(BTClibValueError, match="invalid psbt version: 3"):
        psbt.serialize()

    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)
    # swap the two tx_id, each input keeping its own output index
    tx_id_0, tx_id_1 = (psbt_in.previous_tx_id for psbt_in in psbt.inputs)
    psbt.inputs[0].previous_tx_id = tx_id_1
    psbt.inputs[1].previous_tx_id = tx_id_0
    err_msg = "mismatched non-witness utxo / outpoint tx_id"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()


def test_valid_ripemd160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = ripemd160(preimage)
    psbt.inputs[0].ripemd160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_ripemd160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].ripemd160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid RIPEMD160 preimage"):
        psbt.assert_valid()


def test_valid_sha256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = sha256(preimage)
    psbt.inputs[0].sha256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_sha256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].sha256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid SHA256 preimage"):
        psbt.assert_valid()


def test_valid_hash160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash160(preimage)
    psbt.inputs[0].hash160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH160 preimage"):
        psbt.assert_valid()


def test_valid_hash256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash256(preimage)
    psbt.inputs[0].hash256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH256 preimage"):
        psbt.assert_valid()


def test_join_psbts() -> None:
    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt1 = Psbt.b64decode(psbt1_str)

    psbt2_str = "cHNidP8BAIkCAAAAAQKRPRGG7prm5Q6O5UJleyh9L9mmTPInNsVHnHzOS+ouAAAAAAAAAAAAAkBCDwAAAAAAIgAg1CyIdLnm/VxeOpIrt1Cvd2pVfTIgBuhGjqY7NVWGNgNDZAMAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGAAAAAAABASslqRIAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGIgICAO+hDq7He+h19gglhqAwUuruSCtWpIXFyEkj53crNh1IMEUCIQDiB1FrWN+TYztVhZTo7T7OJzQXTDz5dOhMG9+2ydm8+AIgb6pEEFSXYa9bAOExy4VQ3R3hpbi94l4doBBqLHQIh1ABIgIDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etHMEQCIC/gN9WvBgebfiLJoNGXL6VPtblmo09Yr9bkjmCdMVIfAiBKJu4UTYVPkun4Whq8YKlddlRp95nzzInN4MnPx0N7ZQEBBf2oAVIhAgDvoQ6ux3vodfYIJYagMFLq7kgrVqSFxchJI+d3KzYdIQKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWyEDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etTrmRSIQJAg8IBrMPT1XzBOuatwoVRObsgDKywIO/hTXX5BLqJ2yECWDeYBx2nVYYUPeICE2IgZ32CtqldcbZWrhmncmX7fxIhAs/eanomSWEuQFlCjry6HTmZcZ03c12wzMe6+jFMZFjYU68CkACyZ1MhA2HwlTuHQ7vQzuBibvN/r36m4MaIP6p1CEypK06o02pyIQNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7SEDahsw8dKvYjcoyrLfr+kWiXBRmG8cr0EBhDoslO3JgF0hA34ELbQa8gKi0ju2YUck4PSOLtfJ+QWAREM9Zmn4zAcjIQOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwSEDw2+64TPFicHXuZ1HYJWxEQ5v6iKmuTdgDvwIndMCfI9WrmgiBgIA76EOrsd76HX2CCWGoDBS6u5IK1akhcXISSPndys2HRj8i5WHKgAAgAAAAIAAAACAAQAAAAEAAAAiBgKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWxgN8rafKgAAgAAAAIAAAACAAQAAAAEAAAAiBgNh8JU7h0O70M7gYm7zf69+puDGiD+qdQhMqStOqNNqchg/h1X2LAAAgAAAAIAAAACAAQAAAAEAAAAiBgNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7RgmqLvwLAAAgAAAAIAAAACAAQAAAAEAAAAiBgNqGzDx0q9iNyjKst+v6RaJcFGYbxyvQQGEOiyU7cmAXRgQqVSnLAAAgAAAAIAAAACAAQAAAAEAAAAiBgN+BC20GvICotI7tmFHJOD0ji7XyfkFgERDPWZp+MwHIxgZXhf6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwRhm/AUgLAAAgAAAAIAAAACAAQAAAAEAAAAiBgPDb7rhM8WJwde5nUdglbERDm/qIqa5N2AO/Aid0wJ8jxg2/ys6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgPGl+7dj6StJU/DbqbkvCF2hhXJF/vFYEv4/lZRt07Z6xiTeMdTKgAAgAAAAIAAAACAAQAAAAEAAAAAAAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.fallback_lock_time = psbt1.lock_time
    joint_psbt = join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    )

    joint_psbt.assert_valid()
    assert all(i in joint_psbt.inputs for i in psbt1.inputs + psbt2.inputs)
    assert all(i in joint_psbt.outputs for i in psbt1.outputs + psbt2.outputs)

    # non-shuffled join is deterministic
    assert join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    ) == join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    )
    # Check that joining with shuffle=True does really shuffle inputs and
    # outputs. 10 attempts should be enough to get at least a shuffled
    # join that is different from the unshuffled one
    assert any(
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=True,
            shuffle_out=True,
        )
        != joint_psbt
        for _ in range(10)
    )

    # failure: different locktimes
    psbt2.fallback_lock_time = psbt1.lock_time ^ 12345678
    with pytest.raises(BTClibValueError, match="Lock times are not the same"):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # failure: common inputs
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.inputs.append(psbt2.inputs[0])
    err_msg = "common inputs"
    with pytest.raises(BTClibValueError, match=err_msg):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    fingerprint = b"beef"
    pub_key = bytes.fromhex(
        "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"
    )
    psbt1.hd_key_paths[pub_key] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    psbt2.hd_key_paths[pub_key] = BIP32KeyOrigin(fingerprint, "m/42/0/0/2")
    with pytest.raises(
        BTClibValueError, match="hd_key_paths: same pub_key, different key_origin"
    ):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    fingerprint = b"beef"
    pubkey1 = bytes.fromhex(
        "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"
    )
    pubkey2 = bytes.fromhex(
        "03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc"
    )
    psbt1.hd_key_paths[pubkey1] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    psbt2.hd_key_paths[pubkey2] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    with pytest.raises(
        BTClibValueError, match="hd_key_paths: same key_origin, different pub_key"
    ):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    psbt1.unknown[b"foo"] = b"321"
    psbt2.unknown[b"foo"] = b"123"
    with pytest.raises(BTClibValueError, match="unknown: same key, different value"):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # there is no merge_out parameter to ask for an output merge with:
    # coalescing two outputs paying one script invalidates every signature
    # already made over the previous set, and after the shuffle above the
    # result would depend on the order the merge ran in.
    # What says so is the parameter list, rather than a merge_out=True
    # call asserted to raise: that call raises a TypeError whose text is
    # the interpreter's -- CPython's "unexpected keyword argument" -- and
    # not a contract of this library, while the two asserts below are the
    # contract itself, no parameter of that name and no **kwargs to
    # swallow one
    params = inspect.signature(join_psbts).parameters
    assert "merge_out" not in params
    assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def test_shuffle_sort_inp_out() -> None:
    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt1 = Psbt.b64decode(psbt1_str)
    # let's shuffle inputs and outputs
    psbt1.sort_inputs()
    psbt1.sort_outputs()
    psbt1.assert_valid()


def test_shuffle_sort() -> None:
    """One sequence, sorted or shuffled, and the caller's left alone.

    The two lists it used to take were a psbt's inputs and its vin, kept
    in step because the outpoint of an input lived in the other list;
    under BIP370 the input carries its own outpoint, so there is one
    list to reorder and nothing to keep in step with it.
    """
    list_a = [2, 1, 4, 3]

    # testing sort
    assert _sort_or_shuffle(list_a, lambda t: t) == [1, 2, 3, 4]
    assert list_a == [2, 1, 4, 3]

    # testing shuffle
    # 10 attempts should be enough to reduce to zero the probability
    # of having (all) shuffled ones identical to the original one
    assert any(
        _sort_or_shuffle(list_a) != list_a and list_a == [2, 1, 4, 3] for _ in range(10)
    )


def test_a_psbt_may_have_no_inputs() -> None:
    """BIP174 lists two such psbts as valid, and btclib must take both.

    A PSBT's global unsigned transaction is incomplete by construction --
    that is the whole point of the format -- so the two rules that make an
    empty vin or vout invalid in a *transaction* do not apply to it,
    anywhere on its path: deserialize_tx on the way in, Psbt.assert_valid,
    and Tx.serialize on the way back out (issue 170).
    """
    # "PSBT with global unsigned tx that has 0 inputs and 0 outputs"
    empty = "cHNidP8BAAoAAAAAAAAAAAAAAA=="
    psbt = Psbt.b64decode(empty)
    assert not psbt.tx.vin
    assert not psbt.tx.vout
    assert not psbt.inputs
    assert not psbt.outputs
    psbt.assert_valid()
    assert psbt.b64encode() == empty
    assert Psbt.from_dict(psbt.to_dict()) == psbt

    # the transaction on its own is still not a valid transaction: the two
    # rules are dropped for the template, not for Tx
    with pytest.raises(BTClibValueError, match="Missing inputs"):
        psbt.tx.assert_valid()

    # valid, and not signable: every check in assert_signable is per input,
    # so without an explicit test an empty vin passes the loop vacuously
    # and a caller signs nothing while being told nothing. The answer
    # belongs here, not in assert_valid, which would refuse a psbt BIP174
    # calls valid
    with pytest.raises(BTClibValueError, match="nothing to sign: no inputs"):
        psbt.assert_signable()


def test_the_global_unsigned_tx_is_mandatory() -> None:
    """A psbt with no PSBT_GLOBAL_UNSIGNED_TX at all is refused (BIP174).

    Distinct from a psbt whose transaction has no inputs, which BIP174
    allows: Psbt.parse tracks whether the key was seen, so the two get
    different answers.
    """
    # "PSBT where inputs and outputs are provided but without an unsigned tx"
    no_tx = (
        "cHNidP8AAQBpAgAAAAGe/8Ee1KsvBiepWx6Kcs97VBcYtNMbrN+iUwLtGyRoNQAAAAAA/////"
        "wJhLQEAAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAAAAAAJagUpZ2FCcm9tAA"
        "AAAAABABYAFA0lQfhqxdgm7O5vlIhc2yEbGF+wAAA="
    )
    err_msg = "malformed psbt: missing global unsigned tx"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(no_tx)


def test_a_value_that_is_not_the_stated_size_says_so() -> None:
    """The size mismatch is what is reported, and the check is reachable.

    deserialize_tx compares the re-serialized transaction against the
    value it came from. Were Tx.parse to validate on the way in, a value
    the parse rejects would never reach the comparison, and this vector
    would be reported as "Missing inputs" -- true of it, and not what is
    wrong with it: 51 bytes whose transaction is 10.
    """
    bad_size = "cHNidP8BADN0Af8HAAEAAAABAP8BAApzMXQo/wAAAAAB/wEDAQAAAQAAAAAAAAAAdgEAAABBAAkAAAAAAA=="
    with pytest.raises(BTClibValueError, match="wrong tx serialization format"):
        Psbt.b64decode(bad_size)


# issue 249: the finalizer against btclib's own script engine

_PRV_KEY = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_PUB_KEY = bytes.fromhex(
    "02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d"
)


def _p2pkh_script_code(pub_key_hash: bytes) -> bytes:
    return serialize(
        ["OP_DUP", "OP_HASH160", pub_key_hash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )


def _single_key_psbt(kind: str) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input psbt of the given kind, signed and not finalized.

    The Updater's job, done here because btclib has no Signer: the psbt
    carries the utxo, the scripts the input needs, and one partial
    signature filed under the public key that made it.
    """
    p2pk = serialize([_PUB_KEY, "OP_CHECKSIG"])
    witness_script = p2pk if "p2wsh" in kind else b""
    script_pub_key = {
        "p2pkh": ScriptPubKey.p2pkh(_PUB_KEY),
        "p2wpkh": ScriptPubKey.p2wpkh(_PUB_KEY),
        "p2wsh": ScriptPubKey.p2wsh(p2pk),
        "p2sh-p2wpkh": ScriptPubKey.p2sh(ScriptPubKey.p2wpkh(_PUB_KEY).script),
        "p2sh-p2wsh": ScriptPubKey.p2sh(ScriptPubKey.p2wsh(p2pk).script),
    }[kind]
    redeem_script = (
        ScriptPubKey.p2wpkh(_PUB_KEY).script
        if kind == "p2sh-p2wpkh"
        else ScriptPubKey.p2wsh(p2pk).script
        if kind == "p2sh-p2wsh"
        else b""
    )

    prev_out = TxOut(100_000, script_pub_key)
    # the previous transaction, not merely the output it holds: a legacy
    # input is spent against the whole of it, and its id is the outpoint
    prev_tx = Tx(
        2, 0, [TxIn(OutPoint("00" * 31 + "01", 0), b"", 0xFFFFFFFF)], [prev_out]
    )
    tx_in = TxIn(OutPoint(prev_tx.id, 0), b"", 0xFFFFFFFF)
    tx = Tx(2, 0, [tx_in], [TxOut(90_000, ScriptPubKey.p2wpkh(_PUB_KEY))])

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].redeem_script = redeem_script
    psbt.inputs[0].witness_script = witness_script
    if kind == "p2pkh":
        psbt.inputs[0].non_witness_utxo = prev_tx
        msg_hash = sig_hash.legacy(script_pub_key.script, tx, 0, 1)
    else:
        psbt.inputs[0].witness_utxo = prev_out
        # BIP143's script code: the witness script for p2wsh, the p2pkh
        # script for the same hash160 for p2wpkh
        script_code = witness_script or _p2pkh_script_code(hash160(_PUB_KEY))
        msg_hash = sig_hash.segwit_v0(script_code, tx, 0, 1, prev_out.value)
    sig = dsa.sign_(msg_hash, _PRV_KEY).serialize() + b"\x01"
    psbt.inputs[0].partial_sigs = {_PUB_KEY: sig}
    return psbt, [prev_out]


@pytest.mark.parametrize(
    "kind", ["p2pkh", "p2wpkh", "p2wsh", "p2sh-p2wpkh", "p2sh-p2wsh"]
)
def test_what_the_finalizer_builds_the_engine_accepts(kind: str) -> None:
    """Finalize each single-key shape and run the result (issue #249).

    The five kinds a wallet actually holds, and the assertion is the
    script engine's rather than a string comparison: what the Finalizer
    writes is what a node executes, so the engine is the authority on
    whether it is right.

    Only the two multisig shapes reach here through BIP174's own
    vectors, which is why the single-key ones were broken -- the
    signature went into the script_sig of an input BIP141 requires an
    empty one of, and the public key a p2pkh or p2wpkh script hashes
    reached no stack at all.
    """
    psbt, prevouts = _single_key_psbt(kind)
    finalized = finalize_psbt(psbt)
    verify_transaction(prevouts, extract_tx(finalized, check_validity=False))


@pytest.mark.parametrize("kind", ["p2pkh", "p2wpkh", "p2sh-p2wpkh"])
def test_a_single_key_input_is_spent_with_its_public_key(kind: str) -> None:
    """The key beside the signature, and the empty script_sig (issue #249).

    Where each of the two goes is the whole of the difference between
    the three kinds: a native segwit input is spent with an empty
    script_sig and a witness, a wrapped one pushes its redeem script and
    nothing else, and a legacy p2pkh carries both stack items in the
    script_sig.
    """
    psbt, _ = _single_key_psbt(kind)
    sig = psbt.inputs[0].partial_sigs[_PUB_KEY]
    redeem_script = psbt.inputs[0].redeem_script
    psbt_in = finalize_psbt(psbt).inputs[0]

    if kind == "p2pkh":
        assert psbt_in.final_script_sig == serialize([sig, _PUB_KEY])
        assert not psbt_in.final_script_witness
    else:
        assert psbt_in.final_script_sig == serialize(
            [redeem_script] if redeem_script else []
        )
        assert psbt_in.final_script_witness.stack == (sig, _PUB_KEY)


def test_a_native_p2wsh_input_gets_no_script_sig() -> None:
    """No redeem script is no push, not a push of nothing (issue #249).

    serialize([b""]) is the one byte OP_0, which is a non-empty
    script_sig -- the very thing BIP141 forbids a native segwit input,
    and which the engine names.
    """
    psbt, _ = _single_key_psbt("p2wsh")
    assert finalize_psbt(psbt).inputs[0].final_script_sig == b""


def test_a_single_key_input_takes_one_signature() -> None:
    """A second signature is not a second half (issue #249).

    A p2wpkh output commits to one public key, so two partial signatures
    are two claims about which key that is; picking one is a guess, and
    the wrong guess builds a witness that will not run.

    The second signature is a real one, made by a second key over the
    same sig_hash, and it has to be: issue #173 put a signature check in
    the finalizer ahead of this one, so a signature merely refiled under
    another key is refused as invalid before the count is ever reached.
    Two valid signatures are what isolate the count, and they are also
    the case that matters -- two participants who each signed.
    """
    psbt, prev_outs = _single_key_psbt("p2wpkh")
    script_code = _p2pkh_script_code(hash160(_PUB_KEY))
    msg_hash = sig_hash.segwit_v0(script_code, psbt.tx, 0, 1, prev_outs[0].value)
    other_prv_key = _PRV_KEY + 1
    other_pub_key = pub_keyinfo_from_prv_key(other_prv_key)[0]
    psbt.inputs[0].partial_sigs[other_pub_key] = (
        dsa.sign_(msg_hash, other_prv_key).serialize() + b"\x01"
    )

    err_msg = "2 signatures for a single-key input"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)


def _one_input_finalized_each() -> tuple[Psbt, Psbt]:
    """Return the two psbts of two participants, one input finalized each."""
    finalized = finalize_psbt(Psbt.b64decode(TO_BE_FINALIZED))
    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = Psbt.b64decode(TO_BE_FINALIZED)
    first.inputs[0].final_script_sig = finalized.inputs[0].final_script_sig
    second.inputs[1].final_script_sig = finalized.inputs[1].final_script_sig
    second.inputs[1].final_script_witness = finalized.inputs[1].final_script_witness
    return first, second


def test_combining_takes_the_union_of_the_final_witnesses() -> None:
    """A witness one psbt has and the other has not survives the combine.

    BIP174's Combiner "must merge them into one PSBT", and the result
    "must contain all of the key-value pairs from each of the PSBTs": two
    participants finalizing one input each is the case that says so for
    the witness, which is not a map and so is not merged pair by pair.
    Both orders, the union being commutative when nothing conflicts.
    """
    finalized = finalize_psbt(Psbt.b64decode(TO_BE_FINALIZED))
    first, second = _one_input_finalized_each()
    for psbts in ([first, second], list(_one_input_finalized_each())[::-1]):
        combined = combine_psbts(psbts)
        assert combined.inputs[0].final_script_sig == (
            finalized.inputs[0].final_script_sig
        )
        assert combined.inputs[1].final_script_witness == (
            finalized.inputs[1].final_script_witness
        )

    # what conflicts is picked from, and the psbt combined *into* keeps
    # what it has: the arbitrary choice BIP174 allows a Combiner, and the
    # one Bitcoin Core's PSBTInput::Merge makes. Merging the two stacks
    # element-wise is what must not happen -- a witness stack is
    # positional, so two of them for one input are two spends of it
    first, second = _one_input_finalized_each()
    first.inputs[1].final_script_witness = Witness([b"\x01"])
    combined = combine_psbts([first, second])
    assert combined.inputs[1].final_script_witness == Witness([b"\x01"])


def test_finalize_refuses_a_signature_of_another_sig_hash_type() -> None:
    """BIP174 charges the Finalizer with the check, and it is per input.

    "If the input has a PSBT_IN_SIGHASH_TYPE field, the Input Finalizer
    must fail to finalize that input if any signature does not match the
    specified sighash type." Skipping it finalizes a psbt into a
    transaction whose signatures commit to something other than the input
    asked for, and the input is what the other participants agreed to.
    """
    # the vector's own psbt: both inputs ask for SIGHASH_ALL, and every
    # signature commits to it
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    assert psbt.inputs[0].sig_hash_type == 1
    assert all(sig[-1] == 1 for sig in psbt.inputs[0].partial_sigs.values())
    finalize_psbt(psbt)

    psbt.inputs[0].sig_hash_type = 3
    err_msg = "mismatched sig_hash type: 0x1 vs 0x3"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)

    # 0 is SIGHASH_DEFAULT, a type an input may ask for and no ECDSA
    # signature carries: what BIP174 tests is the field's presence, so a
    # falsy value is not an absent field
    psbt.inputs[0].sig_hash_type = 0
    err_msg = "mismatched sig_hash type: 0x1 vs 0x0"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)

    # no field, no check: the signatures say which type they commit to
    psbt.inputs[0].sig_hash_type = None
    finalize_psbt(psbt)


def test_finalize_checks_a_partial_signature_against_its_pub_key() -> None:
    """A signature filed under a key that did not make it is refused.

    PsbtIn.assert_valid parses the DER and can do no more: what the
    signature commits to is the whole transaction, which a per-field
    validator has not got. The Finalizer has it, and BIP174 has it decide
    "if the input has enough data to pass validation".
    """
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    finalize_psbt(psbt)

    # the two signatures of the 2-of-2 swapped between its two keys: both
    # are DER, both keys are on the curve, and neither pair belongs
    # together
    keys = list(psbt.inputs[0].partial_sigs)
    sigs = list(psbt.inputs[0].partial_sigs.values())
    psbt.inputs[0].partial_sigs = {keys[0]: sigs[1], keys[1]: sigs[0]}
    err_msg = "invalid partial signature for pub_key "
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)

    # and the same for the segwit input, whose hash is BIP143's
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    keys = list(psbt.inputs[1].partial_sigs)
    sigs = list(psbt.inputs[1].partial_sigs.values())
    psbt.inputs[1].partial_sigs = {keys[0]: sigs[1], keys[1]: sigs[0]}
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)


def test_an_input_that_does_not_say_what_it_spends() -> None:
    """No utxo is no dispatch, and the finalizer builds what it always did.

    A missing utxo is a psbt an Updater has not finished, not evidence
    about the spend, so it is not refused here: the signatures go into
    the script_sig with the redeem script after them, which is the
    answer for every kind the psbt has not identified. The same holds
    one level down, for a p2sh input carrying no redeem script
    (issue #249).
    """
    psbt, _ = _single_key_psbt("p2wpkh")
    sig = psbt.inputs[0].partial_sigs[_PUB_KEY]
    psbt.inputs[0].witness_utxo = None

    psbt_in = finalize_psbt(psbt).inputs[0]
    assert psbt_in.final_script_sig == serialize([sig])
    assert not psbt_in.final_script_witness


def test_the_sig_hash_of_an_input_that_does_not_say_what_it_spends() -> None:
    """Four inputs whose hash is not computable, each finalized all the same.

    None out of `_sig_hash_from_psbt_in` is "the psbt does not say what
    is being signed", which is not evidence against the signature: the
    Finalizer leaves such an input alone rather than refusing it.
    """
    # no utxo at all
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].non_witness_utxo = None
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    finalize_psbt(psbt)

    # p2sh with no redeem script: the script_pub_key names a hash, and
    # the script it hashes is what would be signed
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].redeem_script = b""
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    finalize_psbt(psbt)

    # p2wsh with no witness script, which is the BIP143 script code
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[1].witness_script = b""
    assert _sig_hash_from_psbt_in(psbt.inputs[1], psbt.tx, 1, 1) is None
    finalize_psbt(psbt)

    # a taproot output is spent with schnorr signatures, and they travel
    # in the taproot fields: an ECDSA partial signature beside a p2tr
    # script_pub_key is not a signature this hash would check
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(100000, ScriptPubKey("5120" + "aa" * 32))
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    finalize_psbt(psbt)


def test_the_sig_hash_of_every_input_kind_a_partial_signature_signs() -> None:
    """The helper's hash is the one the vectors' own signatures verify against.

    BIP174's valid psbts carry three partial signatures, over a p2wsh
    input and two p2wpkh ones; the p2sh and legacy dispatch is what the
    Finalizer tests above exercise, that psbt's two inputs being a p2sh
    2-of-2 and a p2sh-p2wsh one.
    """
    vectors = load("psbt", "_data", "bip174_test_vectors.json")["valid psbts"]
    checked = 0
    for vector in vectors:
        psbt = Psbt.b64decode(vector["encoded psbt"])
        for vin_i, psbt_in in enumerate(psbt.inputs):
            for pub_key, sig in psbt_in.partial_sigs.items():
                msg_hash = _sig_hash_from_psbt_in(psbt_in, psbt.tx, vin_i, sig[-1])
                assert msg_hash is not None
                assert dsa.verify_(msg_hash, pub_key, sig[:-1], lower_s=False)
                checked += 1
    # a count, so that a loop that stops finding signatures is a failure
    # and not a green run over nothing
    assert checked == 3


def test_the_outpoint_names_an_output_of_the_non_witness_utxo() -> None:
    """An index past that transaction's vout is refused, not an IndexError.

    The tx_id check beside it does not answer this question, and both
    readers of the spent output index with it: assert_signable, through
    _signable_payload, and the sig_hash the Finalizer verifies against.
    """
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    utxo = psbt.inputs[0].non_witness_utxo
    assert utxo is not None
    psbt.inputs[0].output_index = len(utxo.vout)

    err_msg = "outpoint vout out of range for the non-witness utxo"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()
