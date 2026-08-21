# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.psbt` module."""

import base64
import dataclasses
import inspect
from copy import deepcopy
from io import BytesIO
from typing import Any

import pytest

from btclib import var_bytes, var_int
from btclib.bip32 import BIP32KeyOrigin
from btclib.curves import sec_point
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256, tagged_hash
from btclib.psbt import (
    Psbt,
    PsbtIn,
    PsbtOut,
    assert_signatures_only,
    assert_signed,
    combine,
    ecdsa_sig_hash,
    extract_tx,
    finalize,
    join,
    new_signers,
    sign,
)
from btclib.psbt import musig2 as psbt_musig2
from btclib.psbt.psbt import (
    _V2_GLOBAL_FIELDS,
    HAS_SIG_HASH_SINGLE,
    INPUTS_MODIFIABLE,
    OUTPUTS_MODIFIABLE,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_VERSION,
    _sig_hash_from_psbt_in,
    _sort_or_shuffle,
    leaf_script,
    prevouts,
)
from btclib.psbt.psbt_in import _V2_FIELDS as _V2_INPUT_FIELDS
from btclib.psbt.psbt_in import LOCK_TIME_THRESHOLD
from btclib.psbt.psbt_out import _V2_FIELDS as _V2_OUTPUT_FIELDS
from btclib.psbt.psbt_utils import PSBT_SEPARATOR
from btclib.script import (
    ScriptPubKey,
    TaprootScriptTree,
    Witness,
    output_prvkey_from_merkle_root,
    serialize,
    sig_hash,
    taproot,
)
from btclib.script.engine import verify_transaction
from btclib.script.taproot import input_script_sig, tree_helper
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import MAX_TX_IN_COUNT, MAX_TX_OUT_COUNT
from tests import load
from tests.conftest import JsonGolden
from tests.psbt import psbt_vectors

# first tests are part of the official BIP174 test vectors


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
    rejection to its reason rather than to the fact of one. The case the
    BIP describes as a witness serialization and the one it describes as
    a value whose size is not the stated size share "superfluous witness
    record": the second one's transaction carries a marker over no
    witness, which `Tx.parse` stops on before the size is anything
    (issue 1104).
    """
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "signer check failures")
)
def test_signer_check_failure_bip174(test_vector: dict[str, str]) -> None:
    """Reproduce BIP174's signer check failures, message and all."""
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
    """Reproduce BIP371's invalid psbts, each refused with its message."""
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
    """Return the valid BIP373 psbt whose description starts with this."""
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


def test_an_aggregate_key_with_no_participants_is_not_a_field() -> None:
    """A field naming an aggregate key and naming nobody under it.

    Not reachable from bytes — an empty value is refused as it is read,
    a participant list being a positive number of keys — so the object is
    where the check has to be as well: KeyAgg has no answer for an empty
    list, and a psbt asserting valid with one names a session no signer
    can join.
    """
    psbt = _bip373_psbt("Spend of a Taproot output where the output key")
    aggregate = next(iter(psbt.inputs[0].musig2_participant_pub_keys))

    psbt.inputs[0].musig2_participant_pub_keys = {aggregate: []}
    err_msg = "invalid musig2 participant pub keys: none for aggregate key"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    err_msg = "invalid musig2 participant pub keys: 0 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        PsbtIn.parse(psbt.inputs[0].serialize(check_validity=False))


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


# what BIP375 excludes from version 0, on top of BIP370's twelve: a
# silent payment output has no script until the inputs are fixed, and
# only version 2 has a field to write one into afterwards. Listed here
# because BIP375 publishes no invalid-psbt vector per field to derive
# them from, the way bip370_test_vectors.json does
_BIP375_V2_FIELDS = {
    "PSBT_GLOBAL_SP_ECDH_SHARE",
    "PSBT_GLOBAL_SP_DLEQ",
    "PSBT_IN_SP_ECDH_SHARE",
    "PSBT_IN_SP_DLEQ",
    "PSBT_OUT_SP_V0_INFO",
    "PSBT_OUT_SP_V0_LABEL",
}


def test_the_v2_field_tables_hold_bip370s_twelve() -> None:
    """The three tables are the whole of what version 0 must exclude.

    A type byte no table names is filed under `unknown` and accepted, so
    a field missing from them is a psbt accepted that the BIP calls
    invalid -- which is what all twelve of these were. Derived from the
    vector file rather than listed again here: each of those cases is
    named after the one field it carries.

    BIP375's six are added to the expectation rather than derived:
    bip375_test_vectors.json has no case per field for them, so a list is
    the only statement there is.
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
    assert tabulated == named_by_the_bip | _BIP375_V2_FIELDS


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
    """Return the valid BIP370 psbt whose description starts with this."""
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
    combined = combine([deepcopy(psbt), updated])
    assert combined.inputs[0].sequence == 0xFFFFFFFD
    assert combine([deepcopy(updated), deepcopy(psbt)]).inputs[0].sequence == 0xFFFFFFFD

    other = deepcopy(psbt)
    other.inputs[0].output_index = 1
    with pytest.raises(BTClibValueError, match="mismatched psbt.tx.id: "):
        combine([deepcopy(psbt), deepcopy(other)])
    # and the other way round: what is compared is two identifiers for
    # equality, where an ordering would refuse one of the two arrangements
    # of the same disagreement and accept the other
    with pytest.raises(BTClibValueError, match="mismatched psbt.tx.id: "):
        combine([deepcopy(other), deepcopy(psbt)])

    # and the two versions are not combined into each other: which of
    # them the result would be is the caller's to say, with to_v0/to_v2
    with pytest.raises(BTClibValueError, match="mismatched psbt version: 0 vs 2"):
        combine([psbt, psbt.to_v0()])


def test_combining_keeps_a_fallback_lock_time_whichever_copy_holds_it() -> None:
    """The Combiner answers the same whichever psbt came first.

    The fallback is only reached when no input requires a lock time, so
    two psbts differing in it can compute the same lock time, be the same
    transaction by the unique id, and still disagree about the field --
    which is the case Bitcoin Core's Merge takes it in.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2")
    psbt.inputs[0].required_height_lock_time = 700_000
    psbt.fallback_lock_time = None
    other = deepcopy(psbt)
    other.fallback_lock_time = 500_000

    assert psbt.unique_id == other.unique_id
    assert psbt.lock_time == other.lock_time == 700_000

    for psbts in ([psbt, other], [other, psbt]):
        combined = combine([deepcopy(p) for p in psbts])
        assert combined.fallback_lock_time == 500_000
        assert combined.lock_time == 700_000

    # and the one already there is kept, as every other combined field is
    both = deepcopy(other)
    both.fallback_lock_time = 400_000
    assert combine([both, deepcopy(other)]).fallback_lock_time == 400_000


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
    combined = combine([deepcopy(both), inputs_only])
    # the inputs stay modifiable, the outputs do not, and the
    # SIGHASH_SINGLE one of the psbt that has it survives
    assert combined.tx_modifiable == INPUTS_MODIFIABLE | HAS_SIG_HASH_SINGLE

    # an undefined bit is nobody's to drop
    undefined = deepcopy(both)
    undefined.tx_modifiable = 0b1000
    assert combine([deepcopy(both), undefined]).tx_modifiable == 0b1100

    # a psbt with no field at all is "nothing may be modified", so it
    # clears the two bits of the psbt it is combined with
    absent = deepcopy(both)
    absent.tx_modifiable = None
    assert combine([deepcopy(both), absent]).tx_modifiable == HAS_SIG_HASH_SINGLE

    # and no field on either side stays no field: a combine does not
    # invent a claim neither psbt made
    plain = _bip370_psbt("1 input, 2 output updated PSBTv2")
    assert combine([plain, deepcopy(plain)]).tx_modifiable is None


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
        join([first, deepcopy(first)], True, True, False, False)

    first.tx_modifiable = INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    second = deepcopy(first)
    second.inputs[0].previous_tx_id = bytes.fromhex("11" * 32)
    second.inputs[0].non_witness_utxo = None
    second.inputs[0].sequence = 0xFFFFFFFD
    joined = join([first, deepcopy(second)], True, True, False, False)
    assert len(joined.inputs) == 2
    assert len(joined.outputs) == 4
    assert joined.version == 2
    assert joined.tx_modifiable == INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE

    frozen = deepcopy(second)
    frozen.tx_modifiable = INPUTS_MODIFIABLE
    with pytest.raises(BTClibValueError, match="the outputs are not modifiable"):
        join([first, frozen], True, True, False, False)

    # the transaction version is the transaction's, not the psbt's, and
    # enforce_same_tx_version is what asks the psbts to agree on it
    other_tx_version = deepcopy(second)
    other_tx_version.tx_version = 3
    with pytest.raises(BTClibValueError, match="Version numbers are not the same"):
        join([first, other_tx_version], True, True, False, False)

    with pytest.raises(BTClibValueError, match="mismatched psbt version: 0 vs 2"):
        join([first, second.to_v0()], True, True, False, False)


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


def test_the_v2_fields_are_valid_at_both_ends_of_their_range() -> None:
    """The value each bound allows, beside the one the test above refuses.

    A range asserted from one side only is a range whose own number never
    mattered: every one of these bounds survives being moved by one as
    long as nothing asks for the value it is supposed to admit. So each
    is exercised here at the edge it accepts -- and at zero, which is a
    number three of these fields treat differently from each other.
    """
    psbt = _bip370_psbt("1 input, 2 output updated PSBTv2")
    psbt_in = psbt.inputs[0]

    # a timestamp of 0xFFFFFFFF is the last second nLockTime can express,
    # and the second after it is a field that does not fit
    psbt_in.required_time_lock_time = 0xFFFFFFFF
    psbt_in.assert_valid()
    psbt_in.required_time_lock_time = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid required time locktime: "):
        psbt_in.assert_valid()
    psbt_in.required_time_lock_time = None

    # height 1 is the first block a lock time can require: 0 is
    # nLockTime's "no lock time at all", so an input requiring it
    # requires nothing
    psbt_in.required_height_lock_time = 1
    psbt_in.assert_valid()
    psbt_in.required_height_lock_time = 0
    with pytest.raises(BTClibValueError, match="invalid required height locktime: 0"):
        psbt_in.assert_valid()
    psbt_in.required_height_lock_time = None

    # no flag set is a psbt nobody may modify, which is a psbt ready to
    # be signed rather than an invalid one
    psbt.tx_modifiable = 0
    psbt.assert_valid()
    psbt.tx_modifiable = 0xFF
    psbt.assert_valid()
    psbt.tx_modifiable = None

    # and both ends of the fallback lock time, which is the field the
    # Creator writes when no input requires one
    for lock_time in (0, 0xFFFFFFFF):
        psbt.fallback_lock_time = lock_time
        psbt.assert_valid()
    psbt.fallback_lock_time = -1
    with pytest.raises(BTClibValueError, match="invalid fallback locktime: -1"):
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


def test_the_global_version_is_four_octets_and_no_other_number_of_them() -> None:
    """BIP174 calls it a little-endian uint32, so five values are not one.

    Read without its width, the field made one psbt out of five encodings:
    an empty value, one octet, two, three and four all deserialize to a
    version this writes back as four -- the malleability every other
    fixed-width field of the format is held away from.

    A length is not an opinion about what the psbt means, so it is refused
    with either value of `check_validity`; and it is refused ahead of the
    version being one of the two that exist, which is what a value of `00`
    in one octet would otherwise have been.
    """
    header = "70736274ff" + "01020402000000" + "01040100" + "01050100"
    canonical = f"{header}01fb040200000000"

    psbt = Psbt.parse(canonical)
    assert psbt.version == 2
    assert psbt.serialize().hex() == canonical

    for size in (0, 1, 2, 3, 5):
        value = (2).to_bytes(max(size, 4), "little")[:size]
        field = bytes([1]) + PSBT_GLOBAL_VERSION + bytes([size]) + value
        raw = bytes.fromhex(header) + field + PSBT_SEPARATOR
        err_msg = f"invalid global version length: {size} bytes instead of 4"
        for check_validity in (True, False):
            with pytest.raises(BTClibValueError, match=err_msg):
                Psbt.parse(raw, check_validity=check_validity)


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
        combine(psbts)
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("btclib_test_vectors.json", "unfinalizable psbts")
)
def test_unfinalizable_psbt_btclib(test_vector: dict[str, str]) -> None:
    """Valid psbts a Finalizer must refuse."""
    psbt = Psbt.b64decode(test_vector["encoded psbt"])
    with pytest.raises(BTClibValueError) as excinfo:
        finalize(psbt)
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
    """Reproduce BIP174's Creator example via Psbt.from_tx."""
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
    """Reproduce BIP174's Combiner example."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine([psbt1, psbt2])
    assert combined_psbt == psbt


# the psbt BIP174's Combiner example produces, which its Finalizer
# example turns into the one test_finalize compares against: two inputs,
# a p2sh 2-of-2 and a p2sh-p2wsh 2-of-2, each with both signatures and
# each asking for SIGHASH_ALL. It is the fixture of every Finalizer test
# below, the checks a Finalizer makes being per input
TO_BE_FINALIZED = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"


def test_finalize() -> None:
    """Reproduce BIP174's Finalizer example."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    to_be_finalized_psbt = Psbt.b64decode(TO_BE_FINALIZED)
    finalized_psbt = finalize(to_be_finalized_psbt)
    assert finalized_psbt == psbt


def test_extract_tx() -> None:
    """Reproduce BIP174's Extractor example, byte for byte."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    tx = extract_tx(psbt)
    tx_string = "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000"
    tx_bin = tx.serialize(include_witness=True)
    assert tx_bin.hex() == tx_string


def test_lexicographic_ordering() -> None:
    """Reproduce BIP174's lexicographic Combiner example, either order."""
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine([psbt1, psbt2])
    assert combined_psbt == psbt
    combined_psbt = combine([psbt2, psbt1])
    assert combined_psbt == psbt


# not part of the official BIP174 test vector


def test_merge() -> None:
    """Combine two psbts whose input carries a sig_hash type."""
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)

    psbt1.inputs[0].sig_hash_type = 1
    psbt.inputs[0].sig_hash_type = 1
    combined_psbt = combine([psbt2, psbt1])
    assert combined_psbt == psbt


def test_missing_script_pub_key() -> None:
    """Refuse to sign an input whose script_pub_key is missing."""
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
    """Round-trip a from_tx psbt through serialize and dict."""
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

    err_msg = "3 bytes after the psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse(psbt_bin + b"abc")
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse((psbt_bin + b"abc").hex())
    # base64 is octets too, being decoded to them
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(base64.b64encode(psbt_bin + b"abc").decode("ascii"))


def test_explicit_version() -> None:
    """Convert between versions 0 and 2; refuse any other version."""
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


@pytest.mark.parametrize("version", [0x80000000, 0xFFFFFFFF])
def test_tx_version_over_the_signed_bound(version: int) -> None:
    """A version 2 psbt holds every transaction version `Tx` does.

    BIP370 calls PSBT_GLOBAL_TX_VERSION a signed integer and btclib
    reads it unsigned, which is `Tx`'s own reading of the same four
    octets; the parser table says why. Read as signed, these two
    versions have no four-byte encoding to be written into and the
    field's `ffffffff` comes back as -1, which `Tx` then refuses.
    """
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    psbt = Psbt.from_tx(Tx(version, 0, [tx_in], [tx_out]))

    psbt_v2 = psbt.to_v2()
    psbt_bin = psbt_v2.serialize()
    # 0x01 0x02, the key length and the global type, then the four
    # little-endian octets of the version, which is what a signed field
    # could not have written
    assert bytes.fromhex("0102") + b"\x04" + version.to_bytes(4, "little") in psbt_bin

    parsed = Psbt.parse(psbt_bin)
    assert parsed.tx_version == version
    assert parsed == psbt_v2
    assert psbt_v2.to_v0() == psbt
    assert psbt_v2.tx == psbt.tx


def test_global_unknown() -> None:
    """Round-trip a psbt carrying an unknown global key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def _one_input_psbt() -> Psbt:
    """Return the smallest psbt these tests need: one input, one output."""
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    return Psbt.from_tx(Tx(1, 0, [tx_in], [tx_out]))


@pytest.mark.parametrize("message", [b"hello world", b"", "öäü \U0001f604".encode()])
def test_the_signed_message_round_trips_in_both_versions(message: bytes) -> None:
    """BIP322's global field, a field now rather than an unknown key.

    "Versions allowing inclusion: 0, 2" is what keeps it out of the
    BIP370 table beside it, and is what the two halves below are: the
    same message in a version 0 psbt and in the version 2 psbt of the
    same transaction, each written and read back as itself. Nothing is
    left under `unknown`, which is where it went before it was a field
    and is what says the registration took.

    The empty message is the case a truthiness test loses: BIP322 signs
    it like any other -- its own vectors do -- so what says a psbt
    carries no message is the absence of the field, not an empty value.
    """
    psbt = _one_input_psbt()
    assert psbt.signed_message is None

    for one in (psbt, psbt.to_v2()):
        one.signed_message = message
        parsed = Psbt.parse(one.serialize())
        assert parsed.signed_message == message
        assert not parsed.unknown
        assert parsed == one
        assert Psbt.from_dict(one.to_dict()) == one


def test_the_signed_message_key_is_its_type_byte_alone() -> None:
    """<keydata> is "none", so a longer key is not this field.

    The rule every field written that way is held to, and the reason it
    is a rule: a key of two octets is a second field of one type, which
    is one psbt with two messages in it.
    """
    psbt = _one_input_psbt()
    psbt.signed_message = b"hi"
    raw = psbt.serialize()

    # 0x01 0x09, the key length and the global type, then the message as
    # a var_bytes; the replacement is the same field with a zero octet
    # of keydata after the type
    assert raw.count(bytes.fromhex("0109026869")) == 1
    keyed = raw.replace(bytes.fromhex("0109026869"), bytes.fromhex("020900026869"))
    with pytest.raises(BTClibValueError, match="invalid global signed message key"):
        Psbt.parse(keyed)


def test_combining_takes_a_signed_message_from_either_side() -> None:
    """The Combiner's rule for a field that is one key-value pair.

    Taken where the psbt combined into has none, kept where it has one,
    and the empty message is a message in both directions: a truthy test
    would drop it, so combine([a, b]) and combine([b, a]) would answer
    differently for the same pair.
    """
    for message in (b"a message", b""):
        plain, carrying = _one_input_psbt(), _one_input_psbt()
        carrying.signed_message = message
        assert combine([deepcopy(plain), deepcopy(carrying)]).signed_message == message
        assert combine([deepcopy(carrying), deepcopy(plain)]).signed_message == message

    kept, other = _one_input_psbt(), _one_input_psbt()
    kept.signed_message = b"the first"
    other.signed_message = b"the second"
    assert combine([kept, other]).signed_message == b"the first"

    assert combine([_one_input_psbt(), _one_input_psbt()]).signed_message is None


def test_joining_does_not_carry_a_signed_message_over() -> None:
    """A message names a transaction, and joining builds another one.

    BIP322 binds the message to the first input's outpoint, and a join
    can put a different input first; carrying the field over would name
    a challenge the joined transaction does not answer.
    """
    first = _one_input_psbt()
    first.signed_message = b"mine"
    second = Psbt.from_tx(
        Tx(
            1,
            0,
            [TxIn(OutPoint(bytes(reversed(range(32))), 0), b"", 0xFFFFFFFF)],
            [TxOut(1000, "a914f987c321394968be164053d352fc49763b2be55c87")],
        )
    )
    joined = join([first, second], False, False, False, False)
    assert joined.signed_message is None


def test_output_unknown() -> None:
    """Round-trip a psbt carrying an unknown output key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.outputs[0].unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_output_scripts_serialization() -> None:
    """Round-trip an output carrying redeem and witness scripts."""
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
    """Combine two psbts holding one half of hd_key_paths each."""
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

    combined_psbt = combine([psbt_1, psbt_2])
    assert combined_psbt == psbt


def test_valid_sign() -> None:
    """Check the Updater's example psbt passes assert_signable."""
    psbt_str = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.assert_signable()


def test_valid_sign_2() -> None:
    """Check signability with a matching non-witness utxo added."""
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
    """Add one partial signature and match the expected psbt."""
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
    """Round-trip a Psbt through dict, against the golden json."""
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
    """Match the Creator example's binary serialization both ways."""
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
    """Refuse bad field types, versions, and mismatched outpoints."""
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
    psbt.inputs[0].sig_hash_type = 101  # type: ignore[assignment]
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
    """Accept a RIPEMD160 preimage that hashes to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = ripemd160(preimage)
    psbt.inputs[0].ripemd160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_ripemd160_preimage() -> None:
    """Refuse a RIPEMD160 preimage that does not hash to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].ripemd160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid RIPEMD160 preimage"):
        psbt.assert_valid()


def test_valid_sha256_preimage() -> None:
    """Accept a SHA256 preimage that hashes to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = sha256(preimage)
    psbt.inputs[0].sha256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_sha256_preimage() -> None:
    """Refuse a SHA256 preimage that does not hash to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].sha256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid SHA256 preimage"):
        psbt.assert_valid()


def test_valid_hash160_preimage() -> None:
    """Accept a HASH160 preimage that hashes to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash160(preimage)
    psbt.inputs[0].hash160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash160_preimage() -> None:
    """Refuse a HASH160 preimage that does not hash to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH160 preimage"):
        psbt.assert_valid()


def test_valid_hash256_preimage() -> None:
    """Accept a HASH256 preimage that hashes to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash256(preimage)
    psbt.inputs[0].hash256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash256_preimage() -> None:
    """Refuse a HASH256 preimage that does not hash to its key."""
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH256 preimage"):
        psbt.assert_valid()


def test_join() -> None:
    """Join psbts, shuffled or not; refuse conflicting ones."""
    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt1 = Psbt.b64decode(psbt1_str)

    psbt2_str = "cHNidP8BAIkCAAAAAQKRPRGG7prm5Q6O5UJleyh9L9mmTPInNsVHnHzOS+ouAAAAAAAAAAAAAkBCDwAAAAAAIgAg1CyIdLnm/VxeOpIrt1Cvd2pVfTIgBuhGjqY7NVWGNgNDZAMAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGAAAAAAABASslqRIAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGIgICAO+hDq7He+h19gglhqAwUuruSCtWpIXFyEkj53crNh1IMEUCIQDiB1FrWN+TYztVhZTo7T7OJzQXTDz5dOhMG9+2ydm8+AIgb6pEEFSXYa9bAOExy4VQ3R3hpbi94l4doBBqLHQIh1ABIgIDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etHMEQCIC/gN9WvBgebfiLJoNGXL6VPtblmo09Yr9bkjmCdMVIfAiBKJu4UTYVPkun4Whq8YKlddlRp95nzzInN4MnPx0N7ZQEBBf2oAVIhAgDvoQ6ux3vodfYIJYagMFLq7kgrVqSFxchJI+d3KzYdIQKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWyEDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etTrmRSIQJAg8IBrMPT1XzBOuatwoVRObsgDKywIO/hTXX5BLqJ2yECWDeYBx2nVYYUPeICE2IgZ32CtqldcbZWrhmncmX7fxIhAs/eanomSWEuQFlCjry6HTmZcZ03c12wzMe6+jFMZFjYU68CkACyZ1MhA2HwlTuHQ7vQzuBibvN/r36m4MaIP6p1CEypK06o02pyIQNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7SEDahsw8dKvYjcoyrLfr+kWiXBRmG8cr0EBhDoslO3JgF0hA34ELbQa8gKi0ju2YUck4PSOLtfJ+QWAREM9Zmn4zAcjIQOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwSEDw2+64TPFicHXuZ1HYJWxEQ5v6iKmuTdgDvwIndMCfI9WrmgiBgIA76EOrsd76HX2CCWGoDBS6u5IK1akhcXISSPndys2HRj8i5WHKgAAgAAAAIAAAACAAQAAAAEAAAAiBgKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWxgN8rafKgAAgAAAAIAAAACAAQAAAAEAAAAiBgNh8JU7h0O70M7gYm7zf69+puDGiD+qdQhMqStOqNNqchg/h1X2LAAAgAAAAIAAAACAAQAAAAEAAAAiBgNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7RgmqLvwLAAAgAAAAIAAAACAAQAAAAEAAAAiBgNqGzDx0q9iNyjKst+v6RaJcFGYbxyvQQGEOiyU7cmAXRgQqVSnLAAAgAAAAIAAAACAAQAAAAEAAAAiBgN+BC20GvICotI7tmFHJOD0ji7XyfkFgERDPWZp+MwHIxgZXhf6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwRhm/AUgLAAAgAAAAIAAAACAAQAAAAEAAAAiBgPDb7rhM8WJwde5nUdglbERDm/qIqa5N2AO/Aid0wJ8jxg2/ys6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgPGl+7dj6StJU/DbqbkvCF2hhXJF/vFYEv4/lZRt07Z6xiTeMdTKgAAgAAAAIAAAACAAQAAAAEAAAAAAAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.fallback_lock_time = psbt1.lock_time
    joint_psbt = join(
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
    assert join(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    ) == join(
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
        join(
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
        join(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # failure: common inputs. The shared input comes from the other psbt,
    # which is what this refusal is about: each psbt spends its outpoints
    # once and is valid on its own, and only the join would spend one of
    # them twice -- a psbt naming one outpoint twice by itself is refused
    # by `Tx.assert_valid`, which `_ensure_consistency` reaches first
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.inputs.append(deepcopy(psbt1.inputs[0]))
    err_msg = "common inputs"
    with pytest.raises(BTClibValueError, match=err_msg):
        join(
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
        join(
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
        join(
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
        join(
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
    params = inspect.signature(join).parameters
    assert "merge_out" not in params
    assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def test_shuffle_sort_inp_out() -> None:
    """Sort a psbt's inputs and outputs and keep it valid."""
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
        _sort_or_shuffle(list_a, None) != list_a and list_a == [2, 1, 4, 3]
        for _ in range(10)
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


def _psbt_from_unsigned_tx_value(value: bytes) -> bytes:
    """Return the smallest psbt carrying `value` as PSBT_GLOBAL_UNSIGNED_TX.

    The two tests below hand it octets no encoder would write, which is
    what a vector file usually holds; built here instead because what
    each of them is about is a length, and a base64 string states one
    where these state where it came from.
    """
    return (
        b"psbt\xff"
        + var_int.serialize(len(PSBT_GLOBAL_UNSIGNED_TX))
        + PSBT_GLOBAL_UNSIGNED_TX
        + var_bytes.serialize(value)
        + PSBT_SEPARATOR
    )


def test_a_value_that_is_not_the_stated_size_says_so() -> None:
    """The size mismatch is what is reported, and by the parser itself.

    The value announces more octets than its transaction holds, and a
    value is one whole transaction: the thirty-nine left over are refused
    where they are read, rather than the length being taken on trust and
    the remainder dropped in silence.

    BIP174's "invalid value data due to its size being not the stated
    size" is such a value and no longer reaches this refusal: its
    transaction carries a witness marker over no witness at all, so
    `Tx.parse` stops on that first (issue 1104). The shape is what this
    test is about, so it builds one whose transaction is otherwise
    well-formed.
    """
    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, ScriptPubKey(b"\x51"))],
    )
    value = tx.serialize(include_witness=False) + b"\x00" * 39
    with pytest.raises(BTClibValueError, match="39 bytes after the transaction"):
        Psbt.parse(_psbt_from_unsigned_tx_value(value))


def test_an_unsigned_tx_that_re_serializes_to_something_else_is_refused() -> None:
    """`deserialize_tx` compares the parse against the octets it read.

    BIP174's global unsigned transaction is the stripped serialization,
    which is why `deserialize_tx` is called with `include_witness` False
    and compares: a value holding a witness serialization is a value the
    psbt could not write back.

    A witness carrying something is what reaches that comparison. A
    template written in witness format has empty stacks by construction
    -- it is unsigned -- so `Tx.parse` refuses it one layer down for the
    encoding (issue 1104), and what is left here is the transaction that
    parses whole and re-serializes to something else.
    """
    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF, Witness([b"\x03" * 64]))],
        [TxOut(1, ScriptPubKey(b"\x51"))],
    )
    value = tx.serialize(include_witness=True)
    with pytest.raises(BTClibValueError, match="wrong tx serialization format"):
        Psbt.parse(_psbt_from_unsigned_tx_value(value))


# issue 249: the finalizer against btclib's own script engine

_PRV_KEY = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_PUB_KEY = bytes.fromhex(
    "02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d"
)
# a second key, for the inputs that hold more than one signature
_OTHER_PRV_KEY = _PRV_KEY + 1
_OTHER_PUB_KEY = pub_keyinfo_from_prv_key(_OTHER_PRV_KEY)[0]


def _p2pkh_script_code(pub_key_hash: bytes) -> bytes:
    return serialize(
        ["OP_DUP", "OP_HASH160", pub_key_hash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )


def _spending_tx(prev_out: TxOut) -> tuple[Tx, Tx]:
    """Return the transaction spending an output, and the one holding it.

    The previous transaction and not merely the output: a legacy input is
    spent against the whole of it, and its id is the outpoint the
    spending transaction names.
    """
    prev_tx = Tx(
        2, 0, [TxIn(OutPoint("00" * 31 + "01", 0), b"", 0xFFFFFFFF)], [prev_out]
    )
    tx_in = TxIn(OutPoint(prev_tx.id, 0), b"", 0xFFFFFFFF)
    return Tx(2, 0, [tx_in], [TxOut(90_000, ScriptPubKey.p2wpkh(_PUB_KEY))]), prev_tx


def _single_key_psbt(kind: str) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input psbt of the given kind, signed and not finalized.

    The Updater's job: the psbt carries the utxo, the scripts the input
    needs, and one partial signature filed under the public key that
    made it, built directly rather than through `sign` so these
    finalizer-focused tests do not depend on it.
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
    tx, prev_tx = _spending_tx(prev_out)

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
    finalized = finalize(psbt)
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
    psbt_in = finalize(psbt).inputs[0]

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
    assert finalize(psbt).inputs[0].final_script_sig == b""


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
    psbt.inputs[0].partial_sigs[_OTHER_PUB_KEY] = (
        dsa.sign_(msg_hash, _OTHER_PRV_KEY).serialize() + b"\x01"
    )

    err_msg = "2 signatures for a single-key input"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)


# issue 305: the empty push BIP147 asks for is the script's, not the
# signatures'


def _multisig_psbt(
    threshold: int, kind: str, signers: int | None = None
) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input threshold-of-2 psbt, signed and not finalized.

    `_single_key_psbt` one key further, and the four kinds are the four
    places a multisig script can sit: the script_pub_key of a bare
    multisig, the redeem script of a p2sh, the witness script of a p2wsh,
    and the witness script of a p2sh-p2wsh, which is the only one the
    redeem script does not name.

    The signatures go in the order the script holds the keys, which
    `lexicographic_sorting=False` makes the order given here:
    OP_CHECKMULTISIG never goes back, so a witness ordered otherwise is
    one the engine refuses whatever the dummy.

    `signers` is how many of the two sign, and defaults to the threshold,
    which is the psbt a coordinator stops collecting at. The other two
    counts are what a Finalizer has to answer for: everyone signing a
    1-of-2, which is more signatures than the script pops, and one
    signer of a 2-of-2, which is fewer.
    """
    keys = [_PUB_KEY, _OTHER_PUB_KEY]
    multisig = ScriptPubKey.p2ms(threshold, keys, lexicographic_sorting=False).script
    witness_script = multisig if "wsh" in kind else b""
    script_pub_key = {
        "multi": ScriptPubKey(multisig),
        "sh-multi": ScriptPubKey.p2sh(multisig),
        "wsh-multi": ScriptPubKey.p2wsh(multisig),
        "sh-wsh-multi": ScriptPubKey.p2sh(ScriptPubKey.p2wsh(multisig).script),
    }[kind]
    redeem_script = (
        multisig
        if kind == "sh-multi"
        else ScriptPubKey.p2wsh(multisig).script
        if kind == "sh-wsh-multi"
        else b""
    )

    prev_out = TxOut(100_000, script_pub_key)
    tx, prev_tx = _spending_tx(prev_out)

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].redeem_script = redeem_script
    psbt.inputs[0].witness_script = witness_script
    if witness_script:
        psbt.inputs[0].witness_utxo = prev_out
        msg_hash = sig_hash.segwit_v0(multisig, tx, 0, 1, prev_out.value)
    else:
        psbt.inputs[0].non_witness_utxo = prev_tx
        # the script being spent, which for a p2sh input is its redeem
        # script and for a bare multisig the script_pub_key: the same
        # bytes either way here
        msg_hash = sig_hash.legacy(multisig, tx, 0, 1)
    prv_keys = [_PRV_KEY, _OTHER_PRV_KEY][: threshold if signers is None else signers]
    psbt.inputs[0].partial_sigs = {
        pub_keyinfo_from_prv_key(prv_key)[0]: dsa.sign_(msg_hash, prv_key).serialize()
        + b"\x01"
        for prv_key in prv_keys
    }
    return psbt, [prev_out]


@pytest.mark.parametrize("kind", ["multi", "sh-multi", "wsh-multi", "sh-wsh-multi"])
@pytest.mark.parametrize("threshold", [1, 2])
def test_a_multisig_input_is_spent_with_the_element_the_script_pops(
    threshold: int, kind: str
) -> None:
    """OP_CHECKMULTISIG pops one element more than it reads (issue #305).

    Whatever the threshold: BIP147 is the rule that the extra element be
    empty, not the rule that it be there. Counting the signatures to
    decide, as the Finalizer did, is right for every threshold but a
    1-of-n, where one signature is a full satisfaction and the element is
    popped all the same -- and a witness one element short is what the
    engine here refuses.

    The 2-of-2 cases are what every psbt vector already covered, and they
    are the control: the count and the script agree there, so what the
    fix must not do is change them.
    """
    psbt, prev_outs = _multisig_psbt(threshold, kind)
    psbt_in = psbt.inputs[0]
    sigs = list(psbt_in.partial_sigs.values())
    redeem_script = [psbt_in.redeem_script] if psbt_in.redeem_script else []
    witness_script = psbt_in.witness_script

    finalized = finalize(psbt)
    verify_transaction(prev_outs, extract_tx(finalized, check_validity=False))

    final = finalized.inputs[0]
    if witness_script:
        assert final.final_script_witness.stack == (b"", *sigs, witness_script)
        assert final.final_script_sig == serialize([*redeem_script])
    else:
        assert final.final_script_sig == serialize([b"", *sigs, *redeem_script])
        assert not final.final_script_witness


def test_the_dummy_is_the_multisig_script_and_not_a_second_signature() -> None:
    """A p2pk input holding two signatures gets no empty push (issue #305).

    Two signatures for a script that checks one is caller error, the way
    `_single_key` refuses the same thing for p2pkh and p2wpkh, and the
    count gave that error a BIP147 dummy on top of it. Reading the script
    answers it: a p2pk is not a p2ms, so nothing is pushed and the
    script_sig is the two signatures the caller supplied.

    Both signatures are real, over the same sig_hash: the Finalizer
    verifies every partial signature before building anything.
    """
    p2pk = serialize([_PUB_KEY, "OP_CHECKSIG"])
    prev_out = TxOut(100_000, ScriptPubKey(p2pk))
    tx, prev_tx = _spending_tx(prev_out)
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    msg_hash = sig_hash.legacy(p2pk, tx, 0, 1)
    sigs = {
        pub_keyinfo_from_prv_key(prv_key)[0]: dsa.sign_(msg_hash, prv_key).serialize()
        + b"\x01"
        for prv_key in (_PRV_KEY, _OTHER_PRV_KEY)
    }
    psbt.inputs[0].partial_sigs = sigs

    final_script_sig = finalize(psbt).inputs[0].final_script_sig
    assert final_script_sig == serialize([*sigs.values()])


def test_an_input_that_says_no_script_is_left_with_the_count() -> None:
    """No script is no answer, and the count is the only evidence (issue #305).

    A bare multisig needs no script of its own to be finalized, so it
    reaches the Finalizer with the utxo missing the way any input whose
    sig_hash is not computable does -- and there `is_p2ms` has nothing to
    read where the number of signatures still says something. Two
    signatures are a multisig in every case but the caller error the test
    above names, so the empty push stays.
    """
    psbt, _ = _multisig_psbt(2, "multi")
    sigs = list(psbt.inputs[0].partial_sigs.values())
    psbt.inputs[0].non_witness_utxo = None

    final = finalize(psbt).inputs[0]
    assert final.final_script_sig == serialize([b"", *sigs])


def _spent_with(
    psbt_in: PsbtIn, sigs: tuple[bytes, ...]
) -> tuple[bytes, tuple[bytes, ...]]:
    """Return the script_sig and witness stack a multisig input spends with.

    The shape the test above asserts, as the expectation of the tests
    below, which vary the signatures rather than the kind: BIP147's empty
    element, the signatures, and the script the spend names -- the
    witness script in the witness of a p2wsh, the redeem script last in
    the script_sig of everything else.

    The input has to be the one before `finalize`, which clears both
    scripts.
    """
    redeem_script = [psbt_in.redeem_script] if psbt_in.redeem_script else []
    if psbt_in.witness_script:
        return serialize(redeem_script), (b"", *sigs, psbt_in.witness_script)
    return serialize([b"", *sigs, *redeem_script]), ()


@pytest.mark.parametrize("kind", ["multi", "sh-multi", "wsh-multi", "sh-wsh-multi"])
def test_a_multisig_input_is_spent_in_the_order_the_script_lists_its_keys(
    kind: str,
) -> None:
    """The Finalizer orders the signatures, and the dict does not (issue #431).

    OP_CHECKMULTISIG walks the keys forward and never goes back, so the
    signatures have to arrive in the order the script lists the keys they
    belong to. `partial_sigs` cannot supply it: a dict holds what it was
    given in the order it was given, and `combine` merges with an update,
    so for a coordinator it is the order the copies came back in.

    Reversing the map is that coordinator, and the engine is the
    authority on the result.
    """
    psbt, prev_outs = _multisig_psbt(2, kind)
    in_script_order = tuple(psbt.inputs[0].partial_sigs.values())
    expected = _spent_with(psbt.inputs[0], in_script_order)
    psbt.inputs[0].partial_sigs = dict(
        reversed(list(psbt.inputs[0].partial_sigs.items()))
    )

    finalized = finalize(psbt)
    verify_transaction(prev_outs, extract_tx(finalized, check_validity=False))
    final = finalized.inputs[0]
    assert (final.final_script_sig, final.final_script_witness.stack) == expected


@pytest.mark.parametrize("kind", ["multi", "sh-multi", "wsh-multi", "sh-wsh-multi"])
def test_a_multisig_input_pushes_the_threshold_and_not_every_signature(
    kind: str,
) -> None:
    """A 1-of-2 both participants signed spends with one (issue #431).

    OP_CHECKMULTISIG pops as many signatures as the script says and then
    one element more, which BIP147 requires to be empty. Pushing both
    signatures therefore puts the first of them where the dummy belongs,
    and the spend fails on the dummy rule with the real dummy left over.

    Which of the two is kept is the script's answer and not the map's:
    the first key it lists that has signed.
    """
    psbt, prev_outs = _multisig_psbt(1, kind, signers=2)
    first_in_script_order = next(iter(psbt.inputs[0].partial_sigs.values()))
    expected = _spent_with(psbt.inputs[0], (first_in_script_order,))

    finalized = finalize(psbt)
    verify_transaction(prev_outs, extract_tx(finalized, check_validity=False))
    final = finalized.inputs[0]
    assert (final.final_script_sig, final.final_script_witness.stack) == expected


def test_a_multisig_input_short_of_the_threshold_is_not_finalized() -> None:
    """One signature does not satisfy a 2-of-2 (issue #431).

    The Finalizer's own question -- whether the input has enough data to
    pass validation -- and for a multisig the script answers it. What
    used to be built instead was a script_sig one element short, which
    only the engine then refused.
    """
    psbt, _ = _multisig_psbt(2, "multi", signers=1)
    with pytest.raises(BTClibValueError, match="1 signatures for a 2-of-2 multisig"):
        finalize(psbt)


def test_a_signature_of_a_key_the_multisig_script_omits_is_dropped() -> None:
    """A signature is not evidence that its key belongs to this script.

    The Finalizer builds the spend the script asks for, and a key the
    script does not list has no place in it -- so the signature is left
    out rather than refused, an input being free to carry what some other
    branch would need. It is a real signature over this input's own
    sig_hash, which is what the Finalizer verifies every one of them
    against.
    """
    psbt, prev_outs = _multisig_psbt(1, "multi")
    signed = tuple(psbt.inputs[0].partial_sigs.values())
    expected = _spent_with(psbt.inputs[0], signed)
    msg_hash = sig_hash.legacy(prev_outs[0].script_pub_key.script, psbt.tx, 0, 1)
    stranger = _PRV_KEY + 2
    psbt.inputs[0].partial_sigs[pub_keyinfo_from_prv_key(stranger)[0]] = (
        dsa.sign_(msg_hash, stranger).serialize() + b"\x01"
    )

    finalized = finalize(psbt)
    verify_transaction(prev_outs, extract_tx(finalized, check_validity=False))
    final = finalized.inputs[0]
    assert (final.final_script_sig, final.final_script_witness.stack) == expected


def _one_input_finalized_each() -> tuple[Psbt, Psbt]:
    """Return the two psbts of two participants, one input finalized each."""
    finalized = finalize(Psbt.b64decode(TO_BE_FINALIZED))
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
    finalized = finalize(Psbt.b64decode(TO_BE_FINALIZED))
    first, second = _one_input_finalized_each()
    for psbts in ([first, second], list(_one_input_finalized_each())[::-1]):
        combined = combine(psbts)
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
    combined = combine([first, second])
    assert combined.inputs[1].final_script_witness == Witness([b"\x01"])


def test_combining_merges_every_field_a_map_holds() -> None:
    """The preimages, the taproot fields and the musig2 maps too (issue #432).

    "The resulting PSBT must contain all of the key-value pairs from each
    of the PSBTs", and the list of fields the Combiner walked was the
    BIP174 one: everything BIP371 and BIP373 added to an input or an
    output was dropped, silently and both ways round.

    One field of each kind here -- a map, a single value, and the
    positional list a taproot tree is -- with the two psbts carrying
    disjoint halves so that the union is the whole.
    """
    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = deepcopy(first)
    internal_key = bytes.fromhex("aa" * 32)
    leaf_hash = bytes.fromhex("bb" * 32)

    first.inputs[0].sha256_preimages = {sha256(b"one"): b"one"}
    second.inputs[0].sha256_preimages = {sha256(b"two"): b"two"}
    first.inputs[0].taproot_internal_key = internal_key
    second.inputs[0].taproot_script_spend_signatures = {
        internal_key + leaf_hash: bytes.fromhex("cc" * 64)
    }
    second.outputs[0].taproot_tree = [(0, 192, b"\x51")]

    combined = combine([first, second])
    assert combined.inputs[0].sha256_preimages == {
        sha256(b"one"): b"one",
        sha256(b"two"): b"two",
    }
    assert combined.inputs[0].taproot_internal_key == internal_key
    assert combined.inputs[0].taproot_script_spend_signatures
    assert combined.outputs[0].taproot_tree == [(0, 192, b"\x51")]


def test_combining_refuses_two_participant_lists_for_one_aggregate_key() -> None:
    """A merge that would write a key's participants into something else.

    An aggregate key is computed from its list, so two different lists
    under one key are not the conflict BIP174 lets a Combiner pick from:
    one of them says that key aggregates something it does not, and no
    reader could tell which. The same list twice is no conflict at all.
    """
    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = deepcopy(first)
    # real points, `Psbt.assert_valid` asking that of a participant list:
    # what this test is about is two lists under one key, not what the
    # aggregation of either comes to
    aggregate_pub_key = bytes.fromhex(
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    )
    participants = [
        bytes.fromhex(
            "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00"
        ),
        bytes.fromhex(
            "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c"
        ),
    ]

    first.inputs[0].musig2_participant_pub_keys = {aggregate_pub_key: participants}
    second.inputs[0].musig2_participant_pub_keys = {
        aggregate_pub_key: list(participants)
    }
    combined = combine([first, second])
    assert combined.inputs[0].musig2_participant_pub_keys[aggregate_pub_key] == (
        participants
    )

    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = deepcopy(first)
    first.outputs[0].musig2_participant_pub_keys = {aggregate_pub_key: participants}
    second.outputs[0].musig2_participant_pub_keys = {
        aggregate_pub_key: list(reversed(participants))
    }
    err_msg = "mismatched musig2 participants for aggregate key "
    with pytest.raises(BTClibValueError, match=err_msg):
        combine([first, second])


def test_combining_leaves_every_psbt_it_was_given_alone() -> None:
    """The Combiner returns a copy, and merged into none of its arguments.

    Without it the returned psbt *is* `psbts[0]`: a coordinator that
    keeps its own copy to check the next signer's answer against holds
    the copy the last answer was merged into, so the check would pass
    whatever came back.
    """
    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = deepcopy(first)
    first.inputs[0].sha256_preimages = {sha256(b"one"): b"one"}
    second.inputs[0].sha256_preimages = {sha256(b"two"): b"two"}
    first_before, second_before = deepcopy(first), deepcopy(second)

    combined = combine([first, second])

    assert combined is not first
    assert first == first_before
    assert second == second_before


def test_the_combined_psbt_shares_no_object_with_what_was_combined() -> None:
    """Not only psbts[0]: `_combine_field` assigns what it takes.

    A field taken from a later psbt is that psbt's own object -- a
    witness_utxo, a preimage map -- so mutating the combined psbt would
    reach into an argument the caller still holds. Mutation is the test
    because identity is what is being asserted, and `==` cannot see it.
    """
    first = Psbt.b64decode(TO_BE_FINALIZED)
    second = deepcopy(first)
    # a map only `second` carries, so the combined psbt takes second's
    second.inputs[0].sha256_preimages = {sha256(b"two"): b"two"}
    first.inputs[0].sha256_preimages = {}

    combined = combine([first, second])
    assert combined.inputs[0].sha256_preimages == {sha256(b"two"): b"two"}

    combined.inputs[0].sha256_preimages.clear()
    combined.inputs[0].partial_sigs.clear()
    assert second.inputs[0].sha256_preimages == {sha256(b"two"): b"two"}
    assert first.inputs[0].partial_sigs


def test_joining_leaves_every_psbt_it_was_given_alone() -> None:
    """The joined psbt shares no input or output with what was joined.

    `join` concatenates the input and output maps of every psbt, so
    without a copy the joined psbt's inputs *are* theirs, and an Updater
    filling one in afterwards fills in a psbt somebody else holds.

    Two psbts of different kinds, which is what `join` needs: they spend
    different outputs, so they have different outpoints, and one
    transaction cannot spend one output twice -- two copies of one psbt
    are refused as "common inputs".
    """
    first, _ = _single_key_psbt("p2wpkh")
    second, _ = _single_key_psbt("p2wsh")
    first_before, second_before = deepcopy(first), deepcopy(second)

    joined = join([first, second], False, False, False, False)

    assert first == first_before
    assert second == second_before
    given = [*first.inputs, *second.inputs]
    assert all(inp is not joined_inp for inp in given for joined_inp in joined.inputs)

    joined.inputs[0].witness_script = b"\x51"
    joined.outputs[0].redeem_script = b"\x51"
    joined.inputs[0].partial_sigs.clear()
    assert first == first_before
    assert second == second_before


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
    finalize(psbt)

    psbt.inputs[0].sig_hash_type = 3
    err_msg = "mismatched sig_hash type: 0x1 vs 0x3"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # 0 is SIGHASH_DEFAULT, a type an input may ask for and no ECDSA
    # signature carries: what BIP174 tests is the field's presence, so a
    # falsy value is not an absent field
    psbt.inputs[0].sig_hash_type = 0
    err_msg = "mismatched sig_hash type: 0x1 vs 0x0"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # no field, no check: the signatures say which type they commit to
    psbt.inputs[0].sig_hash_type = None
    finalize(psbt)


def test_finalize_checks_a_partial_signature_against_its_pub_key() -> None:
    """A signature filed under a key that did not make it is refused.

    PsbtIn.assert_valid parses the DER and can do no more: what the
    signature commits to is the whole transaction, which a per-field
    validator has not got. The Finalizer has it, and BIP174 has it decide
    "if the input has enough data to pass validation".
    """
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    finalize(psbt)

    # the two signatures of the 2-of-2 swapped between its two keys: both
    # are DER, both keys are on the curve, and neither pair belongs
    # together
    keys = list(psbt.inputs[0].partial_sigs)
    sigs = list(psbt.inputs[0].partial_sigs.values())
    psbt.inputs[0].partial_sigs = {keys[0]: sigs[1], keys[1]: sigs[0]}
    err_msg = "invalid partial signature for pub_key "
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # and the same for the segwit input, whose hash is BIP143's
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    keys = list(psbt.inputs[1].partial_sigs)
    sigs = list(psbt.inputs[1].partial_sigs.values())
    psbt.inputs[1].partial_sigs = {keys[0]: sigs[1], keys[1]: sigs[0]}
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)


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

    psbt_in = finalize(psbt).inputs[0]
    assert psbt_in.final_script_sig == serialize([sig])
    assert not psbt_in.final_script_witness


def test_the_sig_hash_of_an_input_that_does_not_say_what_it_spends() -> None:
    """Four inputs whose hash is not computable, three finalized all the same.

    None out of `_sig_hash_from_psbt_in` is "the psbt does not say what
    is being signed", which is not evidence against the signature: the
    Finalizer leaves such an input alone rather than refusing it.

    The fourth is a p2tr input, and there the Finalizer does refuse: a
    taproot input is finalized from its taproot fields, so an ECDSA
    partial signature beside a p2tr script_pub_key is not a spend of it
    -- and building one out of the partial signatures, as this used to,
    produced a script_sig BIP341 gives no meaning to.
    """
    # no utxo at all
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].non_witness_utxo = None
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    finalize(psbt)

    # p2sh with no redeem script: the script_pub_key names a hash, and
    # the script it hashes is what would be signed
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].redeem_script = b""
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    finalize(psbt)

    # p2wsh with no witness script, which is the BIP143 script code
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[1].witness_script = b""
    assert _sig_hash_from_psbt_in(psbt.inputs[1], psbt.tx, 1, 1) is None
    finalize(psbt)

    # a taproot output is spent with schnorr signatures, and they travel
    # in the taproot fields: an ECDSA partial signature beside a p2tr
    # script_pub_key is not a signature this hash would check
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(100000, ScriptPubKey("5120" + "aa" * 32))
    assert _sig_hash_from_psbt_in(psbt.inputs[0], psbt.tx, 0, 1) is None
    with pytest.raises(BTClibValueError, match="missing taproot signature"):
        finalize(psbt)


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
                assert dsa.verify_(msg_hash, pub_key, sig[:-1])
                checked += 1
    # a count, so that a loop that stops finding signatures is a failure
    # and not a green run over nothing
    assert checked == 3


def test_the_signer_signs_the_hash_the_finalizer_checks() -> None:
    """`ecdsa_sig_hash` is the public half of the Finalizer's own dispatch.

    Both halves of BIP174's valid psbts are covered by asking the two
    for the same input: whatever the private helper answers a Finalizer,
    the Signer is told, and a signature made over one verifies under the
    other. The vectors' own signatures are what
    `test_the_sig_hash_of_every_input_kind_a_partial_signature_signs`
    checks that hash against.
    """
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    for vin_i, psbt_in in enumerate(psbt.inputs):
        for sig in psbt_in.partial_sigs.values():
            assert ecdsa_sig_hash(psbt, vin_i, hash_type=sig[-1]) == (
                _sig_hash_from_psbt_in(psbt_in, psbt.tx, vin_i, sig[-1])
            )


def test_the_signer_is_told_the_hash_type_the_input_asks_for() -> None:
    """The default is the input's field, and SIGHASH_ALL where it has none.

    An input that asks for a type is an input whose signatures must
    commit to it, which is what the Finalizer refuses them for; a Signer
    reading the psbt therefore needs no argument in the ordinary case.
    SIGHASH_ALL is the fallback because it is what a signature with
    nothing said about it means.
    """
    psbt, _ = _single_key_psbt("p2wpkh")
    assert psbt.inputs[0].sig_hash_type is None
    assert ecdsa_sig_hash(psbt, 0) == ecdsa_sig_hash(psbt, 0, hash_type=1)

    psbt.inputs[0].sig_hash_type = 3
    assert ecdsa_sig_hash(psbt, 0) == ecdsa_sig_hash(psbt, 0, hash_type=3)
    assert ecdsa_sig_hash(psbt, 0) != ecdsa_sig_hash(psbt, 0, hash_type=1)


def test_what_a_signer_cannot_be_given_a_hash_for() -> None:
    """Four inputs a Signer is stopped on, where the Finalizer is not.

    None out of the private helper is "the psbt does not say what is
    being signed", and a Finalizer checking a signature it was handed
    learns nothing from that. A Signer about to make one has to stop, so
    the same three cases raise here -- and a taproot input is named for
    what it is rather than reported as silence, its message being
    `taproot_sig_hash`'s.

    SIGHASH_DEFAULT is the fourth, and it is not about the input: 0 is a
    taproot type that no ECDSA signature carries, so a psbt asking for it
    is one the Finalizer could not accept a partial signature for either.
    """
    psbt = Psbt.b64decode(TO_BE_FINALIZED)
    err_msg = "input 0 does not say what is being signed"

    no_utxo = deepcopy(psbt)
    no_utxo.inputs[0].non_witness_utxo = None
    with pytest.raises(BTClibValueError, match=err_msg):
        ecdsa_sig_hash(no_utxo, 0)

    no_redeem_script = deepcopy(psbt)
    no_redeem_script.inputs[0].redeem_script = b""
    with pytest.raises(BTClibValueError, match=err_msg):
        ecdsa_sig_hash(no_redeem_script, 0)

    no_witness_script = deepcopy(psbt)
    no_witness_script.inputs[1].witness_script = b""
    with pytest.raises(BTClibValueError, match="input 1 does not say"):
        ecdsa_sig_hash(no_witness_script, 1)

    taproot_input = deepcopy(psbt)
    taproot_input.inputs[0].non_witness_utxo = None
    taproot_input.inputs[0].witness_utxo = TxOut(
        100000, ScriptPubKey("5120" + "aa" * 32)
    )
    with pytest.raises(BTClibValueError, match="input 0 is taproot"):
        ecdsa_sig_hash(taproot_input, 0)

    with pytest.raises(BTClibValueError, match="SIGHASH_DEFAULT is not an ECDSA"):
        ecdsa_sig_hash(psbt, 0, hash_type=0)
    asking_for_default = deepcopy(psbt)
    asking_for_default.inputs[0].sig_hash_type = 0
    with pytest.raises(BTClibValueError, match="SIGHASH_DEFAULT is not an ECDSA"):
        ecdsa_sig_hash(asking_for_default, 0)

    with pytest.raises(BTClibValueError, match="invalid sig_hash type: 0x4"):
        ecdsa_sig_hash(psbt, 0, hash_type=4)


def test_a_witness_utxo_alone_signs_no_non_witness_spend() -> None:
    """No role reads a legacy sig_hash out of a witness utxo.

    BIP174 puts `PSBT_IN_WITNESS_UTXO` on segwit inputs alone, and its
    Signer checks a non-witness utxo against the outpoint it claims to
    be -- a line it has none of for the other field, whose script_pub_key
    is therefore unvouched for. Bitcoin Core stops for the same reason,
    `require_witness_sig`. Signing, verifying an answer and finalizing
    all raise, rather than the Signer alone: skipping the check is what
    would finalize the input whose signature cannot be believed.
    """
    signed, _ = _single_key_psbt("p2pkh")
    prev_tx = signed.inputs[0].non_witness_utxo
    assert prev_tx is not None
    prev_out = prev_tx.vout[0]

    unvouched = deepcopy(signed)
    unvouched.inputs[0].non_witness_utxo = None
    unvouched.inputs[0].witness_utxo = prev_out

    err_msg = "input 0: a witness utxo alone does not say what a non-witness"
    with pytest.raises(BTClibValueError, match=err_msg):
        ecdsa_sig_hash(unvouched, 0)
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(unvouched)
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(_stripped_of_signatures(unvouched), unvouched)

    # the same psbt is refused before that, where a caller runs the check
    # BIP174 wrote for the Updater's output
    with pytest.raises(BTClibValueError, match="script type not in"):
        unvouched.assert_signable()

    # and the very same input, with the transaction it is spent against,
    # signs and finalizes
    assert ecdsa_sig_hash(signed, 0) == sig_hash.legacy(
        prev_out.script_pub_key.script, signed.tx, 0, 1
    )
    assert finalize(signed).inputs[0].final_script_sig


def _stripped_of_signatures(psbt: Psbt) -> Psbt:
    """Return the psbt as it was before a Signer answered."""
    request = deepcopy(psbt)
    for psbt_in in request.inputs:
        psbt_in.partial_sigs = {}
    return request


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


def _taproot_signed(description: str) -> Psbt:
    """Aggregate a BIP373 psbt's MuSig2 session into a taproot signature.

    Which is the only way this tree produces a taproot signature: BIP371's
    own valid psbts carry signatures beside utxos that do not commit to
    the transaction they sit in, so they cannot be finalized -- the hash a
    taproot signature checks against covers every input.
    """
    psbt = Psbt.b64decode(
        next(
            test_vector["encoded psbt"]
            for test_vector in load("psbt", "_data", "bip373_test_vectors.json")[
                "valid psbts"
            ]
            if description in test_vector["description"]
        )
    )
    psbt_in = psbt.inputs[0]
    aggregate_pub_key = next(iter(psbt_in.musig2_participant_pub_keys))
    leaf_hash = next(iter(psbt_in.musig2_partial_sigs))[66:]
    psbt_musig2.partial_sigs_agg(psbt, 0, aggregate_pub_key, leaf_hash=leaf_hash)
    return psbt


def test_a_taproot_input_is_finalized_from_its_own_fields() -> None:
    """The key path and the script path, and the witness each is spent with.

    BIP341: the witness of a key path spend is the signature alone, and of
    a script path spend the signature, the leaf script and the control
    block. The script_sig is empty either way, a witness v1 program having
    nothing to put in it.
    """
    psbt = finalize(
        _taproot_signed("output key is a MuSig2 Aggregate Pubkey, with all partial")
    )
    assert not psbt.inputs[0].final_script_sig
    assert psbt.inputs[0].final_script_witness.stack == (
        _taproot_signed("output key is a MuSig2 Aggregate Pubkey, with all partial")
        .inputs[0]
        .taproot_key_spend_signature,
    )

    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    key_data, sig = next(iter(psbt.inputs[0].taproot_script_spend_signatures.items()))
    script, control_block = leaf_script(psbt.inputs[0], key_data[32:])
    finalized = finalize(psbt)
    assert not finalized.inputs[0].final_script_sig
    assert finalized.inputs[0].final_script_witness.stack == (
        sig,
        script,
        control_block,
    )


def _bip371_psbt(description: str) -> Psbt:
    """Return the valid BIP371 psbt whose description contains this."""
    return Psbt.b64decode(
        next(
            test_vector["encoded psbt"]
            for test_vector in load("psbt", "_data", "bip371_test_vectors.json")[
                "valid psbts"
            ]
            if description in test_vector["description"]
        )
    )


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip371_test_vectors.json", "valid psbts")
)
def test_bip371s_own_psbts_are_signable(test_vector: dict[str, str]) -> None:
    """Every valid BIP371 psbt passes the Signer's pre-flight (issue #435).

    None of them did: a p2tr input carrying a witness_utxo was refused
    as "script type not in ('p2wpkh', 'p2wsh')", the rule BIP174 wrote
    for a witness utxo beside a legacy input, applied to a witness kind
    that did not exist when it was written.

    They are the positive case for what replaces it, and they cover both
    ways a taproot output is spent: the key path ones carry an internal
    key and no merkle root, the script path ones a root and three leaf
    scripts with their control blocks.
    """
    Psbt.b64decode(test_vector["encoded psbt"]).assert_signable()


def test_what_a_taproot_input_cannot_be_signed_from() -> None:
    """Every way the taproot fields of an input fail to reach its output key.

    What the redeem and witness script checks are for the other kinds:
    the psbt is held to the output being spent, so a field that does not
    reach it is a field a Signer must not act on.
    """
    key_path = "one P2TR key only input with internal key"
    script_path = "one P2TR script path only input with dummy internal key"

    # an internal key that tweaks to some other output key
    psbt = _bip371_psbt(key_path)
    psbt.inputs[0].taproot_internal_key = _PUB_KEY[1:]
    with pytest.raises(BTClibValueError, match="is not the output key being spent"):
        psbt.assert_signable()

    # the right internal key and a merkle root the output does not
    # commit to: a key path spend is the tweak by no root at all
    psbt = _bip371_psbt(key_path)
    psbt.inputs[0].taproot_merkle_root = b"\x01" * 32
    with pytest.raises(BTClibValueError, match="is not the output key being spent"):
        psbt.assert_signable()

    # a leaf script the control block beside it does not prove
    psbt = _bip371_psbt(script_path)
    control_block, (script, leaf_version) = next(
        iter(psbt.inputs[0].taproot_leaf_scripts.items())
    )
    psbt.inputs[0].taproot_leaf_scripts[control_block] = (
        script + b"\x51",
        leaf_version,
    )
    with pytest.raises(BTClibValueError, match="does not prove leaf script"):
        psbt.assert_signable()

    # a leaf version that is not the one the control block declares:
    # the proof is then of a leaf `leaf_script` will not find
    psbt = _bip371_psbt(script_path)
    psbt.inputs[0].taproot_leaf_scripts[control_block] = (script, 0xC2)
    with pytest.raises(BTClibValueError, match="is not the control block's"):
        psbt.assert_signable()


def test_a_taproot_input_is_checked_whichever_utxo_it_carries() -> None:
    """The non_witness_utxo path used to be the one that checked nothing.

    A taproot input carrying the whole previous transaction took the
    branch that returns the payload without typing it, so the two checks
    below never ran and every taproot field was signable. The output
    being spent is the same output either way, which is what `_prev_out`
    answers and what this asks it for.

    The script_pub_key is built by `ScriptPubKey.p2tr`, which tweaks by
    an empty *tree*, and the check tweaks by an empty *root*: that the
    psbt is signable at all is the two spellings agreeing on this key.
    """
    internal_key = _PUB_KEY[1:]
    prev_out = TxOut(100_000, ScriptPubKey.p2tr(_PUB_KEY))
    tx, prev_tx = _spending_tx(prev_out)
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    psbt.inputs[0].taproot_internal_key = internal_key
    psbt.assert_signable()

    psbt.inputs[0].taproot_internal_key = _OTHER_PUB_KEY[1:]
    with pytest.raises(BTClibValueError, match="is not the output key being spent"):
        psbt.assert_signable()


def test_what_a_taproot_input_cannot_be_finalized_from() -> None:
    """Every way the taproot fields of an input fail to be a spend of it."""
    # a signature of the wrong sig_hash type: the input asks for one and
    # the signature commits to another
    psbt = _taproot_signed("output key is a MuSig2 Aggregate Pubkey, with all partial")
    psbt.inputs[0].sig_hash_type = 1
    err_msg = "invalid taproot key path signature sig_hash type"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # a signature of the right shape that signs something else
    psbt = _taproot_signed("output key is a MuSig2 Aggregate Pubkey, with all partial")
    psbt.inputs[0].taproot_key_spend_signature = b"\x01" * 64
    err_msg = "invalid taproot key path signature for output key"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # no utxo, which is not one input's problem: a taproot signature
    # commits to the amount and script of every input, so the hash cannot
    # be computed for any of them. Not through the Finalizer, which
    # without a utxo cannot tell the input is taproot at all and answers
    # "missing signatures" as it does for every input that does not say
    # what it spends
    psbt = _taproot_signed("output key is a MuSig2 Aggregate Pubkey, with all partial")
    psbt.inputs[0].witness_utxo = None
    with pytest.raises(BTClibValueError, match="no utxo for input 0"):
        prevouts(psbt)
    with pytest.raises(BTClibValueError, match="missing signatures"):
        finalize(psbt)

    # two script path signatures, i.e. two spends of two leaves
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    key_data, sig = next(iter(psbt.inputs[0].taproot_script_spend_signatures.items()))
    psbt.inputs[0].taproot_script_spend_signatures[b"\x01" * 64] = sig
    err_msg = "2 taproot script path signatures"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # one, under a tapleaf hash the input carries no script for
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    psbt.inputs[0].taproot_script_spend_signatures = {key_data[:32] + b"\x02" * 32: sig}
    with pytest.raises(BTClibValueError, match="no leaf script for tapleaf hash"):
        finalize(psbt)

    # a leaf whose script is not a single key and OP_CHECKSIG: what else
    # goes on the stack is not something the psbt says
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    control_block = next(iter(psbt.inputs[0].taproot_leaf_scripts))
    psbt.inputs[0].taproot_leaf_scripts[control_block] = (b"\x51", 0xC0)
    with pytest.raises(BTClibValueError, match="no leaf script for tapleaf hash"):
        finalize(psbt)

    # the same, reached by its own hash: the leaf is the one signed for and
    # the script asks for more than a signature
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    control_block = next(iter(psbt.inputs[0].taproot_leaf_scripts))
    script = serialize(["OP_1"])
    psbt.inputs[0].taproot_leaf_scripts = {control_block: (script, 0xC0)}
    leaf_hash_ = tagged_hash(b"TapLeaf", b"\xc0" + var_bytes.serialize(script))
    psbt.inputs[0].taproot_script_spend_signatures = {key_data[:32] + leaf_hash_: sig}
    err_msg = "not a single key and OP_CHECKSIG"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # a signature filed under a key that is not the leaf's
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    psbt.inputs[0].taproot_script_spend_signatures = {b"\x03" * 32 + key_data[32:]: sig}
    err_msg = "which is not the key of leaf script"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)

    # and the leaf's own key, with a signature that signs something else
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    psbt.inputs[0].taproot_script_spend_signatures = {key_data: b"\x01" * 64}
    err_msg = "invalid taproot script path signature for key"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize(psbt)


# issue 439: sign() over a KeyManager


class _KeyManager:
    """A `KeyManager` test double: keys known by pub_key, or by origin.

    sign_calls counts every call that found a key, which is what the
    idempotency test checks: a key `sign` already has a signature for
    must never reach either method a second time.
    """

    def __init__(
        self,
        by_pub_key: dict[bytes, int] | None = None,
        by_origin: dict[str, int] | None = None,
    ) -> None:
        self.by_pub_key = dict(by_pub_key or {})
        self.by_origin = dict(by_origin or {})
        self.sign_calls = 0

    def _prv_key(self, pub_key: bytes, origin: BIP32KeyOrigin | None) -> int | None:
        if pub_key in self.by_pub_key:
            return self.by_pub_key[pub_key]
        if origin is not None:
            return self.by_origin.get(origin.description)
        return None

    def sign_ecdsa(
        self, pub_key: bytes, origin: BIP32KeyOrigin | None, msg_hash: bytes
    ) -> bytes | None:
        prv_key = self._prv_key(pub_key, origin)
        if prv_key is None:
            return None
        self.sign_calls += 1
        return dsa.sign_(msg_hash, prv_key).serialize()

    def sign_schnorr(
        self,
        pub_key: bytes,
        origin: BIP32KeyOrigin | None,
        msg_hash: bytes,
        merkle_root: bytes,
    ) -> bytes | None:
        prv_key = self._prv_key(pub_key, origin)
        if prv_key is None:
            return None
        self.sign_calls += 1
        tweaked = output_prvkey_from_merkle_root(prv_key, merkle_root)
        return ssa.sign_(msg_hash, tweaked).serialize()

    def sign_schnorr_script_path(
        self,
        pub_key: bytes,
        origin: BIP32KeyOrigin | None,
        msg_hash: bytes,
        leaf_hash: bytes,
    ) -> bytes | None:
        # no tweak, which is the whole difference from sign_schnorr
        # above: a leaf key signs as itself, and leaf_hash is context
        # this double has no policy to apply it to
        prv_key = self._prv_key(pub_key, origin)
        if prv_key is None:
            return None
        self.sign_calls += 1
        return ssa.sign_(msg_hash, prv_key).serialize()


def _unsigned_multisig_psbt() -> Psbt:
    """Build a one-input, unsigned native p2wsh 2-of-2 psbt.

    Both cosigners' keys are in hd_key_paths, as BIP174 has the Updater
    write them; the two origins only need to be distinct from each
    other, their fingerprint and path not being what this test is about.
    """
    witness_script = serialize(
        ["OP_2", _PUB_KEY, _OTHER_PUB_KEY, "OP_2", "OP_CHECKMULTISIG"]
    )
    script_pub_key = ScriptPubKey.p2wsh(witness_script)
    prev_out = TxOut(100_000, script_pub_key)
    tx, _ = _spending_tx(prev_out)

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out
    psbt.inputs[0].witness_script = witness_script
    psbt.inputs[0].hd_key_paths = {
        _PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0"),
        _OTHER_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/1"),
    }
    return psbt


_TAPROOT_PRV_KEY = _PRV_KEY + 2
_TAPROOT_PUB_KEY = pub_keyinfo_from_prv_key(_TAPROOT_PRV_KEY)[0]
# x-only, dropping the parity byte compressed carries and x-only never
# does: PSBT_IN_TAP_INTERNAL_KEY is 32 bytes, and so is a KeyManager's
# pub_key for a schnorr candidate
_TAPROOT_INTERNAL_KEY = _TAPROOT_PUB_KEY[1:]


def _taproot_key_path_psbt(
    script_tree: TaprootScriptTree | None = None,
) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input, unsigned p2tr psbt spendable by the key path.

    script_tree only produces the merkle root the output key is tweaked
    by: the psbt itself carries the root and not the tree, as BIP371
    has it, and `sign` is never told the tree either.
    """
    script_pub_key = ScriptPubKey.p2tr(_TAPROOT_PUB_KEY, script_tree)
    prev_out = TxOut(100_000, script_pub_key)
    tx, _ = _spending_tx(prev_out)

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out
    psbt.inputs[0].taproot_internal_key = _TAPROOT_INTERNAL_KEY
    psbt.inputs[0].taproot_merkle_root = (
        tree_helper(script_tree)[1] if script_tree else b""
    )
    return psbt, [prev_out]


_LEAF_PRV_KEY = _PRV_KEY + 3
_LEAF_KEY = pub_keyinfo_from_prv_key(_LEAF_PRV_KEY)[0][1:]
# the leaf spent below, and the one shape a Finalizer can build a witness
# for: `single_leaf_key`'s <32-byte key> OP_CHECKSIG
_LEAF_TREE: TaprootScriptTree = [(0xC0, [_LEAF_KEY, "OP_CHECKSIG"])]
_LEAF_SCRIPT = taproot.serialize([_LEAF_KEY, "OP_CHECKSIG"])
_LEAF_HASH = taproot.leaf_hash(0xC0, _LEAF_SCRIPT)


def _taproot_script_path_psbt(
    *, with_leaf_script: bool = True
) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input, unsigned p2tr psbt spendable by a single leaf.

    The Updater's half of a script path: the leaf script filed under the
    control block that proves it, and the leaf's key filed under the
    tapleaf hash it appears in, which is BIP371's way of saying that this
    key signs for that leaf. The internal key is there too, and holds no
    key any test here signs the key path with -- a script path spend of
    an output that could also be spent by its owner is the ordinary
    shape, and the one that says `sign` asks for both.

    with_leaf_script drops `PSBT_IN_TAP_LEAF_SCRIPT` alone, leaving the
    derivation naming a leaf the psbt does not carry the script of.
    """
    script_pub_key = ScriptPubKey.p2tr(_TAPROOT_PUB_KEY, _LEAF_TREE)
    prev_out = TxOut(100_000, script_pub_key)
    tx, _ = _spending_tx(prev_out)
    control_block = input_script_sig(_TAPROOT_PUB_KEY, _LEAF_TREE, 0)[1]

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out
    psbt.inputs[0].taproot_internal_key = _TAPROOT_INTERNAL_KEY
    psbt.inputs[0].taproot_merkle_root = tree_helper(_LEAF_TREE)[1]
    if with_leaf_script:
        psbt.inputs[0].taproot_leaf_scripts[control_block] = (_LEAF_SCRIPT, 0xC0)
    psbt.inputs[0].taproot_hd_key_paths = {
        _LEAF_KEY: ([_LEAF_HASH], BIP32KeyOrigin(b"\x00" * 4, "m/1"))
    }
    return psbt, [prev_out]


@pytest.mark.parametrize(
    "kind", ["p2pkh", "p2wpkh", "p2wsh", "p2sh-p2wpkh", "p2sh-p2wsh"]
)
def test_sign_writes_the_signature_a_key_manager_makes(kind: str) -> None:
    """sign() reaches the same partial signature `_single_key_psbt` has.

    hd_key_paths is the only difference between the two psbts: the one
    built here carries no signature yet, and a BIP32KeyOrigin under
    _PUB_KEY is what makes it the one candidate `sign` finds.
    """
    signed, prevouts = _single_key_psbt(kind)
    expected_sig = signed.inputs[0].partial_sigs[_PUB_KEY]

    psbt = deepcopy(signed)
    psbt.inputs[0].partial_sigs = {}
    psbt.inputs[0].hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0")}

    result, signed_vins = sign(psbt, _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY}))

    assert signed_vins == [0]
    assert result.inputs[0].partial_sigs == {_PUB_KEY: expected_sig}
    verify_transaction(prevouts, extract_tx(finalize(result), check_validity=False))


def test_sign_falls_back_to_the_origin_the_key_manager_recognizes() -> None:
    """A manager that misses the exact key still answers by its origin.

    Decision #1 of issue #439: both travel on every call, key first and
    origin as the fallback a watch-only-shaped manager needs -- one that
    knows a fingerprint and path rather than every child key derived
    from it.
    """
    signed, _ = _single_key_psbt("p2wpkh")
    expected_sig = signed.inputs[0].partial_sigs[_PUB_KEY]
    origin = BIP32KeyOrigin(b"\x01\x02\x03\x04", "m/84h/0h/0h/0/0")

    psbt = deepcopy(signed)
    psbt.inputs[0].partial_sigs = {}
    psbt.inputs[0].hd_key_paths = {_PUB_KEY: origin}

    key_manager = _KeyManager(by_origin={origin.description: _PRV_KEY})
    result, signed_vins = sign(psbt, key_manager)

    assert signed_vins == [0]
    assert result.inputs[0].partial_sigs == {_PUB_KEY: expected_sig}


def test_sign_skips_a_key_the_key_manager_does_not_hold() -> None:
    """One signer of a 2-of-2 answers for its own key, and stops there.

    Decision #3 of issue #439: None is not an error, so the other
    cosigner's key is left for its own turn rather than raised on.
    """
    result, signed_vins = sign(
        _unsigned_multisig_psbt(), _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY})
    )

    assert signed_vins == [0]
    assert list(result.inputs[0].partial_sigs) == [_PUB_KEY]


def test_sign_never_asks_twice_for_a_key_already_signed() -> None:
    """A second sign() over the first result asks key_manager nothing new."""
    key_manager = _KeyManager(
        by_pub_key={_PUB_KEY: _PRV_KEY, _OTHER_PUB_KEY: _OTHER_PRV_KEY}
    )

    once, signed_vins = sign(_unsigned_multisig_psbt(), key_manager)
    assert signed_vins == [0]
    assert key_manager.sign_calls == 2

    twice, signed_vins_again = sign(once, key_manager)
    assert signed_vins_again == []
    assert key_manager.sign_calls == 2
    assert twice.inputs[0].partial_sigs == once.inputs[0].partial_sigs


def test_sign_returns_a_copy() -> None:
    """The psbt handed to sign() is untouched, as finalize's own is."""
    psbt = _unsigned_multisig_psbt()
    sign(psbt, _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY}))
    assert psbt.inputs[0].partial_sigs == {}


def test_sign_writes_the_taproot_key_path_signature() -> None:
    """A key-path-only p2tr input, signed and then finalized."""
    psbt, prevouts = _taproot_key_path_psbt()
    key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})

    result, signed_vins = sign(psbt, key_manager)

    assert signed_vins == [0]
    verify_transaction(prevouts, extract_tx(finalize(result), check_validity=False))


def test_sign_tweaks_the_taproot_key_by_the_merkle_root() -> None:
    """The key path signature of an output that also carries script leaves.

    key_manager is handed only psbt_in.taproot_merkle_root, never the
    tree that produced it -- BIP371's own shape -- and still has to
    produce a signature of the tweaked output key the engine accepts.
    """
    script_tree: TaprootScriptTree = [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]]
    psbt, prevouts = _taproot_key_path_psbt(script_tree)
    key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})

    result, signed_vins = sign(psbt, key_manager)

    assert signed_vins == [0]
    verify_transaction(prevouts, extract_tx(finalize(result), check_validity=False))


def test_sign_skips_a_taproot_key_the_key_manager_does_not_hold() -> None:
    """None from sign_schnorr leaves the input without a signature."""
    psbt, _ = _taproot_key_path_psbt()
    result, signed_vins = sign(psbt, _KeyManager())

    assert signed_vins == []
    assert not result.inputs[0].taproot_key_spend_signature


def test_sign_leaves_a_taproot_input_already_signed_alone() -> None:
    """A second sign() over the first result asks key_manager nothing new.

    The taproot counterpart of
    `test_sign_never_asks_twice_for_a_key_already_signed`: the one
    candidate is the internal key, and taproot_key_spend_signature
    already holding a signature is what says there is nothing to ask
    for.
    """
    psbt, _ = _taproot_key_path_psbt()
    key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})

    once, signed_vins = sign(psbt, key_manager)
    assert signed_vins == [0]
    assert key_manager.sign_calls == 1

    twice, signed_vins_again = sign(once, key_manager)
    assert signed_vins_again == []
    assert key_manager.sign_calls == 1
    assert (
        twice.inputs[0].taproot_key_spend_signature
        == once.inputs[0].taproot_key_spend_signature
    )


def test_sign_appends_the_sig_hash_type_a_taproot_input_asks_for() -> None:
    """BIP341 appends the type where it is not the default, as `sign` does.

    Every other taproot test here leaves sig_hash_type unset, which is
    SIGHASH_DEFAULT and appends nothing; this is the other half.

    `assert_signatures_only` is asked as well as the Finalizer, both
    verifying the 64 bytes and not the 65: the type byte is what the
    message was chosen by, and verifying it as part of the signature
    fails an answer that is perfectly good.
    """
    request, prevouts = _taproot_key_path_psbt()
    request.inputs[0].sig_hash_type = 1  # ALL
    key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})

    returned, signed_vins = sign(request, key_manager)

    assert signed_vins == [0]
    signature = returned.inputs[0].taproot_key_spend_signature
    assert len(signature) == 65
    assert signature[-1] == sig_hash.ALL
    assert_signatures_only(request, returned)
    verify_transaction(prevouts, extract_tx(finalize(returned), check_validity=False))


def test_sign_writes_the_taproot_script_path_signature() -> None:
    """A single-key leaf, signed and then finalized (issue #560).

    The signature is filed under the key and the leaf hash together,
    which is what `PSBT_IN_TAP_SCRIPT_SIG` is keyed by, and the witness
    the Finalizer builds from it is what the engine is asked about: a
    script path spend proves the leaf, so the leaf key signs untweaked
    and the control block carries the rest of the proof.
    """
    psbt, prevouts = _taproot_script_path_psbt()
    key_manager = _KeyManager(by_pub_key={_LEAF_KEY: _LEAF_PRV_KEY})

    result, signed_vins = sign(psbt, key_manager)

    assert signed_vins == [0]
    signatures = result.inputs[0].taproot_script_spend_signatures
    assert list(signatures) == [_LEAF_KEY + _LEAF_HASH]
    assert len(signatures[_LEAF_KEY + _LEAF_HASH]) == 64
    verify_transaction(prevouts, extract_tx(finalize(result), check_validity=False))


def test_sign_appends_the_sig_hash_type_to_a_script_path_signature() -> None:
    """The 65-byte shape of a script path signature (issue #560).

    The mutation session of PR 558 could reach it from no test at all,
    the only script path signature this tree produced being a BIP373
    aggregation of partial signatures that commit to SIGHASH_DEFAULT --
    and appending a type byte to that one is not the same signature, the
    hash a type commits to being another. So it is signed here, and
    checked by the two readers of the byte: `assert_signatures_only`,
    which verifies an answer over the 64 bytes and not the 65, and the
    script engine, which is what says the type is the one the
    transaction was hashed with.
    """
    request, prevouts = _taproot_script_path_psbt()
    request.inputs[0].sig_hash_type = 1  # ALL
    key_manager = _KeyManager(by_pub_key={_LEAF_KEY: _LEAF_PRV_KEY})

    returned, signed_vins = sign(request, key_manager)

    assert signed_vins == [0]
    signature = returned.inputs[0].taproot_script_spend_signatures[
        _LEAF_KEY + _LEAF_HASH
    ]
    assert len(signature) == 65
    assert signature[-1] == sig_hash.ALL
    assert_signatures_only(request, returned)
    verify_transaction(prevouts, extract_tx(finalize(returned), check_validity=False))


def test_sign_offers_a_taproot_input_both_of_its_paths() -> None:
    """One manager holding both keys answers for both, and is asked once.

    Which of the two spends the input is the Finalizer's choice, so a
    signer that can answer for either has no reason to be asked twice --
    and a second sign() over the result asks for neither again, the key
    path signature and the leaf's entry each saying there is nothing
    left to sign.
    """
    psbt, _ = _taproot_script_path_psbt()
    key_manager = _KeyManager(
        by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY, _LEAF_KEY: _LEAF_PRV_KEY}
    )

    once, signed_vins = sign(psbt, key_manager)
    assert signed_vins == [0]
    assert key_manager.sign_calls == 2
    assert once.inputs[0].taproot_key_spend_signature
    assert once.inputs[0].taproot_script_spend_signatures

    twice, signed_vins_again = sign(once, key_manager)
    assert signed_vins_again == []
    assert key_manager.sign_calls == 2
    assert (
        twice.inputs[0].taproot_script_spend_signatures
        == once.inputs[0].taproot_script_spend_signatures
    )


def test_sign_skips_a_leaf_key_the_key_manager_does_not_hold() -> None:
    """None from sign_schnorr_script_path leaves the leaf unsigned."""
    psbt, _ = _taproot_script_path_psbt()
    result, signed_vins = sign(psbt, _KeyManager())

    assert signed_vins == []
    assert not result.inputs[0].taproot_script_spend_signatures


def test_sign_skips_a_leaf_the_psbt_carries_no_script_for() -> None:
    """A derivation naming a tapleaf hash is not on its own a candidate.

    `PSBT_IN_TAP_LEAF_SCRIPT` is what says which condition the leaf
    imposes, and without it there is nothing to read before signing: a
    tapleaf hash alone is a commitment to a script this signer has never
    seen, which is what a psbt exists to avoid. key_manager holds the
    key and is never asked for it.
    """
    psbt, _ = _taproot_script_path_psbt(with_leaf_script=False)
    key_manager = _KeyManager(by_pub_key={_LEAF_KEY: _LEAF_PRV_KEY})

    result, signed_vins = sign(psbt, key_manager)

    assert signed_vins == []
    assert key_manager.sign_calls == 0
    assert not result.inputs[0].taproot_script_spend_signatures


def test_sign_raises_on_a_psbt_that_cannot_be_signed() -> None:
    """assert_signable's own pre-flight runs before any candidate does."""
    psbt = Psbt.b64decode("cHNidP8BAAoAAAAAAAAAAAAAAA==")
    with pytest.raises(BTClibValueError, match="nothing to sign: no inputs"):
        sign(psbt, _KeyManager())


def test_sign_raises_when_a_candidate_cannot_be_hashed() -> None:
    """A candidate whose message cannot be built stops sign() outright.

    A p2wsh input naming _PUB_KEY as a candidate but carrying no witness
    script leaves ecdsa_sig_hash nothing to build the message from: the
    same "no utxo, no redeem script, or no witness script" it refuses a
    Signer with directly.
    """
    witness_script = serialize([_PUB_KEY, "OP_CHECKSIG"])
    prev_out = TxOut(100_000, ScriptPubKey.p2wsh(witness_script))
    tx, _ = _spending_tx(prev_out)

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out
    psbt.inputs[0].hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0")}
    # no witness_script: assert_signable does not require one, and
    # ecdsa_sig_hash is what has nothing to compute a hash from

    err_msg = "does not say what is being signed"
    with pytest.raises(BTClibValueError, match=err_msg):
        sign(psbt, _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY}))


def test_sign_leaves_alone_an_input_with_no_candidate() -> None:
    """The same defect, with no candidate: sign() never asks and never raises.

    hd_key_paths empty is "nothing here is mine to sign", which is not
    the same claim as "this input is broken" -- an input none of
    key_manager's keys are named for is not this Signer's business.
    """
    witness_script = serialize([_PUB_KEY, "OP_CHECKSIG"])
    prev_out = TxOut(100_000, ScriptPubKey.p2wsh(witness_script))
    tx, _ = _spending_tx(prev_out)

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out

    result, signed_vins = sign(psbt, _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY}))

    assert signed_vins == []
    assert result.inputs[0].partial_sigs == {}


# the Finalizer's clearing rule, one list for both kinds of input


def _fully_populated(psbt: Psbt) -> Psbt:
    """Fill in every field a Finalizer is meant to drop, and some it keeps.

    The preimage maps are keyed by the hash of their own preimage, which
    `PsbtIn.assert_valid` checks, so they cannot be filled with
    arbitrary bytes.
    """
    psbt_in = psbt.inputs[0]
    psbt_in.ripemd160_preimages = {ripemd160(b"one"): b"one"}
    psbt_in.sha256_preimages = {sha256(b"two"): b"two"}
    psbt_in.hash160_preimages = {hash160(b"three"): b"three"}
    psbt_in.hash256_preimages = {hash256(b"four"): b"four"}
    psbt_in.unknown = {b"\xfc\x01": b"vendor"}
    return psbt


@pytest.mark.parametrize("kind", ["p2wsh", "p2tr"])
def test_a_finalized_input_keeps_the_utxo_and_the_unknown_fields_only(
    kind: str,
) -> None:
    """BIP174's rule, and the same one whichever kind the input is.

    "All other data except the UTXO and unknown fields in the input
    key-value map should be cleared from the PSBT." The taproot branch
    cleared nothing at all, so a finalized psbt went on publishing that
    input's key origins -- master fingerprint and derivation path, per
    key -- where an ECDSA input published none; and the ECDSA branch left
    the four preimage maps, which after finalization are in the witness
    anyway.

    btclib is stricter than Bitcoin Core here, whose
    `PSBTInput::FromSignatureData` clears four fields and leaves the
    taproot ones, the sighash type and the preimages.
    """
    if kind == "p2tr":
        psbt, prevouts = _taproot_key_path_psbt()
        psbt.inputs[0].hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0")}
        key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})
    else:
        signed, prevouts = _single_key_psbt(kind)
        psbt = deepcopy(signed)
        psbt.inputs[0].partial_sigs = {}
        psbt.inputs[0].hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0")}
        key_manager = _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY})

    signed, signed_vins = sign(_fully_populated(psbt), key_manager)
    assert signed_vins == [0]
    psbt_in = finalize(signed).inputs[0]

    # spelled out rather than imported from psbt.py: `_FINALIZED_KEEPS`
    # is what the code believes, and a test that imported it would agree
    # with a wrong list as readily as with a right one. Every other field
    # of PsbtIn is walked, so a field added there and left out of both
    # lists fails here
    kept = {
        "non_witness_utxo",
        "witness_utxo",
        "unknown",
        "previous_tx_id",
        "output_index",
        "sequence",
        "required_time_lock_time",
        "required_height_lock_time",
        "final_script_sig",
        "final_script_witness",
    }
    empty = PsbtIn(check_validity=False)
    for field in dataclasses.fields(psbt_in):
        if field.name not in kept:
            assert getattr(psbt_in, field.name) == getattr(empty, field.name), (
                f"{field.name} survived finalization"
            )

    # the two BIP174 exempts by name, and the spend it built
    assert psbt_in.unknown == {b"\xfc\x01": b"vendor"}
    assert psbt_in.witness_utxo or psbt_in.non_witness_utxo
    assert psbt_in.final_script_sig or psbt_in.final_script_witness
    verify_transaction(prevouts, extract_tx(finalize(signed), check_validity=False))


@pytest.mark.parametrize("kind", ["p2wsh", "p2tr"])
def test_finalizing_twice_is_finalizing_once(kind: str) -> None:
    """An input already finalized is left alone, not refused.

    "The Input Finalizer determines if the input has enough data" and one
    carrying its final scripts has more than enough; Core's
    `SignPSBTInput` skips it too. Refusing it meant a psbt whose signer
    had finalized one input could not be finalized at all: the second
    pass raised "missing signatures" for the input already done, the
    first pass having cleared the signatures it used.
    """
    if kind == "p2tr":
        psbt, _ = _taproot_key_path_psbt()
        key_manager = _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})
    else:
        signed, _ = _single_key_psbt(kind)
        psbt = deepcopy(signed)
        psbt.inputs[0].partial_sigs = {}
        psbt.inputs[0].hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\x00" * 4, "m/0")}
        key_manager = _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY})

    signed, _ = sign(psbt, key_manager)
    once = finalize(signed)
    assert finalize(once) == once


# the check that belongs before combine when the answer came from
# somebody else


def _request_and_answer() -> tuple[Psbt, Psbt]:
    """Return a 2-of-2 request the first signer signed, and the answer.

    The shape the validator exists for: the coordinator holds `request`
    and gets `returned` back, and everything in it but the second
    signature has to be what was sent.
    """
    request, signed_vins = sign(
        _unsigned_multisig_psbt(), _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY})
    )
    assert signed_vins == [0]
    returned, signed_vins = sign(
        deepcopy(request), _KeyManager(by_pub_key={_OTHER_PUB_KEY: _OTHER_PRV_KEY})
    )
    assert signed_vins == [0]
    return request, returned


def test_an_answer_carrying_only_a_new_signature_is_accepted() -> None:
    """The honest case, and the one that has to keep working.

    Both signatures are there afterwards, so the psbt finalizes: the
    validator refusing a good answer would be the expensive kind of
    wrong.
    """
    request, returned = _request_and_answer()

    assert_signatures_only(request, returned)

    combined = combine([request, returned])
    assert set(combined.inputs[0].partial_sigs) == {_PUB_KEY, _OTHER_PUB_KEY}


def test_an_answer_that_changes_the_transaction_is_refused() -> None:
    """Whichever field of it, and a sequence included (issue #381).

    `combine` compares the psbt's identifier, and for a version 2 psbt
    that identifier zeroes every sequence -- BIP370 making the sequence a
    field an Updater may set. So a changed sequence is exactly what it
    cannot see, and comparing the transaction whole is what does.
    """
    request, returned = _request_and_answer()
    returned.outputs[0].amount = 1
    with pytest.raises(BTClibValueError, match="the transaction being signed"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.inputs[0].sequence = 0xFFFFFFFD
    with pytest.raises(BTClibValueError, match="the transaction being signed"):
        assert_signatures_only(request, returned)


@pytest.mark.parametrize(
    "field, value",
    [
        ("witness_script", b"\x51"),
        ("redeem_script", b"\x51"),
        ("sig_hash_type", 3),
        ("final_script_sig", b"\x51"),
        ("taproot_internal_key", b"\x02" * 32),
    ],
)
def test_an_answer_that_changes_a_context_field_is_refused(
    field: str, value: object
) -> None:
    """A signer's answer may add a signature and nothing else.

    Equality and not `combine`'s "was not overwritten": a signer that
    fills in a script the request left empty is playing Updater too, and
    a caller who wants that has `combine` and no illusion it was checked.
    `final_script_sig` is here because that is the decision about a
    finalized answer -- it is not a signature, so it must be equal, and
    an answer that finalizes an input is refused rather than merged.
    """
    request, returned = _request_and_answer()
    setattr(returned.inputs[0], field, value)
    with pytest.raises(BTClibValueError, match=f"input 0: {field} was changed"):
        assert_signatures_only(request, returned)


def test_an_answer_that_overwrites_one_entry_of_a_map_is_refused() -> None:
    """The sharp edge `combine` has: `_combine_field` does dict.update.

    A field that is several key-value pairs is merged pair by pair, so an
    answer cannot add a whole `hd_key_paths` where the request had one --
    but it can replace the origin filed under a single public key, and
    the merge takes it.
    """
    request, returned = _request_and_answer()
    returned.inputs[0].hd_key_paths[_PUB_KEY] = BIP32KeyOrigin(b"\xff" * 4, "m/9")
    with pytest.raises(BTClibValueError, match="input 0: hd_key_paths was changed"):
        assert_signatures_only(request, returned)


def test_an_answer_that_adds_a_preimage_or_a_vendor_field_is_refused() -> None:
    """Neither is a signature, so neither may appear (issue #381).

    An `unknown` entry is the decision about vendor fields: they are data
    a caller re-serializes and hands on, and an answer is not the place
    they arrive from.
    """
    request, returned = _request_and_answer()
    returned.inputs[0].sha256_preimages = {sha256(b"x"): b"x"}
    with pytest.raises(BTClibValueError, match="input 0: sha256_preimages"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.inputs[0].unknown = {b"\xfc\x01": b"vendor"}
    with pytest.raises(BTClibValueError, match="input 0: unknown was changed"):
        assert_signatures_only(request, returned)


def test_an_answer_that_touches_the_first_signature_is_refused() -> None:
    """Dropped or replaced, both refused.

    `combine` would put a dropped signature back with nobody the wiser
    that it had been taken out, and a replaced one is a signature this
    coordinator never saw made.
    """
    request, returned = _request_and_answer()
    del returned.inputs[0].partial_sigs[_PUB_KEY]
    with pytest.raises(BTClibValueError, match="partial_sigs of .* was dropped"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.inputs[0].partial_sigs[_PUB_KEY] = returned.inputs[0].partial_sigs[
        _OTHER_PUB_KEY
    ]
    with pytest.raises(BTClibValueError, match="partial_sigs of .* was changed"):
        assert_signatures_only(request, returned)


def test_an_answer_carrying_a_signature_that_does_not_verify_is_refused() -> None:
    """Every signature that arrived is checked before anything is merged."""
    request, returned = _request_and_answer()
    good = returned.inputs[0].partial_sigs[_OTHER_PUB_KEY]
    # the same key, a signature of some other message: the DER of the
    # first signer's signature under the second signer's key
    returned.inputs[0].partial_sigs[_OTHER_PUB_KEY] = (
        request.inputs[0].partial_sigs[_PUB_KEY][:-1] + good[-1:]
    )
    err_msg = "input 0: invalid signature for pub_key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


def test_a_signature_whose_message_cannot_be_computed_is_refused() -> None:
    """Where the Finalizer leaves it alone, the validator refuses it.

    `_assert_partial_sigs_verify` skips a signature the psbt gives it no
    message for -- a Finalizer learns nothing about a signature from a
    psbt that does not say what was signed. Here it is the one thing that
    must not be merged, so the same silence is a refusal.

    Both psbts lose the witness script, so it is not a changed field: the
    request is one that never said what the signature covers.
    """
    request, returned = _request_and_answer()
    request.inputs[0].witness_script = b""
    returned.inputs[0].witness_script = b""
    del request.inputs[0].partial_sigs[_PUB_KEY]

    err_msg = "cannot verify the signature of .*does not say what was signed"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


def test_an_answer_that_loosens_tx_modifiable_is_refused() -> None:
    """The one field an answer may change, and only in one direction.

    A Signer clears a modifiable bit when it adds a signature a change
    would break, so tightening is the legitimate answer; setting a bit
    the request had clear says the psbt may still be modified in a way
    the request said it may not. `_combined_tx_modifiable` is the rule,
    and an answer no more permissive than the request is one the two
    combine into unchanged.

    Version 2, `PSBT_GLOBAL_TX_MODIFIABLE` being a field BIP370 does not
    allow a version 0 psbt to carry.
    """
    request, returned = _request_and_answer()
    request, returned = request.to_v2(), returned.to_v2()
    request.tx_modifiable = 0
    returned.tx_modifiable = INPUTS_MODIFIABLE
    with pytest.raises(BTClibValueError, match="tx_modifiable is more permissive"):
        assert_signatures_only(request, returned)

    # the other way round is a Signer doing its job
    request.tx_modifiable = INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    returned.tx_modifiable = OUTPUTS_MODIFIABLE
    assert_signatures_only(request, returned)


def test_an_answer_that_changes_the_fallback_lock_time_is_refused() -> None:
    """Inert for this psbt, and a field that travels all the same.

    The transaction comparison catches a changed fallback wherever the
    lock time is computed from it, which is every psbt whose inputs
    require none. This is the other case: an input requiring a height
    lock time makes the fallback unused, so the two psbts agree on the
    transaction and differ on a field that becomes live again the moment
    that requirement is dropped. Not a signature, so it must be equal.
    """
    request, returned = _request_and_answer()
    request, returned = request.to_v2(), returned.to_v2()
    for psbt in (request, returned):
        psbt.inputs[0].required_height_lock_time = 700_000
    request.fallback_lock_time = 500_000
    returned.fallback_lock_time = 600_000
    assert request.lock_time == returned.lock_time == 700_000

    with pytest.raises(BTClibValueError, match="fallback_lock_time was changed"):
        assert_signatures_only(request, returned)


def test_an_answer_that_changes_a_global_field_or_an_output_is_refused() -> None:
    """The global maps and every output field, none of them signatures."""
    request, returned = _request_and_answer()
    returned.version = 2
    with pytest.raises(BTClibValueError, match="mismatched psbt version"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.hd_key_paths = {_PUB_KEY: BIP32KeyOrigin(b"\xff" * 4, "m/9")}
    with pytest.raises(BTClibValueError, match="global hd_key_paths were changed"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.unknown = {b"\xfc\x02": b"vendor"}
    with pytest.raises(BTClibValueError, match="global unknown fields were changed"):
        assert_signatures_only(request, returned)

    request, returned = _request_and_answer()
    returned.outputs[0].redeem_script = b"\x51"
    with pytest.raises(BTClibValueError, match="output 0: redeem_script was changed"):
        assert_signatures_only(request, returned)


def _taproot_request_and_answer() -> tuple[Psbt, Psbt, list[TxOut]]:
    """Return an unsigned p2tr key path request, and the answer to it."""
    request, prevouts_ = _taproot_key_path_psbt()
    returned, signed_vins = sign(
        deepcopy(request),
        _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY}),
    )
    assert signed_vins == [0]
    return request, returned, prevouts_


def test_a_taproot_answer_is_checked_against_the_output_key() -> None:
    """The Finalizer's own check, asked one role earlier."""
    request, returned, prevouts_ = _taproot_request_and_answer()
    assert_signatures_only(request, returned)
    verify_transaction(prevouts_, extract_tx(finalize(returned), check_validity=False))

    request, returned, _ = _taproot_request_and_answer()
    returned.inputs[0].taproot_key_spend_signature = b"\x01" * 64
    err_msg = "invalid taproot key path signature for output key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


def test_a_taproot_answer_that_changes_the_signature_it_was_sent_is_refused() -> None:
    """The scalar field's own rule: set once, it must come back as it was."""
    # the answer of the first round is the request of the second, which is
    # what makes the signature a field that is already set
    signed_request = _taproot_request_and_answer()[1]
    tampered = deepcopy(signed_request)
    tampered.inputs[0].taproot_key_spend_signature = b"\x02" * 64

    err_msg = "taproot_key_spend_signature was changed"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(signed_request, tampered)


def test_a_taproot_signature_beside_a_non_taproot_input_is_refused() -> None:
    """There is no output key to check it against.

    An answer that files a schnorr signature on an input spending a
    witness v0 output is describing some other input, and the Finalizer
    would not read the field either -- it dispatches on the spent script.
    """
    request, returned = _request_and_answer()
    returned.inputs[0].taproot_key_spend_signature = b"\x01" * 64
    err_msg = "a taproot signature for an input spending no taproot output"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


def test_an_answer_whose_signature_commits_to_another_sig_hash_type() -> None:
    """The type the input asks for is the type the answer must sign.

    `_assert_sig_hash_type` is BIP174's rule for the Finalizer, asked
    here as well: a signature committing to something other than the
    input asked for is one the other participants did not agree to, and
    refusing it before the merge is cheaper than refusing it after.
    """
    request, returned = _request_and_answer()
    request.inputs[0].sig_hash_type = 1
    returned.inputs[0].sig_hash_type = 1
    sig = returned.inputs[0].partial_sigs[_OTHER_PUB_KEY]
    returned.inputs[0].partial_sigs[_OTHER_PUB_KEY] = sig[:-1] + b"\x03"
    with pytest.raises(BTClibValueError, match="mismatched sig_hash type"):
        assert_signatures_only(request, returned)


def test_a_taproot_script_path_answer_is_checked_against_the_leaf_key() -> None:
    """The script path half, against the key its tapleaf hash names.

    BIP373's own vector is the signature, aggregated from the session the
    psbt carries; the request is that psbt with the signature taken back
    out, so every other field agrees by construction and the signature is
    the only difference.
    """
    description = "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    returned = _taproot_signed(description)
    request = deepcopy(returned)
    request.inputs[0].taproot_script_spend_signatures = {}

    assert_signatures_only(request, returned)

    key_data = next(iter(returned.inputs[0].taproot_script_spend_signatures))
    returned.inputs[0].taproot_script_spend_signatures[key_data] = b"\x01" * 64
    err_msg = "invalid taproot script path signature for key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


def test_an_answer_that_signs_the_other_path_of_a_taproot_input() -> None:
    """The key path signature it was sent is not checked a second time.

    An input its owner can spend and a leaf key can spend is signable on
    both paths, one round each, so the second round's request is a psbt
    whose `taproot_key_spend_signature` is already set. What the check owes
    that field is the rule of every signature the request carried -- set
    once, it comes back as it was, which is
    `_assert_signatures_added_only`'s -- and not a verification of the
    caller's own psbt.
    """
    request, _ = _taproot_script_path_psbt()
    request, signed_vins = sign(
        request, _KeyManager(by_pub_key={_TAPROOT_INTERNAL_KEY: _TAPROOT_PRV_KEY})
    )
    assert signed_vins == [0]
    assert request.inputs[0].taproot_key_spend_signature

    returned, signed_vins = sign(
        deepcopy(request), _KeyManager(by_pub_key={_LEAF_KEY: _LEAF_PRV_KEY})
    )
    assert signed_vins == [0]
    assert returned.inputs[0].taproot_script_spend_signatures

    assert_signatures_only(request, returned)


def test_an_answer_that_is_not_a_valid_psbt_is_refused() -> None:
    """It came from outside, so it is validated before it is compared."""
    request, returned = _request_and_answer()
    returned.inputs[0].partial_sigs[b"\x02" * 10] = b"\x30\x06"
    err_msg = "invalid partial signature pub_key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signatures_only(request, returned)


# the two wallets below are what `new_signers` answers, so they are told
# apart by their master fingerprint and not by their derivation path:
# `_unsigned_multisig_psbt` gives both keys the fingerprint zero, distinct
# paths being all its own tests need
_FIRST_WALLET = bytes.fromhex("01020304")
_SECOND_WALLET = bytes.fromhex("deadbeef")


def _two_wallets_psbt() -> Psbt:
    """Return the 2-of-2 psbt with an origin per wallet, and no signature."""
    psbt = _unsigned_multisig_psbt()
    psbt.inputs[0].hd_key_paths = {
        _PUB_KEY: BIP32KeyOrigin(_FIRST_WALLET, "m/0"),
        _OTHER_PUB_KEY: BIP32KeyOrigin(_SECOND_WALLET, "m/0"),
    }
    return psbt


def _two_wallets_request_and_answer() -> tuple[Psbt, Psbt]:
    """Return that psbt signed by the first wallet, and by both."""
    request, signed_vins = sign(
        _two_wallets_psbt(), _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY})
    )
    assert signed_vins == [0]
    returned, signed_vins = sign(
        deepcopy(request), _KeyManager(by_pub_key={_OTHER_PUB_KEY: _OTHER_PRV_KEY})
    )
    assert signed_vins == [0]
    return request, returned


def test_a_psbt_whose_inputs_all_carry_a_verified_signature_is_accepted() -> None:
    """The honest case, and what "signed" does and does not mean.

    The request is accepted too, one signature short of what its 2-of-2
    script needs: the question is whether every input carries a signature
    that verifies, not whether what it carries satisfies the script, which
    is `finalize`'s and the script engine's. A caller wanting the second
    answer has `finalize`, which builds the spend or refuses to.
    """
    request, returned = _two_wallets_request_and_answer()
    assert len(returned.inputs[0].partial_sigs) == 2

    assert_signed(returned)
    assert_signed(request)


def test_an_unsigned_input_is_refused_unless_the_session_is_partial() -> None:
    """Which of the two a psbt is is the caller's to say.

    A device holds keys for some of the inputs only whenever one psbt
    spans several wallets, so an input it left alone is legitimate
    mid-session and is the psbt being incomplete at the end of one.
    Nothing in the psbt says which of the two it is looking at.
    """
    psbt = _two_wallets_psbt()

    with pytest.raises(BTClibValueError, match="input 0: not signed"):
        assert_signed(psbt)

    assert_signed(psbt, allow_partial=True)


def test_a_signature_that_does_not_verify_is_refused_however_many_there_are() -> None:
    """The count and the arithmetic are independent questions.

    The two signatures are swapped, so each is a valid DER signature of
    this transaction under the *other* cosigner's key: the input carries
    as many as it did, and neither verifies where it is filed.
    allow_partial does not excuse it either -- it drops the requirement
    that an input be signed, not the check on what it holds.
    """
    _, returned = _two_wallets_request_and_answer()
    partial_sigs = returned.inputs[0].partial_sigs
    partial_sigs[_PUB_KEY], partial_sigs[_OTHER_PUB_KEY] = (
        partial_sigs[_OTHER_PUB_KEY],
        partial_sigs[_PUB_KEY],
    )

    with pytest.raises(BTClibValueError, match="invalid signature for pub_key"):
        assert_signed(returned)
    with pytest.raises(BTClibValueError, match="invalid signature for pub_key"):
        assert_signed(returned, allow_partial=True)


def test_a_signature_of_an_input_that_says_nothing_of_what_it_spends() -> None:
    """Refused, where the Finalizer leaves it alone.

    A p2wsh input without its witness script does not say what was
    signed, and `_assert_partial_sigs_verify` skips exactly this case: the
    Finalizer has the psbt's other fields to fall back on and learns
    nothing about the signature from a missing one. A caller asking
    whether the signatures are good has to be told that this one could
    not be checked.
    """
    _, returned = _two_wallets_request_and_answer()
    returned.inputs[0].witness_script = b""

    err_msg = "the psbt does not say what was signed"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signed(returned)


def test_a_psbt_with_no_inputs_carries_no_signature_at_all() -> None:
    """BIP174 calls it valid, and the loop below would pass it vacuously.

    `assert_signable`'s answer to the same shape, for the same reason: a
    caller told that a psbt with nothing in it is signed is told the
    opposite of what it asked.
    """
    # "PSBT with global unsigned tx that has 0 inputs and 0 outputs"
    psbt = Psbt.b64decode("cHNidP8BAAoAAAAAAAAAAAAAAA==")

    with pytest.raises(BTClibValueError, match="nothing is signed: no inputs"):
        assert_signed(psbt)
    with pytest.raises(BTClibValueError, match="nothing is signed: no inputs"):
        assert_signed(psbt, allow_partial=True)


def test_a_finalized_input_is_refused_rather_than_reported_unsigned() -> None:
    """It carries no partial signature because finalizing cleared them.

    BIP174 has the Finalizer drop everything but the utxo and the unknown
    fields, so the psbt that holds a complete spend is the one this would
    otherwise call unsigned. What it now carries is a script_sig and a
    witness, whose signatures the script engine verifies.
    """
    finalized = finalize(_two_wallets_request_and_answer()[1])

    with pytest.raises(BTClibValueError, match="input 0 is finalized"):
        assert_signed(finalized)


def test_a_taproot_signature_is_verified_against_the_key_it_spends() -> None:
    """`_assert_taproot_sigs_verify`'s, so both paths are covered."""
    returned = _taproot_request_and_answer()[1]
    assert_signed(returned)

    returned.inputs[0].taproot_key_spend_signature = b"\x01" * 64
    err_msg = "invalid taproot key path signature for output key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signed(returned)

    script_path = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    assert_signed(script_path)

    key_data = next(iter(script_path.inputs[0].taproot_script_spend_signatures))
    script_path.inputs[0].taproot_script_spend_signatures[key_data] = b"\x01" * 64
    err_msg = "invalid taproot script path signature for key"
    with pytest.raises(BTClibValueError, match=err_msg):
        assert_signed(script_path)


def test_a_musig2_session_is_not_a_signature_until_it_is_aggregated() -> None:
    """Round 1 and round 2 are what a participant answered, not a spend.

    BIP373's own vector with every public nonce in it is a session going
    round, and the input is unsigned until `partial_sigs_agg` adds the
    partial signatures up into the BIP340 signature the spend needs --
    which is the signature this then verifies, and which the same vector's
    "with all partial signatures" sibling produces.
    """
    mid_session = _bip373_psbt(
        "Spend of a Taproot output where the output key is a MuSig2 "
        "Aggregate Pubkey, with all pubnonces"
    )
    assert mid_session.inputs[0].musig2_pub_nonces

    with pytest.raises(BTClibValueError, match="input 0: not signed"):
        assert_signed(mid_session)

    aggregated = _taproot_signed(
        "the output key is a MuSig2 Aggregate Pubkey, with all partial"
    )
    assert_signed(aggregated)


def test_new_signers_names_the_wallet_whose_key_the_answer_signed_with() -> None:
    """One round at a time, each read against what was sent.

    Which is what `combine` cannot be asked afterwards: the union it takes
    records nothing of which side an entry came from.
    """
    request, returned = _two_wallets_request_and_answer()

    assert new_signers(_two_wallets_psbt(), request) == {_FIRST_WALLET}
    assert new_signers(request, returned) == {_SECOND_WALLET}


def test_an_answer_that_adds_no_signature_names_no_signer() -> None:
    """A device that had already signed, and one that holds no key here.

    Both add nothing, and the two are not distinguishable from the psbt:
    an empty answer is what the caller asked about, so it is an empty set
    and not an error. Asked of each kind of signature a psbt carries,
    "was already there" being the case every one of them walks past.
    """
    signed_psbts = [
        _two_wallets_request_and_answer()[1],
        _taproot_request_and_answer()[1],
        _taproot_signed(
            "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
        ),
        _bip373_psbt(
            "Spend of a Taproot output where the output key is a MuSig2 "
            "Aggregate Pubkey, with all pubnonces"
        ),
    ]

    for signed in signed_psbts:
        assert new_signers(signed, deepcopy(signed)) == set()


def test_a_wallet_that_signed_with_two_keys_is_one_signer() -> None:
    """A fingerprint is what a psbt states about a key, and all it states.

    `_unsigned_multisig_psbt`'s two cosigners share a master fingerprint
    and differ by path, which is one wallet holding both keys of its own
    2-of-2 -- so two signatures arrive and one wallet made them.
    """
    request = _unsigned_multisig_psbt()
    returned, signed_vins = sign(
        deepcopy(request),
        _KeyManager(by_pub_key={_PUB_KEY: _PRV_KEY, _OTHER_PUB_KEY: _OTHER_PRV_KEY}),
    )
    assert signed_vins == [0]
    assert len(returned.inputs[0].partial_sigs) == 2

    assert new_signers(request, returned) == {b"\x00" * 4}


def test_a_signature_the_psbt_states_no_origin_for_is_refused() -> None:
    """Which device made it is not a thing to guess at.

    The shape this arrives in is a countersigner's file: a signature under
    a key nothing in the psbt derives, where an empty answer would read as
    "nobody signed" and a caller filing the answer would file it under the
    wrong name.
    """
    request, returned = _two_wallets_request_and_answer()
    del returned.inputs[0].hd_key_paths[_OTHER_PUB_KEY]

    err_msg = "no key origin for the signature of"
    with pytest.raises(BTClibValueError, match=err_msg):
        new_signers(request, returned)


def test_a_taproot_key_path_answer_is_read_through_the_internal_key() -> None:
    """What BIP371 says about who holds the key the output commits to.

    The signature is under the output key, which is the internal key
    tweaked by the merkle root: no psbt field states the output key's
    origin, and the internal key's entry in
    `PSBT_IN_TAP_BIP32_DERIVATION` is what names the wallet that can sign
    for it.
    """
    request, returned, _ = _taproot_request_and_answer()
    derivation: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]] = {
        _TAPROOT_INTERNAL_KEY: ([], BIP32KeyOrigin(_SECOND_WALLET, "m/0"))
    }
    request.inputs[0].taproot_hd_key_paths = derivation
    returned.inputs[0].taproot_hd_key_paths = derivation

    assert_signatures_only(request, returned)
    assert new_signers(request, returned) == {_SECOND_WALLET}


def test_a_taproot_script_path_answer_is_read_through_the_leaf_key() -> None:
    """The key its key data names, whose origin the same field states."""
    request, _ = _taproot_script_path_psbt()
    request.inputs[0].taproot_hd_key_paths = {
        _LEAF_KEY: ([_LEAF_HASH], BIP32KeyOrigin(_FIRST_WALLET, "m/1"))
    }
    returned, signed_vins = sign(
        deepcopy(request), _KeyManager(by_pub_key={_LEAF_KEY: _LEAF_PRV_KEY})
    )
    assert signed_vins == [0]

    assert new_signers(request, returned) == {_FIRST_WALLET}


def test_a_musig2_round_is_the_answer_of_the_participant_it_is_filed_under() -> None:
    """As `assert_signatures_only` counts the two maps among the signatures.

    A public nonce is what round 1 of that participant *is*, so a session
    that gained one gained an answer, and the participant is the first 33
    bytes of the key data it is filed under. BIP373's vector carries three
    of them and no origin for any -- the field is optional and these psbts
    were written to exercise the musig2 fields -- so the origins are what
    this test adds, one wallet holding two of the three keys.
    """
    returned = _bip373_psbt(
        "Spend of a Taproot output where the output key is a MuSig2 "
        "Aggregate Pubkey, with all pubnonces"
    )
    request = deepcopy(returned)
    request.inputs[0].musig2_pub_nonces = {}

    wallets = [_FIRST_WALLET, _FIRST_WALLET, _SECOND_WALLET]
    participants = [key_data[:33] for key_data in returned.inputs[0].musig2_pub_nonces]
    assert len(participants) == len(wallets)
    for i, (participant, wallet) in enumerate(zip(participants, wallets, strict=True)):
        returned.inputs[0].hd_key_paths[participant] = BIP32KeyOrigin(wallet, f"m/{i}")

    assert new_signers(request, returned) == {_FIRST_WALLET, _SECOND_WALLET}


def test_new_signers_refuses_two_psbts_with_a_different_number_of_inputs() -> None:
    """An answer to some other request, which there is nothing to read.

    Only the counts are compared here, being what the walk below needs;
    that the two are otherwise the same request is
    `assert_signatures_only`'s question, and the merge is what must not
    happen before both have answered.
    """
    request, returned = _two_wallets_request_and_answer()
    del request.inputs[0]

    err_msg = "mismatched number of psbt inputs"
    with pytest.raises(BTClibValueError, match=err_msg):
        new_signers(request, returned)


def test_a_solver_spends_a_script_this_finalizer_would_guess_at() -> None:
    """A witness script of no standard kind, and the caller's own stack.

    The generic construction is the satisfaction of a multisig -- the
    signatures, the BIP147 dummy where one is popped, the witness script
    -- which is a guess for any other script. It is not refused, so a
    caller with a script of their own answers over it rather than after
    it, and what they answer is used whole.
    """
    signed, prevouts_ = _single_key_psbt("p2wsh")
    witness_script = signed.inputs[0].witness_script
    ((_, signature),) = signed.inputs[0].partial_sigs.items()

    # the guess: signature and script, which for a p2pk witness script is
    # right, and is what makes this comparison meaningful
    guessed = finalize(signed)
    assert guessed.inputs[0].final_script_witness.stack == (signature, witness_script)

    # the caller's own, with an element the finalizer had no reason to add
    stack = Witness([b"", signature, witness_script])

    def solver(_psbt: Psbt, _vin_i: int) -> tuple[bytes, Witness]:
        return b"", stack

    solved = finalize(signed, solver=solver)
    assert solved.inputs[0].final_script_witness == stack
    assert solved.inputs[0].final_script_sig == b""
    # the bookkeeping is the finalizer's either way: what BIP174 says to
    # clear is cleared, and the utxo it says to keep is kept
    assert not solved.inputs[0].partial_sigs
    assert not solved.inputs[0].witness_script
    assert solved.inputs[0].witness_utxo or solved.inputs[0].non_witness_utxo
    assert prevouts_


def test_a_solver_answering_none_leaves_the_input_to_the_finalizer() -> None:
    """The refusals and the answers are both what they were unasked."""
    signed, _ = _single_key_psbt("p2wsh")

    def abstain(_psbt: Psbt, _vin_i: int) -> tuple[bytes, Witness] | None:
        return None

    assert finalize(signed, solver=abstain) == finalize(signed)

    # an input with nothing to finalize is refused as before
    psbt = deepcopy(signed)
    psbt.inputs[0].partial_sigs = {}
    with pytest.raises(BTClibValueError, match="missing signatures"):
        finalize(psbt, solver=abstain)


def test_a_solver_spends_the_taproot_leaf_the_psbt_cannot_choose() -> None:
    """Two script path signatures are two spends, and the caller picks one.

    Which leaf to spend is a choice the psbt does not record, so the
    finalizer refuses it. A caller that has chosen says so with the
    witness BIP341 asks for -- the signature, the leaf script, the
    control block -- and the refusal becomes their answer.
    """
    psbt = _taproot_signed(
        "a key in a script is a MuSig2 Aggregate Pubkey, with all partial"
    )
    _, sig = next(iter(psbt.inputs[0].taproot_script_spend_signatures.items()))
    psbt.inputs[0].taproot_script_spend_signatures[b"\x01" * 64] = sig
    with pytest.raises(BTClibValueError, match="2 taproot script path signatures"):
        finalize(psbt)

    control_block, (leaf, _version) = next(
        iter(psbt.inputs[0].taproot_leaf_scripts.items())
    )
    chosen = Witness([sig, leaf, control_block])

    def solver(_psbt: Psbt, _vin_i: int) -> tuple[bytes, Witness]:
        return b"", chosen

    solved = finalize(psbt, solver=solver)
    assert solved.inputs[0].final_script_witness == chosen
    # an empty script_sig, which is what BIP341 spends a witness v1
    # program with, and the caller's to get right
    assert solved.inputs[0].final_script_sig == b""
    assert not solved.inputs[0].taproot_script_spend_signatures


def test_a_solver_does_not_take_over_checking_the_signatures() -> None:
    """What satisfies the script is the caller's; a bad signature is not.

    The solver is never reached, which is the fact: a caller cannot
    finalize an invalid signature by answering over it. What the solver
    was asked is recorded rather than refused, so that the very same
    solver can then finalize the psbt whose signature is good -- what
    stopped the first call was the signature, and this is what says so.
    """
    signed, _ = _single_key_psbt("p2wsh")
    psbt = deepcopy(signed)
    ((pub_key, _),) = psbt.inputs[0].partial_sigs.items()
    psbt.inputs[0].partial_sigs = {pub_key: b"\x30" * 71 + b"\x01"}

    asked: list[int] = []

    def solver(psbt_: Psbt, vin_i: int) -> tuple[bytes, Witness]:
        asked.append(vin_i)
        return b"", Witness([b"", psbt_.inputs[vin_i].witness_script])

    with pytest.raises(BTClibValueError):
        finalize(psbt, solver=solver)
    assert not asked

    solved = finalize(signed, solver=solver)
    assert asked == [0]
    assert solved.inputs[0].final_script_witness.stack[-1] == (
        signed.inputs[0].witness_script
    )


@pytest.mark.parametrize(
    "psbt_str",
    [
        pytest.param("0", id="one character, no group"),
        pytest.param("\x80", id="not ascii"),
        pytest.param("cHNidP8", id="a truncated group"),
    ],
)
def test_b64decode_refuses_a_string_base64_cannot_read(psbt_str: str) -> None:
    """A psbt that is not base64 is refused with the library's exception.

    Found by tests/fuzz_test.py, and kept here as the input that found it:
    `base64.b64decode` raises binascii.Error for the first and the third
    and a plain ValueError for the second, and a caller catching
    BTClibValueError to reject what somebody pasted caught neither.
    """
    with pytest.raises(BTClibValueError, match="invalid base64 encoding"):
        Psbt.b64decode(psbt_str)


def _psbt_v2_declaring(input_count: int, output_count: int) -> bytes:
    """Return a PSBTv2 whose global map declares those two counts.

    The maps themselves are not written: what is under test is the count
    being believed, and the point of the check is that it is refused
    before anything is allocated for what the count promised.
    """

    def count_field(type_: int, count: int) -> bytes:
        value = var_int.serialize(count)
        return bytes([1, type_, len(value)]) + value

    global_map = (
        bytes([1, 0xFB, 4])
        + (2).to_bytes(4, "little")  # PSBT_GLOBAL_VERSION
        + bytes([1, 0x02, 4])
        + (2).to_bytes(4, "little")  # PSBT_GLOBAL_TX_VERSION
        + count_field(0x04, input_count)
        + count_field(0x05, output_count)
        + b"\x00"
    )
    return b"psbt\xff" + global_map


def test_a_declared_map_count_is_bounded_before_it_is_allocated_for() -> None:
    """A count no transaction could have is refused, not believed (issue 569).

    A PSBT's maps are a transaction's inputs and outputs, so a count
    above what a block has room for describes no transaction at all --
    `MAX_TX_IN_COUNT` and `MAX_TX_OUT_COUNT` in `btclib.tx.limits`.
    Believing one costs an object per declared map before the first is
    read: an empty input map is a single octet on the wire and a dozen
    fields in memory, which is the amplification the check exists to
    refuse. Measured on the issue's own reproducer, a PSBTv2 declaring
    100,000 empty input maps in about 100 KB: 125 MB of peak allocation
    before, 0.1 MB now.

    Both counts are checked because each names itself in the refusal,
    which is what a caller reads to know which of the two was wrong.
    """
    with pytest.raises(BTClibValueError, match="too many input maps"):
        Psbt.parse(_psbt_v2_declaring(MAX_TX_IN_COUNT + 1, 0))

    with pytest.raises(BTClibValueError, match="too many output maps"):
        Psbt.parse(_psbt_v2_declaring(0, MAX_TX_OUT_COUNT + 1))


def test_the_three_entries_that_took_a_psbt_unasked() -> None:
    """`combine`, `prevouts` and `new_signers` (issue 692, under #684).

    Each is public and each read a psbt `Psbt.assert_valid` refuses, and
    handed back an answer as if nothing were wrong: an invalid psbt into
    `combine` gave an invalid psbt out, presented as a combine that
    worked; `prevouts` returned the amounts and scripts a BIP341
    signature commits to, which is the list that most wants to have been
    checked; `new_signers` compared two psbts and read key data and
    origin fields raw out of both maps.

    `combine` asks after the version and identifier checks rather than
    before them: those two are what make the psbts one transaction's, so a
    caller handing over two unrelated ones is told that instead of
    whichever of them fails its own validation first.
    """
    good = Psbt.b64decode(TO_BE_FINALIZED)
    witness_utxo = good.inputs[1].witness_utxo
    assert witness_utxo is not None

    bad = deepcopy(good)
    bad.inputs[1].witness_utxo = TxOut(
        2**64, witness_utxo.script_pub_key, check_validity=False
    )
    err_msg = "invalid satoshi amount: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()

    with pytest.raises(BTClibValueError, match=err_msg):
        combine([deepcopy(bad), deepcopy(bad)])
    with pytest.raises(BTClibValueError, match=err_msg):
        prevouts(deepcopy(bad))
    with pytest.raises(BTClibValueError, match=err_msg):
        new_signers(deepcopy(bad), deepcopy(good))
