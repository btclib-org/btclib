# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.frost` module.

The key material is BIP445's own 2-of-3 group, read out of the vectors
vendored under `tests/ecc/_data/bip445/` rather than copied here: it is
what `tests/ecc/frost_test.py` signs with, so a re-pinned vector file
moves both at once. What is built here instead is the transaction --
BIP445 publishes no psbt, having nothing to say about one -- so every
spend below pays the group and is spent by it, and what says the session
was right is btclib's own script engine over the extracted transaction.
"""

from copy import deepcopy
from typing import Any

import pytest

from btclib.alias import Octets, TaprootScriptTree
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.ecc import frost, ssa
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData, PubKeyData
from btclib.psbt import Psbt, combine, extract_tx, finalize, join

# the two modules are one name apart and both are in play: the roles
# under test are the psbt ones, and the key material and the session
# they are built over are `btclib.ecc.frost`'s
from btclib.psbt import frost as psbt_frost
from btclib.psbt.psbt import prevouts, taproot_sig_hash
from btclib.script import ScriptPubKey, serialize, taproot, type_and_payload
from btclib.script.engine import verify_transaction
from btclib.script.taproot import input_script_sig, tree_helper
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load

_GROUP: dict[str, Any] = load("ecc", "_data", "bip445", "sign_verify_vectors.json")[
    "test_groups"
][0]

T: int = _GROUP["t"]
N: int = _GROUP["n"]
THRESH_PK = bytes.fromhex(_GROUP["thresh_pk"])
X_ONLY = THRESH_PK[1:]
SEC_SHARES = tuple(bytes.fromhex(share) for share in _GROUP["secshares"][:N])
PUB_SHARES: tuple[bytes | None, ...] = tuple(
    bytes.fromhex(share) for share in _GROUP["pubshares"][:N]
)
# a pubshare of the vectors that is a point and is not one of this
# group's: the file publishes it to be refused, and it is what the
# tampering below needs -- the entry before it is not a point at all, so
# a psbt carrying it would be refused for the wrong reason
FOREIGN_PUB_SHARE = bytes.fromhex(_GROUP["pubshares"][-1])

# the subset that signs: t of the n, which is where FROST parts from
# MuSig2's n-of-n and the reason the identifiers have to travel
SIGNERS = (0, 1)

# the participant whose knowledge of the group the psbts below carry:
# key material is keyed by its writer, so one is named rather than
# assumed
WRITER = 0

# the subtypes of the module under test, spelled out rather than
# imported: what these tests hold the records to is the layout, and
# reading it from the module it describes would agree with whatever that
# module happened to do
THRESHOLD_INFO, PUB_NONCE, PARTIAL_SIG = 0, 1, 2

# the internal key of the script path output, and the leaf the group
# signs in: `<32-byte key> OP_CHECKSIG` is the shape a Finalizer can
# build a witness for
INTERNAL_KEY = PrvKeyData(0xDEAD1234).pub.sec
LEAF_TREE: TaprootScriptTree = [(0xC0, [X_ONLY, "OP_CHECKSIG"])]
LEAF_SCRIPT = serialize([X_ONLY, "OP_CHECKSIG"])
LEAF_HASH = taproot.leaf_hash(0xC0, LEAF_SCRIPT)


def proprietary_key(subtype: int, key_data: bytes) -> bytes:
    """Return BIP174's proprietary key, written out here by hand.

    The type, the identifier's length as a compact size integer, the
    identifier, the subtype as another compact size integer, and the key
    data. Every value here is below 0xfd, so each compact size integer is
    the one byte holding it.
    """
    return b"\xfc" + b"\x06" + b"btclib" + bytes([subtype]) + key_data


def record_key_data(my_id: int, leaf_hash: bytes = b"") -> bytes:
    """Return the key data of one participant's record about this group.

    The identifier of the participant whose record it is, the group's
    threshold public key, and -- for a session in a leaf script -- the
    tapleaf hash.
    """
    return my_id.to_bytes(4, "big") + THRESH_PK + leaf_hash


def group_info(
    pub_shares: tuple[bytes | None, ...] = PUB_SHARES,
) -> frost.ThresholdInfo:
    """Return the group's key material, with the shares a holder knows."""
    return frost.ThresholdInfo(T, THRESH_PK, pub_shares)


def spending_psbt(prev_out: TxOut) -> Psbt:
    """Return the unsigned psbt of a transaction spending one output."""
    prev_tx = Tx(
        2, 0, [TxIn(OutPoint("00" * 31 + "01", 0), b"", 0xFFFFFFFF)], [prev_out]
    )
    tx = Tx(
        2,
        0,
        [TxIn(OutPoint(prev_tx.id, 0), b"", 0xFFFFFFFF)],
        [TxOut(90_000, prev_out.script_pub_key)],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prev_out
    return psbt


def internal_key_psbt() -> Psbt:
    """Return a psbt whose input's taproot internal key is the group's.

    One x-only tweak, the BIP341 commitment to an empty script tree, so
    the output key the spend verifies under is not the threshold public
    key the records are filed under.
    """
    psbt = spending_psbt(TxOut(100_000, ScriptPubKey.p2tr(PubKeyData(THRESH_PK))))
    psbt.inputs[0].taproot_internal_key = X_ONLY
    psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, group_info())
    return psbt


def output_key_psbt() -> Psbt:
    """Return a psbt whose input pays the threshold public key itself.

    Nothing to tweak: the output key *is* the group's key, so the
    signature the session produces verifies under it unchanged.
    """
    psbt = spending_psbt(TxOut(100_000, ScriptPubKey(serialize(["OP_1", X_ONLY]))))
    psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, group_info())
    return psbt


def script_path_psbt() -> Psbt:
    """Return a psbt spending a leaf script the group's key is in.

    Nothing to tweak either, and for another reason: a key in a leaf
    signs as itself, and the message is BIP342's. The internal key is
    somebody else's, which is what makes this a script path spend rather
    than a key path one dressed up.
    """
    script_pub_key = ScriptPubKey.p2tr(PubKeyData(INTERNAL_KEY), LEAF_TREE)
    psbt = spending_psbt(TxOut(100_000, script_pub_key))
    psbt.inputs[0].taproot_internal_key = INTERNAL_KEY[1:]
    psbt.inputs[0].taproot_merkle_root = tree_helper(LEAF_TREE)[1]
    control_block = input_script_sig(PubKeyData(INTERNAL_KEY), LEAF_TREE, 0)[1]
    psbt.inputs[0].taproot_leaf_scripts[control_block] = (LEAF_SCRIPT, 0xC0)
    psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, group_info())
    return psbt


def run_rounds(
    psbt: Psbt, *, leaf_hash: Octets = b"", signers: tuple[int, ...] = SIGNERS
) -> None:
    """Run both rounds over one psbt, as a coordinator holding it would.

    `signers` is the subset that signs this session, which the psbt
    carries rather than the module: a test that needs a subset no one
    holder's key material names on its own passes its own.
    """
    sec_nonces = {
        my_id: psbt_frost.nonce_gen(
            psbt, 0, my_id, SEC_SHARES[my_id], THRESH_PK, leaf_hash=leaf_hash
        )
        for my_id in signers
    }
    for my_id in signers:
        psbt_frost.partial_sign(
            psbt,
            0,
            sec_nonces[my_id],
            my_id,
            SEC_SHARES[my_id],
            THRESH_PK,
            leaf_hash=leaf_hash,
        )


def test_the_vectors_key_material_is_the_group_it_says() -> None:
    """What every test below rests on, measured rather than assumed.

    Each secret share is the discrete logarithm of the public share
    beside it, and the public shares reconstruct the threshold public
    key. The vectors are read by index here, so a re-pinned file whose
    groups have moved is a failure with a name rather than a session
    that does not assemble.
    """
    for sec_share, pub_share in zip(SEC_SHARES, PUB_SHARES, strict=True):
        assert bytes_from_point(mult(int.from_bytes(sec_share, "big"))) == pub_share
    frost.validate_threshold_info(group_info())
    assert (T, N) == (2, 3)


def test_a_whole_session_is_run_over_the_psbt() -> None:
    """Both rounds and every role, with btclib as a signing subset.

    What a Signer and a Finalizer add to the psbt the Updater wrote: two
    public nonces, two partial signatures, the aggregate signature, and a
    transaction the script engine accepts. The third participant does
    nothing, which is the whole difference from `btclib.psbt.musig2` --
    the group is three and the session is two.

    The secret nonces stay in this function, which is the point of
    `nonce_gen` returning them, and each is spent exactly once:
    `btclib.ecc.frost.sign` zeroes the bytearray it consumes.
    """
    psbt = internal_key_psbt()
    spent = prevouts(psbt)

    sec_nonces = {
        my_id: psbt_frost.nonce_gen(
            psbt, 0, my_id, SEC_SHARES[my_id], THRESH_PK, extra_in=b"\x07" * 32
        )
        for my_id in SIGNERS
    }
    session = psbt_frost.session_context(psbt, 0, THRESH_PK)
    assert session.ids == SIGNERS
    assert (session.t, session.n) == (T, N)

    for my_id in SIGNERS:
        psbt_frost.partial_sign(
            psbt, 0, sec_nonces[my_id], my_id, SEC_SHARES[my_id], THRESH_PK
        )
        # spent, and the bytearray says so: a second signature under one
        # secnonce is what hands out the secret share
        with pytest.raises(BTClibValueError, match="secnonce value is out of range"):
            psbt_frost.partial_sign(
                psbt, 0, sec_nonces[my_id], my_id, SEC_SHARES[my_id], THRESH_PK
            )

    for my_id in SIGNERS:
        assert psbt_frost.partial_sig_verify(psbt, 0, my_id, THRESH_PK)

    sig = psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK)
    output_key = type_and_payload(spent[0].script_pub_key.script)[1]
    assert ssa.verify_(taproot_sig_hash(psbt, 0), output_key, sig)
    # the session is gone, its key material with it, and what replaced it
    # is the signature
    assert not psbt.inputs[0].unknown
    assert len(psbt.inputs[0].taproot_key_spend_signature) == 64

    verify_transaction(spent, extract_tx(finalize(psbt)))


def test_the_threshold_key_may_be_the_output_key_itself() -> None:
    """The second of the three ways the key reaches the output.

    The output pays the group's key untweaked, so the tweaks derived
    from the psbt are none at all and the aggregate signature verifies
    under the key the records are filed under.
    """
    psbt = output_key_psbt()
    spent = prevouts(psbt)
    run_rounds(psbt)

    sig = psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK)
    assert ssa.verify_(taproot_sig_hash(psbt, 0), X_ONLY, sig)
    verify_transaction(spent, extract_tx(finalize(psbt)))


def test_a_session_in_a_leaf_script() -> None:
    """The third: the group's key inside a `<key> OP_CHECKSIG` leaf.

    The message is BIP342's rather than BIP341's, the taproot tweak
    belongs to the output key the script path does not sign for, and the
    signature goes under the key and the tapleaf hash where a Finalizer
    reads it.
    """
    psbt = script_path_psbt()
    spent = prevouts(psbt)
    run_rounds(psbt, leaf_hash=LEAF_HASH)

    # the records of a session in a leaf carry the tapleaf hash after the
    # threshold public key, and are a shape `assert_valid_records` reads
    unknown = psbt.inputs[0].unknown
    for my_id in SIGNERS:
        for subtype in (PUB_NONCE, PARTIAL_SIG):
            assert proprietary_key(subtype, record_key_data(my_id, LEAF_HASH)) in (
                unknown
            )
    psbt_frost.assert_valid_records(psbt.inputs[0])

    for my_id in SIGNERS:
        assert psbt_frost.partial_sig_verify(
            psbt, 0, my_id, THRESH_PK, leaf_hash=LEAF_HASH
        )
    psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK, leaf_hash=LEAF_HASH)
    assert psbt.inputs[0].taproot_script_spend_signatures[X_ONLY + LEAF_HASH]
    assert not psbt.inputs[0].unknown

    verify_transaction(spent, extract_tx(finalize(psbt)))


def test_the_tapleaf_hash_is_keyword_only() -> None:
    """A tapleaf hash is named where it is passed, never taken by position.

    It follows the threshold public key, which is a `bytes` as it is: a
    caller reading a signature's positional arguments would otherwise
    hand a leaf to whichever function came next in the call.
    """
    psbt = script_path_psbt()
    calls = {
        "nonce_gen": (psbt, 0, 0, SEC_SHARES[0], THRESH_PK),
        "partial_sign": (psbt, 0, bytearray(64), 0, SEC_SHARES[0], THRESH_PK),
        "partial_sig_verify": (psbt, 0, 0, THRESH_PK),
        "session_context": (psbt, 0, THRESH_PK),
        "partial_sigs_agg": (psbt, 0, THRESH_PK),
    }
    for name, positional in calls.items():
        with pytest.raises(TypeError, match="positional argument"):
            getattr(psbt_frost, name)(*positional, LEAF_HASH)


def test_a_threshold_key_of_odd_y_is_tweaked_x_only() -> None:
    """The internal key is x-only, so the tweak is BIP341's for either parity.

    The group's own key has an even y, where an x-only tweak and a plain
    one are the same thing. The negated key material -- every secret
    share negated, hence every public share and the threshold public key
    with it -- is the same group with the other parity, and the same
    x-only key: BIP341's output key is one, and a plain tweak of the odd
    point is another.
    """
    odd_sec_shares = tuple(
        (secp256k1.n - int.from_bytes(share, "big")).to_bytes(32, "big")
        for share in SEC_SHARES
    )
    # a compressed point's prefix is 2 or 3, and the other parity is the other
    odd_pub_shares = tuple(
        bytes([5 - share[0]]) + share[1:]
        for share in map(bytes.fromhex, _GROUP["pubshares"][:N])
    )
    odd_thresh_pk = bytes([5 - THRESH_PK[0]]) + X_ONLY
    assert THRESH_PK[0] == 2
    assert odd_thresh_pk[0] == 3
    info = frost.ThresholdInfo(T, odd_thresh_pk, odd_pub_shares)
    frost.validate_threshold_info(info)

    psbt = spending_psbt(TxOut(100_000, ScriptPubKey.p2tr(PubKeyData(THRESH_PK))))
    psbt.inputs[0].taproot_internal_key = X_ONLY
    psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, info)
    spent = prevouts(psbt)

    sec_nonces = {
        my_id: psbt_frost.nonce_gen(
            psbt, 0, my_id, odd_sec_shares[my_id], odd_thresh_pk
        )
        for my_id in SIGNERS
    }
    for my_id in SIGNERS:
        psbt_frost.partial_sign(
            psbt, 0, sec_nonces[my_id], my_id, odd_sec_shares[my_id], odd_thresh_pk
        )
        assert psbt_frost.partial_sig_verify(psbt, 0, my_id, odd_thresh_pk)
    psbt_frost.partial_sigs_agg(psbt, 0, odd_thresh_pk)

    verify_transaction(spent, extract_tx(finalize(psbt)))


def test_the_records_are_proprietary_keys_and_survive_the_encoding() -> None:
    """BIP174's proprietary key, byte for byte, and back off the wire.

    What the psbt codec promises about a key it does not know is that it
    keeps it whole, its type byte included, and re-emits it exactly as it
    arrived. These records are that promise's whole transport, so what is
    checked is the bytes rather than a parse of them.
    """
    psbt = internal_key_psbt()
    run_rounds(psbt)
    unknown = psbt.inputs[0].unknown

    assert set(unknown) == {
        proprietary_key(THRESHOLD_INFO, record_key_data(WRITER)),
        *(proprietary_key(PUB_NONCE, record_key_data(i)) for i in SIGNERS),
        *(proprietary_key(PARTIAL_SIG, record_key_data(i)) for i in SIGNERS),
    }
    # `t`, `n`, and a pair per public share, each integer at the width
    # `btclib.ecc.frost` serializes an identifier in
    assert unknown[
        proprietary_key(THRESHOLD_INFO, record_key_data(WRITER))
    ] == b"".join(
        [
            T.to_bytes(4, "big"),
            N.to_bytes(4, "big"),
            *(i.to_bytes(4, "big") + bytes(PUB_SHARES[i] or b"") for i in range(N)),
        ]
    )
    for my_id in SIGNERS:
        assert len(unknown[proprietary_key(PUB_NONCE, record_key_data(my_id))]) == 66
        assert len(unknown[proprietary_key(PARTIAL_SIG, record_key_data(my_id))]) == 32

    read_back = Psbt.b64decode(psbt.b64encode())
    assert read_back.inputs[0].unknown == unknown
    # and what came back is still a session a Finalizer can finish, which
    # a round trip that lost a byte would not be
    psbt_frost.partial_sigs_agg(read_back, 0, THRESH_PK)
    verify_transaction(prevouts(psbt), extract_tx(finalize(read_back)))


def test_a_session_survives_the_combiner() -> None:
    """Each signer on its own copy, which is how a session is actually run.

    The coordinator hands out the psbt, every signer writes its own
    record into its own copy, and what comes back is merged. BIP174's
    Combiner merges a map as the union of the two, pair by pair, so what
    decides whether both signers' records survive is whether their keys
    differ -- which is what the identifier in the key data buys, and the
    last part of this test measures rather than asserts.

    The secret nonces are the signers' and never travel: only the psbts
    are combined.
    """
    psbt = internal_key_psbt()
    spent = prevouts(psbt)

    round_1 = {my_id: deepcopy(psbt) for my_id in SIGNERS}
    sec_nonces = {
        my_id: psbt_frost.nonce_gen(
            round_1[my_id], 0, my_id, SEC_SHARES[my_id], THRESH_PK
        )
        for my_id in SIGNERS
    }
    for copy in round_1.values():
        assert len(copy.inputs[0].unknown) == 2
    nonces_in = combine(list(round_1.values()))
    assert len(nonces_in.inputs[0].unknown) == 3

    round_2 = {my_id: deepcopy(nonces_in) for my_id in SIGNERS}
    for my_id in SIGNERS:
        psbt_frost.partial_sign(
            round_2[my_id], 0, sec_nonces[my_id], my_id, SEC_SHARES[my_id], THRESH_PK
        )
    signed = combine(list(round_2.values()))
    assert len(signed.inputs[0].unknown) == 5

    for my_id in SIGNERS:
        assert psbt_frost.partial_sig_verify(signed, 0, my_id, THRESH_PK)
    psbt_frost.partial_sigs_agg(signed, 0, THRESH_PK)
    verify_transaction(spent, extract_tx(finalize(signed)))

    # the counterfactual, on the very same copies: the identifier taken
    # out of the key data leaves the two signers writing one key, and the
    # union then keeps whichever psbt was merged last
    keyed_by_subtype = [deepcopy(round_2[my_id]) for my_id in SIGNERS]
    key = proprietary_key(PARTIAL_SIG, THRESH_PK)
    for copy, my_id in zip(keyed_by_subtype, SIGNERS, strict=True):
        psbt_in = copy.inputs[0]
        psbt_in.unknown[key] = psbt_in.unknown.pop(
            proprietary_key(PARTIAL_SIG, record_key_data(my_id))
        )
    merged = combine(keyed_by_subtype)
    assert merged.inputs[0].unknown[key] == keyed_by_subtype[-1].inputs[0].unknown[key]
    assert merged.inputs[0].unknown[key] != keyed_by_subtype[0].inputs[0].unknown[key]


def test_two_participants_knowledge_of_one_group_is_merged() -> None:
    """Key material is keyed by its writer, so partial knowledge adds up.

    `ThresholdInfo` is what one holder knows, and two holders need not
    know the same shares. Keyed by the group alone the two records would
    be one key, and BIP174's Combiner resolves one key by keeping a
    side: whichever psbt was merged last, with the other participant's
    knowledge gone and nothing raised. The writer's identifier in the
    key data is what makes the union the right merge here as it is for
    the two session records, and the second half of this test is that
    counterfactual measured rather than argued.
    """
    psbt = spending_psbt(TxOut(100_000, ScriptPubKey.p2tr(PubKeyData(THRESH_PK))))
    psbt.inputs[0].taproot_internal_key = X_ONLY
    spent = prevouts(psbt)
    left, right = deepcopy(psbt), deepcopy(psbt)
    # neither holder knows all three shares, and each knows a share the
    # other does not
    psbt_frost.add_threshold_info(
        left.inputs[0], 0, group_info((PUB_SHARES[0], PUB_SHARES[1], None))
    )
    psbt_frost.add_threshold_info(
        right.inputs[0], 2, group_info((None, PUB_SHARES[1], PUB_SHARES[2]))
    )
    assert set(left.inputs[0].unknown).isdisjoint(right.inputs[0].unknown)

    merged = combine([left, right])

    assert len(merged.inputs[0].unknown) == 2
    assert psbt_frost.threshold_info(merged.inputs[0], THRESH_PK) == group_info()
    psbt_frost.assert_valid_records(merged.inputs[0])
    # and the session runs over what the merge assembled, which is what
    # the merge is for: participants 0 and 2 sign, and neither holder's
    # record alone names both of them
    run_rounds(merged, signers=(0, 2))
    psbt_frost.partial_sigs_agg(merged, 0, THRESH_PK)
    assert not merged.inputs[0].unknown
    verify_transaction(spent, extract_tx(finalize(merged)))

    # the counterfactual, on those same two records: with the writer out
    # of the key data both land on one key, and the union keeps the last
    keyed_by_group = [deepcopy(left), deepcopy(right)]
    key = proprietary_key(THRESHOLD_INFO, THRESH_PK)
    for copy, writer in zip(keyed_by_group, (0, 2), strict=True):
        psbt_in = copy.inputs[0]
        psbt_in.unknown[key] = psbt_in.unknown.pop(
            proprietary_key(THRESHOLD_INFO, record_key_data(writer))
        )
    erased = combine(keyed_by_group)

    assert len(erased.inputs[0].unknown) == 1
    surviving = erased.inputs[0].unknown[key]
    assert surviving == keyed_by_group[-1].inputs[0].unknown[key]
    # and what it costs, read off the record's own layout: the pair
    # naming participant 0 is in the record the union dropped and in no
    # other, so that share is gone with nothing raised
    pair_0 = (0).to_bytes(4, "big") + bytes(PUB_SHARES[0] or b"")
    assert pair_0 in keyed_by_group[0].inputs[0].unknown[key]
    assert pair_0 not in surviving


def test_two_writers_that_disagree_are_refused() -> None:
    """A merge has a case a union of disjoint keys does not: a conflict.

    Two participants' records are merged rather than picked between, so
    key material nobody can sign with consistently -- one identifier
    with two public shares, or two records disagreeing on the threshold
    or on the size of the group -- has to raise. Picking a side would
    sign under a key the other holder does not have, which is what
    `psbt.combine` does for the fields it knows and cannot do for these.
    """
    psbt = internal_key_psbt()
    written = psbt.inputs[0].unknown[
        proprietary_key(THRESHOLD_INFO, record_key_data(WRITER))
    ]
    counts = written[:8]
    pair = {i: i.to_bytes(4, "big") + bytes(PUB_SHARES[i] or b"") for i in range(N)}

    for key_data, value, err_msg in (
        (
            # participant 1's share, as participant 2 has it, is not the
            # one participant 0 filed
            record_key_data(2),
            counts + (1).to_bytes(4, "big") + bytes(PUB_SHARES[2] or b"") + pair[2],
            "mismatched frost public share of participant 1",
        ),
        (
            record_key_data(2),
            (1).to_bytes(4, "big") + N.to_bytes(4, "big") + pair[1] + pair[2],
            "mismatched frost threshold info of participant 2",
        ),
        (
            record_key_data(2),
            counts[:4] + (N + 1).to_bytes(4, "big") + pair[1] + pair[2],
            "mismatched frost threshold info of participant 2",
        ),
        (
            record_key_data(7),
            counts + pair[1] + pair[2],
            "frost threshold info of participant 7, who is not one of the 3",
        ),
    ):
        broken = _broken(psbt, THRESHOLD_INFO, key_data, value)
        with pytest.raises(BTClibValueError, match=err_msg):
            psbt_frost.threshold_info(broken.inputs[0], THRESH_PK)
        # and the validity check is the merge, so it refuses the same
        with pytest.raises(BTClibValueError, match=err_msg):
            psbt_frost.assert_valid_records(broken.inputs[0])


def test_join_is_not_the_merge_a_session_goes_through() -> None:
    """`join` builds another transaction, so it merges no input of this one.

    Its consistency check refuses one unknown key holding two values, and
    that check reads the psbt's own global map: these records are on an
    input, so two psbts carrying one key with different values join
    rather than being refused -- and the inputs they land on are the two
    they came from, which is why a session is not what `join` merges.
    """
    left = internal_key_psbt()
    right = deepcopy(left)
    right.inputs[0].previous_tx_id = b"\x02" * 32
    key = proprietary_key(THRESHOLD_INFO, record_key_data(WRITER))
    right.inputs[0].unknown[key] = b"\x00" * len(left.inputs[0].unknown[key])

    joined = join([left, right], True, True, False, False)

    assert len(joined.inputs) == 2
    assert [psbt_in.unknown[key] for psbt_in in joined.inputs] == [
        left.inputs[0].unknown[key],
        right.inputs[0].unknown[key],
    ]


def test_the_updater_files_key_material_it_has_checked() -> None:
    """The Updater role, on an input and on an output alike.

    The threshold public key is not a parameter because the record is
    filed under it, and what `add_threshold_info` refuses is key material
    that does not reconstruct it: a public share off the group's own
    polynomial is the way the record can be wrong with every length
    right, and no signer could use it. The writer's own identifier is a
    parameter, and one the group does not have is refused: the record
    says what *that participant* knows, so there is nobody for it to be
    about.
    """
    psbt = spending_psbt(TxOut(100_000, ScriptPubKey.p2tr(PubKeyData(THRESH_PK))))
    info = group_info()

    for psbt_map in (psbt.inputs[0], psbt.outputs[0]):
        assert psbt_frost.add_threshold_info(psbt_map, WRITER, info) == THRESH_PK
        assert psbt_frost.threshold_info(psbt_map, THRESH_PK) == info
        psbt_frost.assert_valid_records(psbt_map)
        assert proprietary_key(THRESHOLD_INFO, record_key_data(WRITER)) in (
            psbt_map.unknown
        )

    tampered = group_info((PUB_SHARES[0], PUB_SHARES[1], FOREIGN_PUB_SHARE))
    with pytest.raises(BTClibValueError, match="do not lie on a single polynomial"):
        psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, tampered)

    # the identifiers of the group are 0 to n-1: one below, one past and
    # a far one all name nobody
    for my_id in (-1, N, 7):
        with pytest.raises(
            BTClibValueError, match=f"frost participant {my_id} is not one of"
        ):
            psbt_frost.add_threshold_info(psbt.inputs[0], my_id, info)

    psbt.inputs[0].unknown = {}
    err_msg = "no frost threshold info for threshold public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_frost.threshold_info(psbt.inputs[0], THRESH_PK)


def test_only_the_public_shares_the_psbt_knows_travel() -> None:
    """An `(id, pubshare)` pair list, not an `n`-slot array with a hole.

    `ThresholdInfo` allows a share to be unknown to its holder, so the
    record carries the ones it has, each under its own identifier. What
    that costs is a participant nobody can hold to a partial signature --
    there is no key to check one against -- so a session naming it is
    refused rather than run.
    """
    psbt = spending_psbt(TxOut(100_000, ScriptPubKey.p2tr(PubKeyData(THRESH_PK))))
    psbt.inputs[0].taproot_internal_key = X_ONLY
    info = group_info((PUB_SHARES[0], None, PUB_SHARES[2]))
    psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, info)

    assert psbt_frost.threshold_info(psbt.inputs[0], THRESH_PK) == info
    key = proprietary_key(THRESHOLD_INFO, record_key_data(WRITER))
    assert len(psbt.inputs[0].unknown[key]) == 2 * 4 + 2 * (4 + 33)

    err_msg = "no frost public share of participant 1"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_frost.nonce_gen(psbt, 0, 1, SEC_SHARES[1], THRESH_PK)

    # and the same refusal from the other side: a nonce that arrived for
    # that participant is a session nobody else can verify
    psbt_frost.nonce_gen(psbt, 0, 0, SEC_SHARES[0], THRESH_PK)
    psbt.inputs[0].unknown[proprietary_key(PUB_NONCE, record_key_data(1))] = (
        b"\x02" * 66
    )
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    for my_id in (-1, N, 7):
        with pytest.raises(
            BTClibValueError, match=f"frost participant {my_id} is not one of"
        ):
            psbt_frost.nonce_gen(psbt, 0, my_id, SEC_SHARES[0], THRESH_PK)


def test_a_session_the_psbt_does_not_describe() -> None:
    """Each way a psbt can fail to say what is being signed.

    A Signer derives the session rather than choosing it, so every one of
    these is a psbt that cannot be signed rather than one that signs
    something else -- which is the difference the checks buy.
    """
    # no key material for the key the caller names
    psbt = internal_key_psbt()
    psbt.inputs[0].unknown = {}
    with pytest.raises(BTClibValueError, match="no frost threshold info"):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    # an internal key that is not the threshold public key: BIP328
    # derivation is MuSig2's, so there is nothing to derive to here
    psbt = internal_key_psbt()
    psbt.inputs[0].taproot_internal_key = INTERNAL_KEY[1:]
    err_msg = "is neither the taproot output key nor the internal key"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    # no internal key either, and an output key that is somebody else's
    psbt = internal_key_psbt()
    psbt.inputs[0].taproot_internal_key = b""
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    # the merkle root of another script tree: the tweak is then not the
    # one the output key commits to, and the tweaked key is not it either
    psbt = internal_key_psbt()
    psbt.inputs[0].taproot_merkle_root = b"\x01" * 32
    with pytest.raises(BTClibValueError, match="is not the key being spent"):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    # an output key that is another one, sorting below the tweaked key and
    # above it: what is refused is a key that differs, not one of the two
    # orders it can differ in
    for other_key in (bytes(32), b"\xff" * 32):
        psbt = spending_psbt(
            TxOut(100_000, ScriptPubKey(serialize(["OP_1", other_key])))
        )
        psbt.inputs[0].taproot_internal_key = X_ONLY
        psbt_frost.add_threshold_info(psbt.inputs[0], WRITER, group_info())
        with pytest.raises(BTClibValueError, match="is not the key being spent"):
            psbt_frost.session_context(psbt, 0, THRESH_PK)


def test_a_round_that_the_other_round_has_not_reached() -> None:
    """Each round needs what the one before wrote, and says what is missing."""
    # no nonce at all: there is no session to build a context of
    psbt = internal_key_psbt()
    with pytest.raises(
        BTClibValueError, match="no frost public nonce for threshold public key"
    ):
        psbt_frost.session_context(psbt, 0, THRESH_PK)

    # round 2 without this signer's own nonce, the other's being there
    run_rounds(psbt)
    without_nonce = deepcopy(psbt)
    del without_nonce.inputs[0].unknown[proprietary_key(PUB_NONCE, record_key_data(0))]
    with pytest.raises(
        BTClibValueError, match="no frost public nonce of participant 0"
    ):
        psbt_frost.partial_sign(
            without_nonce, 0, bytearray(64), 0, SEC_SHARES[0], THRESH_PK
        )

    # a partial signature nobody sent
    without_sig = deepcopy(psbt)
    del without_sig.inputs[0].unknown[proprietary_key(PARTIAL_SIG, record_key_data(1))]
    with pytest.raises(
        BTClibValueError, match="no frost partial signature of participant 1"
    ):
        psbt_frost.partial_sig_verify(without_sig, 0, 1, THRESH_PK)

    # and aggregation names who did not sign: the signers of a session
    # are the ones that published a nonce, so this is a subset one short
    # of itself rather than a group short of its threshold
    with pytest.raises(
        BTClibValueError, match="missing frost partial signature of participant 1"
    ):
        psbt_frost.partial_sigs_agg(without_sig, 0, THRESH_PK)


def test_partial_signatures_that_do_not_add_up() -> None:
    """Refuse to aggregate a partial signature of another session.

    Such a signature verifies alone and adds up to nothing, and catching
    that is the Finalizer's check: the aggregate signature is verified
    before it is written, so a psbt combined out of two sessions is
    refused rather than finalized into a transaction the network drops.
    """
    psbt = internal_key_psbt()
    run_rounds(psbt)
    key = proprietary_key(PARTIAL_SIG, record_key_data(0))
    psig = psbt.inputs[0].unknown[key]
    # the same signer's signature, one bit different: every other partial
    # signature still verifies, and the total does not
    psbt.inputs[0].unknown[key] = (
        (int.from_bytes(psig, "big") + 1) % secp256k1.n
    ).to_bytes(32, "big")

    assert not psbt_frost.partial_sig_verify(psbt, 0, 0, THRESH_PK)
    assert psbt_frost.partial_sig_verify(psbt, 0, 1, THRESH_PK)
    with pytest.raises(BTClibValueError, match="do not add up to a signature of"):
        psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK)


def test_a_session_signing_for_a_sig_hash_type_of_its_own() -> None:
    """SIGHASH_ALL, spelled out: 65 bytes of signature, and the type appended.

    BIP341 appends the type to the 64 bytes whenever it is not the
    default one, and the input is what asks for it -- so the message
    every signer commits to changes with it, and the aggregate signature
    carries the byte that says so.
    """
    psbt = internal_key_psbt()
    psbt.inputs[0].sig_hash_type = 1  # ALL
    spent = prevouts(psbt)
    run_rounds(psbt)

    psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK)
    signature = psbt.inputs[0].taproot_key_spend_signature
    assert len(signature) == 65
    assert signature[-1] == 1
    verify_transaction(spent, extract_tx(finalize(psbt)))


def test_records_of_another_session_are_not_read_as_this_one() -> None:
    """A session is what is filed under its own key and leaf, and no more.

    One input may carry a session per group and per leaf, so the filter
    that reads one out of the records is an equality on the key data
    after the identifier: an ordering would take in whatever sorts the
    right way, and what it took in would be a nonce of a session
    committing to another key.

    Two foreign sessions here, one threshold key sorting above the real
    one and one below, so neither direction of a weakened comparison can
    pass. An unknown record that is not this module's at all goes in
    beside them and is still there at the end: dropping the session is
    not dropping whatever else the input carries.
    """
    psbt = internal_key_psbt()
    spent = prevouts(psbt)
    run_rounds(psbt)
    psbt_in = psbt.inputs[0]

    # built from points rather than from bytes, the records of a session
    # this module wrote holding keys that are keys
    keys = [bytes_from_point(mult(scalar)) for scalar in range(2, 200)]
    below = [key for key in keys if key < THRESH_PK]
    above = [key for key in keys if key > THRESH_PK]
    assert below, "no key of these points sorts below the group's own"
    assert above, "no key of these points sorts above the group's own"
    nonce = psbt_in.unknown[proprietary_key(PUB_NONCE, record_key_data(0))]
    psig = psbt_in.unknown[proprietary_key(PARTIAL_SIG, record_key_data(0))]
    foreign_keys = set()
    for foreign in (below[0], above[0]):
        key_data = (2).to_bytes(4, "big") + foreign
        psbt_in.unknown[proprietary_key(PUB_NONCE, key_data)] = nonce
        psbt_in.unknown[proprietary_key(PARTIAL_SIG, key_data)] = psig
        foreign_keys |= {
            proprietary_key(PUB_NONCE, key_data),
            proprietary_key(PARTIAL_SIG, key_data),
        }
    stranger = b"\xfc" + b"\x05" + b"other" + b"\x00"
    psbt_in.unknown[stranger] = b"whatever this means"

    psbt_frost.partial_sigs_agg(psbt, 0, THRESH_PK)

    assert set(psbt_in.unknown) == {stranger, *foreign_keys}
    verify_transaction(spent, extract_tx(finalize(psbt)))


def _broken(psbt: Psbt, subtype: int, key_data: bytes, value: bytes) -> Psbt:
    """Return a copy of the psbt with one record written into its input."""
    copy = deepcopy(psbt)
    copy.inputs[0].unknown[proprietary_key(subtype, key_data)] = value
    return copy


def test_assert_valid_records_reads_what_the_codec_cannot() -> None:
    """A proprietary record is an unknown key, and a codec asks it nothing.

    So the shape a signer will read these records at is checked here or
    nowhere, and every record refused below is one the codec itself
    accepts, round-trips and hands on. The last two refusals are
    `btclib.ecc.frost`'s own: key material is held to the reconstruction
    that module makes, which is what a psbt carrying it is for.
    """
    psbt = internal_key_psbt()
    run_rounds(psbt)
    psbt_frost.assert_valid_records(psbt.inputs[0])
    written = record_key_data(WRITER)
    info = psbt.inputs[0].unknown[proprietary_key(THRESHOLD_INFO, written)]
    counts = info[:8]
    pair_0 = (0).to_bytes(4, "big") + bytes(PUB_SHARES[0] or b"")

    # each of these replaces the record the Updater wrote, the key data
    # being the same one, so what is measured is that record alone and
    # not a merge of it with a well-formed neighbour -- except the first,
    # whose whole subject is a key data of the wrong length
    for key_data, value, err_msg in (
        (written[:-1], info, "invalid frost threshold info key length: 36"),
        (
            written,
            info[:-1],
            f"invalid frost threshold info length: {len(info) - 1} bytes",
        ),
        (
            written,
            T.to_bytes(4, "big") + (200).to_bytes(4, "big"),
            "invalid frost participant count: 200",
        ),
        (
            written,
            counts + (9).to_bytes(4, "big") + pair_0[4:],
            "invalid frost participant identifier: 9",
        ),
        (
            written,
            counts + pair_0 + pair_0,
            "invalid frost participant identifier: 0",
        ),
        (written, counts, "At least t pubshares must be present."),
        (
            # a real public share of the group, under the identifier of
            # another participant: what binds the two is the pair, so
            # this is the one way the record can be wrong with every
            # length right and every point on the polynomial
            written,
            counts + pair_0 + (1).to_bytes(4, "big") + bytes(PUB_SHARES[2] or b""),
            "The provided key material is incorrect",
        ),
    ):
        with pytest.raises(BTClibValueError, match=err_msg):
            psbt_frost.assert_valid_records(
                _broken(psbt, THRESHOLD_INFO, key_data, value).inputs[0]
            )

    for subtype, what, size in (
        (PUB_NONCE, "frost public nonce", 66),
        (PARTIAL_SIG, "frost partial signature", 32),
    ):
        broken = _broken(psbt, subtype, record_key_data(0)[:-1], bytes(size))
        with pytest.raises(BTClibValueError, match=f"invalid {what} key length: 36"):
            psbt_frost.assert_valid_records(broken.inputs[0])
        broken = _broken(psbt, subtype, record_key_data(0), bytes(size - 1))
        with pytest.raises(
            BTClibValueError, match=f"invalid {what} length: {size - 1}"
        ):
            psbt_frost.assert_valid_records(broken.inputs[0])
