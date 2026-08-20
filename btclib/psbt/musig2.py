# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The three roles BIP373 defines, over `btclib.ecc.musig2`.

https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki

`btclib.psbt.psbt_in` and `psbt_out` carry the four MuSig2 fields; what
is here is what they mean. One function per role, and the roles are
BIP373's own:

- **Updater**: `add_participant_pub_keys` aggregates a list of keys and
  files it under the aggregate key it makes, on an input or an output;
- **Signer**: `nonce_gen` writes the public nonce of round 1 and
  `partial_sign` the partial signature of round 2;
- **Finalizer**: `partial_sigs_agg` adds the partial signatures up into
  the BIP340 signature the spend needs, writes it to
  `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG`, and drops the
  session.

**Where the secret nonce lives is the caller's business, and this module
holds nothing.** `nonce_gen` hands back the `bytearray` that
`btclib.ecc.musig2.sign` consumes, and `partial_sign` takes it back;
between the two rounds it is in the caller's hands and never in the psbt,
which travels. That is not squeamishness about serialization: a secnonce
that signs twice hands out the private key by elementary algebra, and a
psbt is a file that gets copied, combined and re-read. A session object
owned by btclib would have to be as careful as the bytearray already is,
with a lifetime the library cannot see the end of -- so the decision is
to own no state at all, which is also the answer the libsecp256k1 musig
module gives (an opaque secnonce its own API invalidates after use) and
the shape an interactive threshold scheme needs (issue #257).

What a psbt says, and what it therefore need not be told, is how the
aggregate key reaches the output being spent. Four ways, and BIP373
publishes a vector for each:

- the aggregate key **is** the taproot output key: nothing to tweak;
- the aggregate key is the **internal key**: one x-only tweak, the BIP341
  commitment to the merkle root the input carries;
- the aggregate key is a **key in a leaf script**: nothing to tweak, and
  the message is BIP342's rather than BIP341's -- which is why every
  function here takes the tapleaf hash the key data carries;
- the internal key is **derived** from the aggregate key: BIP328
  derivation, i.e. one plain tweak per step of the path in
  `PSBT_IN_TAP_BIP32_DERIVATION`, then the x-only one.

`session_context` is where those four are read off the psbt, and it is
public because a signer needs it for what BIP327 asks beyond signing:
`btclib.ecc.musig2.partial_sig_verify_` against another signer's nonce.
It returns the `KeyAggContext` it built the session on, alongside the
session itself: `partial_sigs_agg` is a caller that needs the tweaked
key, and the alternative -- aggregating the participants over again to
get it -- is the quadratic shape issue #1046 fixed.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import NamedTuple

from btclib.alias import Octets
from btclib.bip32 import BIP328_CHAIN_CODE, pub_key_derivation_tweaks
from btclib.curves import secp256k1
from btclib.curves.sec_point import bytes_from_point
from btclib.ecc import musig2, ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, tagged_hash
from btclib.psbt.psbt import (
    Psbt,
    leaf_script,
    prevouts,
    single_leaf_key,
    taproot_sig_hash,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import (
    MUSIG2_PUB_KEY_SIZE,
    assert_valid_musig2_pub_key,
)
from btclib.script import type_and_payload
from btclib.to_prv_key import PrvKey
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "Session",
    "add_participant_pub_keys",
    "assert_valid_participants",
    "nonce_gen",
    "partial_sig_verify",
    "partial_sign",
    "partial_sigs_agg",
    "session_context",
]


def add_participant_pub_keys(
    psbt_map: PsbtIn | PsbtOut,
    participant_pub_keys: Sequence[Octets],
    *,
    sort: bool = False,
) -> bytes:
    """Add the participants of one aggregate key, and return that key.

    The Updater role, and the aggregate key is not a parameter because it
    is not a choice: `KeyAgg` computes it from the list, so a caller
    handing in both could file a list under a key it does not aggregate
    to -- which is exactly the field's meaning gone, and no reader could
    tell.

    sort=True aggregates the sorted list, as BIP327's `KeySort` sorts it
    and as BIP373 requires whenever sorting was used at all: the order is
    part of the key, so it is stored in the order it was aggregated in.
    """
    # the order is part of the aggregate key, so this decides which key
    # the participants are filed under
    assert_type(sort, bool, "sort")
    keys = musig2.key_sort(participant_pub_keys) if sort else participant_pub_keys
    aggregate_pub_key = bytes_from_point(musig2.key_agg(keys).Q, secp256k1)
    psbt_map.musig2_participant_pub_keys[aggregate_pub_key] = [
        bytes_from_octets(key, MUSIG2_PUB_KEY_SIZE) for key in keys
    ]
    return aggregate_pub_key


def _participants(psbt_in: PsbtIn, aggregate_pub_key: bytes) -> list[bytes]:
    """Return the participants of an aggregate key, in aggregation order."""
    participants = psbt_in.musig2_participant_pub_keys.get(aggregate_pub_key)
    if not participants:
        err_msg = "no musig2 participants for aggregate key "
        err_msg += aggregate_pub_key.hex()
        raise BTClibValueError(err_msg)
    return participants


def _derivation_tweaks(psbt_in: PsbtIn, aggregate_pub_key: bytes) -> list[bytes]:
    """Return the BIP328 tweaks from the aggregate key to the internal one.

    The path is the one `PSBT_IN_TAP_BIP32_DERIVATION` files the internal
    key under, and what says it starts at the aggregate key is the master
    fingerprint: BIP328's synthetic xpub is the aggregate key with
    `BIP328_CHAIN_CODE`, so its fingerprint is hash160 of that key.
    BIP373 lets that field be assumed to be BIP328 derivation whenever no
    `PSBT_GLOBAL_XPUB` names a synthetic xpub, which is what makes the
    fingerprint enough to recognize it.
    """
    internal_key = psbt_in.taproot_internal_key
    fingerprint = hash160(aggregate_pub_key)[:4]
    derivation = psbt_in.taproot_hd_key_paths.get(internal_key)
    if derivation is None or derivation[1].master_fingerprint != fingerprint:
        err_msg = "no BIP328 derivation from musig2 aggregate key "
        err_msg += f"{aggregate_pub_key.hex()} to taproot internal key "
        err_msg += internal_key.hex()
        raise BTClibValueError(err_msg)
    return pub_key_derivation_tweaks(
        aggregate_pub_key, BIP328_CHAIN_CODE, derivation[1].der_path
    )


def _tweaks(
    psbt_in: PsbtIn, aggregate_pub_key: bytes, leaf_hash: bytes, output_key: bytes
) -> tuple[list[bytes], list[bool]]:
    """Return the tweaks between the aggregate key and what is spent.

    Which of BIP373's four ways this psbt is written in is read here, and
    the module docstring lists them. A psbt saying none of them is
    refused rather than signed under an untweaked key: the partial
    signatures would add up to a signature valid under a key the output
    does not commit to, i.e. to nothing at all, and the psbt is where a
    signer can still notice.
    """
    x_only_aggregate = aggregate_pub_key[1:]

    # a key in a script signs as itself: the taproot tweak belongs to the
    # output key, which the script path does not sign for
    if leaf_hash:
        return [], []

    if psbt_in.taproot_internal_key:
        tweaks = (
            []
            if psbt_in.taproot_internal_key == x_only_aggregate
            else _derivation_tweaks(psbt_in, aggregate_pub_key)
        )
        # BIP341: the output key commits to the internal key and the root
        # of the script tree, which is empty for an output with no scripts
        taproot_tweak = tagged_hash(
            b"TapTweak",
            psbt_in.taproot_internal_key + psbt_in.taproot_merkle_root,
        )
        return [*tweaks, taproot_tweak], [False] * len(tweaks) + [True]

    if output_key == x_only_aggregate:
        return [], []

    err_msg = f"musig2 aggregate key {aggregate_pub_key.hex()} is neither "
    err_msg += "the taproot output key nor the internal key of the input"
    raise BTClibValueError(err_msg)


class _SessionParts(NamedTuple):
    """What a session is, before the nonces of round 1 exist.

    `tweaked_pub_key` is the aggregate key **as tweaked for this session**,
    compressed, and it is what the nonces and the partial signatures of
    the input are keyed by -- not the aggregate key the participants are
    filed under, which is the untweaked one. The two differ in exactly
    the cases where the aggregate key is not what the spend verifies
    against: Bitcoin Core keys these fields by its `plain_pub`, which is
    the aggregate key carried through the derivation and the taproot
    tweak (`SignMuSig2` in script/sign.cpp), and a psbt keyed either
    other way is one no other implementation reads.

    `key_agg_ctx` is the `KeyAggContext` `tweaked_pub_key` was read off of
    -- carried along rather than dropped, so that a caller needing it
    (`session_context`, on to `partial_sigs_agg`) does not aggregate the
    participants a second time to get it back.
    """

    participants: list[bytes]
    tweaks: list[bytes]
    is_xonly: list[bool]
    msg: bytes
    tweaked_pub_key: bytes
    key_agg_ctx: musig2.KeyAggContext


def _session_parts(
    psbt: Psbt, vin_i: int, aggregate_pub_key: bytes, leaf_hash: bytes
) -> _SessionParts:
    """Return everything a signer derives from the psbt before round 1.

    Which is why it is not `session_context` itself: round 1 needs the
    message -- BIP327 binds the nonce to it -- and the aggregate nonce it
    is about to contribute to is not there yet.
    """
    psbt_in = psbt.inputs[vin_i]
    output_key = type_and_payload(prevouts(psbt)[vin_i].script_pub_key.script)[1]
    participants = _participants(psbt_in, aggregate_pub_key)
    tweaks, is_xonly = _tweaks(psbt_in, aggregate_pub_key, leaf_hash, output_key)
    msg = taproot_sig_hash(psbt, vin_i, leaf_hash=leaf_hash)

    # what the tweaks were read off the psbt for: the key the signatures
    # will verify under has to be the key the spend needs, which is the
    # output key of a key path spend and the script's own key otherwise.
    # A merkle root, a derivation path or a tapleaf hash that does not
    # belong to this input fails here, before a secret nonce is spent on
    # a signature nobody can use
    key_agg_ctx = musig2.key_agg_and_tweak(participants, tweaks, is_xonly)
    expected = _script_key(psbt_in, leaf_hash) if leaf_hash else output_key
    if key_agg_ctx.x_only_pub_key != expected:
        err_msg = f"the tweaked musig2 key {key_agg_ctx.x_only_pub_key.hex()} is not "
        err_msg += f"the key being spent, {expected.hex()}"
        raise BTClibValueError(err_msg)

    return _SessionParts(
        participants,
        tweaks,
        is_xonly,
        msg,
        bytes_from_point(key_agg_ctx.Q, secp256k1),
        key_agg_ctx,
    )


def _script_key(psbt_in: PsbtIn, leaf_hash: bytes) -> bytes:
    """Return the x-only key the leaf script of a script path spend signs with.

    BIP342 spends a leaf with what its own script asks for, so what the
    tweaked key is checked against is a key in that script -- the one and
    only one of a `<key> OP_CHECKSIG` leaf, which is the shape a MuSig2
    aggregate key in a script takes and the shape BIP373's own vector
    uses. `single_leaf_key` is the same question the Finalizer asks of
    the same field, and it is asked in one place for that reason.
    """
    script, _ = leaf_script(psbt_in, leaf_hash)
    return single_leaf_key(script)


class Session(NamedTuple):
    """A BIP327 session, and the `KeyAggContext` it was built on.

    `context` is what `btclib.ecc.musig2.sign` and `partial_sig_verify_`
    take. `key_agg_ctx` is the aggregation `_session_parts` already did to
    reach it -- handed back rather than left for a caller that needs the
    tweaked key, `x_only_pub_key` included, to aggregate the participants
    a second time.
    """

    context: musig2.SessionContext
    key_agg_ctx: musig2.KeyAggContext


def session_context(
    psbt: Psbt, vin_i: int, aggregate_pub_key: Octets, *, leaf_hash: Octets = b""
) -> Session:
    """Return the BIP327 session the psbt describes, and its key aggregation.

    The aggregate nonce is the sum of the public nonces the input carries
    for this session, so every signer that has published one is in it: a
    context built before the last nonce arrives is a different context,
    and the partial signatures made against the two do not add up.
    `btclib.ecc.musig2.partial_sig_verify_` is what catches that, and
    this is what it takes.
    """
    aggregate_pub_key = bytes_from_octets(aggregate_pub_key, MUSIG2_PUB_KEY_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    parts = _session_parts(psbt, vin_i, aggregate_pub_key, leaf_hash)
    pub_nonces = _session_pub_nonces(
        psbt.inputs[vin_i], parts.tweaked_pub_key, leaf_hash
    )
    if not pub_nonces:
        err_msg = "no musig2 public nonce for aggregate key "
        err_msg += aggregate_pub_key.hex()
        raise BTClibValueError(err_msg)
    # in aggregation order and not in the order the map holds them: an
    # aggregate nonce is a sum, so the order is not what it changes --
    # what it changes is which signer a missing nonce is missing for,
    # and `partial_sig_verify` reports that as a False of its own
    agg_nonce = musig2.nonce_agg(
        [pub_nonces[key] for key in parts.participants if key in pub_nonces]
    )
    context = musig2.SessionContext(
        agg_nonce, parts.participants, parts.tweaks, parts.is_xonly, parts.msg
    )
    return Session(context, parts.key_agg_ctx)


def _key_data(
    participant_pub_key: bytes, tweaked_pub_key: bytes, leaf_hash: bytes
) -> bytes:
    """Return the key data BIP373 files a nonce and a partial signature under.

    The tweaked key, not the aggregate key of the participants field:
    `_SessionParts` says why, and it is the one place the difference
    between the two has to be got right.
    """
    return participant_pub_key + tweaked_pub_key + leaf_hash


def _session_pub_nonces(
    psbt_in: PsbtIn, tweaked_pub_key: bytes, leaf_hash: bytes
) -> dict[bytes, bytes]:
    """Return the public nonces of one session, by participant key."""
    return {
        key_data[:MUSIG2_PUB_KEY_SIZE]: pub_nonce
        for key_data, pub_nonce in psbt_in.musig2_pub_nonces.items()
        if key_data[MUSIG2_PUB_KEY_SIZE:] == tweaked_pub_key + leaf_hash
    }


def _session_partial_sigs(
    psbt_in: PsbtIn, tweaked_pub_key: bytes, leaf_hash: bytes
) -> dict[bytes, bytes]:
    """Return the partial signatures of one session, by participant key."""
    return {
        key_data[:MUSIG2_PUB_KEY_SIZE]: psig
        for key_data, psig in psbt_in.musig2_partial_sigs.items()
        if key_data[MUSIG2_PUB_KEY_SIZE:] == tweaked_pub_key + leaf_hash
    }


def nonce_gen(
    psbt: Psbt,
    vin_i: int,
    prv_key: PrvKey,
    aggregate_pub_key: Octets,
    *,
    leaf_hash: Octets = b"",
    extra_in: Octets | None = None,
) -> bytearray:
    """Write the public nonce of round 1, and return the secret one.

    The Signer role, first half. The returned bytearray is what
    `partial_sign` consumes and what must not be copied, written down or
    put in the psbt: the module docstring says why the decision is to
    hand it back rather than keep it.

    The nonce is bound to everything BIP327 lets it be bound to -- the
    signer's key, the aggregate key of the session and the message --
    because all three are in the psbt, and a nonce derived from fewer of
    them is one a faulty random source can repeat across sessions.
    """
    aggregate_pub_key = bytes_from_octets(aggregate_pub_key, MUSIG2_PUB_KEY_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    parts = _session_parts(psbt, vin_i, aggregate_pub_key, leaf_hash)
    pub_key = musig2.individual_pub_key(prv_key)
    if pub_key not in parts.participants:
        err_msg = f"{pub_key.hex()} is not a participant of aggregate key "
        err_msg += aggregate_pub_key.hex()
        raise BTClibValueError(err_msg)

    sec_nonce, pub_nonce = musig2.nonce_gen(
        prv_key, pub_key, parts.tweaked_pub_key[1:], parts.msg, extra_in
    )
    key_data = _key_data(pub_key, parts.tweaked_pub_key, leaf_hash)
    psbt.inputs[vin_i].musig2_pub_nonces[key_data] = pub_nonce
    return sec_nonce


def partial_sign(
    psbt: Psbt,
    vin_i: int,
    sec_nonce: bytearray,
    prv_key: PrvKey,
    aggregate_pub_key: Octets,
    *,
    leaf_hash: Octets = b"",
) -> bytes:
    """Write the partial signature of round 2, and return it.

    The Signer role, second half. The secnonce is consumed by
    `btclib.ecc.musig2.sign`, which zeroes it: this function cannot be
    called twice with one nonce, and that is the point.

    The signature is verified before it is written, against the session
    the psbt describes: a signer that publishes a partial signature of a
    session it got wrong has published a number the others cannot use and
    cannot make it un-published.
    """
    aggregate_pub_key = bytes_from_octets(aggregate_pub_key, MUSIG2_PUB_KEY_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    psbt_in = psbt.inputs[vin_i]
    pub_key = musig2.individual_pub_key(prv_key)
    tweaked_pub_key = _session_parts(
        psbt, vin_i, aggregate_pub_key, leaf_hash
    ).tweaked_pub_key
    key_data = _key_data(pub_key, tweaked_pub_key, leaf_hash)
    pub_nonce = psbt_in.musig2_pub_nonces.get(key_data)
    if pub_nonce is None:
        err_msg = f"no musig2 public nonce of {pub_key.hex()} for aggregate key "
        err_msg += aggregate_pub_key.hex()
        raise BTClibValueError(err_msg)

    session = session_context(psbt, vin_i, aggregate_pub_key, leaf_hash=leaf_hash)
    psig = musig2.sign(sec_nonce, prv_key, session.context)
    if not musig2.partial_sig_verify_(psig, pub_nonce, pub_key, session.context):
        # unreachable short of a defect in either this module or `sign`:
        # the context is the one the signature was just made against.
        # It stays because what it costs is one verification against a
        # partial signature that no other signer can be told to ignore
        raise BTClibValueError("invalid musig2 partial signature")  # pragma: no cover
    psbt_in.musig2_partial_sigs[key_data] = psig
    return psig


def partial_sig_verify(
    psbt: Psbt,
    vin_i: int,
    participant_pub_key: Octets,
    aggregate_pub_key: Octets,
    *,
    leaf_hash: Octets = b"",
) -> bool:
    """Verify one participant's partial signature, as the psbt holds it.

    What BIP327 asks every signer to do before aggregating, over the psbt
    the partial signature arrived in: the nonce it is checked against is
    the one the same input carries for the same participant, so a
    signature that was made against another session answers False here
    rather than at aggregation time, where the only news is that the
    total does not verify.
    """
    aggregate_pub_key = bytes_from_octets(aggregate_pub_key, MUSIG2_PUB_KEY_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    participant_pub_key = bytes_from_octets(participant_pub_key, MUSIG2_PUB_KEY_SIZE)
    psbt_in = psbt.inputs[vin_i]
    tweaked_pub_key = _session_parts(
        psbt, vin_i, aggregate_pub_key, leaf_hash
    ).tweaked_pub_key
    key_data = _key_data(participant_pub_key, tweaked_pub_key, leaf_hash)
    psig = psbt_in.musig2_partial_sigs.get(key_data)
    pub_nonce = psbt_in.musig2_pub_nonces.get(key_data)
    if psig is None or pub_nonce is None:
        err_msg = f"no musig2 partial signature of {participant_pub_key.hex()} "
        err_msg += f"for aggregate key {aggregate_pub_key.hex()}"
        raise BTClibValueError(err_msg)
    session = session_context(psbt, vin_i, aggregate_pub_key, leaf_hash=leaf_hash)
    return musig2.partial_sig_verify_(
        psig, pub_nonce, participant_pub_key, session.context
    )


def partial_sigs_agg(
    psbt: Psbt, vin_i: int, aggregate_pub_key: Octets, *, leaf_hash: Octets = b""
) -> ssa.Sig:
    """Aggregate the session's partial signatures, and drop the session.

    The Finalizer role. The BIP340 signature goes where the spend reads
    it -- `PSBT_IN_TAP_KEY_SIG` for a key path spend, and
    `PSBT_IN_TAP_SCRIPT_SIG` under the key and tapleaf hash for a script
    path one -- with the sig_hash type appended when the input asks for
    one other than the default, as BIP341 appends it.

    Every participant must have signed: MuSig2 is n-of-n, so a missing
    partial signature is not a smaller quorum but an aggregate signature
    that verifies under nothing.

    The three MuSig2 fields of that session are then removed. What
    replaces them is the signature itself, and a nonce that has been used
    is worse than useless: keeping it invites a second session with the
    same nonce, which is the one thing that hands out a private key.
    """
    aggregate_pub_key = bytes_from_octets(aggregate_pub_key, MUSIG2_PUB_KEY_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    psbt_in = psbt.inputs[vin_i]
    session = session_context(psbt, vin_i, aggregate_pub_key, leaf_hash=leaf_hash)
    tweaked_pub_key = bytes_from_point(session.key_agg_ctx.Q, secp256k1)
    partial_sigs = _session_partial_sigs(psbt_in, tweaked_pub_key, leaf_hash)
    missing = [key for key in session.context.pub_keys if key not in partial_sigs]
    if missing:
        err_msg = "missing musig2 partial signature of "
        err_msg += ", ".join(key.hex() for key in missing)
        raise BTClibValueError(err_msg)

    sig = musig2.partial_sig_agg(
        [partial_sigs[key] for key in session.context.pub_keys], session.context
    )
    x_only_pub_key = session.key_agg_ctx.x_only_pub_key
    if not ssa.verify_(session.context.msg, x_only_pub_key, sig):
        # a partial signature that verifies on its own and does not add
        # up is what a peer sending one of another session produces, so
        # this is the Finalizer's check and not a belt-and-braces one
        err_msg = "the musig2 partial signatures do not add up to a signature "
        err_msg += f"of {x_only_pub_key.hex()}"
        raise BTClibValueError(err_msg)

    signature = sig.serialize()
    if psbt_in.sig_hash_type:
        # BIP341: the type is appended, and its absence is SIGHASH_DEFAULT
        signature += psbt_in.sig_hash_type.to_bytes(1, "big")
    if leaf_hash:
        psbt_in.taproot_script_spend_signatures[x_only_pub_key + leaf_hash] = signature
    else:
        psbt_in.taproot_key_spend_signature = signature

    _drop_session(psbt_in, aggregate_pub_key, tweaked_pub_key, leaf_hash)
    return sig


def _drop_session(
    psbt_in: PsbtIn,
    aggregate_pub_key: bytes,
    tweaked_pub_key: bytes,
    leaf_hash: bytes,
) -> None:
    """Remove the nonces, the partial signatures and the participants.

    Two keys, because the fields are keyed by two: the nonces and the
    partial signatures by the tweaked key, the participants by the
    aggregate key they aggregate to.
    """
    tail = tweaked_pub_key + leaf_hash
    for field in (psbt_in.musig2_pub_nonces, psbt_in.musig2_partial_sigs):
        for key_data in [k for k in field if k[MUSIG2_PUB_KEY_SIZE:] == tail]:
            del field[key_data]
    psbt_in.musig2_participant_pub_keys.pop(aggregate_pub_key, None)


def assert_valid_participants(psbt_map: PsbtIn | PsbtOut) -> None:
    """Raise unless every participant list aggregates to the key it is under.

    The check `assert_valid` cannot make: it is `KeyAgg` over the list,
    which is the aggregation this module exists to do, and a codec that
    depended on it would depend on a signing scheme. What it catches is
    the one way the field can be wrong while every length is right --
    a list that is not the aggregate key's -- which no signer can use and
    no Updater should have written.
    """
    for aggregate_pub_key, participants in psbt_map.musig2_participant_pub_keys.items():
        assert_valid_musig2_pub_key(aggregate_pub_key, "musig2 aggregate pub key")
        computed = bytes_from_point(musig2.key_agg(participants).Q, secp256k1)
        if computed != aggregate_pub_key:
            err_msg = f"musig2 participants aggregate to {computed.hex()}, "
            err_msg += f"not to {aggregate_pub_key.hex()}"
            raise BTClibValueError(err_msg)
