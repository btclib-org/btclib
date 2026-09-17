# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A FROST session carried through a psbt, over `btclib.ecc.frost`.

BIP445 specifies nonce generation, partial signing and aggregation, and
says nothing about psbt transport; no psbt BIP assigns FROST type bytes.
So the session is written into the key space BIP174 reserves for
proprietary use, under the identifier `btclib`.

**No other wallet reads these fields, and none is meant to.** A psbt
carrying them is useful among btclib participants and nowhere else:
BIP174 says of the proprietary type that "there is no expectation that
any publicly available software be able to understand any specific
meanings of it and the subtypes", and everything below is inside that
sentence. Another implementation keeps these records whole, as it keeps
any unknown key, and can say nothing about the session they describe.

**When a psbt BIP assigns FROST type bytes, these fields are dropped,
not aliased.** No compatibility shim, no dual reading, no silent
acceptance of both spellings: the module is rewritten onto the assigned
bytes, and a psbt written today still parses as any psbt does while
being a session nothing here reads any more. That is the price of not
waiting for the BIP, and it is declared here rather than discovered by
whoever finds an old file.

A key is BIP174's proprietary key, built and parsed here byte for byte:
the type, the identifier's length and the identifier, the subtype, and
the key data.

```text
0xfc || compactsize(6) || b"btclib" || compactsize(subtype) || key data
```

Every key data opens with the identifier of the participant the record
belongs to, and what follows says which group or which session:

- `FROST_THRESHOLD_INFO`, on an input or an output, under the writer's
  identifier and the threshold public key: `t`, `n`, and an
  `(id, pubshare)` pair for every public share **that participant**
  knows;
- `FROST_PUB_NONCE`, on an input, under the signer's identifier, the
  threshold public key and the tapleaf hash of a script path spend: the
  66-byte pubnonce of round 1;
- `FROST_PARTIAL_SIG`, on an input, under the same key data: the
  32-byte partial signature of round 2.

`FROST_PUB_NONCE` and `FROST_PARTIAL_SIG` are BIP373's
`PSBT_IN_MUSIG2_PUB_NONCE` and `PSBT_IN_MUSIG2_PARTIAL_SIG` key shape
with the participant's identifier where MuSig2 has the participant's
public key, and `FROST_THRESHOLD_INFO` is
`PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` with the key material FROST's own
`ThresholdInfo` holds where MuSig2 has a list of keys. Two things a
MuSig2 field has no counterpart for travel because a FROST signing set
is a subset of the group: the identifiers, and the public share of each.

**A participant identifier is in the key of every record**, which is
what makes BIP174's Combiner the merge these fields survive.
`psbt.combine` takes the union of two `unknown` maps pair by pair, so
what two participants wrote into their own copies is all there
afterwards; a record keyed without the identifier is last-writer-wins,
and one participant's contribution silently replaces the other's.
`psbt.join` is a different operation and not one a session goes through:
it concatenates the inputs of psbts of different transactions, and the
`unknown: same key, different value` refusal of its consistency check
reads the psbt's own global map, which these input and output records
are not in.

That is why the key material is keyed by its **writer** and not by the
group: the record says what one participant knows about the group,
which is what makes two holders of partial knowledge merge instead of
erasing each other. What it moves to the reader is the merge itself --
`threshold_info` unions the pairs of every record filed under one
threshold public key -- and a merge has a case the union of disjoint
keys does not: two participants disagreeing. A pubshare filed twice for
one identifier with two values, or two records disagreeing on `t` or on
the size of the group, is key material nobody can sign with
consistently, so it raises rather than being picked between. That
refusal is `psbt.combine`'s own `_combine_musig2_participants` one
layer down: BIP373's field gets it from `psbt.py`, which knows that
field; nothing in `psbt.py` knows this one, by the decision recorded
there against explicit proprietary support, so it lives here, where the
meaning of these records lives. `validate_threshold_info` then runs on
what the reader assembled rather than on what one writer sent.

**The tweaks are derived from the psbt and not carried**, as
`btclib.psbt.musig2` derives MuSig2's, so there is no field for them:

- the threshold public key **is** the taproot output key: nothing to
  tweak;
- it is the **internal key**: one x-only tweak, the BIP341 commitment to
  the merkle root the input carries;
- it is a **key in a leaf script**: nothing to tweak, and the message is
  BIP342's rather than BIP341's.

A psbt saying none of those is refused rather than signed under a key
the output does not commit to. The fourth way `btclib.psbt.musig2` reads
off a psbt is BIP328 derivation, and it stops at MuSig2: BIP328 is the
"Derivation Scheme for MuSig2 Aggregate Keys" and builds its synthetic
xpub from a BIP327 aggregate key, with BIP373 saying when a psbt's
taproot derivation field may be read as one. Neither covers a threshold
public key, which comes from key generation rather than from aggregating
a list, so an internal key that is not the threshold public key itself
is refused here instead of being derived to.

**Where the secret nonce lives is the caller's business, and this module
holds nothing.** `nonce_gen` hands back the `bytearray` that
`btclib.ecc.frost.sign` consumes and `partial_sign` takes it back;
between the two rounds it is in the caller's hands and never in the
psbt, which travels. `btclib.psbt.musig2`'s docstring gives the reason
and it holds verbatim: a secnonce that signs twice hands out the secret
share by elementary algebra, and a psbt is a file that gets copied,
combined and re-read.

The roles are BIP373's, over BIP445's own rounds:

- **Updater**: `add_threshold_info` files the key material a dealer or a
  DKG produced under the threshold public key it reconstructs to, on an
  input or an output;
- **Signer**: `nonce_gen` writes the public nonce of round 1,
  `partial_sign` the partial signature of round 2, and
  `partial_sig_verify` holds another signer to what it sent;
- **Finalizer**: `partial_sigs_agg` adds the partial signatures up into
  the BIP340 signature the spend needs, writes it to
  `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG`, and drops the
  session.

**The signers of a session are whoever published a nonce for it**, which
is where a threshold differs from MuSig2's *n*-of-*n*: `session_context`
reads the identifiers out of the nonce records rather than out of the
key material, and a nonce that arrives after a partial signature was
made describes a different session -- exactly the state
`btclib.ecc.frost.partial_sig_verify_` is for.
"""

from __future__ import annotations

from typing import NamedTuple

from btclib import var_bytes, var_int
from btclib.alias import Octets
from btclib.ecc import frost, ssa

# the widths this module writes are the ones `btclib.ecc.frost` reads:
# an identifier is `_ID_SIZE` bytes big-endian there (`_serialize_ids`),
# a public share and a threshold public key are compressed points, and
# `_MAX_PARTICIPANTS` is the security bound that module states. Imported
# rather than restated, as `ecc.frost` itself imports `curves.curve`'s
# `_sum_var`: a second copy of a width is a second thing to keep true
from btclib.ecc.frost import _ID_SIZE, _MAX_PARTICIPANTS, _PK_SIZE
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.psbt.psbt import (
    Psbt,
    leaf_script,
    prevouts,
    single_leaf_key,
    taproot_sig_hash,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import LEAF_HASH_SIZE
from btclib.script import type_and_payload
from btclib.utils import bytes_from_octets

__all__ = [
    "FROST_PARTIAL_SIG",
    "FROST_PUB_NONCE",
    "FROST_THRESHOLD_INFO",
    "PREFIX",
    "PROPRIETARY",
    "add_threshold_info",
    "assert_valid_records",
    "nonce_gen",
    "partial_sig_verify",
    "partial_sign",
    "partial_sigs_agg",
    "session_context",
    "threshold_info",
]

# BIP174's proprietary key type, which `psbt_in` and `psbt_out`
# deliberately have no constant for: an unknown key is kept whole there,
# its type byte included, so this module is where the byte is written
PROPRIETARY = b"\xfc"

# the identifier every key of this module carries, and the one thing
# about these records that cannot be changed later without breaking
# every psbt already written
PREFIX = b"btclib"

# the subtypes, whose meaning is this module's to give: BIP174 leaves
# both the subtype and the key data to the proprietary type user
FROST_THRESHOLD_INFO = 0
FROST_PUB_NONCE = 1
FROST_PARTIAL_SIG = 2

# what a record about one group is keyed by: the writer's identifier
# and the threshold public key
_INFO_KEY_SIZE = _ID_SIZE + _PK_SIZE

# and what one contribution to one session is keyed by: the signer's own
# identifier, that same threshold public key, and the tapleaf hash of
# the script being signed -- present when the threshold key is a key in
# a script, absent when it is the taproot internal or output key
_SESSION_KEY_SIZES = (
    _INFO_KEY_SIZE,
    _INFO_KEY_SIZE + LEAF_HASH_SIZE,
)

# what each of the two rounds of BIP445 produces: `nonce_gen` two
# points, `sign` one scalar
_PUB_NONCE_SIZE = 66
_PARTIAL_SIG_SIZE = 32

# an `(id, pubshare)` pair of the threshold info record, and the two
# counts in front of the pairs -- `t` and `n`, written at an
# identifier's own width so that the record holds one integer width
_PAIR_SIZE = _ID_SIZE + _PK_SIZE
_COUNTS_SIZE = 2 * _ID_SIZE


def _subtype_key(subtype: int) -> bytes:
    """Return what every key of one subtype starts with.

    A compact size integer is self-delimiting, so no encoding is a
    prefix of another's: matching this answers the subtype exactly, and
    a `startswith` is the whole of the parse a record needs.
    """
    return PROPRIETARY + var_bytes.serialize(PREFIX) + var_int.serialize(subtype)


def _records(psbt_map: PsbtIn | PsbtOut, subtype: int) -> dict[bytes, bytes]:
    """Return the records of one subtype, by their key data."""
    prefix = _subtype_key(subtype)
    return {
        key[len(prefix) :]: value
        for key, value in psbt_map.unknown.items()
        if key.startswith(prefix)
    }


def _record_key(subtype: int, my_id: int, tail: bytes) -> bytes:
    """Return the whole key of one record.

    The subtype, the identifier of the participant whose record it is,
    and what the record is about: a threshold public key, or one with a
    tapleaf hash after it.
    """
    return _subtype_key(subtype) + my_id.to_bytes(_ID_SIZE, "big") + tail


def _by_participant(
    psbt_map: PsbtIn | PsbtOut, subtype: int, tail: bytes
) -> dict[int, bytes]:
    """Return the records of one subtype about one thing, by participant.

    An equality on the key data after the identifier, as
    `btclib.psbt.musig2` filters its own two maps: one input may carry a
    session per threshold key and per leaf, and an ordering would take
    in whatever sorts the right way -- a nonce of another session, which
    changes the aggregate nonce the others signed against.
    """
    return {
        int.from_bytes(key_data[:_ID_SIZE], "big"): value
        for key_data, value in _records(psbt_map, subtype).items()
        if key_data[_ID_SIZE:] == tail
    }


def _serialize_threshold_info(info: frost.ThresholdInfo) -> bytes:
    """Return the value of a threshold info record.

    The pairs are what makes the record a list rather than an `n`-slot
    array with a hole marker: `ThresholdInfo.pub_shares` may hold `None`
    where the holder does not know a share, and what is written is the
    shares it does know, each under its own identifier.
    """
    n = len(info.pub_shares)
    pairs = [
        i.to_bytes(_ID_SIZE, "big") + pub_share
        for i, pub_share in enumerate(info.pub_shares)
        if pub_share is not None
    ]
    return b"".join(
        [info.t.to_bytes(_ID_SIZE, "big"), n.to_bytes(_ID_SIZE, "big"), *pairs]
    )


def _parse_threshold_info(value: bytes) -> tuple[int, int, dict[int, bytes]]:
    """Return one record's `t`, its `n`, and the public shares it knows.

    The parts rather than a `ThresholdInfo`, because one record is one
    participant's knowledge and the key material is what `threshold_info`
    merges out of all of them.

    `n` is read before anything is built from it: a psbt is somebody
    else's input, and the four bytes the record spells `n` in reach past
    what any machine would allocate. The bound is the one
    `btclib.ecc.frost` states, so key material this refuses is key
    material that module refuses too.
    """
    if len(value) < _COUNTS_SIZE or (len(value) - _COUNTS_SIZE) % _PAIR_SIZE:
        err_msg = f"invalid frost threshold info length: {len(value)} bytes"
        raise BTClibValueError(err_msg)
    t = int.from_bytes(value[:_ID_SIZE], "big")
    n = int.from_bytes(value[_ID_SIZE:_COUNTS_SIZE], "big")
    if n > _MAX_PARTICIPANTS:
        err_msg = f"invalid frost participant count: {n}"
        raise BTClibValueError(err_msg)
    pub_shares: dict[int, bytes] = {}
    for start in range(_COUNTS_SIZE, len(value), _PAIR_SIZE):
        pair = value[start : start + _PAIR_SIZE]
        i = int.from_bytes(pair[:_ID_SIZE], "big")
        if i >= n or i in pub_shares:
            err_msg = f"invalid frost participant identifier: {i}"
            raise BTClibValueError(err_msg)
        pub_shares[i] = pair[_ID_SIZE:]
    return t, n, pub_shares


def add_threshold_info(
    psbt_map: PsbtIn | PsbtOut, my_id: int, info: frost.ThresholdInfo
) -> bytes:
    """Add what one participant knows of a group, and return the group's key.

    The Updater role. `my_id` is the participant whose knowledge the
    record states, and it is in the key: two participants writing what
    each of them knows write two records, which is what a Combiner can
    merge. Its own knowledge is what a participant may write, so an
    identifier the group does not have is refused.

    `validate_threshold_info` runs first, so what the record says is key
    material a signer can use: the public shares in it lie on one
    polynomial and reconstruct the threshold public key they are filed
    under. A participant that cannot check that much of what it holds --
    fewer than `t` shares known -- has nothing to assert about the group
    and is refused here by that call rather than by a rule of this
    module's own. `btclib.psbt.musig2.add_participant_pub_keys` computes
    its aggregate key rather than taking one for the same reason, and
    the difference is where the key comes from: FROST's is key
    generation's, so it is checked and not derived.
    """
    frost.validate_threshold_info(info)
    if not 0 <= my_id < len(info.pub_shares):
        err_msg = f"frost participant {my_id} is not one of the "
        err_msg += f"threshold public key {info.thresh_pk.hex()}"
        raise BTClibValueError(err_msg)
    key = _record_key(FROST_THRESHOLD_INFO, my_id, info.thresh_pk)
    psbt_map.unknown[key] = _serialize_threshold_info(info)
    return info.thresh_pk


def threshold_info(
    psbt_map: PsbtIn | PsbtOut, thresh_pk: Octets
) -> frost.ThresholdInfo:
    """Return the key material a psbt map carries for one threshold key.

    The union of what every participant that wrote a record knows, which
    is the merge the module docstring says the reader owes: each record
    is one writer's knowledge, so the shares of the group are spread
    across them and no single record need hold them all.

    Two writers that disagree raise. A public share filed for one
    identifier with two values, or two records disagreeing on `t` or on
    the size of the group, is key material that cannot be signed with
    consistently, and picking one of the two would sign under a key the
    other holder does not have. The merged result then goes through
    `validate_threshold_info`, so what a signer reads is checked as a
    whole rather than a record at a time.

    Public where `btclib.psbt.musig2`'s own reader is private: a MuSig2
    participant list is a field of the map and a caller reads it there,
    where these are bytes inside `unknown` and this is the only way to
    read them back.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    records = _by_participant(psbt_map, FROST_THRESHOLD_INFO, thresh_pk)
    if not records:
        err_msg = f"no frost threshold info for threshold public key {thresh_pk.hex()}"
        raise BTClibValueError(err_msg)

    # in identifier order, so that which record a conflict is reported
    # against is the psbt's own arrangement and not the map's
    parsed = [
        (writer, *_parse_threshold_info(records[writer])) for writer in sorted(records)
    ]
    t, n = parsed[0][1], parsed[0][2]
    pub_shares: dict[int, bytes] = {}
    for writer, record_t, record_n, record_shares in parsed:
        if writer >= record_n:
            err_msg = f"frost threshold info of participant {writer}, "
            err_msg += f"who is not one of the {record_n} the record declares"
            raise BTClibValueError(err_msg)
        if (record_t, record_n) != (t, n):
            err_msg = f"mismatched frost threshold info of participant {writer} "
            err_msg += f"for threshold public key {thresh_pk.hex()}"
            raise BTClibValueError(err_msg)
        for i, pub_share in record_shares.items():
            if pub_shares.setdefault(i, pub_share) != pub_share:
                err_msg = f"mismatched frost public share of participant {i} "
                err_msg += f"for threshold public key {thresh_pk.hex()}"
                raise BTClibValueError(err_msg)

    info = frost.ThresholdInfo(t, thresh_pk, [pub_shares.get(i) for i in range(n)])
    frost.validate_threshold_info(info)
    return info


def _pub_share(info: frost.ThresholdInfo, my_id: int) -> bytes:
    """Return one participant's public share, refusing a session without it.

    A `SessionContext` this module builds always carries the public
    shares of its signers: they are what `partial_sig_verify_` checks a
    partial signature against, and a psbt that publishes a nonce for a
    participant whose share it does not carry describes a session no
    other signer can hold that one to.
    """
    if not 0 <= my_id < len(info.pub_shares):
        err_msg = f"frost participant {my_id} is not one of the "
        err_msg += f"threshold public key {info.thresh_pk.hex()}"
        raise BTClibValueError(err_msg)
    pub_share = info.pub_shares[my_id]
    if pub_share is None:
        err_msg = f"no frost public share of participant {my_id} for "
        err_msg += f"threshold public key {info.thresh_pk.hex()}"
        raise BTClibValueError(err_msg)
    return pub_share


def _tweaks(
    psbt_in: PsbtIn, thresh_pk: bytes, leaf_hash: bytes, output_key: bytes
) -> tuple[list[bytes], list[bool]]:
    """Return the tweaks between the threshold public key and what is spent.

    Which of the three ways the module docstring lists this psbt is
    written in is read here, and a psbt saying none of them is refused
    rather than signed under an untweaked key: the partial signatures
    would add up to a signature valid under a key the output does not
    commit to, and the psbt is where a signer can still notice.
    """
    x_only = thresh_pk[1:]

    # a key in a script signs as itself: the taproot tweak belongs to the
    # output key, which the script path does not sign for
    if leaf_hash:
        return [], []

    if psbt_in.taproot_internal_key == x_only:
        # BIP341: the output key commits to the internal key and the root
        # of the script tree, which is empty for an output with no scripts
        taproot_tweak = tagged_hash(
            b"TapTweak", psbt_in.taproot_internal_key + psbt_in.taproot_merkle_root
        )
        return [taproot_tweak], [True]

    if not psbt_in.taproot_internal_key and output_key == x_only:
        return [], []

    err_msg = f"frost threshold public key {thresh_pk.hex()} is neither the "
    err_msg += "taproot output key nor the internal key of the input"
    raise BTClibValueError(err_msg)


class _SessionParts(NamedTuple):
    """What a session is, before the nonces of round 1 exist.

    `tweaked_x_only` is the threshold public key **as tweaked for this
    session**, which is what the spend verifies against and what the
    nonces are bound to. It is not what the records are keyed by: those
    carry the threshold public key itself, which is the key generation
    answered and the one a caller names.
    """

    info: frost.ThresholdInfo
    tweaks: list[bytes]
    is_xonly: list[bool]
    msg: bytes
    tweaked_x_only: bytes


def _session_parts(
    psbt: Psbt, vin_i: int, thresh_pk: bytes, leaf_hash: bytes
) -> _SessionParts:
    """Return everything a signer derives from the psbt before round 1.

    Which is why it is not `session_context` itself: round 1 needs the
    message -- BIP445 binds the nonce to it -- and the aggregate nonce it
    is about to contribute to is not there yet.
    """
    psbt_in = psbt.inputs[vin_i]
    output_key = type_and_payload(prevouts(psbt)[vin_i].script_pub_key.script)[1]
    info = threshold_info(psbt_in, thresh_pk)
    tweaks, is_xonly = _tweaks(psbt_in, thresh_pk, leaf_hash, output_key)
    msg = taproot_sig_hash(psbt, vin_i, leaf_hash=leaf_hash)

    # what the tweaks were read off the psbt for: the key the signatures
    # will verify under has to be the key the spend needs, which is the
    # output key of a key path spend and the script's own key otherwise.
    # A merkle root or a tapleaf hash that does not belong to this input
    # fails here, before a secret nonce is spent on a signature nobody
    # can use
    tweak_ctx = frost.thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)
    expected = (
        single_leaf_key(leaf_script(psbt_in, leaf_hash)[0]) if leaf_hash else output_key
    )
    if tweak_ctx.x_only_pub_key != expected:
        err_msg = f"the tweaked frost key {tweak_ctx.x_only_pub_key.hex()} is not "
        err_msg += f"the key being spent, {expected.hex()}"
        raise BTClibValueError(err_msg)

    return _SessionParts(info, tweaks, is_xonly, msg, tweak_ctx.x_only_pub_key)


def session_context(
    psbt: Psbt, vin_i: int, thresh_pk: Octets, *, leaf_hash: Octets = b""
) -> frost.SessionContext:
    """Return the BIP445 session the psbt describes.

    The signers are the participants that published a nonce for this
    session, in identifier order, and the aggregate nonce is the sum of
    those nonces: a context built before the last nonce arrives is a
    different context, and the partial signatures made against the two
    do not add up. `btclib.ecc.frost.partial_sig_verify_` is what catches
    that, and this is what it takes.

    A `SessionContext` is the whole of what a caller needs back, unlike
    `btclib.psbt.musig2`'s pair: nothing here aggregates a key list, so
    there is no second object to carry, and the tweaked key is
    `btclib.ecc.frost.session_values`, memoized on the context.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    parts = _session_parts(psbt, vin_i, thresh_pk, leaf_hash)
    pub_nonces = _by_participant(
        psbt.inputs[vin_i], FROST_PUB_NONCE, thresh_pk + leaf_hash
    )
    if not pub_nonces:
        err_msg = "no frost public nonce for threshold public key "
        err_msg += thresh_pk.hex()
        raise BTClibValueError(err_msg)
    ids = sorted(pub_nonces)
    return frost.SessionContext(
        len(parts.info.pub_shares),
        parts.info.t,
        ids,
        [_pub_share(parts.info, i) for i in ids],
        thresh_pk,
        frost.nonce_agg([pub_nonces[i] for i in ids]),
        parts.tweaks,
        parts.is_xonly,
        parts.msg,
    )


def nonce_gen(
    psbt: Psbt,
    vin_i: int,
    my_id: int,
    sec_share: Octets,
    thresh_pk: Octets,
    *,
    leaf_hash: Octets = b"",
    extra_in: Octets | None = None,
) -> bytearray:
    """Write the public nonce of round 1, and return the secret one.

    The Signer role, first half. The returned bytearray is what
    `partial_sign` consumes and what must not be copied, written down or
    put in the psbt: the module docstring says why the decision is to
    hand it back rather than keep it.

    The nonce is bound to everything BIP445 lets it be bound to -- the
    signer's secret share, its public share, the tweaked threshold
    public key of the session and the message -- because all four are
    here, and a nonce derived from fewer of them is one a faulty random
    source can repeat across sessions. The identifier is the caller's,
    as it is everywhere in `btclib.ecc.frost`, and that it is this
    secret share's identifier is what `btclib.ecc.frost.sign` checks in
    round 2 against the public share this one names.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    parts = _session_parts(psbt, vin_i, thresh_pk, leaf_hash)
    sec_nonce, pub_nonce = frost.nonce_gen(
        sec_share,
        _pub_share(parts.info, my_id),
        parts.tweaked_x_only,
        parts.msg,
        extra_in,
    )
    key = _record_key(FROST_PUB_NONCE, my_id, thresh_pk + leaf_hash)
    psbt.inputs[vin_i].unknown[key] = pub_nonce
    return sec_nonce


def partial_sign(
    psbt: Psbt,
    vin_i: int,
    sec_nonce: bytearray,
    my_id: int,
    sec_share: Octets,
    thresh_pk: Octets,
    *,
    leaf_hash: Octets = b"",
) -> bytes:
    """Write the partial signature of round 2, and return it.

    The Signer role, second half. The secnonce is consumed by
    `btclib.ecc.frost.sign`, which zeroes it: this function cannot be
    called twice with one nonce, and that is the point.

    The signature is verified before it is written, against the session
    the psbt describes: a signer that publishes a partial signature of a
    session it got wrong has published a number the others cannot use
    and cannot make it un-published.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    psbt_in = psbt.inputs[vin_i]
    pub_nonces = _by_participant(psbt_in, FROST_PUB_NONCE, thresh_pk + leaf_hash)
    if my_id not in pub_nonces:
        err_msg = f"no frost public nonce of participant {my_id} for "
        err_msg += f"threshold public key {thresh_pk.hex()}"
        raise BTClibValueError(err_msg)

    session = session_context(psbt, vin_i, thresh_pk, leaf_hash=leaf_hash)
    psig = frost.sign(sec_nonce, sec_share, my_id, session)
    pub_share = _pub_share(threshold_info(psbt_in, thresh_pk), my_id)
    if not frost.partial_sig_verify_(
        psig, my_id, pub_nonces[my_id], pub_share, session
    ):
        # unreachable short of a defect in either this module or `sign`:
        # the context is the one the signature was just made against.
        # It stays because what it costs is one verification against a
        # partial signature that no other signer can be told to ignore
        raise BTClibValueError(
            "invalid frost partial signature"
        )  # pragma: no cover -- sign() and verify() here share one session
    key = _record_key(FROST_PARTIAL_SIG, my_id, thresh_pk + leaf_hash)
    psbt_in.unknown[key] = psig
    return psig


def partial_sig_verify(
    psbt: Psbt, vin_i: int, my_id: int, thresh_pk: Octets, *, leaf_hash: Octets = b""
) -> bool:
    """Verify one participant's partial signature, as the psbt holds it.

    `btclib.ecc.frost.partial_sig_verify_` over the psbt the partial
    signature arrived in: the nonce it is checked against is the one the
    same input carries for the same participant, so a signature made
    against another session answers False here rather than at
    aggregation time, where the only news is that the total does not
    verify.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    psbt_in = psbt.inputs[vin_i]
    tail = thresh_pk + leaf_hash
    psig = _by_participant(psbt_in, FROST_PARTIAL_SIG, tail).get(my_id)
    pub_nonce = _by_participant(psbt_in, FROST_PUB_NONCE, tail).get(my_id)
    if psig is None or pub_nonce is None:
        err_msg = f"no frost partial signature of participant {my_id} for "
        err_msg += f"threshold public key {thresh_pk.hex()}"
        raise BTClibValueError(err_msg)
    session = session_context(psbt, vin_i, thresh_pk, leaf_hash=leaf_hash)
    pub_share = _pub_share(threshold_info(psbt_in, thresh_pk), my_id)
    return frost.partial_sig_verify_(psig, my_id, pub_nonce, pub_share, session)


def partial_sigs_agg(
    psbt: Psbt, vin_i: int, thresh_pk: Octets, *, leaf_hash: Octets = b""
) -> ssa.Sig:
    """Aggregate the session's partial signatures, and drop the session.

    The Finalizer role. The BIP340 signature goes where the spend reads
    it -- `PSBT_IN_TAP_KEY_SIG` for a key path spend, and
    `PSBT_IN_TAP_SCRIPT_SIG` under the key and tapleaf hash for a script
    path one -- with the sig_hash type appended when the input asks for
    one other than the default, as BIP341 appends it.

    Every signer of the session must have signed. That is not the group:
    a FROST session is the subset that published nonces, and the
    threshold is what says whether such a subset can sign at all --
    `btclib.ecc.frost.session_values` refuses a session of fewer than
    `t` signers, so what is missing here is a partial signature from a
    participant that joined this one.

    The records of that session are then removed, the key material
    included. What replaces them is the signature itself, and a nonce
    that has been used is worse than useless: keeping it invites a
    second session with the same nonce, which is the one thing that
    hands out a secret share.
    """
    thresh_pk = bytes_from_octets(thresh_pk, _PK_SIZE)
    leaf_hash = bytes_from_octets(leaf_hash)
    psbt_in = psbt.inputs[vin_i]
    session = session_context(psbt, vin_i, thresh_pk, leaf_hash=leaf_hash)
    partial_sigs = _by_participant(psbt_in, FROST_PARTIAL_SIG, thresh_pk + leaf_hash)
    missing = [my_id for my_id in session.ids if my_id not in partial_sigs]
    if missing:
        err_msg = "missing frost partial signature of participant "
        err_msg += ", ".join(str(my_id) for my_id in missing)
        raise BTClibValueError(err_msg)

    sig = frost.partial_sig_agg([partial_sigs[my_id] for my_id in session.ids], session)
    x_only_pub_key = frost.thresh_pubkey_and_tweak(
        thresh_pk, session.tweaks, session.is_xonly
    ).x_only_pub_key
    if not ssa.verify_(session.msg, x_only_pub_key, sig):
        # a partial signature that verifies on its own and does not add
        # up is what a peer sending one of another session produces, so
        # this is the Finalizer's check and not a belt-and-braces one
        err_msg = "the frost partial signatures do not add up to a signature "
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

    _drop_session(psbt_in, thresh_pk, leaf_hash)
    return sig


def _drop_session(psbt_in: PsbtIn, thresh_pk: bytes, leaf_hash: bytes) -> None:
    """Remove the nonces, the partial signatures and the key material.

    Every writer's record of each, since each of the three is a record
    per participant. The key material is about the group rather than
    about this session, so it goes where the session that used it is the
    one being finished -- a spend of this input has no further use for
    it, and BIP174 has a Finalizer clear what it understands.
    """
    for subtype, tail in (
        (FROST_PUB_NONCE, thresh_pk + leaf_hash),
        (FROST_PARTIAL_SIG, thresh_pk + leaf_hash),
        (FROST_THRESHOLD_INFO, thresh_pk),
    ):
        for my_id in _by_participant(psbt_in, subtype, tail):
            del psbt_in.unknown[_record_key(subtype, my_id, tail)]


def _assert_valid_session_records(
    psbt_map: PsbtIn | PsbtOut, subtype: int, size: int, what: str
) -> None:
    """Raise unless every record of one subtype is a session's shape."""
    for key_data, value in _records(psbt_map, subtype).items():
        if len(key_data) not in _SESSION_KEY_SIZES:
            err_msg = f"invalid {what} key length: {len(key_data)}"
            raise BTClibValueError(err_msg)
        if len(value) != size:
            err_msg = f"invalid {what} length: {len(value)}"
            raise BTClibValueError(err_msg)


def assert_valid_records(psbt_map: PsbtIn | PsbtOut) -> None:
    """Raise unless every frost record of the map is one this module wrote.

    The check `assert_valid` cannot make: a proprietary record is an
    unknown key to the codec, which keeps it whole and asks nothing
    about it, so what a psbt says about a FROST session is checked here
    or nowhere. Key material goes through `validate_threshold_info`,
    which is the reconstruction this module exists to make possible and
    which no codec should depend on; the session records are checked for
    the shape a signer will read them at.
    """
    for key_data in _records(psbt_map, FROST_THRESHOLD_INFO):
        if len(key_data) != _INFO_KEY_SIZE:
            err_msg = f"invalid frost threshold info key length: {len(key_data)}"
            raise BTClibValueError(err_msg)
    # by group and not by record: what has to hold is what a reader
    # assembles out of every writer's record, which is `threshold_info`
    # -- the merge, its refusal of two writers that disagree, and
    # `validate_threshold_info` over the result
    for thresh_pk in {
        key_data[_ID_SIZE:] for key_data in _records(psbt_map, FROST_THRESHOLD_INFO)
    }:
        threshold_info(psbt_map, thresh_pk)
    _assert_valid_session_records(
        psbt_map, FROST_PUB_NONCE, _PUB_NONCE_SIZE, "frost public nonce"
    )
    _assert_valid_session_records(
        psbt_map, FROST_PARTIAL_SIG, _PARTIAL_SIG_SIZE, "frost partial signature"
    )
