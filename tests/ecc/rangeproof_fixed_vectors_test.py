# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.ecc.rangeproof` against the proofs zkp publishes.

The vectors are the C arrays of libsecp256k1-zkp's own
`src/modules/rangeproof/tests_impl.h`, with the blinding factor, the
value and the range that module's `CHECK`s assert about each --
`tests/_data/README.md` has the pin and how the arrays were read.

That provenance is what separates them from
`zkp_rangeproof_vectors.json` beside them, which this tree asked zkp to
sign: a recording answers with what was asked for, where these octets
and the answers beside them were published by the implementation this
format comes from. So the range in the header is held here to what
upstream states about those octets rather than to what a library call
made for this tree answered, and no test below reaches for the flagged
extension.

They also reach shapes no recording here has: a mantissa filling the
width the format allows, over as many rings as that takes; an exponent
the signer lowered from the one it was asked for; a `min_value` a step
below the signed ceiling; the proof of a value stated in the clear that
zkp itself wrote; and a message filling the room the widest of them
leaves for one, which is what `vector_0` of
`test_rangeproof_fixed_vectors_reproducible` carries. The recordings
beside them are signed with no message at all.

What is asked of them is the parse, the range the header states, the
rings the value's digits index, the signature over those rings, and a
rewind. Those last two are the questions a recording answers with less
force: the octets and the nonces are the implementation's own, so a
walk that closes on their own `e0`, and a rewind that opens the
commitment published beside the proof, are this module agreeing with
zkp. `nonce_3` is what `test_rangeproof_fixed_vectors` rewinds its
`vector_3` under and `vector_nonce` what the entries of
`test_rangeproof_fixed_vectors_reproducible` share; the two entries
with no nonce field are rewound by upstream under the commitment
itself, which `_nonce` has.
"""

from typing import Any

import pytest

from btclib.curves import mult, secp256k1
from btclib.ecc.pedersen import (
    _point_from_x,
    bytes_from_commitment,
    commit,
    commitment_from_octets,
)
from btclib.ecc.rangeproof import RangeProof, rewind, verify
from tests import load, vector_id

_VECTORS = load("ecc", "_data", "zkp_rangeproof_fixed_vectors.json")
_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_VECTORS)]
_BY_ID = {v["id"]: v for v in _VECTORS}

# zkp's own `SECP256K1_RANGEPROOF_MAX_MESSAGE_LEN`, of
# `include/secp256k1_rangeproof.h`, which states it as the message a
# maximally-sized rangeproof holds and any embeddable message fits in.
# It is the buffer `test_rangeproof_fixed_vectors_reproducible` fills
# with `0xFF`, and the room `vector_0`'s own rings have for one
_MAX_MESSAGE_LEN = 3968

# `message_2` of `test_rangeproof_fixed_vectors`, a C string literal, so
# what its `sizeof` covers and its `CHECK` compares is the terminator too
_ASCII = (
    b"When I see my own likeness in the depths of someone else's "
    b"consciousness,  I always experience a moment of panic.\x00"
)

# what upstream embedded in each entry, as octets rather than a length.
# `test_rangeproof_fixed_vectors_reproducible` signs its three, so theirs
# is the `message` buffer its own block passes `secp256k1_rangeproof_sign`;
# `test_rangeproof_fixed_vectors` signs none of its three and states
# theirs in the `CHECK`s beside its rewinds instead
_SIGNED_WITH = {
    "test_rangeproof_fixed_vectors vector_1": b"",
    "test_rangeproof_fixed_vectors vector_2": _ASCII,
    "test_rangeproof_fixed_vectors vector_3": b"",
    "test_rangeproof_fixed_vectors_reproducible vector_0": b"\xff" * _MAX_MESSAGE_LEN,
    "test_rangeproof_fixed_vectors_reproducible vector_1": b"\xff" * 128,
    "test_rangeproof_fixed_vectors_reproducible vector_2": b"",
}


def _nonce(vector: dict[str, Any]) -> bytes:
    """Return the octets upstream rewinds that entry under.

    `nonce_3` and the `vector_nonce` three entries share are published
    as their own arrays and transcribed. The two entries without one
    are rewound by upstream under `pc.data`, and
    `secp256k1_pedersen_commitment_parse` ends `memcpy(commit->data,
    input, 33)` -- so that buffer is the published commitment itself,
    and the 32 octets `secp256k1_rangeproof_rewind` reads out of it are
    that commitment's own first 32. Nothing is derived here that
    upstream does not publish; the field is absent because upstream
    declares no array, not because the octets are out of reach.
    """
    if "nonce" in vector:
        return bytes.fromhex(vector["nonce"])
    return bytes.fromhex(vector["commitment"])[:32]


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_parse_reads_and_writes_back_the_octets_zkp_publishes(
    vector: dict[str, Any],
) -> None:
    """Byte for byte, over proofs this tree had no hand in writing.

    The round trip is what pins every field of them: the sign bits, the
    ring commitments and the signature go back out unread, and the
    header goes back out as the fields the tests below ask about.
    """
    octets = bytes.fromhex(vector["proof"])
    assert RangeProof.parse(octets).serialize() == octets


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_header_proves_the_range_zkp_checks_it_proves(
    vector: dict[str, Any],
) -> None:
    """`secp256k1_rangeproof_verify`'s two out-parameters, read from the octets.

    Those are what upstream's own `CHECK`s state about each proof, so
    the header is held here to an implementation that neither runs nor
    is installed. `min_value` is what a proof carrying no such field and
    one carrying eight zero octets both verify to, which is why the
    comparison is against `min_value or 0`; which of the two a proof is
    stays in the round trip above.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    assert (proof.min_value or 0) == vector["verify"]["min value"]
    assert proof.max_value == vector["verify"]["max value"]


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_rings_open_at_the_published_blinding_factor(
    vector: dict[str, Any],
) -> None:
    """The commitment, its ring commitments, and the keys the digits name.

    The commitment comes first because everything after it hangs from
    it: `ecc.pedersen.commit` over the published blinding factor and
    value has to be the point whose octets upstream published beside
    the proof, which is what `bytes_from_commitment` writes. Reading its
    residuosity bit as parity answers a different point for some of
    these vectors and the same point for the rest, with nothing in the
    octets saying which.

    Then the ring commitments the proof states, each at the head of its
    own ring, and the keys `sign_key_idx` names across the rings, whose
    sum is `blind * G`. That sum reduces to
    `sum(digit * weight) == value - min_value`, which is why the heads
    are asserted directly rather than left to it.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    assert bytes_from_commitment(commitment) == bytes.fromhex(vector["commitment"])

    rings = proof.pubk_rings(commitment)
    stated = tuple(
        _point_from_x(x, sign)
        for x, sign in zip(proof.ring_commitments, proof.signs, strict=True)
    )
    assert tuple(ring[0] for ring in rings[: len(stated)]) == stated

    total = None
    for ring, j in zip(rings, proof.sign_key_idx(vector["value"]), strict=True):
        total = ring[j] if total is None else secp256k1.add_aff_var(total, ring[j])
    assert total == mult(vector["blind"], secp256k1.G, secp256k1)


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_signature_holds_for_the_published_commitment(
    vector: dict[str, Any],
) -> None:
    """The rings walked back to the `e0` upstream published.

    The commitment is the one published beside the proof, lifted with
    `ecc.pedersen.commitment_from_octets` rather than recomputed from
    the blinding factor: everything the walk hangs from is then read
    out of the vector, the last ring commitment it recovers included.

    A turned octet of the signature beside it, because a walk that
    accepts everything accepts these too.
    """
    commitment = commitment_from_octets(vector["commitment"])
    octets = bytes.fromhex(vector["proof"])
    assert verify(commitment, octets)

    turned = bytearray(octets)
    turned[-1] ^= 1
    assert not verify(commitment, bytes(turned))


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_published_nonce_reads_back_what_upstream_reads_back(
    vector: dict[str, Any],
) -> None:
    """`secp256k1_rangeproof_rewind`'s three out-parameters, and its nonce.

    Upstream holds the blinding factor to the `blind_<n>` or the
    `vector_blind` published beside the proof, and the value and the
    message to what its own block states -- the buffer it passed
    `secp256k1_rangeproof_sign` where it signs the entry, the `CHECK`s
    beside its rewind where it does not -- so those are what is asked
    here. What comes back past the message is the rest of the
    sidechannel, which a signer leaves zero.

    The commitment is lifted from the octets published beside the
    proof rather than rebuilt from the blinding factor: a rewind
    refuses whatever does not open the commitment it is handed, so
    reading it out of the vector is what leaves the nonce as the only
    thing the recovery hangs from.
    """
    commitment = commitment_from_octets(vector["commitment"])
    rewound = rewind(commitment, bytes.fromhex(vector["proof"]), _nonce(vector))
    assert rewound.blind == int(vector["blind"], 16)
    assert rewound.value == vector["value"]

    signed_with = _SIGNED_WITH[vector["id"]]
    assert rewound.message[: len(signed_with)] == signed_with
    assert not any(rewound.message[len(signed_with) :])


def test_the_maximum_length_message_comes_back_with_its_padding() -> None:
    """`vector_0`'s message: the `0xFF` run, then what the rings pad it with.

    The shape this file has and no recording beside it does, which is
    why it is asked for on its own: a message at
    `SECP256K1_RANGEPROOF_MAX_MESSAGE_LEN` over the widest mantissa the
    format carries. The run is asserted at that length and the padding
    for being there and being zero, rather than the two together as a
    total, so that a rewind returning the run alone -- or a message of
    the right length that is not this one -- fails here.
    """
    vector = _BY_ID["test_rangeproof_fixed_vectors_reproducible vector_0"]
    commitment = commitment_from_octets(vector["commitment"])
    rewound = rewind(commitment, bytes.fromhex(vector["proof"]), _nonce(vector))

    assert rewound.message[:_MAX_MESSAGE_LEN] == b"\xff" * _MAX_MESSAGE_LEN
    padding = rewound.message[_MAX_MESSAGE_LEN:]
    assert padding
    assert not any(padding)
