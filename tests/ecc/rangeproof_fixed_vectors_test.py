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
below the signed ceiling; and the proof of a value stated in the clear
that zkp itself wrote.

What is asked of them is the parse, the range the header states, and
the rings the value's digits index. The borromean signature is read
back byte for byte and not verified, which is
[ISS 1072](https://github.com/btclib-org/btclib/issues/1072).
"""

from typing import Any

import pytest

from btclib.curves import mult, secp256k1
from btclib.ecc.pedersen import _point_from_x, bytes_from_commitment, commit
from btclib.ecc.rangeproof import RangeProof
from tests import load, vector_id

_VECTORS = load("ecc", "_data", "zkp_rangeproof_fixed_vectors.json")
_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_VECTORS)]


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
