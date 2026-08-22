# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Commitment-tweaked ephemeral key (nonce): sign-to-contract.

A signature commits to a value by tweaking its nonce with it, at no cost
in size: what comes out is an ordinary DSA or SSA signature, and only
whoever is shown the committed value and the receipt can tell that it
commits to anything.

Let commit_hash be the commitment value and R a curve point, then

e = hash(R||commit_hash)

is a commitment operation.

When signing, an ephemeral secret key k is generated and its
corresponding curve point R = kG is used. Here, instead of using (k, R),
compute the commitment to commit_hash

e = hash(R||commit_hash),

tweak k with e and consequently substitute R with W = (k+e)G = R+eG, then
proceed signing in the standard way, using (k+e, W).

When the committer/signer will reveal R and commit_hash, the verifier
will check that

W.x = (R+eG).x

with e = hash(R||commit_hash)) and W.x being known from the signature.

R is the receipt, and it is the signer's to keep: nothing in the
signature says what it was. `dsa.sign` and `ssa.sign` take the commitment
as a parameter and return the receipt beside the signature, `dsa.verify`
and `ssa.verify` take the two back to open the commitment, and this
module is the tweak behind all four.

**The committed value must also reach the nonce derivation**, which is
the half of the scheme that is easy to leave out and fatal to leave out.
Tweaking alone leaves the untweaked k a function of the message and the
key only, so two signatures over one message with two commitments have
nonces differing by e2-e1 -- a value the openings make public. Two ECDSA
signatures over one message with a known nonce difference are two
equations in the two unknowns k and the private key, and the same holds
for BIP340. libsecp256k1's own s2c module states it as the reason it
refuses a custom nonce function: "an attacker can exfiltrate the secret
key by signing the same message thrice with different commitments". So
`commit_entropy_` is not optional garnish, and the two schemes each feed
it to their nonce derivation before calling `commit_nonce_`: dsa through
RFC6979's section 3.6 additional data, ssa through BIP340's auxiliary
randomness.

Both hashes are tagged, and the tags are the scheme's: they are what
keeps a tweak from being read as a challenge, or an ECDSA commitment as a
BIP340 one. Each caller passes its own, because they differ per scheme
and a default would be the wrong one for somebody.
"""

from __future__ import annotations

from hashlib import sha256

from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.alias import HashF, Integer, Octets, Point
from btclib.curves import (
    Curve,
    bytes_from_point,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.curves.curve import _libsecp256k1_serves, _tweak_add_var
from btclib.exceptions import BTClibRuntimeError
from btclib.hashes import tagged_hash
from btclib.utils import bytes_from_octets, int_from_bits

__all__ = [
    "commit_entropy_",
    "commit_nonce_",
    "commit_point_",
]


def commit_entropy_(commit_hash: Octets, tag: bytes, hf: HashF = sha256) -> bytes:
    """Return the committed value as entropy for a nonce derivation.

    Hashed, and not passed on as it is, so that a nonce can be derived by
    someone who knows a hash of the value and not the value itself: that
    is what lets a signing device commit to a host's randomness before
    the host reveals it, which is the ordering the anti-exfil protocol is
    built on.
    """
    return tagged_hash(tag, bytes_from_octets(commit_hash), hf)


def _tweak(
    commit_hash: Octets, receipt: Point, tag: bytes, ec: Curve, hf: HashF
) -> int:
    """Return the tagged hash(receipt||commit_hash) tweak for the receipt."""
    t = bytes_from_point(receipt, ec) + bytes_from_octets(commit_hash)
    while True:
        t = tagged_hash(tag, t, hf)
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        tweak = int_from_bits(t, ec.nlen)  # candidate tweak
        if 0 < tweak < ec.n:  # acceptable value for tweak
            return tweak  # successful candidate
        # libsecp256k1 fails here instead of asking the hash again, and
        # on secp256k1 the two agree: the first candidate is out of range
        # about once in 2^128. It is the low-cardinality curves that need
        # a second candidate -- with nlen of 4 bits an out-of-range tweak
        # is one in three -- and there the reference has no answer at all


def commit_nonce_(
    commit_hash: Octets,
    nonce: Integer,
    tag: bytes,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[int, Point]:
    """Return the commitment-tweaked nonce, and the receipt to reveal.

    The receipt is the point of the nonce as it came in: it is what the
    tweak hashes, so a verifier given the committed value can recompute
    the tweak and reach the point the signature carries.
    """
    nonce = scalar_from_prv_key(nonce, ec)
    receipt = mult(nonce, ec.G, ec)
    tweak = _tweak(commit_hash, receipt, tag, ec, hf)

    # secp256k1_ec_seckey_tweak_add computes the sum in constant time,
    # where Python's own `(a + b) % n` is variable in time with the
    # operands and leaves an unzeroized copy of each intermediate behind
    # -- this is the one place a secret nonce is tweaked in Python that
    # the delegation removes. Gated on the curve alone, as BIP32
    # derivation gates the same call: hf enters only the tagged hash
    # above, computed in Python either way
    if _libsecp256k1_serves(ec, None):
        try:
            tweaked = libsecp256k1_keys.prvkey_tweak_add(nonce, tweak)
        except ValueError as e:
            # tweak is in range past _tweak's own loop, so the one sum
            # the binding refuses is the zero btclib refuses too
            raise BTClibRuntimeError("failed to sign: zero tweaked nonce") from e
        return int.from_bytes(tweaked, byteorder="big", signed=False), receipt

    tweaked_nonce = (nonce + tweak) % ec.n
    # the tweak is uniform in 1..n-1, so a zero sum is a one-in-n event
    # and not a rejection to loop over: a second candidate would be a
    # second tweak, and the tweak is what the verifier recomputes.
    # Refused here, because a nonce of zero has no point to sign with and
    # mod_inv_var(0) is the error the caller would see instead
    if tweaked_nonce == 0:
        raise BTClibRuntimeError("failed to sign: zero tweaked nonce")
    return tweaked_nonce, receipt


def commit_point_(
    commit_hash: Octets,
    receipt: Point,
    tag: bytes,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Point:
    """Return W = R + hash(R||commit_hash)G, the point the nonce became.

    Its x-coordinate is what the signature's r was built from -- dsa
    reduces that coordinate modulo the group order and ssa keeps the field
    element -- so the comparison against r belongs to each scheme and not
    here.
    """
    tweak = _tweak(commit_hash, receipt, tag, ec, hf)

    # R + tweak*G, which is `_tweak_add_var`'s whole subject: one
    # secp256k1_ec_pubkey_tweak_add on the serialized point where the
    # curve allows it, and the Python addition where it does not --
    # including the one-in-n sum at infinity, which is answered here
    # rather than raised, as `ec.add` answers it
    return _tweak_add_var(receipt, tweak, ec)
