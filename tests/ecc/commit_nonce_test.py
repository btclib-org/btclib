# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.commit_nonce` module.

The commitment is a parameter of `dsa.sign` and `ssa.sign`, so what is
exercised here is those two: a signature carrying a commitment verifies as
an ordinary one, opens against the value committed to, and opens against
nothing else.

The dsa construction is libsecp256k1-zkp's `ecdsa_s2c`, and the fixed
vectors of that module's test suite are below. The ssa side matches
bitcoin-core/secp256k1#1140's tags, an open and unmerged pull request
whose `tests_impl.h` publishes no fixed vector of its own, so it has
none to match and is tested against itself and against the properties
the scheme needs.
"""

import random
import struct
from hashlib import sha1, sha256

import pytest

from btclib.alias import INF
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import commit_nonce, dsa, ssa
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import (
    _tweak,
    commit_entropy_,
    commit_nonce_,
    commit_point_,
)
from btclib.ecc.dsa import _S2C_DATA_TAG, _S2C_POINT_TAG
from btclib.ecc.rfc6979_nonce import rfc6979_nonce_
from btclib.ecc.ssa import _S2C_POINT_TAG as _SSA_POINT_TAG
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from tests.curves.curve_test import low_card_curves

random.seed(42)

# FIPS 180-4 section 4.2.2 and 5.3.3, for the midstate recomputation at
# the end of this file
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)  # fmt: skip
_SHA256_INIT = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)  # fmt: skip


def _rotr(x: int, n: int) -> int:
    """Rotate a 32-bit word right by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


_COMMIT = b"to be committed"
_MSG = b"to be signed"

# a key valid on every curve tested here, so that a signature is a
# deterministic function of the arguments and a parity that shows up once
# shows up always
_PRV_KEY = 12345678901234567890


def test_dsa_commitment() -> None:
    """Check a committing dsa signature verifies and opens only its value."""
    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            pub_key = mult(_PRV_KEY, ec.G, ec)
            for lower_s in (True, False):
                sig, receipt = dsa.sign(
                    _MSG,
                    _PRV_KEY,
                    None,
                    lower_s,
                    ec,
                    hf,
                    grind=False,
                    commit=_COMMIT,
                )
                # an ordinary signature, whether or not it commits
                dsa.assert_as_valid(_MSG, pub_key, sig, hf)
                dsa.assert_as_valid(
                    _MSG, pub_key, sig, hf, commit=_COMMIT, receipt=receipt
                )
                # to that value and to no other
                assert not dsa.verify(
                    _MSG, pub_key, sig, hf, commit=b"not this", receipt=receipt
                )
                # and with the receipt the signer kept, not another point
                assert not dsa.verify(
                    _MSG,
                    pub_key,
                    sig,
                    hf,
                    commit=_COMMIT,
                    receipt=mult(2, receipt, ec),
                )


def test_ssa_commitment() -> None:
    """Check a committing ssa signature verifies over both nonce parities."""
    # the tweak moves the nonce's point, so BIP340's even-y normalization
    # has to be applied to the moved one: both parities are collected
    # here, the odd ones being the signatures that fail without it
    parities = set()
    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            prv_key, x_Q = ssa.gen_keys(_PRV_KEY, ec)
            commit_hash = reduce_to_hlen(_COMMIT, hf)
            for i in range(4):
                aux = i.to_bytes(hf().digest_size, "big")
                sig, receipt = ssa.sign(_MSG, prv_key, aux, ec, hf, commit=_COMMIT)
                ssa.assert_as_valid(_MSG, x_Q, sig, hf)
                ssa.assert_as_valid(_MSG, x_Q, sig, hf, commit=_COMMIT, receipt=receipt)
                assert not ssa.verify(
                    _MSG, x_Q, sig, hf, commit=b"not this", receipt=receipt
                )
                assert not ssa.verify(
                    _MSG, x_Q, sig, hf, commit=_COMMIT, receipt=mult(2, receipt, ec)
                )
                # the receipt is the even-y point the tweak hashed
                assert receipt[1] % 2 == 0
                W = commit_point_(commit_hash, receipt, _SSA_POINT_TAG, ec, hf)
                parities.add(W[1] % 2)

    assert parities == {0, 1}


def test_the_python_path_is_the_committing_one() -> None:
    """A commitment tweaks the nonce, which the bindings do not hand out.

    Its `aux_rand32` would carry the half of the commitment that is
    RFC6979 additional data, but the libsecp256k1 fast path derives the
    nonce inside the call and returns neither the point nor a tweaked
    nonce, so it cannot be the path that commits. What says it took the
    other path is the signature: the one the committed nonce produces,
    derived here a second time out of the parts.
    """
    ec, hf = secp256k1, sha256
    commit_hash = reduce_to_hlen(_COMMIT, hf)
    msg_hash = reduce_to_hlen(_MSG, hf)

    sig, receipt = dsa.sign_(msg_hash, _PRV_KEY, grind=False, commit_hash=commit_hash)

    entropy = commit_entropy_(commit_hash, _S2C_DATA_TAG, hf)
    nonce = rfc6979_nonce_(msg_hash, _PRV_KEY, ec, hf, entropy)
    assert receipt == mult(nonce, ec.G, ec)
    tweaked_nonce, tweaked_receipt = commit_nonce_(
        commit_hash, nonce, _S2C_POINT_TAG, ec, hf
    )
    assert tweaked_receipt == receipt
    assert sig == dsa.sign_(msg_hash, _PRV_KEY, tweaked_nonce, grind=False)
    # and the point a verifier recomputes is the tweaked nonce's
    assert commit_point_(commit_hash, receipt, _S2C_POINT_TAG, ec, hf) == mult(
        tweaked_nonce, ec.G, ec
    )


# src/modules/ecdsa_s2c/tests_impl.h, test_ecdsa_s2c_fixed_vectors: the
# key and the message of that fixture, and its two (s2c_data, opening)
# pairs. The opening is the compressed original nonce point, which is
# btclib's receipt, and reproducing it pins the derivation of the
# untweaked nonce entire -- the s2c/ecdsa/data tag, RFC6979's additional
# data, and the seed layout key||msg||data that libsecp256k1's nonce
# function uses. What it does not reach is the *other* tag: the tweak
# comes after the opening, so s2c/ecdsa/point is pinned by the midstates
# below instead, and by nothing here
_ZKP_PRV_KEY = bytes.fromhex("55" * 32)
_ZKP_MSG_HASH = bytes.fromhex("88" * 32)
_ZKP_VECTORS = [
    pytest.param(
        "1bf6fb42f41eb876c4d7aa0d67242b00baab99dc2084493e4e63277fa1f77f22",
        "03f030def3188c0f56fcea87435b307643f45dafe22cbc82fd56034fae97417d3a",
        id="zkp-0",
    ),
    pytest.param(
        "35199a8fbf84ad6ef69a184c1b19285befbe06e60b6264e6d373893f6855e24a",
        "03901717ce7c7484a2ce1b7dc7403b14e0354971393ec092a7f3e0c8e4e2d2639d",
        id="zkp-1",
    ),
]


@pytest.mark.parametrize("commit_hash, opening", _ZKP_VECTORS)
def test_libsecp256k1_zkp_fixed_vectors(commit_hash: str, opening: str) -> None:
    """The receipt is the opening libsecp256k1-zkp's own fixture expects."""
    sig, receipt = dsa.sign_(
        _ZKP_MSG_HASH, _ZKP_PRV_KEY, grind=False, commit_hash=commit_hash
    )
    assert bytes_from_point(receipt, secp256k1).hex() == opening

    # and the commitment opens, which is what the fixture asserts next
    pub_key = mult(int.from_bytes(_ZKP_PRV_KEY, "big"), secp256k1.G, secp256k1)
    assert dsa.verify_(
        _ZKP_MSG_HASH, pub_key, sig, commit_hash=commit_hash, receipt=receipt
    )


# src/modules/ecdsa_s2c/main_impl.h hardcodes, for each of its two tagged
# hashes, the SHA256 state after the 64 bytes of SHA256(tag)||SHA256(tag).
# Those two constants are the only published thing that depends on the
# exact tag strings, and the point tag needs them: mangle it and every
# vector above still passes -- the opening is the untweaked nonce and the
# tweak comes after it -- while nothing btclib signs opens under
# secp256k1_ecdsa_s2c_verify_commit any more. A silent incompatibility is
# the one failure a copied constant invites, so the strings are recomputed
# into the constants rather than trusted alongside them.
_POINT_MIDSTATE = (
    0xA9B21C7B, 0x358C3E3E, 0x0B6863D1, 0xC62B2035,
    0xB44B40CE, 0x254A8912, 0x0F85D0D4, 0x8A5BF91C,
)  # fmt: skip
_DATA_MIDSTATE = (
    0xFEEFD675, 0x73166C99, 0xE2309CB8, 0x6D458113,
    0x01D3A512, 0x00E18112, 0x37EE0874, 0x421FC55F,
)  # fmt: skip
_ZKP_MIDSTATES = [
    pytest.param(_S2C_POINT_TAG, _POINT_MIDSTATE, id="point"),
    # the control: this one the openings pin too, so agreement here says
    # the recomputation below is right and not two errors cancelling
    pytest.param(_S2C_DATA_TAG, _DATA_MIDSTATE, id="data"),
]


def _sha256_midstate(block: bytes) -> tuple[int, ...]:
    """Return the SHA256 state after compressing one 64-byte block.

    hashlib finalizes and cannot be asked for a state, so the compression
    function is here. One block is all a midstate is, which is why there
    is no padding and no length: FIPS 180-4 section 6.2.2, verbatim.
    """
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = _SHA256_INIT
    for i in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + s1 + ((e & f) ^ (~e & g)) + _SHA256_K[i] + w[i]) & 0xFFFFFFFF
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
        h, g, f, e = g, f, e, (d + t1) & 0xFFFFFFFF
        d, c, b, a = c, b, a, (t1 + t2) & 0xFFFFFFFF

    return tuple(
        (x + y) & 0xFFFFFFFF
        for x, y in zip(_SHA256_INIT, (a, b, c, d, e, f, g, h), strict=True)
    )


@pytest.mark.parametrize("tag, midstate", _ZKP_MIDSTATES)
def test_the_tags_are_libsecp256k1s(tag: bytes, midstate: tuple[int, ...]) -> None:
    """Each tag string reproduces the midstate the C source publishes."""
    assert _sha256_midstate(sha256(tag).digest() * 2) == midstate


def test_the_commitment_reaches_the_nonce() -> None:
    """Two commitments over one message must not share an untweaked nonce.

    Sharing one is the whole vulnerability: the tweaked nonces then
    differ by a value the two openings make public, and two signatures
    over one message with a known nonce difference are two equations in
    the two unknowns k and the private key. The receipt *is* the
    untweaked nonce's point, so distinct receipts are the property, and
    a plain signature's nonce must be a third value again.
    """
    hf = sha256
    _, receipt_a = dsa.sign(_MSG, _PRV_KEY, grind=False, commit=b"contract A")
    _, receipt_b = dsa.sign(_MSG, _PRV_KEY, grind=False, commit=b"contract B")
    plain_nonce = rfc6979_nonce_(reduce_to_hlen(_MSG, hf), _PRV_KEY)
    plain_point = mult(plain_nonce, secp256k1.G, secp256k1)
    assert receipt_a != receipt_b
    assert plain_point not in {receipt_a, receipt_b}

    # ssa keeps its aux and mixes the commitment into it, so the same
    # holds there with the aux held fixed -- random aux would hide it
    prv_key, _ = ssa.gen_keys(_PRV_KEY)
    aux = bytes(32)
    _, receipt_a = ssa.sign(_MSG, prv_key, aux, commit=b"contract A")
    _, receipt_b = ssa.sign(_MSG, prv_key, aux, commit=b"contract B")
    plain_k, _, _, _ = bip340_nonce_(reduce_to_hlen(_MSG, hf), prv_key, aux)
    assert receipt_a != receipt_b
    assert mult(plain_k, secp256k1.G, secp256k1) not in {receipt_a, receipt_b}


def test_a_commitment_derives_its_own_nonce() -> None:
    """Verify dsa refuses a caller nonce beside a commitment.

    ssa has no nonce parameter to clash with: its aux is entropy, and
    the commitment is mixed into it rather than displacing it.
    """
    with pytest.raises(BTClibValueError, match="commitment derives its own nonce"):
        dsa.sign(_MSG, _PRV_KEY, 1234, commit=_COMMIT)
    with pytest.raises(BTClibValueError, match="commitment derives its own nonce"):
        dsa.sign_(
            reduce_to_hlen(_MSG, sha256), _PRV_KEY, 1234, commit_hash=b"\x00" * 32
        )


def test_a_plain_signature_opens_no_commitment() -> None:
    """The r of a signature that committed to nothing is not W.x."""
    ec = secp256k1
    nonce = 1 + random.randrange(ec.n - 1)
    receipt = mult(nonce, ec.G, ec)
    pub_key = mult(_PRV_KEY, ec.G, ec)
    sig = dsa.sign(_MSG, _PRV_KEY, nonce, grind=False)
    with pytest.raises(BTClibRuntimeError, match="commitment verification failed"):
        dsa.assert_as_valid(_MSG, pub_key, sig, commit=_COMMIT, receipt=receipt)

    prv_key, x_Q = ssa.gen_keys(_PRV_KEY, ec)
    ssa_sig = ssa.sign(_MSG, prv_key)
    with pytest.raises(BTClibRuntimeError, match="commitment verification failed"):
        ssa.assert_as_valid(_MSG, x_Q, ssa_sig, commit=_COMMIT, receipt=receipt)


def test_commitment_needs_the_receipt() -> None:
    """A commitment without its receipt, or a receipt alone, is a caller error.

    A TypeError and not a False: `verify` answers about a signature, and
    "nothing here opens this" is not an answer about one.
    """
    pub_key = mult(_PRV_KEY, secp256k1.G, secp256k1)
    sig, receipt = dsa.sign(_MSG, _PRV_KEY, grind=False, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="commitment without the receipt"):
        dsa.verify(_MSG, pub_key, sig, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="receipt without the commitment"):
        dsa.verify(_MSG, pub_key, sig, receipt=receipt)

    prv_key, x_Q = ssa.gen_keys(_PRV_KEY)
    ssa_sig, receipt = ssa.sign(_MSG, prv_key, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="commitment without the receipt"):
        ssa.verify(_MSG, x_Q, ssa_sig, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="receipt without the commitment"):
        ssa.verify(_MSG, x_Q, ssa_sig, receipt=receipt)


def test_zero_tweaked_nonce() -> None:
    """A tweak that cancels the nonce has no next candidate to try.

    One in n, so it is searched for rather than waited for, on a curve
    where one in n is one in eleven: the commitment is the free argument,
    the tweak being a hash of the other two.
    """
    ec, hf = low_card_curves["ec13_11"], sha256
    nonce = 1
    receipt = mult(nonce, ec.G, ec)
    commit_hash = next(
        h
        for h in (i.to_bytes(4, "big") for i in range(1000))
        if _tweak(h, receipt, _S2C_POINT_TAG, ec, hf) == ec.n - nonce
    )
    with pytest.raises(BTClibRuntimeError, match="zero tweaked nonce"):
        commit_nonce_(commit_hash, nonce, _S2C_POINT_TAG, ec, hf)


def test_zero_tweaked_nonce_through_the_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The binding's own refusal of a zero sum maps to the same error.

    On secp256k1 the loop above is not the one to force here --
    `secp256k1_ec_seckey_tweak_add` refuses a zero result exactly where
    the Python `% ec.n` in the fallback answers zero, and both have to
    raise the one error `commit_nonce_` has always raised for it.
    """
    ec = secp256k1
    nonce = 1 + random.randrange(ec.n - 1)
    monkeypatch.setattr(commit_nonce, "_tweak", lambda *_: ec.n - nonce)
    with pytest.raises(BTClibRuntimeError, match="zero tweaked nonce"):
        commit_nonce_(b"", nonce, _S2C_POINT_TAG, ec, sha256)


def test_commit_point_falls_back_at_infinity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tweaked point at infinity is answered as ec.add answers it.

    `secp256k1_ec_pubkey_tweak_add` refuses a result at infinity, where
    `ec.add` returns it -- the one behaviour difference between the two
    halves issue #271 calls out, so the fallback has to be exercised
    rather than trusted: a tweak forced to n - k lands exactly there.
    """
    ec = secp256k1
    k = 1 + random.randrange(ec.n - 1)
    receipt = mult(k, ec.G, ec)
    monkeypatch.setattr(commit_nonce, "_tweak", lambda *_: ec.n - k)
    assert commit_point_(b"", receipt, _S2C_POINT_TAG, ec, sha256) == INF


def test_the_python_tweaks_are_the_bindings_tweaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both halves, computed twice, are the same answer with the dispatch off.

    The bindings are the authority on the sum `commit_nonce_` computes
    and the point `commit_point_` computes, and the Python arithmetic is
    the reference implementation of both -- so what has to hold is that
    the two agree, over both parities of the resulting point, the shape
    `30e2ec19` used for BIP32 and taproot.
    """
    ec, hf = secp256k1, sha256
    parities = set()
    for i in range(16):
        commit_hash = i.to_bytes(4, "big")
        nonce = 1 + random.randrange(ec.n - 1)
        delegated_nonce, receipt = commit_nonce_(
            commit_hash, nonce, _S2C_POINT_TAG, ec, hf
        )
        delegated_point = commit_point_(commit_hash, receipt, _S2C_POINT_TAG, ec, hf)
        parities.add(delegated_point[1] % 2)
        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(commit_nonce, "_libsecp256k1_serves", lambda *_: False)
            assert commit_nonce_(commit_hash, nonce, _S2C_POINT_TAG, ec, hf) == (
                delegated_nonce,
                receipt,
            )
            assert (
                commit_point_(commit_hash, receipt, _S2C_POINT_TAG, ec, hf)
                == delegated_point
            )
    assert parities == {0, 1}
