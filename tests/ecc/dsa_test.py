#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.dsa` module."""

import secrets
from hashlib import sha1, sha256, sha512
from typing import Any

import pytest
from btclib_libsecp256k1 import dsa as libsecp256k1_dsa
from btclib_libsecp256k1 import recovery as libsecp256k1_recovery

from btclib.alias import INF, Point
from btclib.curves import (
    Curve,
    bytes_from_point,
    curve,
    double_mult,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.curves.curve import CURVES
from btclib.curves.curve_group import _mult
from btclib.ecc import dsa
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.number_theory import mod_inv
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from tests import load, vector_id
from tests.curves.curve_test import low_card_curves, no_bindings, secp256k1_bis
from tests.to_key_test import Q as pub_key_point
from tests.to_key_test import Q_compressed as pub_key_compressed
from tests.to_key_test import q as prv_key_int
from tests.to_key_test import q_hexstring as prv_key_hexstring
from tests.to_key_test import (
    wif_compressed_string,
    wif_uncompressed_string,
    xprv_data,
    xprv_string,
    xpub_data,
    xpub_string,
)


def test_signature_on_an_equal_curve() -> None:
    """A curve equal to secp256k1 is secp256k1, bindings included."""
    # guards against the dispatch comparing identities, which sends any
    # other object holding the secp256k1 parameters down the Python path
    # in silence: the answer must be the one the singleton gives, and
    # RFC6979 makes it deterministic, hence comparable (issue #142)
    msg = b"Satoshi Nakamoto"

    q, Q = dsa.gen_keys(0x1, secp256k1_bis)
    sig = dsa.sign(msg, q, ec=secp256k1_bis)
    assert sig.ec == secp256k1
    assert sig == dsa.sign(msg, q)
    assert dsa.verify(msg, Q, sig)


def test_parse_stops_at_the_end_of_the_sequence() -> None:
    """A byte after the DER sequence is not part of the signature.

    Guards against it being dropped: `Sig.parse(der + b"\\x01")`
    answering with the `Sig` of `der` is how a two-byte hash type
    reaches verification as a valid signature (issue #129). Core rejects the
    element with one size equation, `(lenR + lenS + 7) != sig.size()` in
    IsValidSignatureEncoding, and only under the flags asking for
    canonical DER: hence strict here, and hence the lenient parse the
    engine uses when DERSIG is off still takes it.
    """
    q, _ = dsa.gen_keys(0x1)
    der = dsa.sign(b"Satoshi Nakamoto", q).serialize()
    assert dsa.Sig.parse(der).serialize() == der

    err_msg = "trailing bytes after the DER sequence"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.Sig.parse(der + b"\x01")
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.Sig.parse((der + b"\x01").hex())

    assert dsa.Sig.parse(der + b"\x01", strict=False).serialize() == der


def test_signature() -> None:
    msg = b"Satoshi Nakamoto"

    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    dsa.assert_as_valid(msg, Q, sig)
    assert dsa.verify(msg, Q, sig)
    assert sig == dsa.Sig.parse(sig.serialize())
    assert sig == dsa.Sig.parse(sig.serialize().hex())

    # https://bitcointalk.org/index.php?topic=285142.40
    # Deterministic Usage of DSA and ECDSA (RFC 6979)
    r = 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
    s = 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5
    assert sig.r == r
    assert sig.s in (s, sig.ec.n - s)

    # malleability
    malleated_sig = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert dsa.verify(msg, Q, malleated_sig, lower_s=False)

    keys = dsa.recover_pub_keys(msg, sig)
    assert len(keys) == 2
    assert Q in keys

    keys = dsa.recover_pub_keys(msg, sig.serialize())
    assert len(keys) == 2
    assert Q in keys

    msg_fake = b"Craig Wright"
    assert not dsa.verify(msg_fake, Q, sig)
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa.assert_as_valid(msg_fake, Q, sig)

    _, Q_fake = dsa.gen_keys()
    assert not dsa.verify(msg, Q_fake, sig)
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa.assert_as_valid(msg, Q_fake, sig)

    err_msg = "not a valid public key: |no bytes representation for infinity point"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, INF, sig)

    sig_invalid = dsa.Sig(sig.ec.p, sig.s, check_validity=False)
    assert not dsa.verify(msg, Q, sig_invalid)
    err_msg = "scalar r not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_invalid)

    sig_invalid = dsa.Sig(sig.r, sig.ec.p, check_validity=False)
    assert not dsa.verify(msg, Q, sig_invalid)
    err_msg = "scalar s not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_invalid)

    err_msg = "private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, 0)

    # ephemeral key not in 1..n-1
    err_msg = "private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, 0)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, sig.ec.n)


def test_gec() -> None:
    """GEC 2: Test Vectors for SEC 1, section 2.

    - http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
    """
    # 2.1.1 Scheme setup
    ec = CURVES["secp160r1"]
    hf = sha1

    # 2.1.2 Key Deployment for U
    dU = 971761939728640320549601132085879836204587084162
    dU, QU = dsa.gen_keys(dU, ec)
    assert format(dU, f"{ec.n_size!s}x") == "aa374ffc3ce144e6b073307972cb6d57b2a4e982"
    assert QU == (
        466448783855397898016055842232266600516272889280,
        1110706324081757720403272427311003102474457754220,
    )
    assert (
        bytes_from_point(QU, ec).hex() == "0251b4496fecc406ed0e75a24a3c03206251419dc0"
    )

    # 2.1.3 Signing Operation for U
    msg = b"abc"
    k = 702232148019446860144825009548118511996283736794
    lower_s = False
    sig = dsa.sign_(reduce_to_hlen(msg, hf), dU, k, lower_s, ec, hf)
    assert sig.r == 0xCE2873E5BE449563391FEB47DDCBA2DC16379191
    assert sig.s == 0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54
    assert sig.ec == ec

    # 2.1.4 Verifying Operation for V
    dsa.assert_as_valid(msg, QU, sig, lower_s, hf)
    assert dsa.verify(msg, QU, sig, lower_s, hf)


def test_low_cardinality() -> None:
    """Test low-cardinality curves for all msg/key pairs."""

    # five of the eight low-cardinality curves. All eight have a prime
    # order, so that is not what selects them: the loop below is
    # quadratic in n, and ec13_19, ec17_13 and ec19_23 are left out to
    # bound the runtime rather than for any property they lack
    test_curves = [
        low_card_curves["ec13_11"],
        low_card_curves["ec17_23"],
        low_card_curves["ec19_13"],
        low_card_curves["ec23_19"],
        low_card_curves["ec23_31"],
    ]

    lower_s = True
    # only low cardinality test curves or it would take forever
    for ec in test_curves:
        for q in range(1, ec.n):  # all possible private keys
            QJ = _mult(q, ec.GJ, ec)  # public key
            for k in range(1, ec.n):  # all possible ephemeral keys
                RJ = _mult(k, ec.GJ, ec)
                r = ec.x_aff_from_jac(RJ) % ec.n
                k_inv = mod_inv(k, ec.n)
                for e in range(ec.n):  # all possible challenges
                    s = k_inv * (e + q * r) % ec.n
                    # bitcoin canonical 'low-s' encoding for ECDSA
                    if lower_s and s > ec.n // 2:
                        s = ec.n - s
                    if r == 0 or s == 0:
                        err_msg = "failed to sign: "
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            dsa._sign_(e, q, k, lower_s, ec)
                    else:
                        sig = dsa._sign_(e, q, k, lower_s, ec)
                        assert r == sig.r
                        assert s == sig.s
                        assert ec == sig.ec
                        # valid signature must pass verification
                        dsa._assert_as_valid_(e, QJ, r, s, lower_s, ec)

                        jac_keys = dsa._recover_pub_keys_(e, r, s, lower_s, ec)
                        Qs = [ec.aff_from_jac(key) for key in jac_keys]
                        assert ec.aff_from_jac(QJ) in Qs
                        assert len(jac_keys) in {2, 4}


def test_pub_key_recovery() -> None:
    ec = CURVES["secp112r2"]

    q = 0x10
    Q = mult(q, ec.G, ec)

    msg = b"Satoshi Nakamoto"
    sig = dsa.sign(msg, q, ec=ec)
    dsa.assert_as_valid(msg, Q, sig)
    assert dsa.verify(msg, Q, sig)

    keys = dsa.recover_pub_keys(msg, sig)
    assert len(keys) == 4
    assert Q in keys
    for Q in keys:
        assert dsa.verify(msg, Q, sig)


def test_key_id_is_j_above_the_parity_bit() -> None:
    """A key_id names SEC 1's j and a y_K-coordinate parity, in that order.

    x_K is r, or r + ec.n when ec.n < K[0] < ec.p and r alone is not on
    the curve; that second candidate is what a key_id of 2 or 3 asks for.
    Reaching it on secp256k1 takes r + ec.n < ec.p, some 2^-127 of
    signatures, so a low-cardinality curve is where it is expressible --
    and it is what `_recover_pub_keys_` iterates, so the two functions
    have to agree on it for the plural to be the singular over a range.
    """
    for ec in (low_card_curves["ec17_13"], low_card_curves["ec19_13"]):
        assert ec.cofactor == 2
        cases = 0
        for q in range(1, ec.n):
            Q = ec.aff_from_jac(_mult(q, ec.GJ, ec))
            for k in range(1, ec.n):
                x_K = ec.x_aff_from_jac(_mult(k, ec.GJ, ec))
                if not ec.n < x_K < ec.p:  # else x_K is r itself
                    continue
                r = x_K % ec.n
                k_inv = mod_inv(k, ec.n)
                for e in range(ec.n):
                    s = k_inv * (e + q * r) % ec.n
                    if r == 0 or s == 0:
                        continue
                    recovered = []
                    for key_id in range(2 * (ec.cofactor + 1)):
                        # a candidate x_K off the curve, or a key that
                        # does not verify, is "not this key_id"
                        try:
                            QJ = dsa._recover_pub_key_(key_id, e, r, s, False, ec)
                        except (BTClibValueError, BTClibRuntimeError):
                            continue
                        recovered.append((key_id, ec.aff_from_jac(QJ)))

                    key_ids = [key_id for key_id, Q_ in recovered if Q_ == Q]
                    assert key_ids, "the signer's own key is not recoverable"
                    # j = 1, never the j = 2 a mask in place would read
                    assert all(key_id >> 1 == 1 for key_id in key_ids)

                    # and the plural is that range, less what dropped out
                    jac_keys = dsa._recover_pub_keys_(e, r, s, False, ec)
                    assert [ec.aff_from_jac(QJ) for QJ in jac_keys] == [
                        Q_ for _, Q_ in recovered
                    ]
                    cases += 1
        assert cases == 288


def test_key_id_is_the_j_zero_pair_when_n_is_above_p() -> None:
    """The mirror of the case above, and issue 183's n > p box.

    `r = x_K % ec.n` can only reduce while n < p, so on a curve whose order
    is above the field prime -- four of the eight low-cardinality curves,
    and six of the 27 catalogued ones, `secp224k1` among them -- r *is* x_K
    and the signer is always named by the j = 0 pair, key_id 0 or 1. Which
    makes the j >= 1 candidates spurious rather than merely unlikely: they
    are the `(r + j*ec.n) % ec.p` wrap, and every one of them either misses
    the curve or fails to verify. Over the 5832 signatures ec13_19 admits,
    every one of them: 18 private keys, 18 nonces and 18 challenges, no r
    of them zero -- which is itself the n > p property, x_K never reaching
    a multiple of the order.
    """
    ec = low_card_curves["ec13_19"]
    assert ec.n > ec.p
    cases = 0
    for q in range(1, ec.n):
        Q = ec.aff_from_jac(_mult(q, ec.GJ, ec))
        for k in range(1, ec.n):
            r = ec.x_aff_from_jac(_mult(k, ec.GJ, ec)) % ec.n
            # asserted, not skipped: this is the n > p property the
            # docstring names -- x_K < p < n, so x_K % n is x_K, and no
            # multiple of G on this curve has x_K == 0 (measured: the r
            # values are {1,2,3,4,5,6,9,10,12}). `if r == 0: continue`
            # was a branch no input could take, so it read as a
            # possibility this curve has, and a swapped curve would have
            # skipped silently where this says so
            assert r
            k_inv = mod_inv(k, ec.n)
            for e in range(ec.n):
                s = k_inv * (e + q * r) % ec.n
                if s == 0:
                    continue
                key_ids = []
                for key_id in range(2 * (ec.cofactor + 1)):
                    try:
                        QJ = dsa._recover_pub_key_(key_id, e, r, s, False, ec)
                    except (BTClibValueError, BTClibRuntimeError):
                        continue
                    if ec.aff_from_jac(QJ) == Q:
                        key_ids.append(key_id)

                assert key_ids, "the signer's own key is not recoverable"
                assert all(key_id >> 1 == 0 for key_id in key_ids)
                cases += 1
    assert cases == 5832


def test_crack_prv_key() -> None:
    ec = CURVES["secp256k1"]

    q, _ = dsa.gen_keys(1)
    k = 1 + secrets.randbelow(ec.n - 1)

    msg1 = b"Paolo is afraid of ephemeral random numbers"
    m_1 = reduce_to_hlen(msg1)
    sig1 = dsa.sign_(m_1, q, k)

    msg2 = b"and Paolo is right to be afraid"
    m_2 = reduce_to_hlen(msg2)
    sig2 = dsa.sign_(m_2, q, k)

    q_cracked, k_cracked = dsa.crack_prv_key(msg1, sig1.serialize(), msg2, sig2)

    #  if the lower_s convention has changed only one of s1 and s2
    sig2 = dsa.Sig(sig2.r, ec.n - sig2.s)
    qc2, kc2 = dsa.crack_prv_key(msg1, sig1, msg2, sig2.serialize())

    assert (q == q_cracked and k in (k_cracked, ec.n - k_cracked)) or (
        q == qc2 and k in (kc2, ec.n - kc2)
    )

    with pytest.raises(BTClibValueError, match="not the same r in signatures"):
        dsa.crack_prv_key(msg1, sig1, msg2, dsa.Sig(16, sig1.s))

    with pytest.raises(BTClibValueError, match="identical signatures"):
        dsa.crack_prv_key(msg1, sig1, msg1, sig1)

    a = ec._a
    b = ec._b
    alt_ec = Curve(ec.p, a, b, ec.double_aff(ec.G), ec.n, ec.cofactor)
    sig = dsa.Sig(sig1.r, sig1.s, alt_ec)
    with pytest.raises(BTClibValueError, match="not the same curve in signatures"):
        dsa.crack_prv_key(msg1, sig, msg2, sig2)


def test_forge_hash_sig() -> None:
    """Forging valid hash signatures."""

    ec = CURVES["secp256k1"]

    # see https://twitter.com/pwuille/status/1063582706288586752
    # Satoshi's key
    key = "03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    Q = point_from_octets(key, ec)

    # pick u1 and u2 at will
    u1 = 1
    u2 = 2
    R = double_mult(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, lower_s=True, ec=ec)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, lower_s=True, ec=ec)


def test_sign_input_type() -> None:
    msg = b"Satoshi Nakamoto"
    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    dsa.assert_as_valid(msg, Q, sig)
    dsa.assert_as_valid(msg, Q, sig.serialize())


def test_prv_key_is_not_a_pub_key() -> None:
    """Verification must reject a private key, in any representation.

    https://github.com/btclib-org/btclib/issues/143
    """
    msg = b"Satoshi Nakamoto"
    sig = dsa.sign(msg, prv_key_int)
    # a hash function other than sha256 takes the Python implementation,
    # which converts the key on its own
    sig_sha1 = dsa.sign(msg, prv_key_int, hf=sha1)

    for prv_key in (
        prv_key_int,
        prv_key_hexstring,
        wif_compressed_string,
        wif_uncompressed_string,
        xprv_string,
        xprv_data,
    ):
        assert not dsa.verify(msg, prv_key, sig)  # type: ignore[arg-type]
        assert not dsa.verify(msg, prv_key, sig_sha1, hf=sha1)  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError, match="not a public key"):
            dsa.assert_as_valid(msg, prv_key, sig)  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError, match="not a public key"):
            dsa.assert_as_valid(msg, prv_key, sig_sha1, hf=sha1)  # type: ignore[arg-type]
        # neither the rejection nor its message may echo the secret
        with pytest.raises(BTClibValueError) as excinfo:
            dsa.assert_as_valid(msg, prv_key, sig)  # type: ignore[arg-type]
        assert str(prv_key) not in str(excinfo.value)

    # the very same key, in its public representations, still verifies
    for pub_key in (
        pub_key_point,
        pub_key_compressed,
        pub_key_compressed.hex(),
        xpub_string,
        xpub_data,
    ):
        assert dsa.verify(msg, pub_key, sig)
        assert dsa.verify(msg, pub_key, sig_sha1, hf=sha1)


def test_the_two_secret_multiplications_answer_the_python_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`gen_keys` and `_sign_` multiply the generator through `mult`.

    Both scalars are secret — the private key of a key pair, the nonce
    of a signature — and both points are the generator's multiples, so
    on secp256k1 `mult` hands them to libsecp256k1, which is constant
    time where the Jacobian fixed window under it is not.

    The Python path is what every other curve takes and what
    `test_low_cardinality` exercises there; here it is computed for
    secp256k1 too, with the dispatch inside `mult` switched off, and the
    two answers are held to each other. `_mult` beside them is the third
    opinion: it is the arithmetic being delegated, called directly.
    """
    ec = secp256k1
    nonce = 0x9E5755E5A8FCC1B0A2FD1E0AD9E8D6B29B67D67E6C6A0DEE01E7E1F30DB9A0BE
    for q in (0x1, 0x2, prv_key_int, ec.n - 1):
        _, Q = dsa.gen_keys(q)
        sig = dsa._sign_(0x1234, q, nonce, True, ec)

        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(curve, "_libsecp256k1_applicable", lambda *_: False)
            assert dsa.gen_keys(q)[1] == Q
            assert dsa._sign_(0x1234, q, nonce, True, ec) == sig

        assert Q == ec.aff_from_jac(_mult(q, ec.GJ, ec))
        assert sig.r == ec.x_aff_from_jac(_mult(nonce, ec.GJ, ec)) % ec.n


def test_libsecp256k1() -> None:
    msg = b"Satoshi Nakamoto"
    prvkey_int, pubkey_point = dsa.gen_keys(0x1)
    btclib_sig = dsa.sign(msg, prvkey_int)
    pub_key = bytes_from_point(pubkey_point)
    assert dsa.verify(msg, pub_key, btclib_sig)
    assert dsa.verify(msg, pub_key, btclib_sig.serialize())

    msg_hash = reduce_to_hlen(msg)
    libsecp256k1_sig = libsecp256k1_dsa.sign(msg_hash, prvkey_int)
    assert btclib_sig.serialize() == libsecp256k1_sig
    assert libsecp256k1_dsa.verify(msg_hash, pub_key, btclib_sig.serialize())
    assert dsa.verify_(msg_hash, pub_key, libsecp256k1_sig)


def _recovered(
    key_id: int, msg: bytes, sig: dsa.Sig, lower_s: bool = True
) -> Point | None:
    """The recovered key, or None for a candidate that recovers nothing."""
    try:
        return dsa.recover_pub_key(key_id, msg, sig, lower_s)
    except (BTClibValueError, BTClibRuntimeError):
        return None


def _recovered_(key_id: int, msg_hash: bytes, sig: dsa.Sig) -> Point | None:
    """The same, for a caller holding the hash rather than the message."""
    try:
        return dsa.recover_pub_key_(key_id, msg_hash, sig)
    except (BTClibValueError, BTClibRuntimeError):
        return None


def test_libsecp256k1_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """`recover_pub_key` through secp256k1_ecdsa_recover.

    A recid is a key_id -- the same two bits, in the same order -- so the
    two implementations have to answer the same point for every candidate,
    and the same refusal for the candidates that recover nothing, which on
    secp256k1 is key_id 2 and 3. That is what the delegation rests on: the
    recovery flag of a message signature carries a key_id from outside, so
    the number has to mean there what it means here.

    `recover_pub_keys` beside them is the enumeration, which is these same
    four recids on secp256k1 with sha256 and the Python loop everywhere
    else; `test_recovery_multiplies_in_libsecp256k1` below is where the
    three implementations of it are held to one list.
    """
    msg = b"Satoshi Nakamoto"
    for q in (0x1, 0x2, prv_key_int, secp256k1.n - 1):
        prv_key, Q = dsa.gen_keys(q)
        sig = dsa.sign(msg, prv_key)
        keys = dsa.recover_pub_keys(msg, sig)
        assert Q in keys

        recovering = []
        for key_id in range(2 * (secp256k1.cofactor + 1)):
            delegated = _recovered(key_id, msg, sig)
            with monkeypatch.context() as no_bindings:
                no_bindings.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
                python = _recovered(key_id, msg, sig)
            assert delegated == python
            if delegated is not None:
                assert delegated in keys
                recovering.append(key_id)
        # the signer's own key has j = 0, so it is one of the first pair,
        # and the second pair recovers nothing: r + ec.n < ec.p is some
        # 2^-127 of signatures, and both implementations require it
        assert recovering == [0, 1]

        # the lower-s rule is the caller's, and it is btclib that applies
        # it: the recoverable parser takes any s in [1, n-1]
        key_id = next(k for k in recovering if _recovered(k, msg, sig) == Q)
        malleated = dsa.Sig(sig.r, secp256k1.n - sig.s)
        err_msg = "not a low s"
        with pytest.raises(BTClibValueError, match=err_msg):
            dsa.recover_pub_key(key_id ^ 1, msg, malleated)
        assert _recovered(key_id ^ 1, msg, malleated, lower_s=False) == Q


def test_recover_pub_keys_takes_the_hash_that_recover_pub_keys_reduces() -> None:
    """The two spellings of the enumeration are one function.

    `challenge_` reduces a digest to an integer and does not hash it
    again, so the underscore spelling is the one a caller holding a hash
    -- a sig_hash, the `reduce_to_hlen(magic_message(msg))` of a message
    signature -- has to reach for: the other would hash it a second time.
    Nothing in btclib calls either, bms naming its own key_id since issue
    269, so this is what holds the pairing that justifies both.

    The malleated signature is the plural's answer where the singular
    raises: a candidate that fails is dropped rather than reported, and
    every candidate fails the lower-s rule at once, so the enumeration of
    a high-s signature is empty and not an error. Both spellings say so on
    both implementations -- sha256 here is the four recover calls, sha512
    the Python loop -- the rule being btclib's either way, since the
    recoverable parser takes any s in [1, n-1].
    """
    msg = b"Satoshi Nakamoto"
    for q in (0x1, 0x2, prv_key_int, secp256k1.n - 1):
        prv_key, Q = dsa.gen_keys(q)
        # the hash function is the argument both spellings thread through
        # to the challenge, and it is also what the dispatch reads: sha256
        # enumerates through the bindings, sha512 through the Python loop
        for hf in (sha256, sha512):
            msg_hash = reduce_to_hlen(msg, hf)
            sig = dsa.sign(msg, prv_key, hf=hf)
            keys = dsa.recover_pub_keys(msg, sig, hf=hf)
            assert Q in keys
            assert dsa.recover_pub_keys_(msg_hash, sig, hf=hf) == keys
            # the octets spelling of both arguments, which is the shape a
            # caller of the public API is likelier to hold
            assert dsa.recover_pub_keys_(msg_hash.hex(), sig.serialize(), hf=hf) == keys

            malleated = dsa.Sig(sig.r, secp256k1.n - sig.s)
            assert dsa.recover_pub_keys_(msg_hash, malleated, hf=hf) == []
            assert Q in dsa.recover_pub_keys_(msg_hash, malleated, lower_s=False, hf=hf)


def test_recovery_multiplies_in_libsecp256k1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The three implementations of the enumeration, and one answer (issue 286).

    On secp256k1 with sha256 `recover_pub_keys` is four
    `secp256k1_ecdsa_recover` calls: the enumeration is btclib's loop --
    the bindings recover the one candidate a recid names -- but every
    candidate in it is one of those recids. Patching `dsa`'s own dispatch
    off reaches the Python enumeration, whose step 1.6.1 is still
    libsecp256k1's; patching `curves.curve`'s off as well reaches the wNAF
    under that.

    The three have to answer the same *list* and not merely the same set:
    a candidate that fails step 1.6 is dropped rather than reported, so
    the position of a key in it is what a caller reads a key_id from, and
    two implementations that drop differently would disagree about the
    recovery flag of a message signature without disagreeing about any
    key. Which is why `no_bindings` alone is not this test: it leaves
    `dsa`'s dispatch on, and the comparison would be the bindings against
    themselves.
    """
    msg = b"Satoshi Nakamoto"
    for q in (0x1, 0x2, prv_key_int, secp256k1.n - 1):
        prv_key, Q = dsa.gen_keys(q)
        sig = dsa.sign(msg, prv_key)
        # four recover calls, which is what production runs here
        keys = dsa.recover_pub_keys(msg, sig)
        assert Q in keys
        key_ids = range(2 * (secp256k1.cofactor + 1))
        # and the same, candidate by candidate, None where one recovers
        # nothing: the enumeration is these four answers less the Nones
        recovered = [_recovered(key_id, msg, sig) for key_id in key_ids]
        assert [key for key in recovered if key is not None] == keys

        with monkeypatch.context() as patch:
            # the Python enumeration, its double_mult still delegated
            patch.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
            assert dsa.recover_pub_keys(msg, sig) == keys
            assert [_recovered(key_id, msg, sig) for key_id in key_ids] == recovered

            # and the same with the arithmetic under it patched off too
            no_bindings(patch)
            assert dsa.recover_pub_keys(msg, sig) == keys
            assert [_recovered(key_id, msg, sig) for key_id in key_ids] == recovered


@pytest.mark.parametrize(
    ("r", "expected_key_ids"),
    [(2, [0, 1, 2, 3]), (7, [2, 3])],
    ids=["four-candidates", "the-j-one-pair-alone"],
)
def test_the_enumeration_asks_for_the_j_one_candidates(
    r: int, expected_key_ids: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """key_id 2 and 3, which no signature of secp256k1 will produce.

    They need `r + ec.n < ec.p`, some 2^-127 of signatures, so a signature
    cannot reach them and the enumeration would answer the same list with
    those two candidates never asked for. An r is fabricated instead: with
    `r = 2` both r and `r + ec.n` are x-coordinates of the curve and all
    four candidates recover, and with `r = 7` only `r + ec.n` is, so the
    list is two keys long and their key_ids are 2 and 3 -- the dense-list
    case, where an index into the list is not the key_id that produced it.

    `(r, s)` is no signature anybody made, and does not have to be: step
    1.6 is arithmetic on r and s, and the key it recovers satisfies the
    equation by construction. What it pins is that the four `recover` calls
    ask for the same candidates as the Python loop, in the same order, and
    drop the same ones -- on the two key_ids the bindings and the Python
    path arrive at differently, `recid & 2` against `(r + j*ec.n) % ec.p`.
    """
    msg_hash = reduce_to_hlen(b"Satoshi Nakamoto")
    sig = dsa.Sig(r, 12345)

    keys = dsa.recover_pub_keys_(msg_hash, sig)
    candidates = [_recovered_(key_id, msg_hash, sig) for key_id in range(4)]
    assert [
        key_id for key_id, key in enumerate(candidates) if key is not None
    ] == expected_key_ids
    assert [key for key in candidates if key is not None] == keys

    with monkeypatch.context() as patch:
        patch.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
        assert dsa.recover_pub_keys_(msg_hash, sig) == keys
        no_bindings(patch)
        assert dsa.recover_pub_keys_(msg_hash, sig) == keys


def _search_key_id(msg: bytes, sig: dsa.Sig, Q: Point, lower_s: bool = True) -> int:
    """The key_id arrived at by recovering and comparing, not by signing.

    The derivation `sign_recoverable` exists not to run: it is here as the
    independent opinion its key_id is held against, one recovery per
    candidate until one is the signer's own key.
    """
    for key_id in range(2 * (sig.ec.cofactor + 1)):
        if _recovered(key_id, msg, sig, lower_s) == Q:
            return key_id
    raise AssertionError("no key_id recovers the public key")


def test_the_key_id_search_reports_a_key_it_cannot_reach() -> None:
    """The helper above raises rather than answer, and this is why it can.

    Its loop returns the first key_id that recovers Q, so a Q no candidate
    recovers has to leave it with nothing to return. Untested, that
    fallthrough would be the one line of the cross-check that never runs --
    and a search that answered 0 for a key it never found would make every
    caller above agree with `sign_recoverable` for the wrong reason.
    """
    msg = b"a message"
    prv_key, _Q = dsa.gen_keys()
    sig = dsa.sign(msg, prv_key)

    # a key of somebody else: the signature is valid, and none of its
    # candidates is this point
    _other_prv_key, other_Q = dsa.gen_keys()

    err_msg = "no key_id recovers the public key"
    with pytest.raises(AssertionError, match=err_msg):
        _search_key_id(msg, sig, other_Q)


def test_sign_recoverable_is_sign_plus_the_key_id_a_search_would_find(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The recoverable spelling signs what `sign` signs, and names the key_id.

    Three opinions on one signature, and they have to be the same one:
    `sign`, which is r and s alone; `secp256k1_ecdsa_sign_recoverable`,
    which is r, s and the recid; and the search, which recovers candidate
    after candidate until one is the signer's key. The Python path is asked
    for all three too, the dispatch patched off, because that is where the
    key_id is derived rather than reported -- read off the nonce's point at
    signing time, which is the whole of issue 285.
    """
    for i in range(20):
        msg = f"message {i}".encode()
        prv_key, Q = dsa.gen_keys()
        msg_hash = reduce_to_hlen(msg)

        sig, key_id = dsa.sign_recoverable(msg, prv_key)
        assert sig == dsa.sign(msg, prv_key)
        assert (sig, key_id) == dsa.sign_recoverable_(msg_hash, prv_key)
        assert dsa.recover_pub_key(key_id, msg, sig) == Q
        assert key_id == _search_key_id(msg, sig, Q)

        # the bindings' own recoverable signing, which is what the
        # delegated path above answered with
        sig_bytes, recid = libsecp256k1_recovery.sign(msg_hash, prv_key)
        assert sig.r == int.from_bytes(sig_bytes[:32], "big")
        assert sig.s == int.from_bytes(sig_bytes[32:], "big")
        assert key_id == recid

        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
            assert dsa.sign_recoverable(msg, prv_key) == (sig, key_id)


def test_the_key_id_survives_what_the_bindings_decline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each condition that sends a signature down the Python path.

    A nonce of the caller's, a high s allowed, another hash function and
    another curve: four signatures the bindings do not make, and the key_id
    of each still recovers the signer. The first two are secp256k1, so the
    dispatch is what declines them rather than the curve, and patching it
    off must not change the answer -- the Python path is the only one that
    ever produced them.
    """
    msg = b"Satoshi Nakamoto"
    prv_key, Q = dsa.gen_keys(prv_key_int)
    nonce = 0x9E5755E5A8FCC1B0A2FD1E0AD9E8D6B29B67D67E6C6A0DEE01E7E1F30DB9A0BE

    cases: list[dict[str, Any]] = [
        {"nonce": nonce},
        {"lower_s": False},
        {"hf": sha512},
    ]
    for kwargs in cases:
        lower_s = bool(kwargs.get("lower_s", True))
        sig, key_id = dsa.sign_recoverable(msg, prv_key, **kwargs)
        hf = kwargs.get("hf", sha256)
        assert dsa.recover_pub_key(key_id, msg, sig, lower_s, hf) == Q
        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
            assert dsa.sign_recoverable(msg, prv_key, **kwargs) == (sig, key_id)

    ec = CURVES["secp112r2"]
    q, Q = dsa.gen_keys(0x10, ec)
    sig, key_id = dsa.sign_recoverable(msg, q, ec=ec)
    assert dsa.recover_pub_key(key_id, msg, sig) == Q
    assert key_id == _search_key_id(msg, sig, Q)


def test_the_low_s_negation_flips_the_key_id_parity_bit() -> None:
    """Negating s mirrors K, so bit 0 flips and j does not.

    The two signatures over one nonce are the same r and the two s of the
    malleability -- which is why `lower_s=False` is how the negation is
    reached from outside: the same `_sign_recoverable_` call with the
    reflection left out. Where the s that was computed is already low the
    negation never happens and the two key_ids agree, so both outcomes have
    to be reached for the assertion to be about anything, and the nonces
    are fixed rather than drawn: which s comes out is a property of
    (c, q, nonce) and a random one would make the coverage random too.
    """
    ec = secp256k1
    flipped = kept = 0
    for q in (0x1, 0x2, prv_key_int, ec.n - 1):
        for c in (0x1234, 0xDEAD, ec.n - 1):
            for nonce in (0x1, 0x2, 0xC0FFEE):
                high_s, high_id = dsa._sign_recoverable_(c, q, nonce, False, ec)
                low_s, low_id = dsa._sign_recoverable_(c, q, nonce, True, ec)
                assert high_s.r == low_s.r
                negated = high_s.s > ec.n // 2
                assert low_s.s == (ec.n - high_s.s if negated else high_s.s)
                assert low_id == (high_id ^ 1 if negated else high_id)
                # and j is the bit the reflection cannot reach: x_K is what
                # both signatures were built from
                assert high_id >> 1 == low_id >> 1
                flipped += negated
                kept += not negated
    assert flipped and kept


def test_the_key_id_names_j_where_j_is_reachable() -> None:
    """The cofactor-2 curves, where `x_K // ec.n` is not a boolean.

    On secp256k1 the j bit needs r + ec.n < ec.p, some 2^-127 of
    signatures, so `2 if x_K != r else 0` would pass every test the
    delegated path can be held to. These two curves have x_K above ec.n for
    two of their twelve nonces, and there the signer's own key is named by
    a key_id of 2 or 3: every signature they admit is made both ways round
    and its key_id required to recover the signer.
    """
    for name, expected in (("ec17_13", 2880), ("ec19_13", 3456)):
        ec = low_card_curves[name]
        assert ec.cofactor == 2
        cases = 0
        j_reached = 0
        for q in range(1, ec.n):
            Q = ec.aff_from_jac(_mult(q, ec.GJ, ec))
            for k in range(1, ec.n):
                for c in range(ec.n):
                    for lower_s in (True, False):
                        try:
                            sig, key_id = dsa._sign_recoverable_(c, q, k, lower_s, ec)
                        except BTClibRuntimeError:  # r == 0 or s == 0
                            continue
                        QJ = dsa._recover_pub_key_(key_id, c, sig.r, sig.s, lower_s, ec)
                        assert ec.aff_from_jac(QJ) == Q
                        cases += 1
                        j_reached += key_id >> 1
        assert cases == expected
        # the same j = 1 count from both, the two nonces above ec.n being
        # two on either curve; what differs is the total, ec17_13 having
        # two nonces whose x_K is a multiple of 13 and so no signature at
        # all where ec19_13 has none
        assert j_reached == 576


def signature_vectors(fname: str) -> list[Any]:
    """One case per signature vector, named by the message it signs."""
    return [
        pytest.param(vector, id=vector_id(index, vector["msg"][:16]))
        for index, vector in enumerate(load("ecc", "_data", fname)["vectors"])
    ]


# https://github.com/rustyrussell/secp256k1-py/blob/master/tests/data/ecdsa_sig.json
# 199 vectors, JSON-equal to upstream and reformatted on the way in;
# tests/_data/README.md pins the revision, for this and the file below
@pytest.mark.parametrize("vector", signature_vectors("ecdsa_sig.json"))
def test_libsecp256k1_py_vectors_ecdsa(vector: dict[str, str]) -> None:
    msg_hash = bytes.fromhex(vector["msg"])
    assert len(msg_hash) == 32
    sig_raw = bytes.fromhex(vector["sig"])
    prv_key = bytes.fromhex(vector["privkey"])
    assert len(prv_key) == 32

    sig = dsa.sign_(msg_hash, prv_key)
    assert sig.serialize() == sig_raw[:-1]
    pub_key = pub_keyinfo_from_prv_key(prv_key, compressed=True)[0]
    assert dsa.verify_(msg_hash, pub_key, sig)

    sig_der = libsecp256k1_dsa.sign(msg_hash, prv_key)
    assert sig_der == sig_raw[:-1]
    pub_key = pub_keyinfo_from_prv_key(prv_key)[0]
    assert libsecp256k1_dsa.verify(msg_hash, pub_key, sig_der)


# https://github.com/rustyrussell/secp256k1-py/blob/master/tests/data/ecdsa_custom_nonce_sig.json
# 199 vectors, same upstream, same reformatting
@pytest.mark.parametrize("vector", signature_vectors("ecdsa_custom_nonce_sig.json"))
def test_libsecp256k1_py_vectors_ecdsa_nonce(vector: dict[str, str]) -> None:
    msg_hash = bytes.fromhex(vector["msg"])
    assert len(msg_hash) == 32
    sig_der = bytes.fromhex(vector["sig"])
    nonce = bytes.fromhex(vector["nonce"])
    assert len(nonce) == 32
    prv_key = bytes.fromhex(vector["privkey"])
    assert len(prv_key) == 32

    sig = dsa.sign_(msg_hash, prv_key, nonce)
    assert sig.serialize() == sig_der
    pub_key = pub_keyinfo_from_prv_key(prv_key, compressed=True)[0]
    assert dsa.verify_(msg_hash, pub_key, sig_der)

    pub_key = pub_keyinfo_from_prv_key(prv_key)[0]
    assert libsecp256k1_dsa.verify(msg_hash, pub_key, sig_der)


def test_verify_infinity_point() -> None:
    """K = w*(c + r*q)*G is INF whenever c == -r*q (mod n).

    For Q = G (q = 1) and r = s = 1: w = 1, u = n - 1, v = 1, so
    K = u*G + v*Q is INF. The low-cardinality loop can never get here:
    it only verifies signatures it just produced, whose K = k*G with
    k nonzero.
    """
    ec = CURVES["secp256k1"]
    err_msg = r"invalid \(INF\) key"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa._assert_as_valid_(ec.n - 1, ec.GJ, 1, 1, True, ec)


def test_verify_with_another_hash_function_on_both_arithmetics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verification equation the bindings decline, on both arithmetics.

    A hash function that is not sha256 is one of the reasons
    `libsecp256k1_dsa.verify` is not asked -- a commitment to check, a
    caller-imposed nonce and another curve are the others -- and what
    answers instead is `_assert_as_valid_`, whose multiplication is the
    bindings' all the same: 128 us against the 1.10 ms of the Python
    arithmetic, which is the whole of this verification either way.

    The two must not disagree, about a valid signature or an invalid one,
    and least of all about the infinity point: a libsecp256k1 pubkey is
    never the identity, so the K that is INF is answered on this side of
    the boundary -- from the z == 0 of `jac_from_aff`, in the same line
    that answered it before.
    """
    msg = b"a message to sign"
    q, Q = dsa.gen_keys(0x1234567890ABCDEF)
    sig = dsa.sign(msg, q, hf=sha512)
    ec = sig.ec

    def checks() -> None:
        dsa.assert_as_valid(msg, Q, sig, hf=sha512)
        assert dsa.verify(msg, Q, sig, hf=sha512)
        # the same signature over another message
        assert not dsa.verify(b"another message", Q, sig, hf=sha512)
        # K = u*G + v*Q is INF for Q = G, r = s = 1 and c = n-1
        with pytest.raises(BTClibRuntimeError, match=r"invalid \(INF\) key"):
            dsa._assert_as_valid_(ec.n - 1, ec.GJ, 1, 1, True, ec)

    checks()
    no_bindings(monkeypatch)
    checks()


def test_verify_answers_about_signatures_not_about_types() -> None:
    """A caller error is not an invalid signature.

    Guards against verify and verify_ catching Exception, which reports
    an hf passed as sha256() instead of sha256 -- a digest object where
    a constructor goes -- as a signature that does not verify, and does
    the same to AttributeError, RecursionError and MemoryError.
    """
    msg = b"a message to sign"
    q, Q = dsa.gen_keys(0x12345678)
    sig = dsa.sign(msg, q)
    assert dsa.verify(msg, Q, sig)

    # still False: these are answers about the signature
    assert not dsa.verify(b"another message", Q, sig)
    assert not dsa.verify(msg, Q, b"")
    assert not dsa.verify(msg, Q, b"\x30\x06\x02\x01\x80\x02\x01\x80")

    # a TypeError says so: raised, not folded into False
    with pytest.raises(TypeError, match="not callable"):
        dsa.verify(msg, Q, sig, hf=sha256())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="not callable"):
        dsa.verify_(reduce_to_hlen(msg), Q, sig, hf="sha256")  # type: ignore[arg-type]

    # BTClibRuntimeError is caught by name and not as RuntimeError, so a
    # RecursionError -- which is a RuntimeError -- is not swallowed either
    assert issubclass(RecursionError, RuntimeError)
    assert not issubclass(RecursionError, BTClibRuntimeError)
