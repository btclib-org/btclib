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
from hashlib import sha1, sha256
from typing import Any

import pytest
from btclib_libsecp256k1 import dsa as libsecp256k1_dsa

from btclib.alias import INF
from btclib.curves import (
    Curve,
    bytes_from_point,
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
from tests import vectors
from tests.curves.test_curve import low_card_curves, secp256k1_bis
from tests.test_to_key import Q as pub_key_point
from tests.test_to_key import Q_compressed as pub_key_compressed
from tests.test_to_key import q as prv_key_int
from tests.test_to_key import q_hexstring as prv_key_hexstring
from tests.test_to_key import (
    wif_compressed_string,
    wif_uncompressed_string,
    xprv_data,
    xprv_string,
    xpub_data,
    xpub_string,
)


def test_signature_on_an_equal_curve() -> None:
    """A curve equal to secp256k1 is secp256k1, bindings included."""
    # the dispatch used to compare identities, so signing with any other
    # object holding the secp256k1 parameters took the python path in
    # silence: the answer must be the one the singleton gives, and
    # RFC6979 makes it deterministic, hence comparable (issue #142)
    msg = b"Satoshi Nakamoto"

    q, Q = dsa.gen_keys(0x1, secp256k1_bis)
    sig = dsa.sign(msg, q, ec=secp256k1_bis)
    assert sig.ec == secp256k1
    assert sig == dsa.sign(msg, q)
    assert dsa.verify(msg, Q, sig)


def test_parse_stops_at_the_end_of_the_sequence() -> None:
    """A byte after the DER sequence is not part of the signature.

    It used to be dropped, so `Sig.parse(der + b"\\x01")` answered with the
    `Sig` of `der` -- which is how a two-byte hash type reached
    verification as a valid signature (issue #129). Core rejects the
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

    # ec.n has to be prime to sign
    test_curves = [
        low_card_curves["ec13_11"],
        # low_card_curves["ec13_19"],
        # low_card_curves["ec17_13"],
        low_card_curves["ec17_23"],
        low_card_curves["ec19_13"],
        # low_card_curves["ec19_23"],
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
    # a hash function other than sha256 takes the python implementation,
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


def signature_vectors(fname: str) -> list[Any]:
    """One case per signature vector, named by the message it signs."""
    return [
        pytest.param(vector, id=vectors.vector_id(index, vector["msg"][:16]))
        for index, vector in enumerate(vectors.load("ecc", "_data", fname)["vectors"])
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


def test_verify_answers_about_signatures_not_about_types() -> None:
    """A caller error is not an invalid signature.

    verify and verify_ caught Exception, so an hf passed as sha256()
    instead of sha256 -- a digest object where a constructor goes -- was
    reported as a signature that does not verify. So were AttributeError,
    RecursionError and MemoryError.
    """
    msg = b"a message to sign"
    q, Q = dsa.gen_keys(0x12345678)
    sig = dsa.sign(msg, q)
    assert dsa.verify(msg, Q, sig)

    # still False: these are answers about the signature
    assert not dsa.verify(b"another message", Q, sig)
    assert not dsa.verify(msg, Q, b"")
    assert not dsa.verify(msg, Q, b"\x30\x06\x02\x01\x80\x02\x01\x80")

    # a TypeError now says so, where it used to mean "invalid signature"
    with pytest.raises(TypeError, match="not callable"):
        dsa.verify(msg, Q, sig, hf=sha256())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="not callable"):
        dsa.verify_(reduce_to_hlen(msg), Q, sig, hf="sha256")  # type: ignore[arg-type]

    # BTClibRuntimeError is caught by name and not as RuntimeError, so a
    # RecursionError -- which is a RuntimeError -- is not swallowed either
    assert issubclass(RecursionError, RuntimeError)
    assert not issubclass(RecursionError, BTClibRuntimeError)
