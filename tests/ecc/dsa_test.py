# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.dsa` module."""

import secrets
from hashlib import sha1, sha256, sha512
from typing import Any

import pytest

from btclib._libsecp256k1 import dsa as libsecp256k1_dsa
from btclib._libsecp256k1 import ffi as libsecp256k1_ffi
from btclib._libsecp256k1 import recovery as libsecp256k1_recovery
from btclib.alias import INF, JacPoint, Point
from btclib.curves import (
    Curve,
    PreparedPoint,
    bytes_from_point,
    curve,
    curve_group,
    double_mult_var,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.curves.curve import CURVES
from btclib.curves.curve_group import CurveGroup, _mult
from btclib.ecc import dsa
from btclib.ecc.rfc6979_nonce import challenge_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.number_theory import mod_inv_var
from btclib.to_pub_key import pub_keyinfo_from_prv_key, pub_keyinfo_from_pub_key
from tests import load, needs_bindings, vector_id
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
    """  # noqa: D301
    # `b"\x01"` above is the literal text of the code quoted, backslash
    # and all: an r prefix would double that backslash instead
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
    """Sign and verify, with the RFC6979 vector, recovery and refusals."""
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
    # the vector is the plain RFC6979 signature, and grinding is a search
    # over nonces: this message's first draw has a high r, so the default
    # signs it again with a counter and lands somewhere else
    plain = dsa.sign(msg, q, grind=False)
    assert plain.r == r
    assert plain.s in {s, sig.ec.n - s}
    assert sig != plain
    assert dsa.verify(msg, Q, plain)

    # malleability: the high-s twin is a valid signature of the same
    # message under the same key, and verification says so -- which form s
    # took was the signer's choice, so nothing that only reads the
    # signature has standing to refuse it (issue 695)
    malleated_sig = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert dsa.verify(msg, Q, malleated_sig)
    dsa.assert_as_valid(msg, Q, malleated_sig)

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

    # the boundary itself, not `ec.p` (a different, larger prime): `< n`
    # weakened to `<= n` would still refuse `ec.p` and miss `n` exactly
    with pytest.raises(BTClibValueError, match="scalar r not in 1..n-1: "):
        dsa.Sig(sig.ec.n, sig.s)
    with pytest.raises(BTClibValueError, match="scalar s not in 1..n-1: "):
        dsa.Sig(sig.r, sig.ec.n)

    # the lower boundary too, zero and not one below it: `0 < r`/`0 < s`
    # weakened to `-1 <` would accept the one value this rule excludes
    # that ssa.Sig's own 0..n-1 does not
    with pytest.raises(BTClibValueError, match="scalar r not in 1..n-1: "):
        dsa.Sig(0, sig.s)
    with pytest.raises(BTClibValueError, match="scalar s not in 1..n-1: "):
        dsa.Sig(sig.r, 0)

    err_msg = "private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, 0)

    # ephemeral key not in 1..n-1
    err_msg = "private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, 0, grind=False)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, sig.ec.n, grind=False)


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
    sig = dsa.sign_(reduce_to_hlen(msg, hf), dU, k, lower_s, ec, hf, grind=False)
    assert sig.r == 0xCE2873E5BE449563391FEB47DDCBA2DC16379191
    assert sig.s == 0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54
    assert sig.ec == ec

    # 2.1.4 Verifying Operation for V
    dsa.assert_as_valid(msg, QU, sig, hf)
    assert dsa.verify(msg, QU, sig, hf)


def _step_1_6_1(c: int, r: int, s: int, ec: Curve) -> list[Point | None]:
    """Return SEC 1 v.2 step 1.6.1's candidate per key_id, None where none.

    The step written out with the curve's affine arithmetic, as the
    independent opinion `_recover_pub_key_` is held against: a candidate is
    r^-1*(s*K - c*G) over the lift of x_K = r + j*ec.n, and None where that
    x_K is no field element, or no x-coordinate of the curve, or where the
    sum is INF. On a curve of prime order those three are the whole of what
    step 1.6 refuses, which is what issue 890 turns on, so this list less
    its Nones is what the enumeration has to answer.
    """
    candidates: list[Point | None] = []
    r_1 = mod_inv_var(r, ec.n)
    for key_id in range(2 * (ec.cofactor + 1)):
        x_K = r + (key_id >> 1) * ec.n
        if ec.cofactor == 1:
            if x_K >= ec.p:  # the screen, where the implementation screens
                candidates.append(None)
                continue
        else:  # and the reduction where it reduces
            x_K %= ec.p
        try:
            y = ec.y_even_var(x_K)
        except BTClibValueError:
            candidates.append(None)
            continue
        K = x_K, ec.p - y if key_id & 0b01 else y
        Q = ec.add_var(mult(r_1 * s % ec.n, K, ec), mult(-r_1 * c % ec.n, ec.G, ec))
        candidates.append(None if Q == INF else Q)
    return candidates


def _verifies(c: int, Q: Point, r: int, s: int, ec: Curve) -> bool:
    """Answer whether Q verifies (r, s), which is step 1.6.2 as a boolean."""
    try:
        dsa._assert_as_valid_(
            c, (Q[0], Q[1], 1), r, s, ec, ec._fixed_points, lower_s=False
        )
    except (BTClibValueError, BTClibRuntimeError):
        return False
    return True


@pytest.mark.parametrize("name", list(low_card_curves))
def test_low_cardinality(name: str) -> None:
    """Exercise every low-cardinality curve in its own exhaustive test case."""
    ec = low_card_curves[name]
    lower_s = True
    for q in range(1, ec.n):  # all possible private keys
        QJ = _mult(q, ec.GJ, ec)  # public key
        for k in range(1, ec.n):  # all possible ephemeral keys
            RJ = _mult(k, ec.GJ, ec)
            r = ec.x_aff_from_jac_var(RJ) % ec.n
            k_inv = mod_inv_var(k, ec.n)
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
                    # valid signature must pass verification, and here even
                    # under the strict rule: every s above was normalized
                    dsa._assert_as_valid_(
                        e, QJ, r, s, ec, ec._fixed_points, lower_s=lower_s
                    )

                    jac_keys = dsa._recover_pub_keys_(e, r, s, ec, lower_s=lower_s)
                    Qs = [ec.aff_from_jac_var(key) for key in jac_keys]
                    assert ec.aff_from_jac_var(QJ) in Qs
                    # every key it answers is a key, where the INF the list
                    # used to carry is none: with Q at infinity the
                    # verification of step 1.6.2 passes vacuously, so the
                    # pair can be a single key and the count is not the
                    # assertion (issue 890)
                    assert INF not in Qs
                    # and the list is exactly step 1.6.1's candidates, less
                    # what step 1.6 refuses: on a curve of prime order that
                    # is the screen and the infinity test alone, and above
                    # cofactor 1 the verification as well, a lift there
                    # landing outside the prime-order subgroup
                    candidates = [Q_ for Q_ in _step_1_6_1(e, r, s, ec) if Q_]
                    if ec.cofactor > 1:
                        candidates = [
                            Q_ for Q_ in candidates if _verifies(e, Q_, r, s, ec)
                        ]
                    assert Qs == candidates


def test_pub_key_recovery() -> None:
    """Recover four keys on secp112r2, all verifying the signature."""
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
            Q = ec.aff_from_jac_var(_mult(q, ec.GJ, ec))
            for k in range(1, ec.n):
                x_K = ec.x_aff_from_jac_var(_mult(k, ec.GJ, ec))
                if not ec.n < x_K < ec.p:  # else x_K is r itself
                    continue
                r = x_K % ec.n
                k_inv = mod_inv_var(k, ec.n)
                for e in range(ec.n):
                    s = k_inv * (e + q * r) % ec.n
                    if r == 0 or s == 0:
                        continue
                    recovered = []
                    for key_id in range(2 * (ec.cofactor + 1)):
                        # a candidate x_K off the curve, or a key that
                        # does not verify, is "not this key_id"
                        try:
                            QJ = dsa._recover_pub_key_(
                                key_id, e, r, s, ec, lower_s=False
                            )
                        except (BTClibValueError, BTClibRuntimeError):
                            continue
                        recovered.append((key_id, ec.aff_from_jac_var(QJ)))

                    key_ids = [key_id for key_id, Q_ in recovered if Q_ == Q]
                    assert key_ids, "the signer's own key is not recoverable"
                    # j = 1, never the j = 2 a mask in place would read
                    assert all(key_id >> 1 == 1 for key_id in key_ids)

                    # and the plural is that range, less what dropped out
                    jac_keys = dsa._recover_pub_keys_(e, r, s, ec, lower_s=False)
                    assert [ec.aff_from_jac_var(QJ) for QJ in jac_keys] == [
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
        Q = ec.aff_from_jac_var(_mult(q, ec.GJ, ec))
        for k in range(1, ec.n):
            r = ec.x_aff_from_jac_var(_mult(k, ec.GJ, ec)) % ec.n
            # asserted, not skipped: this is the n > p property the
            # docstring names -- x_K < p < n, so x_K % n is x_K, and no
            # multiple of G on this curve has x_K == 0 (measured: the r
            # values are {1,2,3,4,5,6,9,10,12}). `if r == 0: continue`
            # was a branch no input could take, so it read as a
            # possibility this curve has, and a swapped curve would have
            # skipped silently where this says so
            assert r
            k_inv = mod_inv_var(k, ec.n)
            for e in range(ec.n):
                s = k_inv * (e + q * r) % ec.n
                if s == 0:
                    continue
                key_ids = []
                for key_id in range(2 * (ec.cofactor + 1)):
                    try:
                        QJ = dsa._recover_pub_key_(key_id, e, r, s, ec, lower_s=False)
                    except (BTClibValueError, BTClibRuntimeError):
                        continue
                    if ec.aff_from_jac_var(QJ) == Q:
                        key_ids.append(key_id)

                assert key_ids, "the signer's own key is not recoverable"
                assert all(key_id >> 1 == 0 for key_id in key_ids)
                cases += 1
    assert cases == 5832


def test_crack_prv_key() -> None:
    """Crack key and nonce from two signatures sharing the nonce."""
    ec = CURVES["secp256k1"]

    q, _ = dsa.gen_keys(1)
    k = 1 + secrets.randbelow(ec.n - 1)

    msg1 = b"Paolo is afraid of ephemeral random numbers"
    m_1 = reduce_to_hlen(msg1)
    sig1 = dsa.sign_(m_1, q, k, grind=False)

    msg2 = b"and Paolo is right to be afraid"
    m_2 = reduce_to_hlen(msg2)
    sig2 = dsa.sign_(m_2, q, k, grind=False)

    q_cracked, k_cracked = dsa.crack_prv_key_var(msg1, sig1.serialize(), msg2, sig2)

    #  if the lower_s convention has changed only one of s1 and s2
    sig2 = dsa.Sig(sig2.r, ec.n - sig2.s)
    qc2, kc2 = dsa.crack_prv_key_var(msg1, sig1, msg2, sig2.serialize())

    assert (q == q_cracked and k in {k_cracked, ec.n - k_cracked}) or (
        q == qc2 and k in {kc2, ec.n - kc2}
    )

    with pytest.raises(BTClibValueError, match="not the same r in signatures"):
        dsa.crack_prv_key_var(msg1, sig1, msg2, dsa.Sig(16, sig1.s))

    with pytest.raises(BTClibValueError, match="identical signatures"):
        dsa.crack_prv_key_var(msg1, sig1, msg1, sig1)

    a = ec._a
    b = ec._b
    alt_ec = Curve(ec.p, a, b, ec.double_aff_var(ec.G), ec.n, ec.cofactor)
    sig = dsa.Sig(sig1.r, sig1.s, alt_ec)
    with pytest.raises(BTClibValueError, match="not the same curve in signatures"):
        dsa.crack_prv_key_var(msg1, sig, msg2, sig2)


def test_forge_hash_sig() -> None:
    """Forge valid hash signatures."""
    ec = CURVES["secp256k1"]

    # see https://twitter.com/pwuille/status/1063582706288586752
    # Satoshi's key
    key = "03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    Q = point_from_octets(key, ec)

    # pick u1 and u2 at will
    u1 = 1
    u2 = 2
    R = double_mult_var(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv_var(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, ec, ec._fixed_points, lower_s=True)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult_var(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv_var(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, ec, ec._fixed_points, lower_s=True)


def test_sign_input_type() -> None:
    """Verify assert_as_valid takes a Sig or its DER serialization."""
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

    # the spellings a PubKey declares -- a str, a BIP32KeyData -- which
    # carry a private key and are refused for what they hold. No
    # `type: ignore` on these: they type check, which is the whole of
    # what makes False the right answer for them
    for prv_key in (
        prv_key_hexstring,
        wif_compressed_string,
        wif_uncompressed_string,
        xprv_string,
        xprv_data,
    ):
        assert not dsa.verify(msg, prv_key, sig)
        assert not dsa.verify(msg, prv_key, sig_sha1, hf=sha1)
        with pytest.raises(BTClibValueError, match="not a public key"):
            dsa.assert_as_valid(msg, prv_key, sig)
        with pytest.raises(BTClibValueError, match="not a public key"):
            dsa.assert_as_valid(msg, prv_key, sig_sha1, hf=sha1)
        # neither the rejection nor its message may echo the secret
        with pytest.raises(BTClibValueError) as refusal:
            dsa.assert_as_valid(msg, prv_key, sig)
        assert str(prv_key) not in str(refusal.value)

    # and the int, which a PubKey does not declare at all: refused as a
    # type rather than answered False, which is issue #814's rule and the
    # stronger half of this issue's. Somebody passing an int here meant a
    # private key, where False reads as a signature that did not verify.
    # `verify` refuses it as `assert_as_valid` does, a TypeError being
    # outside the `except` that turns a refusal into False -- and the
    # `type: ignore` these two need, where the five above need none, is
    # the line this rule draws, written out by the type checker
    for call in (dsa.verify, dsa.assert_as_valid):
        with pytest.raises(BTClibTypeError, match="not a public key") as wrong_type:
            call(msg, prv_key_int, sig)  # type: ignore[arg-type]
        assert str(prv_key_int) not in str(wrong_type.value)

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


@needs_bindings
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
            no_bindings.setattr(curve, "_libsecp256k1_serves", lambda *_: False)
            assert dsa.gen_keys(q)[1] == Q
            assert dsa._sign_(0x1234, q, nonce, True, ec) == sig

        assert ec.aff_from_jac_var(_mult(q, ec.GJ, ec)) == Q
        assert sig.r == ec.x_aff_from_jac_var(_mult(nonce, ec.GJ, ec)) % ec.n


@needs_bindings
def test_libsecp256k1() -> None:
    """Verify btclib and the bindings sign and verify byte-for-byte."""
    msg = b"Satoshi Nakamoto"
    prvkey_int, pubkey_point = dsa.gen_keys(0x1)
    # grind=False on both sides: the bindings' sign() with no extra
    # entropy is the plain RFC6979 signature, which is what byte-for-byte
    # means here
    btclib_sig = dsa.sign(msg, prvkey_int, grind=False)
    pub_key = bytes_from_point(pubkey_point)
    assert dsa.verify(msg, pub_key, btclib_sig)
    assert dsa.verify(msg, pub_key, btclib_sig.serialize())

    msg_hash = reduce_to_hlen(msg)
    libsecp256k1_sig = libsecp256k1_dsa.sign(msg_hash, prvkey_int)
    assert btclib_sig.serialize() == libsecp256k1_sig
    assert libsecp256k1_dsa.verify(msg_hash, pub_key, btclib_sig.serialize())
    assert dsa.verify_(msg_hash, pub_key, libsecp256k1_sig)


@needs_bindings
def test_a_plain_sign_reaches_the_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default call signs a secret key through libsecp256k1, not Python.

    `sign_`'s guard -- `_libsecp256k1_serves(ec, hf) and nonce is None and
    lower_s and commit_hash is None` -- is every default a caller who
    passes none of the three keeps, and both arms it chooses between
    reach the same signature from the same secret key: nothing about the
    result says which one produced it (issue 975, asked in general of
    every guard a computed value could disable rather than of this one,
    which has none). What differs is not the nonce's own point --
    `mult(k, ec.G, ec)` reaches libsecp256k1 either way while it serves,
    SECURITY.md's own accounting of it -- but its modular inverse, which
    this call does inside libsecp256k1's own constant time and the
    Python arm below draws as a blinded Python integer instead. This
    records the call into `libsecp256k1_dsa.sign` instead of the answer
    it returns, so a change that silently stopped taking it would fail
    here rather than reproduce the same signature from the arm it
    stands in for.
    """
    calls: list[int] = []
    real_sign = libsecp256k1_dsa.sign

    def record(msg_bytes: bytes, prvkey: int, *args: Any, **kwargs: Any) -> bytes:
        calls.append(prvkey)
        return real_sign(msg_bytes, prvkey, *args, **kwargs)

    monkeypatch.setattr(libsecp256k1_dsa, "sign", record)

    q, _Q = dsa.gen_keys(0x1234)
    dsa.sign(b"Satoshi Nakamoto", q, grind=False)
    assert calls == [q]


# Core's low-R grinding (issue #638): the loop is `dsa._grind_low_r`, and
# what follows holds it to the three implementations that have it -- Core's
# `CKey::Sign` since its PR 13666, electrum-ecc's `ECPrivkey.ecdsa_sign`
# and embit's `PrivateKey.sign`. 2**255 is the bound all three grind
# towards: r at or above it has its highest bit set, and DER then pays a
# 0x00 byte to keep it from reading as negative
_LOW_R = 2**255


def test_grinding_lands_on_a_low_r() -> None:
    """Every ground signature is low-R, and half of them were already.

    Which is the whole of what grinding buys and what it costs: a 70-byte
    DER encoding instead of 71, for the price of one extra signature on
    average. Grinding starts from the plain RFC6979 signature and no extra
    entropy at all, so a message whose r is low already is signed exactly
    as `grind=False` signs it -- and that is about half of them, which is
    what the count checks: an implementation whose first attempt carried a
    counter would satisfy every other assertion here.

    69 bytes is a scalar below 2**248, one draw in 256 for each of r and s,
    hence the inequality rather than an equality on the length.
    """
    q, Q = dsa.gen_keys(0x1)
    unchanged = 0
    for i in range(64):
        msg = f"btclib grind {i}".encode()
        plain = dsa.sign(msg, q, grind=False)
        ground = dsa.sign(msg, q, grind=True)
        assert ground.r < _LOW_R
        assert len(ground.serialize()) <= 70
        assert dsa.verify(msg, Q, ground)
        # the two agree exactly where the plain signature is low-R
        assert (plain == ground) == (plain.r < _LOW_R)
        unchanged += plain == ground
    # 32 expected, and the interval is what a fair coin gives over 64
    # draws with room to spare: a one-sided implementation lands at 0 or 64
    assert 20 < unchanged < 44


@needs_bindings
def test_grinding_retries_with_cores_own_counter() -> None:
    """The retry sequence, rebuilt from the bindings beside the loop.

    Core signs with a null ndata and then re-signs with
    `WriteLE32(extra_entropy, ++counter)` into a zeroed 32-byte buffer,
    which is electrum-ecc's and embit's `counter.to_bytes(32, "little")`:
    so the ground signature is the first low-R element of that sequence,
    and nothing weaker says so. An off-by-one in the counter, or a
    big-endian encoding, or 32 zero bytes for the first attempt, each
    produces a valid low-R signature that no other assertion in this file
    would object to.
    """
    q = prv_key_int
    retries = []
    for i in range(24):
        msg_hash = reduce_to_hlen(f"btclib grind {i}".encode())
        sequence = [
            dsa.Sig.parse(
                libsecp256k1_dsa.sign(
                    msg_hash,
                    q,
                    None if counter == 0 else counter.to_bytes(32, "little"),
                )
            )
            for counter in range(16)
        ]
        first_low = next(i for i, sig in enumerate(sequence) if sig.r < _LOW_R)
        assert dsa.sign_(msg_hash, q, grind=True) == sequence[first_low]
        retries.append(first_low)

    # a signature that grinds and one that does not are both here, and so
    # is a counter past its first value: the increment is asserted, not
    # only the first step off zero
    assert min(retries) == 0
    assert max(retries) > 1


@needs_bindings
def test_grinding_agrees_on_both_arithmetics(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counter reaches one nonce through the bindings and through RFC6979.

    libsecp256k1's nonce function appends the 32 octets it is given to the
    key and the message inside HMAC-DRBG, which is where RFC6979's section
    3.6 additional data goes, so the two grinds walk the same sequence of
    nonces. They must agree byte for byte, or a ground signature would
    depend on which arithmetic made it -- and the Python path is what
    signs for every other curve and hash function, where there are no
    bindings to fall back on.
    """
    q, Q = dsa.gen_keys(prv_key_int)
    for i in range(16):
        msg = f"btclib grind {i}".encode()
        delegated = dsa.sign(msg, q, grind=True)
        with monkeypatch.context() as no_dsa_bindings:
            no_dsa_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            python = dsa.sign(msg, q, grind=True)
        assert delegated == python
        assert delegated.r < _LOW_R
        assert dsa.verify(msg, Q, python)


def test_grinding_is_about_r_and_not_about_the_encoded_length() -> None:
    """Grinding chooses r, and the encoded length is what follows from it.

    embit stops its loop at `len(sig.serialize()) > 70` where Core asks for
    r < 2**255, and the two are one question only for a low s. With
    `lower_s=False` the s that was computed stays, its own highest bit set
    half of the time, so a ground signature is 71 bytes with a low r --
    which is not a case Core can reach, libsecp256k1 handing back the low s
    always, and is one btclib reaches on purpose. `lower_s=False` is also
    one of the reasons the bindings are not asked, so this is the Python
    grind, and sha512 below is another of those reasons.
    """
    q, Q = dsa.gen_keys(prv_key_int)
    lengths = set()
    for i in range(32):
        msg = f"btclib grind {i}".encode()
        sig = dsa.sign(msg, q, lower_s=False, grind=True)
        assert sig.r < _LOW_R
        assert dsa.verify(msg, Q, sig)
        lengths.add(len(sig.serialize()))
    # both, and the 71 is the byte s asked for: grinding did not go looking
    # for another s, and a loop on the length would have
    assert lengths == {70, 71}

    for i in range(8):
        msg = f"btclib grind {i}".encode()
        sig = dsa.sign(msg, q, hf=sha512, grind=True)
        assert sig.r < _LOW_R
        assert dsa.verify(msg, Q, sig, hf=sha512)


def test_grinding_refuses_what_already_owns_the_nonce() -> None:
    """A nonce of the caller's and a commitment leave nothing to grind.

    Grinding is a search over nonces: with the nonce given there is nothing
    to search, and a commitment already occupies the extra entropy the
    counter travels through. The second is not only a clash of encodings --
    grinding a nonce is exactly the freedom the anti-exfil protocol takes
    away from a signing device.

    The refusal is the same whether `grind` was asked for or left at its
    `True` default, which is what makes `grind=False` the only way to sign
    with a nonce of one's own: neither of the two quietly wins, and which
    one did is exactly what a caller pinning a signature could not have
    guessed from the bytes.
    """
    msg = b"Satoshi Nakamoto"
    nonce = 0x9E5755E5A8FCC1B0A2FD1E0AD9E8D6B29B67D67E6C6A0DEE01E7E1F30DB9A0BE
    err_msg = "grinding derives its own nonce"
    # asked for outright
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, prv_key_int, nonce, grind=True)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, prv_key_int, grind=True, commit=b"a commitment")
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), prv_key_int, grind=True, commit_hash=bytes(32))

    # and left at the default, which is that same True and that same refusal
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, prv_key_int, nonce)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, prv_key_int, commit=b"a commitment")
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), prv_key_int, commit_hash=bytes(32))

    # and `grind=False` is what signs either of them
    _, Q = dsa.gen_keys(prv_key_int)
    assert dsa.verify(msg, Q, dsa.sign(msg, prv_key_int, nonce, grind=False))
    sig, receipt = dsa.sign(msg, prv_key_int, grind=False, commit=b"a commitment")
    assert dsa.verify(msg, Q, sig, commit=b"a commitment", receipt=receipt)


# Bitcoin Core v31.1.0 as the oracle, on a regtest node with no wallet:
# `createrawtransaction` spends outpoint 0101..01:0 -- a p2wpkh output of
# the key, worth 1 BTC -- into a p2wpkh output of the same key worth the
# value named below, and `signrawtransactionwithkey` signs that with the
# key's WIF and that prevout. Core grinds by default, so the witness item
# it produces is its ground signature; `msg_hash` is btclib's own segwit v0
# `sig_hash.from_tx` for the transaction Core built, which is what the
# signature verifying under it confirms.
#
# Private key, message hash, DER signature with Core's sighash byte
# dropped, and the number of retries grinding cost. That last field is
# what makes these five more than one vector five times over: 0 is the
# draw grinding leaves alone, and 2 and 7 pin the counter well past its
# first value. The output values that re-derive them, in this order:
# 0.999, 0.997, 0.998, 0.987 and 0.993 BTC.
#
# A list of pytest.param rather than a tuple of tuples: a DER signature is
# two source lines wide, and implicit concatenation inside a collection
# literal is what ruff's ISC004 objects to -- a missing comma away from
# being one element instead of two
_CORE_VECTORS = [
    pytest.param(
        0x1,
        "133bf859d57c50cb522cff0ac5300f639c90a089914ff6103d095615b1d844f2",
        "304402205a9cc47c9c726331dfe114f1f5d83800b0f3c67a70ac3d373e1a31bd8b6c6f11"
        "0220734109a45cbc732e999c988842531dc1f20b2e5f590aed7732fa304e4ba27ee3",
        0,
        id=vector_id(0, "0-retries"),
    ),
    pytest.param(
        0x1,
        "d14c29beb26e63426a41b36a11183b54f5b22c33115d8e7f0ba49a58b336149e",
        "30440220353bdc7e3946c2b75b87b5587677794c55533275fd129c6ef26d877ff37f7032"
        "0220182f97be35ab386b1adea91a224876b1f00d43966f1b8de6517af8ed33f56c95",
        1,
        id=vector_id(1, "1-retry"),
    ),
    pytest.param(
        0x1,
        "e4a96c927ca0fb2a09bd17cb86aea29917199b304d075d23a191566a8cf61b09",
        "3044022052b0cd32b4171b77bb22e83bc450d5123d257f961aa21521fa3a4eda7639e63b"
        "022047e4aa600baaab959f5a460f0124a7153ccda22459775ccf8ac6ecc3c9326c09",
        2,
        id=vector_id(2, "2-retries"),
    ),
    pytest.param(
        0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D,
        "f56caf9a85d192163762c9f99d39992c68e987c929ed859efc6a890c75012d8b",
        "304402201b7fb7e26572ebc9c3613513b672fed24a81e3e98a76739f67ac457be0c47cd4"
        "022028e43694137339433c0d40f68a1ae48293a5629f8fe08b9bb1722e8d0f951b4e",
        3,
        id=vector_id(3, "3-retries"),
    ),
    pytest.param(
        0x1,
        "367edb7a74cf12d6111efa368624d599a44fdda82a028059091f0967b61adba9",
        "304402202efab9db55ab5abb9d78b5617ad5ec5117efdb36f5ba3150b462acf0297cd052"
        "0220178fbc4d9f9817ddb0f35a2ed9cf9e0437f3ea261c00b4a176201b6558b722da",
        7,
        id=vector_id(4, "7-retries"),
    ),
]


@pytest.mark.parametrize("prv_key, msg_hash, der, retries", _CORE_VECTORS)
@needs_bindings
def test_core_grinds_the_same_signatures(
    prv_key: int, msg_hash: str, der: str, retries: int
) -> None:
    """Reproduce Bitcoin Core's own low-R signatures, byte for byte."""
    sig_hash = bytes.fromhex(msg_hash)
    sig = dsa.sign_(sig_hash, prv_key, grind=True)
    assert sig.serialize().hex() == der
    assert sig.r < _LOW_R

    _, Q = dsa.gen_keys(prv_key)
    assert dsa.verify_(sig_hash, Q, sig)

    # the retry count is a claim about which element of Core's sequence
    # this is, so it is checked and not merely recorded: the plain
    # signature for a count of zero, the counter's own signature otherwise
    plain = dsa.sign_(sig_hash, prv_key, grind=False)
    assert (plain == sig) == (retries == 0)
    aux_rand32 = None if retries == 0 else retries.to_bytes(32, "little")
    assert sig.serialize() == libsecp256k1_dsa.sign(sig_hash, prv_key, aux_rand32)


def test_a_sig_that_never_validated_answers_false_and_does_not_raise() -> None:
    """Why `assert_as_valid_` validates a `Sig` it was handed (issue 888).

    The class is frozen, so an instance that validated at construction
    stays valid, and the second pass looks redundant. What makes it not is
    the two ways an unvalidated instance is reachable: `check_validity=False`,
    which the library itself passes for values libsecp256k1 has just
    computed, and `object.__setattr__`, which reaches past frozen as
    `tests/bip32/bip32_test.py::test_assert_valid2` does on purpose.

    Both of those reach `_serialize_scalar`, where `to_bytes(...,
    signed=False)` raises OverflowError for a negative r -- an
    ArithmeticError, so not in the `(ValueError, BTClibRuntimeError)` tuple
    `verify_` catches. Drop the validation and a function whose whole answer
    is True or False raises instead, which is the rule issue #814 states.
    """
    _, Q = dsa.gen_keys(prv_key_int)
    msg_hash = reduce_to_hlen(b"Satoshi Nakamoto")

    unvalidated = dsa.Sig(-1, 5, check_validity=False)
    assert not dsa.verify_(msg_hash, Q, unvalidated)
    with pytest.raises(BTClibValueError, match="scalar r not in 1..n-1"):
        dsa.assert_as_valid_(msg_hash, Q, unvalidated)

    # and the same for an instance that validated and was rewritten after
    corrupted = dsa.sign_(msg_hash, prv_key_int)
    object.__setattr__(corrupted, "r", -1)
    assert not dsa.verify_(msg_hash, Q, corrupted)
    with pytest.raises(BTClibValueError, match="scalar r not in 1..n-1"):
        dsa.assert_as_valid_(msg_hash, Q, corrupted)


def _recovered(key_id: int, msg: bytes, sig: dsa.Sig) -> Point | None:
    """Return the recovered key, None for a candidate recovering nothing."""
    try:
        return dsa.recover_pub_key(key_id, msg, sig)
    except (BTClibValueError, BTClibRuntimeError):
        return None


def _recovered_(key_id: int, msg_hash: bytes, sig: dsa.Sig) -> Point | None:
    """Recover the same, for a caller holding the hash, not the message."""
    try:
        return dsa.recover_pub_key_(key_id, msg_hash, sig)
    except (BTClibValueError, BTClibRuntimeError):
        return None


@needs_bindings
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
                no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
                python = _recovered(key_id, msg, sig)
            assert delegated == python
            if delegated is not None:
                assert delegated in keys
                recovering.append(key_id)
        # the signer's own key has j = 0, so it is one of the first pair,
        # and the second pair recovers nothing: r + ec.n < ec.p is some
        # 2^-127 of signatures, and both implementations require it
        assert recovering == [0, 1]

        # negating s mirrors the nonce's point, so the candidate that
        # recovers the signer is the one whose parity bit flipped -- and
        # the malleated signature does recover it, on both
        # implementations, no lower-s rule refusing what the signer was
        # free to produce (issue 695). The recoverable parser takes any s
        # in [1, n-1] and that is now the whole of the rule
        key_id = next(k for k in recovering if _recovered(k, msg, sig) == Q)
        malleated = dsa.Sig(sig.r, secp256k1.n - sig.s)
        assert _recovered(key_id ^ 1, msg, malleated) == Q
        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert _recovered(key_id ^ 1, msg, malleated) == Q


@needs_bindings
def test_the_low_s_rule_is_asked_for_and_not_assumed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Where the strict rule lives once the public surface drops it (issue 695).

    The rule is not gone: `SCRIPT_VERIFY_LOW_S` is in Core's
    `STANDARD_SCRIPT_VERIFY_FLAGS`, so a high-s signature inside a
    transaction is non-standard and does not relay, and `sign` normalizes
    for that reason. What is gone is a verifier refusing one -- so the
    strict answer is what a leading-underscore function gives when asked
    for it, `lower_s=False` being the default there too.

    Both implementations of the recovery are asked, being one step written
    twice: the bindings answer the named candidate and the Python path
    answers all four, and a rule enforced by one and not the other would
    make the two disagree about a signature neither made.
    """
    msg = b"Satoshi Nakamoto"
    prv_key, Q = dsa.gen_keys(prv_key_int)
    msg_hash = reduce_to_hlen(msg)
    sig = dsa.sign(msg, prv_key)
    malleated = dsa.Sig(sig.r, secp256k1.n - sig.s)
    key_id = _search_key_id(msg, sig, Q)
    c = challenge_(msg_hash, secp256k1, sha256)
    QJ = Q[0], Q[1], 1
    err_msg = "not a low s"

    # the public spellings take the malleated signature, both of them
    assert dsa.verify(msg, Q, malleated)
    assert dsa.recover_pub_key(key_id ^ 1, msg, malleated) == Q

    # and every private spelling refuses it when told to
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa._assert_as_valid_(
            c,
            QJ,
            malleated.r,
            malleated.s,
            secp256k1,
            secp256k1._fixed_points,
            lower_s=True,
        )
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa._libsecp256k1_recover_point_(key_id ^ 1, msg_hash, malleated, lower_s=True)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa._recover_pub_key_(
            key_id ^ 1, c, malleated.r, malleated.s, secp256k1, lower_s=True
        )
    # the enumeration drops a candidate that fails rather than report it,
    # so there the same refusal is an empty list: every one of the four
    # fails the one rule at once
    assert (
        dsa._recover_pub_keys_(c, malleated.r, malleated.s, secp256k1, lower_s=True)
        == []
    )

    # the signature as signed passes the strict rule on both paths, which
    # is what says the refusals above are about the malleation and not
    # about the arguments being threaded wrongly
    dsa._assert_as_valid_(
        c, QJ, sig.r, sig.s, secp256k1, secp256k1._fixed_points, lower_s=True
    )
    assert dsa._libsecp256k1_recover_point_(key_id, msg_hash, sig, lower_s=True) == Q
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
        assert dsa.recover_pub_key(key_id, msg, sig) == Q


def test_recover_pub_keys_takes_the_hash_that_recover_pub_keys_reduces() -> None:
    """The two spellings of the enumeration are one function.

    `challenge_` reduces a digest to an integer and does not hash it
    again, so the underscore spelling is the one a caller holding a hash
    -- a sig_hash, the `reduce_to_hlen(magic_message(msg))` of a message
    signature -- has to reach for: the other would hash it a second time.
    Nothing in btclib calls either, bms naming its own key_id since issue
    269, so this is what holds the pairing that justifies both.

    The malleated signature is enumerated exactly as the signature it was
    made from: negating s mirrors the nonce's point, so the same keys come
    back with the parity bit of each candidate flipped, and the signer's
    own is among them. Both spellings say so on both implementations --
    sha256 here is the four recover calls, sha512 the Python loop -- which
    form s took having been the signer's choice (issue 695).
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
            malleated_keys = dsa.recover_pub_keys_(msg_hash, malleated, hf=hf)
            assert Q in malleated_keys
            assert dsa.recover_pub_keys(msg, malleated, hf=hf) == malleated_keys


@needs_bindings
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
            # the Python enumeration, its double_mult_var still delegated
            patch.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert dsa.recover_pub_keys(msg, sig) == keys
            assert [_recovered(key_id, msg, sig) for key_id in key_ids] == recovered

            # and the same with the arithmetic under it patched off too
            no_bindings(patch)
            assert dsa.recover_pub_keys(msg, sig) == keys
            assert [_recovered(key_id, msg, sig) for key_id in key_ids] == recovered


@pytest.mark.parametrize(
    "r, expected_key_ids",
    [(2, [0, 1, 2, 3]), (7, [2, 3])],
    ids=["four-candidates", "the-j-one-pair-alone"],
)
@needs_bindings
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
    path arrive at differently, `recid & 2` against the screen on
    x_K = r + j*ec.n. Both r are small enough for that screen to admit the
    j = 1 pair, which is the point of fabricating one: no signature has an
    r that low, and the screen is the whole of what the two paths have to
    agree about there (issue 891).
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
        patch.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
        assert dsa.recover_pub_keys_(msg_hash, sig) == keys
        no_bindings(patch)
        assert dsa.recover_pub_keys_(msg_hash, sig) == keys


def test_the_recovered_key_can_be_infinity_and_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Q = r^-1*(s*K - c*G) is INF whenever s*K == c*G, and INF is no key.

    Step 1.6.2's verification does not catch it, which is why the infinity
    test that replaced it is not a shortcut's price but its gain (issue
    890): with Q at infinity the recomputed K' is the lift itself, so the
    congruence x_K % ec.n == r passes and the enumeration reported the INF
    as a recovered key -- (5, 0) once converted, which is btclib's sentinel
    for infinity and no public key at all. `ssa._recover_pub_key_` has
    always refused its own, for this same reason.

    Reached through the public spelling and not the private one: with s = 1
    the condition is K == c*G, so r is that point's x-coordinate and the
    key_id its parity. sha512 is what sends the recovery down the Python
    path on secp256k1 -- the bindings cannot answer INF, a libsecp256k1
    public key being a point of the curve -- and the fully Python
    arithmetic under it answers the same, as it does for BIP340.
    """
    ec = secp256k1
    msg_hash = reduce_to_hlen(b"Satoshi Nakamoto", sha512)
    c = challenge_(msg_hash, ec, sha512)
    K = mult(c, ec.G, ec)
    sig = dsa.Sig(K[0], 1)
    key_id = K[1] & 0b01

    err_msg = r"invalid \(INF\) key"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa.recover_pub_key_(key_id, msg_hash, sig, sha512)
    keys = dsa.recover_pub_keys_(msg_hash, sig, sha512)
    assert keys
    assert INF not in keys

    with monkeypatch.context() as patch:
        no_bindings(patch)
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            dsa.recover_pub_key_(key_id, msg_hash, sig, sha512)
        assert dsa.recover_pub_keys_(msg_hash, sig, sha512) == keys


def _search_key_id(msg: bytes, sig: dsa.Sig, Q: Point) -> int:
    """Find the key_id by recovering and comparing, not by signing.

    The derivation `sign_recoverable` exists not to run: it is here as the
    independent opinion its key_id is held against, one recovery per
    candidate until one is the signer's own key.
    """
    for key_id in range(2 * (sig.ec.cofactor + 1)):
        if _recovered(key_id, msg, sig) == Q:
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


@needs_bindings
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

    `sign` is asked with `grind=False`, that being the signature the
    recoverable spelling makes: it takes no `grind` at all, a compact
    signature having no DER pad for a low r to save, so the plain one is
    what the two have in common.
    """
    for i in range(20):
        msg = f"message {i}".encode()
        prv_key, Q = dsa.gen_keys()
        msg_hash = reduce_to_hlen(msg)

        sig, key_id = dsa.sign_recoverable(msg, prv_key)
        assert sig == dsa.sign(msg, prv_key, grind=False)
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
            no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert dsa.sign_recoverable(msg, prv_key) == (sig, key_id)


@needs_bindings
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
        sig, key_id = dsa.sign_recoverable(msg, prv_key, **kwargs)
        hf = kwargs.get("hf", sha256)
        assert dsa.recover_pub_key(key_id, msg, sig, hf) == Q
        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert dsa.sign_recoverable(msg, prv_key, **kwargs) == (sig, key_id)

    ec = CURVES["secp112r2"]
    q, Q = dsa.gen_keys(0x10, ec)
    sig, key_id = dsa.sign_recoverable(msg, q, ec=ec)
    assert dsa.recover_pub_key(key_id, msg, sig) == Q
    assert key_id == _search_key_id(msg, sig, Q)


@needs_bindings
def test_recover_pub_key_dispatches_to_the_bindings_for_0_to_3_only() -> None:
    """The bindings take a recovery id of 0, 1, 2 or 3, and nothing wider.

    A key_id outside that range has to reach the Python path instead,
    which answers in its own words rather than the bindings': its own
    screen on x_K = r + j*ec.n, which is no field element for a j of -1
    or 2 (issue 891) -- not the bindings' "the recovery id must be 0, 1,
    2, or 3", which is what a widened or narrowed guard sends a boundary
    value to instead. Four key_ids, one per boundary the six ways this
    guard survived moved.
    """
    q = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD
    # grind=False: this signature is the fixture, chosen for the four
    # answers below, and another r is another set of candidates
    sig = dsa.sign(b"msg", q, grind=False)
    msg_hash = b"\x00" * 32

    cases = {
        -1: (BTClibValueError, r"invalid key_id \(-1\)"),
        2: (BTClibValueError, "public key recovery failed"),
        3: (BTClibValueError, "public key recovery failed"),
        4: (BTClibValueError, r"invalid key_id \(4\)"),
    }
    for key_id, (exc, err_msg) in cases.items():
        with pytest.raises(exc, match=err_msg):
            dsa.recover_pub_key_(key_id, msg_hash, sig)


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
            Q = ec.aff_from_jac_var(_mult(q, ec.GJ, ec))
            for k in range(1, ec.n):
                for c in range(ec.n):
                    for lower_s in (True, False):
                        try:
                            sig, key_id = dsa._sign_recoverable_(c, q, k, lower_s, ec)
                        except BTClibRuntimeError:  # r == 0 or s == 0
                            continue
                        QJ = dsa._recover_pub_key_(
                            key_id, c, sig.r, sig.s, ec, lower_s=lower_s
                        )
                        assert ec.aff_from_jac_var(QJ) == Q
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
@needs_bindings
def test_libsecp256k1_py_vectors_ecdsa(vector: dict[str, str]) -> None:
    """Reproduce secp256k1-py's ECDSA vectors on both implementations."""
    msg_hash = bytes.fromhex(vector["msg"])
    assert len(msg_hash) == 32
    sig_raw = bytes.fromhex(vector["sig"])
    prv_key = bytes.fromhex(vector["privkey"])
    assert len(prv_key) == 32

    # the vectors are libsecp256k1's own plain signatures, as the
    # comparison below says in the same breath
    sig = dsa.sign_(msg_hash, prv_key, grind=False)
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
@needs_bindings
def test_libsecp256k1_py_vectors_ecdsa_nonce(vector: dict[str, str]) -> None:
    """Reproduce secp256k1-py's custom-nonce ECDSA vectors."""
    msg_hash = bytes.fromhex(vector["msg"])
    assert len(msg_hash) == 32
    sig_der = bytes.fromhex(vector["sig"])
    nonce = bytes.fromhex(vector["nonce"])
    assert len(nonce) == 32
    prv_key = bytes.fromhex(vector["privkey"])
    assert len(prv_key) == 32

    sig = dsa.sign_(msg_hash, prv_key, nonce, grind=False)
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
        dsa._assert_as_valid_(
            ec.n - 1, ec.GJ, 1, 1, ec, ec._fixed_points, lower_s=False
        )


@needs_bindings
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
    the boundary -- from the z == 0 of `_jac_from_aff`, in the same line
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
            dsa._assert_as_valid_(
                ec.n - 1, ec.GJ, 1, 1, ec, ec._fixed_points, lower_s=False
            )

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


def test_a_bad_hf_raises_rather_than_answering_about_the_signature() -> None:
    """An hf that is not one is the caller's mistake, not an invalid signature.

    The distinction `verify_` claims to draw and did not: its `except
    (ValueError, BTClibRuntimeError)` reports anything it catches as a
    signature that does not verify, so the refusal has to be the
    BTClibTypeError `hashes._assert_valid_hf` raises and has to happen
    before the try. `sha256()` for `sha256` is the mistake it is written
    for (issue #745).
    """
    msg = b"Satoshi Nakamoto"
    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    msg_hash = reduce_to_hlen(msg)
    assert dsa.verify_(msg_hash, Q, sig)

    err_msg = "not a hash function"
    with pytest.raises(BTClibTypeError, match=err_msg):
        dsa.verify_(msg_hash, Q, sig, sha256())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match=err_msg):
        dsa.assert_as_valid_(msg_hash, Q, sig, sha256())  # type: ignore[arg-type]
    # and through the un-underscored spellings, which reduce first
    with pytest.raises(BTClibTypeError, match=err_msg):
        dsa.verify(msg, Q, sig, sha256())  # type: ignore[arg-type]


def test_verification_under_a_prepared_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A prepared key verifies what the bare key verifies, and no more.

    `PreparedPoint` is a memoization the caller opted into, so it must be
    invisible in the answer: the same signatures pass, the same ones
    fail, and the refusals keep their class. Asserted on both arithmetics
    -- the delegated one, where the object buys nothing and must
    therefore cost nothing either, and the Python one, which is what it
    is for.
    """
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    _, Q = dsa.gen_keys(prv_key)
    prepared = PreparedPoint(Q)
    msg = b"Satoshi Nakamoto"
    sig = dsa.sign(msg, prv_key)

    for _ in range(2):
        dsa.assert_as_valid(msg, prepared, sig)
        assert dsa.verify(msg, prepared, sig)
        assert not dsa.verify(b"another message", prepared, sig)
        # the wrong key, prepared, is still the wrong key
        assert not dsa.verify(msg, PreparedPoint(dsa.gen_keys(prv_key + 1)[1]), sig)
        # and it is a public key wherever one is read, the tables being
        # the only thing about it that is not the point's
        assert pub_keyinfo_from_pub_key(prepared) == pub_keyinfo_from_pub_key(Q)
        no_bindings(monkeypatch)


def test_a_prepared_key_stops_the_per_signature_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 2 tables a verification rebuilds per signature become 0.

    This is issue #893 itself, and it is asserted as a count rather than
    as a duration: what a prepared key buys is that the wNAF tables of
    the key's two GLV halves are memoized instead of built and dropped,
    and the tables built per call is the thing that changes. A time would
    measure the machine.

    `_odd_multiples` is where a table that is *not* memoized is built --
    `_multi_mult_w_NAF_var` sends a fixed point to
    `_cached_odd_multiples_aff` instead -- so counting calls to it counts
    exactly what the preparing removes. Two per verification: the key's
    two halves, the generator's two being fixed already.
    """
    no_bindings(monkeypatch)
    prv_key = 0xB6B7E2CA8E31CE45C1D2C0E1E0C5D62F0E52B1E8C8B5A4A9D3E2F1C0B9A8D7E6
    _, Q = dsa.gen_keys(prv_key)
    msg = b"Satoshi Nakamoto"
    sig = dsa.sign(msg, prv_key)

    builds = []
    built = curve_group._odd_multiples

    def counting(point: JacPoint, ec: CurveGroup, w: int) -> list[JacPoint]:
        builds.append(point)
        return built(point, ec, w)

    monkeypatch.setattr(curve_group, "_odd_multiples", counting)

    # one verification first, and the count taken after it: the
    # generator's own two tables are memoized as well, so on a worker
    # that has verified nothing yet they are built here once and would
    # be counted as the key's
    assert dsa.verify(msg, Q, sig)
    builds.clear()
    for _ in range(3):
        assert dsa.verify(msg, Q, sig)
    assert len(builds) == 6

    prepared = PreparedPoint(Q)
    # the same warm-up on the other arm, filling the key's two wide
    # tables, which is what the break-even in `PreparedPoint` prices
    assert dsa.verify(msg, prepared, sig)
    builds.clear()
    for _ in range(3):
        assert dsa.verify(msg, prepared, sig)
    assert not builds


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_a_key_that_is_no_point_is_refused_by_the_verification_itself(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both arithmetics refuse 33 octets that are no point, in one parse.

    The delegated path does not prove the key before verifying with it:
    the verification's own parse is that proof, and proving it here as
    well would lift one x twice (issue 887). So what a bad key raises
    comes from the bindings and is translated, where the Python path
    raises it while converting -- the two messages are held equal here,
    that being the only thing a caller sees of the difference.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, _ = dsa.gen_keys(0x1234567890ABCDEF)
    msg = b"a message"
    sig = dsa.sign(msg, q)

    for no_point in (b"\x02" + bytes(32), b"\x03" + b"\xff" * 32):
        with pytest.raises(BTClibValueError, match="not a public key"):
            dsa.assert_as_valid(msg, no_point, sig)


_ARMS = [
    pytest.param(True, marks=needs_bindings, id="bindings"),
    pytest.param(False, id="python"),
]


@pytest.mark.parametrize("bindings", _ARMS)
def test_the_check_changes_no_signature(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`verify` is a truth: what it turns on reads, and writes nothing.

    The three spellings answer the same octets, which is what puts the
    flag in `_TRUTHS` rather than beside `lower_s` and `grind` in
    `_KINDS`, and what makes declining the check a decision about time
    and not about which signature a key and a message make.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, Q = dsa.gen_keys(0x1234567890ABCDEF)
    msg = b"a message signed three ways"
    sec = bytes_from_point(Q)

    checked = dsa.sign(msg, q)
    assert checked == dsa.sign(msg, q, verify=False)
    assert checked == dsa.sign(msg, q, pub_key=sec)
    # and grinding is still Core's sequence, the check being of the
    # signature the loop kept rather than of the ones it discarded
    assert checked == dsa.sign(msg, q, grind=True, pub_key=Q)


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_key_handed_in_is_the_key_that_would_have_been_derived(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every spelling of the signer's own key is accepted, and is the same key.

    Compressed and uncompressed differ only in what the check pays to
    parse -- the field square root that recovers y -- and a `Point` or a
    `PreparedPoint` is what a caller of the Python arithmetic holds. All
    four are the key the check would have derived, so all four verify.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, Q = dsa.gen_keys(0x1234567890ABCDEF)
    msg = b"a message signed under a key already held"
    expected = dsa.sign(msg, q, verify=False)

    for key in (
        bytes_from_point(Q),
        bytes_from_point(Q, compressed=False),
        Q,
        PreparedPoint(Q),
    ):
        assert dsa.sign(msg, q, pub_key=key) == expected


@pytest.mark.parametrize("bindings", _ARMS)
def test_the_wrong_key_is_told_apart_from_a_wrong_computation(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A key that is not this private key's is a ValueError, not a fault.

    The whole reason the failing branch derives: a wrong argument and a
    faulted computation fail the same verification, and reporting one as
    the other tells a caller their hardware is broken because they
    mistyped. `BTClibRuntimeError` stays what it has always meant here.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, _ = dsa.gen_keys(0x1234567890ABCDEF)
    _, other = dsa.gen_keys(0xFEDCBA0987654321)
    msg = b"a message signed under someone else's key"

    with pytest.raises(BTClibValueError, match="not this private key's"):
        dsa.sign(msg, q, pub_key=bytes_from_point(other))


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_key_is_refused_beside_the_flag_that_declines_the_check(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller contradicting themselves is answered, not resolved.

    Raised before anything is signed and before the key is parsed, so
    what a caller hears is about the two arguments rather than about the
    octets of one of them -- and raised on both arms, so that a dispatch
    nobody asked for is not what decides which error arrives.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, Q = dsa.gen_keys(0x1234567890ABCDEF)
    with pytest.raises(BTClibValueError, match="verify=False declines"):
        dsa.sign(b"a message", q, verify=False, pub_key=bytes_from_point(Q))
    with pytest.raises(BTClibValueError, match="verify=False declines"):
        dsa.sign_(sha256(b"a message").digest(), q, verify=False, pub_key=Q)


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_key_fixed_in_advance_cannot_pass_a_signature_of_another_key(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What makes taking the key on trust safe, stated as a property.

    The keys a signature verifies under are a property of that signature
    -- `recover_pub_keys_` walks them -- so a key chosen before the
    signature exists is not one of them. That is why the trust can cost a
    wrong diagnosis and never a wrong success, and it is checked here
    over keys and messages rather than argued in a docstring.
    """
    if not bindings:
        no_bindings(monkeypatch)

    _, wrong = dsa.gen_keys(0x1234567890ABCDEF)
    for i in range(1, 21):
        q, _ = dsa.gen_keys(0xFEDCBA0987654321 + i)
        with pytest.raises(BTClibValueError, match="not this private key's"):
            dsa.sign(i.to_bytes(32, "big"), q, pub_key=wrong)


def test_the_two_arms_answer_the_same_refusals(monkeypatch: pytest.MonkeyPatch) -> None:
    """One contract, two implementations, and the same words for a failure.

    A fallback that answered differently from the arm it stands in for
    would be two libraries wearing one name: the signature, the exception
    type and the message are all held equal here, which is the thing no
    per-arm test can say.
    """
    q, _ = dsa.gen_keys(0x1234567890ABCDEF)
    _, other = dsa.gen_keys(0xFEDCBA0987654321)
    msg = b"a message both arms sign"

    def answers() -> tuple[Any, ...]:
        signature = dsa.sign(msg, q, pub_key=None)
        with pytest.raises(BTClibValueError) as wrong_key:
            dsa.sign(msg, q, pub_key=bytes_from_point(other))
        with pytest.raises(BTClibValueError) as contradiction:
            dsa.sign(msg, q, verify=False, pub_key=bytes_from_point(other))
        # the third failure a supplied key can have, and the one this
        # test's name promised without holding: octets that are no point
        with pytest.raises(BTClibValueError) as no_point:
            dsa.sign(msg, q, pub_key=b"\x02" + bytes(32))
        return (
            signature,
            str(wrong_key.value),
            str(contradiction.value),
            str(no_point.value),
        )

    delegated = answers()
    with monkeypatch.context() as python:
        python.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
        assert answers() == delegated


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_key_that_is_no_point_is_refused_before_anything_is_signed(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused by both arms, and on the Python one before it has signed.

    A caller who mistyped an argument should not be told about it by a
    check on a signature they are now holding -- which with grinding
    would be after the whole loop. Both arms refuse before signing: the
    delegated one because the bindings parse `pubkey` on the way in, the
    Python one because `_python_key` is hoisted above the signing, where
    the check would have paid the same parse anyway.

    Only the second half is asserted here, and the asymmetry is the
    point rather than an omission. On the delegated arm the call that
    parses and the call that signs are one crossing, so nothing this
    side of it can watch the order; that property is
    `test_octets_that_are_not_a_key_are_refused_before_anything_is_signed`
    in btclib-secp256k1, which is where it can be seen. What is held on
    both arms here is that the refusal arrives and is btclib's own
    exception.

    The words are held equal too, and that is the cheap half: the
    delegated arm translates the bindings' `invalid public key` into
    this package's own `not a public key`, which is what
    `assert_as_valid_` and `point_from_pub_key` say. Unifying it by
    proving the key here instead would be a field square root the
    bindings then repeat, some 2.2 of the 5.8 microseconds handing a key
    in saves. Pinning the message is what makes the translation safe: a
    wording that moves upstream fails here rather than quietly ceasing
    to match.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, _ = dsa.gen_keys(0x1234567890ABCDEF)
    no_point = b"\x02" + bytes(32)

    with pytest.raises(BTClibValueError, match="^not a public key$"):
        dsa.sign(b"a message", q, pub_key=no_point)

    if bindings:
        return

    real = dsa._sign_
    signed = []

    def counting(*args: Any, **kwargs: Any) -> Any:
        signed.append(1)
        return real(*args, **kwargs)

    with monkeypatch.context() as counted:
        counted.setattr(dsa, "_sign_", counting)
        # the counter is wired to the call that signs, and this says so:
        # without it the assertion below would pass on a patch of the
        # wrong function. grind=False so that "exactly one" is a property
        # of the code rather than of this key and message drawing a low r
        # on the first attempt -- true here, and a puzzling failure for
        # whoever changes the message
        dsa.sign(b"a message", q, verify=False, grind=False)
        assert signed == [1]

        signed.clear()
        with pytest.raises(BTClibValueError, match="^not a public key$"):
            dsa.sign(b"a message", q, pub_key=no_point)
    assert not signed, "the key was refused after something was signed"


def test_a_fault_is_not_reported_as_a_wrong_key() -> None:
    """The other half of the discrimination, and the one no input reaches.

    A fresh signature verifies under the key that made it, so neither
    `BTClibRuntimeError` is reachable from an argument -- what they
    report is memory that flipped or a fault induced on purpose.
    `_abort_unless_checked` takes the verification as a callable exactly
    so that this can be said without patching the arithmetic: all four
    of its branches are entered here, and an inversion of the two causes
    fails the test rather than passing quietly.
    """
    signer = b"\x02" + bytes(31) + b"\x01"
    other = b"\x02" + bytes(31) + b"\x02"
    derivations = 0

    def derive() -> bytes:
        nonlocal derivations
        derivations += 1
        return signer

    # nothing supplied, and the signature verifies: the common path,
    # which pays the derivation because it has no other key to ask about
    dsa._abort_unless_checked(lambda _: True, derive, None)
    assert derivations == 1

    # nothing supplied, and it does not: the fault this check is for
    with pytest.raises(BTClibRuntimeError, match="does not verify"):
        dsa._abort_unless_checked(lambda _: False, derive, None)
    assert derivations == 2

    # supplied and verifying: the derivation is not reached at all, which
    # is the whole of what supplying the key buys
    dsa._abort_unless_checked(lambda _: True, derive, other)
    assert derivations == 2

    # supplied, failing, and the signer's own key fails too: a fault
    # under a handed-in key, which must not be reported as a wrong key
    with pytest.raises(BTClibRuntimeError, match="does not verify"):
        dsa._abort_unless_checked(lambda _: False, derive, other)
    assert derivations == 3

    # supplied, failing, and the signer's own key verifies: a wrong key
    with pytest.raises(BTClibValueError, match="not this private key's"):
        dsa._abort_unless_checked(lambda key: key == signer, derive, other)
    assert derivations == 4


@needs_bindings
def test_the_delegated_grind_is_the_sequence_the_python_arm_walks() -> None:
    """The defence the delegation rests on, and the reason it is here.

    `sign_` no longer grinds on the delegated arm: libsecp256k1's own
    `grind` walks Core's `CKey::Sign` counter and so does
    `_grind_low_r`, so looping here would re-derive what the bindings
    already do and pay a crossing per attempt -- two on average.

    What that costs is Core's sequence living in two places, and it is
    only affordable while the two agree. They are held equal here over
    keys and messages rather than at the one input a smoke test would
    use, so a change of sequence on either side is a red suite instead
    of a signature nobody else can reproduce. The signatures are
    compared, not merely the low-r property: two different low-r
    signatures of one message would pass that and be the bug this is
    for.
    """
    for i in range(1, 61):
        q, _ = dsa.gen_keys(0xFEDCBA0987654321 + i * 7919)
        msg_hash = sha256(i.to_bytes(8, "big")).digest()

        delegated = dsa.sign_(msg_hash, q, grind=True, verify=False)
        compact = libsecp256k1_dsa.sign(
            msg_hash, q, compact=True, grind=True, verify=False
        )
        assert delegated.r == int.from_bytes(compact[:32], "big")
        assert delegated.s == int.from_bytes(compact[32:], "big")

        # and it is the signature btclib's own loop reaches, which is the
        # half that says the delegation changed no answer
        with pytest.MonkeyPatch.context() as python:
            python.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert dsa.sign_(msg_hash, q, grind=True, verify=False) == delegated

        # the point of grinding at all, and cheap to say here
        assert dsa._is_low_r(delegated.r, secp256k1)


@needs_bindings
def test_the_delegated_arm_asks_the_bindings_to_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`verify` reaches `secp256k1_ecdsa_sign` once, as the caller wrote it.

    Nothing before this recorded it: the crossing above shows the two
    arms agree on the signature `grind=True, verify=False` produces, not
    that `verify` is the argument deciding whether a check follows it, or
    that grinding pays for one crossing and not one per attempt (issue
    986). `_grind_low_r`'s own loop is the Python arm's; the delegated
    arm's grinding is `secp256k1_ecdsa_sign`'s own, which this call does
    not see -- what it can see, and what this asserts, is that btclib
    crosses into it once per `sign_` call, whether that call grinds or
    not.
    """
    real_sign = libsecp256k1_dsa.sign
    calls: list[bool] = []

    def sign(*args: Any, **kwargs: Any) -> bytes:
        calls.append(kwargs["verify"])
        return real_sign(*args, **kwargs)

    q, _ = dsa.gen_keys(prv_key_int)
    msg_hash = sha256(b"a message").digest()

    with monkeypatch.context() as patch:
        patch.setattr(libsecp256k1_dsa, "sign", sign)
        for grind in (True, False):
            for verify in (True, False):
                calls.clear()
                dsa.sign_(msg_hash, q, grind=grind, verify=verify)
                # one crossing, carrying the caller's own verify -- not
                # zero, which is #982's bill, and not two, which is the
                # grinding loop this arm no longer walks
                assert calls == [verify]


@needs_bindings
def test_sign_recoverable_asks_the_bindings_to_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`verify=True` reaches `secp256k1_ecdsa_sign_recoverable`, written out.

    `sign_recoverable_` takes no `verify` of its own: the comment at its
    call into the bindings argues why True belongs there rather than at
    the bindings' default, the recovery id being a value nothing
    downstream re-derives the way a faulted r or s is caught by the
    first verification anybody makes of a plain signature. Nothing held
    that argument to the keyword actually written before this (issue
    986): a refactor dropping it, or writing False, changes no signature
    and no recovered key, and would still be caught by nothing.
    """
    real_sign = libsecp256k1_recovery.sign
    calls: list[bool] = []

    def sign(*args: Any, **kwargs: Any) -> tuple[bytes, int]:
        calls.append(kwargs["verify"])
        return real_sign(*args, **kwargs)

    q, _ = dsa.gen_keys(prv_key_int)
    msg_hash = sha256(b"a message").digest()

    with monkeypatch.context() as patch:
        patch.setattr(libsecp256k1_recovery, "sign", sign)
        dsa.sign_recoverable_(msg_hash, q)

    assert calls == [True]


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_signer_answers_what_sign_answers(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held key changes what a signature costs and not what it is.

    `Signer.sign_` is `sign_` over a key derived once, so the two answer
    the same DER octets -- asserted with `verify` both ways and over
    both `sign_` and `sign`, which reduces with hf first as the free
    spelling does. And over the arm that holds no bindings key at all --
    a curve or a hash function the bindings decline -- where `sign_` is
    the whole of the implementation.
    """
    if not bindings:
        no_bindings(monkeypatch)

    q, Q = dsa.gen_keys(prv_key_int)

    signer = dsa.Signer(prv_key_int)
    for msg in (b"", b"a message", bytes(32), bytes(1000)):
        msg_hash = reduce_to_hlen(msg)
        for verify in (True, False):
            expected = dsa.sign_(msg_hash, q, verify=verify).serialize()
            assert signer.sign_(msg_hash, verify=verify) == expected
            assert (
                signer.sign(msg, verify=verify)
                == dsa.sign(msg, q, verify=verify).serialize()
            )
        assert dsa.verify_(msg_hash, Q, signer.sign_(msg_hash))

    # grind reaches the same loop `sign_` walks on both arms
    for grind in (True, False):
        expected = dsa.sign(b"grind", q, grind=grind).serialize()
        assert signer.sign(b"grind", grind=grind) == expected


@needs_bindings
def test_a_signer_derives_and_parses_the_public_key_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The floor this class is for: held once, and never recomputed.

    `Signer.__init__` derives the public key with one `mult` -- the same
    multiplication `gen_keys` makes -- and on the delegated arm parses it
    into SEC octets once with `_sec_from_pub_key`, `_delegated_sign_`'s
    own docstring pricing that parse. What a later `sign_` call reads is
    the object `__init__` built, asserted here by its identity rather
    than by a call count: `mult` is not this class's alone, the Python
    arm's own nonce point costing one per signature, so counting every
    call would conflate the two. `_sec_from_pub_key` has no such second
    caller on this path, so it is counted as well, for the one call the
    constructor is asked to make and `_delegated_sign_` never repeats.
    """
    # `getattr`, not `dsa._sec_from_pub_key`: the name is imported into
    # `dsa` rather than defined there, so mypy's `--no-implicit-reexport`
    # refuses the plain attribute read even though `setattr` below patches
    # the same name -- and has to, `Signer.__init__` reading the copy
    # `from ... import` bound in `dsa`'s own namespace and not a fresh
    # lookup in `to_pub_key`
    real_sec = getattr(dsa, "_sec_from_pub_key")  # noqa: B009
    sec_calls: list[object] = []

    def counting_sec(*args: Any, **kwargs: Any) -> Any:
        sec_calls.append(1)
        return real_sec(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(dsa, "_sec_from_pub_key", counting_sec)
        signer = dsa.Signer(prv_key_int)
        assert sec_calls == [1]
        python_key = signer._python_key
        pub_key_sec = signer._pub_key_sec
        assert pub_key_sec is not None

        for msg in (b"a", b"b", b"c"):
            signer.sign(msg)
        assert sec_calls == [1]
        assert signer._python_key is python_key
        assert signer._pub_key_sec is pub_key_sec

    with monkeypatch.context() as patch:
        no_bindings(patch)
        python_signer = dsa.Signer(prv_key_int)
        assert python_signer._pub_key_sec is None
        held = python_signer._python_key

        for msg in (b"a", b"b", b"c"):
            python_signer.sign(msg)
        assert python_signer._python_key is held


def test_a_signer_refuses_what_the_constructor_refuses() -> None:
    """The key and the hash function are read at the constructor.

    A public constructor, so the refusal belongs at it rather than at
    the first signature -- which is the only place a caller could hear
    it, the public key being derived here.
    """
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        dsa.Signer(0)
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        dsa.Signer(secp256k1.n)
    with pytest.raises(BTClibTypeError):
        dsa.Signer(prv_key_int, secp256k1, "not a hash function")  # type: ignore[arg-type]


@pytest.mark.parametrize("bindings", _ARMS)
def test_the_arms_refuse_a_signature_that_does_not_verify(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check is wired to the raise, not merely written near it.

    No input reaches it -- a fresh signature verifies under the key that
    made it -- so what says the branch is live is a substituted
    verification: the bindings' own `_verify_` for the delegated arm,
    `_python_verified` for the Python one, each where its own check
    lives. Nothing about either refusal is fabricated, so the sentence
    is the one the real implementation raises.
    """
    msg = b"a message whose check is made to fail"

    if bindings:
        signer = dsa.Signer(prv_key_int)
        with monkeypatch.context() as patch:
            patch.setattr(libsecp256k1_dsa, "_verify_", lambda *_, **__: False)
            with pytest.raises(BTClibRuntimeError, match="does not verify"):
                signer.sign(msg)
            # verify=False never reaches the substituted check
            signer.sign(msg, verify=False)
        return

    no_bindings(monkeypatch)
    signer = dsa.Signer(prv_key_int)
    with monkeypatch.context() as patch:
        patch.setattr(dsa, "_python_verified", lambda *_, **__: False)
        with pytest.raises(BTClibRuntimeError, match="does not verify"):
            signer.sign(msg)
        signer.sign(msg, verify=False)


def test_a_wiped_python_signer_refuses_rather_than_signing_with_the_zeros(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lifetime a signer hands its caller, on the arm that can give it.

    `wipe` is the instruction and the `with` block is how to give it
    without having to remember; both leave a signer that refuses, and
    neither can be undone -- what the signer held it no longer holds. On
    this arm the scalar is the whole of what signing needs, so dropping
    it is genuinely the end of this signer's lifetime, an `int`'s own
    limit aside.
    """
    no_bindings(monkeypatch)

    signer = dsa.Signer(prv_key_int)
    assert signer.sign_(sha256(b"a message").digest())
    assert signer._q
    signer.wipe()
    assert not signer._q
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        signer.sign_(sha256(b"a message").digest())
    # idempotent, as `close` is on the signer contract
    signer.wipe()
    assert not signer._q

    with dsa.Signer(prv_key_int) as block_signer:
        assert block_signer.sign(b"a message")
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        block_signer.sign(b"a message")

    # and the block wipes on the way out of an exception too
    raising = dsa.Signer(prv_key_int)
    with pytest.raises(ZeroDivisionError), raising:
        _ = 1 / 0
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        raising.sign(b"a message")


@needs_bindings
def test_a_delegated_signer_s_wipe_zeroes_the_buffer_it_signs_from() -> None:
    """`wipe` reaches this arm's key now, not only the reference to it.

    btclib-secp256k1#253 is what makes this true: `dsa.sign`'s `prvkey`
    argument passes a 32-octet cffi array through unconverted rather
    than coercing it to a fresh, unreachable `bytes` on every call
    (btclib-secp256k1#247, closed by that change), so the buffer this
    signer built at construction is the same 32 octets every signature
    it has made was read from, and overwriting it now reaches every one
    of them at once -- not only the copy this object happens to be
    holding when `wipe` is called.
    """
    signer = dsa.Signer(prv_key_int)
    assert signer.sign(b"a message")

    buffer = signer._prvkey_buffer
    assert bytes(libsecp256k1_ffi.buffer(buffer)) != bytes(32)
    signer.wipe()
    assert bytes(libsecp256k1_ffi.buffer(buffer)) == bytes(32)
    assert signer._prvkey_buffer is None

    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        signer.sign(b"a message")
    # idempotent, as `close` is on the signer contract
    signer.wipe()
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        signer.sign(b"a message")

    with dsa.Signer(prv_key_int) as block_signer:
        assert block_signer.sign(b"a message")
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        block_signer.sign(b"a message")

    # and the block wipes on the way out of an exception too
    raising = dsa.Signer(prv_key_int)
    with pytest.raises(ZeroDivisionError), raising:
        _ = 1 / 0
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        raising.sign(b"a message")
