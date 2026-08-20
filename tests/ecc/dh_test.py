# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.dh` module."""

from hashlib import sha1, sha256

import pytest

from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.curves import bytes_from_point, mult
from btclib.curves.curve import CURVES
from btclib.ecc import dh, diffie_hellman, dsa
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.kdf import ansi_x9_63_kdf
from tests import needs_bindings


def test_ecdh() -> None:
    """Check both sides derive one shared key, at sizes around the digest."""
    ec = CURVES["secp256k1"]
    hf = sha256

    a, A = dsa.gen_keys()  # Alice
    b, B = dsa.gen_keys()  # Bob

    # Alice computes the shared secret using Bob's public key
    shared_secret_a = mult(a, B)

    # Bob computes the shared secret using Alice's public key
    shared_secret_b = mult(b, A)

    assert shared_secret_a == shared_secret_b
    assert shared_secret_a == mult(a * b, ec.G)

    # hash the shared secret to remove weak bits
    shared_secret_field_element = shared_secret_a[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)

    shared_info = b"deadbeef"

    hf_size = hf().digest_size
    for size in (hf_size - 1, hf_size, hf_size + 1):
        shared_key = ansi_x9_63_kdf(z, size, hf, None)
        assert len(shared_key) == size
        assert shared_key == diffie_hellman(a, B, size, None, ec, hf)
        assert shared_key == diffie_hellman(b, A, size, None, ec, hf)
        shared_key = ansi_x9_63_kdf(z, size, hf, shared_info)
        assert len(shared_key) == size
        assert shared_key == diffie_hellman(a, B, size, shared_info, ec, hf)
        assert shared_key == diffie_hellman(b, A, size, shared_info, ec, hf)

    max_size = hf_size * (2**32 - 1)
    size = max_size + 1
    with pytest.raises(BTClibValueError, match="cannot derive a key larger than "):
        ansi_x9_63_kdf(z, size, hf, None)


def test_gec_2() -> None:
    """GEC 2: Test Vectors for SEC 1, section 4.1.

    - http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
    """
    # 4.1.1
    ec = CURVES["secp160r1"]
    hf = sha1

    # 4.1.2
    dU = 971761939728640320549601132085879836204587084162
    assert dU == 0xAA374FFC3CE144E6B073307972CB6D57B2A4E982
    QU = mult(dU, ec.G, ec)
    assert QU == (
        466448783855397898016055842232266600516272889280,
        1110706324081757720403272427311003102474457754220,
    )
    assert (
        bytes_from_point(QU, ec).hex() == "0251b4496fecc406ed0e75a24a3c03206251419dc0"
    )

    # 4.1.3
    dV = 399525573676508631577122671218044116107572676710
    assert dV == 0x45FB58A92A17AD4B15101C66E74F277E2B460866
    QV = mult(dV, ec.G, ec)
    assert QV == (
        420773078745784176406965940076771545932416607676,
        221937774842090227911893783570676792435918278531,
    )
    assert (
        bytes_from_point(QV, ec).hex() == "0349b41e0e9c0369c2328739d90f63d56707c6e5bc"
    )

    # expected results
    z_exp = 1155982782519895915997745984453282631351432623114
    assert z_exp == 0xCA7C0F8C3FFA87A96E1B74AC8E6AF594347BB40A
    size = 20

    # 4.1.4
    z, _ = mult(dU, QV, ec)  # x coordinate only
    assert z == z_exp
    keyingdata = ansi_x9_63_kdf(
        z.to_bytes(ec.p_size, byteorder="big", signed=False), size, hf, None
    )
    assert keyingdata.hex() == "744ab703f5bc082e59185f6d049d2d367db245c2"
    # the whole scheme, on the curve the bindings do not serve: this
    # vector is what covers the Python shared point, secp256k1 having
    # been handed to libsecp256k1
    assert diffie_hellman(dU, QV, size, None, ec, hf) == keyingdata

    # 4.1.5
    z, _ = mult(dV, QU, ec)  # x coordinate only
    assert z == z_exp
    keyingdata = ansi_x9_63_kdf(
        z.to_bytes(ec.p_size, byteorder="big", signed=False), size, hf, None
    )
    assert keyingdata.hex() == "744ab703f5bc082e59185f6d049d2d367db245c2"


def test_the_python_shared_point_is_the_bindings_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One shared key, whoever multiplies the point.

    Three ways to the same bytes: libsecp256k1 for each side of the
    agreement, and the Python endomorphism path for one of them. The
    patch is how that path is reached on secp256k1 at all, `mult`
    delegating every scalar but zero once the point is a public key
    rather than the generator.
    """
    a, A = dsa.gen_keys()  # Alice
    b, B = dsa.gen_keys()  # Bob

    shared_key = diffie_hellman(a, B, 32)
    assert diffie_hellman(b, A, 32) == shared_key
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dh, "_libsecp256k1_serves", lambda *_: False)
        assert diffie_hellman(a, B, 32) == shared_key


@needs_bindings
def test_a_normal_dU_reaches_the_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ordinary key takes the direct multiplication into libsecp256k1.

    `diffie_hellman` reduces the key with `d = dU % ec.n` before the guard
    that gates the direct `pubkey_tweak_mul` call on `d` being nonzero: a
    mutant of that one line -- `ReplaceBinaryOperator_Mod_FloorDiv`
    turning it to `dU // ec.n`, `_Mod_RShift` to `dU >> ec.n` -- makes `d`
    zero for every `dU` below `n`, which is every caller, and the guard
    then falls through to `mult(dU, QV, ec)` instead. That call still
    reaches libsecp256k1: it reduces `dU` on its own and dispatches
    through `_libsecp256k1_multi_mult`/`pubkey_tweak_mul_sum`, a second
    constant-time binding rather than the Python endomorphism arithmetic
    -- so the mutant costs this line's direct entry point and not the
    constant-time guarantee itself. `ansi_x9_63_kdf` derives the same
    bytes off either binding's point, so no assertion on the shared key
    tells the two apart (issue 975); this records the call into
    `pubkey_tweak_mul` instead of the answer it returns, so a mutant that
    skips the direct delegation fails here rather than matching it.
    """
    calls: list[int] = []
    real_tweak_mul = libsecp256k1_keys.pubkey_tweak_mul

    def record(pubkey_bytes: bytes, tweak: int, compressed: bool = True) -> bytes:
        calls.append(tweak)
        return real_tweak_mul(pubkey_bytes, tweak, compressed)

    monkeypatch.setattr(libsecp256k1_keys, "pubkey_tweak_mul", record)

    a, _A = dsa.gen_keys()  # Alice
    _b, B = dsa.gen_keys()  # Bob
    diffie_hellman(a, B, 32)
    assert calls == [a % CURVES["secp256k1"].n]


def test_infinity_shared_secret() -> None:
    """A degenerate scalar, zero mod n, maps every public key to INF."""
    ec = CURVES["secp256k1"]
    err_msg = r"invalid \(INF\) key"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        diffie_hellman(0, ec.G, 32)
