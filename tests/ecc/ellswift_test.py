# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.ellswift` module.

The two BIP324 vector files pin the map itself, which is deterministic.
`create` and `encode` are not -- one of up to eight preimages is picked
at random -- so what holds them is a round trip, and the bindings are the
other implementation it is held against: `decode` of libsecp256k1 accepts
what btclib's Python encoded, and btclib's Python decodes what
libsecp256k1 created.
"""

import secrets
from typing import Any

import pytest

from btclib._libsecp256k1 import ellswift as libsecp256k1_ellswift
from btclib.curves import mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.curves.sec_point import bytes_from_point
from btclib.ecc import ellswift
from btclib.ecc.ellswift import _xswiftec_inv_var, _xswiftec_var
from btclib.exceptions import BTClibValueError
from tests import load_csv, needs_bindings, vector_id

# the other three Koblitz curves of the catalogue: a == 0 and a square
# -3, which is all the map wants, so the Python path serves them and this
# is what says so. secp224k1 is the one with p % 4 == 1, i.e. the one
# whose square roots go through Tonelli-Shanks rather than a single pow
OTHER_CURVES = ("secp160k1", "secp192k1", "secp224k1")


def decode_vectors() -> list[Any]:
    """Load BIP324's ellswift_decode_test_vectors.csv as pytest params."""
    return [
        pytest.param(row, id=vector_id(index, row[2]))
        for index, row in enumerate(
            load_csv("ecc", "_data", "ellswift_decode_test_vectors.csv")
        )
    ]


def xswiftec_inv_vectors() -> list[Any]:
    """Load BIP324's xswiftec_inv_test_vectors.csv as pytest params."""
    return [
        pytest.param(row, id=vector_id(index, row[10]))
        for index, row in enumerate(
            load_csv("ecc", "_data", "xswiftec_inv_test_vectors.csv")
        )
    ]


@pytest.mark.parametrize("row", decode_vectors())
@needs_bindings
def test_ellswift_decode_vectors(row: list[str]) -> None:
    """BIP324's decode vectors, against the map and against the bindings.

    - https://github.com/bitcoin/bips/blob/master/bip-0324/ellswift_decode_test_vectors.csv

    The comment column names the branch each row exercises, and is the
    test id: `u%p=0`, `t>=p`, which of the three candidate x-coordinates
    is the valid one, and the `u^3+t^2+7=0` substitution.
    """
    ellswift_hex, x_hex, _comment = row
    ell = bytes.fromhex(ellswift_hex)
    x = int(x_hex, 16)

    u = int.from_bytes(ell[:32], byteorder="big", signed=False)
    t = int.from_bytes(ell[32:], byteorder="big", signed=False)
    assert _xswiftec_var(u, t, secp256k1) == x

    # the whole of decode, both paths, and the bindings beside them: the
    # vector pins the x-coordinate, the parity of t pins the y
    Q = ellswift.decode_var(ell)
    assert Q[0] == x
    assert bytes_from_point(Q) == libsecp256k1_ellswift.decode(ell)


@pytest.mark.parametrize("row", decode_vectors())
@needs_bindings
def test_the_python_decode_is_the_bindings_one(
    row: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every decode vector again, with the dispatch patched off.

    `decode` hands secp256k1 to libsecp256k1, so without this the Python
    map would be exercised by `_xswiftec_var` alone and never through the
    function a caller reaches.
    """
    ell = bytes.fromhex(row[0])
    expected = ellswift.decode_var(ell)
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(ellswift, "_libsecp256k1_serves", lambda *_: False)
        assert ellswift.decode_var(ell) == expected


@pytest.mark.parametrize("row", xswiftec_inv_vectors())
def test_xswiftec_inv_vectors(row: list[str]) -> None:
    """BIP324's inverse vectors: eight cases per row, failures included.

    - https://github.com/bitcoin/bips/blob/master/bip-0324/xswiftec_inv_test_vectors.csv

    An empty cell is a case with no preimage, and asserting that it has
    none is the half that matters: an inverse too permissive would
    return something for it and still pass every non-empty cell.
    """
    u = int(row[0], 16)
    x = int(row[1], 16)

    for case in range(8):
        cell = row[2 + case]
        t = _xswiftec_inv_var(x, u, case, secp256k1)
        if not cell:
            assert t is None, f"case {case} should have no preimage"
        else:
            assert t == int(cell, 16), f"case {case}"
            # every preimage the inverse returns maps back to the x it
            # was asked about, which no cell of the file states
            assert _xswiftec_var(u, t, secp256k1) == x


@needs_bindings
def test_create_and_encode_round_trip() -> None:
    """What create and encode produce, decode takes back to the key.

    Randomized on both sides, so this runs a handful of keys rather than
    one: a case that fails once in eight is what the eight-way choice of
    a preimage could hide.
    """
    for _ in range(8):
        q, Q = _key_pair()

        for ell in (ellswift.create_var(q), ellswift.encode_var(Q)):
            assert len(ell) == ellswift.ELL_SIZE
            assert ellswift.decode_var(ell) == Q
            # the bindings agree about what btclib produced
            assert libsecp256k1_ellswift.decode(ell) == bytes_from_point(Q)


@needs_bindings
def test_the_python_create_and_encode_are_the_bindings_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python encoding is one libsecp256k1 decodes, and conversely.

    Equality is not the assertion available here: the encoding is a
    random choice among preimages, so the two implementations agree on
    the key rather than on the bytes. That is the whole property -- an
    encoding is not canonical.
    """
    for _ in range(8):
        q, Q = _key_pair()
        sec = bytes_from_point(Q)

        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(ellswift, "_libsecp256k1_serves", lambda *_: False)
            python_create = ellswift.create_var(q)
            python_encode = ellswift.encode_var(Q)
            # the Python path also decodes what the bindings created
            assert ellswift.decode_var(libsecp256k1_ellswift.create(q)) == Q

        for ell in (python_create, python_encode):
            assert libsecp256k1_ellswift.decode(ell) == sec
            assert ellswift.decode_var(ell) == Q


@needs_bindings
def test_xdh_agrees_between_parties_and_with_the_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One shared secret, whichever side derives it and whichever path.

    Four values that must be equal: each party through the bindings, and
    each party through the Python map.
    """
    for _ in range(4):
        a, _A = _key_pair()
        b, _B = _key_pair()
        ell_a = ellswift.create_var(a)
        ell_b = ellswift.create_var(b)

        shared = libsecp256k1_ellswift.xdh(ell_a, ell_b, a, 0)
        assert libsecp256k1_ellswift.xdh(ell_a, ell_b, b, 1) == shared
        assert ellswift.xdh(ell_a, ell_b, a, 0) == shared
        assert ellswift.xdh(ell_a, ell_b, b, 1) == shared

        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(ellswift, "_libsecp256k1_serves", lambda *_: False)
            assert ellswift.xdh(ell_a, ell_b, a, 0) == shared
            assert ellswift.xdh(ell_a, ell_b, b, 1) == shared


@pytest.mark.parametrize("curve_name", OTHER_CURVES)
def test_the_other_koblitz_curves(curve_name: str) -> None:
    """The Python path on the curves the bindings do not serve.

    Not a redundant pass over the same arithmetic: these reach it without
    a monkeypatch, which is what keeps the map honest about `ec` being a
    parameter rather than a decoration.
    """
    ec = CURVES[curve_name]

    q = secrets.randbelow(ec.n - 1) + 1
    Q = mult(q, ec.G, ec)

    for ell in (ellswift.create_var(q, ec), ellswift.encode_var(Q, ec)):
        assert len(ell) == 2 * ec.p_size
        assert ellswift.decode_var(ell, ec) == Q

    b = secrets.randbelow(ec.n - 1) + 1
    ell_a = ellswift.create_var(q, ec)
    ell_b = ellswift.create_var(b, ec)
    shared = ellswift.xdh(ell_a, ell_b, q, 0, ec)
    assert ellswift.xdh(ell_a, ell_b, b, 1, ec) == shared


def test_a_curve_the_map_is_not_defined_on() -> None:
    """Refuse a curve with a != 0 at every entry point of the map."""
    ec = CURVES["secp256r1"]
    q, _Q = _key_pair()
    ell = bytes(2 * ec.p_size)

    err_msg = "the ElligatorSwift map wants a curve with a == 0"
    with pytest.raises(BTClibValueError, match=err_msg):
        ellswift.create_var(q, ec)
    with pytest.raises(BTClibValueError, match=err_msg):
        ellswift.encode_var(mult(q, ec.G, ec), ec)
    with pytest.raises(BTClibValueError, match=err_msg):
        ellswift.decode_var(ell, ec)
    with pytest.raises(BTClibValueError, match=err_msg):
        ellswift.xdh(ell, ell, q, 0, ec)


def test_wrong_size_encoding() -> None:
    """An encoding is two field elements, and nothing else is one."""
    ell = ellswift.create_var(secrets.randbelow(secp256k1.n - 1) + 1)

    for bad in (ell[:-1], ell + b"\x00", b""):
        with pytest.raises(BTClibValueError, match="invalid ElligatorSwift size"):
            ellswift.decode_var(bad)
        with pytest.raises(BTClibValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(bad, ell, 1, 0)
        with pytest.raises(BTClibValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(ell, bad, 1, 0)


def test_invalid_party() -> None:
    """The party says which encoding is the caller's; there are two."""
    ell = ellswift.create_var(secrets.randbelow(secp256k1.n - 1) + 1)

    for party in (-1, 2):
        with pytest.raises(BTClibValueError, match="invalid party"):
            ellswift.xdh(ell, ell, 1, party)


def test_invalid_private_key() -> None:
    """A key outside 1..n-1 is refused, and by `scalar_from_prv_key`."""
    ell = ellswift.create_var(secrets.randbelow(secp256k1.n - 1) + 1)

    for prv_key in (0, secp256k1.n):
        with pytest.raises(BTClibValueError):
            ellswift.create_var(prv_key)
        with pytest.raises(BTClibValueError):
            ellswift.xdh(ell, ell, prv_key, 0)


def _key_pair() -> tuple[int, tuple[int, int]]:
    """Return a random secp256k1 key pair."""
    q = secrets.randbelow(secp256k1.n - 1) + 1
    return q, mult(q, secp256k1.G, secp256k1)
