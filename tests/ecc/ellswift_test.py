# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.ellswift` module's own `xdh`.

The encoding is btclib_ecc's, and its tests are that package's. What
is btclib's is BIP324's x-only ECDH over two encodings, and the bindings
are the other implementation it is held against: each party through
them, and each party through the Python arithmetic, reach one secret.
"""

import hashlib
import secrets

import pytest

from btclib.curves import CURVES, mult, secp256k1
from btclib.ecc import ellswift
from btclib.exceptions import BTClibTypeError, BTClibValueError
from tests import needs_bindings, no_bindings_anywhere

# the other Koblitz curves of the catalogue: a == 0 and a square -3, which
# is all the map wants, so the Python path serves them without a switch
OTHER_CURVES = ("secp160k1", "secp192k1", "secp224k1")


def _key() -> int:
    """Return a random secp256k1 private key."""
    return secrets.randbelow(secp256k1.n - 1) + 1


@needs_bindings
def test_xdh_agrees_between_parties_and_with_the_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One shared secret, whichever side derives it and whichever path.

    Six values that must be equal: each party through the bindings called
    directly, through `xdh` delegating to them, and through the Python
    arithmetic.
    """
    from btclib_secp256k1 import ellswift as libsecp256k1_ellswift  # noqa: PLC0415

    for _ in range(4):
        a, b = _key(), _key()
        ell_a = ellswift.create_var(a)
        ell_b = ellswift.create_var(b)

        shared = libsecp256k1_ellswift.xdh(ell_a, ell_b, a, 0)
        assert libsecp256k1_ellswift.xdh(ell_a, ell_b, b, 1) == shared
        assert ellswift.xdh(ell_a, ell_b, a, 0) == shared
        assert ellswift.xdh(ell_a, ell_b, b, 1) == shared

        with monkeypatch.context() as no_bindings:
            no_bindings_anywhere(no_bindings)
            assert ellswift.xdh(ell_a, ell_b, a, 0) == shared
            assert ellswift.xdh(ell_a, ell_b, b, 1) == shared


@pytest.mark.parametrize("curve_name", OTHER_CURVES)
def test_xdh_on_the_other_koblitz_curves(curve_name: str) -> None:
    """The Python path on the curves the bindings do not serve."""
    ec = CURVES[curve_name]

    a = secrets.randbelow(ec.n - 1) + 1
    b = secrets.randbelow(ec.n - 1) + 1
    ell_a = ellswift.create_var(a, ec)
    ell_b = ellswift.create_var(b, ec)
    assert len(ell_a) == len(ell_b) == 2 * ec.p_size
    shared = ellswift.xdh(ell_a, ell_b, a, 0, ec)
    assert ellswift.xdh(ell_a, ell_b, b, 1, ec) == shared


def test_xdh_on_a_curve_the_map_is_not_defined_on() -> None:
    """A curve with a != 0 is refused by the map, as a ValueError."""
    ec = CURVES["secp256r1"]
    ell = bytes(2 * ec.p_size)

    err_msg = "the ElligatorSwift map wants a curve with a == 0"
    with pytest.raises(ValueError, match=err_msg):
        ellswift.xdh(ell, ell, 1, 0, ec)


def test_xdh_refuses_what_is_not_a_curve() -> None:
    """`ec` is a Curve, and a curve's name is not one."""
    ell = ellswift.create_var(_key())

    with pytest.raises(BTClibTypeError, match="invalid ec type: str"):
        ellswift.xdh(ell, ell, 1, 0, "secp256k1")  # type: ignore[arg-type]


def test_xdh_wrong_size_encoding() -> None:
    """An encoding is two field elements, and nothing else is one."""
    ell = ellswift.create_var(_key())

    assert len(ell) == ellswift.ELL_SIZE
    for bad in (ell[:-1], ell + b"\x00", b""):
        with pytest.raises(BTClibValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(bad, ell, 1, 0)
        with pytest.raises(BTClibValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(ell, bad, 1, 0)


def test_xdh_invalid_party() -> None:
    """The party says which encoding is the caller's; there are two."""
    ell = ellswift.create_var(_key())

    for party in (-1, 2):
        with pytest.raises(BTClibValueError, match="invalid party"):
            ellswift.xdh(ell, ell, 1, party)


def test_xdh_invalid_private_key() -> None:
    """A key outside 1..n-1 is refused, by `scalar_from_prv_key`."""
    ell = ellswift.create_var(_key())

    for prv_key in (0, secp256k1.n):
        with pytest.raises(ValueError, match="private key not in 1..n-1"):
            ellswift.xdh(ell, ell, prv_key, 0)


def test_xdh_tag_is_bip324s() -> None:
    """The secret is the hash under BIP324's own tag, recomputed here."""
    a, b = _key(), _key()
    ell_a = ellswift.create_var(a)
    ell_b = ellswift.create_var(b)

    x = mult(a, ellswift.decode_var(ell_b))[0]
    preimage = ell_a + ell_b + x.to_bytes(32, "big")
    tag_hash = hashlib.sha256(b"bip324_ellswift_xonly_ecdh").digest()
    expected = hashlib.sha256(tag_hash + tag_hash + preimage).digest()
    assert ellswift.XDH_TAG == b"bip324_ellswift_xonly_ecdh"
    assert ellswift.xdh(ell_a, ell_b, a, 0) == expected
