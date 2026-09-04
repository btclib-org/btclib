# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.to_prv_key` module."""

# Third party imports
import pytest

# Library imports
from btclib.alias import INF
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibTypeError, BTClibValueError, InvalidPrvKeyError
from btclib.to_prv_key import int_from_prv_key, prv_keyinfo_from_prv_key
from tests.to_key_test import (
    INF_xpub_data,
    Q,
    compressed_prv_keys,
    compressed_pub_keys,
    invalid_prv_keys,
    net_aware_prv_keys,
    net_unaware_prv_keys,
    not_a_prv_keys,
    plain_prv_keys,
    plain_pub_keys,
    q,
    q0,
    qn,
    uncompressed_pub_keys,
    xprv0_data,
    xprv_data,
    xprv_string,
    xprvn_data,
    xpub_data,
)


def test_from_prv_key() -> None:
    """Check every private-key form against network and compression.

    A WIF is not one of the forms: `to_prv_key` cannot spell it, so
    `compressed_prv_keys` and `net_aware_prv_keys` below hold only an
    xprv, which is always compressed -- there is no uncompressed
    net-aware form left for this module to resolve (issue #1188).
    """
    secp256r1 = CURVES["secp256r1"]
    m_c = (q, "mainnet", True)
    m_unc = (q, "mainnet", False)
    t_c = (q, "testnet", True)
    t_unc = (q, "testnet", False)
    for prv_key in [q, *plain_prv_keys]:
        assert q == int_from_prv_key(prv_key)
        assert q == int_from_prv_key(prv_key, secp256r1)
        assert m_c == prv_keyinfo_from_prv_key(prv_key)
        assert m_c == prv_keyinfo_from_prv_key(prv_key, "mainnet")
        assert m_c == prv_keyinfo_from_prv_key(prv_key, "mainnet", compressed=True)
        assert m_c == prv_keyinfo_from_prv_key(prv_key, compressed=True)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key, "mainnet", compressed=False)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key, compressed=False)
        assert t_c == prv_keyinfo_from_prv_key(prv_key, "testnet")
        assert t_c == prv_keyinfo_from_prv_key(prv_key, "testnet", compressed=True)
        assert t_unc == prv_keyinfo_from_prv_key(prv_key, "testnet", compressed=False)

    for prv_key2 in [xprv_data, *compressed_prv_keys]:
        assert q == int_from_prv_key(prv_key2)
        with pytest.raises(BTClibValueError):
            int_from_prv_key(prv_key2, secp256r1)
        assert m_c == prv_keyinfo_from_prv_key(prv_key2)
        assert m_c == prv_keyinfo_from_prv_key(prv_key2, "mainnet")
        assert m_c == prv_keyinfo_from_prv_key(prv_key2, "mainnet", compressed=True)
        assert m_c == prv_keyinfo_from_prv_key(prv_key2, compressed=True)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key2, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key2, compressed=False)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key2, "testnet")
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key2, "testnet", compressed=True)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key2, "testnet", compressed=False)

    for prv_key4 in [xprv_data, *net_aware_prv_keys]:
        assert q == int_from_prv_key(prv_key4)
        with pytest.raises(BTClibValueError):
            int_from_prv_key(prv_key4, secp256r1)
        assert prv_keyinfo_from_prv_key(prv_key4) == m_c
        assert prv_keyinfo_from_prv_key(prv_key4, "mainnet") == m_c
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key4, "testnet")

    for prv_key5 in [q, *net_unaware_prv_keys]:
        assert q == int_from_prv_key(prv_key5)
        assert q == int_from_prv_key(prv_key5, secp256r1)
        assert prv_keyinfo_from_prv_key(prv_key5) in {m_c, m_unc}
        assert prv_keyinfo_from_prv_key(prv_key5, "mainnet") in {m_c, m_unc}
        assert prv_keyinfo_from_prv_key(prv_key5, "testnet") in {t_c, t_unc}

    for invalid_prv_key in [q0, qn, xprv0_data, xprvn_data, *invalid_prv_keys]:
        with pytest.raises(BTClibValueError):
            int_from_prv_key(invalid_prv_key)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(invalid_prv_key)

    for not_a_prv_key in [
        q0,
        qn,
        xprv0_data,
        xprvn_data,
        INF_xpub_data,
        *not_a_prv_keys,
        *plain_pub_keys,
        xpub_data,
        *compressed_pub_keys,
        *uncompressed_pub_keys,
    ]:
        with pytest.raises(BTClibValueError):
            int_from_prv_key(not_a_prv_key)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(not_a_prv_key)

    # a Point is a public key spelling and no private one, so it is the
    # type that is wrong and not the value: issue #814's rule, and the
    # `type: ignore` these two need -- where none of the spellings above
    # needs one -- is the same line drawn by the type checker
    for a_point in [INF, Q]:
        with pytest.raises(BTClibTypeError, match="not a private key"):
            int_from_prv_key(a_point)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="not a private key"):
            prv_keyinfo_from_prv_key(a_point)  # type: ignore[arg-type]


def test_no_key_material_in_exceptions() -> None:
    """Private key material must not reach exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    # network mismatch on a valid xprv
    with pytest.raises(BTClibValueError, match="not a testnet key: ") as excinfo:
        prv_keyinfo_from_prv_key(xprv_data, "testnet")
    assert xprv_string not in str(excinfo.value)

    # out-of-range scalar
    with pytest.raises(BTClibValueError, match="not in 1..n-1") as excinfo:
        int_from_prv_key(qn)
    assert f"{qn:x}" not in str(excinfo.value).lower()

    # unparsable octets
    with pytest.raises(BTClibValueError, match="not a private key") as excinfo:
        int_from_prv_key("02" * 33)
    assert "0202" not in str(excinfo.value)


def test_a_recognised_format_stops_the_guessing() -> None:
    """InvalidPrvKeyError propagates; a format neither recognises moves on.

    An xpub is a BIP32 xkey, so "not a private key" is the answer and not
    a step on the way to one -- the format is recognised, and what is
    wrong with it is worth more than the news that it is not octets
    either. The WIF half of this question is now `b58`'s (issue #1188).
    """
    xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    with pytest.raises(InvalidPrvKeyError, match="not a private key: prefix 0x03"):
        prv_keyinfo_from_prv_key(xpub)

    with pytest.raises(BTClibValueError):
        prv_keyinfo_from_prv_key(xpub)


def test_an_uncompressed_sec_key_still_resolves() -> None:
    """The compressed check follows the xkey decode, not precedes it.

    A BIP32 key is always compressed, so the check has to be there; ahead
    of the decode it would reject 32 raw bytes asked for uncompressed,
    which are octets and have nothing to do with BIP32.
    """
    q_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    q_int = int(q_hex, 16)
    assert prv_keyinfo_from_prv_key(bytes.fromhex(q_hex), compressed=False) == (
        q_int,
        "mainnet",
        False,
    )
    assert int_from_prv_key(bytes.fromhex(q_hex)) == q_int

    # and a real xprv asked for uncompressed is still a conflict
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    err_msg = "uncompressed SEC / compressed BIP32 mismatch"
    with pytest.raises(InvalidPrvKeyError, match=err_msg):
        prv_keyinfo_from_prv_key(xprv, compressed=False)
