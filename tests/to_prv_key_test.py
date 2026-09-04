# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.to_prv_key` module."""

# Third party imports
import pytest

# Library imports
from btclib.alias import INF
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibTypeError, BTClibValueError, NotAPrvKeyError
from btclib.to_prv_key import int_from_prv_key, prv_keyinfo_from_prv_key
from tests.to_key_test import (
    Q,
    compressed_pub_keys,
    invalid_prv_keys,
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

    The forms are the scalar and its octets, and neither carries either
    property: a WIF is `b58`'s object and an xprv is `bip32`'s, each read
    where it is defined (issue #1188). So what is crossed here is what
    the arguments fill in, and nothing contradicts them.
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

    for prv_key5 in [q, *net_unaware_prv_keys]:
        assert q == int_from_prv_key(prv_key5)
        assert q == int_from_prv_key(prv_key5, secp256r1)
        assert prv_keyinfo_from_prv_key(prv_key5) in {m_c, m_unc}
        assert prv_keyinfo_from_prv_key(prv_key5, "mainnet") in {m_c, m_unc}
        assert prv_keyinfo_from_prv_key(prv_key5, "testnet") in {t_c, t_unc}

    for invalid_prv_key in [q0, qn, *invalid_prv_keys]:
        with pytest.raises(BTClibValueError):
            int_from_prv_key(invalid_prv_key)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(invalid_prv_key)

    for not_a_prv_key in [
        q0,
        qn,
        *not_a_prv_keys,
        *plain_pub_keys,
        *compressed_pub_keys,
        *uncompressed_pub_keys,
    ]:
        with pytest.raises(BTClibValueError):
            int_from_prv_key(not_a_prv_key)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(not_a_prv_key)

    # a Point and an extended key are spellings of other modules' types,
    # so what is wrong is the type and not the value: issue #814's rule,
    # and the `type: ignore` these need -- where none of the spellings
    # above needs one -- is the same line drawn by the type checker
    for wrong_type in [INF, Q, xprv_data, xprv0_data, xprvn_data, xpub_data]:
        with pytest.raises(BTClibTypeError, match="not a private key"):
            int_from_prv_key(wrong_type)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="not a private key"):
            prv_keyinfo_from_prv_key(wrong_type)  # type: ignore[arg-type]


def test_no_key_material_in_exceptions() -> None:
    """Private key material must not reach exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    # an xprv is no key here at all, and the refusal must not echo it
    with pytest.raises(BTClibValueError, match="not a private key") as excinfo:
        prv_keyinfo_from_prv_key(xprv_string, "testnet")
    assert xprv_string not in str(excinfo.value)

    # out-of-range scalar
    with pytest.raises(BTClibValueError, match="not in 1..n-1") as excinfo:
        int_from_prv_key(qn)
    assert f"{qn:x}" not in str(excinfo.value).lower()

    # unparsable octets
    with pytest.raises(BTClibValueError, match="not a private key") as excinfo:
        int_from_prv_key("02" * 33)
    assert "0202" not in str(excinfo.value)


def test_the_text_spellings_of_other_modules_are_refused() -> None:
    """A WIF and an extended key are text this module does not read.

    Both are base58, and neither is `ec.n_size` octets or their hex, so
    each is refused as octets that are no scalar: `b58` reads the one and
    `bip32` the other, and a caller holding either calls that module and
    passes the scalar on (issue #1188).
    """
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    for text in (xprv, xpub, wif):
        with pytest.raises(NotAPrvKeyError, match="not a private key: not octets"):
            prv_keyinfo_from_prv_key(text)
        with pytest.raises(NotAPrvKeyError, match="not a private key: not octets"):
            int_from_prv_key(text)


def test_an_uncompressed_sec_key_still_resolves() -> None:
    """32 raw bytes asked for uncompressed are a scalar and are resolved.

    `compressed` is what the record is filled in with here rather than a
    property of the input, so no size and no prefix contradicts it.
    """
    q_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    q_int = int(q_hex, 16)
    assert prv_keyinfo_from_prv_key(bytes.fromhex(q_hex), compressed=False) == (
        q_int,
        "mainnet",
        False,
    )
    assert int_from_prv_key(bytes.fromhex(q_hex)) == q_int
