#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.to_prv_key` module."""

# Third party imports
import pytest

# Library imports
from btclib.alias import INF
from btclib.ec.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.to_prv_key import (
    _prv_keyinfo_from_wif,
    int_from_prv_key,
    prv_keyinfo_from_prv_key,
)
from tests.test_to_key import (
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
    uncompressed_prv_keys,
    uncompressed_pub_keys,
    wif_compressed_string,
    xprv0_data,
    xprv_data,
    xprv_string,
    xprvn_data,
    xpub_data,
)


def test_from_prv_key() -> None:
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

    for prv_key3 in uncompressed_prv_keys:
        assert q == int_from_prv_key(prv_key3)
        with pytest.raises(BTClibValueError):
            int_from_prv_key(prv_key3, secp256r1)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key3)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key3, "mainnet")
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key3, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key3, compressed=True)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key3, "mainnet", compressed=False)
        assert m_unc == prv_keyinfo_from_prv_key(prv_key3, compressed=False)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key3, "testnet")
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key3, "testnet", compressed=True)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key3, "testnet", compressed=False)

    for prv_key4 in [xprv_data, *net_aware_prv_keys]:
        assert q == int_from_prv_key(prv_key4)
        with pytest.raises(BTClibValueError):
            int_from_prv_key(prv_key4, secp256r1)
        assert prv_keyinfo_from_prv_key(prv_key4) in (m_c, m_unc)
        assert prv_keyinfo_from_prv_key(prv_key4, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(prv_key4, "testnet")

    for prv_key5 in [q, *net_unaware_prv_keys]:
        assert q == int_from_prv_key(prv_key5)
        assert q == int_from_prv_key(prv_key5, secp256r1)
        assert prv_keyinfo_from_prv_key(prv_key5) in (m_c, m_unc)
        assert prv_keyinfo_from_prv_key(prv_key5, "mainnet") in (m_c, m_unc)
        assert prv_keyinfo_from_prv_key(prv_key5, "testnet") in (t_c, t_unc)

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
        INF,
        INF_xpub_data,
        *not_a_prv_keys,
        Q,
        *plain_pub_keys,
        xpub_data,
        *compressed_pub_keys,
        *uncompressed_pub_keys,
    ]:
        with pytest.raises(BTClibValueError):
            int_from_prv_key(not_a_prv_key)  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(not_a_prv_key)  # type: ignore[arg-type]


def test_no_key_material_in_exceptions() -> None:
    """Private key material must not reach exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    # network mismatch on a valid xprv
    with pytest.raises(BTClibValueError, match="not a testnet key: ") as excinfo:
        prv_keyinfo_from_prv_key(xprv_data, "testnet")
    assert xprv_string not in str(excinfo.value)

    # network mismatch on a valid WIF
    with pytest.raises(BTClibValueError, match="not a testnet wif: ") as excinfo:
        _prv_keyinfo_from_wif(wif_compressed_string, "testnet")
    assert wif_compressed_string not in str(excinfo.value)

    # out-of-range scalar
    with pytest.raises(BTClibValueError, match="not in 1..n-1") as excinfo:
        int_from_prv_key(qn)
    assert f"{qn:x}" not in str(excinfo.value).lower()

    # unparsable octets
    with pytest.raises(BTClibValueError, match="not a private key") as excinfo:
        int_from_prv_key("02" * 33)
    assert "0202" not in str(excinfo.value)
