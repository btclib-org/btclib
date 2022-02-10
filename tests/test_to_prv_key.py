#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.to_prv_key` module."

# Third party imports
import pytest

# Library imports
from btclib.ecc.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.to_prv_key import int_from_prv_key, prv_keyinfo_from_prv_key
from tests.test_to_key import (
    INF,
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
    xprv0_data,
    xprv_data,
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
            int_from_prv_key(invalid_prv_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(invalid_prv_key)  # type: ignore

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
            int_from_prv_key(not_a_prv_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(not_a_prv_key)  # type: ignore
