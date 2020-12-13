#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.base58_wif` module."

from typing import List, Tuple

import pytest

from btclib.base58 import b58encode
from btclib.base58_wif import wif_from_prv_key
from btclib.curve import secp256k1
from btclib.exceptions import BTClibValueError
from btclib.to_prv_key import prv_keyinfo_from_prv_key

ec = secp256k1


def test_wif_from_prv_key() -> None:
    prv_key = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    test_vectors: List[Tuple[str, str, bool]] = [
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", "mainnet", True),
        ("cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx", "testnet", True),
        ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "mainnet", False),
        ("91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2", "testnet", False),
        (" KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", "mainnet", True),
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ", "mainnet", True),
    ]
    for v in test_vectors:
        assert v[0].strip() == wif_from_prv_key(prv_key, v[1], v[2])
        q, network, compressed = prv_keyinfo_from_prv_key(v[0])
        assert q == int(prv_key, 16)
        assert network == v[1]
        assert compressed == v[2]

    bad_q = ec.n.to_bytes(ec.nsize, byteorder="big", signed=False)
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1: "):
        wif_from_prv_key(bad_q, "mainnet", True)

    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # not a private key: 33 bytes
    bad_q = 33 * b"\x02"
    with pytest.raises(BTClibValueError, match="not a private key: "):
        wif_from_prv_key(bad_q, "mainnet", True)
    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a WIF: missing leading 0x80
    good_q = 32 * b"\x02"
    payload = b"\x81" + good_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a compressed WIF: missing trailing 0x01
    payload = b"\x80" + good_q + b"\x00"
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a WIF: wrong size (35)
    payload = b"\x80" + good_q + b"\x01\x00"
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)
