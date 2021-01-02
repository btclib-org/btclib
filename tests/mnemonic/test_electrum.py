#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.electrum` module."

import json
from os import path

import pytest

from btclib.bip32 import bip32, slip132
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import electrum


def test_mnemonic() -> None:
    lang = "en"

    entropy = 0x110AAAA03974D093EDA670121023CD0772
    eversion = "standard"
    # FIXME: is the following mnemonic obtained in Electrum
    # from the above entropy?
    mnemonic = "ability awful fetch liberty company spatial panda hat then canal ball crouch bunker"
    mnemonic2 = electrum.mnemonic_from_entropy(entropy, eversion, lang)
    assert mnemonic == mnemonic2

    entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
    assert entr - entropy < 0xFFF

    xprv = "xprv9s21ZrQH143K2tn5j4pmrLXkS6dkbuX6mFhJfCxAwN6ofRo5ddCrLRWogKEs1AptPmLgrthKxU2csfBgkoKECWtj1XMRicRsoWawukaRQft"
    xprv2 = electrum.mxprv_from_mnemonic(mnemonic)
    assert xprv2 == xprv

    eversion = "std"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mnemonic_from_entropy(entropy, eversion, lang)

    unkn_ver = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.entropy_from_mnemonic(unkn_ver, lang)

    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mxprv_from_mnemonic(unkn_ver)

    for eversion in ("2fa", "2fa_segwit"):
        mnemonic = electrum.mnemonic_from_entropy(entropy, eversion, lang)
        with pytest.raises(
            BTClibValueError, match="unmanaged electrum mnemonic version: "
        ):
            electrum.mxprv_from_mnemonic(mnemonic)

    mnemonic = "slender flight session office noodle hand couple option office wait uniform morning"
    assert electrum.version_from_mnemonic(mnemonic)[0] == "2fa_segwit"

    mnemonic = (
        "history recycle company awful donor fold beef nominee hard bleak bracket six"
    )
    assert electrum.version_from_mnemonic(mnemonic)[0] == "2fa"


def test_vectors() -> None:
    fname = "electrum_test_vectors.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r") as file_:
        electrum_test_vectors = json.load(file_)

    lang = "en"
    for mnemonic, passphrase, rmxprv, rmxpub, address in electrum_test_vectors:
        if mnemonic != "":
            assert rmxprv == electrum.mxprv_from_mnemonic(mnemonic, passphrase)

            eversion, mnemonic = electrum.version_from_mnemonic(mnemonic)
            entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
            mnem = electrum.mnemonic_from_entropy(entr, eversion, lang)
            assert mnem == mnemonic

        assert rmxpub == bip32.xpub_from_xprv(rmxprv)

        xprv = bip32.derive(rmxprv, "m/0h/0")
        assert address == slip132.address_from_xkey(xprv)
