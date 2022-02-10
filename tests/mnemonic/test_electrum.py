#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.electrum` module."

import json
import secrets
from os import path

import pytest

from btclib.bip32 import bip32, slip132
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, electrum
from btclib.network import NETWORKS


def test_mnemonic() -> None:
    lang = "en"

    entropy = 0x110AAAA03974D093EDA670121023CD0772
    mnemonic_type = "standard"
    # FIXME: is the following mnemonic obtained in Electrum
    # from the above entropy?
    mnemonic = "ability awful fetch liberty company spatial panda hat then canal ball crouch bunker"
    mnemonic2 = electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)
    assert mnemonic == mnemonic2

    entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
    assert entr - entropy < 0xFFF

    xprv = "xprv9s21ZrQH143K2tn5j4pmrLXkS6dkbuX6mFhJfCxAwN6ofRo5ddCrLRWogKEs1AptPmLgrthKxU2csfBgkoKECWtj1XMRicRsoWawukaRQft"
    xprv2 = electrum.mxprv_from_mnemonic(mnemonic)
    assert xprv2 == xprv

    mnemonic_type = "std"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)

    unkn_ver = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.entropy_from_mnemonic(unkn_ver, lang)

    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mxprv_from_mnemonic(unkn_ver)

    for mnemonic_type in ("2fa", "2fa_segwit"):
        mnemonic = electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)
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
    with open(filename, "r", encoding="ascii") as file_:
        electrum_test_vectors = json.load(file_)

    lang = "en"
    for mnemonic, passphrase, rmxprv, rmxpub, address in electrum_test_vectors:
        if mnemonic != "":
            assert rmxprv == electrum.mxprv_from_mnemonic(mnemonic, passphrase)

            mnemonic_type, mnemonic = electrum.version_from_mnemonic(mnemonic)
            entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
            mnem = electrum.mnemonic_from_entropy(mnemonic_type, entr, lang)
            assert mnem == mnemonic

        assert rmxpub == bip32.xpub_from_xprv(rmxprv)

        xprv = bip32.derive(rmxprv, "m/0h/0")
        assert address == slip132.address_from_xkey(xprv)


def test_mnemonic_from_entropy() -> None:
    # zero leading bit should not throw an error
    electrum.mnemonic_from_entropy("standard", secrets.randbits(127), "en")
    # random mnemonic
    electrum.mnemonic_from_entropy()


def test_p2wpkh_p2sh() -> None:
    "Test generation of a p2wpkh-p2sh wallet."

    # https://bitcoinelectrum.com/creating-a-p2sh-segwit-wallet-with-electrum/
    # https://www.youtube.com/watch?v=-1DBJWwA2Cw

    p2wpkh_p2sh_xkey_version = NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv
    mnemonics = [
        "matrix fitness cook logic peace mercy dinosaur sign measure rescue alert turtle",
        "chief popular furnace myth decline subject actual toddler plunge rug mixed unlock",
    ]
    versions = ["segwit", "standard"]
    addresses = [
        "38Ysa2TRwGAGLEE1pgV2HCX7MAw6XsP6BJ",
        "3A5u2RTjs3t33Kyc48zHA7Dfsr8Zsfwkoo",
    ]
    for mnemonic, version, p2wpkh_p2sh_address in zip(mnemonics, versions, addresses):
        # this is an electrum mnemonic
        assert electrum.version_from_mnemonic(mnemonic)[0] == version
        # of course, it is invalid as BIP39 mnemonic
        with pytest.raises(BTClibValueError, match="invalid checksum: "):
            bip39.mxprv_from_mnemonic(mnemonic, "")
        # nonetheless, let's use it as BIP39 mnemonic
        rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "", verify_checksum=False)
        # and force the xkey version to p2wpkh_p2sh
        mxprv = bip32.derive(rootxprv, "m/49h/0h/0h", p2wpkh_p2sh_xkey_version)
        mxpub = bip32.xpub_from_xprv(mxprv)
        # finally, verify the first receiving address
        xpub = bip32.derive_from_account(mxpub, 0, 0)
        assert p2wpkh_p2sh_address == slip132.address_from_xkey(xpub)
