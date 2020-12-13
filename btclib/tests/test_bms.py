#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.bms` module."

import json
from hashlib import sha256 as hf
from os import path

import pytest

from btclib import base58_address, bech32_address, bip32, bms, dsa
from btclib.base58_address import p2pkh, p2wpkh_p2sh
from btclib.base58_wif import wif_from_prv_key
from btclib.bech32_address import p2wpkh
from btclib.curve import CURVES, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.to_prv_key import prv_keyinfo_from_prv_key

ec = secp256k1


def test_signature() -> None:
    msg = "test message"

    wif, addr = bms.gen_keys()
    sig = bms.sign(msg, wif)
    bms.assert_as_valid(msg, addr, sig)
    assert bms.verify(msg, addr, sig)
    assert sig == bms.Sig.deserialize(sig.serialize())
    assert sig == bms.Sig.deserialize(sig.serialize().hex())
    assert sig == bms.Sig.b64decode(sig.b64encode())
    assert sig == bms.Sig.b64decode(sig.b64encode().encode("ascii"))

    assert sig == bms.sign(msg, wif.encode("ascii"))

    # sig taken from (Electrum and) Bitcoin Core
    wif, addr = bms.gen_keys("5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw")
    sig = bms.sign(msg, wif)
    bms.assert_as_valid(msg, addr, sig)
    assert bms.verify(msg, addr, sig)
    exp_sig = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert sig.b64encode() == exp_sig

    bms.assert_as_valid(msg, addr, exp_sig)
    bms.assert_as_valid(msg, addr, exp_sig.encode("ascii"))

    dsa_sig = dsa.Sig(sig.dsa_sig.r, sig.dsa_sig.s, CURVES["secp256r1"])
    err_msg = "invalid curve: "
    with pytest.raises(BTClibValueError, match=err_msg):
        sig = bms.Sig(sig.rf, dsa_sig)


def test_exceptions() -> None:

    msg = "test"
    wif = "KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu"
    address = base58_address.p2pkh(wif)
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
    bms.assert_as_valid(msg, address, exp_sig)

    bms_sig = bms.Sig.b64decode(exp_sig)
    err_msg = "invalid recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.Sig(26, bms_sig.dsa_sig)

    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLoVc="
    err_msg = "invalid decoded length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, address, exp_sig)
    assert not bms.verify(msg, address, exp_sig)

    exp_sig = "GpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQgBR4PpI+w2tJdD4v+hxElvAaUSqv2eU="
    err_msg = "invalid recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, address, exp_sig)
    assert not bms.verify(msg, address, exp_sig)
    exp_sig = "QpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQgBR4PpI+w2tJdD4v+hxElvAaUSqv2eU="
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, address, exp_sig)
    assert not bms.verify(msg, address, exp_sig)

    # compressed wif, uncompressed address
    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    address = "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T"
    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, address)

    # uncompressed wif, compressed address
    wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
    err_msg = "not a private or compressed public key for mainnet: "
    # FIXME puzzling error message
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, address)

    msg = "test"
    wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
    b58_p2pkh = base58_address.p2pkh(wif)
    b58_p2wpkh = bech32_address.p2wpkh(wif)
    b58_p2wpkh_p2sh = base58_address.p2wpkh_p2sh(wif)

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, b58_p2pkh)
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, b58_p2wpkh)
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, b58_p2wpkh_p2sh)

    # Invalid recovery flag (39) for base58 address
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
    bms_sig = bms.Sig.b64decode(exp_sig)
    bms_sig = bms.Sig(39, bms_sig.dsa_sig, check_validity=False)
    sig_encoded = bms_sig.b64encode(check_validity=False)
    err_msg = "invalid recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2pkh, sig_encoded)

    # Invalid recovery flag (35) for bech32 address
    exp_sig = "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    bms_sig = bms.Sig.b64decode(exp_sig)
    bms_sig = bms.Sig(35, bms_sig.dsa_sig, check_validity=False)
    err_msg = "invalid recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2wpkh, bms_sig)


@pytest.mark.sixth
def test_one_prv_key_multiple_addresses() -> None:

    msg = "Paolo is afraid of ephemeral random numbers"

    # Compressed WIF
    wif = "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
    addr_p2pkh_compressed = p2pkh(wif)
    addr_p2wpkh_p2sh = p2wpkh_p2sh(wif)
    addr_p2wpkh = p2wpkh(wif)

    # sign with no address
    sig1 = bms.sign(msg, wif)
    # True for Bitcoin Core
    bms.assert_as_valid(msg, addr_p2pkh_compressed, sig1)
    assert bms.verify(msg, addr_p2pkh_compressed, sig1)
    # True for Electrum p2wpkh_p2sh
    bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig1)
    assert bms.verify(msg, addr_p2wpkh_p2sh, sig1)
    # True for Electrum p2wpkh
    bms.assert_as_valid(msg, addr_p2wpkh, sig1)
    assert bms.verify(msg, addr_p2wpkh, sig1)

    # sign with p2pkh address
    sig1 = bms.sign(msg, wif, addr_p2pkh_compressed)
    # True for Bitcoin Core
    bms.assert_as_valid(msg, addr_p2pkh_compressed, sig1)
    assert bms.verify(msg, addr_p2pkh_compressed, sig1)
    # True for Electrum p2wpkh_p2sh
    bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig1)
    assert bms.verify(msg, addr_p2wpkh_p2sh, sig1)
    # True for Electrum p2wpkh
    bms.assert_as_valid(msg, addr_p2wpkh, sig1)
    assert bms.verify(msg, addr_p2wpkh, sig1)
    assert sig1 == bms.sign(msg, wif, addr_p2pkh_compressed.encode("ascii"))

    err_msg = "invalid recovery flag: "

    # sign with p2wpkh_p2sh address (BIP137)
    sig2 = bms.sign(msg, wif, addr_p2wpkh_p2sh)
    # False for Bitcoin Core
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr_p2pkh_compressed, sig2)
    assert not bms.verify(msg, addr_p2pkh_compressed, sig2)
    # True for BIP137 p2wpkh_p2sh
    bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig2)
    assert bms.verify(msg, addr_p2wpkh_p2sh, sig2)
    # False for BIP137 p2wpkh
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr_p2wpkh, sig2)
    assert not bms.verify(msg, addr_p2wpkh, sig2)
    assert sig2 == bms.sign(msg, wif, addr_p2wpkh_p2sh.encode("ascii"))

    # sign with p2wpkh address (BIP137)
    sig3 = bms.sign(msg, wif, addr_p2wpkh)
    # False for Bitcoin Core
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr_p2pkh_compressed, sig3)
    assert not bms.verify(msg, addr_p2pkh_compressed, sig3)
    # False for BIP137 p2wpkh_p2sh
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig3)
    assert not bms.verify(msg, addr_p2wpkh_p2sh, sig3)
    # True for BIP137 p2wpkh
    bms.assert_as_valid(msg, addr_p2wpkh, sig3)
    assert bms.verify(msg, addr_p2wpkh, sig3)
    assert sig3 == bms.sign(msg, wif, addr_p2wpkh.encode("ascii"))

    # uncompressed WIF / p2pkh address
    q, network, _ = prv_keyinfo_from_prv_key(wif)
    wif2 = wif_from_prv_key(q, network, False)
    addr_p2pkh_uncompressed = p2pkh(wif2)

    # sign with uncompressed p2pkh
    sig4 = bms.sign(msg, wif2, addr_p2pkh_uncompressed)
    # False for Bitcoin Core compressed p2pkh
    with pytest.raises(BTClibValueError, match="wrong p2pkh address: "):
        bms.assert_as_valid(msg, addr_p2pkh_compressed, sig4)
    assert not bms.verify(msg, addr_p2pkh_compressed, sig4)
    # False for BIP137 p2wpkh_p2sh
    # FIXME: puzzling error message
    # it should have been "wrong p2wpkh-p2sh address: "
    with pytest.raises(BTClibValueError, match="wrong p2pkh address: "):
        bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig4)
    assert not bms.verify(msg, addr_p2wpkh_p2sh, sig4)
    # False for BIP137 p2wpkh
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr_p2wpkh, sig4)
    assert not bms.verify(msg, addr_p2wpkh, sig4)
    # True for Bitcoin Core uncompressed p2pkh
    bms.assert_as_valid(msg, addr_p2pkh_uncompressed, sig4)
    assert bms.verify(msg, addr_p2pkh_uncompressed, sig4)
    assert sig4 == bms.sign(msg, wif2, addr_p2pkh_uncompressed.encode("ascii"))

    # unrelated different wif
    wif3 = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    addr_p2pkh_compressed = p2pkh(wif3)
    addr_p2wpkh_p2sh = p2wpkh_p2sh(wif3)
    addr_p2wpkh = p2wpkh(wif3)

    # False for Bitcoin Core compressed p2pkh
    with pytest.raises(BTClibValueError, match="wrong p2pkh address: "):
        bms.assert_as_valid(msg, addr_p2pkh_compressed, sig1)
    assert not bms.verify(msg, addr_p2pkh_compressed, sig1)
    # False for BIP137 p2wpkh_p2sh
    with pytest.raises(BTClibValueError, match="wrong p2wpkh-p2sh address: "):
        bms.assert_as_valid(msg, addr_p2wpkh_p2sh, sig1)
    assert not bms.verify(msg, addr_p2wpkh_p2sh, sig1)
    # False for BIP137 p2wpkh
    with pytest.raises(BTClibValueError, match="wrong p2wpkh address: "):
        bms.assert_as_valid(msg, addr_p2wpkh, sig1)
    assert not bms.verify(msg, addr_p2wpkh, sig1)

    # FIXME: puzzling error message
    err_msg = "not a private or compressed public key for mainnet: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif2, addr_p2pkh_compressed)

    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, wif, addr_p2pkh_uncompressed)


def test_msgsign_p2pkh() -> None:
    msg = "test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    q = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

    # uncompressed
    wif1u = wif_from_prv_key(q, "mainnet", False)
    assert wif1u == "5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw"
    add1u = base58_address.p2pkh(wif1u)
    assert add1u == "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    sig1u = bms.sign(msg, wif1u)
    assert bms.verify(msg, add1u, sig1u)
    assert sig1u.rf == 27
    exp_sig1u = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert sig1u.b64encode() == exp_sig1u

    # compressed
    wif1c = wif_from_prv_key(q, "mainnet", True)
    assert wif1c == "L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk"
    add1c = base58_address.p2pkh(wif1c)
    assert add1c == "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    sig1c = bms.sign(msg, wif1c)
    assert bms.verify(msg, add1c, sig1c)
    assert sig1c.rf == 31
    exp_sig1c = "H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert sig1c.b64encode() == exp_sig1c

    assert not bms.verify(msg, add1c, sig1u)
    assert not bms.verify(msg, add1u, sig1c)

    bms_sig = bms.Sig(sig1c.rf + 1, sig1c.dsa_sig)
    assert not bms.verify(msg, add1c, bms_sig)

    # malleate s
    dsa_sig = dsa.Sig(sig1c.dsa_sig.r, ec.n - sig1c.dsa_sig.s, sig1c.dsa_sig.ec)
    bms_sig = bms.Sig(sig1c.rf, dsa_sig)
    assert not bms.verify(msg, add1c, bms_sig)

    # update rf to satisfy above malleation
    bms_sig = bms.Sig(sig1c.rf + 1, dsa_sig)
    assert bms.verify(msg, add1c, bms_sig)


def test_msgsign_p2pkh_2() -> None:
    msg = "test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    # compressed
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
    exp_sig = "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif, address)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig
    sig = bms.sign(msg.encode(), wif)
    assert bms.verify(msg.encode(), address, sig)
    assert sig.b64encode() == exp_sig

    wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
    # uncompressed
    address = "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T"
    exp_sig = "HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif, address)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig
    sig = bms.sign(msg.encode(), wif)
    assert bms.verify(msg.encode(), address, sig)
    assert sig.b64encode() == exp_sig


def test_verify_p2pkh() -> None:
    msg = "Hello, world!"
    address = "1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG"
    exp_sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = "test message"
    address = "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    exp_sig = "IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = "test message"
    address = "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    exp_sig = "G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_signmessage.py
    msg = address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
    exp_sig = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
    msg = "test message"
    address = "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce"
    exp_sig = "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50="
    assert bms.verify(msg, address, exp_sig)

    msg = "test message 2"
    assert not bms.verify(msg, address, exp_sig)

    msg = (
        "freenode:#bitcoin-otc:b42f7e7ea336db4109df6badc05c6b3ea8bfaa13575b51631c5178a7"
    )
    address = "1GdKjTSg2eMyeVvPV5Nivo6kR8yP2GT7wF"
    exp_sig = "GyMn9AdYeZIPWLVCiAblOOG18Qqy4fFaqjg5rjH6QT5tNiUXLS6T2o7iuWkV1gc4DbEWvyi8yJ8FvSkmEs3voWE="
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "1Hpj6xv9AzaaXjPPisQrdAD2tu84cnPv3f"
    exp_sig = "INEJxQnSu6mwGnLs0E8eirl5g+0cAC9D5M7hALHD9sK0XQ66CH9mas06gNoIX7K1NKTLaj3MzVe8z3pt6apGJ34="
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX"
    exp_sig = "IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc="
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv"
    exp_sig = "H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As="
    assert bms.verify(msg, address, exp_sig)

    # leading space
    exp_sig = " H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As="
    assert bms.verify(msg, address, exp_sig)

    # trailing space
    exp_sig = "H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= "
    assert bms.verify(msg, address, exp_sig)

    # leading and trailing spaces
    exp_sig = " H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= "
    assert bms.verify(msg, address, exp_sig)


def test_segwit() -> None:

    msg = "test"
    wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
    b58_p2pkh = base58_address.p2pkh(wif)
    b58_p2wpkh = bech32_address.p2wpkh(wif)
    b58_p2wpkh_p2sh = base58_address.p2wpkh_p2sh(wif)

    # p2pkh base58 address (Core, Electrum, BIP137)
    exp_sig = "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b58_p2pkh, exp_sig)
    sig = bms.sign(msg, wif)  # no address: p2pkh assumed
    assert bms.verify(msg, b58_p2pkh, sig)
    assert sig.b64encode() == exp_sig

    # p2wpkh-p2sh base58 address (Electrum)
    assert bms.verify(msg, b58_p2wpkh_p2sh, sig)

    # p2wpkh bech32 address (Electrum)
    assert bms.verify(msg, b58_p2wpkh, sig)

    # p2wpkh-p2sh base58 address (BIP137)
    # different first letter in sig because of different rf
    exp_sig = "JBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b58_p2wpkh_p2sh, exp_sig)
    sig = bms.sign(msg, wif, b58_p2wpkh_p2sh)
    assert bms.verify(msg, b58_p2wpkh_p2sh, sig)
    assert sig.b64encode() == exp_sig

    # p2wpkh bech32 address (BIP137)
    # different first letter in sig because of different rf
    exp_sig = "KBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b58_p2wpkh, exp_sig)
    sig = bms.sign(msg, wif, b58_p2wpkh)
    assert bms.verify(msg, b58_p2wpkh, sig)
    assert sig.b64encode() == exp_sig


def test_sign_strippable_message() -> None:

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"

    msg = ""
    exp_sig = "IFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " "
    exp_sig = "IEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = "  "
    exp_sig = "H/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    msg = "test"
    exp_sig = "IJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " test "
    exp_sig = "IA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = "test "
    exp_sig = "IPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " test"
    exp_sig = "H1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo="
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert sig.b64encode() == exp_sig


def test_vector_python_bitcoinlib() -> None:
    """Test python-bitcoinlib test vectors

    https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_data/bms.json
    """

    fname = "bms.json"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "r") as file_:
        test_vectors = json.load(file_)

    for vector in test_vectors[:5]:
        msg = vector["address"]
        bsm_sig = bms.sign(msg, vector["wif"])
        assert bms.verify(msg, vector["address"], bsm_sig)
        bsm_sig_encoded = bsm_sig.b64encode()
        assert bms.verify(msg, vector["address"], bsm_sig_encoded)
        assert bms.verify(msg, vector["address"], vector["signature"])

        # python-bitcoinlib has a signature different from the
        # one generated by Core/Electrum/btclib (which are identical)
        assert bsm_sig_encoded != vector["signature"]

        # python-bitcoinlib does not use RFC6979 deterministic nonce
        # as proved by different r compared to Core/Electrum/btclib
        test_vector_sig = bms.Sig.b64decode(vector["signature"])
        assert bsm_sig.dsa_sig.r != test_vector_sig.dsa_sig.r

        # while Core/Electrum/btclib use "low-s" canonical signature
        assert bsm_sig.dsa_sig.s < ec.n - bsm_sig.dsa_sig.s
        # this is not true for python-bitcoinlib
        # assert test_vector_sig.dsa_sig.s < ec.n - test_vector_sig.dsa_sig.s
        # self.assertGreater(test_vector_sig.dsa_sig.s, ec.n - test_vector_sig.dsa_sig.s)

        # just in case you wonder, here's the malleated signature
        dsa_sig = dsa.Sig(
            bsm_sig.dsa_sig.r, ec.n - bsm_sig.dsa_sig.s, bsm_sig.dsa_sig.ec
        )
        bms_sig_malleated = bms.Sig(
            bsm_sig.rf + (1 if bsm_sig.rf == 31 else -1), dsa_sig
        )
        assert bms.verify(msg, vector["address"], bms_sig_malleated)
        bsm_sig_encoded = bms_sig_malleated.b64encode()
        assert bms.verify(msg, vector["address"], bsm_sig_encoded)
        # of course,
        # it is not equal to the python-bitcoinlib one (different r)
        assert bsm_sig_encoded != vector["signature"]


def test_ledger() -> None:
    """Hybrid ECDSA Bitcoin message signature generated by Ledger"""

    mnemonic = (
        "barely sun snack this snack relief pipe attack disease boss enlist lawsuit"
    )

    # non-standard leading 31 in DER serialization
    derivation_path = "m/1"
    msg = b"\xfb\xa3\x1f\x8cd\x85\xe29#K\xb3{\xfd\xa7<?\x95oL\xee\x19\xb2'oh\xa7]\xd9A\xfeU\xd8"
    dersig_hex_str = "3144022012ec0c174936c2a46dc657252340b2e6e6dd8c31dd059b6f9f33a90c21af2fba022030e6305b3ccf88009d419bf7651afcfcc0a30898b93ae9de9aa6ac03cf8ec56b"

    # pub_key derivation
    rprv = bip32.mxprv_from_bip39_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)

    # the actual message being signed
    magic_msg = bms._magic_message(msg)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig_hex_str)
    key_id = dersig[0]
    dsa_sig = dsa.Sig.deserialize(b"\x30" + dersig[1:])

    # ECDSA signature verification of the patched dersig
    dsa.assert_as_valid(magic_msg, xprv, dsa_sig, hf)
    assert dsa.verify(magic_msg, xprv, dsa_sig)

    # compressed address
    addr = base58_address.p2pkh(xprv)

    # equivalent Bitcoin Message Signature
    rec_flag = 27 + 4 + (key_id & 0x01)
    bms_sig = bms.Sig(rec_flag, dsa_sig)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg, addr, bms_sig)
    assert bms.verify(msg, addr, bms_sig)
    assert not bms.verify(magic_msg, addr, bms_sig)

    bms.sign(msg, xprv)

    # standard leading 30 in DER serialization
    derivation_path = "m/0/0"
    msg_str = "hello world"
    dersig_hex_str = "3045022100967dac3262b4686e89638c8219c5761017f05cd87a855edf034f4a3ec6b59d3d0220108a4ef9682b71a45979d8c75c393382d9ccb8eb561d73b8c5fc0b87a47e7d27"

    # pub_key derivation
    rprv = bip32.mxprv_from_bip39_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)

    # the actual message being signed
    magic_msg = bms._magic_message(msg_str)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig_hex_str)
    key_id = dersig[0]
    dsa_sig = dsa.Sig.deserialize(b"\x30" + dersig[1:])

    # ECDSA signature verification of the patched dersig
    dsa.assert_as_valid(magic_msg, xprv, dsa_sig, hf)
    assert dsa.verify(magic_msg, xprv, dsa_sig)

    # compressed address
    addr = base58_address.p2pkh(xprv)

    # equivalent Bitcoin Message Signature
    rec_flag = 27 + 4 + (key_id & 0x01)
    bms_sig = bms.Sig(rec_flag, dsa_sig)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg_str, addr, bms_sig)
    assert bms.verify(msg_str, addr, bms_sig)
    assert not bms.verify(magic_msg, addr, bms_sig)
