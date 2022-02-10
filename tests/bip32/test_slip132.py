#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.slip132` module."

from typing import List, Tuple

import pytest

from btclib import b32, b58
from btclib.bip32 import bip32, slip132
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39
from btclib.network import NETWORKS


def test_slip132() -> None:
    mnemonic = "enough regret erode news field main wild jar erupt bronze velvet ugly"
    mxprv = bip39.mxprv_from_mnemonic(mnemonic)

    xprv = slip132.p2pkh_xkey(mxprv)
    assert (
        xprv
        == "xprv9y7Yxxyy7wn5ktGVzAmgatW1vu7daX4V8ddWMcSbKJyK6TzkBbZDimAMCLoogpf4GEp2ThmBZ476vwe7xVC9sPsNfJcyu5isQixgF95HS31"
    )
    with pytest.raises(BTClibValueError, match="not a public key: "):
        slip132.address_from_xpub(xprv)
    xpub = bip32.xpub_from_xprv(xprv)
    assert (
        xpub
        == "xpub6C6uNUWrxKLNyNLy6CJgx2SkUvx7yynLVrZ79zrCseWHyGKtj8sUGZUq3dw9fqJGETSEeX1iztXAfRvxh6Gk2m7yVjDCx5cbRP2So559Hb5"
    )
    address = slip132.address_from_xpub(xpub)
    assert slip132.address_from_xkey(xprv) == address
    assert address == "1DjfiAgNyvRXhYXiDgE9K7bfB82hVUPTm1"
    with pytest.raises(BTClibValueError, match="not a root key: "):
        slip132.p2pkh_xkey(xprv)

    yprv = slip132.p2wpkh_p2sh_xkey(mxprv)
    assert (
        yprv
        == "yprvAJstKLzg5g8RzxfPiX4UT5vH6y5FJkK2yVNkxrzG92WagSCu2PnAxT34JPGCT9Wh5LJCXZi1wB7fd6FUA9veMf2kig7A6cTxD4GMjSbcrqv"
    )
    with pytest.raises(BTClibValueError, match="not a public key: "):
        slip132.address_from_xpub(yprv)
    ypub = bip32.xpub_from_xprv(yprv)
    assert (
        ypub
        == "ypub6XsEirXZv3gjDSjrpYbUpDs1ezujiD2tLiJMmFPshN3ZZEY3Zw6RWFMY9grBtrN88Qan7FAVmtPQnLfuepRy7ZVDNQkkDTMGzYoCJpQdwt4"
    )
    address = slip132.address_from_xpub(ypub)
    assert slip132.address_from_xkey(yprv) == address
    assert address == "3QnhAKhuuwSf2bEFKpgvDKUHNe3rpZr6PG"
    with pytest.raises(BTClibValueError, match="not a root key: "):
        slip132.p2wpkh_p2sh_xkey(xprv)

    zprv = slip132.p2wpkh_xkey(mxprv)
    assert (
        zprv
        == "zprvAceWp8rDBfL7EJ4Mz5p76v6ZmFQ3UyftmmHqfdUidHoTPoFwjApHYCXPhdWNsxLv6ozzauk8LQXNjNn2CcxLaLzezH7QTQ3rk9tn8GmzaXT"
    )
    with pytest.raises(BTClibValueError, match="not a public key: "):
        slip132.address_from_xpub(zprv)
    zpub = bip32.xpub_from_xprv(zprv)
    assert (
        zpub
        == "zpub6qdsDeP722tQSn8q67M7U43JKHEXtSPk8zDSU1tLBdLSGbb6Gi8Y5zqsYuYPhxprjsxc4ZdqvjC86iuv1SXmmvCkJgZJmoCPbDZdHwUaKbX"
    )
    address = slip132.address_from_xpub(zpub)
    assert slip132.address_from_xkey(zprv) == address
    assert address == "bc1qcne7y6yae0lz3kceg80aunmafu0rwm3uzmf7v6"
    with pytest.raises(BTClibValueError, match="not a root key: "):
        slip132.p2wpkh_xkey(xprv)


def test_slip132_test_vectors() -> None:
    """SLIP132 test vector

    https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    """
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    kpath = "m/0/0"
    test_vectors: List[Tuple[bytes, str, str, str, str]] = [
        (
            NETWORKS["mainnet"].bip32_prv,
            "m / 44h / 0h / 0h",
            "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
            "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        ),
        (
            NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv,
            "m / 49h / 0h / 0h",
            "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF",
            "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        ),
        (
            NETWORKS["mainnet"].slip132_p2wpkh_prv,
            "m / 84h / 0h / 0h",
            "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
    ]
    for version, der_path, prv, pub, addr in test_vectors:
        rxprv = bip39.mxprv_from_mnemonic(mnemonic, "")
        mxprv = bip32.derive(rxprv, der_path, version)
        assert prv == mxprv
        mxpub = bip32.xpub_from_xprv(mxprv)
        assert pub == mxpub
        xpub = bip32.derive(mxpub, kpath)
        address = slip132.address_from_xpub(xpub)
        assert addr == address
        address = slip132.address_from_xkey(xpub)
        assert addr == address
        xprv = bip32.derive(mxprv, kpath)
        address = slip132.address_from_xkey(xprv)
        assert addr == address
        if version == NETWORKS["mainnet"].bip32_prv:
            address = b58.p2pkh(xpub)
            assert addr == address
            address = b58.p2pkh(xprv)
            assert addr == address
        elif version == NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv:
            address = b58.p2wpkh_p2sh(xpub)
            assert addr == address
            address = b58.p2wpkh_p2sh(xprv)
            assert addr == address
        elif version == NETWORKS["mainnet"].slip132_p2wpkh_prv:
            address = b32.p2wpkh(xpub)
            assert addr == address
            address = b32.p2wpkh(xprv)
            assert addr == address


def test_addresses() -> None:

    # data cross-checked with Electrum and
    # https://jlopp.github.io/xpub-converter/

    # 128 bits
    raw_entr = bytes.fromhex("6" * 32)
    # 12 words
    mnemonic = bip39.mnemonic_from_entropy(raw_entr, "en")

    # m / purpose h / coin_type h / account h / change / address_index
    test_vectors: List[Tuple[str, str, str]] = [
        # coin_type = 0 -> mainnet
        (
            "m/44h/0h/0h",
            "bip32_prv",  # p2pkh or p2sh
            "xpub6C3uWu5Go5q62JzJpbjyCLYRGLYvexFeiepZTsYZ6SRexARkNfjG7GKtQVuGR3KHsyKsAwv7Hz3iNucPp6pfHiLvBczyK1j5CtBtpHB3NKx",
        ),
        (
            "m/49h/0h/0h",
            "slip132_p2wpkh_p2sh_prv",  # p2wpkh-p2sh (i.e., p2sh-wrapped p2wpkh)
            "ypub6YBGdYufCVeoPVmNXfdrWhaBCXsQoLKNetNmD9bPTrKmnKVmiyU8f1uJqwGdmBb8kbAZpHoYfXQTLbWpkXc4skQDAreeCUXdbX9k8vtiHsN",
        ),
        (
            "m/49h/0h/0h",
            "slip132_p2wsh_p2sh_prv",  # p2wsh-p2sh (i.e., p2sh-wrapped p2wsh)
            "Ypub6j5Mkne6mTDAp4vkUL6qLmuyvKug1gzxyA2S8QrvqdABQW4gVNrQk8mEeeE7Kcp2z4EYgsofYjnxTm8b3km22EWt1Km3bszdVFRcipc6rXu",
        ),
        (
            "m/84h/0h/0h",
            "slip132_p2wpkh_prv",  # p2wpkh
            "zpub6qg3Uc1BAQkQvcBUYMmZHSzbsshSon3FvJ8yvH3ZZMjFNvJkwSji8UUwghiF3wvpvSvcNWVP8kfUhc2V2RwGp6pTC3ouj6njj956f26TniN",
        ),
        (
            "m/84h/0h/0h",
            "slip132_p2wsh_prv",  # p2wsh
            "Zpub72a8bqjcjNJnMBLrV2EY7XLQbfji28irEZneqYK6w8Zf16sfhr7zDbLsVQficP9j9uzbF6VW1y3ypmeFKf6Dxaw82WvK8WFjcsLyEvMNZjF",
        ),
        # coin_type = 1 -> testnet
        (
            "m/44h/1h/0h",
            "bip32_prv",  # p2pkh or p2sh
            "tpubDChqWo2Xi2wNsxyJBE8ipcTJHLKWcqeeNUKBVTpUCNPZkHzHTm3qKAeHqgCou1t8PAY5ZnJ9QDa6zXSZxmjDnhiBpgZ7f6Yv88wEm5HXVbm",
        ),
        (
            "m/49h/1h/0h",
            "slip132_p2wpkh_p2sh_prv",  # p2wpkh-p2sh (i.e., p2sh-wrapped p2wpkh)
            "upub5Dj8j7YrwodV68mt58QmNpSzjqjso2WMXEpLGLSvskKccGuXhCh3dTedkzVLAePA617UyXAg2vdswJXTYjU4qjMJaHU79GJVVJCAiy9ezZ2",
        ),
        (
            "m/49h/1h/0h",
            "slip132_p2wsh_p2sh_prv",  # p2wsh-p2sh (i.e., p2sh-wrapped p2wsh)
            "Upub5QdDrMHJWmBrWhwG1nskCtnoTdn91PBwqWU1BbiUFXA2ETUSTc5KiaWZZhSoj5c4KUBTr7Anv92P4U9Dqxd1zDTyQkaWYfmVP2U3Js1W5cG",
        ),
        (
            "m/84h/1h/0h",
            "slip132_p2wpkh_prv",  # p2wpkh
            "vpub5ZhJmduYY7M5J2qCJgSW7hunX6zJrr5WuNg2kKt321HseZEYxqJc6Zso47aNXQw3Wf3sA8kppbfsxnLheUNXcL3xhzeBHLNp8fTVBN6DnJF",
        ),
        (
            "m/84h/1h/0h",
            "slip132_p2wsh_prv",  # p2wsh
            "Vpub5kbPtsdz74uSibzaFLuUwnFbEu2a5Cm7DeKhfb9aPn8HGjoTjEgtBgjirpXr5r9wk87r2ikwhp4P5wxTwhXUkpAdYTkagjqp2PjMmGPBESU",
        ),
    ]

    for der_path, addr_type, mxpub in test_vectors:
        der_path_elements = der_path.split("/")

        network = "testnet" if der_path_elements[2] == "1h" else "mainnet"
        rootprv = bip39.mxprv_from_mnemonic(mnemonic, "", network)

        version = getattr(NETWORKS[network], addr_type)
        xprv = bip32.derive(rootprv, der_path, version)
        assert mxpub == bip32.xpub_from_xprv(xprv)

        err_msg = "invalid version forced on the extended key"
        # a non-private version cannot be forced on a private key
        pub_version = NETWORKS[network].bip32_pub
        with pytest.raises(BTClibValueError, match=err_msg):
            bip32.derive(rootprv, der_path, pub_version)

        # just changing the public version with no derivation does work
        bip32.derive(mxpub, "m", pub_version)
        with pytest.raises(BTClibValueError, match=err_msg):
            bip32.derive(mxpub, "m", version)
