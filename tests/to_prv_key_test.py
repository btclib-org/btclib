# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.to_prv_key` module."""

# Third party imports
import pytest

# Library imports
from btclib.alias import INF
from btclib.b58 import wif_from_prv_key
from btclib.base58 import encode as b58encode
from btclib.bip32 import BIP32KeyData
from btclib.bip32.bip32 import rootxprv_from_seed
from btclib.curves.curve import CURVES
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    InvalidPrvKeyError,
    NotAPrvKeyError,
)
from btclib.to_prv_key import (
    _prv_keyinfo_from_wif,
    _prv_keyinfo_from_xprvwif,
    int_from_prv_key,
    prv_keyinfo_from_prv_key,
)
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
    """Check every private-key form against network and compression."""
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
        assert prv_keyinfo_from_prv_key(prv_key4) in {m_c, m_unc}
        assert prv_keyinfo_from_prv_key(prv_key4, "mainnet") in {m_c, m_unc}
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

    # network mismatch on a valid WIF
    with pytest.raises(BTClibValueError, match="not a testnet wif: ") as excinfo:
        _prv_keyinfo_from_wif(wif_compressed_string, "testnet", None)
    assert wif_compressed_string not in str(excinfo.value)

    # out-of-range scalar
    with pytest.raises(BTClibValueError, match="not in 1..n-1") as excinfo:
        int_from_prv_key(qn)
    assert f"{qn:x}" not in str(excinfo.value).lower()

    # unparsable octets
    with pytest.raises(BTClibValueError, match="not a private key") as excinfo:
        int_from_prv_key("02" * 33)
    assert "0202" not in str(excinfo.value)


def test_a_mistyped_wif_is_reported_as_one() -> None:
    """The headline case: one wrong character in a WIF.

    The checksum failure must not be swallowed -- the string retried as
    a hex-string, and the caller told "not a private key", which is true
    and useless. Every reason travels with the exception.
    """
    good = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    assert prv_keyinfo_from_prv_key(good)[1] == "mainnet"

    mistyped = f"{good[:-1]}8"
    for func in (int_from_prv_key, prv_keyinfo_from_prv_key):
        with pytest.raises(NotAPrvKeyError, match="not a private key") as exc_info:
            func(mistyped)
        message = str(exc_info.value)
        assert "invalid checksum" in message
        assert "not a WIF" in message
        assert "not a BIP32 xkey" in message
        assert "not octets" in message
        # never the input itself, which is candidate key material
        assert mistyped not in message


def test_a_recognised_format_stops_the_guessing() -> None:
    """InvalidPrvKeyError propagates; NotAPrvKeyError moves on.

    Which is the whole of the split. A WIF whose prefix and checksum are
    right is a WIF: what is wrong with it is worth more than the news that
    it is not a hex-string either.
    """
    # 0x80, right checksum, right size, trailing byte 0x00 instead of 0x01
    payload = b"\x80" + 32 * b"\x02" + b"\x00"
    with pytest.raises(InvalidPrvKeyError, match="missing trailing 0x01") as info:
        prv_keyinfo_from_prv_key(b58encode(payload))
    # the reason, not an accumulation: the guessing stopped
    assert "not octets" not in str(info.value)
    assert "not a BIP32 xkey" not in str(info.value)

    # an xpub is an xkey, so "not a private key" is the answer and not a
    # step on the way to one
    xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    with pytest.raises(InvalidPrvKeyError, match="not a private key: prefix 0x03"):
        prv_keyinfo_from_prv_key(xpub)

    # both are BTClibValueError, so code catching that is unaffected
    for bad in (b58encode(payload), xpub):
        with pytest.raises(BTClibValueError):
            prv_keyinfo_from_prv_key(bad)


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


def test_a_wif_on_a_network_sharing_its_prefix() -> None:
    """A signet WIF declared as signet is accepted (issue #207).

    A name comparison against the reverse lookup cannot do it: the lookup
    answers "testnet" for the 0xef prefix the four test networks share,
    so a signet WIF asked for as signet would be refused as "not a signet
    wif: prefix 0xef" -- naming the very prefix signet asks for. The
    check is the forward one the xprv path uses, i.e. membership.
    """
    for network in ("testnet", "regtest", "signet", "testnet4"):
        wif = wif_from_prv_key(q, network)
        # the declared network is the one returned, not the lookup's guess
        assert prv_keyinfo_from_prv_key(wif, network) == (q, network, True)
        assert _prv_keyinfo_from_wif(wif, network, None) == (q, network, True)

    # undeclared, the canonical name of the shared prefix is what it is
    assert prv_keyinfo_from_prv_key(wif_from_prv_key(q, "signet")) == (
        q,
        "testnet",
        True,
    )

    # and the check still refuses what it should: mainnet is a different
    # prefix, so it is a different network type
    with pytest.raises(InvalidPrvKeyError, match="not a signet wif: prefix 0x80"):
        prv_keyinfo_from_prv_key(wif_from_prv_key(q, "mainnet"), "signet")
    with pytest.raises(InvalidPrvKeyError, match="not a mainnet wif: prefix 0xef"):
        prv_keyinfo_from_prv_key(wif_from_prv_key(q, "signet"), "mainnet")


def test_the_xprvwif_helper_takes_a_bip32_key_data_too() -> None:
    """`_prv_keyinfo_from_xprvwif` answers for a parsed xprv, not only a str.

    Both public callers dispatch a `BIP32KeyData` to `_prv_keyinfo_from_xprv`
    before they reach this helper, so its `isinstance` guard is never False
    through them and the WIF attempt it skips is what nothing else measures.
    The guard is the helper's own contract rather than a duplicate of theirs:
    a parsed xprv is not a string the WIF decoder could be asked about, and
    handing it to `_prv_keyinfo_from_wif` would be a `NotAPrvKeyError` added
    to the reasons of a key that is in good order.
    """
    xprv = rootxprv_from_seed(b"\x01" * 32)
    data = BIP32KeyData.b58decode(xprv)

    assert _prv_keyinfo_from_xprvwif(data, None, None) == _prv_keyinfo_from_xprvwif(
        xprv, None, None
    )
    assert _prv_keyinfo_from_xprvwif(data, "mainnet", None)[1] == "mainnet"
