# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.to_pub_key` module."""

from collections.abc import Callable, Sequence

import pytest

from btclib.alias import INF, Point
from btclib.bip32 import BIP32KeyData, derive, rootxprv_from_seed
from btclib.curves import bytes_from_point
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.to_pub_key import (
    Key,
    PubkeyInfo,
    fingerprint,
    point_from_key,
    point_from_pub_key,
    pub_keyinfo_from_key,
    pub_keyinfo_from_pub_key,
)
from tests.to_key_test import (
    INF_xpub_data,
    Q,
    compressed_prv_keys,
    compressed_pub_keys,
    invalid_prv_keys,
    invalid_pub_keys,
    net_aware_prv_keys,
    net_aware_pub_keys,
    net_unaware_prv_keys,
    net_unaware_pub_keys,
    not_a_pub_keys,
    plain_prv_keys,
    plain_pub_keys,
    q,
    q0,
    qn,
    uncompressed_prv_keys,
    uncompressed_pub_keys,
    xprv0_data,
    xprv_data,
    xprv_string,
    xprvn_data,
    xpub_data,
)

secp256r1 = CURVES["secp256r1"]

# the four answers Q converts to, one per network and compression
m_c = bytes_from_point(Q, compressed=True), "mainnet"
m_unc = bytes_from_point(Q, compressed=False), "mainnet"
t_c = bytes_from_point(Q, compressed=True), "testnet"
t_unc = bytes_from_point(Q, compressed=False), "testnet"

# The two conversions under test, always as a pair: what converts to a
# point converts to pub-key info too, and each check below is a question
# about the key form rather than about which of the two answers it. That
# is what lets one check serve both pairs -- the pub-key-only
# point_from_pub_key/pub_keyinfo_from_pub_key, and point_from_key/
# pub_keyinfo_from_key, which take a private key as well.
#
# The argument types are unchecked (`...`) because no single parameter
# type accepts both pairs: the pub-key pair takes PubKey where the key
# pair takes Key, an int prv key among them, and mypy checks a
# callable's arguments contravariantly, so the wider Key would reject the
# narrower pair.
Conversions = tuple[Callable[..., Point], Callable[..., PubkeyInfo]]


def _check_point(point_from: Callable[..., Point], key: Key) -> None:
    """Q is the point behind the key, and it is a point on secp256k1 alone.

    A public key *is* a point, so a curve that does not hold it has to
    refuse it. An int private key is a scalar instead, and every curve
    has that scalar: secp256r1 answers with the r1 point rather than
    raising, which is why the int forms skip the check.
    """
    assert Q == point_from(key)
    if not isinstance(key, int):
        with pytest.raises(BTClibValueError):
            point_from(key, secp256r1)


def _check_plain(api: Conversions, keys: Sequence[Key]) -> None:
    """Check a form fixing neither network nor compression: four answers.

    Nothing in the form can contradict the request, so every combination
    is answered by re-encoding the point as asked, and the default is
    compressed mainnet.
    """
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert m_c == keyinfo_from(key)
        assert m_c == keyinfo_from(key, "mainnet")
        assert m_c == keyinfo_from(key, "mainnet", compressed=True)
        assert m_c == keyinfo_from(key, compressed=True)
        assert m_unc == keyinfo_from(key, "mainnet", compressed=False)
        assert m_unc == keyinfo_from(key, compressed=False)
        assert t_c == keyinfo_from(key, "testnet")
        assert t_c == keyinfo_from(key, "testnet", compressed=True)
        assert t_unc == keyinfo_from(key, "testnet", compressed=False)


def _check_compressed(api: Conversions, keys: Sequence[Key]) -> None:
    """Check a compressed form: an uncompressed answer is refused.

    An xpub or a compressed WIF carries the compression in the form
    itself, and a request for the other one is a mismatch to report, not
    a re-encoding to perform.
    """
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert m_c == keyinfo_from(key)
        assert m_c == keyinfo_from(key, "mainnet")
        assert m_c == keyinfo_from(key, "mainnet", compressed=True)
        assert m_c == keyinfo_from(key, compressed=True)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, compressed=False)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, "testnet", compressed=False)


def _check_uncompressed(api: Conversions, keys: Sequence[Key]) -> None:
    """Check an uncompressed form: a compressed answer is refused.

    The mirror of _check_compressed, and the default flips with it: an
    uncompressed form asked for no compression in particular answers
    uncompressed.

    Only the compressed half of the testnet request is asked, because it
    is the half both refuse: an uncompressed testnet answer is right for
    a 04-prefixed SEC key, which names no network, and wrong for an
    uncompressed WIF, which names mainnet. Which network each form
    answers for is _check_net_aware and _check_net_unaware.
    """
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert m_unc == keyinfo_from(key)
        assert m_unc == keyinfo_from(key, "mainnet")
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, compressed=True)
        assert m_unc == keyinfo_from(key, "mainnet", compressed=False)
        assert m_unc == keyinfo_from(key, compressed=False)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, "testnet", compressed=True)


def _check_net_aware(api: Conversions, keys: Sequence[Key]) -> None:
    """Check a form naming mainnet: testnet is refused.

    Whether the answer is compressed depends on the form, which is what
    _check_compressed and _check_uncompressed pin down; here either one
    will do.
    """
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert keyinfo_from(key) in (m_c, m_unc)
        assert keyinfo_from(key, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key, "testnet")


def _check_net_unaware(api: Conversions, keys: Sequence[Key]) -> None:
    """Check a form naming no network: both answered, mainnet by default."""
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert keyinfo_from(key) in (m_c, m_unc)
        assert keyinfo_from(key, "mainnet") in (m_c, m_unc)
        assert keyinfo_from(key, "testnet") in (t_c, t_unc)


def _check_refused(api: Conversions, keys: Sequence[Key]) -> None:
    """Neither conversion has an answer for these.

    Each test asks it twice, of what is an invalid key and of what is no
    key at all, and the second list contains the first: not_a_pub_keys is
    the invalid private keys and the invalid public ones together. The
    assertion is the same one either way, every refusal here being a
    BTClibValueError, so the two calls name the two vocabularies rather
    than expect two answers.
    """
    point_from, keyinfo_from = api
    for key in keys:
        with pytest.raises(BTClibValueError):
            point_from(key)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key)


def test_from_pub_key() -> None:
    """Every public-key form, crossed with network and compression."""
    api: Conversions = point_from_pub_key, pub_keyinfo_from_pub_key
    _check_plain(api, [Q, *plain_pub_keys])
    _check_compressed(api, [xpub_data, *compressed_pub_keys])
    _check_uncompressed(api, uncompressed_pub_keys)
    _check_net_aware(api, [xpub_data, *net_aware_pub_keys])
    _check_net_unaware(api, net_unaware_pub_keys)
    _check_refused(api, [INF, INF_xpub_data, *invalid_pub_keys])
    _check_refused(
        api,
        [
            INF,
            INF_xpub_data,
            *not_a_pub_keys,
            q,
            q0,
            qn,
            *plain_prv_keys,
            xprv_data,
            xprv0_data,
            xprvn_data,
            *compressed_prv_keys,
            *uncompressed_prv_keys,
        ],
    )


def test_from_key() -> None:
    """Every key form, private ones included, crossed the same way.

    The private forms answer with the public key they derive, so each
    check is the one its public counterpart above gets: an int and its
    hex-string carry neither network nor compression, a compressed WIF
    carries both.
    """
    api: Conversions = point_from_key, pub_keyinfo_from_key
    _check_plain(api, [Q, *plain_pub_keys, q, *plain_prv_keys])
    _check_compressed(
        api, [*compressed_pub_keys, xpub_data, xprv_data, *compressed_prv_keys]
    )
    _check_uncompressed(api, [*uncompressed_pub_keys, *uncompressed_prv_keys])
    _check_net_aware(
        api, [*net_aware_pub_keys, xpub_data, xprv_data, *net_aware_prv_keys]
    )
    _check_net_unaware(api, [q, *net_unaware_prv_keys, *net_unaware_pub_keys])
    _check_refused(
        api,
        [
            INF,
            INF_xpub_data,
            *invalid_pub_keys,
            q0,
            qn,
            xprv0_data,
            xprvn_data,
            *invalid_prv_keys,
        ],
    )
    _check_refused(
        api, [q0, qn, xprv0_data, xprvn_data, INF, INF_xpub_data, *not_a_pub_keys]
    )


def test_fingerprint() -> None:
    """Verify the fingerprint matches the child's parent_fingerprint."""
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    xprv = rootxprv_from_seed(seed)
    pf = fingerprint(xprv)  # xprv is automatically converted to xpub
    child_key = derive(xprv, 0x80000000)
    pf2 = BIP32KeyData.b58decode(child_key).parent_fingerprint
    assert pf == pf2


def test_no_key_material_in_exceptions() -> None:
    """Private key material must not reach exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    # an xprv passed where a public key is expected must not be echoed
    with pytest.raises(BTClibValueError) as excinfo:
        pub_keyinfo_from_pub_key(xprv_string)
    assert xprv_string not in str(excinfo.value)

    with pytest.raises(BTClibValueError) as excinfo:
        point_from_pub_key(xprv_string)
    assert xprv_string not in str(excinfo.value)

    # nor an xprv on the wrong network
    with pytest.raises(BTClibValueError) as excinfo:
        pub_keyinfo_from_key(xprv_string, "testnet")
    assert xprv_string not in str(excinfo.value)

    # nor the 0x00-prefixed key field of an xprv, which is a private key
    with pytest.raises(BTClibValueError) as excinfo:
        point_from_pub_key(xprv_data.key)
    assert xprv_data.key.hex() not in str(excinfo.value)
