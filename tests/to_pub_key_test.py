# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.to_pub_key` module."""

from collections.abc import Callable, Sequence

import pytest

from btclib.alias import INF, Point
from btclib.curves import (
    PreparedPoint,
    bytes_from_point,
    mult,
    point_from_octets,
)
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.to_pub_key import (
    Key,
    PubkeyInfo,
    _sec_from_key,
    _sec_from_pub_key,
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
    assert point_from(key) == Q
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


def _check_net_unaware(api: Conversions, keys: Sequence[Key]) -> None:
    """Check a form naming no network: both answered, mainnet by default."""
    point_from, keyinfo_from = api
    for key in keys:
        _check_point(point_from, key)
        assert keyinfo_from(key) in {m_c, m_unc}
        assert keyinfo_from(key, "mainnet") in {m_c, m_unc}
        assert keyinfo_from(key, "testnet") in {t_c, t_unc}


def _check_refused(api: Conversions, keys: Sequence[Key]) -> None:
    """Neither conversion has an answer for these.

    Each test asks it twice, of what is an invalid key and of what is no
    key at all, and the second list contains the first: not_a_pub_keys is
    the invalid private keys and the invalid public ones together. The
    assertion is the same one either way, every refusal here being a
    BTClibValueError, so the two calls name the two vocabularies rather
    than expect two answers.

    Every key here is of a type the union declares. What is not is
    `_check_refused_as_a_type`'s, and the two are separate because the
    difference is a promise rather than a detail.
    """
    point_from, keyinfo_from = api
    for key in keys:
        with pytest.raises(BTClibValueError):
            point_from(key)
        with pytest.raises(BTClibValueError):
            keyinfo_from(key)


def _check_refused_as_a_type(api: Conversions, keys: Sequence[object]) -> None:
    """Check the refusal of a type no spelling of a public key has.

    The other half of `_check_refused`, and the difference is issue
    #814's rule: a value of a declared type that is no key is a
    BTClibValueError, a type the union does not declare is a
    BTClibTypeError. That is what lets `dsa.verify` answer False for the
    first and refuse the second, being total over what it declares.

    An int is the one that matters: in this library an int is a private
    key and never a public one, so passing one here is the very
    confusion issue #143 is about.

    `object` and not `Key`, which is the point of the function: what it
    is handed is what the union does not declare, so a parameter of that
    union would be a type error at every call site rather than at none.
    """
    point_from, keyinfo_from = api
    for key in keys:
        with pytest.raises(BTClibTypeError, match="not a public key"):
            point_from(key)
        with pytest.raises(BTClibTypeError, match="not a public key"):
            keyinfo_from(key)


def test_from_pub_key() -> None:
    """Every public-key form, crossed with network and compression."""
    api: Conversions = point_from_pub_key, pub_keyinfo_from_pub_key
    _check_plain(api, [Q, *plain_pub_keys])
    _check_compressed(api, compressed_pub_keys)
    _check_uncompressed(api, uncompressed_pub_keys)
    _check_net_unaware(api, net_unaware_pub_keys)
    _check_refused(api, [INF, *invalid_pub_keys])
    _check_refused(
        api,
        [
            INF,
            *not_a_pub_keys,
            *plain_prv_keys,
            *compressed_prv_keys,
            *uncompressed_prv_keys,
        ],
    )
    # the three int spellings of a private key, which `test_from_key`
    # below accepts and this must not: an int is no PubKey at all. An
    # extended key joins them, being `bip32`'s type and no longer a
    # spelling of this union (issue #1188)
    _check_refused_as_a_type(
        api, [q, q0, qn, xpub_data, xprv_data, xprv0_data, xprvn_data, INF_xpub_data]
    )


def test_from_key() -> None:
    """Every key form, private ones included, crossed the same way.

    The private forms answer with the public key they derive, so each
    check is the one its public counterpart above gets: an int and its
    hex-string carry neither network nor compression, and nothing left in
    this union carries either. A WIF is `b58`'s spelling and an extended
    key is `bip32`'s, and `to_pub_key` reaches neither (issue #1188).
    """
    api: Conversions = point_from_key, pub_keyinfo_from_key
    _check_plain(api, [Q, *plain_pub_keys, q, *plain_prv_keys])
    _check_compressed(api, [*compressed_pub_keys, *compressed_prv_keys])
    _check_uncompressed(api, [*uncompressed_pub_keys, *uncompressed_prv_keys])
    _check_net_unaware(api, [q, *net_unaware_prv_keys, *net_unaware_pub_keys])
    _check_refused(api, [INF, *invalid_pub_keys, q0, qn, *invalid_prv_keys])
    _check_refused(api, [q0, qn, INF, *not_a_pub_keys])


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


def test_a_prepared_point_is_a_key_wherever_a_point_is() -> None:
    """The four converters answer a prepared point as they answer its point.

    `curves.PreparedPoint` carries a caller's word about how often the
    point will be multiplied, and nothing else: no converter here has a
    use for that word, so each answers by asking itself about the point,
    and what proves it is that the two answers are the same object's.

    Both unions, `PubKey` and the wider `Key`, and the unproven
    conversion below them: a prepared point reaching that one is a
    verification on the delegated path, where the tables it holds are not
    what answers.
    """
    prepared = PreparedPoint(Q)

    assert point_from_pub_key(prepared) == point_from_pub_key(Q)
    assert point_from_key(prepared) == point_from_key(Q)
    assert pub_keyinfo_from_pub_key(prepared) == pub_keyinfo_from_pub_key(Q)
    assert pub_keyinfo_from_key(prepared) == pub_keyinfo_from_key(Q)
    for compressed in (True, False):
        assert pub_keyinfo_from_pub_key(
            prepared, "mainnet", compressed
        ) == pub_keyinfo_from_pub_key(Q, "mainnet", compressed)

    # the uncompressed form, which is what that conversion answers for a
    # point: the cheap one for whatever call proves it
    assert _sec_from_pub_key(prepared) == bytes_from_point(Q, compressed=False)

    # and a prepared point of another curve is refused where a bare point
    # of it is: preparing validates against its own curve, so what is
    # asked here is the second one
    other = CURVES["secp256r1"]
    prepared_r1 = PreparedPoint(mult(12, other.G, other), other)
    with pytest.raises(BTClibValueError, match="not a valid public key"):
        point_from_pub_key(prepared_r1)


def test_the_unproven_conversion_takes_every_spelling_a_key_has() -> None:
    """`_sec_from_key` answers what `pub_keyinfo_from_key` answers.

    The same key, which is what has to hold: the octets differ where the
    form does -- a point comes back uncompressed here, that being the
    cheap one for the call this feeds, and compressed from the public
    spelling, which answers "whatever the key says" and a point says
    nothing -- so the two are compared as the points they name. A private
    key as an int, a point, a prepared point, SEC octets. A WIF is
    `b58`'s spelling and an extended key is `bip32`'s, and neither is
    `Key`'s (issue #1188).

    What this one does not do is prove octets a point: it leaves that to
    the call it feeds, `script.taproot`'s tweak.

    The refusal is the one spelling that differs, and it is named in the
    docstring: octets of the right size that are no point reach the call
    below as a public key, where `pub_keyinfo_from_key` reports them as
    neither kind of key.
    """
    q = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    point = mult(q)
    sec = bytes_from_point(point, compressed=True)

    for key in (q, point, PreparedPoint(point), sec):
        assert point_from_octets(_sec_from_key(key)) == point_from_key(key)

    # what is no key in any spelling is refused in the same words, the
    # fallthrough to the private key being the same one
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        _sec_from_key("not a key")
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        pub_keyinfo_from_key("not a key")

    # and the one difference, which the docstring names: 33 octets that
    # are no point come back from here, for the call that feeds them to
    # refuse, where the public spelling proves them and reports that they
    # are neither kind of key
    no_point = b"\x02" + bytes(32)
    assert _sec_from_key(no_point) == no_point
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        pub_keyinfo_from_key(no_point)
