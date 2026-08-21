# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.key`, the canonical form of a key.

What is worth asserting beyond the conversions themselves is the shape
the module chose and the reasons it chose it for: that the lazy
properties are computed once, that equality reads the declared fields and
so does not change when a lazy one has been asked for, that the two SEC
spellings of one key are deliberately unequal, and that a private key
never reaches a repr.
"""

import pytest

from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData, PubKeyData

Q_INT = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
Q_POINT = mult(Q_INT, secp256k1.G, secp256k1)
SEC_COMPRESSED = bytes_from_point(Q_POINT, secp256k1, True)
SEC_UNCOMPRESSED = bytes_from_point(Q_POINT, secp256k1, False)


def test_pub_key_data() -> None:
    """A public key parses from either SEC form, and lifts to its point."""
    for sec, compressed in ((SEC_COMPRESSED, True), (SEC_UNCOMPRESSED, False)):
        key = PubKeyData(sec)
        assert key.sec == sec
        assert key.network == "mainnet"
        assert key.is_compressed is compressed
        assert key.curve == secp256k1
        assert key.point == Q_POINT

    # a hex string is octets, as it is everywhere else in the library
    assert PubKeyData(SEC_COMPRESSED.hex()) == PubKeyData(SEC_COMPRESSED)


def test_pub_key_data_point_is_computed_once() -> None:
    """The lift is memoized: the same tuple comes back, not an equal one."""
    key = PubKeyData(SEC_COMPRESSED)
    assert key.point is key.point


def test_pub_key_data_equality_ignores_what_was_asked_for() -> None:
    """Equality and hashing read the declared fields: a lift changes neither."""
    lifted, untouched = PubKeyData(SEC_COMPRESSED), PubKeyData(SEC_COMPRESSED)
    assert lifted.point == Q_POINT
    assert lifted == untouched
    assert hash(lifted) == hash(untouched)
    assert len({lifted, untouched}) == 1


def test_pub_key_data_sec_forms_are_not_equal() -> None:
    """The two spellings of one key are different keys: different addresses."""
    assert PubKeyData(SEC_COMPRESSED) != PubKeyData(SEC_UNCOMPRESSED)


def test_the_lift_is_the_proof() -> None:
    """Octets of the right shape that are no point are refused by `point`.

    The whole of what makes this design lazy rather than eager: the
    constructor reads a length and a prefix, and the curve is asked only
    when somebody wants the point. A key nobody asks has never been
    proved one, which is deliberate and is what this asserts.
    """
    not_a_point = PubKeyData(b"\x02" + b"\x11" * 32)
    assert not_a_point.is_compressed
    with pytest.raises(BTClibValueError, match="invalid x-coordinate"):
        _ = not_a_point.point


def test_hybrid_sec_prefixes_are_refused() -> None:
    """0x06 and 0x07 carry both coordinates, and are not a canonical form.

    `sec_point.point_from_octets` parses one when asked; this type takes
    that function's default and does not ask, so a hybrid key never
    becomes a `PubKeyData`.
    """
    for prefix in (b"\x06", b"\x07"):
        with pytest.raises(BTClibValueError, match="invalid uncompressed SEC prefix"):
            PubKeyData(prefix + SEC_UNCOMPRESSED[1:])


def test_a_network_name_is_normalized_on_the_way_in() -> None:
    """Two spellings of one network are one key, not two.

    `network_from_name` accepts " MainNet ", so without the coercion the
    two would be unequal and hash apart -- and a dict or a set would hold
    the same key twice.
    """
    plain, spelled = PubKeyData(SEC_COMPRESSED), PubKeyData(SEC_COMPRESSED, " MainNet ")
    assert plain == spelled
    assert hash(plain) == hash(spelled)
    assert len({plain, spelled}) == 1
    assert spelled.network == "mainnet"
    assert PrvKeyData(Q_INT, " MainNet ") == PrvKeyData(Q_INT)


def test_the_network_travels_to_the_derived_key() -> None:
    """What the type exists to carry: a derived key is on its parent's chain."""
    key = PrvKeyData(Q_INT, "testnet")
    assert key.pub.network == "testnet"
    assert key.pub.sec == SEC_COMPRESSED


def test_pub_key_data_deferred_validity() -> None:
    """`check_validity=False` builds what the constructor would refuse."""
    key = PubKeyData(b"\x02", check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid SEC key size"):
        key.assert_valid()


@pytest.mark.parametrize(
    "sec, err_msg",
    [
        (b"", "invalid SEC key size"),
        (b"\x02" + b"\x11" * 31, "invalid SEC key size"),
        (b"\x05" + b"\x11" * 32, "invalid compressed SEC prefix"),
        (b"\x02" + b"\x11" * 64, "invalid uncompressed SEC prefix"),
    ],
)
def test_invalid_pub_key_data(sec: bytes, err_msg: str) -> None:
    """Octets no SEC public key has are refused, and never echoed."""
    with pytest.raises(BTClibValueError, match=err_msg):
        PubKeyData(sec)


def test_pub_key_data_type_and_network() -> None:
    """A type no key has, and a name no network has, are both refused."""
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        PubKeyData(1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid network type"):
        PubKeyData(SEC_COMPRESSED, 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError):
        PubKeyData(SEC_COMPRESSED, "no-such-network")


def test_prv_key_data() -> None:
    """A private key derives its public one, in the SEC form it says."""
    for compressed, sec in ((True, SEC_COMPRESSED), (False, SEC_UNCOMPRESSED)):
        key = PrvKeyData(Q_INT, "mainnet", compressed)
        assert key.q == Q_INT
        assert key.network == "mainnet"
        assert key.compressed is compressed
        assert key.curve == secp256k1
        assert key.pub == PubKeyData(sec)


def test_prv_key_data_pub_is_derived_once() -> None:
    """The multiplication is memoized, being the dearest conversion here."""
    key = PrvKeyData(Q_INT)
    assert key.pub is key.pub


def test_prv_key_data_repr_masks_the_secret() -> None:
    """A private key never reaches a repr, as `BIP32KeyData`'s does not."""
    text = repr(PrvKeyData(Q_INT))
    assert f"{Q_INT:x}" not in text
    assert str(Q_INT) not in text
    assert "q=..." in text
    assert "mainnet" in text


def test_prv_key_data_deferred_validity() -> None:
    """`check_validity=False` builds what the constructor would refuse."""
    key = PrvKeyData(0, check_validity=False)
    with pytest.raises(BTClibValueError, match="not in 1..n-1"):
        key.assert_valid()


@pytest.mark.parametrize("q", [0, secp256k1.n, -1])
def test_invalid_prv_key_data(q: int) -> None:
    """A scalar outside 1..n-1 is refused, and never echoed."""
    with pytest.raises(BTClibValueError, match="not in 1..n-1"):
        PrvKeyData(q)


def test_prv_key_data_types() -> None:
    """A bool is a kind and not a number, and neither is a string a scalar."""
    with pytest.raises(BTClibTypeError, match="not a private key scalar"):
        PrvKeyData(True)
    with pytest.raises(BTClibTypeError, match="not a private key scalar"):
        PrvKeyData("cafe")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid network type"):
        PrvKeyData(Q_INT, 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid compressed type"):
        PrvKeyData(Q_INT, "mainnet", 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError):
        PrvKeyData(Q_INT, "no-such-network")
