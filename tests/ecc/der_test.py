# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.der` module."""

import pytest

from btclib.curves import secp256k1
from btclib.ecc.dsa import Sig
from btclib.exceptions import BTClibValueError

ec = secp256k1


def test_der_size() -> None:
    """Round-trip DER serializations of every size from 8 to 72 bytes."""
    sig8 = 1, 1
    sig72 = ec.n - 2, ec.n - 1
    sig71 = 2**255 - 4, ec.n - 1
    sig70 = 2**255 - 4, 2**255 - 1
    sig70b = 2**255 - 4, 2**248 - 1
    sig69 = 2**255 - 4, 2**247 - 1
    sig68 = 2**247 - 1, 2**247 - 1
    sigs = [sig8, sig72, sig71, sig70, sig70b, sig69, sig68]
    lengths = [8, 72, 71, 70, 70, 69, 68]

    for length, (r, s) in zip(lengths, sigs, strict=True):
        sig = Sig(r, s)
        assert r == sig.r
        assert s == sig.s
        assert ec == sig.ec
        sig_bin = sig.serialize()
        assert len(sig_bin) == length
        assert sig == Sig.parse(sig_bin)


def test_der_deserialize() -> None:
    """Refuse each malformed DER field with its own message."""
    err_msg = "non-hexadecimal number found "
    with pytest.raises(ValueError, match=err_msg):
        Sig.parse("not a sig")

    sig = Sig(2**255 - 4, 2**247 - 1)
    sig_bin = sig.serialize()
    r_size = sig_bin[3]

    bad_sig_bin = b"\x31" + sig_bin[1:]
    err_msg = "invalid compound header: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)

    # a length overrunning the buffer is the DER being malformed, so it
    # is a BTClibValueError: var_bytes calls it a BTClibRuntimeError, and
    # a caller filtering parse failures on BTClibValueError -- as
    # psbt_in._assert_valid_partial_sigs does -- would not have caught it
    bad_sig_bin = sig_bin[:1] + b"\x41" + sig_bin[2:]
    err_msg = "invalid DER length: not enough binary data"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)

    # r and s scalars
    for offset in (4, 6 + r_size):
        bad_sig_bin = sig_bin[: offset - 2] + b"\x00" + sig_bin[offset - 1 :]
        err_msg = "invalid value header: "
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x00" + sig_bin[offset:]
        err_msg = "invalid DER length: zero size"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x80" + sig_bin[offset:]
        err_msg = "invalid DER length: not enough binary data"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[:offset] + b"\x80" + sig_bin[offset + 1 :]
        err_msg = "invalid negative scalar"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[:offset] + b"\x00\x7f" + sig_bin[offset + 2 :]
        err_msg = "invalid 'highest bit set' padding"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

    data_size = sig_bin[1]
    malleated_size = (data_size + 1).to_bytes(1, byteorder="big", signed=False)
    bad_sig_bin = sig_bin[:1] + malleated_size + sig_bin[2:] + b"\x01"
    err_msg = "invalid DER sequence length"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)


def test_der_one_byte_scalar() -> None:
    """Guard against a one-byte DER scalar indexing past its buffer.

    3006020100020100 is r = s = 0, each written in the one byte that is
    minimal DER for zero. A 'highest bit set' test that reads the second
    byte of a value having none lets IndexError escape Sig.parse
    whatever the flags -- strict, the last of its three conditions, does
    not spare it -- and IndexError is not what a caller filtering parse
    failures catches.
    """
    for strict in (True, False):
        err_msg = "scalar r not in 1..n-1: "
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse("3006020100020100", strict=strict)

        # check_validity=False asks for the numbers those bytes spell,
        # whatever they are, and what they spell is zero
        sig = Sig.parse("3006020100020100", check_validity=False, strict=strict)
        assert (sig.r, sig.s) == (0, 0)

    # a single byte with the highest bit set is still a negative scalar
    err_msg = "invalid negative scalar"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse("3006020180020180")
    sig = Sig.parse("3006020180020180", check_validity=False, strict=False)
    assert (sig.r, sig.s) == (0x80, 0x80)


def test_der_serialize() -> None:
    """Refuse out-of-range scalars and an r that fits no x-coordinate."""
    r = 2**247 - 1
    s = 2**247 - 1
    Sig(r, s)

    err_msg = "scalar r not in 1..n-1: "
    for bad_r in (0, ec.n):
        _ = Sig(bad_r, s, check_validity=False)
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig(bad_r, s)

    err_msg = "scalar s not in 1..n-1: "
    for bad_s in (0, ec.n):
        _ = Sig(r, bad_s, check_validity=False)
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig(r, bad_s)

    err_msg = r"r is not \(congruent to\) a valid x-coordinate: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig(5, s)
