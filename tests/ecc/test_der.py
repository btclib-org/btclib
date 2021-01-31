#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.der` module."

import pytest

from btclib.ecc.curve import secp256k1
from btclib.ecc.der import Sig
from btclib.exceptions import BTClibRuntimeError, BTClibValueError

ec = secp256k1


def test_der_size() -> None:

    sig8 = 1, 1
    sig72 = ec.n - 2, ec.n - 1
    sig71 = 2 ** 255 - 4, ec.n - 1
    sig70 = 2 ** 255 - 4, 2 ** 255 - 1
    sig70b = 2 ** 255 - 4, 2 ** 248 - 1
    sig69 = 2 ** 255 - 4, 2 ** 247 - 1
    sig68 = 2 ** 247 - 1, 2 ** 247 - 1
    sigs = [sig8, sig72, sig71, sig70, sig70b, sig69, sig68]
    lenghts = [8, 72, 71, 70, 70, 69, 68]

    for length, (r, s) in zip(lenghts, sigs):
        sig = Sig(r, s)
        assert r == sig.r
        assert s == sig.s
        assert ec == sig.ec
        sig_bin = sig.serialize()
        assert len(sig_bin) == length
        assert sig == Sig.parse(sig_bin)


def test_der_deserialize() -> None:

    err_msg = "non-hexadecimal number found "
    with pytest.raises(ValueError, match=err_msg):
        Sig.parse("not a sig")

    sig = Sig(2 ** 255 - 4, 2 ** 247 - 1)
    sig_bin = sig.serialize()
    r_size = sig_bin[3]

    bad_sig_bin = b"\x31" + sig_bin[1:]
    err_msg = "invalid compound header: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)

    bad_sig_bin = sig_bin[:1] + b"\x41" + sig_bin[2:]
    err_msg = "not enough binary data"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        Sig.parse(bad_sig_bin)

    # r and s scalars
    for offset in (4, 6 + r_size):
        bad_sig_bin = sig_bin[: offset - 2] + b"\x00" + sig_bin[offset - 1 :]
        err_msg = "invalid value header: "
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x00" + sig_bin[offset:]
        err_msg = "zero size"
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x80" + sig_bin[offset:]
        err_msg = "not enough binary data"
        with pytest.raises(BTClibRuntimeError, match=err_msg):
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


def test_der_serialize() -> None:

    r = 2 ** 247 - 1
    s = 2 ** 247 - 1
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
