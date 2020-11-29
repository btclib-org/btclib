#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.der` module."

import pytest

from btclib.curve import secp256k1
from btclib.der import DerSig, SighashDerSig
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.script import SIGHASHES

ec = secp256k1


def test_der_size() -> None:

    sig8 = 1, 1
    sig72 = ec.n - 1, ec.n - 1
    sig71 = 2 ** 255 - 1, ec.n - 1
    sig70 = 2 ** 255 - 1, 2 ** 255 - 1
    sig70b = 2 ** 255 - 1, 2 ** 248 - 1
    sig69 = 2 ** 255 - 1, 2 ** 247 - 1
    sig68 = 2 ** 247 - 1, 2 ** 247 - 1
    sigs = [sig8, sig72, sig71, sig70, sig70b, sig69, sig68]
    lenghts = [8, 72, 71, 70, 70, 69, 68]  # not including SIGHASHES

    for length, sig in zip(lenghts, sigs):
        dsa_sig = DerSig(*sig)
        assert sig[0] == dsa_sig.r
        assert sig[1] == dsa_sig.s
        assert ec == dsa_sig.ec
        dsa_sig_bin = dsa_sig.serialize()
        assert len(dsa_sig_bin) == length
        assert dsa_sig == DerSig.deserialize(dsa_sig_bin)
        for sighash in SIGHASHES:
            der_sig = SighashDerSig(dsa_sig, sighash)
            assert dsa_sig == der_sig.dsa_sig
            assert sighash == der_sig.sighash
            der_sig_bin = der_sig.serialize()
            assert len(der_sig_bin) == length + 1
            assert der_sig == SighashDerSig.deserialize(der_sig_bin)


def test_der_deserialize() -> None:

    err_msg = "non-hexadecimal number found "
    with pytest.raises(ValueError, match=err_msg):
        DerSig.deserialize("not a sig")

    dsa_sig = DerSig(2 ** 255 - 1, 2 ** 247 - 1)
    for sighash in SIGHASHES:
        der_sig_bin = SighashDerSig(dsa_sig, sighash=sighash).serialize()
        r_size = der_sig_bin[3]

        bad_der_sig_bin = b"\x31" + der_sig_bin[1:]
        err_msg = "invalid DER type: "
        with pytest.raises(BTClibValueError, match=err_msg):
            SighashDerSig.deserialize(bad_der_sig_bin)

        bad_der_sig_bin = der_sig_bin[:1] + b"\x41" + der_sig_bin[2:]
        err_msg = "not enough binary data"
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            SighashDerSig.deserialize(bad_der_sig_bin)

        bad_der_sig_bin = der_sig_bin[:-1] + b"\x00"
        err_msg = "invalid sighash: 0x"
        with pytest.raises(BTClibValueError, match=err_msg):
            SighashDerSig.deserialize(bad_der_sig_bin)

        # r and s scalars
        for offset in (4, 6 + r_size):
            bad_der_sig_bin = (
                der_sig_bin[: offset - 2] + b"\x00" + der_sig_bin[offset - 1 :]
            )
            err_msg = "invalid value header: "
            with pytest.raises(BTClibValueError, match=err_msg):
                SighashDerSig.deserialize(bad_der_sig_bin)

            bad_der_sig_bin = der_sig_bin[: offset - 1] + b"\x00" + der_sig_bin[offset:]
            err_msg = "zero size"
            with pytest.raises(BTClibRuntimeError, match=err_msg):
                SighashDerSig.deserialize(bad_der_sig_bin)

            bad_der_sig_bin = der_sig_bin[: offset - 1] + b"\x80" + der_sig_bin[offset:]
            err_msg = "not enough binary data"
            with pytest.raises(BTClibRuntimeError, match=err_msg):
                SighashDerSig.deserialize(bad_der_sig_bin)

            bad_der_sig_bin = der_sig_bin[:offset] + b"\x80" + der_sig_bin[offset + 1 :]
            err_msg = " not in 1..n-1: "
            with pytest.raises(BTClibValueError, match=err_msg):
                SighashDerSig.deserialize(bad_der_sig_bin)

            bad_der_sig_bin = (
                der_sig_bin[:offset] + b"\x00\x7f" + der_sig_bin[offset + 2 :]
            )
            err_msg = "invalid null byte at the start of scalar"
            with pytest.raises(BTClibValueError, match=err_msg):
                SighashDerSig.deserialize(bad_der_sig_bin)

        data_size = der_sig_bin[1]
        malleated_size = (data_size + 1).to_bytes(1, byteorder="big")
        bad_der_sig_bin = der_sig_bin[:1] + malleated_size + der_sig_bin[2:] + b"\x01"
        err_msg = "invalid DER size"
        with pytest.raises(BTClibValueError, match=err_msg):
            SighashDerSig.deserialize(bad_der_sig_bin)


def test_derserialize() -> None:

    dsa_sig = DerSig(2 ** 247 - 1, 2 ** 247 - 1)
    err_msg = "invalid sighash: 0x"
    with pytest.raises(BTClibValueError, match=err_msg):
        SighashDerSig(dsa_sig, sighash=0x85)

    for sighash in SIGHASHES:
        err_msg = "scalar r not in 1..n-1: "
        for bad_r in (0, ec.n):
            bad_dsa_sig = DerSig(bad_r, dsa_sig.s, check_validity=False)
            with pytest.raises(BTClibValueError, match=err_msg):
                SighashDerSig(bad_dsa_sig, sighash=sighash)

        err_msg = "scalar s not in 1..n-1: "
        for bad_s in (0, ec.n):
            bad_dsa_sig = DerSig(dsa_sig.r, bad_s, check_validity=False)
            with pytest.raises(BTClibValueError, match=err_msg):
                SighashDerSig(bad_dsa_sig, sighash=sighash)
