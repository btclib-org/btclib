# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bms` module."""

# `Point | None` below is evaluated at def time without this, and py3.9 --
# the floor when this was written -- had no `|` on types: the module failed
# to import there, so the whole file was 10 collection errors on the oldest
# supported interpreter and passed on every other.
# The floor is 3.10 now, where `|` on types is the language, so this line no
# longer carries the file. It stays because every module in btclib and its
# tests opens with it, and because the annotations it defers are still not
# evaluated at def time -- which is what keeps a forward reference cheap
from __future__ import annotations

import base64
import contextlib
import dataclasses
from collections.abc import Callable
from hashlib import sha256
from typing import Any

import pytest

from btclib import b32, b58
from btclib._libsecp256k1 import recovery as libsecp256k1_recovery
from btclib.alias import Point
from btclib.b58 import h160_from_address
from btclib.bip32 import bip32
from btclib.curves import curve, mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import bms, dsa
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import magic_message
from btclib.key import PrvKeyData
from btclib.mnemonic import bip39
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from tests import load, needs_bindings, vector_id
from tests.curves.curve_test import no_bindings_anywhere

ec = secp256k1


def test_check_validity_defaults_to_true_everywhere_it_appears() -> None:
    """serialize, b64encode and parse all refuse an invalid Sig by default.

    Built once with `check_validity=False`, an out-of-range recovery
    flag is invalid for every one of the checks these three otherwise
    make on the way to bytes or back: a default flipped to `False`
    would let it through silently instead.
    """
    dsa_sig = dsa.Sig(1, 1, ec, check_validity=False)
    invalid = bms.Sig(100, dsa_sig, check_validity=False)

    with pytest.raises(BTClibValueError, match="invalid recovery flag: "):
        invalid.serialize()
    invalid.serialize(check_validity=False)

    with pytest.raises(BTClibValueError, match="invalid recovery flag: "):
        invalid.b64encode()
    invalid.b64encode(check_validity=False)

    data = invalid.serialize(check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid recovery flag: "):
        bms.Sig.parse(data)
    bms.Sig.parse(data, check_validity=False)


def test_signature() -> None:
    """Round-trip sign, verify and the encodings; malleation included."""
    msg = b"test message"

    wif, addr = bms.gen_keys()
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    bms.assert_as_valid(msg, addr, bms_sig)
    assert bms.verify(msg, addr, bms_sig)
    assert bms_sig == bms.Sig.parse(bms_sig.serialize())
    assert bms_sig == bms.Sig.parse(bms_sig.serialize().hex())
    assert bms_sig == bms.Sig.b64decode(bms_sig.b64encode())
    assert bms_sig == bms.Sig.b64decode(bms_sig.b64encode().encode("ascii"))

    assert bms_sig == bms.sign(msg, b58.prv_key_data_from_wif(wif.encode("ascii")))

    # frozen: `__init__` sets both fields through `object.__setattr__`
    # for exactly this reason, and nothing after construction reaches
    # them the same way
    with pytest.raises(dataclasses.FrozenInstanceError):
        bms_sig.rf = 27  # type: ignore[misc]

    # malleated signature
    dsa_sig = dsa.Sig(bms_sig.dsa_sig.r, bms_sig.dsa_sig.ec.n - bms_sig.dsa_sig.s)
    # the recovery flag names which candidate the key is, and negating s
    # mirrors the nonce's point: without updating rf the signature opens
    # to a different key, hence to a different address
    bms_sig = bms.Sig(bms_sig.rf, dsa_sig)
    err_msg = "invalid p2pkh address: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, addr, bms_sig)
    # update rf to satisfy above malleation
    i = 1 if bms_sig.rf % 2 else -1
    bms_sig = bms.Sig(bms_sig.rf + i, dsa_sig)
    # and then it opens to the address, which is the whole answer: which
    # form s took was the signer's choice, and Core's verifymessage
    # accepts the high one too (issue 695)
    bms.assert_as_valid(msg, addr, bms_sig)
    assert bms.verify(msg, addr, bms_sig)

    # bms_sig taken from (Electrum and) Bitcoin Core
    wif = "5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw"
    addr = b58.p2pkh(wif)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    bms.assert_as_valid(msg, addr, bms_sig)
    assert bms.verify(msg, addr, bms_sig)
    exp_sig = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert bms_sig.b64encode() == exp_sig

    bms.assert_as_valid(msg, addr, exp_sig)
    bms.assert_as_valid(msg, addr, exp_sig.encode("ascii"))

    dsa_sig = dsa.Sig(bms_sig.dsa_sig.r, bms_sig.dsa_sig.s, CURVES["secp256r1"])
    err_msg = "invalid curve: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms_sig = bms.Sig(bms_sig.rf, dsa_sig)


def test_long_message() -> None:
    """Sign and verify across the one-byte length boundary.

    The message length is prefixed as a var_int, so a message of 253
    bytes or more is signable and verifiable; guards against a fixed
    one-byte length making signing raise OverflowError from 256 bytes on.
    """
    wif, addr = bms.gen_keys()
    for length in (252, 253, 255, 256, 0x10000):
        msg = b"a" * length
        bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
        bms.assert_as_valid(msg, addr, bms_sig)
        assert bms.verify(msg, addr, bms_sig)


def test_exceptions() -> None:
    """Refuse bad addresses, flags, encodings and key/address pairs."""
    msg = b"test"
    wif = "KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu"
    address = b58.p2pkh(wif)
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
    bms.assert_as_valid(msg, address, exp_sig)
    bms_sig = bms.Sig.b64decode(exp_sig)

    err_msg = "not a p2wpkh address: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b32.p2wsh(32 * b"\x00"), exp_sig)

    # a program's length, not only its version: p2wsh above is version 0
    # with a 32-byte program, caught by the length half of `wit_ver != 0
    # or len(h160) != 20` alone -- `!= 0` weakened to `< 0` needs a
    # *non-zero* version paired with a 20-byte program, which no other
    # witness type is, to be told apart
    not_p2wpkh = b32.address_from_witness(5, bytes(20))
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, not_p2wpkh, exp_sig)

    err_msg = "invalid recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.Sig(26, bms_sig.dsa_sig)

    # the upper boundary, not only the lower one: `self.rf > 42` weakened
    # to `>= 42` would refuse 42 itself, which the vector above cannot
    # show since it only ever moves the lower bound
    bms.Sig(42, bms_sig.dsa_sig)
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.Sig(43, bms_sig.dsa_sig)

    # 84 base64 characters and then a padding one, i.e. a pad following
    # a complete group: guards against b64decode discarding it, as
    # anything out of the alphabet, and handing over the 63 bytes left
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLoVc="
    err_msg = "invalid base64 encoding: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, address, exp_sig)
    assert not bms.verify(msg, address, exp_sig)

    # well formed base64 this time, but 60 bytes: too few for the
    # [1-byte rf][32-bytes r][32-bytes s] the slices below assume
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2e"
    err_msg = "invalid decoded length: 60"
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
        bms.sign(msg, b58.prv_key_data_from_wif(wif), address)

    # uncompressed wif, compressed address: the mismatch the case above
    # reports, reported the same way -- not as "not a private or
    # compressed public key for mainnet" leaking out of p2wpkh_p2sh,
    # tried with an uncompressed key on the way to BIP137
    wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), address)

    msg = b"test"
    wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
    b58_p2pkh = b58.p2pkh(wif)
    b32_p2wpkh = b32.p2wpkh(b58.prv_key_data_from_wif(wif).pub.sec)
    b58_p2wpkh_p2sh = b58.p2wpkh_p2sh(wif)

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2pkh)
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), b32_p2wpkh)
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2wpkh_p2sh)

    # Invalid recovery flag (39) for base58 p2pkh address
    exp_sig = "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
    bms_sig = bms.Sig.b64decode(exp_sig)
    bms_sig = bms.Sig(39, bms_sig.dsa_sig, check_validity=False)
    sig_encoded = bms_sig.b64encode(check_validity=False)
    err_msg = "invalid p2pkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2pkh, sig_encoded)

    # Invalid recovery flag (35) for bech32 p2wpkh address
    exp_sig = "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    bms_sig = bms.Sig.b64decode(exp_sig)
    bms_sig = bms.Sig(35, bms_sig.dsa_sig, check_validity=False)
    err_msg = "invalid p2wpkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b32_p2wpkh, bms_sig)


def test_every_recovery_flag_is_ruled_on_by_range_alone() -> None:
    """Sweep 27..42 against each address type, the range check in isolation.

    A single vector per address type -- 39 for p2pkh, 35 for p2wpkh --
    only ever pins one side of a range that has two boundaries each
    (p2pkh's is one-sided, p2wpkh's and p2wpkh-p2sh's are not): `> 34`
    weakened to `>= 34` refuses 34 itself, and `30 < rf < 35 or rf > 38`
    weakened to `30 < rf != 35 or rf > 38` accepts 36 and 37, neither of
    which any existing vector asks about.

    Called directly on the three private helpers rather than through
    `assert_as_valid`: that entry point recovers a public key from `rf`
    before any range check runs, and not every `rf` recovers one from a
    fixed signature, which is a fact about elliptic-curve recovery and
    not about the range check this test is for. A wrong pub_key and
    h160 here still tell "recovery flag" from "address" apart -- only
    the range check can raise the first, and the address one always
    raises the second once the range holds.
    """
    wif = "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
    dummy_pub_key = b"\x02" + 32 * b"\x00"
    b58_p2pkh = b58.p2pkh(wif)
    _, h160_p2pkh, _ = h160_from_address(b58_p2pkh)
    b32_p2wpkh = b32.p2wpkh(b58.prv_key_data_from_wif(wif).pub.sec)
    b58_p2wpkh_p2sh = b58.p2wpkh_p2sh(wif)
    _, h160_p2sh, _ = h160_from_address(b58_p2wpkh_p2sh)

    checks: list[tuple[Callable[[int], None], set[int], str, str]] = [
        (
            lambda rf: bms._assert_p2pkh(b58_p2pkh, rf, dummy_pub_key, h160_p2pkh),
            set(range(27, 35)),
            "invalid p2pkh address recovery flag: ",
            "invalid p2pkh address: ",
        ),
        (
            lambda rf: bms._assert_p2wpkh(b32_p2wpkh, rf, dummy_pub_key),
            {31, 32, 33, 34, 39, 40, 41, 42},
            "invalid p2wpkh address recovery flag: ",
            "invalid p2wpkh address: ",
        ),
        (
            lambda rf: bms._assert_p2wpkh_p2sh(
                b58_p2wpkh_p2sh, rf, dummy_pub_key, h160_p2sh
            ),
            set(range(31, 39)),
            "invalid p2wpkh-p2sh address recovery flag: ",
            "invalid p2wpkh-p2sh address: ",
        ),
    ]
    for check, valid_range, flag_err, address_err in checks:
        for rf in range(27, 43):
            expected = address_err if rf in valid_range else flag_err
            with pytest.raises(BTClibValueError, match=expected):
                check(rf)


def test_the_address_is_read_the_same_however_it_is_held() -> None:
    """`sign` takes a String address, and a String is text or any buffer.

    Two spellings of one address used to sign under different flags:
    text was stripped of blanks and `bytes` was only decoded, so a
    padded `bytes` address named an address the key does not have and
    the call came back `mismatch between private key and address` -- a
    complaint about the key, for blanks around the address. The buffers
    did not decode at all. All of them read through `str_from_string`
    now, which strips nothing and is followed by the strip that does
    (issue #1238).
    """
    msg = b"however it is held"
    wif = "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
    address = b58.p2pkh(wif)
    expected = bms.sign(msg, b58.prv_key_data_from_wif(wif), address)

    padded = f"  {address}  "
    for spelling in (
        address.encode("ascii"),
        padded,
        padded.encode("ascii"),
        bytearray(address.encode("ascii")),
        memoryview(address.encode("ascii")),
    ):
        assert bms.sign(msg, b58.prv_key_data_from_wif(wif), spelling).rf == expected.rf

    # and a byte outside ascii is this library's complaint about the
    # address, where the hand-rolled decode let Python's own out
    with pytest.raises(BTClibValueError, match="non-ascii character in address"):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), address.encode("ascii") + b"\xc3")


def test_one_prv_key_multiple_addresses() -> None:
    """Verify the BIP137 flag binds a signature to its address type."""
    msg = b"Paolo is afraid of ephemeral random numbers"

    # Compressed WIF
    wif = "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
    b58_p2pkh_compressed = b58.p2pkh(wif)
    b58_p2wpkh_p2sh = b58.p2wpkh_p2sh(wif)
    b32_p2wpkh = b32.p2wpkh(b58.prv_key_data_from_wif(wif).pub.sec)

    # sign with no address
    sig1 = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    # True for Bitcoin Core
    bms.assert_as_valid(msg, b58_p2pkh_compressed, sig1)
    assert bms.verify(msg, b58_p2pkh_compressed, sig1)
    # True for Electrum p2wpkh_p2sh
    bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig1)
    assert bms.verify(msg, b58_p2wpkh_p2sh, sig1)
    # True for Electrum p2wpkh
    bms.assert_as_valid(msg, b32_p2wpkh, sig1)
    assert bms.verify(msg, b32_p2wpkh, sig1)

    # sign with p2pkh address
    sig1 = bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2pkh_compressed)
    # True for Bitcoin Core
    bms.assert_as_valid(msg, b58_p2pkh_compressed, sig1)
    assert bms.verify(msg, b58_p2pkh_compressed, sig1)
    # True for Electrum p2wpkh_p2sh
    bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig1)
    assert bms.verify(msg, b58_p2wpkh_p2sh, sig1)
    # True for Electrum p2wpkh
    bms.assert_as_valid(msg, b32_p2wpkh, sig1)
    assert bms.verify(msg, b32_p2wpkh, sig1)
    assert sig1 == bms.sign(
        msg, b58.prv_key_data_from_wif(wif), b58_p2pkh_compressed.encode("ascii")
    )

    # sign with p2wpkh_p2sh address (BIP137)
    sig2 = bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2wpkh_p2sh)
    # False for Bitcoin Core
    err_msg = "invalid p2pkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2pkh_compressed, sig2)
    assert not bms.verify(msg, b58_p2pkh_compressed, sig2)
    # True for BIP137 p2wpkh_p2sh
    bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig2)
    assert bms.verify(msg, b58_p2wpkh_p2sh, sig2)
    # False for BIP137 p2wpkh
    err_msg = "invalid p2wpkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b32_p2wpkh, sig2)
    assert not bms.verify(msg, b32_p2wpkh, sig2)
    assert sig2 == bms.sign(
        msg, b58.prv_key_data_from_wif(wif), b58_p2wpkh_p2sh.encode("ascii")
    )

    # sign with p2wpkh address (BIP137)
    sig3 = bms.sign(msg, b58.prv_key_data_from_wif(wif), b32_p2wpkh)
    # False for Bitcoin Core
    err_msg = "invalid p2pkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2pkh_compressed, sig3)
    assert not bms.verify(msg, b58_p2pkh_compressed, sig3)
    # False for BIP137 p2wpkh_p2sh
    err_msg = "invalid p2wpkh-p2sh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig3)
    assert not bms.verify(msg, b58_p2wpkh_p2sh, sig3)
    # True for BIP137 p2wpkh
    bms.assert_as_valid(msg, b32_p2wpkh, sig3)
    assert bms.verify(msg, b32_p2wpkh, sig3)
    assert sig3 == bms.sign(
        msg, b58.prv_key_data_from_wif(wif), b32_p2wpkh.encode("ascii")
    )

    # uncompressed WIF / p2pkh address
    data = b58.prv_key_data_from_wif(wif)
    wif2 = b58.wif_from_prv_key(data.q, data.network, False)
    b58_p2pkh_uncompressed = b58.p2pkh(wif2)

    # sign with uncompressed p2pkh
    sig4 = bms.sign(msg, b58.prv_key_data_from_wif(wif2), b58_p2pkh_uncompressed)
    # False for Bitcoin Core compressed p2pkh
    with pytest.raises(BTClibValueError, match="invalid p2pkh address: "):
        bms.assert_as_valid(msg, b58_p2pkh_compressed, sig4)
    assert not bms.verify(msg, b58_p2pkh_compressed, sig4)
    # False for BIP137 p2wpkh_p2sh
    err_msg = "invalid p2wpkh-p2sh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig4)
    assert not bms.verify(msg, b58_p2wpkh_p2sh, sig4)
    # False for BIP137 p2wpkh
    err_msg = "invalid p2wpkh address recovery flag: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.assert_as_valid(msg, b32_p2wpkh, sig4)
    assert not bms.verify(msg, b32_p2wpkh, sig4)
    # True for Bitcoin Core uncompressed p2pkh
    bms.assert_as_valid(msg, b58_p2pkh_uncompressed, sig4)
    assert bms.verify(msg, b58_p2pkh_uncompressed, sig4)
    assert sig4 == bms.sign(
        msg, b58.prv_key_data_from_wif(wif2), b58_p2pkh_uncompressed.encode("ascii")
    )

    # unrelated different wif
    wif3 = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    b58_p2pkh_compressed = b58.p2pkh(wif3)
    b58_p2wpkh_p2sh = b58.p2wpkh_p2sh(wif3)
    b32_p2wpkh = b32.p2wpkh(b58.prv_key_data_from_wif(wif3).pub.sec)

    # False for Bitcoin Core compressed p2pkh
    with pytest.raises(BTClibValueError, match="invalid p2pkh address: "):
        bms.assert_as_valid(msg, b58_p2pkh_compressed, sig1)
    assert not bms.verify(msg, b58_p2pkh_compressed, sig1)
    # False for BIP137 p2wpkh_p2sh
    with pytest.raises(BTClibValueError, match="invalid p2wpkh-p2sh address: "):
        bms.assert_as_valid(msg, b58_p2wpkh_p2sh, sig1)
    assert not bms.verify(msg, b58_p2wpkh_p2sh, sig1)
    # False for BIP137 p2wpkh
    with pytest.raises(BTClibValueError, match="invalid p2wpkh address: "):
        bms.assert_as_valid(msg, b32_p2wpkh, sig1)
    assert not bms.verify(msg, b32_p2wpkh, sig1)

    # wif2 is the uncompressed spelling of wif, so neither address is the
    # other key's: one mismatch, reported once. The uncompressed key used
    # to answer "not a private or compressed public key for mainnet",
    # raised out of the p2wpkh_p2sh BIP137 tries before giving up
    err_msg = "mismatch between private key and address"
    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif2), b58_p2pkh_compressed)

    with pytest.raises(BTClibValueError, match=err_msg):
        bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2pkh_uncompressed)


def test_msgsign_p2pkh() -> None:
    """Reproduce Core's signatures, compressed and uncompressed keys."""
    msg = b"test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    q = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

    # uncompressed
    wif1u = b58.wif_from_prv_key(q, "mainnet", False)
    assert wif1u == "5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw"
    add1u = b58.p2pkh(wif1u)
    assert add1u == "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    bms_sig1u = bms.sign(msg, b58.prv_key_data_from_wif(wif1u))
    assert bms.verify(msg, add1u, bms_sig1u)
    assert bms_sig1u.rf == 27
    exp_sig1u = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert bms_sig1u.b64encode() == exp_sig1u

    # compressed
    wif1c = b58.wif_from_prv_key(q, "mainnet", True)
    assert wif1c == "L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk"
    add1c = b58.p2pkh(wif1c)
    assert add1c == "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    bms_sig1c = bms.sign(msg, b58.prv_key_data_from_wif(wif1c))
    assert bms.verify(msg, add1c, bms_sig1c)
    assert bms_sig1c.rf == 31
    exp_sig1c = "H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
    assert bms_sig1c.b64encode() == exp_sig1c

    assert not bms.verify(msg, add1c, bms_sig1u)
    assert not bms.verify(msg, add1u, bms_sig1c)

    bms_sig = bms.Sig(bms_sig1c.rf + 1, bms_sig1c.dsa_sig)
    assert not bms.verify(msg, add1c, bms_sig)

    # malleate s
    s = ec.n - bms_sig1c.dsa_sig.s
    dsa_sig = dsa.Sig(bms_sig1c.dsa_sig.r, s, bms_sig1c.dsa_sig.ec)
    # without updating rf the signature opens to a different key
    bms_sig = bms.Sig(bms_sig1c.rf, dsa_sig)
    assert not bms.verify(msg, add1c, bms_sig)

    # update rf to satisfy above malleation, and it is accepted
    i = 1 if bms_sig1c.rf % 2 else -1
    bms_sig = bms.Sig(bms_sig1c.rf + i, dsa_sig)
    assert bms.verify(msg, add1c, bms_sig)


def test_msgsign_p2pkh_2() -> None:
    """Reproduce Core's signatures, with and without a named address."""
    msg = b"test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    # compressed
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
    exp_sig = "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif), address)
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
    # uncompressed
    address = "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T"
    exp_sig = "HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif), address)
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig


def test_verify_p2pkh() -> None:
    """Verify published p2pkh signatures, surrounding spaces included."""
    msg = b"Hello, world!"
    address = "1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG"
    exp_sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = b"test message"
    address = "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    exp_sig = "IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = b"test message"
    address = "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    exp_sig = "G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_signmessage.py
    address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
    msg = address.encode()
    exp_sig = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
    msg = b"test message"
    address = "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce"
    exp_sig = "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50="
    assert bms.verify(msg, address, exp_sig)

    msg = b"test message 2"
    assert not bms.verify(msg, address, exp_sig)

    msg = b"freenode:#bitcoin-otc:b42f7e7ea336db4109df6badc05c6b3ea8bfaa13575b51631c5178a7"
    address = "1GdKjTSg2eMyeVvPV5Nivo6kR8yP2GT7wF"
    exp_sig = "GyMn9AdYeZIPWLVCiAblOOG18Qqy4fFaqjg5rjH6QT5tNiUXLS6T2o7iuWkV1gc4DbEWvyi8yJ8FvSkmEs3voWE="
    assert bms.verify(msg, address, exp_sig)

    msg = b"testtest"
    address = "1Hpj6xv9AzaaXjPPisQrdAD2tu84cnPv3f"
    exp_sig = "INEJxQnSu6mwGnLs0E8eirl5g+0cAC9D5M7hALHD9sK0XQ66CH9mas06gNoIX7K1NKTLaj3MzVe8z3pt6apGJ34="
    assert bms.verify(msg, address, exp_sig)

    msg = b"testtest"
    address = "18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX"
    exp_sig = "IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc="
    assert bms.verify(msg, address, exp_sig)

    msg = b"testtest"
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
    """Reproduce Electrum and BIP137 signatures for segwit addresses."""
    msg = b"test"
    wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
    b58_p2pkh = b58.p2pkh(wif)
    b32_p2wpkh = b32.p2wpkh(b58.prv_key_data_from_wif(wif).pub.sec)
    b58_p2wpkh_p2sh = b58.p2wpkh_p2sh(wif)

    # p2pkh base58 address (Core, Electrum, BIP137)
    exp_sig = "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b58_p2pkh, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))  # no address: p2pkh assumed
    assert bms.verify(msg, b58_p2pkh, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # p2wpkh-p2sh base58 address (Electrum)
    assert bms.verify(msg, b58_p2wpkh_p2sh, bms_sig)

    # p2wpkh bech32 address (Electrum)
    assert bms.verify(msg, b32_p2wpkh, bms_sig)

    # p2wpkh-p2sh base58 address (BIP137)
    # different first letter in bms_sig because of different rf
    exp_sig = "JBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b58_p2wpkh_p2sh, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif), b58_p2wpkh_p2sh)
    assert bms.verify(msg, b58_p2wpkh_p2sh, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # p2wpkh bech32 address (BIP137)
    # different first letter in bms_sig because of different rf
    exp_sig = "KBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="
    assert bms.verify(msg, b32_p2wpkh, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif), b32_p2wpkh)
    assert bms.verify(msg, b32_p2wpkh, bms_sig)
    assert bms_sig.b64encode() == exp_sig


def test_sign_strippable_message() -> None:
    """Reproduce Core's signatures for messages Electrum would strip."""
    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"

    msg = b""
    exp_sig = "IFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = b" "
    exp_sig = "IEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = b"  "
    exp_sig = "H/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    msg = b"test"
    exp_sig = "IJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = b" test "
    exp_sig = "IA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = b"test "
    exp_sig = "IPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = b" test"
    exp_sig = "H1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo="
    assert bms.verify(msg, address, exp_sig)
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    assert bms.verify(msg, address, bms_sig)
    assert bms_sig.b64encode() == exp_sig


# all 200 of the file, not a slice: the file is the only place these
# addresses appear, so a vector left out is proved by nothing else. They
# cost a signature each -- the price of a vendored vector being able to
# report a regression at all
PYTHON_BITCOINLIB_VECTORS = [
    pytest.param(vector, id=vector_id(index, vector["address"]))
    for index, vector in enumerate(load("ecc", "_data", "signmessage.json"))
]


@pytest.mark.parametrize("vector", PYTHON_BITCOINLIB_VECTORS)
def test_vector_python_bitcoinlib(vector: dict[str, Any]) -> None:
    """Test python-bitcoinlib test vectors.

    `signmessage.json` is upstream's own name for it,
    `bitcoin/tests/data/signmessage.json`; tests/_data/README.md pins
    the revision.
    """
    msg = vector["address"].encode()

    # btclib self-consistency check
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(vector["wif"]))
    assert bms.verify(msg, vector["address"], bms_sig)
    bms_sig_encoded = bms_sig.b64encode()
    assert bms.verify(msg, vector["address"], bms_sig_encoded)

    # Core/Electrum/btclib provide identical signature
    # they use "low-s" canonical signature
    assert bms_sig.dsa_sig.s < ec.n - bms_sig.dsa_sig.s

    # python-bitcoinlib provides a valid signature
    # but does not respect low-s, and it is accepted all the same: this
    # is the disagreement with Core's verifymessage that issue 645
    # measured over all 200 of these vectors, and issue 695 settled
    assert bms.verify(msg, vector["address"], vector["signature"])

    # python-bitcoinlib has a signature different from Core/Electrum/btclib
    assert bms_sig_encoded != vector["signature"]

    # but the reason is not the low-s
    # here's the malleated Core/Electrum/btclib signature
    s = ec.n - bms_sig.dsa_sig.s
    dsa_sig = dsa.Sig(bms_sig.dsa_sig.r, s, bms_sig.dsa_sig.ec)
    # properly malleated fixing also rf
    i = 1 if bms_sig.rf % 2 else -1
    bms_sig_malleated = bms.Sig(bms_sig.rf + i, dsa_sig)
    assert bms.verify(msg, vector["address"], bms_sig_malleated)
    bms_sig_encoded = bms_sig_malleated.b64encode()
    assert bms.verify(msg, vector["address"], bms_sig_encoded)

    # the malleated signature is still not equal to the python-bitcoinlib one
    assert bms_sig_encoded != vector["signature"]

    # python-bitcoinlib does not use RFC6979 deterministic nonce
    # as proved by different r compared to Core/Electrum/btclib
    test_vector_sig = bms.Sig.b64decode(vector["signature"])
    assert bms_sig.dsa_sig.r != test_vector_sig.dsa_sig.r


def test_the_file_carries_the_high_s_vectors_the_case_rests_on() -> None:
    """88 of the 200 are high-s, which is what the test above rests on.

    That test accepts every vector, and would keep saying so over a file
    of low-s signatures alone: what makes it evidence about the low-s
    rule is that part of the file is the case in dispute. So the split is
    measured here rather than assumed, and the count is a property of the
    vendored file -- `tests/_data/README.md` pins its revision -- and not
    of this tree.

    88 is the size of the interoperability gap issue 695 measured against
    a node: Bitcoin Core v31.1.0's `verifymessage` answers true for all
    200 of these, and these 88 are the ones btclib refused.
    """
    high_s = 0
    for vector in load("ecc", "_data", "signmessage.json"):
        sig = bms.Sig.b64decode(vector["signature"])
        high_s += sig.dsa_sig.s > ec.n - sig.dsa_sig.s
    assert high_s == 88


def test_ledger() -> None:
    """Hybrid ECDSA Bitcoin message signature generated by Ledger."""
    mnemonic = (
        "barely sun snack this snack relief pipe attack disease boss enlist lawsuit"
    )

    # non-standard leading 31 in DER serialization
    derivation_path = "m/1"
    msg = b"\xfb\xa3\x1f\x8cd\x85\xe29#K\xb3{\xfd\xa7<?\x95oL\xee\x19\xb2'oh\xa7]\xd9A\xfeU\xd8"
    dersig_hex_str = "3144022012ec0c174936c2a46dc657252340b2e6e6dd8c31dd059b6f9f33a90c21af2fba022030e6305b3ccf88009d419bf7651afcfcc0a30898b93ae9de9aa6ac03cf8ec56b"

    # pub_key derivation
    rprv = bip39.mxprv_from_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)

    # the actual message being signed
    magic_msg = magic_message(msg)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig_hex_str)
    key_id = dersig[0]
    dsa_sig = dsa.Sig.parse(b"\x30" + dersig[1:])

    # ECDSA signature verification of the patched dersig;
    # the xpub, verification taking public keys alone
    xpub = bip32.xpub_from_xprv(xprv)
    dsa.assert_as_valid(magic_msg, xpub, dsa_sig)
    assert dsa.verify(magic_msg, xpub, dsa_sig)

    # compressed address
    addr = b58.p2pkh(xprv)

    # equivalent Bitcoin Message Signature
    rec_flag = 27 + 4 + (key_id & 0x01)
    bms_sig = bms.Sig(rec_flag, dsa_sig)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg, addr, bms_sig)
    assert bms.verify(msg, addr, bms_sig)
    assert not bms.verify(magic_msg, addr, bms_sig)

    bms.sign(msg, PrvKeyData(*prv_keyinfo_from_prv_key(xprv)))

    # standard leading 30 in DER serialization
    derivation_path = "m/0/0"
    msg_str = b"hello world"
    dersig_hex_str = "3045022100967dac3262b4686e89638c8219c5761017f05cd87a855edf034f4a3ec6b59d3d0220108a4ef9682b71a45979d8c75c393382d9ccb8eb561d73b8c5fc0b87a47e7d27"

    # pub_key derivation
    rprv = bip39.mxprv_from_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)

    # the actual message being signed
    magic_msg = magic_message(msg_str)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig_hex_str)
    key_id = dersig[0]
    dsa_sig = dsa.Sig.parse(b"\x30" + dersig[1:])

    # ECDSA signature verification of the patched dersig;
    # the xpub, verification taking public keys alone
    xpub = bip32.xpub_from_xprv(xprv)
    dsa.assert_as_valid(magic_msg, xpub, dsa_sig)
    assert dsa.verify(magic_msg, xpub, dsa_sig)

    # compressed address
    addr = b58.p2pkh(xprv)

    # equivalent Bitcoin Message Signature
    rec_flag = 27 + 4 + (key_id & 0x01)
    bms_sig = bms.Sig(rec_flag, dsa_sig)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg_str, addr, bms_sig)
    assert bms.verify(msg_str, addr, bms_sig)
    assert not bms.verify(magic_msg, addr, bms_sig)


def test_recover_pub_key_input_type() -> None:
    """Verify recovery takes a Sig object or its serialization alike."""
    msg = b"test message"
    wif, _ = bms.gen_keys()
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))

    key_id = bms_sig.rf - 27 & 0b11
    magic_msg = magic_message(msg)
    Q = dsa.recover_pub_key(key_id, magic_msg, bms_sig.dsa_sig.serialize(), sha256)
    Q2 = dsa.recover_pub_key(key_id, magic_msg, bms_sig.dsa_sig, sha256)
    assert Q == Q2


def test_the_recovery_flag_carries_a_key_id_not_a_list_index() -> None:
    """`sign` searches the key_ids rather than indexing the recovered list.

    `dsa.recover_pub_keys(...).index(Q)` is the key_id only while no
    earlier candidate has dropped out of that list, and a candidate drops
    whenever its x-coordinate is not on the curve. So the property to pin
    is the round trip: the key_id read back out of rf recovers the signing
    key, whatever else the recovery set holds.
    """
    for i in range(8):
        msg = f"message {i}".encode()
        prv_key, pub_key = dsa.gen_keys()
        bms_sig = bms.sign(msg, PrvKeyData(prv_key))
        magic_msg = magic_message(msg)
        key_id = bms_sig.rf - 27 & 0b11
        assert dsa.recover_pub_key(key_id, magic_msg, bms_sig.dsa_sig) == pub_key
        # and it is the *first* key_id that does, which is what makes the
        # flag reproducible: signing the same message twice with the same
        # key gives the same rf only because the search order is fixed
        earlier = [
            k
            for k in range(key_id)
            if _recovers(k, magic_msg, bms_sig.dsa_sig) == pub_key
        ]
        assert not earlier


def _recovers(key_id: int, magic_msg: bytes, dsa_sig: dsa.Sig) -> Point | None:
    with contextlib.suppress(BTClibValueError, BTClibRuntimeError):
        return dsa.recover_pub_key(key_id, magic_msg, dsa_sig)
    return None


def _search_key_id(magic_msg: bytes, dsa_sig: dsa.Sig, q: int) -> int:
    """Return the first key_id that recovers the public key of q.

    The key_id arrived at from the other side: by recovering candidate
    after candidate and comparing, where a signer reads it off the nonce's
    point. That is what makes it a cross-check of `dsa.sign_recoverable`,
    and it lives here because the library has no other caller for it --
    the search is what the recoverable spelling exists not to run.
    """
    Q = mult(q)
    for key_id in range(2 * (secp256k1.cofactor + 1)):
        # a candidate can fail either half of SEC 1 v.2 step 1.6, which
        # means "not this one" and not "no key": see dsa._recover_pub_keys_
        if _recovers(key_id, magic_msg, dsa_sig) == Q:
            return key_id

    raise AssertionError("no key_id recovers the public key")


def test_the_key_id_search_reports_a_key_it_cannot_reach() -> None:
    """The helper above raises rather than answer, and this is why it can.

    The counterpart of `test_a_key_id_that_recovers_nothing` below: that
    one is a candidate recovering *no* key, this one is every candidate
    recovering a key that is not the one asked for. Untested, the
    fallthrough would be the single line of the cross-check that never
    runs -- and a search answering 0 for a key it never found would make
    the callers above agree with the recovery flag for the wrong reason.
    """
    msg = b"a message"
    wif, _addr = bms.gen_keys()
    bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    magic_msg = magic_message(msg)

    # somebody else's private key: the signature is valid, and none of its
    # candidates recovers this q's public key
    other_wif, _other_addr = bms.gen_keys()
    other_q = b58.prv_key_data_from_wif(other_wif).q

    err_msg = "no key_id recovers the public key"
    with pytest.raises(AssertionError, match=err_msg):
        _search_key_id(magic_msg, bms_sig.dsa_sig, other_q)


def test_a_key_id_that_recovers_nothing() -> None:
    """The dropped candidate, which is why the helper above returns None.

    On secp256k1 the recovery set is key_ids 0 and 1: those take x = r,
    while 2 and 3 take x = r + n, which exceeds p unless r < p - n --
    about one r in 2^127 -- so they raise rather than answer. That is the
    candidate `recover_pub_keys` drops from its list, and dropping it is
    what makes `.index` the wrong question for the recovery flag.
    """
    msg = b"a message"
    prv_key, pub_key = dsa.gen_keys()
    bms_sig = bms.sign(msg, PrvKeyData(prv_key))
    magic_msg = magic_message(msg)

    assert _recovers(bms_sig.rf - 27 & 0b11, magic_msg, bms_sig.dsa_sig) == pub_key
    for key_id in (2, 3):
        assert _recovers(key_id, magic_msg, bms_sig.dsa_sig) is None
        # either exception, which is why the helper suppresses both: the
        # wrapped x may miss the curve, and BTClibValueError comes out of
        # y_even_var, or it may land on it and recover a key that does not
        # verify, which is the BTClibRuntimeError
        with pytest.raises((BTClibValueError, BTClibRuntimeError)):
            dsa.recover_pub_key(key_id, magic_msg, bms_sig.dsa_sig)


def test_recoverable_signing_answers_the_key_id_the_search_finds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key_id `sign` reports is the one a search finds, r and s too.

    `sign` reads the key_id off the signature it just made instead of
    signing and then recovering candidate after candidate until one is the
    signer's own key. The key_id is the same thing arrived at from the other
    side -- the parity of the nonce's point and whether its x-coordinate
    exceeded the group order, both of which the signer had in hand -- so
    what has to hold is that the two name one signature, r, s and key_id
    all three.

    Held over random pairs and not fixed vectors, r and s being what
    RFC6979 makes of each: the fixed vectors are the base64 signatures of
    the tests above, which this reproduces through
    `test_the_python_path_answers_the_same`.
    """
    for i in range(20):
        msg = f"message {i}".encode()
        wif, addr = bms.gen_keys()
        bms_sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))

        magic_msg = magic_message(msg)
        q = b58.prv_key_data_from_wif(wif).q
        # grind=False is what `sign_recoverable` does and cannot do
        # otherwise: a message signature is the fixed 65-byte compact form,
        # where a low r saves no DER pad, so there is nothing to grind for
        dsa_sig = dsa.sign(magic_msg, q, grind=False)
        assert bms_sig.dsa_sig == dsa_sig
        key_id = bms_sig.rf - 27 & 0b11
        assert key_id == _search_key_id(magic_msg, dsa_sig, q)
        # and the search asked of the implementation that did not report
        # the key_id, so that the two derivations are independent
        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(dsa, "_libsecp256k1_serves", lambda *_: False)
            assert key_id == _search_key_id(magic_msg, dsa_sig, q)

        bms.assert_as_valid(msg, addr, bms_sig)


# the sibling test functions are called rather than reimplemented, as
# tests/script_engine/python_path_test.py does with the vector walks: two
# copies of a vector drift, and what has to be identical between the two
# runs is precisely the vector -- only the implementation underneath
# differs. Which is what makes these the fixed vectors of the delegation:
# every base64 signature the tests below assert is a published one, from
# Core, Electrum, Ledger or BIP137, and the Python path has to produce and
# verify each of them exactly as the bindings do
@pytest.mark.parametrize(
    "vector_test",
    [
        test_signature,
        test_exceptions,
        test_one_prv_key_multiple_addresses,
        test_msgsign_p2pkh,
        test_msgsign_p2pkh_2,
        test_verify_p2pkh,
        test_segwit,
        test_sign_strippable_message,
        test_ledger,
        test_the_recovery_flag_carries_a_key_id_not_a_list_index,
        test_a_key_id_that_recovers_nothing,
    ],
    ids=lambda vector_test: vector_test.__name__,
)
def test_the_python_path_answers_the_same(
    vector_test: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run the fixed-vector tests again with the dispatch patched off.

    bms is secp256k1 only, so nothing else keeps its Python path reached.

    Unlike taproot or ECDH there is no second curve to fall back for, and
    no message length the bindings decline: `Sig.assert_valid` refuses any
    other curve, so in production the dispatch always answers yes. The
    Python implementation stays as the reference the delegation is held
    against, and this is what reaches it.

    The switch rather than a patch per module, because signing and
    verifying ask in different places: `dsa.sign_recoverable` under
    `sign` asks for itself, while `assert_as_valid` asks in `bms` before
    it recovers. Clearing `_libsecp256k1_available` reaches both, where
    naming one module would leave the other delegated.
    """
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(curve, "_libsecp256k1_available", False)
        vector_test()


@needs_bindings
def test_the_py_arm_reaches_no_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recovery gated on availability alone must be Python throughout.

    A mixed arm is the one shape that is never right: with libsecp256k1 in
    reach `_libsecp256k1_recover_sec_` is the better call, and out of
    reach there is nothing to mix. `assert_as_valid`'s guard picks between
    that and `dsa.recover_pub_key(..., sha256)` for its Python arm, itself
    a dispatch on the same predicate rather than a call that could
    delegate on its own.

    `no_bindings_anywhere` is the check `tests.bip32.bip32_test` and
    `tests.script.taproot_test` use for the same shape: it puts the whole
    of btclib_secp256k1 out of reach, module and already-bound name alike,
    and switches the dispatch off -- which `dsa.recover_pub_key`'s own
    guard then reads the same way `assert_as_valid`'s does, so the walk
    covering `_libsecp256k1_recover_sec_` covers this arm's delegate too.
    """
    wif, addr = bms.gen_keys()
    msg = b"a message signed once and recovered from twice"
    sig = bms.sign(msg, b58.prv_key_data_from_wif(wif))
    # what the bindings answer, taken while they are still in reach
    delegated = bms.verify(msg, addr, sig)
    assert delegated

    no_bindings_anywhere(monkeypatch)

    # what bms itself would have called, so that a walk reaching nothing
    # would fail here rather than pass by touching nothing
    with pytest.raises(AssertionError, match="reached libsecp256k1"):
        libsecp256k1_recovery.recover(bytes(32), bytes(64), 0, True)

    assert bms.verify(msg, addr, sig) == delegated


def test_parse_length_is_not_a_validity_opinion() -> None:
    """65 bytes is what makes the [rf][r][s] slices mean anything.

    The check must hold under check_validity=False too: skipped, a short
    buffer still produces a Sig, r and s coming from truncated slices,
    and every input sharing a prefix collapses onto the same signature.
    """
    wif, _ = bms.gen_keys()
    sig_bin = bms.sign(b"test", b58.prv_key_data_from_wif(wif)).serialize()

    for length in (0, 1, 33, 64):
        err_msg = f"invalid decoded length: {length} instead of 65"
        for check_validity in (True, False):
            with pytest.raises(BTClibValueError, match=err_msg):
                bms.Sig.parse(sig_bin[:length], check_validity=check_validity)

    # and the other half of the same rule: octets are one whole
    # signature, so what follows it in them is refused rather than
    # dropped -- 66 bytes would otherwise be the signature of the 65
    for check_validity in (True, False):
        with pytest.raises(BTClibValueError, match="1 bytes after the signature"):
            bms.Sig.parse(sig_bin + b"\x00", check_validity=check_validity)


def test_b64decode_rejects_what_is_not_base64() -> None:
    """Guard against b64decode discarding what is not in the alphabet.

    That would make a signature reachable from unboundedly many strings,
    the one thing a signature encoding must not allow.
    """
    wif, _ = bms.gen_keys()
    b64_sig = bms.sign(b"test", b58.prv_key_data_from_wif(wif)).b64encode()
    assert bms.Sig.b64decode(b64_sig).b64encode() == b64_sig

    # surrounding whitespace stays tolerated, being what a copied and
    # pasted signature carries
    assert bms.Sig.b64decode(f"  {b64_sig}\n").b64encode() == b64_sig
    assert bms.Sig.b64decode(f" {b64_sig} ".encode()).b64encode() == b64_sig

    err_msg = "invalid base64 encoding: "
    for junk in ("!", "-", " ", "\n"):
        # inserted mid-string, where a strip cannot reach it
        bad_sig = b64_sig[:40] + junk + b64_sig[40:]
        with pytest.raises(BTClibValueError, match=err_msg):
            bms.Sig.b64decode(bad_sig)


def test_b64decode_requires_the_canonical_encoding() -> None:
    """One signature, one string.

    65 bytes take 88 base64 characters, the last data one carrying 4
    significant bits and 2 that are discarded: four distinct strings
    decode to the very same signature. validate=True does not
    see that, and what it makes of padding varies with the interpreter
    in both directions -- 3.11 takes an excess pad that 3.10 and 3.14
    refuse, 3.14 refuses one that they take -- so what settles it
    everywhere is requiring the encoding b64encode gives back.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    wif, _ = bms.gen_keys()
    b64_sig = bms.sign(b"test", b58.prv_key_data_from_wif(wif)).b64encode()
    assert len(b64_sig) == 88

    err_msg = "invalid base64 encoding: not canonical"
    i = alphabet.index(b64_sig[86])
    for discarded_bits in (1, 2, 3):
        malleated = b64_sig[:86] + alphabet[i ^ discarded_bits] + b64_sig[87:]
        assert malleated != b64_sig
        # the same signature, spelled otherwise
        assert base64.b64decode(malleated) == base64.b64decode(b64_sig)
        with pytest.raises(BTClibValueError, match=err_msg):
            bms.Sig.b64decode(malleated)


def test_a_drawn_key_takes_the_network_it_is_asked_for() -> None:
    """`gen_keys(network)` draws on that network's curve.

    Every other call above leaves the argument out, so `"mainnet"` was
    the only default through the draw and the branch that keeps the
    caller's own name never ran. What the name decides is the WIF prefix
    and the address version, which is what is checked here: the curve is
    secp256k1 on either network, so nothing else would say the argument
    had been read.
    """
    wif, addr = bms.gen_keys("testnet")

    assert b58.prv_key_data_from_wif(wif).network == "testnet"
    assert addr == b58.p2pkh(wif)
    # and the default, which is the same call with the name left out
    assert b58.prv_key_data_from_wif(bms.gen_keys()[0]).network == "mainnet"
