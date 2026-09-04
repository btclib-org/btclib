# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.minikey` module."""

from __future__ import annotations

import pytest

from btclib import minikey
from btclib.curves import secp256k1
from btclib.exceptions import BTClibTypeError, InvalidPrvKeyError, NotAPrvKeyError

ec = secp256k1


def test_prv_key_data_from_minikey() -> None:
    """Casascius's own published example, and electrum's.

    https://en.bitcoin.it/wiki/Mini_private_key_format (the 30-character
    example, with its embedded "_SAMPLE_..._" placeholders stripped) and
    tests/test_bitcoin.py (spesmilo/electrum, pinned at 342bca3a, the
    22-character `priv_pub_addr` row with `minikey: True`).
    Both keys are cross-checked independently against the WIF and the
    address each source publishes beside its minikey, ahead of this
    file: `sha256(minikey)` equals the WIF payload's key bytes, and
    hashing the electrum row's own uncompressed public key to a p2pkh
    address reproduces the address given there.
    """
    test_vectors = [
        (
            "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy",
            34592368842595783461480169529335747692719505392594229791591388717055904041387,
        ),
        (
            "SzavMBLoXU6kDrqtUVmffv",
            105627842363267744400190144423808258002852957479547731009248450467191077417570,
        ),
    ]
    for text, q in test_vectors:
        data = minikey.prv_key_data_from_minikey(text)
        assert (data.q, data.network, data.compressed) == (q, "mainnet", False)


def test_wrong_length() -> None:
    """Fewer than 20 characters: electrum's own floor, not a minikey shape."""
    with pytest.raises(
        NotAPrvKeyError, match="wrong minikey length: 19, at least 20 required"
    ):
        minikey.prv_key_data_from_minikey("SzavMBLoXU6kDrqtUVm")


def test_empty_string() -> None:
    """The same length check, at its most extreme."""
    with pytest.raises(
        NotAPrvKeyError, match="wrong minikey length: 0, at least 20 required"
    ):
        minikey.prv_key_data_from_minikey("")


def test_wrong_first_character() -> None:
    """Every minikey starts with 'S'; nothing else does."""
    with pytest.raises(NotAPrvKeyError, match="does not start with 'S'"):
        minikey.prv_key_data_from_minikey("TzavMBLoXU6kDrqtUVmffv")


def test_character_outside_alphabet() -> None:
    """'0' is one of the four look-alike characters base58 excludes."""
    with pytest.raises(NotAPrvKeyError, match="character outside the base58 alphabet"):
        minikey.prv_key_data_from_minikey("S0avMBLoXU6kDrqtUVmffv")


def test_failed_checksum() -> None:
    """Right shape, wrong typo check: a minikey with a fault in it.

    The electrum vector with its last character changed from 'v' to '1',
    still 22 base58 characters starting with 'S', but
    `sha256(text + "?")` no longer starts with a zero byte.
    """
    with pytest.raises(InvalidPrvKeyError, match="invalid minikey: failed checksum"):
        minikey.prv_key_data_from_minikey("SzavMBLoXU6kDrqtUVmff1")


def test_wrong_type() -> None:
    """A non-string input is the caller's own mistake, not a format guess."""
    with pytest.raises(BTClibTypeError, match="invalid minikey type: int"):
        minikey.prv_key_data_from_minikey(0)  # type: ignore[arg-type]


def test_out_of_range_scalar(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checksum-valid minikey whose derived scalar is out of range.

    Unlike a WIF, whose scalar is the payload and can be set directly,
    a minikey's scalar is `sha256(text)`: nothing in this module lets a
    caller choose it, and no real text produces one equal to `ec.n`. The
    branch is tripped by patching the hash rather than searched for:
    CONTRIBUTING.md's coverage rule takes 100% literally, so a statement
    no test reaches is either covered by patching what stands in the way
    -- as the ripemd160 fallback and electrum's round-trip check are --
    or marked `pragma: no cover` with the reason beside it.
    """
    good_minikey = "SzavMBLoXU6kDrqtUVmffv"
    bad_q = ec.n.to_bytes(32, byteorder="big")

    def fake_sha256(data: bytes) -> bytes:
        if data.endswith(b"?"):
            return b"\x00" * 32  # still passes the typo check
        return bad_q

    monkeypatch.setattr(minikey, "sha256", fake_sha256)
    with pytest.raises(InvalidPrvKeyError, match="private key not in 1..n-1"):
        minikey.prv_key_data_from_minikey(good_minikey)
