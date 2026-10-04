# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `sig_hash._SigHashCache`, the midstates of one input.

GHSA-rw95-w37r-537w: every signature check hashed the whole legacy
preimage anew. What is asserted is that a cached hash is the hash the
public functions compute, and that the preimage of an input is built
once for the checks that share a hash class and a script code. The
counts are of calls, not of seconds, which depend on the load.
"""

from collections.abc import Callable

import pytest
from btclib_ecc.ecc import dsa

from btclib.hashes import hash160
from btclib.key import PrvKeyData
from btclib.script import ScriptPubKey, Witness, sig_hash
from btclib.script.engine import ALL_FLAGS, verify_input
from btclib.script.script import serialize
from btclib.script.sig_hash import _legacy, _segwit_v0, _SigHashCache
from btclib.tx import OutPoint, Tx, TxIn, TxOut

PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
PUB_KEY = PrvKeyData(PRV_KEY).pub

CHECKS = 15
# each check but the last leaves its operands for the next one
SCRIPT = b"\x6e\xad" * (CHECKS - 1) + b"\xac"

# every class of hash type, one undefined member of each, and a word
# wider than a byte
HASH_TYPES = [
    0x01,
    0x00,
    0x04,
    0x02,
    0x03,
    0x81,
    0x82,
    0x83,
    0x42,
    0x43,
    0xC2,
    0xC3,
    0x80,
    0xFFFFFFFF,
    -1,
]

Hasher = Callable[[bytes, int], bytes]
CachedHasher = Callable[[bytes, int, _SigHashCache], bytes]


def tx_of(inputs: int, outputs: int) -> Tx:
    """Build a transaction of the given shape, nothing signed."""
    vin = [
        TxIn(OutPoint(i.to_bytes(32, "big"), 0), b"", 0xFFFFFFFF, Witness())
        for i in range(inputs)
    ]
    spk = ScriptPubKey.p2wpkh(PUB_KEY)
    vout = [TxOut(1_000 + j, spk) for j in range(outputs)]
    return Tx(2, 0, vin, vout, check_validity=False)


class Counter:
    """Count the calls of a function of `sig_hash`."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls = 0
        function = getattr(sig_hash, name)

        def counted(*args: object, **kwargs: object) -> object:
            self.calls += 1
            return function(*args, **kwargs)

        monkeypatch.setattr(sig_hash, name, counted)


def legacy_pair(tx: Tx, vin_i: int) -> tuple[Hasher, CachedHasher]:
    """Return the public `legacy` and the cached one, over one input."""

    def public(script_code: bytes, hash_type: int) -> bytes:
        return sig_hash.legacy(script_code, tx, vin_i, hash_type)

    def cached(script_code: bytes, hash_type: int, cache: _SigHashCache) -> bytes:
        return _legacy(script_code, tx, vin_i, hash_type, cache)

    return public, cached


def segwit_v0_pair(tx: Tx, vin_i: int) -> tuple[Hasher, CachedHasher]:
    """Return the public `segwit_v0` and the cached one, over one input."""

    def public(script_code: bytes, hash_type: int) -> bytes:
        return sig_hash.segwit_v0(script_code, tx, vin_i, hash_type, 5_000)

    def cached(script_code: bytes, hash_type: int, cache: _SigHashCache) -> bytes:
        return _segwit_v0(script_code, tx, vin_i, hash_type, 5_000, None, cache)

    return public, cached


@pytest.mark.parametrize("pair", [legacy_pair, segwit_v0_pair])
@pytest.mark.parametrize("vin_i", [0, 1, 2])
def test_a_cached_hash_is_the_hash_of_the_public_functions(
    pair: Callable[[Tx, int], tuple[Hasher, CachedHasher]], vin_i: int
) -> None:
    """Hash types and script codes interleave, one cache serving them all."""
    public, cached = pair(tx_of(3, 2), vin_i)
    cache = _SigHashCache()
    for _ in range(2):
        for script_code in [SCRIPT, b"\xab" + SCRIPT, b"\xac"]:
            for hash_type in HASH_TYPES:
                expected = public(script_code, hash_type)
                assert cached(script_code, hash_type, cache) == expected
                assert cached(script_code, hash_type, cache) == expected


def test_the_legacy_preimage_is_built_once_per_class_and_script_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repeated check costs nothing; a new class or script code does."""
    tx = tx_of(1, 1)
    built = Counter(monkeypatch, "_legacy_tx_copy")
    cache = _SigHashCache()

    for hash_type in [0x01, 0x01, 0x05, 0x01]:  # one class, ALL
        _legacy(SCRIPT, tx, 0, hash_type, cache)
    assert built.calls == 1

    for hash_type in [0x02, 0x02]:  # NONE: its own slot
        _legacy(SCRIPT, tx, 0, hash_type, cache)
    assert built.calls == 2

    _legacy(SCRIPT, tx, 0, 0x01, cache)  # the ALL slot still holds
    assert built.calls == 2

    _legacy(b"\xac", tx, 0, 0x01, cache)  # another script code replaces it
    _legacy(SCRIPT, tx, 0, 0x01, cache)
    assert built.calls == 4


def test_a_midstate_of_one_era_is_not_served_to_the_other() -> None:
    """The same script code and hash class, a legacy and a v0 preimage."""
    tx = tx_of(1, 1)
    cache = _SigHashCache()
    legacy_hash = _legacy(SCRIPT, tx, 0, 1, cache)
    v0_hash = _segwit_v0(SCRIPT, tx, 0, 1, 5_000, None, cache)
    assert legacy_hash == sig_hash.legacy(SCRIPT, tx, 0, 1)
    assert v0_hash == sig_hash.segwit_v0(SCRIPT, tx, 0, 1, 5_000)
    assert legacy_hash != v0_hash


def test_the_single_bug_is_answered_through_the_cache() -> None:
    """An input with no output to match signs the constant, cached or not."""
    tx = tx_of(2, 1)
    cache = _SigHashCache()
    for _ in range(2):
        assert _legacy(SCRIPT, tx, 1, 3, cache) == (256**31).to_bytes(32, "big")


def signed_legacy_tx() -> tuple[Tx, list[TxOut]]:
    """Build a p2sh transaction whose redeem script checks CHECKS times."""
    redeem = SCRIPT
    spk = ScriptPubKey(b"\xa9\x14" + hash160(redeem) + b"\x87", "mainnet")
    prevouts = [TxOut(100_000, spk)]
    tx = tx_of(1, 1)
    msg_hash = sig_hash.legacy(redeem, tx, 0, 1)
    signature = dsa.sign_(msg_hash, PRV_KEY).serialize() + b"\x01"
    tx.vin[0].script_sig = serialize([signature, PUB_KEY.sec, redeem])
    return tx, prevouts


def test_verifying_an_input_builds_the_legacy_preimage_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The checks of a p2sh input share one preimage, and all verify."""
    tx, prevouts = signed_legacy_tx()
    built = Counter(monkeypatch, "_legacy_tx_copy")

    verify_input(prevouts, tx, 0, ALL_FLAGS)

    assert built.calls == 1


def signed_p2wsh_tx() -> tuple[Tx, list[TxOut]]:
    """Build a p2wsh transaction whose witness script checks CHECKS times."""
    spk = ScriptPubKey.p2wsh(SCRIPT)
    prevouts = [TxOut(100_000, spk)]
    tx = tx_of(1, 1)
    msg_hash = sig_hash.segwit_v0(SCRIPT, tx, 0, 1, 100_000)
    signature = dsa.sign_(msg_hash, PRV_KEY).serialize() + b"\x01"
    tx.vin[0].script_witness = Witness([signature, PUB_KEY.sec, SCRIPT])
    return tx, prevouts


def test_verifying_an_input_builds_the_segwit_v0_preimage_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without `PrecomputedTxData` the preimage hashes the prevouts per miss."""
    tx, prevouts = signed_p2wsh_tx()
    built = Counter(monkeypatch, "_serialized_prevouts")

    verify_input(prevouts, tx, 0, ALL_FLAGS)

    assert built.calls == 1
