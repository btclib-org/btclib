# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.obfuscation` module.

Core's own vectors are from `src/test/streams_tests.cpp` at Bitcoin Core
v31.1 (9be056a8a7), cited by line where each is used.
"""

from io import BytesIO
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import obfuscation, var_int
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import Tx

_KEYS = st.binary(min_size=8, max_size=8)
_TX_IDS = (
    "8c41c9bf265f2a920c43ecb9f75c8f59d65a6d752b2e938065c38e41c79f6351",
    "262ebb77943e69322b596bd6b2952ba7ef8b371456c4d1d5385d4fac04b2e479",
)

# `savemempool` on bitcoind v31.1.0, regtest, with two wallet transactions
# in the mempool (the two of `_TX_IDS`, in the file's order)
_MEMPOOL_DAT = bytes.fromhex(
    "02000000000000000896a96b1dca823163ab6b1dca82316396ab6b1dca823062"
    "36c2e2a0102d59f1ba85eb47e3aad2a55a64a7feaa021ddd2ebaa7e1c0fd3c60"
    "96a96b1dca7fce9c69ab6bfc3f87316396a97d1dde41e7ceebea48e243fdea46"
    "a257b6bce53416639f556e0dee83316396bf6b09a2df10000913be1e8be6e6a2"
    "27179300e0155f5894ee5b59c8a234a2fe6f4ee4c6ba06f55b7dea6c5f426b00"
    "8ecf018965aea1d85a51a8c743753343ad1cbe627dcf476dcd306aedc5b05392"
    "6535b6a9a8791ce8653dd7fb80709a01978869e3e90c16556a22ce98accdc618"
    "229cae70de92e3fb1cfbe702846ca42154f2ed78ca8231e8bc6f011dca823163"
    "96a96b1dca82316196a96b1dcb836000096e2a9309e7b1f0b8821e70905468ec"
    "ca5ed2f1898ea349c98fd4d48b0e306396a96be0357dce616e914f05cb823163"
    "80a97f9947ac658bbcbfd7f575f9adc49b21f1f8e5ef56635442601dca823175"
    "96bda8cb67ff7240692014c6efb6cfbe3786dd3aca8b3324a6ed693db7c3a4bc"
    "59d8d7bc16a7c2906bfac47f9bbff1c49889ac93519bd5026c54fe93c8a263b1"
    "d3ee2adf7e28b71fd9c0315d649708ae1565e0a42304cf1ab67c1b94c50e3042"
    "94a898db3be64033589f641a17cf1737d8b120aa06188e27e16441b8ce9f9563"
    "b8cc6b1dca091ba5fca96b1dca82316396a96b1dca823332f536ac5c444154e3"
    "05874068a7d8e73a19f59ca426c13df1bcf64da203c3bd1a721b6fb185df09b6"
    "476d3d09fd09dec4bd3cd9cba1db1a51ff97ff6a71ac17"
)


def test_streams_serializedata_xor() -> None:
    """`streams_serializedata_xor`, streams_tests.cpp lines 303-325."""
    # lines 306-308: the empty stream, with the null key
    assert obfuscation.obfuscate(b"", bytes(8)) == b""
    # lines 311-316
    assert obfuscation.obfuscate("0ff0", "ff" * 8) == bytes.fromhex("f00f")
    # lines 319-324
    assert obfuscation.obfuscate("f00f", "ff0fff0fff0fff0f") == bytes.fromhex("0f00")


def test_xor_file() -> None:
    """`xor_file`, streams_tests.cpp lines 95-145: key, bytes on disk, reads.

    The file holds the vectors `[1, 2, 3]` and `[4, 5]`, each behind its
    compact size, written through the key `ff00ff00ff00ff00`.
    """
    key = "ff00ff00ff00ff00"
    plain = bytes.fromhex("03010203" + "020405")
    on_disk = bytes.fromhex("fc01fd03fd04fa")  # line 128
    assert obfuscation.obfuscate(plain, key) == on_disk
    assert obfuscation.obfuscate(on_disk, key) == plain
    # `ignore(4)`, then reading the second vector: the offset is 4
    assert obfuscation.obfuscate(on_disk[4:], key, offset=4) == plain[4:]


def test_null_key_is_the_identity() -> None:
    """An all-zero key obfuscates nothing (`Obfuscation::operator bool`)."""
    data = bytes(range(37))
    assert obfuscation.obfuscate(data, bytes(8), 5) == data


@pytest.mark.parametrize("offset", range(20))
def test_offsets_that_do_not_align_to_the_key_size(offset: int) -> None:
    """Byte `i` of a slice at `offset` meets `key[(offset + i) % 8]`."""
    key = bytes(range(1, 9))
    data = bytes(range(0x80, 0x80 + 21))
    expected = bytes(b ^ key[(offset + i) % 8] for i, b in enumerate(data))
    assert obfuscation.obfuscate(data, key, offset) == expected


@given(
    data=st.binary(max_size=200),
    key=_KEYS,
    offset=st.integers(min_value=0, max_value=2**64),
)
def test_round_trip(data: bytes, key: bytes, offset: int) -> None:
    """The same call obfuscates and de-obfuscates."""
    once = obfuscation.obfuscate(data, key, offset)
    assert len(once) == len(data)
    assert obfuscation.obfuscate(once, key, offset) == data


@given(data=st.binary(max_size=200), key=_KEYS, data_cuts=st.data())
def test_xor_random_chunks(data: bytes, key: bytes, data_cuts: st.DataObject) -> None:
    """`xor_random_chunks`, streams_tests.cpp lines 22-50.

    Obfuscating a file in pieces, each at its own offset, is obfuscating
    it whole, byte `i` meeting `key[i % 8]`.
    """
    pieces = []
    offset = 0
    while offset < len(data):
        size = data_cuts.draw(st.integers(1, len(data) - offset))
        pieces.append(obfuscation.obfuscate(data[offset : offset + size], key, offset))
        offset += size
    expected = bytes(b ^ key[i % 8] for i, b in enumerate(data))
    assert b"".join(pieces) == expected


def test_mempool_dat_from_bitcoind() -> None:
    """A v2 `mempool.dat` that bitcoind v31.1.0 wrote is read back.

    The payload starts at offset 17, which is not a multiple of eight. It
    holds a `u64` count, each transaction with its `i64` time and `i64`
    delta, the `var_int` count of the deltas of txids not held (none), and
    the unbroadcast set: a `var_int` count, then the txids in internal
    byte order. The parse reads the file to its last byte.
    """
    stream = BytesIO(_MEMPOOL_DAT)
    assert int.from_bytes(stream.read(8), "little") == 2
    key = obfuscation.parse_key(stream)
    offset = stream.tell()
    assert offset == 17
    assert key.hex() == "96a96b1dca823163"
    payload = BytesIO(obfuscation.obfuscate(stream.read(), key, offset))

    assert int.from_bytes(payload.read(8), "little") == len(_TX_IDS)
    for tx_id in _TX_IDS:
        assert Tx.parse(payload).id.hex() == tx_id
        payload.read(16)  # time and delta
    assert var_int.parse(payload) == 0
    assert var_int.parse(payload) == len(_TX_IDS)
    unbroadcast = payload.read()
    assert len(unbroadcast) == 32 * len(_TX_IDS)
    assert {unbroadcast[:32].hex(), unbroadcast[32:].hex()} == {
        bytes.fromhex(tx_id)[::-1].hex() for tx_id in _TX_IDS
    }


def test_key_serialization() -> None:
    """`obfuscation_serialize`, streams_tests.cpp lines 60-80: a vector of 8."""
    key = bytes(range(8))
    serialized = obfuscation.serialize_key(key)
    assert serialized == b"\x08" + key  # line 69: 1 + KEY_SIZE
    stream = BytesIO(serialized + b"tail")
    assert obfuscation.parse_key(stream) == key
    assert stream.read() == b"tail"


@pytest.mark.parametrize("size", [0, 7, 9, 32])
def test_parse_key_refuses_another_size(size: int) -> None:
    """`Obfuscation::Unserialize` throws unless the key is 8 bytes."""
    with pytest.raises(BTClibValueError, match="invalid key size"):
        obfuscation.parse_key(bytes([size]) + bytes(size))


@pytest.mark.parametrize("key", [b"", bytes(7), bytes(9), "00" * 7])
def test_key_of_another_size_is_refused(key: Any) -> None:
    """Both entry points hold the key to eight bytes."""
    with pytest.raises(BTClibValueError, match="invalid size"):
        obfuscation.obfuscate(b"data", key)
    with pytest.raises(BTClibValueError, match="invalid size"):
        obfuscation.serialize_key(key)


def test_offset_is_a_non_negative_integer() -> None:
    """A bool or a float is no offset, and a negative one reads no file."""
    for bad in (True, 1.0, "1"):
        with pytest.raises(BTClibTypeError, match="non-integer offset"):
            obfuscation.obfuscate(b"data", bytes(8), bad)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="negative offset"):
        obfuscation.obfuscate(b"data", bytes(8), -1)
