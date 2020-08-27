#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.blocks` module."

import os

import pytest

from btclib.blocks import Block, BlockHeader


# actually second block in chain, first obtainable from other nodes
def test_block_1() -> None:

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = Block.deserialize(block_bytes)
    assert len(block.transactions) == 1
    assert block.serialize() == block_bytes

    header = block.header
    assert header.time == 1231469665  # 2009-01-09 03:54:25 GMT+1
    assert (
        header.merkleroot
        == "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )

    assert header.bits == 0x1D00FFFF .to_bytes(4, "big")
    assert header.nonce == 0x9962E301
    assert (
        header.hash
        == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    )

    assert block.size == 215
    assert block.weight == 536


# first block with a transaction
def test_block_170() -> None:

    fname = "block_170.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = Block.deserialize(block_bytes)
    assert len(block.transactions) == 2
    assert block.serialize() == block_bytes

    header = block.header
    assert header.time == 1231731025  # 2009-01-12 04:30:25 GMT+1
    assert (
        header.merkleroot
        == "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    )

    assert header.bits == 0x1D00FFFF .to_bytes(4, "big")
    assert header.nonce == 0x709E3E28
    assert (
        header.hash
        == "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
    )

    assert block.size == 490
    assert block.weight == 1636


def test_block_200000() -> None:

    fname = "block_200000.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = Block.deserialize(block_bytes)
    assert len(block.transactions) == 388
    assert block.serialize() == block_bytes

    header = block.header
    assert header.time == 1348310759  # 2012-09-22 12:45:59 GMT+2
    assert (
        header.merkleroot
        == "a08f8101f50fd9c9b3e5252aff4c1c1bd668f878fffaf3d0dbddeb029c307e88"
    )

    assert header.bits == 0x1A05DB8B .to_bytes(4, "big")
    assert header.nonce == 0xF7D8D840
    assert (
        header.hash
        == "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"
    )

    assert block.size == 247533
    assert block.weight == 989800


# first block with segwit transaction
# this block has NO witness data (as seen by legacy nodes)
def test_block_481824() -> None:

    fname = "block_481824.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = Block.deserialize(block_bytes)
    assert len(block.transactions) == 1866
    assert block.serialize() == block_bytes

    header = block.header
    assert header.time == 1503539857  # 2017-08-24 03:57:37 GMT+2
    assert (
        header.merkleroot
        == "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140"
    )

    assert header.bits == 0x18013CE9 .to_bytes(4, "big")
    assert header.nonce == 0x2254FF22
    assert (
        header.hash
        == "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"
    )

    assert block.transactions[0].vin[0].txinwitness == []


# this block has witness data
def test_block_481824_complete() -> None:

    fname = "block_481824_complete.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = Block.deserialize(block_bytes)
    assert len(block.transactions) == 1866
    assert block.serialize() == block_bytes

    header = block.header
    assert header.time == 1503539857  # 2017-08-24 03:57:37 GMT+2
    assert (
        header.merkleroot
        == "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140"
    )

    assert header.bits == 0x18013CE9 .to_bytes(4, "big")
    assert header.nonce == 0x2254FF22
    assert (
        header.hash
        == "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"
    )

    assert block.transactions[0].vin[0].txinwitness != []

    assert block.size == 989323
    assert block.weight == 3954548


def test_only_79_bytes() -> None:

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    header_bytes = open(filename, "rb").read()
    header_bytes = header_bytes[:70]

    with pytest.raises(IndexError):
        BlockHeader.deserialize(header_bytes)


def test_varint_error() -> None:

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block_bytes = block_bytes[:80] + b"\xff"

    with pytest.raises(IndexError):
        Block.deserialize(block_bytes)


def test_invalid_merkleroot() -> None:
    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = Block.deserialize(block_bytes)
    block.header.merkleroot = "00" * 32

    err_msg = "The block merkle root is not the merkle root of the block transactions"
    with pytest.raises(ValueError, match=err_msg):
        block.assert_valid()


def test_invalid_block_version() -> None:
    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = Block.deserialize(block_bytes)

    err_msg = "Invalid block header version"

    block.header.version = 0
    with pytest.raises(ValueError, match=err_msg):
        block.assert_valid()

    block.header.version = 0xFFFFFFFF + 1
    with pytest.raises(ValueError, match=err_msg):
        block.assert_valid()


def test_invalid_block_previoushash_length() -> None:
    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = Block.deserialize(block_bytes)

    block.header.previousblockhash = "00" * 31
    err_msg = "Invalid block previous hash length"
    with pytest.raises(ValueError, match=err_msg):
        block.assert_valid()


def test_invalid_block_merkleroot_length() -> None:
    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = Block.deserialize(block_bytes)

    block.header.merkleroot = "00" * 31
    err_msg = "Invalid block merkle root length"
    with pytest.raises(ValueError, match=err_msg):
        block.header.assert_valid()


def test_invalid_nonce() -> None:
    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = Block.deserialize(block_bytes)

    block.header.nonce = 0
    err_msg = "Invalid nonce"
    with pytest.raises(ValueError, match=err_msg):
        block.assert_valid()
