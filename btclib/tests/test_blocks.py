#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.blocks` module."

import os

from btclib.blocks import serialize_block, deserialize_block, generate_merkle_root


# actually second block in chain, first obtainable from other nodes
def test_block_1():

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)

    assert len(block["transactions"]) == 1

    header = block["header"]
    assert header["time"] == 1231469665  # 2009-01-09 03:54:25 GMT+1

    assert serialize_block(block) == block_bytes

    assert generate_merkle_root(block["transactions"]) == block["header"]["merkleroot"]


# first block with a transaction
def test_block_170():

    fname = "block_170.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block = deserialize_block(block_bytes)

    assert len(block["transactions"]) == 2

    header = block["header"]
    assert header["time"] == 1231731025  # 2009-01-12 04:30:25 GMT+1

    assert serialize_block(block) == block_bytes

    assert generate_merkle_root(block["transactions"]) == block["header"]["merkleroot"]


def test_block_200000():

    fname = "block_200000.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)

    assert serialize_block(block) == block_bytes

    assert generate_merkle_root(block["transactions"]) == block["header"]["merkleroot"]


# first block with segwit transaction
def test_block_481824():

    fname = "block_481824.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 1866

    header = block["header"]
    assert header["time"] == 1503539857  # 2017-08-24 03:57:37 GMT+2

    assert serialize_block(block) == block_bytes

    assert generate_merkle_root(block["transactions"]) == block["header"]["merkleroot"]


# def test_only_79_bytes():
#
#     fname = "block_1.bin"
#     filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
#     header_bytes = open(filename, "rb").read()
#     header_bytes = header_bytes[:79]
#
#     err_msg = "Too little data"
#     with pytest.raises(Exception, match=err_msg):
#         Block.from_bytes(header_bytes)
#
#     with pytest.raises(Exception):
#         BlockHeader.from_bytes(header_bytes)
#
#
# def test_varint_error():
#
#     fname = "block_1.bin"
#     filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
#     block_bytes = open(filename, "rb").read()
#     block_bytes = block_bytes[:80] + b"\xff"
#
#     err_msg = "Too little data"
#     with pytest.raises(Exception, match=err_msg):
#         Block.from_bytes(block_bytes)
