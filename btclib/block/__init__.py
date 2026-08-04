#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Blocks: header and block, their rules, proof of work, merkle proofs."""

from btclib.block import merkle_proof, mining, proof_of_work
from btclib.block.block import (
    Block,
    bip34_commitment,
    merkle_root_and_mutated_from_transactions,
)
from btclib.block.block_context import BlockContext
from btclib.block.block_header import BlockHeader

# btclib.block.limits is not here, as btclib.script.limits is not in
# btclib.script: a caller reading a consensus constant names the module it
# comes from, which is what says the number is Core's and not this
# library's.
# merkle_root_and_mutated_from_transactions is, beside the bip34_commitment
# defined next to it: both are what a header commits to, and this one is
# the single implementation the builder and the validator share -- mining
# builds a candidate header from it and Block.assert_valid compares the
# header against it -- so a caller checking a block by hand needs the same
# function rather than a second one written from the BIP
__all__ = [
    "Block",
    "BlockContext",
    "BlockHeader",
    "bip34_commitment",
    "merkle_proof",
    "merkle_root_and_mutated_from_transactions",
    "mining",
    "proof_of_work",
]
