# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the descriptor package: the grammar, the keys, miniscript.

One test module per source module, with one gap on purpose:
`key_expression` has none of its own. BIP380's KEY expressions are read
through `parse` and written back through `str`, which is where
`descriptors_test` already exercises every spelling of one -- the origin,
the wildcards, the two hardening symbols, the WIF and the xprv -- and a
second module would be those same cases reached by a private function.
"""
