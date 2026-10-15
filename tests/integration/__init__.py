# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The tests that need something this repository does not ship.

A bitcoind to talk to, or a qa-assets checkout to replay. Each of those
tests skips itself without its variable -- `BTCLIB_INTEGRATION`,
`BTCLIB_QA_ASSETS` or `BTCLIB_RUST_BITCOIN_QA_ASSETS` -- and the skip
message says which; `pyproject.toml` leaves this package out of the
coverage ratchet for the same reason. `node_start_test.py` needs neither
and skips nothing.
"""
