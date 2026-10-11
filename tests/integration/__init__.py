# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The tests that need something this repository does not ship.

A bitcoind to talk to, an HWI to run, a device to press a button on.
Each skips itself without its switch in the environment --
`BTCLIB_INTEGRATION`, or `BTCLIB_QA_ASSETS` and
`BTCLIB_RUST_BITCOIN_QA_ASSETS` for the corpora replay -- and the skip
message says which was off; `pyproject.toml` leaves this package out
of the coverage ratchet for the same reason.
"""
