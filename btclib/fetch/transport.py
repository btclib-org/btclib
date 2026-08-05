# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Compatibility exports for the standard-library HTTP transport.

The implementation lives beside `BitcoinCoreRpcClient` in the standalone
`btclib.bitcoin_core_rpc` module. Direct aliases here keep the supported
`btclib.fetch.transport` seam available to the Esplora fetcher and to callers
without maintaining a second copy of its bounded-read and security policy.
"""

from btclib.bitcoin_core_rpc import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    HttpTransport,
    http_request,
    urlopen_transport,
)

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "HttpTransport",
    "http_request",
    "urlopen_transport",
]
