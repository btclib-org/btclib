#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
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
