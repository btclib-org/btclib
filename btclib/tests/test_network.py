#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.network` module."

from btclib.network import (
    NETWORKS,
    curve_from_xkeyversion,
    network_from_xkeyversion,
    xprvversions_from_network,
    xpubversions_from_network,
)


def test_curve_from_xkeyversion():
    for net in NETWORKS:
        all_versions = xpubversions_from_network(net) + xprvversions_from_network(net)
        for version in all_versions:
            # unfortunately 'regtest' shares same versions with 'testnet'
            if net != "regtest":
                assert net == network_from_xkeyversion(version)
            assert NETWORKS[net]["curve"] == curve_from_xkeyversion(version)
