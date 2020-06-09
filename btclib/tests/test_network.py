#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.network` module."

from btclib.network import curve_from_xkeyversion, NETWORKS


def test_curve_from_xkeyversion():
    for net in NETWORKS:
        all_versions = (
            NETWORKS[net]["bip32_prv"],
            NETWORKS[net]["slip132_p2wsh_p2sh_prv"],
            NETWORKS[net]["slip132_p2wpkh_p2sh_prv"],
            NETWORKS[net]["slip132_p2wpkh_prv"],
            NETWORKS[net]["slip132_p2wsh_prv"],
            NETWORKS[net]["bip32_pub"],
            NETWORKS[net]["slip132_p2wsh_p2sh_pub"],
            NETWORKS[net]["slip132_p2wpkh_p2sh_pub"],
            NETWORKS[net]["slip132_p2wpkh_pub"],
            NETWORKS[net]["slip132_p2wsh_pub"],
        )
        for version in all_versions:
            assert NETWORKS[net]["curve"] == curve_from_xkeyversion(version)
