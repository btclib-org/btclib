#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Module btclib.ecc.

The signature schemes are what this package is for, and none of them was
exported: `__all__` held ansi_x9_63_kdf, bip340_nonce_, diffie_hellman and
second_generator, and not dsa, ssa or bms. So `import btclib.ecc` followed
by `btclib.ecc.dsa.sign(...)` raised AttributeError until something else in
the process happened to import the submodule, and what the package
advertised was four helpers instead of the six schemes behind them.

bms and sign_to_contract do `from btclib.ecc import dsa`, i.e. they import
a name from the package that is importing them, and the order of the line
below does not have to work around it: a `from package import name` whose
name is not yet an attribute falls back to importing package.name as a
submodule, which is what happens here. tests/test_imports.py imports every
module of the library with nothing else in sys.modules, which is the order
that would find it if it did not.
"""

from btclib.ecc import bms, borromean, dsa, pedersen, sign_to_contract, ssa
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.dh import ansi_x9_63_kdf, diffie_hellman
from btclib.ecc.pedersen import second_generator

__all__ = [
    "ansi_x9_63_kdf",
    "bip340_nonce_",
    "bms",
    "borromean",
    "diffie_hellman",
    "dsa",
    "pedersen",
    "second_generator",
    "sign_to_contract",
    "ssa",
]
