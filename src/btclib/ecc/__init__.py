# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.ecc: the two schemes that are bitcoin's.

**What is here.** `bms`, the message signature that names its signer by an
address, and `ellswift`, BIP324's x-only ECDH over ElligatorSwift keys.
Each is a protocol's rather than a curve's, which is what keeps it in
btclib. The curve arithmetic and every other scheme -- dsa, ssa, borromean,
MuSig2, FROST, pedersen commitments, the rangeproof, the Diffie-Hellman key
agreement, ECIES, the BIP374 discrete logarithm equality proof and the
nonce derivations -- are the `ecc` package's, which btclib depends
on and imports where it needs them: `from ecc.curves import mult`,
`from ecc.ecc import dsa`.

**bms is imported on demand, and it is the one module that is.** It reaches
`b32`, `b58`, `key` and `network`, which `ellswift` does not. Importing
`bms` eagerly would put those modules behind `import btclib.ecc`;
`__getattr__` at the bottom answers `btclib.ecc.bms` instead, the first
time it is asked for. `from btclib.ecc import bms` is answered there too, a
from-import asking for the attribute before it imports a submodule.
tests/imports_test.py holds `import btclib.ecc` to what `ellswift` needs,
with `bms` absent from it.

**Secrets.** This is the package a private key is handed to, and what
holds around it is conditional. `bms` signs with ecc's `dsa`, and
`ellswift.xdh` is ecc's `decode_var` and `mult`, then BIP324's tagged
hash. The curve operations run on libsecp256k1 where
`ecc.curves.is_libsecp256k1_serving()` holds and the curve is secp256k1;
otherwise the Python arithmetic runs, which is not constant-time. Nor is
a Python object holding a secret zeroized, on either path. SECURITY.md's
limitations section states each condition, and README.md carries the
short form.
"""

from importlib import import_module
from types import ModuleType

from btclib.ecc import ellswift

__all__ = [
    "bms",
    "ellswift",
]


def __getattr__(published: str) -> ModuleType:
    """Import `bms` the first time it is asked for.

    PEP 562, as `btclib/__init__.py` does it: this answers `btclib.ecc.bms`
    on a package that has not imported it, which is how a walker reading
    `__all__` descends and how `from btclib.ecc import *` binds.
    """
    if published == "bms":
        return import_module(f"{__name__}.bms")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with `bms` beside what the package already has.

    `dir()` reads the namespace, so without this `bms` is missing from it
    until first touched, as `btclib/script/__init__.py` says of its own.
    """
    return sorted({*__all__, *globals()})
