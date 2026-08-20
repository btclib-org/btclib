# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib package: what it publishes, and the version metadata.

`__all__` here is the root of the library's public tree: the packages and
top-level modules a caller reaches from this name. Each of those, and each
module below them, declares its own `__all__`, so a walk that starts here
has a declared surface at every node -- which is why the list is not
`pkgutil.iter_modules`: discovery would answer the file tree, and a module
added to the directory would publish itself rather than being published.

That walk is also what `docs/proposals/cli.md` reads to build the command
tree of the out-of-repo command line, and there it is a starting point
rather than the whole answer: a module can be published and carry nothing
a command should spell. The command tree is this tree minus the exclusions
that proposal records, which is a distinction the published surface cannot
express and does not try to.

`name` is not in it, nor are the metadata dunders. `name` is the
distribution's name and not a member of the tree, `__version__` bound by
a star import would overwrite the importing module's own, and each is
still an attribute here: `btclib.__version__` is how a caller reads the
version and `btclib.name` how it reads the name.

Nothing is imported eagerly. A module is imported when it is first asked
for, through the `__getattr__` at the bottom of this file, so `import
btclib` stays what it was -- the metadata lookup below and nothing else --
and the import graph keeps its shape: importing every module here would
put the whole library in `sys.modules` before any single module of it
could be imported first, which is the situation tests/imports_test.py
exists to make impossible, and `btclib.b58` would pull `btclib.script`
in through this file rather than not at all.

What that costs is worth stating: mypy reads a module-level `__getattr__`
as a promise that any attribute may exist, so `btclib.b59` is `Any` to it
and a misspelling on this package is a runtime `AttributeError` rather
than a reported error. The spellings a caller actually writes -- `from
btclib import b58`, `import btclib.b58`, `from btclib.b58 import p2pkh` --
resolve against the real modules and stay checked, which is why the trade
is one attribute lookup's worth of strictness for an import graph that
stays acyclic and a root that publishes its tree.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from types import ModuleType

name = "btclib"
# read back from the installed distribution, so that pyproject.toml is the
# only place the version is written. It is what a caller asking for
# btclib.__version__ wants anyway: the version that is installed, rather
# than the one a source tree happens to carry
try:
    __version__ = version("btclib")
except PackageNotFoundError:
    # a source tree with no metadata beside it: git clone and import, or
    # read the docs, which builds without installing this package. Any
    # number here would be a guess, and reading pyproject.toml back is not
    # the way to stop guessing: tomllib is standard library from 3.11 only,
    # this package supports 3.10, and the file is not in the wheel anyway.
    # Importing has to keep working, so the version says it does not know
    __version__ = "unknown"
__author__ = "The btclib developers"
__author_email__ = "devs@btclib.org"
# the one place the years are written. The notice at the head of every
# source file carries none, by design: it comes from the COPYRIGHT file,
# which ruff's CPY001 (flake8-copyright) enforces, so it never needs
# editing.
# docs/source/conf.py reads this line rather than importing it, read the
# docs not installing this package into the environment it builds in
__copyright__ = "Copyright (c) 2017-2026 The btclib developers"
__license__ = "MIT License"

__all__ = [
    "alias",
    "amount",
    "b32",
    "b58",
    "base58",
    "bech32",
    "bip21",
    "bip32",
    "bip44",
    "bip85",
    "bip322",
    "block",
    "consensus",
    "core_import",
    "curves",
    "descriptors",
    "ecc",
    "exceptions",
    "fee",
    "fetch",
    "hashes",
    "hwi",
    "kdf",
    "mnemonic",
    "network",
    "number_theory",
    "psbt",
    "psbt_signer",
    "psbt_signer_contract",
    "script",
    "silent_payments",
    "slip132",
    "to_prv_key",
    "to_pub_key",
    "tx",
    "tx_builder",
    "tx_or_psbt",
    "utils",
    "var_bytes",
    "var_int",
    "wallet",
]


def __getattr__(published: str) -> ModuleType:
    """Import a published module the first time it is asked for.

    PEP 562: this runs only for a name the package does not already have,
    so it answers `btclib.b58` once and the import machinery's own
    attribute answers it from then on -- and it never runs for `import
    btclib.b58` or `from btclib import b58`, which import the submodule
    themselves. What it makes work is `getattr(btclib, "b58")` on a fresh
    interpreter, which is how a walker reading `__all__` descends, and
    `from btclib import *`, which asks for each name in the list.

    Anything not in `__all__` raises `AttributeError`, private modules
    included: `btclib._ripemd160` is `btclib.hashes`' business, and
    `import btclib._ripemd160` still reaches it. The message is the
    interpreter's own wording, so a typo reads as it does anywhere else.
    """
    if published in __all__:
        return import_module(f"{__name__}.{published}")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the published tree beside what the package already has.

    `dir(btclib)` consults this rather than the namespace, so without it a
    module not yet imported is missing from the completion a caller gets
    at an interactive prompt -- the same names `__getattr__` above will
    answer for.
    """
    return sorted({*__all__, *globals()})
