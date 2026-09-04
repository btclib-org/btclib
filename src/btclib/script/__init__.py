# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Scripts: types, classification, sig hashes, taproot, the engine.

The flat surface is the script itself: the codec, the `ScriptPubKey`
classification with both halves of every pair, the `Witness`, and the
taproot output key a caller builds an address from.

Three submodules are named beside it, being the three subgroups a caller
reaches by name -- `sig_hash` for what a signature commits to, `taproot`
for the tree and the control block, `engine` for the verifier -- and
`docs/proposals/cli.md` promises each as a command group. `taproot` is
imported above for the four names re-exported flat; `sig_hash` and
`engine` are imported on demand by the `__getattr__` at the bottom of this
file, and that is not a choice about speed: both reach the transaction
stack -- `sig_hash` needs `btclib.tx`, whose `tx_in` and `tx_out` import
this package back -- and `btclib.script.engine.script` asks this very
package for `sig_hash`, so importing either from here at import time
closes a cycle on a half-initialized `btclib.script`. That is issue #147's
shape, and tests/imports_test.py is what reports it.

The other submodules are not named: `script`, `script_pub_key`,
`sig_ops`, `spendability` and `witness` are where the flat names above
are defined, and `limits` and `op_codes_tapscript` are tables the engine
reads. Each declares its own `__all__` and is importable; none is a
group.
"""

from importlib import import_module
from types import ModuleType

from btclib.alias import Command, TaprootLeaf, TaprootScriptTree
from btclib.script.script import (
    Script,
    op_int,
    parse,
    push_int,
    script_from_dict,
    script_to_dict,
    serialize,
)
from btclib.script.script_pub_key import (
    ScriptPubKey,
    address,
    addresses,
    assert_nulldata,
    assert_p2ms,
    assert_p2pk,
    assert_p2pkh,
    assert_p2sh,
    assert_p2tr,
    assert_p2wpkh,
    assert_p2wsh,
    assert_segwit,
    is_nulldata,
    is_p2ms,
    is_p2pk,
    # is_p2pkh was the one missing, where assert_p2pkh was not: the other
    # seven assert/is pairs are both here
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    is_segwit,
    p2ms_m_and_keys,
    type_and_payload,
)
from btclib.script.sig_ops import sig_op_count
from btclib.script.spendability import is_unspendable
from btclib.script.taproot import (
    check_output_pubkey,
    input_script_sig,
    output_prvkey,
    output_prvkey_from_merkle_root,
    output_pubkey,
    output_pubkey_from_merkle_root,
)
from btclib.script.witness import Witness

__all__ = [
    "Command",
    "Script",
    "ScriptPubKey",
    # the pair a leaf of a TaprootScriptTree holds, worth naming beside
    # the tree, which is a type and not Any
    "TaprootLeaf",
    "TaprootScriptTree",
    "Witness",
    "address",
    "addresses",
    "assert_nulldata",
    "assert_p2ms",
    "assert_p2pk",
    "assert_p2pkh",
    "assert_p2sh",
    "assert_p2tr",
    "assert_p2wpkh",
    "assert_p2wsh",
    "assert_segwit",
    "check_output_pubkey",
    "engine",
    "input_script_sig",
    "is_nulldata",
    "is_p2ms",
    "is_p2pk",
    "is_p2pkh",
    "is_p2sh",
    "is_p2tr",
    "is_p2wpkh",
    "is_p2wsh",
    "is_segwit",
    "is_unspendable",
    "op_int",
    "output_prvkey",
    "output_prvkey_from_merkle_root",
    "output_pubkey",
    "output_pubkey_from_merkle_root",
    "p2ms_m_and_keys",
    "parse",
    "push_int",
    "script_from_dict",
    "script_to_dict",
    "serialize",
    "sig_hash",
    "sig_op_count",
    "taproot",
    "type_and_payload",
]

# the two subgroups this package publishes without importing: see the
# docstring for the cycle each would close. `taproot` is not here because
# the import above has already bound it, so __getattr__ is never asked
_ON_DEMAND = ("engine", "sig_hash")


def __getattr__(published: str) -> ModuleType:
    """Import a published submodule the first time it is asked for.

    PEP 562, as `btclib/__init__.py` does it: this answers
    `btclib.script.sig_hash` on a package that imported neither, which is
    how a walker reading `__all__` descends, and `from btclib.script import
    *` binds. `from btclib.script import sig_hash` and `import
    btclib.script.engine` never reach here, importing the submodule
    themselves.
    """
    if published in _ON_DEMAND:
        return import_module(f"{__name__}.{published}")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the two on-demand groups beside what is already here.

    The same PEP 562 asymmetry `btclib/__init__.py` answers the same way:
    `dir()` reads the namespace, so a module `__getattr__` has not imported
    yet is missing from it -- `engine` and `sig_hash` until first touched,
    where `taproot` shows because the import above bound it. Interactive
    completion would hide two supported groups.
    """
    return sorted({*__all__, *globals()})
