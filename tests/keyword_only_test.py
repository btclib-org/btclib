# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a keyword-only parameter stays keyword-only.

`*` in a signature is a calling-convention promise -- `check_validity`,
`network`, a dozen others that recur -- and nothing asserted it: a
mutant of `*` to `/` drops the keyword-only rule and adds a
positional-only one in its place, and every test still passed, at every
public callable that took a keyword-only parameter (issue #980). The
reason a whole suite could miss it is the same reason a single test can
catch all of it: the property is mechanical, one
`inspect.signature(...).parameters[name].kind` per site, so walking
`__all__` once covers every site a hand-written test would have to
repeat once per callable.

`KEYWORD_ONLY` is that walk, run once against the current tree and
frozen here rather than recomputed by the test: recomputing it from the
same code the test is meant to guard would make the assertion read
whatever a mutation had just done to it and call that the answer, which
is the blindness this file exists to remove. What is derived at test
time is the *live* signature of each recorded site, checked against the
kind frozen above -- a `*` a mutant turned to `/` is read here as
`POSITIONAL_ONLY` where the table says `KEYWORD_ONLY`, and the two no
longer agree.

A function under a package's `__all__` is named directly; a class is
named once per public method of its own -- `__init__`, and every other
name in its own `__dict__` that does not start with an underscore, so
an alternate constructor (`parse`, `b58decode`, `from_dict`) and an
instance method (`serialize`, `b58encode`) are sites of their own and
not only `__init__`. `Block.parse`'s `check_validity` is exactly the
shape `Block.__init__`'s does not cover: a classmethod the walk would
miss if it stopped at the constructor. Inherited
methods are not walked a second time under a subclass that does not
override them, deduplication being by the id of the underlying function
once resolved, so a name re-exported under a second `__all__` --
`all_test.py`'s `REEXPORTED` -- is one entry and not two either. What
btclib re-exports of the btclib_ecc package is no entry at all, that
package's own suite being what holds its signatures (issue #2282).
"""

from __future__ import annotations

import inspect
from importlib import import_module
from typing import Any

import pytest

from tests import defined_by_btclib_ecc
from tests.all_test import library_modules

# Walked from `btclib`, on the commit this file is part of: every public
# callable that takes at least one keyword-only parameter, and the names
# of those parameters in declaration order. A site dropping out of this
# table -- a parameter renamed, one no longer keyword-only, a callable
# removed from `__all__` -- and a site missing from it -- a new
# keyword-only parameter nothing here has asked about yet -- are both
# a deliberate edit to make, which is what
# test_the_recorded_surface_is_the_whole_of_it asks for
KEYWORD_ONLY: dict[str, list[str]] = {
    "btclib.block.build:build_block": ["version"],
    "btclib.block.build:build_coinbase": [
        "fees",
        "halving_interval",
        "extra_nonce",
        "version",
        "lock_time",
        "check_validity",
    ],
    "btclib.block.mining:candidate_block_header": ["version"],
    "btclib.block.proof_of_work:next_bits": ["pow_limit_bits"],
    "btclib.block:BasicBlockFilter.__init__": ["check_validity"],
    "btclib.block:BasicBlockFilter.from_block": ["check_validity"],
    "btclib.block:BasicBlockFilter.parse": ["check_validity"],
    "btclib.block:BasicBlockFilter.serialize": ["check_validity"],
    "btclib.block:Block.__init__": ["check_validity"],
    "btclib.block:Block.from_dict": ["check_validity"],
    "btclib.block:Block.parse": ["check_validity"],
    "btclib.block:Block.serialize": ["check_validity"],
    "btclib.block:Block.to_dict": ["check_validity"],
    "btclib.block:BlockContext.__init__": ["check_validity"],
    "btclib.block:BlockHeader.__init__": ["check_validity"],
    "btclib.block:BlockHeader.from_dict": ["check_validity"],
    "btclib.block:BlockHeader.parse": ["check_validity"],
    "btclib.block:BlockHeader.serialize": ["check_validity"],
    "btclib.block:BlockHeader.to_dict": ["check_validity"],
    "btclib.block:PartialMerkleTree.__init__": ["check_validity"],
    "btclib.block:PartialMerkleTree.from_txids": ["check_validity"],
    "btclib.block:PartialMerkleTree.parse": ["check_validity"],
    "btclib.block:PartialMerkleTree.serialize": ["check_validity"],
    "btclib.ecc.bms:Sig.__init__": ["check_validity"],
    "btclib.ecc.bms:Sig.b64decode": ["check_validity"],
    "btclib.ecc.bms:Sig.b64encode": ["check_validity"],
    "btclib.ecc.bms:Sig.parse": ["check_validity"],
    "btclib.ecc.bms:Sig.serialize": ["check_validity"],
    "btclib.fee:FeeRate.__init__": ["sats_per_kvbyte"],
    "btclib.fee:FeeRate.from_btc_per_kvbyte": ["round_up"],
    "btclib.fee:FeeRate.from_sats_per_vbyte": ["round_up"],
    "btclib.fee:package_fee": ["ancestor_vsize", "ancestor_fee"],
    "btclib.key:PrvKeyData.__init__": ["check_validity"],
    "btclib.key:PubKeyData.__init__": ["check_validity"],
    "btclib.network:Network.__init__": ["consensus", "check_validity"],
    "btclib.network:Network.from_dict": ["check_validity"],
    "btclib.network:Network.to_dict": ["check_validity"],
    "btclib.p2p:Addr.__init__": ["check_validity"],
    "btclib.p2p:Addr.parse": ["check_validity"],
    "btclib.p2p:Addr.serialize": ["check_validity"],
    "btclib.p2p:AddrV2.__init__": ["check_validity"],
    "btclib.p2p:AddrV2.parse": ["check_validity"],
    "btclib.p2p:AddrV2.serialize": ["check_validity"],
    "btclib.p2p:BlockPayload.__init__": ["check_validity"],
    "btclib.p2p:BlockTxn.__init__": ["check_validity"],
    "btclib.p2p:BlockTxn.parse": ["check_validity"],
    "btclib.p2p:BlockTxn.serialize": ["check_validity"],
    "btclib.p2p:BlockPayload.parse": ["check_validity"],
    "btclib.p2p:BlockPayload.serialize": ["check_validity"],
    "btclib.p2p:CFCheckpt.__init__": ["check_validity"],
    "btclib.p2p:CFCheckpt.parse": ["check_validity"],
    "btclib.p2p:CFCheckpt.serialize": ["check_validity"],
    "btclib.p2p:CFHeaders.__init__": ["check_validity"],
    "btclib.p2p:CFHeaders.parse": ["check_validity"],
    "btclib.p2p:CFHeaders.serialize": ["check_validity"],
    "btclib.p2p:CFilter.__init__": ["check_validity"],
    "btclib.p2p:CFilter.parse": ["check_validity"],
    "btclib.p2p:CFilter.serialize": ["check_validity"],
    "btclib.p2p:CmpctBlock.__init__": ["check_validity"],
    "btclib.p2p:CmpctBlock.parse": ["check_validity"],
    "btclib.p2p:CmpctBlock.serialize": ["check_validity"],
    "btclib.p2p:Feature.__init__": ["check_validity"],
    "btclib.p2p:Feature.parse": ["check_validity"],
    "btclib.p2p:Feature.serialize": ["check_validity"],
    "btclib.p2p:FeeFilter.__init__": ["check_validity"],
    "btclib.p2p:FeeFilter.parse": ["check_validity"],
    "btclib.p2p:FeeFilter.serialize": ["check_validity"],
    "btclib.p2p:GetAddr.__init__": ["check_validity"],
    "btclib.p2p:GetAddr.parse": ["check_validity"],
    "btclib.p2p:GetAddr.serialize": ["check_validity"],
    "btclib.p2p:GetBlockTxn.__init__": ["check_validity"],
    "btclib.p2p:GetBlockTxn.parse": ["check_validity"],
    "btclib.p2p:GetBlockTxn.serialize": ["check_validity"],
    "btclib.p2p:GetCFCheckpt.__init__": ["check_validity"],
    "btclib.p2p:GetCFCheckpt.parse": ["check_validity"],
    "btclib.p2p:GetCFCheckpt.serialize": ["check_validity"],
    "btclib.p2p:Headers.__init__": ["check_validity"],
    "btclib.p2p:Headers.parse": ["check_validity"],
    "btclib.p2p:Headers.serialize": ["check_validity"],
    "btclib.p2p:Inventory.__init__": ["check_validity"],
    "btclib.p2p:Inventory.parse": ["check_validity"],
    "btclib.p2p:Inventory.serialize": ["check_validity"],
    "btclib.p2p:Mempool.__init__": ["check_validity"],
    "btclib.p2p:Mempool.parse": ["check_validity"],
    "btclib.p2p:Mempool.serialize": ["check_validity"],
    "btclib.p2p:MerkleBlock.__init__": ["check_validity"],
    "btclib.p2p:MerkleBlock.parse": ["check_validity"],
    "btclib.p2p:MerkleBlock.serialize": ["check_validity"],
    "btclib.p2p:Message.__init__": ["check_validity"],
    "btclib.p2p:Message.parse": ["check_validity"],
    "btclib.p2p:Message.serialize": ["check_validity"],
    "btclib.p2p:NetworkAddress.__init__": ["check_validity"],
    "btclib.p2p:NetworkAddress.parse": ["check_validity"],
    "btclib.p2p:NetworkAddress.serialize": ["check_validity"],
    "btclib.p2p:NetworkAddressV2.__init__": ["check_validity"],
    "btclib.p2p:NetworkAddressV2.parse": ["check_validity"],
    "btclib.p2p:NetworkAddressV2.serialize": ["check_validity"],
    "btclib.p2p:PartialBlock.__init__": ["check_validity"],
    "btclib.p2p:PartialBlock.fill": ["check_validity"],
    "btclib.p2p:Payload.serialize": ["check_validity"],
    "btclib.p2p:Payload.to_message": ["check_validity"],
    "btclib.p2p:PrefilledTransaction.__init__": ["check_validity"],
    "btclib.p2p:PrefilledTransaction.parse": ["check_validity"],
    "btclib.p2p:PrefilledTransaction.serialize": ["check_validity"],
    "btclib.p2p:Reject.__init__": ["check_validity"],
    "btclib.p2p:Reject.parse": ["check_validity"],
    "btclib.p2p:Reject.serialize": ["check_validity"],
    "btclib.p2p:SendAddrV2.__init__": ["check_validity"],
    "btclib.p2p:SendAddrV2.parse": ["check_validity"],
    "btclib.p2p:SendAddrV2.serialize": ["check_validity"],
    "btclib.p2p:SendCmpct.__init__": ["check_validity"],
    "btclib.p2p:SendCmpct.parse": ["check_validity"],
    "btclib.p2p:SendCmpct.serialize": ["check_validity"],
    "btclib.p2p:SendHeaders.__init__": ["check_validity"],
    "btclib.p2p:SendHeaders.parse": ["check_validity"],
    "btclib.p2p:SendHeaders.serialize": ["check_validity"],
    "btclib.p2p:SendTxRcncl.__init__": ["check_validity"],
    "btclib.p2p:SendTxRcncl.parse": ["check_validity"],
    "btclib.p2p:SendTxRcncl.serialize": ["check_validity"],
    "btclib.p2p:TimestampedNetworkAddress.__init__": ["check_validity"],
    "btclib.p2p:TimestampedNetworkAddress.parse": ["check_validity"],
    "btclib.p2p:TimestampedNetworkAddress.serialize": ["check_validity"],
    "btclib.p2p:TxPayload.__init__": ["check_validity"],
    "btclib.p2p:TxPayload.parse": ["check_validity"],
    "btclib.p2p:TxPayload.serialize": ["check_validity"],
    "btclib.p2p:Verack.__init__": ["check_validity"],
    "btclib.p2p:Verack.parse": ["check_validity"],
    "btclib.p2p:Verack.serialize": ["check_validity"],
    "btclib.p2p:Version.__init__": ["check_validity"],
    "btclib.p2p:Version.parse": ["check_validity"],
    "btclib.p2p:Version.serialize": ["check_validity"],
    "btclib.p2p:WtxidRelay.__init__": ["check_validity"],
    "btclib.p2p:WtxidRelay.parse": ["check_validity"],
    "btclib.p2p:WtxidRelay.serialize": ["check_validity"],
    "btclib.script.sig_hash:from_tx": ["codesep_index"],
    "btclib.script:Script.__init__": ["check_validity"],
    "btclib.script:ScriptPubKey.__init__": ["check_validity"],
    "btclib.script:ScriptPubKey.from_address": ["check_validity"],
    "btclib.script:ScriptPubKey.nulldata": ["check_validity"],
    "btclib.script:ScriptPubKey.p2ms": ["check_validity"],
    "btclib.script:ScriptPubKey.p2pk": ["check_validity"],
    "btclib.script:ScriptPubKey.p2pkh": ["check_validity"],
    "btclib.script:ScriptPubKey.p2sh": ["check_validity"],
    "btclib.script:ScriptPubKey.p2tr": ["check_validity"],
    "btclib.script:ScriptPubKey.p2wpkh": ["check_validity"],
    "btclib.script:ScriptPubKey.p2wsh": ["check_validity"],
    "btclib.script:Witness.__init__": ["check_validity"],
    "btclib.script:Witness.from_dict": ["check_validity"],
    "btclib.script:Witness.parse": ["check_validity"],
    "btclib.script:Witness.serialize": ["check_validity"],
    "btclib.script:Witness.to_dict": ["check_validity"],
    "btclib.tx:Coin.__init__": ["check_validity"],
    "btclib.tx:OutPoint.__init__": ["check_validity"],
    "btclib.tx:OutPoint.from_dict": ["check_validity"],
    "btclib.tx:OutPoint.parse": ["check_validity"],
    "btclib.tx:OutPoint.serialize": ["check_validity"],
    "btclib.tx:OutPoint.to_dict": ["check_validity"],
    "btclib.tx:Tx.__init__": ["check_validity"],
    "btclib.tx:Tx.assert_valid": ["unsigned_template"],
    "btclib.tx:Tx.from_dict": ["check_validity"],
    "btclib.tx:Tx.parse": ["check_validity"],
    "btclib.tx:Tx.serialize": ["check_validity"],
    "btclib.tx:Tx.to_dict": ["check_validity"],
    "btclib.tx:TxIn.__init__": ["check_validity"],
    "btclib.tx:TxIn.from_dict": ["check_validity"],
    "btclib.tx:TxIn.parse": ["check_validity"],
    "btclib.tx:TxIn.serialize": ["check_validity"],
    "btclib.tx:TxIn.to_dict": ["check_validity"],
    "btclib.tx:TxOut.__init__": ["check_validity"],
    "btclib.tx:TxOut.from_dict": ["check_validity"],
    "btclib.tx:TxOut.parse": ["check_validity"],
    "btclib.tx:TxOut.serialize": ["check_validity"],
    "btclib.tx:TxOut.to_dict": ["check_validity"],
}


def _resolve(label: str) -> Any:
    """Import `module:Class.method` or `module:function` back to the object.

    The colon is the split point rather than the last dot: a module name
    is dotted too (`btclib.ecc.dsa`), so the pair is stored apart instead
    of concatenated and re-split.
    """
    module_name, _, attr_path = label.partition(":")
    obj: Any = import_module(module_name)
    for part in attr_path.split("."):
        obj = getattr(obj, part)
    return obj


def _kwonly_names(signature: inspect.Signature) -> list[str]:
    """Return the keyword-only parameter names of one signature, in order."""
    return [
        parameter.name
        for parameter in signature.parameters.values()
        if parameter.kind == inspect.Parameter.KEYWORD_ONLY
    ]


def _class_sites(
    module: Any, name: str, cls: type, seen_ids: set[int]
) -> dict[str, list[str]]:
    """Every public method of one exported class that is keyword-only somewhere.

    `__init__` plus every name in the class's own `__dict__` that does
    not start with an underscore, so an alternate constructor (`parse`,
    `b58decode`, `from_dict`) and an instance method (`serialize`,
    `b58encode`) are sites of their own rather than invisible because
    they are not the constructor. A method inherited and not overridden
    is in a base class's own `__dict__` instead, so it is walked once,
    there.
    """
    found: dict[str, list[str]] = {}
    attr_names = sorted(
        attr for attr in vars(cls) if attr == "__init__" or not attr.startswith("_")
    )
    for attr_name in attr_names:
        bound = getattr(cls, attr_name)
        if not (inspect.isfunction(bound) or inspect.ismethod(bound)):
            continue  # a property or a plain class attribute
        target = bound.__func__ if inspect.ismethod(bound) else bound
        if id(target) in seen_ids:
            continue
        seen_ids.add(id(target))
        kwonly = _kwonly_names(inspect.signature(bound))
        if kwonly:
            found[f"{module.__name__}:{name}.{attr_name}"] = kwonly
    return found


def _live_keyword_only() -> dict[str, list[str]]:
    """Recompute `KEYWORD_ONLY` from the tree currently under test.

    The same walk that produced the table above, run again: every
    module's `__all__`, a function named directly and a class expanded
    by `_class_sites`. Deduplicated by the id of the resolved function --
    `__func__` for a bound classmethod, the function itself otherwise --
    so an object reachable under two names is one entry.
    """
    seen_ids: set[int] = set()
    found: dict[str, list[str]] = {}
    for module in library_modules():
        names = getattr(module, "__all__", None)
        if not names:
            continue
        for name in names:
            obj = getattr(module, name)
            if defined_by_btclib_ecc(obj):
                continue
            if inspect.isclass(obj):
                found.update(_class_sites(module, name, obj, seen_ids))
            elif inspect.isfunction(obj) or inspect.isbuiltin(obj):
                if id(obj) in seen_ids:
                    continue
                seen_ids.add(id(obj))
                kwonly = _kwonly_names(inspect.signature(obj))
                if kwonly:
                    found[f"{module.__name__}:{name}"] = kwonly
    return found


def test_the_recorded_surface_is_the_whole_of_it() -> None:
    """Nothing keyword-only is missing from the table, nothing extra is in it.

    The half `test_a_keyword_only_parameter_stays_keyword_only` cannot
    ask: that test parametrizes over `KEYWORD_ONLY` itself, so a
    keyword-only parameter added to the public surface without a line
    here would run no test at all rather than fail one. This recomputes
    the walk and asks the two agree -- a new site, a removed one, and a
    renamed parameter all show up as one dictionary differing from
    another rather than as a `KeyError` or a silent gap.
    """
    assert _live_keyword_only() == KEYWORD_ONLY


@pytest.mark.parametrize(
    "label, param_name",
    [
        pytest.param(label, param_name, id=f"{label}:{param_name}")
        for label, params in sorted(KEYWORD_ONLY.items())
        for param_name in params
    ],
)
def test_a_keyword_only_parameter_stays_keyword_only(
    label: str, param_name: str
) -> None:
    """One assertion per recorded site, so a mutant of one `*` fails by name.

    `ReplaceBinaryOperator_Mul_Div` turns the `*` in front of a
    keyword-only parameter into `/`, which makes every parameter in
    front of it positional-only and every one after it -- this one
    included -- plain `POSITIONAL_OR_KEYWORD` rather than
    `KEYWORD_ONLY`. Nothing about a call already written with the
    keyword changes, and nothing about the value returned does either,
    which is why no other test in the suite notices (issue #980).
    """
    kind = inspect.signature(_resolve(label)).parameters[param_name].kind
    assert kind == inspect.Parameter.KEYWORD_ONLY, (
        f"{label}'s {param_name} is {kind}, not keyword-only"
    )
