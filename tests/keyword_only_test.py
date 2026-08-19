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

A class is named by its `__init__`, which is where a keyword-only
parameter of a dataclass or a plain one lives; a function under a
package's `__all__` is named directly. Deduplicated by the id of the
callable object once resolved, so a name re-exported under a second
`__all__` -- `btclib.fetch.bitcoin_core` aliasing the `bitcoin-core-rpc`
package, `all_test.py`'s `REEXPORTED` -- is one entry and not two.
"""

from __future__ import annotations

import inspect
from importlib import import_module
from typing import Any

import pytest

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
    "btclib.bip21:Bip21.__init__": ["check_validity"],
    "btclib.bip322:assert_as_valid": ["legacy"],
    "btclib.bip322:to_sign": ["version", "lock_time", "sequence", "extra_inputs"],
    "btclib.bip322:verify": ["legacy"],
    "btclib.bip32:BIP32KeyData.__init__": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.__init__": ["check_validity"],
    "btclib.bip32:decode_from_bip32_derivs": ["check_validity"],
    "btclib.bip32:hardenings_from_der_path": ["bip380_enforced"],
    "btclib.bip32:indexes_from_der_path": ["bip380_enforced"],
    "btclib.bip32:int_from_index_str": ["bip380_enforced"],
    "btclib.block.mining:candidate_block_header": ["version"],
    "btclib.block.proof_of_work:next_bits": ["pow_limit_bits"],
    "btclib.block:Block.__init__": ["check_validity"],
    "btclib.block:BlockContext.__init__": ["check_validity"],
    "btclib.block:BlockHeader.__init__": ["check_validity"],
    "btclib.core_import:account_import_requests": ["active", "key_range"],
    "btclib.core_import:import_request": [
        "internal",
        "active",
        "key_range",
        "next_index",
        "label",
    ],
    "btclib.curves:point_from_octets": ["hybrid"],
    "btclib.curves:set_libsecp256k1_serving": ["serving"],
    "btclib.descriptors:AddrDescriptor.__init__": ["network"],
    "btclib.descriptors:ComboDescriptor.__init__": ["network"],
    "btclib.descriptors:Descriptor.__init__": ["network"],
    "btclib.descriptors:MiniscriptDescriptor.__init__": ["network"],
    "btclib.descriptors:MultiDescriptor.__init__": ["network"],
    "btclib.descriptors:PkDescriptor.__init__": ["network"],
    "btclib.descriptors:PkhDescriptor.__init__": ["network"],
    "btclib.descriptors:RawDescriptor.__init__": ["network"],
    "btclib.descriptors:RawTrDescriptor.__init__": ["network"],
    "btclib.descriptors:ShDescriptor.__init__": ["network"],
    "btclib.descriptors:TrDescriptor.__init__": ["network"],
    "btclib.descriptors:WpkhDescriptor.__init__": ["network"],
    "btclib.descriptors:WshDescriptor.__init__": ["network"],
    "btclib.ecc.bms:Sig.__init__": ["check_validity"],
    "btclib.ecc.dsa:Sig.__init__": ["check_validity"],
    "btclib.ecc.dsa:assert_as_valid": ["commit", "receipt"],
    "btclib.ecc.dsa:assert_as_valid_": ["commit_hash", "receipt"],
    "btclib.ecc.dsa:sign": ["grind", "verify", "pub_key", "commit"],
    "btclib.ecc.dsa:sign_": ["grind", "verify", "pub_key", "commit_hash"],
    "btclib.ecc.dsa:verify": ["commit", "receipt"],
    "btclib.ecc.dsa:verify_": ["commit_hash", "receipt"],
    "btclib.ecc.ecies:Envelope.__init__": ["check_validity"],
    "btclib.ecc.ecies:decrypt": ["magic"],
    "btclib.ecc.ecies:encrypt": ["eph_prv_key", "magic"],
    "btclib.ecc.ssa:Sig.__init__": ["check_validity"],
    "btclib.ecc.ssa:assert_as_valid": ["commit", "receipt"],
    "btclib.ecc.ssa:assert_as_valid_": ["commit_hash", "receipt"],
    "btclib.ecc.ssa:sign": ["verify", "commit"],
    "btclib.ecc.ssa:sign_": ["verify", "commit_hash"],
    "btclib.ecc.ssa:verify": ["commit", "receipt"],
    "btclib.ecc.ssa:verify_": ["commit_hash", "receipt"],
    "btclib.fee:FeeRate.__init__": ["sats_per_kvbyte"],
    "btclib.fee:package_fee": ["ancestor_vsize", "ancestor_fee"],
    "btclib.fetch.transport:http_request": [
        "data",
        "headers",
        "timeout",
        "max_body_size",
        "transport",
    ],
    "btclib.fetch:BitcoinCoreFetcher.__init__": [
        "verify_network",
        "signet_challenge",
    ],
    "btclib.fetch:BitcoinCoreRpcClient.__init__": [
        "user",
        "password",
        "cookie_path",
        "timeout",
        "transport",
    ],
    "btclib.fetch:EsploraFetcher.__init__": ["network", "timeout", "transport"],
    "btclib.fetch:urlopen_transport": ["max_body_size"],
    "btclib.hwi:HwiSigner.__init__": [
        "executable",
        "network",
        "timeout",
        "max_output",
        "emulators",
        "capabilities",
    ],
    "btclib.hwi:enumerate_devices": [
        "executable",
        "network",
        "timeout",
        "max_output",
        "emulators",
    ],
    "btclib.network:Network.__init__": ["check_validity"],
    "btclib.psbt.musig2:add_participant_pub_keys": ["sort"],
    "btclib.psbt.musig2:nonce_gen": ["leaf_hash", "extra_in"],
    "btclib.psbt.musig2:partial_sig_verify": ["leaf_hash"],
    "btclib.psbt.musig2:partial_sign": ["leaf_hash"],
    "btclib.psbt.musig2:partial_sigs_agg": ["leaf_hash"],
    "btclib.psbt.musig2:session_context": ["leaf_hash"],
    "btclib.psbt.psbt_utils:deserialize_sized_int": ["signed"],
    "btclib.psbt.psbt_utils:deserialize_tx": ["unsigned_template"],
    "btclib.psbt.psbt_utils:serialize_sized_int": ["signed"],
    "btclib.psbt.psbt_utils:taproot_bip32_from_dict": ["check_validity"],
    "btclib.psbt:Psbt.__init__": ["check_validity"],
    "btclib.psbt:PsbtIn.__init__": ["check_validity"],
    "btclib.psbt:PsbtOut.__init__": ["check_validity"],
    "btclib.psbt:assert_signed": ["allow_partial"],
    "btclib.psbt:ecdsa_sig_hash": ["hash_type"],
    "btclib.psbt:estimated_input_sizes": ["sizer"],
    "btclib.psbt:extract_tx": ["check_validity"],
    "btclib.psbt:finalize": ["solver"],
    "btclib.psbt:taproot_sig_hash": ["leaf_hash", "hash_type"],
    "btclib.psbt_signer:SoftwareSigner.__init__": ["musig2"],
    "btclib.psbt_signer_contract:assert_psbt_signer": ["der_path", "signable"],
    "btclib.script.sig_hash:from_tx": ["codesep_index"],
    "btclib.script:Script.__init__": ["check_validity"],
    "btclib.script:ScriptPubKey.__init__": ["check_validity"],
    "btclib.script:Witness.__init__": ["check_validity"],
    "btclib.tx:OutPoint.__init__": ["check_validity"],
    "btclib.tx:Tx.__init__": ["check_validity"],
    "btclib.tx:TxIn.__init__": ["check_validity"],
    "btclib.tx:TxOut.__init__": ["check_validity"],
    "btclib.tx_or_psbt:tx_or_psbt_from_any": ["check_validity"],
}


def _resolve(label: str) -> Any:
    """Import `module:Class.__init__` or `module:function` back to the object.

    The colon is the split point rather than the last dot: a module name
    is dotted too (`btclib.ecc.dsa`), so the pair is stored apart instead
    of concatenated and re-split.
    """
    module_name, _, attr_path = label.partition(":")
    obj: Any = import_module(module_name)
    for part in attr_path.split("."):
        obj = getattr(obj, part)
    return obj


def _live_keyword_only() -> dict[str, list[str]]:
    """Recompute `KEYWORD_ONLY` from the tree currently under test.

    The same walk that produced the table above, run again: every
    module's `__all__`, a class read as its own `__init__` and skipped
    when it has none of its own, deduplicated by the id of the resolved
    callable so one object reachable under two names is one entry.
    """
    seen_ids: set[int] = set()
    found: dict[str, list[str]] = {}
    for module in library_modules():
        names = getattr(module, "__all__", None)
        if not names:
            continue
        for name in names:
            obj = getattr(module, name)
            if inspect.ismodule(obj):
                continue
            if inspect.isclass(obj):
                target = obj.__dict__.get("__init__")
                if target is None:
                    continue
                label = f"{module.__name__}:{name}.__init__"
            elif inspect.isfunction(obj) or inspect.isbuiltin(obj):
                target = obj
                label = f"{module.__name__}:{name}"
            else:
                continue
            if id(target) in seen_ids:
                continue
            seen_ids.add(id(target))
            kwonly = [
                parameter.name
                for parameter in inspect.signature(target).parameters.values()
                if parameter.kind == inspect.Parameter.KEYWORD_ONLY
            ]
            if kwonly:
                found[label] = kwonly
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
