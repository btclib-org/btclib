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
not only `__init__`. `Bip21.parse`'s `check_validity` is exactly the
shape `Bip21.__init__`'s does not cover: a classmethod the walk would
have missed had it stopped at the constructor, `*` turned to `/` there
passing both tests below in an earlier revision of this file. Inherited
methods are not walked a second time under a subclass that does not
override them, deduplication being by the id of the underlying function
once resolved, so a name re-exported under a second `__all__` --
`btclib.fetch.bitcoin_core` aliasing the `bitcoin-core-rpc` package,
`all_test.py`'s `REEXPORTED` -- is one entry and not two either.
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
    "btclib.bip21:Bip21.parse": ["check_validity"],
    "btclib.bip21:Bip21.serialize": ["check_validity"],
    "btclib.bip322:Sig.b64decode": ["check_validity"],
    "btclib.bip322:Sig.b64encode": ["check_validity"],
    "btclib.bip322:Sig.serialize": ["check_validity"],
    "btclib.bip322:assert_as_valid": ["legacy"],
    "btclib.bip322:to_sign": ["version", "lock_time", "sequence", "extra_inputs"],
    "btclib.bip322:verify": ["legacy"],
    "btclib.bip32:BIP32KeyData.__init__": ["check_validity"],
    "btclib.bip32:BIP32KeyData.b58decode": ["check_validity"],
    "btclib.bip32:BIP32KeyData.b58encode": ["check_validity"],
    "btclib.bip32:BIP32KeyData.parse": ["check_validity"],
    "btclib.bip32:BIP32KeyData.serialize": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.__init__": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.from_description": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.from_dict": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.parse": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.serialize": ["check_validity"],
    "btclib.bip32:BIP32KeyOrigin.to_dict": ["check_validity"],
    "btclib.bip32:decode_from_bip32_derivs": ["check_validity"],
    "btclib.bip32:hardenings_from_der_path": ["bip380_enforced"],
    "btclib.bip32:indexes_from_der_path": ["bip380_enforced"],
    "btclib.bip32:int_from_index_str": ["bip380_enforced"],
    "btclib.bip38:encrypt": ["compressed"],
    "btclib.bip38:intermediate_code": ["lot", "sequence", "owner_salt"],
    "btclib.bip38:new_key_pair": ["compressed", "seed_b"],
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
    "btclib.bolt11:Bolt11Invoice.__init__": ["check_validity"],
    "btclib.bolt11:Bolt11Invoice.from_invoice": ["check_validity"],
    "btclib.bolt11:Bolt11Invoice.sign": [
        "amount_msat",
        "description",
        "description_hash",
        "expiry",
        "min_final_cltv_expiry",
        "fallback_addresses",
        "route_hints",
        "features",
        "metadata",
        "extra_tags",
        "check_validity",
    ],
    "btclib.bolt11:RouteHintHop.__init__": ["check_validity"],
    "btclib.coin_selection:Candidate.__init__": ["check_validity"],
    "btclib.coin_selection:branch_and_bound": ["dust_fee_rate"],
    "btclib.coin_selection:knapsack": ["dust_fee_rate", "rng"],
    "btclib.coin_selection:select_coins": ["dust_fee_rate", "algorithms", "rng"],
    "btclib.coin_selection:single_random_draw": ["dust_fee_rate", "rng"],
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
    "btclib.ecc.bms:Sig.b64decode": ["check_validity"],
    "btclib.ecc.bms:Sig.b64encode": ["check_validity"],
    "btclib.ecc.bms:Sig.parse": ["check_validity"],
    "btclib.ecc.bms:Sig.serialize": ["check_validity"],
    "btclib.ecc.borromean:BorromeanSig.__init__": ["check_validity"],
    "btclib.ecc.borromean:BorromeanSig.parse": ["check_validity"],
    "btclib.ecc.borromean:BorromeanSig.serialize": ["check_validity"],
    "btclib.ecc.dsa:Sig.__init__": ["check_validity"],
    "btclib.ecc.dsa:Sig.parse": ["check_validity", "strict"],
    "btclib.ecc.dsa:Sig.serialize": ["check_validity"],
    "btclib.ecc.dsa:Signer.sign": ["grind", "verify"],
    "btclib.ecc.dsa:Signer.sign_": ["grind", "verify"],
    "btclib.ecc.dsa:assert_as_valid": ["commit", "receipt"],
    "btclib.ecc.dsa:assert_as_valid_": ["commit_hash", "receipt"],
    "btclib.ecc.dsa:sign": ["grind", "verify", "pub_key", "commit"],
    "btclib.ecc.dsa:sign_": ["grind", "verify", "pub_key", "commit_hash"],
    "btclib.ecc.dsa:verify": ["commit", "receipt"],
    "btclib.ecc.dsa:verify_": ["commit_hash", "receipt"],
    "btclib.ecc.ecies:Envelope.__init__": ["check_validity"],
    "btclib.ecc.ecies:Envelope.b64decode": ["magic", "check_validity"],
    "btclib.ecc.ecies:Envelope.b64encode": ["check_validity"],
    "btclib.ecc.ecies:Envelope.from_ciphertext": ["magic"],
    "btclib.ecc.ecies:Envelope.parse": ["magic", "check_validity"],
    "btclib.ecc.ecies:Envelope.serialize": ["check_validity"],
    "btclib.ecc.ecies:decrypt": ["magic"],
    "btclib.ecc.ecies:encrypt": ["eph_prv_key", "magic"],
    "btclib.ecc.ssa:Sig.__init__": ["check_validity"],
    "btclib.ecc.ssa:Sig.parse": ["check_validity"],
    "btclib.ecc.ssa:Sig.serialize": ["check_validity"],
    "btclib.ecc.ssa:Signer.sign": ["verify"],
    "btclib.ecc.ssa:Signer.sign_": ["verify"],
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
    "btclib.fetch:BitcoinCoreFetcher.broadcast": ["maxfeerate"],
    "btclib.fetch:BitcoinCoreRpcClient.__init__": [
        "user",
        "password",
        "cookie_path",
        "timeout",
        "transport",
    ],
    "btclib.fetch:BitcoinCoreRpcClient.assert_chain": ["signet_challenge"],
    "btclib.fetch:BitcoinCoreRpcClient.call": ["request_timeout", "max_body_size"],
    "btclib.fetch:BitcoinCoreRpcClient.call_batch": [
        "request_timeout",
        "max_body_size",
    ],
    "btclib.fetch:BitcoinCoreRpcClient.call_raw": [
        "jsonrpc",
        "request_timeout",
        "max_body_size",
    ],
    "btclib.fetch:BitcoinCoreRpcClient.from_chain": [
        "user",
        "password",
        "cookie_path",
        "timeout",
        "transport",
        "verify_chain",
        "signet_challenge",
    ],
    "btclib.fetch:BitcoinCoreRestClient.__init__": ["timeout", "transport"],
    "btclib.fetch:BitcoinCoreRestClient.from_chain": ["timeout", "transport"],
    "btclib.fetch:BitcoinCoreRestClient.get_bin": [
        "request_timeout",
        "max_body_size",
    ],
    "btclib.fetch:BitcoinCoreRestClient.get_json": [
        "request_timeout",
        "max_body_size",
    ],
    "btclib.fetch:BitcoinCoreRestFetcher.__init__": [
        "verify_network",
        "signet_challenge",
    ],
    "btclib.fetch:ElectrumFetcher.__init__": ["transport", "timeout"],
    "btclib.fetch:EsploraFetcher.__init__": [
        "network",
        "verify_network",
        "timeout",
        "transport",
    ],
    "btclib.fetch:SessionTransport.__init__": ["max_body_size", "connection_factory"],
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
    "btclib.psbt:Psbt.b64decode": ["check_validity"],
    "btclib.psbt:Psbt.b64encode": ["check_validity"],
    "btclib.psbt:Psbt.from_dict": ["check_validity"],
    "btclib.psbt:Psbt.from_tx": ["check_validity"],
    "btclib.psbt:Psbt.parse": ["check_validity"],
    "btclib.psbt:Psbt.serialize": ["check_validity"],
    "btclib.psbt:Psbt.to_dict": ["check_validity"],
    "btclib.psbt:PsbtIn.__init__": ["check_validity"],
    "btclib.psbt:PsbtIn.from_dict": ["check_validity"],
    "btclib.psbt:PsbtIn.parse": ["psbt_version", "check_validity"],
    "btclib.psbt:PsbtIn.serialize": ["psbt_version", "check_validity"],
    "btclib.psbt:PsbtIn.to_dict": ["check_validity"],
    "btclib.psbt:PsbtOut.__init__": ["check_validity"],
    "btclib.psbt:PsbtOut.from_dict": ["check_validity"],
    "btclib.psbt:PsbtOut.parse": ["psbt_version", "check_validity"],
    "btclib.psbt:PsbtOut.serialize": ["psbt_version", "check_validity"],
    "btclib.psbt:PsbtOut.to_dict": ["check_validity"],
    "btclib.psbt:PsbtView.ecdsa_sig_hash": ["hash_type"],
    "btclib.psbt:PsbtView.input": ["check_validity"],
    "btclib.psbt:PsbtView.output": ["check_validity"],
    "btclib.psbt:PsbtView.taproot_sig_hash": ["leaf_hash", "hash_type"],
    "btclib.psbt:assert_signed": ["allow_partial"],
    "btclib.psbt:ecdsa_sig_hash": ["hash_type"],
    "btclib.psbt:estimated_input_sizes": ["sizer"],
    "btclib.psbt:extract_tx": ["check_validity"],
    "btclib.psbt:finalize": ["solver"],
    "btclib.psbt:taproot_sig_hash": ["leaf_hash", "hash_type"],
    "btclib.psbt_signer:SoftwareSigner.__init__": ["musig2"],
    "btclib.psbt_signer:SoftwareSigner.from_accounts": ["musig2"],
    "btclib.psbt_signer_contract:assert_psbt_signer": ["der_path", "signable"],
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
    "btclib.tx_builder:build_psbt": [
        "tx_version",
        "lock_time",
        "dust_fee_rate",
        "sizer",
    ],
    "btclib.tx_or_psbt:tx_or_psbt_from_any": ["check_validity"],
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
