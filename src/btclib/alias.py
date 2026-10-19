# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The type aliases of the public API, and the input conventions they name.

Octets, String, BinaryData, Integer and Point are ecc.alias's,
which has the reasons for them, and are imported here so that a caller
spells them btclib.alias.Octets.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, Union

from ecc.alias import BinaryData, Integer, Octets, Point, String

__all__ = [
    "BinaryData",
    "Command",
    "HashDigestF",
    "Integer",
    "NetworkField",
    "NetworkName",
    "NetworkType",
    "Octets",
    "Point",
    "ScriptList",
    "ScriptType",
    "String",
    "TaprootLeaf",
    "TaprootLeafPaths",
    "TaprootScriptTree",
    "TxoutType",
]

# Octets are used for serialized script, h160 (20 bytes), h256 (32 bytes),
# BIP32 version (4 bytes), sig_hash_type (1 byte),
# dsa.Sig (DER serialization of ECDSA signature),
# ssa.Sig (BIP340 serialization of Schnorr signature)
# etc.; use btclib.utils.bytes_from_octets to convert them to bytes.
#
# String is used for addresses (base58 or bech32), WIFs, BIP32 keys, a
# message to be signed and bms.Sig (Bitcoin message compact signature
# serialization). In almost all cases (but messages to be signed)
# leading and trailing blanks should always be stripped, and there is
# no need to encode() to bytes as b58decode/b32decode/etc. take care of
# that; use btclib.utils.str_from_string to convert them to str

# What kind of chain a network is: the real one, or one of the test ones.
#
# This is the distinction the version bytes were designed to draw --
# Satoshi's 0x6f, BIP32's tpub, SLIP132, and SLIP44 giving every test
# chain one coin type -- and every network in the catalogue can still be
# placed by it: no prefix of any test network equals any prefix of
# mainnet, on any field, so "main or test" always has an answer where
# "which chain" does not. testnet, regtest, signet and
# testnet4 share one set of prefixes on purpose, Core copying testnet's
# into the newer two, so a prefix cannot tell them apart. See issue #207
# and btclib.network's three network_type_from_* functions.
#
# "main" is Core's own name for the chain (`chain=main` in getblockchain
# info); "test" is SLIP44's testnet *family*, and deliberately not
# Core's `chain=test`, which names testnet3 alone.
#
# A Literal and not an Enum: network names are plain str throughout this
# library, so a lone enum here would be an island, and mypy strict
# already rejects the typo an Enum would guard against. That is the same
# choice the vocabularies below make, for the reasons written over them
NetworkType = Literal["main", "test"]

# The closed vocabularies this library passes as plain str, one Literal
# each: issue #216. Strict mypy refuses a typo at every call site that
# spells the value out, which is most of them, and refuses nothing where
# the string is computed at run time -- that is the whole of what a
# Literal buys and the whole of what it does not.
#
# Literal and not Enum, and the issue measures why: a Literal has no
# runtime existence at all -- nothing to format, nothing new for
# to_dict to serialize, and no signature that stops accepting a str --
# where even enum.StrEnum, formatting as the value at every interpreter
# the floor now covers, would still cost the last two.
#
# Which of them a *parameter* may take is the other half of the answer,
# and it is not the same for all of them: an argument annotated with a
# Literal is a promise that the vocabulary is closed, so ScriptType and
# NetworkField are spelled on parameters. NetworkName is closed too and
# still is not, for the reason written over it.

# What a script_pub_key pays to, as script.script_pub_key.type_and_payload
# names it. Closed, and checked to be: these are exactly what that
# function returns, mypy comparing each return against this alias. Note
# that "unknown" is one of them -- the answer for bytes this library does
# not classify, not the absence of an answer -- so there is no None here
# to widen the type of every caller. Parameters take it: b58's two
# address functions dispatch on it
ScriptType = Literal[
    "nulldata",
    "p2ms",
    "p2pk",
    "p2pkh",
    "p2sh",
    "p2tr",
    "p2wpkh",
    "p2wsh",
    "unknown",
    "witness_unknown",
]

# What Bitcoin Core's `Solver` classifies a script_pub_key as: the
# values of its TxoutType, spelled as its GetTxnOutputType spells them.
# Closed, and not ScriptType: that one is what `type_and_payload` answers,
# which is narrower than Core's classification (issue #211) and names its
# types otherwise.
TxoutType = Literal[
    "nonstandard",
    "anchor",
    "pubkey",
    "pubkeyhash",
    "scripthash",
    "multisig",
    "nulldata",
    "witness_v0_keyhash",
    "witness_v0_scripthash",
    "witness_v1_taproot",
    "witness_unknown",
]

# A field name of network.Network, which the three *_from_key_value
# lookups take as a str and resolve with getattr. The most fragile of
# these vocabularies, and so a parameter type: mypy holds a caller to
# the names below, and `network._NETWORK_FIELDS` is the same vocabulary
# at run time, for the callers mypy never sees -- a name outside it is a
# BTClibValueError there rather than the AttributeError getattr would
# raise, and rather than the empty list that would read as a fact about
# the prefix. network_test.py checks the members against
# dataclasses.fields(Network), the one thing mypy cannot check about a
# name resolved with getattr.
#
# Not "NetworkKey": in this library a key is a private or a public one
NetworkField = Literal[
    "curve",
    "network_type",
    "consensus",
    "genesis_block",
    "wif",
    "p2pkh",
    "p2sh",
    "hrp",
    "bip32_prv",
    "bip32_pub",
    "slip132_p2wpkh_p2sh_prv",
    "slip132_p2wpkh_p2sh_pub",
    "slip132_p2wsh_p2sh_prv",
    "slip132_p2wsh_p2sh_pub",
    "slip132_p2wpkh_prv",
    "slip132_p2wpkh_pub",
    "slip132_p2wsh_prv",
    "slip132_p2wsh_pub",
]

# The networks btclib ships, which is every network there is here:
# network.NETWORKS is fixed at import and read-only, so this list is the
# whole of the vocabulary and not a sample of it.
#
# Still not a parameter type, and issue #216 is where that is decided: the
# `network: str` parameters accept a name with spaces around it and in any
# case -- `network.network_from_name` is what they run it through -- so the
# set they take is wider than the spellings named here, and narrowing the
# annotation without dropping that tolerance would reject calls that work.
# One converter and not a `strip().lower()` per call site, which is what
# left b32 and the mnemonic modules indexing NETWORKS raw and refusing the
# tolerance this paragraph promised (issue #744).
# It names the spellings for a caller who wants mypy to hold them to it;
# network.py annotates with it the tuple of names it loads, which is what
# keeps this list equal to the data
NetworkName = Literal["mainnet", "testnet", "regtest", "signet", "testnet4"]

# A one-shot digest: hf(data) returns the digest, where a
# ecc.alias.HashF returns an object to update. The merkle functions
# of btclib.hashes take this one -- hash256, not hashlib.sha256.
#
# Naming it makes a swap a type error rather than a runtime one, and the
# type is load-bearing in both directions: hashlib.sha256 satisfies a HashF's
# arity but returns a HASH and not bytes, so it is rejected here, and
# hash256 takes an argument, so it is rejected as a HashF
HashDigestF = Callable[[Octets], bytes]

# spelled out rather than written `int | Octets`, though the spellings
# are the same list: a `str` here is an opcode name or hex data and an
# `Octets` str is hex and nothing else, so the two aliases would be one
# name for two roles. The buffers are here because a push of a
# bytearray is a push of what it holds: `script.serialize` wrote one
# already, and `taproot.serialize` had to be taught to -- its
# OP_SUCCESS arm asked `isinstance(script[0], bytes)` and refused the
# other two
Command = int | str | bytes | bytearray | memoryview
ScriptList = list[Command]

# A BIP341 taproot script tree, recursive: a branch nests two more of
# the same alias.
#
# list, and not the Sequence mypy's variance note suggests when a caller's
# list[tuple[int, list[str]]] does not fit: str is itself a Sequence[str],
# so under Sequence the recursion accepts any str as an entire tree --
# output_pubkey(None, "hello") type checks -- and a (leaf_version, script)
# tuple with a str version passes as a branch of two subtrees. Measured
# over five malformed trees, list rejects five and Sequence three.
# Invariance is the cost and the point: it is what makes a str not a tree.
# It is paid wherever a tree is built into a variable instead of passed as
# a literal, by annotating that variable with this alias
TaprootLeaf = tuple[int, ScriptList]
#: A leaf, a one-element list holding a `TaprootLeaf`, or a branch, a
#: two-element list of subtrees.
TaprootScriptTree = list[Union[TaprootLeaf, "TaprootScriptTree"]]

# what tree_helper returns beside the merkle root: every leaf of the tree
# paired with the concatenated sibling hashes that prove it, i.e. the tail
# of the control block input_script_sig builds
TaprootLeafPaths = list[tuple[TaprootLeaf, bytes]]
