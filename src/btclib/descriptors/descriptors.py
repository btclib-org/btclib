# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Output descriptors: the checksum, the parser, the scripts, the spend.

A descriptor says which scripts a wallet owns, in one line of text. This
module reads that line and answers with both halves of what a wallet
does with it: `parse` returns a `Descriptor`, whose `script_pub_keys`
gives what the descriptor pays to at an index -- the receiving side --
and whose `satisfy` gives the script_sig and the witness that spend one
of those scripts, the signatures being handed in. The fragment classes
below are one per grammar function, which is what lets satisfaction be a
method of each rather than a dispatch table.

`satisfy` assembles and does not verify. A signature is checked against
the hash it committed to, that hash is a property of the spending
transaction, and a descriptor has no transaction -- which is also why
the signatures are a parameter rather than something this module makes.
`psbt.finalize` does have one and does check, and builds the same
bytes from a psbt carrying the same signatures.

`update_psbt_input` and `update_psbt_output` are the third answer, and
the one for a spend the signers do not make all at once: BIP174's Updater,
writing the scripts and the key origins into a psbt, for signers to fill
in at their own pace and `psbt.finalize` to assemble. The output half is
also what tells change from a payment, and it makes that claim only where
the descriptor derives the very script being paid -- `index_of` is the
same question asked the other way round, and neither answers from a key
origin whose fingerprint happens to match. This module imports `psbt` for
all of it and nothing there imports back, which is the direction of the
layering: a psbt is a transaction being built, and a descriptor is what a
wallet knows about the outputs it holds.

BIP380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki

The grammar read is BIP380 to BIP390:

- ``pk``, ``pkh``, ``wpkh``, ``combo`` (BIP381, BIP382, BIP384)
- ``sh``, ``wsh``, including ``sh(wpkh())`` and ``sh(wsh())``
- ``multi``, ``sortedmulti`` (BIP383)
- ``addr``, ``raw`` (BIP385)
- ``tr``, with a key path and a script tree whose leaves are ``pk()``,
  ``multi_a()`` and ``sortedmulti_a()`` (BIP386, BIP387)
- ``rawtr``, which no BIP specifies: Bitcoin Core's `doc/descriptors.md`
  is what defines it, and the key it takes is the output key itself
- key expressions: hex public keys (compressed, uncompressed and, inside
  ``tr()`` and ``rawtr()``, x-only), WIF private keys, xpub/xprv with a
  derivation path, key origin, ``/*`` and ``/*h`` wildcards, both ``h``
  and ``'`` hardened markers
- ``musig``, the BIP390 key expression: the BIP327 aggregate of its
  participants, inside a ``tr()`` or a ``rawtr()`` and nowhere else, with
  BIP328 derivation of the aggregate key where it has a path of its own
- the ``<a;b>`` multipath form of BIP389, through `multipath_descriptors`
- a BIP379 miniscript, in both of the positions that BIP allows: inside
  ``wsh()``, where it is a `MiniscriptDescriptor`, and as a leaf of a
  ``tr()`` script tree, where it is a leaf beside the ``pk()`` and the
  ``multi_a()`` ones. Which expression is read as which is the order
  Bitcoin Core reads them in: the functions above are tried first, so the
  ``pk()``, ``pkh()`` and ``multi()`` that belong to both grammars are the
  descriptor functions they were before miniscript, and what is left is a
  miniscript -- of the P2WSH dialect inside ``wsh()`` and of the tapscript
  one inside ``tr()``, which is where ``multi_a()`` replaces ``multi()``

`satisfy` takes a `SpendContext` beside the signatures for the one
fragment that reads more than they carry: a miniscript satisfaction
chooses among branches, and the choice reads hash preimages and the lock
times the transaction being built will carry. Every other fragment ignores
it, having neither a branch to choose nor a preimage to look up.

`miniscript_solver` is the same satisfaction reached from the other side,
where there is a psbt and no descriptor: an `InputSolver` for
`psbt.finalize`, which reads the witness script back into the expression
it is and satisfies it from the input's own fields. It lives here rather
than in `psbt` because of the direction above -- this module imports that
one -- and a caller passes it: `finalize(psbt, solver=miniscript_solver)`.

BIP390's rule that a multipath ``musig()`` may not hold multipath
participants has no counterpart here, and cannot: `parse` refuses a
``<a;b>`` step anywhere, `multipath_descriptors` expands it textually as
BIP389 defines, and what reaches a `Descriptor` is one path per key. Such
a descriptor is refused, and for the more general reason.

A parsed descriptor holds no key that signs. `parse` neuters an xprv to
the xpub the `KeyExpression` then carries, and hands the private spelling
back through the `prv_keys` mapping a caller passes in -- Bitcoin Core's
`Parse(desc, out, error)`, whose descriptor keeps no reference to the
`FlatSigningProvider` it filled. Expansion takes the mapping back for the
one thing an xpub cannot do, a hardened step, which is why
`script_pub_keys`, `satisfy`, the two `update_psbt` halves and the rest
all end in an
optional `prv_keys`. A WIF is not in that mapping: it was already reduced
to its public key on the way in, this module deriving nothing from it and
signing nothing with it.

The network is a parameter of `parse` and not part of a descriptor: a
descriptor names keys and scripts, and the same one means something on
any chain, which is why Bitcoin Core takes the chain from its own context
too. ``addr()`` is the exception, an address carrying the network in its
own prefix.

`str(descriptor)` is the way back: the descriptor as text, without its
checksum, `add_checksum` being what appends one. Bitcoin Core splits it
the same way -- `ToString` writes none and the rpc layer appends it --
where HWI and Electrum name the checksummed form `to_string`. What it
writes is public by construction, there being no private material left
in a parsed descriptor to write.

`account_descriptors` is the other way in, for the one shape a wallet
exports rather than reads: the receive and change descriptors of a BIP44
account, built from an account xpub and the master fingerprint of the key
it came from. The purpose says which of the four encodings the account
means, which is `bip44`'s mapping and is taken from there rather than
copied -- this module imports that one and `bip44` imports nothing back.

`normalized` is the other direction Bitcoin Core has, its
`ToNormalizedString`: the same descriptor with the xpub at each last
hardened step and the hardened prefix moved into the key origin, so that
a holder of no private key can compute every script it describes. That is
what `getdescriptorinfo` answers with, and what an export to a watch-only
wallet wants.

What this module exports is the checksum functions, `parse` and
`multipath_descriptors`, and the fragment classes a parsed descriptor is
made of -- `DescriptorTree` and the `MultiA` a tree leaf may be among
them, both being names a caller reads off `TrDescriptor.tree`.
`KeyExpression` and `PrvKeys` are `key_expression`'s and the `Miniscript`
a `MiniscriptDescriptor` holds is `miniscript`'s; the package `__init__`
re-exports the first two, being what a caller reads off
`Descriptor.key_expressions` and annotates a mapping with.
`INPUT_CHARSET`, `CHECKSUM_CHARSET` and `GENERATOR` stay out: they are the
three tables BIP380's checksum is computed from, which is what `checksum`,
`add_checksum` and `strip_checksum` answer.
"""

from __future__ import annotations

import operator
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from typing import Any, cast

from typing_extensions import override

from btclib.alias import BIP44ScriptType, Octets, ScriptList, TaprootScriptTree
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _derive,
    _key_data_from_bip32_key,
    _xpub_from_xprv,
    fingerprint,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    _HARDENING,
    DerPath,
    indexes_from_der_path,
)
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.bip44 import (
    _assert_valid_account_path,
    _assert_valid_coin_type,
    _indexes_left_to_derive,
    _script_type_from_purpose,
)
from btclib.descriptors import miniscript
from btclib.descriptors.key_expression import (
    KeyExpression,
    PrvKeys,
    _assert_musig_allowed,
    _expression,
    _offered_signature,
    _parse_key,
    _split_arguments,
    _split_function,
)
from btclib.descriptors.miniscript import (
    Miniscript,
    SpendContext,
    _assert_sane,
)
from btclib.descriptors.miniscript import from_script as _miniscript_from_script
from btclib.descriptors.miniscript import parse as _parse_miniscript
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import (
    NETWORKS,
    _validated_network_name,
    network_from_xkeyversion,
)
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import SIG_SIZE, SolutionSizer, _assert_input_types
from btclib.script.script import op_int, serialize
from btclib.script.script import parse as _parse_script
from btclib.script.script_pub_key import ScriptPubKey, _validated_script_from
from btclib.script.taproot import (
    MAX_TREE_DEPTH,
    input_script_sig,
    leaf_hash,
    tree_helper,
)
from btclib.script.witness import Witness
from btclib.tx.tx_in import TxIn
from btclib.utils import assert_type, bytes_from_octets, is_octets

__all__ = [
    "AddrDescriptor",
    "ComboDescriptor",
    "Descriptor",
    "DescriptorLeaf",
    "DescriptorTree",
    "MiniscriptDescriptor",
    "MultiA",
    "MultiDescriptor",
    "PkDescriptor",
    "PkhDescriptor",
    "RawDescriptor",
    "RawTrDescriptor",
    "ShDescriptor",
    "TrDescriptor",
    "WpkhDescriptor",
    "WshDescriptor",
    "account_descriptors",
    "add_checksum",
    "at_index",
    "checksum",
    "from_address",
    "miniscript_sizer",
    "miniscript_solver",
    "multipath_descriptors",
    "normalized",
    "parse",
    "satisfaction_sizer",
    "strip_checksum",
]

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]

# a digit for every character, built once: `char not in INPUT_CHARSET`
# and `INPUT_CHARSET.find(char)` were each a scan of all 92 characters,
# one to validate and one to find the index. -1 rather than None keeps
# the lookup a plain int and doubles as the validity check, since a
# digit is never negative
_INPUT_INDEX = {c: i for i, c in enumerate(INPUT_CHARSET)}


def __descsum_polymod(symbols: list[int]) -> int:
    """Compute the descriptor checksum polymod."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def __descsum_expand(descriptor_string: str) -> list[int]:
    """Perform the character to symbol expansion."""
    groups: list[int] = []
    symbols: list[int] = []
    for char in descriptor_string:
        index = _INPUT_INDEX.get(char, -1)
        if index == -1:
            raise BTClibValueError(f"invalid descriptor character: {char!r}")
        symbols.append(index & 31)
        groups.append(index >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def checksum(descriptor: str) -> str:
    """Compute the descriptor checksum."""
    symbols = [*__descsum_expand(descriptor), 0, 0, 0, 0, 0, 0, 0, 0]
    polymod = __descsum_polymod(symbols) ^ 1
    return "".join(CHECKSUM_CHARSET[(polymod >> (5 * (7 - i))) & 31] for i in range(8))


def strip_checksum(descriptor: str) -> str:
    """Return the descriptor without its checksum, verifying a present one.

    A descriptor without one comes back unchanged: the checksum is
    optional in the language, and only some of Bitcoin Core's RPCs
    require it. What is never accepted is a checksum that does not match,
    which is what the eight characters are there for.
    """
    body, separator, given_checksum = descriptor.partition("#")
    if "#" in given_checksum:
        raise BTClibValueError(f"more than one '#' in the descriptor: {descriptor}")
    # computed before the comparison, and whether or not there is one to
    # compare against: it is also what refuses a character outside
    # INPUT_CHARSET, which is an error in a descriptor with no checksum
    expected = checksum(body)
    if separator and given_checksum != expected:
        err_msg = f"invalid descriptor checksum: {given_checksum}, {expected} expected"
        raise BTClibValueError(err_msg)
    return body


def add_checksum(descriptor: str) -> str:
    """Return the descriptor with its checksum, verifying a present one."""
    body = strip_checksum(descriptor)
    return f"{body}#{checksum(body)}"


def from_address(address: str) -> str:
    """Return the addr() descriptor of the address, checksummed."""
    return add_checksum(f"addr({address})")


# the tapscript leaf version, which is the only one a BIP386 tree has
_TAPSCRIPT_LEAF_VERSION = 0xC0

# where a SCRIPT expression sits. BIP381 to BIP386 give each function a
# position rule -- sh() is top level only, wpkh() is top level or inside
# sh(), and so on -- so the context is an argument of the parser, and
# these strings are what its error messages say
_TOP = "top level"
_P2SH = "sh()"
_P2WSH = "wsh()"
_P2TR = "tr()"

# where a miniscript may be written, and which of BIP379's two contexts
# that position is: inside wsh() and inside a tr() leaf, and nowhere else,
# which is the BIP's own "only valid in wsh() and tr() contexts". The two
# dialects differ in more than their keys, so the position is what picks
# between them rather than something a caller passes
_MINISCRIPT_CONTEXTS = {_P2WSH: miniscript.P2WSH, _P2TR: miniscript.TAPSCRIPT}

# BIP387's own bound on the keys of a multi_a(): the satisfaction puts one
# stack element per key, and a script whose spend would push more than the
# 1000 elements BIP342 allows is one nobody can spend
_MAX_MULTI_A_KEYS = 999

# the two functions BIP387 allows inside tr() and nowhere else. Not in
# _PARSERS with the SCRIPT expressions: what they parse to is a leaf of a
# script tree and not a descriptor, so `_parse_tree` reads them and this
# is what refuses them anywhere a SCRIPT expression is expected
_TREE_FUNCTIONS = ("multi_a", "sortedmulti_a")

_THRESHOLD = re.compile(r"[0-9]+")
# the BIP389 multipath step, brackets included: re.split hands back what
# it split on when the pattern captures it
_MULTIPATH_STEP = re.compile(r"(<[^<>]*>)")


@dataclass(frozen=True)
class MultiA:
    """``multi_a(k,KEY,...)`` or ``sortedmulti_a(k,KEY,...)``: a leaf, BIP387.

    A leaf of a ``tr()`` script tree, beside the bare `KeyExpression` that
    is a ``pk()`` leaf, and not a `Descriptor`: BIP387 allows these two
    functions inside ``tr()`` and nowhere else, so no output pays to one
    of them -- what an output pays to is the ``tr()`` that commits to it
    as one of its tapscripts.
    """

    threshold: int
    keys: tuple[KeyExpression, ...]
    # the ordering that is the whole difference between the two functions,
    # as BIP67 is for sortedmulti(): the keys of a sortedmulti_a() are
    # sorted in the script, so the participants need not agree on an order
    # to agree on an address
    sort: bool = False

    @override
    def __str__(self) -> str:
        """Return the ``multi_a()`` or ``sortedmulti_a()`` leaf as text."""
        name = "sortedmulti_a" if self.sort else "multi_a"
        return _expression(name, str(self.threshold), *map(str, self.keys))

    def _pub_keys(
        self, index: int, network: str, prv_keys: PrvKeys | None
    ) -> list[bytes]:
        """Return the SEC keys in the order the script holds them.

        Sorted on the x-only bytes and not on these: what a tapscript
        carries is 32 bytes per key, and the 33-byte form adds to them a
        prefix saying the parity of y -- so sorting the SEC bytes would
        order the keys by that parity first, and a ``sortedmulti_a()``
        naming a key by its WIF would get another script than the same
        key written x-only.
        """
        pub_keys = [key.sec(index, network, prv_keys) for key in self.keys]
        key_x = operator.itemgetter(slice(1, None))
        return sorted(pub_keys, key=key_x) if self.sort else pub_keys

    def _script(self, index: int, network: str, prv_keys: PrvKeys | None) -> ScriptList:
        """Return the tapscript of BIP387: a CHECKSIG, then CHECKSIGADDs.

        The threshold is pushed as OP_1 to OP_16 where an op code means
        it and as the number itself above that, which is what BIP387 says
        and the one place the two spellings differ.

        The bounds are checked here, and not in the parser, for the reason
        `multi()` has them in `ScriptPubKey.p2ms`: a threshold of none or
        of more keys than there are describes a script nobody can spend,
        and a descriptor built by hand reaches this and not the parser.
        """
        pub_keys = self._pub_keys(index, network, prv_keys)
        if not 1 <= self.threshold <= len(pub_keys):
            err_msg = f"invalid k in k-of-n multi_a: {self.threshold}"
            raise BTClibValueError(err_msg)
        if len(pub_keys) > _MAX_MULTI_A_KEYS:
            err_msg = f"invalid n in k-of-n multi_a: {len(pub_keys)}"
            raise BTClibValueError(err_msg)
        script: ScriptList = [pub_keys[0][1:], "OP_CHECKSIG"]
        for pub_key in pub_keys[1:]:
            script += [pub_key[1:], "OP_CHECKSIGADD"]
        threshold = op_int(self.threshold) if self.threshold <= 16 else self.threshold
        return [*script, threshold, "OP_NUMEQUAL"]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        network: str,
        prv_keys: PrvKeys | None,
    ) -> list[bytes] | None:
        """Return one element per key, or None where the keys have not signed.

        `threshold` of the elements are signatures and the rest the empty
        push. A signature beyond the threshold is not spare, which is the
        first difference from `multi()`: OP_CHECKSIGADD counts every
        signature that verifies and OP_NUMEQUAL compares the count with
        the threshold, where OP_CHECKMULTISIG stops at the signatures it
        was built to pop.

        The elements go in the reverse of the key order, which is the
        second: the signature of the first key is popped first, so it is
        the last element of the witness and the top of the stack. Bitcoin
        Core's satisfier says the same in a comment of its own.

        None rather than an error where fewer keys than the threshold have
        signed: a leaf is one spending path of a tree, and which of them
        the signatures at hand open is the question `TrDescriptor` walks
        the leaves to answer.
        """
        offered = [
            _offered_signature(signatures, sec, x_only=True)
            for sec in self._pub_keys(index, network, prv_keys)
        ]
        if sum(signature is not None for signature in offered) < self.threshold:
            return None
        stack: list[bytes] = []
        signed = 0
        for signature in offered:
            if signature is None or signed == self.threshold:
                stack.append(b"")
            else:
                stack.append(signature)
                signed += 1
        stack.reverse()
        return stack


def _tree_expression(tree: DescriptorTree) -> str:
    """Return a BIP386 TREE as text: a leaf, or two subtrees in braces."""
    if isinstance(tree, tuple):
        return f"{{{_tree_expression(tree[0])},{_tree_expression(tree[1])}}}"
    if isinstance(tree, (MultiA, Miniscript)):
        return str(tree)
    return _expression("pk", str(tree))


# a tr() script tree: a leaf, or a branch of two subtrees. A leaf is the
# KEY expression a `pk()` leaf is, the `MultiA` of BIP387's two
# functions; a branch is a tuple, which is what tells a branch from a
# leaf. The leaves hold KEY expressions and not scripts because a ranged
# descriptor has no script until an index is given
DescriptorLeaf = KeyExpression | MultiA | Miniscript
DescriptorTree = DescriptorLeaf | tuple["DescriptorTree", "DescriptorTree"]


def _leaf_keys(leaf: DescriptorLeaf) -> tuple[KeyExpression, ...]:
    """Return the KEY expressions of one leaf, in the order it names them."""
    if isinstance(leaf, MultiA):
        return leaf.keys
    if isinstance(leaf, Miniscript):
        return leaf.key_expressions
    return (leaf,)


def _tree_leaves(tree: DescriptorTree) -> tuple[DescriptorLeaf, ...]:
    """Return the leaves left to right, which is the order they are numbered.

    `taproot.tree_helper` walks the left subtree before the right one, so
    the n-th leaf here is the n-th leaf there, and that number is what
    `taproot.input_script_sig` takes.
    """
    if isinstance(tree, tuple):
        return _tree_leaves(tree[0]) + _tree_leaves(tree[1])
    return (tree,)


def _tree_keys(tree: DescriptorTree) -> tuple[KeyExpression, ...]:
    keys: tuple[KeyExpression, ...] = ()
    for leaf in _tree_leaves(tree):
        keys += _leaf_keys(leaf)
    return keys


def _leaf_script(
    leaf: DescriptorLeaf, index: int, network: str, prv_keys: PrvKeys | None
) -> ScriptList:
    """Return the tapscript of one leaf: a key, a ``multi_a()``, a miniscript.

    Read back into commands where the leaf is a miniscript, that being
    what a `TaprootLeaf` holds: the round trip is exact for these bytes,
    every push a miniscript writes being the minimal one.
    """
    if isinstance(leaf, MultiA):
        return leaf._script(index, network, prv_keys)
    if isinstance(leaf, Miniscript):
        return _parse_script(leaf.script(index, network, prv_keys))
    return [leaf.sec(index, network, prv_keys)[1:], "OP_CHECKSIG"]


def _leaf_scripts(
    tree: DescriptorTree,
    depth: int,
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> list[tuple[int, bytes]]:
    """Return each leaf's depth and serialized script, left to right.

    The depth is what BIP371's PSBT_OUT_TAP_TREE carries beside the
    script, and the two together are the tree: a depth-first walk that
    records how deep each leaf sits is enough to rebuild the shape it was
    walked from. The order is `_tree_leaves`'s, which is the order
    `taproot.tree_helper` numbers them in.
    """
    if isinstance(tree, tuple):
        return _leaf_scripts(tree[0], depth + 1, index, network, prv_keys) + (
            _leaf_scripts(tree[1], depth + 1, index, network, prv_keys)
        )
    return [(depth, serialize(_leaf_script(tree, index, network, prv_keys)))]


def _leaf_stack(
    leaf: DescriptorLeaf,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
    spend: SpendContext | None,
) -> list[bytes] | None:
    """Return what satisfies one leaf, None where the signatures do not.

    None rather than a refusal, for a miniscript leaf as for the other
    two: which leaf the signatures at hand open is the question the caller
    is walking the tree to answer, so a leaf they do not open is an answer
    and not an error -- including one whose branches want a preimage or a
    lock time this spend does not have.
    """
    if isinstance(leaf, MultiA):
        return leaf._stack(signatures, index, network, prv_keys)
    if isinstance(leaf, Miniscript):
        offered = cast("Mapping[Octets, Octets]", signatures)
        try:
            return leaf.satisfy(offered, spend, index, network, prv_keys)
        except BTClibValueError:
            return None
    signature = _offered_signature(
        signatures, leaf.sec(index, network, prv_keys), x_only=True
    )
    return None if signature is None else [signature]


def _taproot_script_tree(
    tree: DescriptorTree, index: int, network: str, prv_keys: PrvKeys | None
) -> TaprootScriptTree:
    if isinstance(tree, tuple):
        return [
            _taproot_script_tree(tree[0], index, network, prv_keys),
            _taproot_script_tree(tree[1], index, network, prv_keys),
        ]
    return [(_TAPSCRIPT_LEAF_VERSION, _leaf_script(tree, index, network, prv_keys))]


def _required_signature(signatures: Mapping[bytes, bytes], sec: bytes) -> bytes:
    """Return the signature made with a public key, refusing where none is.

    The key is named in the error: it is public by construction, and
    which of a descriptor's keys has not signed is the whole content of
    the refusal.
    """
    signature = _offered_signature(signatures, sec, x_only=False)
    if signature is None:
        raise BTClibValueError(f"no signature for public key {sec.hex()}")
    return signature


def _derived_origin(key: KeyExpression, index: int) -> BIP32KeyOrigin | None:
    """Return the origin of the key at `index`, None for a key without one.

    `KeyExpression.origin` is the path down to the extended key the
    descriptor holds, and what BIP174 carries is the path down to the
    key itself: the derivation the descriptor then does, the wildcard
    step at `index` included, appended to it. A signer given the shorter
    path would derive the wrong key from it.
    """
    if key.origin is None:
        return None
    der_path = [*key.origin.der_path, *key.der_path]
    if key.wildcard is not None:
        der_path.append(key.wildcard + index)
    return BIP32KeyOrigin(key.origin.master_fingerprint, der_path)


def _aggregate_origin(
    key: KeyExpression, index: int, network: str, prv_keys: PrvKeys | None
) -> BIP32KeyOrigin | None:
    """Return where a derived aggregate key came from, None where it is one.

    BIP373's answer to "how does this key relate to the aggregate the
    participants make": the derivation path, under the fingerprint of
    BIP328's synthetic xpub, which is hash160 of the aggregate key -- and
    which is what lets a signer recognize the field as BIP328 derivation
    without a `PSBT_GLOBAL_XPUB` naming that synthetic key.
    `psbt.musig2` reads it back exactly that way.

    None where the expression derives nothing, the key in the script then
    being the aggregate itself and the psbt having nothing to say about how
    to get from one to the other.
    """
    der_path = [*key.der_path]
    if key.wildcard is not None:
        der_path.append(key.wildcard + index)
    if not der_path:
        return None
    aggregate = key.aggregate(index, network, prv_keys)
    return BIP32KeyOrigin(hash160(aggregate)[:4], der_path)


def _taproot_derivations(
    keys: Sequence[KeyExpression],
    leaf_hashes: Mapping[bytes, list[bytes]],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]:
    """Return BIP371's derivation field for a set of taproot key expressions.

    Keyed by the 32 bytes a tapscript holds, and carrying the tapleaf hash
    of every leaf the key appears in, which the caller has worked out: none
    for a key that is only the internal one, and one per leaf otherwise.

    A ``musig()`` puts two kinds of entry here, both of which BIP373 asks
    the Updater for: the key in the script, under the synthetic origin
    `_aggregate_origin` computes, and each participant that carries an
    origin of its own -- the second being how a signer finds out that one
    of the keys it holds is in this group at all. A participant is in no
    leaf, so its leaf hashes are empty; what says which leaves the group
    signs for is the aggregate's own entry.
    """
    derivations: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]] = {}
    for key in keys:
        origin = (
            _aggregate_origin(key, index, network, prv_keys)
            if key.is_aggregate
            else _derived_origin(key, index)
        )
        if origin is not None:
            x_only = key.sec(index, network, prv_keys)[1:]
            derivations[x_only] = (list(leaf_hashes.get(x_only, [])), origin)
        for participant in key.participants:
            participant_origin = _derived_origin(participant, index)
            if participant_origin is None:
                continue
            x_only = participant.sec(index, network, prv_keys)[1:]
            derivations[x_only] = ([], participant_origin)
    return derivations


def _musig2_participants(
    keys: Sequence[KeyExpression],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> dict[bytes, list[bytes]]:
    """Return BIP373's participant field: each aggregate key's own list.

    Keyed by the 33-byte aggregate key rather than by what the script
    holds, which BIP373 requires and which is the whole use of the field:
    the participants are what a signer checks its own keys against, and a
    child of the aggregate is a key the same list answers for.
    """
    return {
        key.aggregate(index, network, prv_keys): key.participant_keys(
            index, network, prv_keys
        )
        for key in keys
        if key.is_aggregate
    }


@dataclass(frozen=True, kw_only=True)
class Descriptor(ABC):
    """A parsed output descriptor: the scripts it describes, on demand.

    Keyword-only so that the fragments below can add positional fields of
    their own: a dataclass field with a default followed by one without
    is a TypeError, and `network` has a default.
    """

    network: str = "mainnet"

    @property
    @abstractmethod
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return every KEY expression the descriptor holds."""

    @abstractmethod
    @override
    def __str__(self) -> str:
        """Return the descriptor as text, without its checksum.

        Public by construction, `parse` having kept no private material
        to write: the same guarantee Bitcoin Core's `ToString` gives by
        holding only a neutered key, where its `ToPrivateString` has to
        be handed the keys back.

        Without the checksum because a fragment inside another one is
        written by this very method, and a checksum there would be part
        of the outer descriptor's text. `add_checksum(str(descriptor))`
        is the checksummed form, which is the split Core has too --
        `ToString` writes none and the rpc layer appends it. HWI and
        Electrum instead name the checksummed one `to_string`.

        Two things are normalized rather than echoed, both because the
        parse keeps the meaning and not the characters: a WIF and an
        uppercase hex key come back as lowercase hex, and an xprv as its
        xpub. The hardening symbol is not one of them -- `KeyExpression`
        remembers which of `h` and `'` was read, the two spellings being
        two checksums.
        """

    @abstractmethod
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        """Return the scriptPubKey bytes at `index`, in Bitcoin Core's order."""

    @property
    def is_ranged(self) -> bool:
        """Return True if the descriptor describes a range of scripts."""
        return any(key.is_ranged for key in self.key_expressions)

    def _assert_index(self, index: int) -> None:
        """Refuse an index out of range, or one with no script of this.

        `satisfy` asks the two questions `script_pub_keys` asks, and has
        to ask them first: an index out of range would otherwise be a
        signature looked up under a key derived from it.
        """
        if not 0 <= index < 0x80000000:
            raise BTClibValueError(f"invalid derivation index: {index}")
        if index and not self.is_ranged:
            err_msg = f"not a ranged descriptor: no script at index {index}"
            raise BTClibValueError(err_msg)

    def script_pub_keys(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> list[ScriptPubKey]:
        """Return the scripts the descriptor describes at `index`.

        A list because ``combo()`` is a set of scripts and not one
        script; every other fragment answers with exactly one.
        """
        self._assert_index(index)
        return [
            ScriptPubKey(script, self.network)
            for script in self._scripts(index, prv_keys)
        ]

    def script_pub_key(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> ScriptPubKey:
        """Return the one script the descriptor describes at `index`."""
        script_pub_keys = self.script_pub_keys(index, prv_keys)
        if len(script_pub_keys) != 1:
            err_msg = f"{len(script_pub_keys)} scripts: use script_pub_keys instead"
            raise BTClibValueError(err_msg)
        return script_pub_keys[0]

    def redeem_script(self, index: int = 0, prv_keys: PrvKeys | None = None) -> bytes:
        """Return the script that ``sh()`` or ``wsh()`` embeds this one as."""
        return self.script_pub_key(index, prv_keys).script

    def address(self, index: int = 0, prv_keys: PrvKeys | None = None) -> str:
        """Return the address of the script at `index`, if it has one."""
        return self.script_pub_key(index, prv_keys).address

    def addresses(self, index: int = 0, prv_keys: PrvKeys | None = None) -> list[str]:
        """Return the address of each script at `index`, empty where none."""
        return [
            script_pub_key.address
            for script_pub_key in self.script_pub_keys(index, prv_keys)
        ]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        """Return the elements that satisfy this fragment's own script.

        What ``sh()`` writes into its script_sig and what ``wsh()`` puts
        in its witness under the script: the same elements, only written
        somewhere else, which is why this is one method and not two.
        Answered by the fragments that are a script another one embeds
        -- ``pk``, ``pkh``, ``wpkh``, ``multi`` -- and refused by the
        rest. The grammar refuses those in an embedding position too, so
        what this answers is a descriptor built by hand.
        """
        err_msg = f"{type(self).__name__} is not a script another one embeds"
        raise BTClibValueError(err_msg)

    def satisfy(
        self,
        signatures: Mapping[Octets, Octets],
        index: int = 0,
        prv_keys: PrvKeys | None = None,
        spend: SpendContext | None = None,
    ) -> tuple[bytes, Witness]:
        """Return the script_sig and witness that spend the script at `index`.

        `signatures` maps a public key to the signature made with it,
        which is the shape `psbt.PsbtIn.partial_sigs` has. Keyed by key
        and not a sequence because the order the signatures go on the
        stack is the descriptor's own knowledge -- the key order of a
        ``multi()``, the sorted order of a ``sortedmulti()`` -- and a
        caller that had to know it would be building the script itself.

        Both halves come back and one of the two is always empty: a
        legacy script has no witness, and a native segwit one has the
        empty script_sig BIP141 requires.

        A signature short of what the script pops is an error and not a
        shorter answer. A 2-of-3 holding one signature is a psbt waiting
        for the second, `psbt.PsbtIn.partial_sigs` is where that state
        belongs, and bytes that do not spend would be a second and
        weaker spelling of it.

        `spend` is what a miniscript satisfaction reads beside the
        signatures -- hash preimages, and the lock times the transaction
        being built will carry -- and is ignored by every other fragment,
        none of which has a branch to choose or a preimage to look up. A
        `wsh()` holding a miniscript is the one shape that needs it, and
        it says so: without one it refuses the fragments that would have
        read it.
        """
        self._assert_index(index)
        return self._satisfy(
            {
                bytes_from_octets(key): bytes_from_octets(signature)
                for key, signature in signatures.items()
            },
            index,
            prv_keys,
            spend,
        )

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Return the satisfaction, the mapping being already in bytes.

        The legacy answer -- the stack pushed into the script_sig, and
        no witness -- which is what ``pk()``, ``pkh()`` and ``multi()``
        are spent with; the fragments spent otherwise override it.
        Separate from `satisfy` so that a wrapper can satisfy its
        argument without normalizing the same mapping a second time.
        """
        return serialize(
            cast(ScriptList, self._stack(signatures, index, prv_keys, spend))
        ), Witness()

    def index_of(
        self,
        script_pub_key: Octets | ScriptPubKey,
        last_index: int = 999,
        prv_keys: PrvKeys | None = None,
    ) -> int | None:
        """Return the index whose script is this one, None where none is.

        What makes an output *this wallet's*, and the only thing that
        does: the script is derived and compared whole. A key origin whose
        fingerprint matches is not an answer -- four bytes of a hash160
        collide, and a psbt is written by whoever sends it, so an output
        marked as change on a fingerprint is an output a wallet may hand
        to somebody else believing it keeps it.

        The output is named however the caller holds it: the
        `ScriptPubKey` that `script_pub_key` returns, that script as
        bytes or as a hex-string, or the address it renders as -- "which
        index is this address" being the question a human has, and
        `ScriptPubKey.from_address` being what answers it. What is
        compared is the script in every case: an address is read for the
        script it encodes, and the network its prefix carries is not part
        of the answer, the same key paying to the same script on every
        chain.

        Anything else is a `BTClibTypeError`, and a string that names no
        output -- neither hex nor an address, the `""` that a script with
        no address renders as among them -- a `BTClibValueError`, because
        None is not "you passed the wrong thing" here: it is *this output
        is not this wallet's*, which is the answer a caller acts on to
        say that an address is somebody else's or that an output is not
        its own change (issue #540).

        `last_index` bounds the search, both ends included, and is the
        caller's: how far ahead of its own gap limit a wallet is willing
        to look is a policy this module has no view on. A descriptor that
        is not ranged has one script and answers 0 or None.
        """
        script = _validated_script_from(script_pub_key)
        last = last_index if self.is_ranged else 0
        for index in range(last + 1):
            if any(
                candidate.script == script
                for candidate in self.script_pub_keys(index, prv_keys)
            ):
                return index
        return None

    def update_psbt_input(
        self,
        psbt: Psbt,
        vin_i: int,
        index: int = 0,
        prv_keys: PrvKeys | None = None,
    ) -> Psbt:
        """Return the psbt with input `vin_i` told what the descriptor knows.

        BIP174's Updater, for the one input this descriptor describes:
        the redeem script of a ``sh()``, the witness script of a
        ``wsh()``, the internal key, merkle root and leaf scripts of a
        ``tr()``, and the origin of every key that carries one -- which is
        what a hardware signer needs, and what `KeyExpression.origin` is
        kept for. `psbt.finalize` then assembles the same bytes
        `satisfy` does, from the signatures the signers filled in at
        their own pace: that pipeline is what a psbt is for, and what
        `satisfy` cannot answer, refusing a partial satisfaction rather
        than returning bytes that do not spend.

        A copy, the psbt handed in being left alone, and the fields of
        the copy mutated in place: `finalize` is the same
        construction, and BIP174's roles read as steps that update a
        psbt rather than as functions that return a field at a time.

        What is not filled is what a descriptor does not know: the utxo,
        the sighash type, the signatures. Nor is the script checked
        against the output being spent -- an input may not carry it yet,
        and `Psbt.assert_signable` asks that question for every input at
        once, being the role after this one.
        """
        self._assert_index(index)
        # an IndexError out of a public method is not an answer, and a
        # negative index would quietly update the input at the other end
        if not 0 <= vin_i < len(psbt.inputs):
            raise BTClibValueError(f"invalid input index: {vin_i}")
        psbt = deepcopy(psbt)
        self._update(psbt.inputs[vin_i], index, prv_keys)
        psbt.assert_valid()
        return psbt

    def update_psbt_output(
        self,
        psbt: Psbt,
        vout_i: int,
        index: int = 0,
        prv_keys: PrvKeys | None = None,
    ) -> Psbt:
        """Return the psbt with output `vout_i` told what the descriptor knows.

        The Updater's other half, and what makes an output recognizable as
        the wallet's own: the redeem script of a ``sh()``, the witness
        script of a ``wsh()``, the internal key and the whole script tree
        of a ``tr()``, and the origin of every key that carries one. A
        signing device reads them to tell change from a payment -- it can
        derive the script itself and see that the money comes back -- and
        a wallet reading a psbt somebody else built reads them for the same
        reason.

        Unlike the input half, the script *is* checked: the output being
        paid is in the psbt already, so this refuses unless the descriptor
        derives exactly that script at `index`. Marking an output as one's
        own is a claim about where money goes, and the only evidence for it
        is the whole script -- never a key origin whose four-byte
        fingerprint matches, which is what `index_of` is for and what it
        says.

        The output tree is BIP371's PSBT_OUT_TAP_TREE and not the leaf
        script an input carries: an output has no leaf being spent, so what
        it publishes is every leaf, each with its depth, which is what lets
        a reader rebuild the tree and check the output key for itself.
        """
        self._assert_index(index)
        # an IndexError out of a public method is not an answer, and a
        # negative index would quietly update the output at the other end
        if not 0 <= vout_i < len(psbt.outputs):
            raise BTClibValueError(f"invalid output index: {vout_i}")
        paid = psbt.tx.vout[vout_i].script_pub_key.script
        if all(
            script.script != paid for script in self.script_pub_keys(index, prv_keys)
        ):
            err_msg = f"output {vout_i} pays to {paid.hex()}, which is not the"
            err_msg += f" script this descriptor describes at index {index}"
            raise BTClibValueError(err_msg)
        psbt = deepcopy(psbt)
        self._update_out(psbt.outputs[vout_i], index, prv_keys)
        psbt.assert_valid()
        return psbt

    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill the key origins, which is what every fragment knows.

        And the whole of what ``pk()``, ``pkh()``, ``wpkh()`` and
        ``multi()`` know: their script is the script_pub_key, which the
        psbt has from the utxo rather than from here. The fragments that
        embed one of those add their scripts to this.

        One method for an input and an output, because BIP174 gives the
        two maps the same fields wherever they mean the same thing: a
        redeem script, a witness script and a key origin say what they say
        whether the psbt is spending the script or paying to it. Only a
        ``tr()`` differs, an input carrying the leaf it spends and an
        output the whole tree, and that is where the two methods below
        part company.

        The mapping is added to and not replaced: BIP174 keys it by
        public key, so a psbt already carrying another signer's key keeps
        it, and this descriptor's entry wins for a key held by both.
        """
        psbt_map.hd_key_paths = {
            **psbt_map.hd_key_paths,
            **self._hd_key_paths(index, prv_keys),
        }

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Fill what an input of this descriptor's script carries."""
        self._update_map(psbt_in, index, prv_keys)

    def _update_out(
        self, psbt_out: PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill what an output paying to this descriptor's script carries."""
        self._update_map(psbt_out, index, prv_keys)

    def _hd_key_paths(
        self, index: int, prv_keys: PrvKeys | None
    ) -> dict[bytes, BIP32KeyOrigin]:
        """Return the origin of each key that has one, keyed by public key.

        A key with no origin is skipped and not refused: a descriptor may
        name one key as plain hex and the next with an origin, the field
        is keyed by key, and what is missing is one entry of it.
        """
        hd_key_paths: dict[bytes, BIP32KeyOrigin] = {}
        for key in self.key_expressions:
            origin = _derived_origin(key, index)
            if origin is not None:
                hd_key_paths[key.sec(index, self.network, prv_keys)] = origin
        return hd_key_paths


@dataclass(frozen=True)
class PkDescriptor(Descriptor):
    """``pk(KEY)``: a P2PK output, BIP381."""

    key: KeyExpression

    @override
    def __str__(self) -> str:
        return _expression("pk", str(self.key))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2pk(self.key.sec(index, self.network, prv_keys)).script]

    @override
    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        # the key is in the script already, so the signature is the whole
        # of what spending a p2pk output takes
        return [
            _required_signature(signatures, self.key.sec(index, self.network, prv_keys))
        ]


@dataclass(frozen=True)
class PkhDescriptor(Descriptor):
    """``pkh(KEY)``: a p2pkh output, BIP381."""

    key: KeyExpression

    @override
    def __str__(self) -> str:
        return _expression("pkh", str(self.key))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2pkh(self.key.sec(index, self.network, prv_keys)).script]

    @override
    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        # what the output commits to is the hash of the key, so the key
        # goes on the stack for the script to hash for itself
        sec = self.key.sec(index, self.network, prv_keys)
        return [_required_signature(signatures, sec), sec]


@dataclass(frozen=True)
class WpkhDescriptor(Descriptor):
    """``wpkh(KEY)``: a p2wpkh output, BIP382."""

    key: KeyExpression

    @override
    def __str__(self) -> str:
        return _expression("wpkh", str(self.key))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2wpkh(self.key.sec(index, self.network, prv_keys)).script]

    @override
    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        # the witness of a p2wpkh spend is what the script_sig of a p2pkh
        # one is, BIP143 having moved it and changed nothing else
        sec = self.key.sec(index, self.network, prv_keys)
        return [_required_signature(signatures, sec), sec]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        # the empty script_sig of BIP141, which is not the same as an
        # empty push: btclib's own engine refuses a native segwit input
        # whose script_sig is there at all (issue #249). A sh(wpkh())
        # gets its one push from the sh() above
        return b"", Witness(self._stack(signatures, index, prv_keys, spend))


@dataclass(frozen=True)
class ShDescriptor(Descriptor):
    """``sh(SCRIPT)``: the argument, p2sh-embedded, BIP381."""

    inner: Descriptor

    @override
    def __str__(self) -> str:
        return _expression("sh", str(self.inner))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2sh(self.inner.redeem_script(index, prv_keys)).script]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Return the argument's satisfaction, the redeem script pushed last.

        One rule for the three shapes ``sh()`` wraps, because the two
        wrapped segwit ones satisfy into the witness and leave the
        script_sig empty: what is appended is the same push either way,
        and what it is appended to is nothing where the spend is a
        witness. Appending is concatenation because a script_sig is
        pushes and nothing else, so serializing them together and
        serializing them apart give the same bytes.
        """
        script_sig, witness = self.inner._satisfy(signatures, index, prv_keys, spend)
        redeem_script = self.inner.redeem_script(index, prv_keys)
        return script_sig + serialize(cast(ScriptList, [redeem_script])), witness

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill the redeem script, and let the argument fill its own fields.

        Delegated rather than dispatched on: the argument of a
        ``sh(wsh())`` is what knows there is a witness script below the
        redeem script, and it is the same method that fills it for a
        native ``wsh()``.
        """
        self.inner._update_map(psbt_map, index, prv_keys)
        psbt_map.redeem_script = self.inner.redeem_script(index, prv_keys)


@dataclass(frozen=True)
class WshDescriptor(Descriptor):
    """``wsh(SCRIPT)``: the argument, P2WSH-embedded, BIP382."""

    inner: Descriptor

    @override
    def __str__(self) -> str:
        return _expression("wsh", str(self.inner))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2wsh(self.inner.redeem_script(index, prv_keys)).script]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Return the witness of a p2wsh spend: the stack, then the script.

        The argument's stack and not its satisfaction, which would be
        those same elements serialized as a script_sig: a witness is a
        stack already, so BIP141 puts them in it one by one and the
        witness script last.
        """
        stack = self.inner._stack(signatures, index, prv_keys, spend)
        return b"", Witness([*stack, self.inner.redeem_script(index, prv_keys)])

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill the witness script; the redeem script is ``sh()``'s to fill.

        Which is the whole difference between a native ``wsh()`` and a
        wrapped one, in the psbt as in the spend: the same witness script,
        and a redeem script only where something wraps it.
        """
        self.inner._update_map(psbt_map, index, prv_keys)
        psbt_map.witness_script = self.inner.redeem_script(index, prv_keys)


@dataclass(frozen=True)
class MiniscriptDescriptor(Descriptor):
    """A BIP379 miniscript where a SCRIPT expression may be one.

    Which is inside ``wsh()``: a miniscript inside ``tr()`` is a leaf of
    the script tree and not a SCRIPT expression, so `DescriptorTree` holds
    that one directly, the way it holds a ``multi_a()``. What this holds is
    the `Miniscript`, whose own interface -- the type properties, the
    resource bounds, the script both ways, the satisfaction -- is
    `btclib.descriptors.miniscript`'s.

    A fragment like the others in what it answers: the script at an index,
    the KEY expressions it names, and the psbt fields those keys fill.
    Unlike the others it does not satisfy: a miniscript satisfaction needs
    more than a mapping of public keys to signatures, so `satisfy` refuses
    and says so.
    """

    node: Miniscript

    @override
    def __str__(self) -> str:
        return str(self.node)

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the KEY expressions of the fragments, left to right."""
        return self.node.key_expressions

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [self.node.script(index, self.network, prv_keys)]

    @override
    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        """Return the witness elements that satisfy the miniscript.

        The one fragment that reads the spend context, and the reason
        `satisfy` takes one: a miniscript satisfaction chooses among
        branches, and the choice reads the hash preimages a ``sha256()``
        wants and the lock times an ``older()`` or an ``after()`` is
        checked against. Non-malleable or refused, which is
        `Miniscript.satisfy`'s rule and BIP379's.
        """
        # cast because `Mapping` is invariant in its key: these bytes are
        # every bit an `Octets`, and a mapping of them is still not a
        # mapping of "bytes or hex" as far as the type checker is concerned
        offered = cast("Mapping[Octets, Octets]", signatures)
        return self.node.satisfy(offered, spend, index, self.network, prv_keys)


@dataclass(frozen=True)
class MultiDescriptor(Descriptor):
    """``multi(k,KEY,...)`` and ``sortedmulti(k,KEY,...)``, BIP383."""

    threshold: int
    keys: tuple[KeyExpression, ...]
    # BIP67 ordering, which is the whole difference between the two
    # functions: the keys of a sortedmulti() are sorted in the script, so
    # the participants need not agree on an order to agree on an address
    sort: bool = False

    @override
    def __str__(self) -> str:
        name = "sortedmulti" if self.sort else "multi"
        return _expression(name, str(self.threshold), *map(str, self.keys))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the KEY expressions, in descriptor order."""
        return self.keys

    def _pub_keys(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        """Return the keys in the order the script holds them.

        `sorted` and not `p2ms`'s own `lexicographic_sorting`, which
        sorts identically: the order is also the order the signatures of
        a satisfaction go in, so one of the two has somewhere to ask for
        it rather than a second copy of the rule.
        """
        pub_keys = [key.sec(index, self.network, prv_keys) for key in self.keys]
        return sorted(pub_keys) if self.sort else pub_keys

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        script_pub_key = ScriptPubKey.p2ms(
            self.threshold,
            self._pub_keys(index, prv_keys),
            self.network,
            lexicographic_sorting=False,
        )
        return [script_pub_key.script]

    @override
    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> list[bytes]:
        """Return the dummy element and `threshold` signatures, in key order.

        OP_CHECKMULTISIG walks the signatures and the keys in one pass
        and never goes back, so the signatures have to be in the order
        the script holds the keys in. More signatures than the threshold
        is not an error and not all of them are used: the script pops
        exactly as many as it was built for, and the rest are the other
        keys of the same descriptor having signed too.

        The first element is the one OP_CHECKMULTISIG pops without
        reading, which BIP147 requires to be the empty push.
        """
        offered = [
            (sec, _offered_signature(signatures, sec, x_only=False))
            for sec in self._pub_keys(index, prv_keys)
        ]
        found = [signature for _, signature in offered if signature is not None]
        if len(found) < self.threshold:
            missing = ", ".join(sec.hex() for sec, sig in offered if sig is None)
            err_msg = f"{len(found)} signatures of {self.threshold}, missing {missing}"
            raise BTClibValueError(err_msg)
        return [b"", *found[: self.threshold]]


@dataclass(frozen=True)
class ComboDescriptor(Descriptor):
    """``combo(KEY)``: the scripts an old wallet would have used, BIP384.

    p2pk and p2pkh, plus p2wpkh and p2sh-p2wpkh when the key is
    compressed -- an uncompressed key is not allowed in a witness
    program.
    """

    key: KeyExpression

    @override
    def __str__(self) -> str:
        return _expression("combo", str(self.key))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        pub_key = self.key.sec(index, self.network, prv_keys)
        scripts = [
            ScriptPubKey.p2pk(pub_key).script,
            ScriptPubKey.p2pkh(pub_key).script,
        ]
        if self.key.is_compressed:
            p2wpkh = ScriptPubKey.p2wpkh(pub_key).script
            scripts += [p2wpkh, ScriptPubKey.p2sh(p2wpkh).script]
        return scripts

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: four scripts, and each of them spent differently.

        Which one is being spent is a question the caller answers, by
        satisfying the descriptor of that script -- ``pk()``, ``pkh()``,
        ``wpkh()`` or ``sh(wpkh())`` of the same key -- and it is a
        question `script_pub_keys` can leave open where this cannot.
        """
        err_msg = "combo() is four scripts: satisfy the one being spent"
        raise BTClibValueError(err_msg)

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Refuse: the four scripts are updated into an input differently.

        One of them is p2sh and wants a redeem script, the other three
        want none, and the input is spending one output: an Updater that
        wrote the key origin and left the script to the caller would have
        filled in the half that is the same for all four and hidden the
        half that is not.
        """
        err_msg = "combo() is four scripts: update the psbt with the one spent"
        raise BTClibValueError(err_msg)


@dataclass(frozen=True)
class AddrDescriptor(Descriptor):
    """``addr(ADDR)``: the script the address expands to, BIP385."""

    addr: str

    @override
    def __str__(self) -> str:
        return _expression("addr", self.addr)

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.from_address(self.addr).script]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: an address names a script and not what spends it.

        BTClibValueError and not the NotImplementedError the parser
        raises for what a later release adds: there is nothing to add,
        an address being a commitment to a key or a script that the
        descriptor does not carry.
        """
        raise BTClibValueError("addr() cannot be satisfied: it holds no key")

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Refuse: there is nothing of an address to write into an input.

        No key, so no origin; no script below the address, so no redeem or
        witness script. Returning the input untouched would be an Updater
        that ran and a caller told it had been updated.
        """
        raise BTClibValueError("addr() cannot update a psbt: it holds no key")


@dataclass(frozen=True)
class RawDescriptor(Descriptor):
    """``raw(HEX)``: the script those bytes are, BIP385."""

    script: bytes

    @override
    def __str__(self) -> str:
        return _expression("raw", self.script.hex())

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [self.script]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: a script and no key expression to satisfy it with.

        What ``raw()`` holds is bytes, which say nothing about which key
        signs for them even where they happen to be a script this module
        can otherwise read; the descriptor of that script is what is
        satisfiable.
        """
        raise BTClibValueError("raw() cannot be satisfied: it holds no key")

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Refuse, for the reason ``addr()`` does: bytes hold no key origin.

        Those bytes may be the script an input spends, and they are then
        its script_pub_key, which the psbt has from the utxo; what a
        descriptor is asked here is what the utxo does not say.
        """
        raise BTClibValueError("raw() cannot update a psbt: it holds no key")


@dataclass(frozen=True)
class TrDescriptor(Descriptor):
    """``tr(KEY)`` or ``tr(KEY,TREE)``: a p2tr output, BIP386."""

    internal_key: KeyExpression
    tree: DescriptorTree | None = None

    @override
    def __str__(self) -> str:
        if self.tree is None:
            return _expression("tr", str(self.internal_key))
        return _expression("tr", str(self.internal_key), _tree_expression(self.tree))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the internal key and every leaf key, in tree order."""
        if self.tree is None:
            return (self.internal_key,)
        return (self.internal_key, *_tree_keys(self.tree))

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        script_tree = (
            None
            if self.tree is None
            else _taproot_script_tree(self.tree, index, self.network, prv_keys)
        )
        internal_key = self.internal_key.sec(index, self.network, prv_keys)
        return [ScriptPubKey.p2tr(internal_key, script_tree).script]

    def _leaf(
        self,
        script_tree: TaprootScriptTree,
        index: int,
        leaf: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, bytes]:
        """Return one leaf's serialized script and its control block.

        The one place either is built, a spend and an update of the same
        leaf wanting the same bytes. The tree is a parameter because both
        callers have computed it already -- and because a ``tr()`` with no
        tree has no leaf, which they answer for themselves.
        """
        internal_key = self.internal_key.sec(index, self.network, prv_keys)
        script, control_block = input_script_sig(internal_key, script_tree, leaf)
        return serialize(script), control_block

    def taproot_merkle_root(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> bytes:
        """Return the root the output key commits to, b"" where there is none.

        BIP371's PSBT_IN_TAP_MERKLE_ROOT, and empty is how that field
        says "key path only": a ``tr(KEY)`` tweaks its internal key with
        no tree, which is not the same as tweaking it with an empty one.
        """
        self._assert_index(index)
        if self.tree is None:
            return b""
        return tree_helper(
            _taproot_script_tree(self.tree, index, self.network, prv_keys)
        )[1]

    def taproot_leaf_scripts(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> dict[bytes, tuple[bytes, int]]:
        """Return every leaf script and its version, keyed by control block.

        The shape of BIP371's PSBT_IN_TAP_LEAF_SCRIPT, and the field an
        Updater is needed for rather than convenient: a control block
        holds the merkle path from its leaf to the root, which is the
        whole tree seen from that leaf, and a psbt carrying one leaf's
        script has no way to compute another's.
        """
        self._assert_index(index)
        if self.tree is None:
            return {}
        script_tree = _taproot_script_tree(self.tree, index, self.network, prv_keys)
        leaf_scripts: dict[bytes, tuple[bytes, int]] = {}
        for leaf in range(len(_tree_leaves(self.tree))):
            script, control_block = self._leaf(script_tree, index, leaf, prv_keys)
            leaf_scripts[control_block] = (script, _TAPSCRIPT_LEAF_VERSION)
        return leaf_scripts

    def _taproot_hd_key_paths(
        self, index: int, prv_keys: PrvKeys | None
    ) -> dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]:
        """Return each key's origin and leaf hashes, keyed by x-only key.

        BIP371 gives a taproot key a field of its own, keyed by the 32
        bytes a tapscript holds and carrying the tapleaf hash of every
        leaf the key appears in: none for a key that is only the internal
        one, no leaf committing to it, and one entry naming each of them
        for a key written into several, the field being keyed by key.

        Named once each: a key in two leaves of the same script is in two
        places of the tree and in one leaf of it, the tapleaf hash being
        of the script, and what a signer reads here is which scripts it
        has to sign for.

        The leaves are walked rather than `taproot_leaf_scripts`, which is
        keyed by control block: which keys a leaf commits to is what the
        leaf says and no longer what its script bytes show, a
        ``multi_a()`` leaf holding as many keys as it names.
        """
        leaf_hashes: dict[bytes, list[bytes]] = {}
        if self.tree is not None:
            script_tree = _taproot_script_tree(self.tree, index, self.network, prv_keys)
            for number, leaf in enumerate(_tree_leaves(self.tree)):
                script = self._leaf(script_tree, index, number, prv_keys)[0]
                hash_ = leaf_hash(_TAPSCRIPT_LEAF_VERSION, script)
                for key in _leaf_keys(leaf):
                    hashes = leaf_hashes.setdefault(
                        key.sec(index, self.network, prv_keys)[1:], []
                    )
                    if hash_ not in hashes:
                        hashes.append(hash_)
        return _taproot_derivations(
            self.key_expressions, leaf_hashes, index, self.network, prv_keys
        )

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Return the witness of a key path spend, or of a script path one.

        The key path whenever a signature for the internal key is
        offered, which is the preference Bitcoin Core's finalizer has:
        it is the cheaper spend and the one the output key commits to
        directly. That signature is one the *output* key verifies, the
        signer having tweaked the key it holds, and it is looked up
        under the internal key because that is the key the descriptor
        names.

        A script path witness is what satisfies the leaf, then the leaf
        script and the control block, which is BIP341's order: one
        signature for a ``pk()`` leaf, one element per key for a
        ``multi_a()`` one, and for a miniscript leaf whatever its
        non-malleable satisfaction is -- which is where `spend` is read, a
        branch of one wanting a preimage or a lock time.

        Both the parity bit and the merkle path in that
        control block are the descriptor's to compute, holding the whole
        tree as it does, where a psbt has to be handed them: it is the one
        thing satisfaction here knows that finalization there cannot work
        out.

        The first leaf the signatures satisfy, left to right, where they
        satisfy several: they are all valid spends of the same output, and
        which is the cheapest is a question about weights that this module
        does not answer.

        The script_sig is empty whichever path is taken: BIP341 spends
        a witness v1 program with the witness alone.
        """
        internal_key = self.internal_key.sec(index, self.network, prv_keys)
        signature = _offered_signature(signatures, internal_key, x_only=True)
        if signature is not None:
            return b"", Witness([signature])
        if self.tree is None:
            raise BTClibValueError("no signature for the tr() internal key")
        script_tree = _taproot_script_tree(self.tree, index, self.network, prv_keys)
        for number, leaf in enumerate(_tree_leaves(self.tree)):
            stack = _leaf_stack(leaf, signatures, index, self.network, prv_keys, spend)
            if stack is not None:
                script, control_block = self._leaf(script_tree, index, number, prv_keys)
                return b"", Witness([*stack, script, control_block])
        err_msg = "no signature for the tr() internal key or for any of its leaves"
        raise BTClibValueError(err_msg)

    def taproot_tree(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> list[tuple[int, int, bytes]]:
        """Return every leaf with its depth: BIP371's PSBT_OUT_TAP_TREE.

        The whole tree, where an input publishes the one leaf it spends and
        the control block that proves it: an output has no leaf being spent
        yet, so what it carries is each script with the depth it sits at,
        in the order a depth-first walk reaches them. A reader rebuilds the
        tree from those two facts and can then check the output key itself
        -- which is why the field is the tree and not the merkle root, a
        root proving nothing about the scripts underneath it.

        Empty for a ``tr(KEY)``, whose output key commits to no script at
        all, and which BIP371 says so about by leaving the field out.
        """
        self._assert_index(index)
        if self.tree is None:
            return []
        scripts = _leaf_scripts(self.tree, 0, index, self.network, prv_keys)
        return [(depth, _TAPSCRIPT_LEAF_VERSION, script) for depth, script in scripts]

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill the taproot fields an input and an output share.

        This replaces the base method rather than adding to it: a taproot
        key origin belongs in `taproot_hd_key_paths`, keyed by the x-only
        key, and a 33-byte entry in `hd_key_paths` beside it would be the
        same key twice in two spellings, for a signer that signs with
        neither.

        The participant list of BIP373 goes here too where a key of the
        descriptor is a ``musig()``: it tells a signer that one of the keys
        it holds is in the group, which is as true of an output being paid
        as of an input being spent.
        """
        psbt_map.taproot_internal_key = self.internal_key.sec(
            index, self.network, prv_keys
        )[1:]
        psbt_map.taproot_hd_key_paths = {
            **psbt_map.taproot_hd_key_paths,
            **self._taproot_hd_key_paths(index, prv_keys),
        }
        psbt_map.musig2_participant_pub_keys = {
            **psbt_map.musig2_participant_pub_keys,
            **_musig2_participants(self.key_expressions, index, self.network, prv_keys),
        }

    @override
    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Add what an input carries: the merkle root and the leaf scripts.

        A control block is the field an Updater is needed for rather than
        convenient -- it holds the merkle path from its leaf to the root,
        which is the whole tree seen from that leaf -- and the merkle root
        is what a verifier tweaks the internal key with.
        """
        self._update_map(psbt_in, index, prv_keys)
        psbt_in.taproot_merkle_root = self.taproot_merkle_root(index, prv_keys)
        psbt_in.taproot_leaf_scripts = {
            **psbt_in.taproot_leaf_scripts,
            **self.taproot_leaf_scripts(index, prv_keys),
        }

    @override
    def _update_out(
        self, psbt_out: PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Add what an output carries: the tree, every leaf of it at once.

        BIP371 gives an output PSBT_OUT_TAP_TREE and no merkle root: the
        root is computed from the tree and would be the same fact twice,
        where the tree is what a reader needs to compute the output key and
        find out that this output is one it can spend.
        """
        self._update_map(psbt_out, index, prv_keys)
        psbt_out.taproot_tree = self.taproot_tree(index, prv_keys)


@dataclass(frozen=True)
class RawTrDescriptor(Descriptor):
    """``rawtr(KEY)``: the key as the output key itself, no tweak at all.

    No BIP specifies this function. BIP386 specifies ``tr()``, the tree
    expression and the x-only key inside them and never mentions
    ``rawtr()``; what defines it is Bitcoin Core's own
    `doc/descriptors.md`, which also carries the warning this docstring
    keeps: an output key whose internal key nobody knows cannot be shown
    to have no hidden script path, so a ``rawtr()`` describes an output a
    wallet already holds rather than one to build.

    The key is BIP341's *output* key, written into ``OP_1 <32 bytes>`` as
    it is. That is the whole difference from ``tr(KEY)``, which tweaks its
    internal key with an empty merkle root, and it is why this is not a
    `TrDescriptor` carrying ``tree=None``.
    """

    key: KeyExpression

    @override
    def __str__(self) -> str:
        return _expression("rawtr", str(self.key))

    @property
    @override
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    @override
    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        # not ScriptPubKey.p2tr, which computes an output key from an
        # internal one: here the key already is the output key, and
        # tweaking it would describe an output nobody named
        output_key = self.key.sec(index, self.network, prv_keys)[1:]
        return [serialize(["OP_1", output_key])]

    @override
    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
        spend: SpendContext | None,
    ) -> tuple[bytes, Witness]:
        """Return the witness of a BIP341 key path spend: one signature.

        Looked up under the key the descriptor names, as ``tr()`` does,
        and the two lookups mean opposite things: there the signature is
        one the *tweaked* key verifies, made by a signer that tweaked the
        internal key it holds, while here it must verify against the key
        as written, so a signer must not tweak anything.

        The script_sig is empty: BIP341 spends a witness v1 program with
        the witness alone.
        """
        output_key = self.key.sec(index, self.network, prv_keys)
        signature = _offered_signature(signatures, output_key, x_only=True)
        if signature is None:
            raise BTClibValueError("no signature for the rawtr() output key")
        return b"", Witness([signature])

    @override
    def _update_map(
        self, psbt_map: PsbtIn | PsbtOut, index: int, prv_keys: PrvKeys | None
    ) -> None:
        """Fill the one taproot field a ``rawtr()`` has anything to say in.

        BIP371's PSBT_IN_TAP_BIP32_DERIVATION, keyed by the x-only key,
        which is the origin of the key the script holds. The other three
        fields are `TrDescriptor`'s and not this one's: PSBT_IN_TAP_
        INTERNAL_KEY names the key a verifier tweaks and a ``rawtr()`` has
        none, so it has no merkle root and no leaf script either.

        What that costs is `psbt.sign`, which signs a taproot input
        through its internal key and therefore leaves this input alone
        rather than tweaking a key it should not: an input with no
        internal key is one that role skips.

        BIP373's participant list is written beside it where the key is a
        ``musig()``, as it is under a ``tr()``: an aggregate key that is
        the output key itself is the first of the four ways BIP373 has of
        reaching what is spent.
        """
        keys = self.key_expressions
        psbt_map.taproot_hd_key_paths = {
            **psbt_map.taproot_hd_key_paths,
            **_taproot_derivations(keys, {}, index, self.network, prv_keys),
        }
        psbt_map.musig2_participant_pub_keys = {
            **psbt_map.musig2_participant_pub_keys,
            **_musig2_participants(keys, index, self.network, prv_keys),
        }


def _assert_position(name: str, context: str, allowed: tuple[str, ...]) -> None:
    if context not in allowed:
        raise BTClibValueError(f"{name}() is not allowed inside {context}")


def _one_argument(arguments: list[str], name: str) -> str:
    if len(arguments) != 1:
        err_msg = f"{name}() takes one argument, {len(arguments)} given"
        raise BTClibValueError(err_msg)
    return arguments[0]


def _parse_multi_a(name: str, args: list[str], prv_keys: dict[str, str]) -> MultiA:
    """Return the leaf of a BIP387 ``multi_a()`` or ``sortedmulti_a()``.

    The keys are read as a ``pk()`` leaf's key is, which is what allows
    BIP387's own vectors to name one by its WIF and the next by an xprv:
    x-only is the spelling a tapscript holds and not the only spelling a
    KEY expression has.
    """
    if len(args) < 2:
        raise BTClibValueError(f"{name}() takes a threshold and at least one key")
    if not _THRESHOLD.fullmatch(args[0]):
        raise BTClibValueError(f"invalid {name}() threshold: {args[0]}")
    keys = tuple(
        _parse_key(key, prv_keys, x_only=True, compressed=True, musig_allowed=True)
        for key in args[1:]
    )
    return MultiA(int(args[0]), keys, sort=name == "sortedmulti_a")


def _parse_leaf_miniscript(expression: str, prv_keys: dict[str, str]) -> Miniscript:
    """Return the miniscript of a tr() leaf, sanity checked as a wsh() one is.

    The tapscript dialect: 32-byte keys, ``multi_a()`` where ``wsh()`` has
    ``multi()``, and a ``d:`` wrapper that is "u" because MINIMALIF is
    consensus under taproot. What is refused is what a descriptor refuses
    anywhere -- an expression that is malleable, needs no signature, mixes
    timelocks, repeats a key, or has a spend past a resource limit -- and
    the leaf is where it is said, a tree being several scripts of which
    this one is unspendable or unsafe.
    """
    node = _parse_miniscript(expression, miniscript.TAPSCRIPT, prv_keys)
    _assert_sane(node)
    return node


def _parse_tree(
    expression: str, prv_keys: dict[str, str], depth: int
) -> DescriptorTree:
    """Return the script tree of a BIP386 TREE expression.

    `depth` is how many braces enclose this subtree, and bounding it is
    what keeps a hostile expression from recursing past the interpreter's
    stack: without it a tree nested a thousand deep left through
    `RecursionError`, which is not a class this library raises and not one
    a caller of `parse` catches. MAX_TREE_DEPTH is the bound because a
    leaf below it has no control block to be spent with, so the
    expression describes no output rather than a large one -- and it is
    where Core stops too, "tr() supports at most 128 nesting levels".
    """
    if depth > MAX_TREE_DEPTH:
        err_msg = f"tr() supports at most {MAX_TREE_DEPTH} nesting levels"
        raise BTClibValueError(err_msg)
    if expression.startswith("{"):
        if not expression.endswith("}"):
            raise BTClibValueError(f"unbalanced braces: {expression}")
        branches = _split_arguments(expression[1:-1])
        if len(branches) != 2:
            err_msg = f"a tr() branch takes two subtrees, {len(branches)} given"
            raise BTClibValueError(err_msg)
        return (
            _parse_tree(branches[0], prv_keys, depth + 1),
            _parse_tree(branches[1], prv_keys, depth + 1),
        )
    name = expression.partition("(")[0]
    if name in _TREE_FUNCTIONS:
        return _parse_multi_a(
            name, _split_arguments(expression[len(name) + 1 : -1]), prv_keys
        )
    if name == "musig":
        # allowed inside tr(), and as a key rather than as a leaf: a leaf
        # is a script, and what a musig() aggregates to is one key of one
        err_msg = "musig() is a key expression: pk(musig(...)) is the leaf"
        raise BTClibValueError(err_msg)
    if name in _PARSERS and name != "pk":
        # a SCRIPT function where a leaf is expected: a position rule and
        # not something a later release adds, which is what the position
        # table says and Bitcoin Core's own message says too. ``pk()``
        # allows tr() among its positions and falls through to be read
        _assert_position(name, _P2TR, _PARSERS[name][0])
    if name != "pk":
        # a leaf that is no BIP386 leaf is a BIP379 miniscript, which is
        # the same order the wsh() half reads its two grammars in
        return _parse_leaf_miniscript(expression, prv_keys)
    args = _split_arguments(expression[len(name) + 1 : -1])
    return _parse_key(
        _one_argument(args, name),
        prv_keys,
        x_only=True,
        compressed=True,
        musig_allowed=True,
    )


# inside a witness program an uncompressed key is unspendable, so
# BIP382 refuses one rather than describing a script nobody can spend;
# inside tr() the keys are x-only to begin with
def _no_uncompressed(context: str) -> bool:
    return context in {_P2WSH, _P2TR}


def _parse_pk(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "pk"),
        prv_keys,
        x_only=context == _P2TR,
        compressed=_no_uncompressed(context),
        musig_allowed=False,
    )
    return PkDescriptor(key, network=network)


def _parse_pkh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "pkh"),
        prv_keys,
        x_only=False,
        compressed=_no_uncompressed(context),
        musig_allowed=False,
    )
    return PkhDescriptor(key, network=network)


def _parse_wpkh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "wpkh"),
        prv_keys,
        x_only=False,
        compressed=True,
        musig_allowed=False,
    )
    return WpkhDescriptor(key, network=network)


def _parse_combo(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    return ComboDescriptor(
        _parse_key(
            _one_argument(args, "combo"),
            prv_keys,
            x_only=False,
            compressed=False,
            musig_allowed=False,
        ),
        network=network,
    )


def _parse_sh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    inner = _parse_expression(_one_argument(args, "sh"), _P2SH, network, prv_keys)
    return ShDescriptor(inner, network=network)


def _parse_wsh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    inner = _parse_expression(_one_argument(args, "wsh"), _P2WSH, network, prv_keys)
    return WshDescriptor(inner, network=network)


def _parse_multi(
    name: str,
    args: list[str],
    context: str,
    network: str,
    prv_keys: dict[str, str],
) -> Descriptor:
    if len(args) < 2:
        raise BTClibValueError(f"{name}() takes a threshold and at least one key")
    if not _THRESHOLD.fullmatch(args[0]):
        raise BTClibValueError(f"invalid {name}() threshold: {args[0]}")
    keys = tuple(
        _parse_key(
            key,
            prv_keys,
            x_only=False,
            compressed=_no_uncompressed(context),
            musig_allowed=False,
        )
        for key in args[1:]
    )
    return MultiDescriptor(
        int(args[0]), keys, sort=name == "sortedmulti", network=network
    )


def _parse_ordered_multi(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    return _parse_multi("multi", args, context, network, prv_keys)


def _parse_sorted_multi(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    return _parse_multi("sortedmulti", args, context, network, prv_keys)


def _parse_tr(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    if len(args) > 2:
        err_msg = f"tr() takes a key and at most one tree, {len(args)} given"
        raise BTClibValueError(err_msg)
    internal_key = _parse_key(
        args[0], prv_keys, x_only=True, compressed=True, musig_allowed=True
    )
    tree = None if len(args) == 1 else _parse_tree(args[1], prv_keys, 0)
    return TrDescriptor(internal_key, tree, network=network)


def _parse_rawtr(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    # one key and no tree: what Core's error says too, "rawtr(): only one
    # key expected", the function having nothing to put a second key in
    key = _parse_key(
        _one_argument(args, "rawtr"),
        prv_keys,
        x_only=True,
        compressed=True,
        musig_allowed=True,
    )
    return RawTrDescriptor(key, network=network)


def _parse_addr(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    address = _one_argument(args, "addr")
    # the network of an addr() descriptor is the address's own: it is
    # written in the prefix, so a parameter could only contradict it
    return AddrDescriptor(address, network=ScriptPubKey.from_address(address).network)


def _parse_raw(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    hex_script = _one_argument(args, "raw")
    try:
        script = bytes_from_octets(hex_script)
    # bytes.fromhex raises a plain ValueError, and every other way of
    # writing a descriptor wrong raises a BTClibValueError
    except ValueError as e:
        raise BTClibValueError(f"raw() takes a hex script: {hex_script}") from e
    return RawDescriptor(script, network=network)


# every SCRIPT function, where BIP381 to BIP386 allow it, and what
# reads it. A table rather than a chain of comparisons because the
# position rule is the interesting half and belongs where it can be read
# beside the others
_PARSERS: dict[
    str,
    tuple[tuple[str, ...], Callable[[list[str], str, str, dict[str, str]], Descriptor]],
] = {
    "pk": ((_TOP, _P2SH, _P2WSH, _P2TR), _parse_pk),
    "pkh": ((_TOP, _P2SH, _P2WSH), _parse_pkh),
    "wpkh": ((_TOP, _P2SH), _parse_wpkh),
    "combo": ((_TOP,), _parse_combo),
    "sh": ((_TOP,), _parse_sh),
    "wsh": ((_TOP, _P2SH), _parse_wsh),
    "multi": ((_TOP, _P2SH, _P2WSH), _parse_ordered_multi),
    "sortedmulti": ((_TOP, _P2SH, _P2WSH), _parse_sorted_multi),
    "tr": ((_TOP,), _parse_tr),
    "rawtr": ((_TOP,), _parse_rawtr),
    "addr": ((_TOP,), _parse_addr),
    "raw": ((_TOP,), _parse_raw),
}


def _parse_miniscript_expression(
    expression: str, context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    """Return the MiniscriptDescriptor of a BIP379 expression, sanity checked.

    Refused where the miniscript is not sane, which is what Bitcoin Core
    refuses too: a descriptor is what a wallet spends from, and an
    expression that can be satisfied without a signature, or whose witness
    a third party can rewrite, or whose timelocks contradict each other, is
    not one to hand a wallet. `miniscript.parse` on its own answers for the
    language and leaves the judgement to the caller.
    """
    node = _parse_miniscript(expression, _MINISCRIPT_CONTEXTS[context], prv_keys)
    _assert_sane(node)
    return MiniscriptDescriptor(node, network=network)


def _parse_expression(
    expression: str, context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    """Return the Descriptor of a SCRIPT expression, in its context.

    A miniscript is what an expression is where it is not one of the
    functions below: the two grammars share ``pk()``, ``pkh()`` and
    ``multi()``, which BIP379 says mean the same thing in both, so those
    are read as the descriptor functions they were before miniscript --
    which is Bitcoin Core's order too, its own parser trying the functions
    it knows and falling through to miniscript for the rest.
    """
    name = expression.partition("(")[0]
    if name == "musig":
        # a key expression where a SCRIPT one is expected: BIP390's own
        # invalid vectors write it as sh(musig()) and wsh(musig()), and
        # what is wrong with both is the position rather than the word
        _assert_musig_allowed(musig_allowed=False)
    if name in _TREE_FUNCTIONS:
        # a tree leaf and no SCRIPT expression, so reaching this is the
        # position rule of BIP387 being broken: `_assert_position` says
        # which position it was, where "unknown function" would say the
        # language has no such word. Before the miniscript branch below,
        # which would answer for the same two names as a tapscript
        # fragment written where a p2wsh one belongs
        _assert_position(name, context, (_P2TR,))
    if name not in _PARSERS and context in _MINISCRIPT_CONTEXTS:
        return _parse_miniscript_expression(expression, context, network, prv_keys)
    name, arguments = _split_function(expression)
    if name not in _PARSERS:
        raise BTClibValueError(f"unknown descriptor function: {name}()")
    allowed, parser = _PARSERS[name]
    _assert_position(name, context, allowed)
    return parser(_split_arguments(arguments), context, network, prv_keys)


def parse(
    descriptor: str,
    network: str = "mainnet",
    prv_keys: dict[str, str] | None = None,
) -> Descriptor:
    """Return the Descriptor of a descriptor string, checksum verified.

    A `str`, an output descriptor being text: what was neither reached
    `strip_checksum` untouched and left as an AttributeError about
    `partition`, or as a TypeError about mixing bytes and str -- neither
    of them a word about the descriptor that was passed.

    The network is asked for here rather than where a script is finally
    written: a name no network has was carried into the Descriptor and
    refused by the encoder that came to use it, which is a complaint
    about a key or an address, one call later than the argument that was
    wrong. Normalized as well, so that what the object holds is the name
    `network_from_name` would answer to.

    `prv_keys` is a mapping, and what is not one was walked anyway: the
    lookups below are `in` and `[]`, so a list of pairs answered "not
    found" for every key rather than saying it is not a mapping. `None`
    is asked for with it, that being the other type the annotation
    declares -- and one call rather than a branch, which is what keeps
    the two spellings of "a declared type" in one place.
    """
    assert_type(descriptor, str, "descriptor")
    network = _validated_network_name(network)
    assert_type(prv_keys, (Mapping, type(None)), "prv_keys")

    if prv_keys is None:
        prv_keys = {}
    return _parse_expression(strip_checksum(descriptor), _TOP, network, prv_keys)


def _normalized_key(key: KeyExpression, prv_keys: PrvKeys | None) -> KeyExpression:
    """Return the key expression re-rooted at its last hardened step.

    What makes a descriptor written with hardened derivation useful to a
    wallet that holds no private key: the extended key becomes the xpub
    at that step, and the hardened prefix moves into the key origin,
    where it is a statement about where the key came from rather than a
    derivation anybody has to perform.

    Three keys are returned as they are, with the symbol normalized and
    nothing else: one that is not extended, one whose path hardens
    nothing, and one whose wildcard is the hardened `/*h`. The last is
    Bitcoin Core's first branch too, and for the same reason -- the step
    that needs the private key is the one taken at every index, so there
    is no point to re-root to.

    A ``musig()`` is its participants normalized: its own path cannot
    harden, BIP390 forbidding it, so there is nothing else of it to
    re-root.
    """
    if key.participants:
        return replace(
            key,
            participants=tuple(
                _normalized_key(participant, prv_keys)
                for participant in key.participants
            ),
            hardening=_HARDENING,
        )
    if key.pub_key is not None or key.wildcard == _HARDENED_OFFSET:
        return replace(key, hardening=_HARDENING)
    hardened = [i for i, step in enumerate(key.der_path) if step >= _HARDENED_OFFSET]
    if not hardened:
        return replace(key, hardening=_HARDENING)

    xprv = prv_keys.get(key.xkey) if prv_keys else None
    if xprv is None:
        err_msg = "no private key to normalize the hardened derivation of a key"
        raise BTClibValueError(err_msg)
    last = hardened[-1] + 1
    prefix = list(key.der_path[:last])
    return replace(
        key,
        origin=BIP32KeyOrigin(
            key.origin.master_fingerprint if key.origin else fingerprint(key.xkey),
            [*(key.origin.der_path if key.origin else []), *prefix],
        ),
        # `xprv` is a string out of the caller's mapping, so the decode
        # validates it; the base58 round trip the public pair would make
        # between the two steps does not
        xkey=_xpub_from_xprv(
            _derive(_key_data_from_bip32_key(xprv), prefix, None)
        ).b58encode(),
        der_path=key.der_path[last:],
        hardening=_HARDENING,
    )


def _mapped_node(
    node: Miniscript, key_map: Callable[[KeyExpression], KeyExpression]
) -> Miniscript:
    """Return the miniscript with `key_map` applied to every key in it.

    The two fields of a node that can hold one: its own KEY expressions
    and the subexpressions under it. What a node derives from those is
    `init=False`, so rebuilding bottom-up is the whole of it -- `replace`
    recomputes the type, the script size and the bounds from the keys
    that are now there.
    """
    return replace(
        node,
        subs=tuple(_mapped_node(sub, key_map) for sub in node.subs),
        keys=tuple(key_map(key) for key in node.keys),
    )


def _mapped_field(
    value: object, key_map: Callable[[KeyExpression], KeyExpression]
) -> object:
    """Return one field of a descriptor with every key in it mapped.

    Where a key can be: the field itself, a key of a ``multi_a()`` leaf, a
    key of a miniscript node or of one nested under it, a key of a
    fragment another one wraps, or an element of a script tree, which is a
    tuple of tuples. Nothing else in a fragment holds one, and a field
    added later that does will be walked here by construction -- which is
    the whole reason this is one function rather than a method per
    fragment.
    """
    if isinstance(value, KeyExpression):
        return key_map(value)
    if isinstance(value, MultiA):
        return replace(value, keys=tuple(key_map(key) for key in value.keys))
    if isinstance(value, Miniscript):
        return _mapped_node(value, key_map)
    if isinstance(value, Descriptor):
        return _mapped_keys(value, key_map)
    if isinstance(value, tuple):
        return tuple(_mapped_field(item, key_map) for item in value)
    return value


def _mapped_keys(
    descriptor: Descriptor, key_map: Callable[[KeyExpression], KeyExpression]
) -> Descriptor:
    """Return the descriptor with `key_map` applied to every key it holds."""
    changed: dict[str, Any] = {
        field.name: _mapped_field(getattr(descriptor, field.name), key_map)
        for field in fields(descriptor)
    }
    return replace(descriptor, **changed)


def normalized(descriptor: Descriptor, prv_keys: PrvKeys | None = None) -> Descriptor:
    """Return the descriptor with the xpub at each last hardened step.

    Bitcoin Core's `ToNormalizedString`, which is what `getdescriptorinfo`
    answers with and what an export to a watch-only wallet wants: every
    key of it derives from an xpub, so a holder of no private key can
    compute every script the descriptor describes.

    The private material is the caller's, as everywhere else here, and is
    needed for exactly the keys that have a hardened step to re-root at.
    Where one of those is missing this raises rather than handing back a
    descriptor that quietly still needs a key.

    The hardening symbol is `h` throughout the result, whichever was
    read: a normalized descriptor is a canonical spelling and not the one
    that came in, which is Core's rule -- "always use h for hardened
    derivation" is how its own interface states it.
    """
    return _mapped_keys(descriptor, lambda key: _normalized_key(key, prv_keys))


def at_index(descriptor: Descriptor, index: int = 0) -> Descriptor:
    """Return the descriptor of one index, with no wildcard left in it.

    A ranged descriptor describes a range of scripts and names none of
    them; this names one, by writing the index the wildcard stands for
    into the derivation path -- ``.../0/*`` at index 5 becomes ``.../0/5``.
    The scripts are the same scripts: what changes is that the answer is
    a descriptor of one, which is what a reader wanting *this* script has
    to be given, an external signer displaying an address among them.

    Bitcoin Core's `deriveaddresses` is the same operation with the
    address as its answer rather than the descriptor.

    A descriptor with no wildcard comes back unchanged, index 0 being the
    only index it has; the participants of a ``musig()`` are walked too,
    the range being on either side of the aggregation and never on both.
    """
    descriptor._assert_index(index)

    def fixed(key: KeyExpression) -> KeyExpression:
        if key.participants:
            key = replace(
                key, participants=tuple(fixed(one) for one in key.participants)
            )
        if key.wildcard is None:
            return key
        return replace(
            key, der_path=(*key.der_path, key.wildcard + index), wildcard=None
        )

    return _mapped_keys(descriptor, fixed)


def miniscript_sizer(psbt_in: PsbtIn, tx_in: TxIn) -> list[int] | None:
    """Size the spend of a psbt input whose witness script is a miniscript.

    A `SolutionSizer`, which is what `psbt_size.estimated_input_sizes` takes
    for the inputs whose spend it cannot read -- and it lives here for
    `miniscript_solver`'s reason, the layering: `descriptors` imports `psbt`
    and nothing there imports back. A caller passes it::

        script_sig, witness = estimated_input_sizes(
            psbt_in, tx_in, sizer=miniscript_sizer
        )

    The witness of a p2wsh spend is the satisfaction and then the witness
    script, so that is the list: `Miniscript.max_witness_stack` and the
    script's own length. It needs no signature and no preimage, an estimate
    being made before either exists -- the size of a signature is the
    context's, and BIP379 fixes a preimage at 32 bytes.

    None where the input is not this sizer's business: no witness script,
    one that is no miniscript, or one no witness can satisfy at all. The
    caller then answers as it did before, which for the last of those is a
    refusal: a script nobody can spend has no spend to estimate.
    """
    # `tx_in` is unread here and checked anyway: the pair is what a
    # `SolutionSizer` declares, so the guarantee is the signature's rather
    # than this body's, and the sizer beside this one does read it
    _assert_input_types(psbt_in, tx_in)
    if not psbt_in.witness_script:
        return None
    known = (*psbt_in.partial_sigs, *psbt_in.hd_key_paths)
    try:
        node = _miniscript_from_script(
            psbt_in.witness_script,
            miniscript.P2WSH,
            {hash160(key): key for key in known},
        )
    # not a miniscript, which is the answer "not mine" and not an error
    except BTClibValueError:
        return None
    stack = node.max_witness_stack
    if stack is None:
        return None
    return [*stack, len(psbt_in.witness_script)]


def satisfaction_sizer(keys: Iterable[Octets]) -> SolutionSizer:
    """Return a `SolutionSizer` for the satisfaction these keys will build.

    `miniscript_sizer` answers "how large could this get", every branch
    open and every signature assumed -- right where a caller does not yet
    know which branch a spend will take, and an overpay where it does. A
    quorum with a timelocked recovery quorum behind the same address is
    exactly that second caller: which of the two a transaction takes is
    decided before anything is estimated, the recovery spend being a
    separate operation with its own inputs and its own signatures.

    `Miniscript.satisfy` already answers the narrower question -- given
    which keys will sign, which branch and how large -- so this is that
    answer as a `SolutionSizer`, beside `miniscript_sizer` and not a mode
    of it::

        witness = estimated_input_sizes(
            psbt_in, tx_in, sizer=satisfaction_sizer(recovery_keys)
        )

    `satisfy` never checks a signature against anything, so a filler one
    of `psbt_size.SIG_SIZE` bytes for each key does exactly what a real
    one would for sizing, and none of them has to exist yet, any more
    than the ones `miniscript_sizer` assumes do. The preimages are the
    psbt input's own, and the sequence is the input being sized, so an
    ``older()`` branch is measured against what this spend actually
    carries. An ``after()`` branch is not, `locktime` being the
    transaction's and not this call's to read -- it is answered as unmet,
    and a script whose only open branch needs one refuses rather than
    guesses.

    None for that refusal and the two `miniscript_sizer` already answers
    with it: no witness script, or one that is no miniscript. A caller
    then falls back exactly as it would for any other sizer answering
    "not mine".
    """
    # an Octets is itself iterable, so `Iterable[Octets]` accepts one as
    # far as the annotation goes: one key handed where the list was meant
    # is as many keys as it has octets, and each of them invalid
    if is_octets(keys):
        raise BTClibTypeError(f"invalid keys type: {type(keys).__name__}")
    if not isinstance(keys, Iterable):
        raise BTClibTypeError(f"invalid keys type: {type(keys).__name__}")
    signer_keys = tuple(bytes_from_octets(key) for key in keys)

    def sizer(psbt_in: PsbtIn, tx_in: TxIn) -> list[int] | None:
        _assert_input_types(psbt_in, tx_in)
        if not psbt_in.witness_script:
            return None
        known = (*psbt_in.partial_sigs, *psbt_in.hd_key_paths, *signer_keys)
        try:
            node = _miniscript_from_script(
                psbt_in.witness_script,
                miniscript.P2WSH,
                {hash160(key): key for key in known},
            )
        # not a miniscript, which is the answer "not mine" and not an error
        except BTClibValueError:
            return None
        signatures = dict.fromkeys(signer_keys, bytes(SIG_SIZE))
        spend = SpendContext(
            sha256_preimages=psbt_in.sha256_preimages,
            hash256_preimages=psbt_in.hash256_preimages,
            ripemd160_preimages=psbt_in.ripemd160_preimages,
            hash160_preimages=psbt_in.hash160_preimages,
            sequence=tx_in.sequence,
        )
        try:
            stack = node.satisfy(cast("Mapping[Octets, Octets]", signatures), spend)
        # these keys build no satisfaction, or only a malleable one
        except BTClibValueError:
            return None
        return [*(len(element) for element in stack), len(psbt_in.witness_script)]

    return sizer


def miniscript_solver(psbt: Psbt, vin_i: int) -> tuple[bytes, Witness] | None:
    """Spend a psbt input whose witness script is a miniscript.

    An `InputSolver`, which is what `psbt.finalize` takes for the inputs
    whose spend is the caller's to know -- and a miniscript is one of
    them, for a reason of layering rather than of design: `descriptors`
    imports `psbt` and nothing there imports back, so the finalizer cannot
    reach the language that reads its witness script. Passing this is what
    closes that circle from the outside::

        final = psbt.finalize(unsigned, solver=miniscript_solver)

    Everything it needs is in the psbt. The witness script is read back
    into the expression it is -- which is what `miniscript.from_script`
    is for, and what makes a signer able to spend a script nobody handed
    it a descriptor for -- and the satisfaction reads the input's own
    fields: the signatures of `partial_sigs`, the four preimage mappings
    BIP174 gave fields to, and the lock times of the transaction the psbt
    is building. A ``pk_h()`` names its key by a hash160, so the keys the
    input knows are offered for that lookup.

    None where the input is not this solver's business: no witness script,
    or one that is not a miniscript, both of which `finalize` then answers
    for as it did before. Where the script *is* a miniscript and the
    signatures do not satisfy it, the refusal is the satisfier's and says
    so -- a witness built from a guess would be worse, being one the
    network refuses after the transaction is broadcast rather than one
    this refuses while it is built.
    """
    # the guard `update_psbt_input` carries, for the same reason: an
    # IndexError out of a public function is not an answer, and a
    # negative index would quietly solve the input at the other end --
    # with a witness this one's script does not satisfy
    if not 0 <= vin_i < len(psbt.inputs):
        raise BTClibValueError(f"invalid input index: {vin_i}")
    psbt_in = psbt.inputs[vin_i]
    if not psbt_in.witness_script:
        return None
    # a pk_h() holds the hash of its key and not the key, so the keys the
    # input carries are what can be recognized: the ones that signed, and
    # the ones an origin names
    known = (*psbt_in.partial_sigs, *psbt_in.hd_key_paths)
    try:
        node = _miniscript_from_script(
            psbt_in.witness_script,
            miniscript.P2WSH,
            {hash160(key): key for key in known},
        )
    # not a miniscript, which is not an error: it is the answer "not mine"
    except BTClibValueError:
        return None
    tx = psbt.tx
    spend = SpendContext(
        sha256_preimages=psbt_in.sha256_preimages,
        hash256_preimages=psbt_in.hash256_preimages,
        ripemd160_preimages=psbt_in.ripemd160_preimages,
        hash160_preimages=psbt_in.hash160_preimages,
        locktime=tx.lock_time,
        sequence=tx.vin[vin_i].sequence,
        version=tx.version,
    )
    stack = node.satisfy(cast("Mapping[Octets, Octets]", psbt_in.partial_sigs), spend)
    # the redeem script of a wrapped p2wsh, and the empty script_sig BIP141
    # requires of a native one
    script_sig: ScriptList = [psbt_in.redeem_script] if psbt_in.redeem_script else []
    return serialize(script_sig), Witness([*stack, psbt_in.witness_script])


def multipath_descriptors(descriptor: str) -> list[str]:
    """Return the single-path descriptors of a BIP389 multipath one.

    A descriptor with no ``<a;b>`` step is one descriptor, returned
    checksummed and otherwise unchanged. One with such steps is as many
    descriptors as a step has elements, the first taking the first
    element of every step, the second the second, and so on -- which is
    what makes the two-element form a receiving chain and a change chain.

    The expansion is textual, as BIP389 defines it, and each result is a
    descriptor to be parsed on its own.
    """
    pieces = _MULTIPATH_STEP.split(strip_checksum(descriptor))
    # re.split with a capturing pattern alternates text and separator, so
    # the odd positions are the multipath steps and the even ones the
    # descriptor around them
    steps = [piece[1:-1].split(";") for piece in pieces[1::2]]
    if not steps:
        return [add_checksum(pieces[0])]
    lengths = {len(step) for step in steps}
    if len(lengths) != 1:
        err_msg = f"multipath steps of different length: {sorted(lengths)}"
        raise BTClibValueError(err_msg)
    length = lengths.pop()
    if length < 2:
        raise BTClibValueError("a multipath step takes at least two elements")
    descriptors = []
    for i in range(length):
        pieces[1::2] = [step[i] for step in steps]
        descriptors.append(add_checksum("".join(pieces)))
    return descriptors


# BIP44's fourth level, the two chains every wallet keeps: 0 receives and
# 1 is change, which is the only difference between the pair below
_RECEIVE_CHAIN = 0
_CHANGE_CHAIN = 1

# what a standard account descriptor is, per script type: the fragment
# built around one ranged key expression. Keyed by BIP44ScriptType, so
# this table and `bip44`'s two are checked against each other -- a fifth
# script type is a key mypy does not know.
#
# Lambdas because `network` is keyword-only on `Descriptor`, so a fragment
# class cannot be the value directly, and because ``sh(wpkh())`` is two
# fragments where the others are one
_DESCRIPTOR_FROM_SCRIPT_TYPE: dict[
    BIP44ScriptType, Callable[[KeyExpression, str], Descriptor]
] = {
    "p2pkh": lambda key, network: PkhDescriptor(key, network=network),
    "p2wpkh-p2sh": lambda key, network: ShDescriptor(
        WpkhDescriptor(key, network=network), network=network
    ),
    "p2wpkh": lambda key, network: WpkhDescriptor(key, network=network),
    "p2tr": lambda key, network: TrDescriptor(key, network=network),
}


def _account_xpub(xkey: BIP32KeyData, indexes: list[int]) -> str:
    """Return the account xpub, derived from the key if it is above it.

    Neutered whatever was handed in, as `parse` neuters what it reads: a
    descriptor holds no key that signs, and nothing below an account level
    hardens, so the xpub computes every script the pair describes.

    The version bytes are BIP32's, whichever the key arrived in. A SLIP132
    ypub or zpub says which script type its keys are for, which is what the
    descriptor function says: the two spellings would then be one claim
    made twice, and a descriptor holding a zpub is one no other
    implementation reads -- Bitcoin Core decodes the BIP32 versions and
    nothing else. Same key, same scripts, one spelling of it.
    """
    network = NETWORKS[network_from_xkeyversion(xkey.version)]
    version = network.bip32_prv if xkey.is_private else network.bip32_pub
    # the private pair, `xkey` being validated already: the public
    # `derive` would serialize to base58 for `xpub_from_xprv` to decode
    # straight back, and each of the four steps would validate
    derived = _derive(xkey, _indexes_left_to_derive(xkey, indexes), version)
    account = _xpub_from_xprv(derived) if xkey.is_private else derived
    return account.b58encode()


def _account_fingerprint(
    xkey: BIP32KeyData, master_fingerprint: Octets | None
) -> bytes:
    """Return the master fingerprint of the key origin, checking what it can.

    Computed from the key only when the key *is* the master one, at depth
    zero: the fingerprint of a key at any other depth is that key's, not
    its master's, and a key origin naming it would send a signer looking
    for a master key nobody has. So a key already below the root has to be
    told, and where the caller says it too the two must agree -- one of
    them would otherwise be silently preferred, and neither is more likely
    to be right.
    """
    own = fingerprint(xkey.b58encode()) if xkey.depth == 0 else None
    if master_fingerprint is None:
        if own is None:
            err_msg = "no master fingerprint: a key below the root cannot say"
            err_msg += " which master key it came from"
            raise BTClibValueError(err_msg)
        return own
    given = bytes_from_octets(master_fingerprint, 4)
    if own is not None and own != given:
        err_msg = f"master fingerprint {given.hex()} is not the key's own"
        err_msg += f" {own.hex()}"
        raise BTClibValueError(err_msg)
    return given


def account_descriptors(
    xkey: BIP32Key,
    der_path: DerPath,
    master_fingerprint: Octets | None = None,
    script_type: BIP44ScriptType | None = None,
) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of a BIP44 account.

    der_path is the three-level account path,
    m/purpose'/coin_type'/account', in any spelling `bip32.derive`
    accepts; xkey is the extended key it starts from, which may be the
    master key or any key already partway down it -- the account xpub
    itself, typically, which is what a wallet exports and what a hardware
    signer answers with.

    The purpose selects the encoding, as it does for a BIP44 address: 44
    is ``pkh()``, 49 ``sh(wpkh())``, 84 ``wpkh()``, 86 ``tr()``. A purpose
    outside `bip44.SCRIPT_TYPE_FROM_PURPOSE` raises unless script_type
    names one of those four, which then overrides the mapping for known
    purposes too. The network is the extended key's own, and the coin type
    has to agree with it.

    Both chains come back because a wallet is both: BIP44 puts receiving
    addresses under `/0` and change under `/1`, and a wallet that imported
    one and not the other cannot recognize its own change -- which is a
    lost output rather than a missing feature. They differ in that step
    and in nothing else, the key origin and the wildcard being the same.

    The master fingerprint is what the key origin needs and what an
    extended key below the root cannot supply, so it is a parameter; where
    xkey is the master key it is computed, and a value handed in beside it
    has to match.

    `add_checksum(str(descriptor))` is the text Bitcoin Core takes. The
    BIP389 spelling of the pair -- one descriptor with a ``<0;1>`` step --
    is text and not a parsed descriptor: `multipath_descriptors` expands
    one and `parse` refuses one, so what this returns is the two.
    """
    xkey = _key_data_from_bip32_key(xkey)

    indexes = indexes_from_der_path(der_path)
    _assert_valid_account_path(indexes)
    if script_type is None:
        script_type = _script_type_from_purpose(indexes[0] - _HARDENED_OFFSET)
    # the lookup and not an isinstance, for `bip44`'s reason: the table is
    # the list of script types this module can build, so missing from it
    # and unknown are one thing, and a Literal is a mypy fact rather than
    # a runtime one
    build = _DESCRIPTOR_FROM_SCRIPT_TYPE.get(script_type)
    if build is None:
        known = ", ".join(sorted(_DESCRIPTOR_FROM_SCRIPT_TYPE))
        raise BTClibValueError(f"unknown script type: {script_type} not in ({known})")
    _assert_valid_coin_type(indexes[1] - _HARDENED_OFFSET, xkey)

    # the xpub first, and the fingerprint after it: a key that does not fit
    # the path is about the two arguments the caller passed together, where
    # a missing fingerprint is about a third
    account_xpub = _account_xpub(xkey, indexes)
    origin = BIP32KeyOrigin(_account_fingerprint(xkey, master_fingerprint), indexes)
    network = network_from_xkeyversion(xkey.version)

    def chain(index: int) -> Descriptor:
        key = KeyExpression(
            origin=origin, xkey=account_xpub, der_path=(index,), wildcard=0
        )
        return build(key, network)

    return chain(_RECEIVE_CHAIN), chain(_CHANGE_CHAIN)
