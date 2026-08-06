# Copyright (c) The btclib developers
#
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

`update_psbt` is the third answer, and the one for a spend the signers
do not make all at once: BIP174's Updater, writing the scripts and the
key origins into a psbt input, for signers to fill in at their own pace
and `psbt.finalize` to assemble. This module imports `psbt` for it
and nothing there imports back, which is the direction of the layering:
a psbt is a transaction being built, and a descriptor is what a wallet
knows about the outputs it holds.

BIP380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki

The grammar read is BIP380 to BIP387 and BIP389, minus miniscript:

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

What raises NotImplementedError, rather than being read wrong: every
miniscript expression, which is issue #187.

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
`script_pub_keys`, `satisfy`, `update_psbt` and the rest all end in an
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
made of -- `KeyExpression`, `DescriptorTree` and the `MultiA` a tree leaf
may be among them, all three being names a caller reads off
`Descriptor.key_expressions` and `TrDescriptor.tree`, and `PrvKeys` being
what a caller annotates the mapping above with. `INPUT_CHARSET`,
`CHECKSUM_CHARSET` and `GENERATOR` stay out: they are the three tables
BIP380's checksum is computed from, which is what `checksum`,
`add_checksum` and `strip_checksum` answer, and each is still importable
from this module the way the test suite takes them.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from typing import Any, cast

from btclib.alias import BIP44ScriptType, Octets, ScriptList, TaprootScriptTree
from btclib.bip32.bip32 import (
    BIP328_CHAIN_CODE,
    BIP32Key,
    BIP32KeyData,
    derive,
    xpub_from_xprv,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    _HARDENING,
    DerPath,
    hardenings_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
    str_from_index_int,
)
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.bip44 import (
    _assert_valid_account_path,
    _assert_valid_coin_type,
    _indexes_left_to_derive,
    _script_type_from_purpose,
)
from btclib.curves import secp256k1
from btclib.curves.sec_point import bytes_from_point
from btclib.ecc.musig2 import key_agg, key_sort
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS, network_from_xkeyversion
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_in import PsbtIn
from btclib.script.script import op_int, serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import input_script_sig, leaf_hash, tree_helper
from btclib.script.witness import Witness
from btclib.to_pub_key import fingerprint, point_from_pub_key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets

__all__ = [
    "AddrDescriptor",
    "ComboDescriptor",
    "Descriptor",
    "DescriptorLeaf",
    "DescriptorTree",
    "KeyExpression",
    "MultiA",
    "MultiDescriptor",
    "PkDescriptor",
    "PkhDescriptor",
    "PrvKeys",
    "RawDescriptor",
    "RawTrDescriptor",
    "ShDescriptor",
    "TrDescriptor",
    "WpkhDescriptor",
    "WshDescriptor",
    "account_descriptors",
    "add_checksum",
    "checksum",
    "from_address",
    "multipath_descriptors",
    "normalized",
    "parse",
    "strip_checksum",
]

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


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
        if char not in INPUT_CHARSET:
            raise BTClibValueError(f"invalid descriptor character: {char!r}")
        index = INPUT_CHARSET.find(char)
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

# BIP379 fragments that are miniscript and nothing else. pk, pkh and
# multi are miniscript too, but they are descriptor functions first and
# are read as such; a wrapper (`s:pk(...)`) is caught by the colon
_MINISCRIPT_FRAGMENTS = frozenset(
    (
        "pk_k",
        "pk_h",
        "older",
        "after",
        "sha256",
        "hash256",
        "ripemd160",
        "hash160",
        "andor",
        "and_v",
        "and_b",
        "and_n",
        "or_b",
        "or_c",
        "or_d",
        "or_i",
        "thresh",
    )
)

# BIP387's own bound on the keys of a multi_a(): the satisfaction puts one
# stack element per key, and a script whose spend would push more than the
# 1000 elements BIP342 allows is one nobody can spend
_MAX_MULTI_A_KEYS = 999

# the two functions BIP387 allows inside tr() and nowhere else. Not in
# _PARSERS with the SCRIPT expressions: what they parse to is a leaf of a
# script tree and not a descriptor, so `_parse_tree` reads them and this
# is what refuses them anywhere a SCRIPT expression is expected
_TREE_FUNCTIONS = ("multi_a", "sortedmulti_a")

_FINGERPRINT = re.compile("[0-9a-fA-F]{8}")
_HEX = re.compile("[0-9a-fA-F]*")
_THRESHOLD = re.compile("[0-9]+")
# the BIP389 multipath step, brackets included: re.split hands back what
# it split on when the pattern captures it
_MULTIPATH_STEP = re.compile("(<[^<>]*>)")


# what `parse` hands back beside the descriptor, and what expansion takes
# when a hardened step needs it: the extended private key each extended
# key was read from, filed under the neutered spelling the descriptor
# keeps. Public identity to private material, which is how Bitcoin Core's
# `FlatSigningProvider` is keyed too -- by the key id there, by the xpub
# here, an extended key being what a descriptor derives from
PrvKeys = Mapping[str, str]


@dataclass(frozen=True)
class KeyExpression:
    """A BIP380 KEY expression: an origin, a key, a derivation path.

    One of three things is the key. Either `pub_key` is the one the
    descriptor fixes, in SEC bytes; or `xkey` is the extended key that
    `der_path` and `wildcard` derive from; or `participants` are the KEY
    expressions BIP390's ``musig()`` aggregates, `der_path` and `wildcard`
    then deriving from the aggregate key as BIP328 prescribes. An x-only
    key is held as its even-y SEC form, which is what BIP340 says those 32
    bytes mean, so that everything downstream sees one representation of a
    public key.

    `origin` never changes the script. It says which master key and which
    path the key came from, which is what a hardware signer needs and
    what BIP174 carries in a PSBT.

    `xkey` is public whatever the descriptor spelled: `parse` neuters an
    xprv and hands the private material back to its caller, so no part of
    a parsed descriptor holds a key that signs. What that costs is a
    hardened step, which an xpub cannot take -- `sec` takes the keys back
    as a parameter for it, the way Bitcoin Core's expansion takes a
    `SigningProvider`.
    """

    origin: BIP32KeyOrigin | None = None
    pub_key: bytes | None = None
    xkey: str = ""
    der_path: tuple[int, ...] = ()
    # the final `/*` step, as the offset its hardening adds to the index:
    # None where the descriptor has no wildcard, 0 for `/*`, 2**31 for
    # `/*h`. One field rather than a flag and a bool, because "hardened"
    # is only meaningful when there is a wildcard to harden
    wildcard: int | None = None
    x_only: bool = False
    # BIP390's ``musig()``: the participants whose keys aggregate to this
    # one, in the order the descriptor writes them. `KeySort` is applied
    # at aggregation and not here, so what is kept is the text's order and
    # what is computed does not depend on it
    participants: tuple[KeyExpression, ...] = ()
    # the symbol every hardened step of this expression is written with:
    # BIP380 gives "h" and "'" one meaning and two spellings, and the two
    # are different strings with different checksums, so a descriptor
    # handed back in the other one is not the descriptor that was read.
    # One symbol for the whole expression, origin included, which is
    # Bitcoin Core's single `m_apostrophe` per key: a path spelled both
    # ways -- BIP380's own valid `[deadbeef/0'/0h/0']` -- is read and
    # written back in the symbol its last hardened step used
    hardening: str = _HARDENING

    @property
    def is_ranged(self) -> bool:
        """Answer whether the key has a wildcard to derive at an index.

        A ``musig()`` is ranged where its own path has one and where a
        participant has one: BIP390 forbids both at once, so whichever it
        is, the index is read in one place.
        """
        return self.wildcard is not None or any(
            key.is_ranged for key in self.participants
        )

    @property
    def is_aggregate(self) -> bool:
        """Answer whether the key is the aggregate of BIP390 participants."""
        return bool(self.participants)

    @property
    def is_compressed(self) -> bool:
        """Return False for an uncompressed SEC public key, True otherwise.

        An extended key is compressed by construction: BIP32 has no
        uncompressed serialization.
        """
        return self.pub_key is None or len(self.pub_key) == 33

    def sec(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> bytes:
        """Return the SEC public key bytes, derived at `index` if ranged.

        `prv_keys` is what `parse` handed back, and is needed for a
        hardened step and for nothing else: an unhardened path derives
        from the xpub the descriptor holds. A key it does not name is
        left as it is, so a mapping covering some of a multisig's keys
        answers for those and no more.

        A ``musig()`` answers with the key its participants aggregate to,
        derived along its own path where it has one: BIP328's synthetic
        xpub is that key at depth zero with the fixed chain code an
        aggregate has instead of one of its own, and `derive` is then what
        refuses a hardened step -- there being no aggregate private key to
        take one with. The index derives the participants or the aggregate
        and never both, BIP390 allowing a wildcard on one side only.
        """
        if self.participants:
            aggregate = self.aggregate(index, network, prv_keys)
            musig_path = list(self.der_path)
            if self.wildcard is not None:
                musig_path.append(self.wildcard + index)
            if not musig_path:
                return aggregate
            synthetic = BIP32KeyData(
                version=NETWORKS[network].bip32_pub,
                depth=0,
                parent_fingerprint=b"\x00" * 4,
                index=0,
                chain_code=BIP328_CHAIN_CODE,
                key=aggregate,
            )
            return pub_keyinfo_from_key(derive(synthetic, musig_path), network)[0]
        if self.pub_key is not None:
            return self.pub_key
        der_path = list(self.der_path)
        if self.wildcard is not None:
            der_path.append(self.wildcard + index)
        xkey = prv_keys.get(self.xkey, self.xkey) if prv_keys else self.xkey
        return pub_keyinfo_from_key(derive(xkey, der_path), network)[0]

    def participant_keys(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> list[bytes]:
        """Return the participant keys in the order they are aggregated in.

        Which is `KeySort`'s order and not the descriptor's: BIP390 sorts
        after all derivation and before aggregation, so that the order the
        keys were written in does not change the key -- a set of keys is
        what MuSig2 is about, and a descriptor that was not backed up does
        not need the order guessed as well. BIP373 stores the participants
        of a psbt in aggregation order too, which is what makes this the
        list that goes into `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS`.
        """
        derived = [key.sec(index, network, prv_keys) for key in self.participants]
        return key_sort(derived)

    def aggregate(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> bytes:
        """Return the key BIP390's participants aggregate to, derived.

        `KeyAgg` over the sorted participants, and nothing more: the
        ``/NUM/.../*`` path of the expression derives *from* this key, and
        `sec` is what walks it. The two are separate because BIP373 keys
        its MuSig2 psbt fields by the aggregate key itself even where what
        the script holds is a child of it -- an aggregate key is what the
        participants make, and a derivation of it is a key the same group
        answers for.
        """
        return bytes_from_point(
            key_agg(self.participant_keys(index, network, prv_keys)).Q, secp256k1
        )

    def __str__(self) -> str:
        """Return the KEY expression, in the spelling it was read in.

        Public whatever was read: an xprv is the xpub `parse` neutered it
        to, and a WIF is the hex of the public key it was reduced to.
        Bitcoin Core writes the same, `ToString` having only the public
        key to write and `ToPrivateString` taking the private material
        back from the caller.

        An x-only key is written as the 32 bytes a ``tr()`` holds, which
        is the spelling it was read in and the only one allowed there.

        A ``musig()`` writes its participants in the order they were read,
        which is not the order they aggregate in: `KeySort` is applied when
        the key is computed, so the text keeps what the descriptor said.
        """
        if self.participants:
            text = _expression("musig", *(str(key) for key in self.participants))
            for index in self.der_path:
                text += "/" + str_from_index_int(index, self.hardening)
            if self.wildcard is not None:
                text += "/*"
            return text
        text = ""
        if self.origin is not None:
            path = str_from_der_path(
                self.origin.der_path, self.origin.master_fingerprint, self.hardening
            )
            text = f"[{path}]"
        if self.pub_key is not None:
            return text + (self.pub_key[1:] if self.x_only else self.pub_key).hex()
        text += self.xkey
        for index in self.der_path:
            text += "/" + str_from_index_int(index, self.hardening)
        if self.wildcard is not None:
            text += "/*" + (self.hardening if self.wildcard else "")
        return text


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
        return sorted(pub_keys, key=lambda sec: sec[1:]) if self.sort else pub_keys

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


def _expression(name: str, *args: str) -> str:
    """Return a descriptor function written out: its name and its arguments."""
    return f"{name}({','.join(args)})"


def _tree_expression(tree: DescriptorTree) -> str:
    """Return a BIP386 TREE as text: a leaf, or two subtrees in braces."""
    if isinstance(tree, tuple):
        return f"{{{_tree_expression(tree[0])},{_tree_expression(tree[1])}}}"
    if isinstance(tree, MultiA):
        return str(tree)
    return _expression("pk", str(tree))


# a tr() script tree: a leaf, or a branch of two subtrees. A leaf is the
# KEY expression a `pk()` leaf is, or the `MultiA` of BIP387's two
# functions; a branch is a tuple, which is what tells a branch from a
# leaf. The leaves hold KEY expressions and not scripts because a ranged
# descriptor has no script until an index is given
DescriptorLeaf = KeyExpression | MultiA
DescriptorTree = DescriptorLeaf | tuple["DescriptorTree", "DescriptorTree"]


def _leaf_keys(leaf: DescriptorLeaf) -> tuple[KeyExpression, ...]:
    """Return the KEY expressions of one leaf, in the order it names them."""
    return leaf.keys if isinstance(leaf, MultiA) else (leaf,)


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
    """Return the tapscript of one leaf: a ``pk()``, or a ``multi_a()``."""
    if isinstance(leaf, MultiA):
        return leaf._script(index, network, prv_keys)
    return [leaf.sec(index, network, prv_keys)[1:], "OP_CHECKSIG"]


def _leaf_stack(
    leaf: DescriptorLeaf,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> list[bytes] | None:
    """Return what satisfies one leaf, None where the signatures do not."""
    if isinstance(leaf, MultiA):
        return leaf._stack(signatures, index, network, prv_keys)
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


def _offered_signature(
    signatures: Mapping[bytes, bytes], sec: bytes, *, x_only: bool = False
) -> bytes | None:
    """Return the signature offered for a public key, None where none is.

    A taproot key answers to either of its two spellings: the 32 x-only
    bytes the script holds, and the 33-byte even-y SEC form a
    KeyExpression keeps it as. Neither is the more correct one, a caller
    has whichever its signer handed back, and 32 bytes cannot be taken
    for 33.
    """
    if sec in signatures:
        return signatures[sec]
    if x_only and sec[1:] in signatures:
        return signatures[sec[1:]]
    return None


def _required_signature(signatures: Mapping[bytes, bytes], sec: bytes) -> bytes:
    """Return the signature made with a public key, refusing where none is.

    The key is named in the error: it is public by construction, and
    which of a descriptor's keys has not signed is the whole content of
    the refusal.
    """
    signature = _offered_signature(signatures, sec)
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
        """
        self._assert_index(index)
        return self._satisfy(
            {
                bytes_from_octets(key): bytes_from_octets(signature)
                for key, signature in signatures.items()
            },
            index,
            prv_keys,
        )

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        """Return the satisfaction, the mapping being already in bytes.

        The legacy answer -- the stack pushed into the script_sig, and
        no witness -- which is what ``pk()``, ``pkh()`` and ``multi()``
        are spent with; the fragments spent otherwise override it.
        Separate from `satisfy` so that a wrapper can satisfy its
        argument without normalizing the same mapping a second time.
        """
        return serialize(
            cast(ScriptList, self._stack(signatures, index, prv_keys))
        ), Witness()

    def update_psbt(
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

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Fill the key origins, which is what every fragment knows.

        And the whole of what ``pk()``, ``pkh()``, ``wpkh()`` and
        ``multi()`` know: their script is the script_pub_key, which the
        psbt has from the utxo rather than from here. The fragments that
        embed one of those add their scripts to this.

        The mapping is added to and not replaced: BIP174 keys it by
        public key, so a psbt already carrying another signer's key keeps
        it, and this descriptor's entry wins for a key held by both.
        """
        psbt_in.hd_key_paths = {
            **psbt_in.hd_key_paths,
            **self._hd_key_paths(index, prv_keys),
        }

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

    def __str__(self) -> str:
        return _expression("pk", str(self.key))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2pk(self.key.sec(index, self.network, prv_keys)).script]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
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

    def __str__(self) -> str:
        return _expression("pkh", str(self.key))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2pkh(self.key.sec(index, self.network, prv_keys)).script]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> list[bytes]:
        # what the output commits to is the hash of the key, so the key
        # goes on the stack for the script to hash for itself
        sec = self.key.sec(index, self.network, prv_keys)
        return [_required_signature(signatures, sec), sec]


@dataclass(frozen=True)
class WpkhDescriptor(Descriptor):
    """``wpkh(KEY)``: a p2wpkh output, BIP382."""

    key: KeyExpression

    def __str__(self) -> str:
        return _expression("wpkh", str(self.key))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2wpkh(self.key.sec(index, self.network, prv_keys)).script]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> list[bytes]:
        # the witness of a p2wpkh spend is what the script_sig of a p2pkh
        # one is, BIP143 having moved it and changed nothing else
        sec = self.key.sec(index, self.network, prv_keys)
        return [_required_signature(signatures, sec), sec]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        # the empty script_sig of BIP141, which is not the same as an
        # empty push: btclib's own engine refuses a native segwit input
        # whose script_sig is there at all (issue #249). A sh(wpkh())
        # gets its one push from the sh() above
        return b"", Witness(self._stack(signatures, index, prv_keys))


@dataclass(frozen=True)
class ShDescriptor(Descriptor):
    """``sh(SCRIPT)``: the argument, p2sh-embedded, BIP381."""

    inner: Descriptor

    def __str__(self) -> str:
        return _expression("sh", str(self.inner))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2sh(self.inner.redeem_script(index, prv_keys)).script]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
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
        script_sig, witness = self.inner._satisfy(signatures, index, prv_keys)
        redeem_script = self.inner.redeem_script(index, prv_keys)
        return script_sig + serialize(cast(ScriptList, [redeem_script])), witness

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Fill the redeem script, and let the argument fill its own fields.

        Delegated rather than dispatched on: the argument of a
        ``sh(wsh())`` is what knows there is a witness script below the
        redeem script, and it is the same method that fills it for a
        native ``wsh()``.
        """
        self.inner._update(psbt_in, index, prv_keys)
        psbt_in.redeem_script = self.inner.redeem_script(index, prv_keys)


@dataclass(frozen=True)
class WshDescriptor(Descriptor):
    """``wsh(SCRIPT)``: the argument, P2WSH-embedded, BIP382."""

    inner: Descriptor

    def __str__(self) -> str:
        return _expression("wsh", str(self.inner))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.p2wsh(self.inner.redeem_script(index, prv_keys)).script]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        """Return the witness of a p2wsh spend: the stack, then the script.

        The argument's stack and not its satisfaction, which would be
        those same elements serialized as a script_sig: a witness is a
        stack already, so BIP141 puts them in it one by one and the
        witness script last.
        """
        stack = self.inner._stack(signatures, index, prv_keys)
        return b"", Witness([*stack, self.inner.redeem_script(index, prv_keys)])

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Fill the witness script; the redeem script is ``sh()``'s to fill.

        Which is the whole difference between a native ``wsh()`` and a
        wrapped one, in the psbt as in the spend: the same witness script,
        and a redeem script only where something wraps it.
        """
        self.inner._update(psbt_in, index, prv_keys)
        psbt_in.witness_script = self.inner.redeem_script(index, prv_keys)


@dataclass(frozen=True)
class MultiDescriptor(Descriptor):
    """``multi(k,KEY,...)`` and ``sortedmulti(k,KEY,...)``, BIP383."""

    threshold: int
    keys: tuple[KeyExpression, ...]
    # BIP67 ordering, which is the whole difference between the two
    # functions: the keys of a sortedmulti() are sorted in the script, so
    # the participants need not agree on an order to agree on an address
    sort: bool = False

    def __str__(self) -> str:
        name = "sortedmulti" if self.sort else "multi"
        return _expression(name, str(self.threshold), *map(str, self.keys))

    @property
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

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        script_pub_key = ScriptPubKey.p2ms(
            self.threshold,
            self._pub_keys(index, prv_keys),
            self.network,
            lexicographic_sorting=False,
        )
        return [script_pub_key.script]

    def _stack(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
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
            (sec, _offered_signature(signatures, sec))
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

    def __str__(self) -> str:
        return _expression("combo", str(self.key))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

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

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: four scripts, and each of them spent differently.

        Which one is being spent is a question the caller answers, by
        satisfying the descriptor of that script -- ``pk()``, ``pkh()``,
        ``wpkh()`` or ``sh(wpkh())`` of the same key -- and it is a
        question `script_pub_keys` can leave open where this cannot.
        """
        err_msg = "combo() is four scripts: satisfy the one being spent"
        raise BTClibValueError(err_msg)

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
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

    def __str__(self) -> str:
        return _expression("addr", self.addr)

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [ScriptPubKey.from_address(self.addr).script]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: an address names a script and not what spends it.

        BTClibValueError and not the NotImplementedError the parser
        raises for what a later release adds: there is nothing to add,
        an address being a commitment to a key or a script that the
        descriptor does not carry.
        """
        raise BTClibValueError("addr() cannot be satisfied: it holds no key")

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
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

    def __str__(self) -> str:
        return _expression("raw", self.script.hex())

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        return [self.script]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
    ) -> tuple[bytes, Witness]:
        """Refuse: a script and no key expression to satisfy it with.

        What ``raw()`` holds is bytes, which say nothing about which key
        signs for them even where they happen to be a script this module
        can otherwise read; the descriptor of that script is what is
        satisfiable.
        """
        raise BTClibValueError("raw() cannot be satisfied: it holds no key")

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
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

    def __str__(self) -> str:
        if self.tree is None:
            return _expression("tr", str(self.internal_key))
        return _expression("tr", str(self.internal_key), _tree_expression(self.tree))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the internal key and every leaf key, in tree order."""
        if self.tree is None:
            return (self.internal_key,)
        return (self.internal_key, *_tree_keys(self.tree))

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

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
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
        signature for a ``pk()`` leaf, and one element per key for a
        ``multi_a()`` one. Both the parity bit and the merkle path in that
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
            stack = _leaf_stack(leaf, signatures, index, self.network, prv_keys)
            if stack is not None:
                script, control_block = self._leaf(script_tree, index, number, prv_keys)
                return b"", Witness([*stack, script, control_block])
        err_msg = "no signature for the tr() internal key or for any of its leaves"
        raise BTClibValueError(err_msg)

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
        """Fill the four taproot fields: internal key, root, leaves, origins.

        This replaces the base method rather than adding to it: a taproot
        key origin belongs in `taproot_hd_key_paths`, keyed by the x-only
        key, and a 33-byte entry in `hd_key_paths` beside it would be the
        same key twice in two spellings, for a signer that signs with
        neither.

        A fifth field where a key of the descriptor is a ``musig()``:
        BIP373's participant list, which is what tells a signer that one of
        the keys it holds is in the group this input is spent by.
        """
        psbt_in.taproot_internal_key = self.internal_key.sec(
            index, self.network, prv_keys
        )[1:]
        psbt_in.taproot_merkle_root = self.taproot_merkle_root(index, prv_keys)
        psbt_in.taproot_leaf_scripts = {
            **psbt_in.taproot_leaf_scripts,
            **self.taproot_leaf_scripts(index, prv_keys),
        }
        psbt_in.taproot_hd_key_paths = {
            **psbt_in.taproot_hd_key_paths,
            **self._taproot_hd_key_paths(index, prv_keys),
        }
        psbt_in.musig2_participant_pub_keys = {
            **psbt_in.musig2_participant_pub_keys,
            **_musig2_participants(self.key_expressions, index, self.network, prv_keys),
        }


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

    def __str__(self) -> str:
        return _expression("rawtr", str(self.key))

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int, prv_keys: PrvKeys | None) -> list[bytes]:
        # not ScriptPubKey.p2tr, which computes an output key from an
        # internal one: here the key already is the output key, and
        # tweaking it would describe an output nobody named
        output_key = self.key.sec(index, self.network, prv_keys)[1:]
        return [serialize(["OP_1", output_key])]

    def _satisfy(
        self,
        signatures: Mapping[bytes, bytes],
        index: int,
        prv_keys: PrvKeys | None,
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

    def _update(self, psbt_in: PsbtIn, index: int, prv_keys: PrvKeys | None) -> None:
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
        psbt_in.taproot_hd_key_paths = {
            **psbt_in.taproot_hd_key_paths,
            **_taproot_derivations(keys, {}, index, self.network, prv_keys),
        }
        psbt_in.musig2_participant_pub_keys = {
            **psbt_in.musig2_participant_pub_keys,
            **_musig2_participants(keys, index, self.network, prv_keys),
        }


def _split_arguments(arguments: str) -> list[str]:
    """Split a comma-separated argument list, at nesting depth zero.

    Parentheses and braces only: they are what nests and what can hold a
    comma of its own, a nested SCRIPT expression and a tr() branch. The
    key origin brackets are deliberately not counted, so that a bracket
    written wrong reaches the key expression parser, which can say which
    of the two ways it is wrong.
    """
    depth = 0
    start = 0
    result = []
    for i, char in enumerate(arguments):
        if char in "({":
            depth += 1
        elif char in ")}":
            depth -= 1
            if depth < 0:
                raise BTClibValueError(f"unbalanced brackets: {arguments}")
        elif char == "," and depth == 0:
            result.append(arguments[start:i])
            start = i + 1
    if depth:
        raise BTClibValueError(f"unbalanced brackets: {arguments}")
    result.append(arguments[start:])
    return result


def _split_function(expression: str) -> tuple[str, str]:
    """Return the function name and the argument string it encloses."""
    open_bracket = expression.find("(")
    if open_bracket < 1 or not expression.endswith(")"):
        raise BTClibValueError(f"not a descriptor expression: {expression}")
    return expression[:open_bracket], expression[open_bracket + 1 : -1]


def _assert_not_miniscript(name: str) -> None:
    """Refuse a miniscript fragment, which is the one thing left unread.

    A wrapper is caught by its colon, and every other function this module
    does not read is answered "unknown descriptor function": miniscript is
    named on its own because it is a language of its own rather than a
    function missing from a table (issue #187).
    """
    if ":" in name or name in _MINISCRIPT_FRAGMENTS:
        err_msg = f"miniscript is not implemented: {name} (issue #187)"
        raise NotImplementedError(err_msg)


def _assert_position(name: str, context: str, allowed: tuple[str, ...]) -> None:
    if context not in allowed:
        raise BTClibValueError(f"{name}() is not allowed inside {context}")


def _one_argument(arguments: list[str], name: str) -> str:
    if len(arguments) != 1:
        err_msg = f"{name}() takes one argument, {len(arguments)} given"
        raise BTClibValueError(err_msg)
    return arguments[0]


def _der_path(path: str) -> list[int]:
    """Return the indexes of a `/`-separated derivation path.

    `bip380_enforced` is the whole of the difference from what a BIP32
    path may spell: an uppercase "H", a "+1", a leading "m" and the
    spaces of "0 h" are all read elsewhere in btclib and none of them is
    a step BIP380 allows. It also refuses 2**31 and above written
    unhardened, there being no such BIP32 index.
    """
    return indexes_from_der_path(path, bip380_enforced=True) if path else []


def _hardening(path: str) -> str:
    """Return the symbol the last hardened step of a path was written with.

    Empty where the path hardens nothing, so that a caller choosing
    between two paths can tell "no opinion" from "an apostrophe". The
    last and not the first, which is Bitcoin Core's rule by construction:
    its parser assigns the bool per hardened element, so the one it ends
    on is the one that is written back.
    """
    if not path:
        return ""
    symbols = [s for s in hardenings_from_der_path(path, bip380_enforced=True) if s]
    return symbols[-1] if symbols else ""


def _key_origin(description: str) -> tuple[BIP32KeyOrigin, str]:
    """Return the key origin of a `[fingerprint/path]` prefix, and its symbol.

    The symbol is the origin's alone, and the caller picks between it and
    the key path's: `BIP32KeyOrigin` does not carry it, an origin being a
    fingerprint and a path whichever way the path was spelled -- two
    origins that differ in nothing else are the same origin, and equality
    and `serialize` both have to keep saying so.
    """
    fingerprint, _, path = description.partition("/")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise BTClibValueError(f"invalid key origin fingerprint: {fingerprint}")
    return BIP32KeyOrigin(fingerprint, _der_path(path)), _hardening(path)


def _pub_key_from_hex(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex key, and whether it was x-only."""
    length = len(key)
    if length == 64:
        if not x_only:
            # "inside tr()" would not be true of every position that
            # refuses one: a musig() participant is inside a tr() and is
            # aggregated as a point, so it needs the byte an x-only key drops
            err_msg = "x-only public keys are allowed in a taproot key expression only"
            raise BTClibValueError(err_msg)
        # the even-y lift of BIP340, which is what an x-only key means
        pub_key = b"\x02" + bytes_from_octets(key)
    elif length in (66, 130):
        prefix = key[:2]
        if (length == 66 and prefix not in ("02", "03")) or (
            length == 130 and prefix != "04"
        ):
            # 06 and 07 are the hybrid encoding, which nothing in bitcoin
            # produces and Bitcoin Core refuses in a descriptor too
            raise BTClibValueError(f"invalid public key prefix: 0x{prefix}")
        pub_key = bytes_from_octets(key)
    else:
        raise BTClibValueError(f"invalid public key length: {length} characters")
    # a key expression is parsed in order to be used, and a point off the
    # curve has no script to derive: refuse it here, where the error can
    # still say it was the key
    point_from_pub_key(pub_key)
    return pub_key, length == 64


def _is_extended_key(key: str) -> bool:
    try:
        BIP32KeyData.b58decode(key)
    # ValueError, not Exception: the question is whether these characters
    # are an extended key, and characters that are not are False
    except ValueError:
        return False
    return True


def _neutered(xkey: str, prv_keys: dict[str, str]) -> str:
    """Return the public spelling of an extended key, filing the private one.

    The one place a descriptor's private material is separated from the
    descriptor, and the reason `KeyExpression.xkey` can be said to be
    public: an xprv is answered with its xpub, and the xprv goes to the
    caller's mapping under that xpub. An xpub is answered with itself and
    files nothing.

    Filed under the public spelling, so that what indexes the mapping is
    not itself a secret -- which is how Bitcoin Core keys the
    `FlatSigningProvider` its own parser fills, by the id of the public
    key rather than by anything that signs.
    """
    if not BIP32KeyData.b58decode(xkey).is_private:
        return xkey
    xpub = xpub_from_xprv(xkey)
    prv_keys[xpub] = xkey
    return xpub


def _origin_and_rest(expression: str) -> tuple[BIP32KeyOrigin | None, str, str]:
    """Split the `[fingerprint/path]` prefix off a KEY expression."""
    if not expression.startswith("["):
        if "]" in expression:
            raise BTClibValueError("']' without the '[' that opens a key origin")
        return None, "", expression
    end = expression.find("]")
    if end < 0:
        raise BTClibValueError("missing ']' in the key origin")
    origin, hardening = _key_origin(expression[1:end])
    return origin, hardening, expression[end + 1 :]


def _assert_musig_allowed(*, musig_allowed: bool) -> None:
    """Refuse a ``musig()`` anywhere BIP390 does not put one.

    Which is everywhere but a ``tr()`` and a ``rawtr()``: their internal
    or output key, and the keys of the ``pk()``, ``multi_a()`` and
    ``sortedmulti_a()`` leaves of a script tree. A participant is one of
    the places it is refused, which is BIP390's "cannot be nested within
    another musig()", and the message names both -- Bitcoin Core's own,
    and the same sentence answers a nested one and a ``wpkh(musig())``.

    BIP390 names ``sp()`` as a third position; btclib does not read
    ``sp()`` at all, so there is nothing here to allow it in.
    """
    if not musig_allowed:
        raise BTClibValueError("musig() is only allowed in tr() and rawtr()")


def _assert_key_characters(rest: str) -> None:
    """Refuse what a KEY expression cannot hold once the origin is off."""
    if "]" in rest:
        raise BTClibValueError("more than one ']' in a single key expression")
    if "<" in rest:
        err_msg = "multipath key expression: use multipath_descriptors first"
        raise BTClibValueError(err_msg)
    if "(" in rest:
        # a function where a key belongs. BIP390's musig() is the one that
        # is a key expression, and reaching here means it was written
        # behind a key origin, which is not where it may be nested
        if rest.startswith("musig("):
            raise BTClibValueError("musig() cannot be nested inside a key origin")
        _assert_not_miniscript(rest[: rest.index("(")])
        raise BTClibValueError("not a key expression")


def _split_wildcard(steps: list[str]) -> tuple[list[str], int | None, str]:
    """Split the final `/*` step off a path: its offset, and its symbol."""
    if steps and steps[-1] in ("*", "*'", "*h"):
        offset = 0 if steps[-1] == "*" else _HARDENED_OFFSET
        return steps[:-1], offset, steps[-1][1:]
    return steps, None, ""


def _fixed_pub_key(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex or WIF key, and whether x-only.

    A hex key is x-only when it was written in 32 bytes, and a WIF when it
    sits where only an x-only key is written: it has no spelling of its
    own to echo, so what is written back is the spelling the position
    takes. Bitcoin Core makes the same distinction with one bool per key
    -- `false` for a hex key it read whole, `ctx == ParseScriptContext::
    P2TR` for a private one -- which is what makes its ``tr(WIF)`` and
    ``rawtr(WIF)`` vectors come back in 32 bytes and not 33.
    """
    if _HEX.fullmatch(key):
        return _pub_key_from_hex(key, x_only=x_only)
    # what is left is a WIF, and pub_keyinfo_from_key answers both for it
    # and for characters that are no key expression at all
    try:
        return pub_keyinfo_from_key(key)[0], x_only
    except (TypeError, ValueError) as e:
        raise BTClibValueError("invalid key expression") from e


def _musig_der_path(suffix: str) -> tuple[tuple[int, ...], int | None]:
    """Return the path and wildcard a ``musig()`` derives the aggregate by.

    Every one of BIP390's rules about it is a refusal here: no hardened
    step and no hardened wildcard, an aggregate key having no private half
    to take either with, which is BIP328's own restriction.
    """
    if not suffix:
        return (), None
    if not suffix.startswith("/"):
        raise BTClibValueError(f"not a musig() derivation path: {suffix}")
    steps, wildcard, wildcard_hardening = _split_wildcard(suffix[1:].split("/"))
    if wildcard_hardening:
        raise BTClibValueError("musig() cannot have a hardened wildcard")
    der_path = _der_path("/".join(steps))
    if any(index >= _HARDENED_OFFSET for index in der_path):
        raise BTClibValueError("musig() cannot have hardened derivation steps")
    return tuple(der_path), wildcard


def _parse_musig(expression: str, prv_keys: dict[str, str]) -> KeyExpression:
    """Return the KeyExpression of a BIP390 ``musig()`` expression.

    The participants are KEY expressions read as any other key in a
    ``tr()`` is, except that none of them may be x-only: MuSig2
    aggregation is over points, so it needs the evenness byte an x-only
    spelling drops -- which is Bitcoin Core's rule too, its own parse
    context allowing 32-byte keys under ``tr()`` and not under
    ``musig()``.

    Derivation on the aggregate key costs three further conditions, all
    BIP390's: every participant an extended key, none of them ranged, and
    no hardened step. The first two are what make one aggregate key per
    index well defined -- with both sides ranged there would be two
    indexes and one wildcard to read them from.
    """
    close = expression.rfind(")")
    inner = expression[len("musig(") : close]
    arguments = _split_arguments(inner)
    if arguments == [""]:
        raise BTClibValueError("musig() takes at least one key")
    try:
        participants = tuple(
            _parse_key(key, prv_keys, compressed=True) for key in arguments
        )
    # which of several participants was wrong is half the answer, and the
    # inner message names neither the function nor the position. Bitcoin
    # Core prefixes its own the same way, "musig(): ..."
    except BTClibValueError as e:
        raise BTClibValueError(f"musig(): {e}") from e
    der_path, wildcard = _musig_der_path(expression[close + 1 :])
    if der_path or wildcard is not None:
        if any(not key.xkey for key in participants):
            err_msg = "musig() derivation requires every participant to be extended"
            raise BTClibValueError(err_msg)
        if any(key.is_ranged for key in participants):
            err_msg = "musig() cannot have a ranged participant and derivation too"
            raise BTClibValueError(err_msg)
    return KeyExpression(
        participants=participants, der_path=der_path, wildcard=wildcard
    )


def _parse_key(
    expression: str,
    prv_keys: dict[str, str],
    *,
    x_only: bool = False,
    compressed: bool = False,
    musig_allowed: bool = False,
) -> KeyExpression:
    """Return the KeyExpression of a BIP380 KEY expression.

    Never echo the key in an error message: a KEY expression is a WIF or
    an xprv as often as it is a public key, and an error message ends up
    in logs and in bug reports.

    The hardening symbol is the last one the expression used, read in the
    order it is written: the origin's path, then the key's, then the
    wildcard. A fixed key hardens nothing and keeps the default, there
    being no step of it to write.

    A ``musig()`` is read before the key origin and not after it, which is
    Bitcoin Core's order and where BIP390's "cannot be nested" comes from:
    the expression is a musig one or it is not, so an origin in front of it
    is not a musig expression with an origin -- it is a key that is no key.
    """
    if expression.startswith("musig("):
        _assert_musig_allowed(musig_allowed=musig_allowed)
        return _parse_musig(expression, prv_keys)
    origin, origin_hardening, rest = _origin_and_rest(expression)
    _assert_key_characters(rest)
    key, separator, path = rest.partition("/")
    if _is_extended_key(key):
        steps, wildcard, wildcard_hardening = _split_wildcard(
            path.split("/") if separator else []
        )
        der_path = "/".join(steps)
        hardening = origin_hardening
        for symbol in (_hardening(der_path), wildcard_hardening):
            hardening = symbol or hardening
        return KeyExpression(
            origin=origin,
            xkey=_neutered(key, prv_keys),
            der_path=tuple(_der_path(der_path)),
            wildcard=wildcard,
            hardening=hardening or _HARDENING,
        )
    if separator:
        raise BTClibValueError("derivation path after a key that cannot derive")
    pub_key, was_x_only = _fixed_pub_key(key, x_only=x_only)
    key_expression = KeyExpression(
        origin=origin,
        pub_key=pub_key,
        x_only=was_x_only,
        hardening=origin_hardening or _HARDENING,
    )
    if compressed and not key_expression.is_compressed:
        raise BTClibValueError("uncompressed public keys are not allowed here")
    return key_expression


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


def _parse_tree(expression: str, prv_keys: dict[str, str]) -> DescriptorTree:
    """Return the script tree of a BIP386 TREE expression."""
    if expression.startswith("{"):
        if not expression.endswith("}"):
            raise BTClibValueError(f"unbalanced braces: {expression}")
        branches = _split_arguments(expression[1:-1])
        if len(branches) != 2:
            err_msg = f"a tr() branch takes two subtrees, {len(branches)} given"
            raise BTClibValueError(err_msg)
        return (
            _parse_tree(branches[0], prv_keys),
            _parse_tree(branches[1], prv_keys),
        )
    name, arguments = _split_function(expression)
    _assert_not_miniscript(name)
    args = _split_arguments(arguments)
    if name in _TREE_FUNCTIONS:
        return _parse_multi_a(name, args, prv_keys)
    if name == "musig":
        # allowed inside tr(), and as a key rather than as a leaf: a leaf
        # is a script, and what a musig() aggregates to is one key of one
        err_msg = "musig() is a key expression: pk(musig(...)) is the leaf"
        raise BTClibValueError(err_msg)
    if name in _PARSERS:
        # a SCRIPT function where a leaf is expected: a position rule and
        # not something a later release adds, which is what the position
        # table says and Bitcoin Core's own message says too. ``pk()``
        # allows tr() among its positions and falls through to be read
        _assert_position(name, _P2TR, _PARSERS[name][0])
    if name != "pk":
        raise BTClibValueError(f"unknown descriptor function: {name}()")
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
    return context in (_P2WSH, _P2TR)


def _parse_pk(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "pk"),
        prv_keys,
        x_only=context == _P2TR,
        compressed=_no_uncompressed(context),
    )
    return PkDescriptor(key, network=network)


def _parse_pkh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "pkh"), prv_keys, compressed=_no_uncompressed(context)
    )
    return PkhDescriptor(key, network=network)


def _parse_wpkh(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    key = _parse_key(_one_argument(args, "wpkh"), prv_keys, compressed=True)
    return WpkhDescriptor(key, network=network)


def _parse_combo(
    args: list[str], context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    return ComboDescriptor(
        _parse_key(_one_argument(args, "combo"), prv_keys), network=network
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
        _parse_key(key, prv_keys, compressed=_no_uncompressed(context))
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
    tree = None if len(args) == 1 else _parse_tree(args[1], prv_keys)
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


def _parse_expression(
    expression: str, context: str, network: str, prv_keys: dict[str, str]
) -> Descriptor:
    """Return the Descriptor of a SCRIPT expression, in its context."""
    name, arguments = _split_function(expression)
    _assert_not_miniscript(name)
    if name == "musig":
        # a key expression where a SCRIPT one is expected: BIP390's own
        # invalid vectors write it as sh(musig()) and wsh(musig()), and
        # what is wrong with both is the position rather than the word
        _assert_musig_allowed(musig_allowed=False)
    if name in _TREE_FUNCTIONS:
        # a tree leaf and no SCRIPT expression, so reaching this is the
        # position rule of BIP387 being broken: `_assert_position` says
        # which position it was, where "unknown function" would say the
        # language has no such word
        _assert_position(name, context, (_P2TR,))
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
    """Return the Descriptor of a descriptor string, checksum verified."""
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
        xkey=xpub_from_xprv(derive(xprv, prefix)),
        der_path=key.der_path[last:],
        hardening=_HARDENING,
    )


def _normalized(value: object, prv_keys: PrvKeys | None) -> object:
    """Return one field of a descriptor with every key in it normalized."""
    if isinstance(value, KeyExpression):
        return _normalized_key(value, prv_keys)
    if isinstance(value, MultiA):
        return replace(
            value, keys=tuple(_normalized_key(k, prv_keys) for k in value.keys)
        )
    if isinstance(value, Descriptor):
        return normalized(value, prv_keys)
    if isinstance(value, tuple):
        return tuple(_normalized(item, prv_keys) for item in value)
    return value


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
    changed: dict[str, Any] = {
        field.name: _normalized(getattr(descriptor, field.name), prv_keys)
        for field in fields(descriptor)
    }
    # `replace` is what keeps this one function rather than a method per
    # fragment: every field is walked, so a field added later carries its
    # keys through here by default
    return replace(descriptor, **changed)


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
    derived = derive(xkey, _indexes_left_to_derive(xkey, indexes), version)
    return xpub_from_xprv(derived) if xkey.is_private else derived


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
    if not isinstance(xkey, BIP32KeyData):
        xkey = BIP32KeyData.b58decode(xkey)

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
