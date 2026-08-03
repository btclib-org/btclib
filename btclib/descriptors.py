#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
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
`psbt.finalize_psbt` does have one and does check, and builds the same
bytes from a psbt carrying the same signatures.

`update_psbt` is the third answer, and the one for a spend the signers
do not make all at once: BIP 174's Updater, writing the scripts and the
key origins into a psbt input, for signers to fill in at their own pace
and `psbt.finalize_psbt` to assemble. This module imports `psbt` for it
and nothing there imports back, which is the direction of the layering:
a psbt is a transaction being built, and a descriptor is what a wallet
knows about the outputs it holds.

BIP 380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki

The grammar read is BIP 380 to BIP 386 and BIP 389, minus miniscript:

- ``pk``, ``pkh``, ``wpkh``, ``combo`` (BIP 381, BIP 382, BIP 384)
- ``sh``, ``wsh``, including ``sh(wpkh())`` and ``sh(wsh())``
- ``multi``, ``sortedmulti`` (BIP 383)
- ``addr``, ``raw`` (BIP 385)
- ``tr``, with a key path and a script tree of ``pk()`` leaves (BIP 386)
- key expressions: hex public keys (compressed, uncompressed and, inside
  ``tr()``, x-only), WIF private keys, xpub/xprv with a derivation path,
  key origin, ``/*`` and ``/*h`` wildcards, both ``h`` and ``'`` hardened
  markers
- the ``<a;b>`` multipath form of BIP 389, through `multipath_descriptors`

What raises NotImplementedError, rather than being read wrong: every
miniscript expression, which is issue #187; and ``multi_a``,
``sortedmulti_a``, ``rawtr`` and ``musig``, which are BIP 387, BIP 386
and BIP 390 and belong with the work that adds them.

The network is a parameter of `parse` and not part of a descriptor: a
descriptor names keys and scripts, and the same one means something on
any chain, which is why Bitcoin Core takes the chain from its own context
too. ``addr()`` is the exception, an address carrying the network in its
own prefix.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import cast

from btclib.alias import Octets, ScriptList, TaprootScriptTree
from btclib.bip32.bip32 import BIP32KeyData, derive
from btclib.bip32.der_path import int_from_index_str
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_in import PsbtIn
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import input_script_sig, leaf_hash, tree_helper
from btclib.script.witness import Witness
from btclib.to_pub_key import point_from_pub_key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets

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


def descriptor_checksum(descriptor: str) -> str:
    """Compute the descriptor checksum."""
    symbols = [*__descsum_expand(descriptor), 0, 0, 0, 0, 0, 0, 0, 0]
    checksum = __descsum_polymod(symbols) ^ 1
    return "".join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def strip_checksum(descriptor: str) -> str:
    """Return the descriptor without its checksum, verifying a present one.

    A descriptor without one comes back unchanged: the checksum is
    optional in the language, and only some of Bitcoin Core's RPCs
    require it. What is never accepted is a checksum that does not match,
    which is what the eight characters are there for.
    """
    body, separator, checksum = descriptor.partition("#")
    if "#" in checksum:
        raise BTClibValueError(f"more than one '#' in the descriptor: {descriptor}")
    # computed before the comparison, and whether or not there is one to
    # compare against: it is also what refuses a character outside
    # INPUT_CHARSET, which is an error in a descriptor with no checksum
    expected = descriptor_checksum(body)
    if separator and checksum != expected:
        err_msg = f"invalid descriptor checksum: {checksum}, {expected} expected"
        raise BTClibValueError(err_msg)
    return body


def add_checksum(descriptor: str) -> str:
    """Return the descriptor with its checksum, verifying a present one."""
    body = strip_checksum(descriptor)
    return f"{body}#{descriptor_checksum(body)}"


def descriptor_from_address(address: str) -> str:
    """Return the addr() descriptor of the address, checksummed."""
    return add_checksum(f"addr({address})")


# the tapscript leaf version, which is the only one a BIP 386 tree has
_TAPSCRIPT_LEAF_VERSION = 0xC0

# where a SCRIPT expression sits. BIP 381 to BIP 386 give each function a
# position rule -- sh() is top level only, wpkh() is top level or inside
# sh(), and so on -- so the context is an argument of the parser, and
# these strings are what its error messages say
_TOP = "top level"
_P2SH = "sh()"
_P2WSH = "wsh()"
_P2TR = "tr()"

# BIP 379 fragments that are miniscript and nothing else. pk, pkh and
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

# descriptor functions read as such and refused rather than guessed at:
# each is a specification of its own, and a script derived wrong is an
# address that loses money
_UNIMPLEMENTED = {
    "multi_a": "BIP 387",
    "sortedmulti_a": "BIP 387",
    "rawtr": "BIP 386",
    "musig": "BIP 390",
}

_FINGERPRINT = re.compile("[0-9a-fA-F]{8}")
_DERIVATION_INDEX = re.compile("[0-9]+[h']?")
_HEX = re.compile("[0-9a-fA-F]*")
_THRESHOLD = re.compile("[0-9]+")
# the BIP 389 multipath step, brackets included: re.split hands back what
# it split on when the pattern captures it
_MULTIPATH_STEP = re.compile("(<[^<>]*>)")


@dataclass(frozen=True)
class KeyExpression:
    """A BIP 380 KEY expression: an origin, a key, a derivation path.

    Either `pub_key` is the key the descriptor fixes, in SEC bytes, or
    `xkey` is the extended key that `der_path` and `wildcard` derive
    from. An x-only key is held as its even-y SEC form, which is what
    BIP 340 says those 32 bytes mean, so that everything downstream sees
    one representation of a public key.

    `origin` never changes the script. It says which master key and which
    path the key came from, which is what a hardware signer needs and
    what BIP 174 carries in a PSBT.
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

    @property
    def is_ranged(self) -> bool:
        """Answer whether the key has a wildcard to derive at an index."""
        return self.wildcard is not None

    @property
    def is_compressed(self) -> bool:
        """Return False for an uncompressed SEC public key, True otherwise.

        An extended key is compressed by construction: BIP 32 has no
        uncompressed serialization.
        """
        return self.pub_key is None or len(self.pub_key) == 33

    def sec(self, index: int = 0, network: str = "mainnet") -> bytes:
        """Return the SEC public key bytes, derived at `index` if ranged."""
        if self.pub_key is not None:
            return self.pub_key
        der_path = list(self.der_path)
        if self.wildcard is not None:
            der_path.append(self.wildcard + index)
        return pub_keyinfo_from_key(derive(self.xkey, der_path), network)[0]


# a tr() script tree: a `pk()` leaf, or a branch of two subtrees. The
# leaves are KEY expressions and not scripts because a ranged descriptor
# has no script until an index is given
DescriptorTree = KeyExpression | tuple["DescriptorTree", "DescriptorTree"]


def _tree_keys(tree: DescriptorTree) -> tuple[KeyExpression, ...]:
    if isinstance(tree, KeyExpression):
        return (tree,)
    return _tree_keys(tree[0]) + _tree_keys(tree[1])


def _taproot_script_tree(
    tree: DescriptorTree, index: int, network: str
) -> TaprootScriptTree:
    if isinstance(tree, KeyExpression):
        script: ScriptList = [tree.sec(index, network)[1:], "OP_CHECKSIG"]
        return [(_TAPSCRIPT_LEAF_VERSION, script)]
    return [
        _taproot_script_tree(tree[0], index, network),
        _taproot_script_tree(tree[1], index, network),
    ]


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
    descriptor holds, and what BIP 174 carries is the path down to the
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
    def _scripts(self, index: int) -> list[bytes]:
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

    def script_pub_keys(self, index: int = 0) -> list[ScriptPubKey]:
        """Return the scripts the descriptor describes at `index`.

        A list because ``combo()`` is a set of scripts and not one
        script; every other fragment answers with exactly one.
        """
        self._assert_index(index)
        return [ScriptPubKey(script, self.network) for script in self._scripts(index)]

    def script_pub_key(self, index: int = 0) -> ScriptPubKey:
        """Return the one script the descriptor describes at `index`."""
        script_pub_keys = self.script_pub_keys(index)
        if len(script_pub_keys) != 1:
            err_msg = f"{len(script_pub_keys)} scripts: use script_pub_keys instead"
            raise BTClibValueError(err_msg)
        return script_pub_keys[0]

    def redeem_script(self, index: int = 0) -> bytes:
        """Return the script that ``sh()`` or ``wsh()`` embeds this one as."""
        return self.script_pub_key(index).script

    def address(self, index: int = 0) -> str:
        """Return the address of the script at `index`, if it has one."""
        return self.script_pub_key(index).address

    def addresses(self, index: int = 0) -> list[str]:
        """Return the address of each script at `index`, empty where none."""
        return [
            script_pub_key.address for script_pub_key in self.script_pub_keys(index)
        ]

    def _stack(self, signatures: Mapping[bytes, bytes], index: int) -> list[bytes]:
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
        self, signatures: Mapping[Octets, Octets], index: int = 0
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
        empty script_sig BIP 141 requires.

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
        )

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Return the satisfaction, the mapping being already in bytes.

        The legacy answer -- the stack pushed into the script_sig, and
        no witness -- which is what ``pk()``, ``pkh()`` and ``multi()``
        are spent with; the fragments spent otherwise override it.
        Separate from `satisfy` so that a wrapper can satisfy its
        argument without normalizing the same mapping a second time.
        """
        return serialize(cast(ScriptList, self._stack(signatures, index))), Witness()

    def update_psbt(self, psbt: Psbt, vin_i: int, index: int = 0) -> Psbt:
        """Return the psbt with input `vin_i` told what the descriptor knows.

        BIP 174's Updater, for the one input this descriptor describes:
        the redeem script of a ``sh()``, the witness script of a
        ``wsh()``, the internal key, merkle root and leaf scripts of a
        ``tr()``, and the origin of every key that carries one -- which is
        what a hardware signer needs, and what `KeyExpression.origin` is
        kept for. `psbt.finalize_psbt` then assembles the same bytes
        `satisfy` does, from the signatures the signers filled in at
        their own pace: that pipeline is what a psbt is for, and what
        `satisfy` cannot answer, refusing a partial satisfaction rather
        than returning bytes that do not spend.

        A copy, the psbt handed in being left alone, and the fields of
        the copy mutated in place: `finalize_psbt` is the same
        construction, and BIP 174's roles read as steps that update a
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
        self._update(psbt.inputs[vin_i], index)
        psbt.assert_valid()
        return psbt

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Fill the key origins, which is what every fragment knows.

        And the whole of what ``pk()``, ``pkh()``, ``wpkh()`` and
        ``multi()`` know: their script is the script_pub_key, which the
        psbt has from the utxo rather than from here. The fragments that
        embed one of those add their scripts to this.

        The mapping is added to and not replaced: BIP 174 keys it by
        public key, so a psbt already carrying another signer's key keeps
        it, and this descriptor's entry wins for a key held by both.
        """
        psbt_in.hd_key_paths = {**psbt_in.hd_key_paths, **self._hd_key_paths(index)}

    def _hd_key_paths(self, index: int) -> dict[bytes, BIP32KeyOrigin]:
        """Return the origin of each key that has one, keyed by public key.

        A key with no origin is skipped and not refused: a descriptor may
        name one key as plain hex and the next with an origin, the field
        is keyed by key, and what is missing is one entry of it.
        """
        hd_key_paths: dict[bytes, BIP32KeyOrigin] = {}
        for key in self.key_expressions:
            origin = _derived_origin(key, index)
            if origin is not None:
                hd_key_paths[key.sec(index, self.network)] = origin
        return hd_key_paths


@dataclass(frozen=True)
class PkDescriptor(Descriptor):
    """``pk(KEY)``: a P2PK output, BIP 381."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2pk(self.key.sec(index, self.network)).script]

    def _stack(self, signatures: Mapping[bytes, bytes], index: int) -> list[bytes]:
        # the key is in the script already, so the signature is the whole
        # of what spending a p2pk output takes
        return [_required_signature(signatures, self.key.sec(index, self.network))]


@dataclass(frozen=True)
class PkhDescriptor(Descriptor):
    """``pkh(KEY)``: a P2PKH output, BIP 381."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2pkh(self.key.sec(index, self.network)).script]

    def _stack(self, signatures: Mapping[bytes, bytes], index: int) -> list[bytes]:
        # what the output commits to is the hash of the key, so the key
        # goes on the stack for the script to hash for itself
        sec = self.key.sec(index, self.network)
        return [_required_signature(signatures, sec), sec]


@dataclass(frozen=True)
class WpkhDescriptor(Descriptor):
    """``wpkh(KEY)``: a P2WPKH output, BIP 382."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2wpkh(self.key.sec(index, self.network)).script]

    def _stack(self, signatures: Mapping[bytes, bytes], index: int) -> list[bytes]:
        # the witness of a p2wpkh spend is what the script_sig of a p2pkh
        # one is, BIP 143 having moved it and changed nothing else
        sec = self.key.sec(index, self.network)
        return [_required_signature(signatures, sec), sec]

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        # the empty script_sig of BIP 141, which is not the same as an
        # empty push: btclib's own engine refuses a native segwit input
        # whose script_sig is there at all (issue #249). A sh(wpkh())
        # gets its one push from the sh() above
        return b"", Witness(self._stack(signatures, index))


@dataclass(frozen=True)
class ShDescriptor(Descriptor):
    """``sh(SCRIPT)``: the argument, P2SH-embedded, BIP 381."""

    inner: Descriptor

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2sh(self.inner.redeem_script(index)).script]

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
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
        script_sig, witness = self.inner._satisfy(signatures, index)
        redeem_script = self.inner.redeem_script(index)
        return script_sig + serialize(cast(ScriptList, [redeem_script])), witness

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Fill the redeem script, and let the argument fill its own fields.

        Delegated rather than dispatched on: the argument of a
        ``sh(wsh())`` is what knows there is a witness script below the
        redeem script, and it is the same method that fills it for a
        native ``wsh()``.
        """
        self.inner._update(psbt_in, index)
        psbt_in.redeem_script = self.inner.redeem_script(index)


@dataclass(frozen=True)
class WshDescriptor(Descriptor):
    """``wsh(SCRIPT)``: the argument, P2WSH-embedded, BIP 382."""

    inner: Descriptor

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the wrapped SCRIPT's KEY expressions."""
        return self.inner.key_expressions

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2wsh(self.inner.redeem_script(index)).script]

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Return the witness of a p2wsh spend: the stack, then the script.

        The argument's stack and not its satisfaction, which would be
        those same elements serialized as a script_sig: a witness is a
        stack already, so BIP 141 puts them in it one by one and the
        witness script last.
        """
        stack = self.inner._stack(signatures, index)
        return b"", Witness([*stack, self.inner.redeem_script(index)])

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Fill the witness script; the redeem script is ``sh()``'s to fill.

        Which is the whole difference between a native ``wsh()`` and a
        wrapped one, in the psbt as in the spend: the same witness script,
        and a redeem script only where something wraps it.
        """
        self.inner._update(psbt_in, index)
        psbt_in.witness_script = self.inner.redeem_script(index)


@dataclass(frozen=True)
class MultiDescriptor(Descriptor):
    """``multi(k,KEY,...)`` and ``sortedmulti(k,KEY,...)``, BIP 383."""

    threshold: int
    keys: tuple[KeyExpression, ...]
    # BIP 67 ordering, which is the whole difference between the two
    # functions: the keys of a sortedmulti() are sorted in the script, so
    # the participants need not agree on an order to agree on an address
    sort: bool = False

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the KEY expressions, in descriptor order."""
        return self.keys

    def _pub_keys(self, index: int) -> list[bytes]:
        """Return the keys in the order the script holds them.

        `sorted` and not `p2ms`'s own `lexicographic_sorting`, which
        sorts identically: the order is also the order the signatures of
        a satisfaction go in, so one of the two has somewhere to ask for
        it rather than a second copy of the rule.
        """
        pub_keys = [key.sec(index, self.network) for key in self.keys]
        return sorted(pub_keys) if self.sort else pub_keys

    def _scripts(self, index: int) -> list[bytes]:
        script_pub_key = ScriptPubKey.p2ms(
            self.threshold,
            self._pub_keys(index),
            self.network,
            lexicographic_sorting=False,
        )
        return [script_pub_key.script]

    def _stack(self, signatures: Mapping[bytes, bytes], index: int) -> list[bytes]:
        """Return the dummy element and `threshold` signatures, in key order.

        OP_CHECKMULTISIG walks the signatures and the keys in one pass
        and never goes back, so the signatures have to be in the order
        the script holds the keys in. More signatures than the threshold
        is not an error and not all of them are used: the script pops
        exactly as many as it was built for, and the rest are the other
        keys of the same descriptor having signed too.

        The first element is the one OP_CHECKMULTISIG pops without
        reading, which BIP 147 requires to be the empty push.
        """
        offered = [
            (sec, _offered_signature(signatures, sec)) for sec in self._pub_keys(index)
        ]
        found = [signature for _, signature in offered if signature is not None]
        if len(found) < self.threshold:
            missing = ", ".join(sec.hex() for sec, sig in offered if sig is None)
            err_msg = f"{len(found)} signatures of {self.threshold}, missing {missing}"
            raise BTClibValueError(err_msg)
        return [b"", *found[: self.threshold]]


@dataclass(frozen=True)
class ComboDescriptor(Descriptor):
    """``combo(KEY)``: the scripts an old wallet would have used, BIP 384.

    P2PK and P2PKH, plus P2WPKH and P2SH-P2WPKH when the key is
    compressed -- an uncompressed key is not allowed in a witness
    program.
    """

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the one KEY expression, as the base class's tuple."""
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        pub_key = self.key.sec(index, self.network)
        scripts = [
            ScriptPubKey.p2pk(pub_key).script,
            ScriptPubKey.p2pkh(pub_key).script,
        ]
        if self.key.is_compressed:
            p2wpkh = ScriptPubKey.p2wpkh(pub_key).script
            scripts += [p2wpkh, ScriptPubKey.p2sh(p2wpkh).script]
        return scripts

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Refuse: four scripts, and each of them spent differently.

        Which one is being spent is a question the caller answers, by
        satisfying the descriptor of that script -- ``pk()``, ``pkh()``,
        ``wpkh()`` or ``sh(wpkh())`` of the same key -- and it is a
        question `script_pub_keys` can leave open where this cannot.
        """
        err_msg = "combo() is four scripts: satisfy the one being spent"
        raise BTClibValueError(err_msg)

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
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
    """``addr(ADDR)``: the script the address expands to, BIP 385."""

    addr: str

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.from_address(self.addr).script]

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Refuse: an address names a script and not what spends it.

        BTClibValueError and not the NotImplementedError the parser
        raises for what a later release adds: there is nothing to add,
        an address being a commitment to a key or a script that the
        descriptor does not carry.
        """
        raise BTClibValueError("addr() cannot be satisfied: it holds no key")

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Refuse: there is nothing of an address to write into an input.

        No key, so no origin; no script below the address, so no redeem or
        witness script. Returning the input untouched would be an Updater
        that ran and a caller told it had been updated.
        """
        raise BTClibValueError("addr() cannot update a psbt: it holds no key")


@dataclass(frozen=True)
class RawDescriptor(Descriptor):
    """``raw(HEX)``: the script those bytes are, BIP 385."""

    script: bytes

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return no KEY expression, the descriptor fixing none."""
        return ()

    def _scripts(self, index: int) -> list[bytes]:
        return [self.script]

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Refuse: a script and no key expression to satisfy it with.

        What ``raw()`` holds is bytes, which say nothing about which key
        signs for them even where they happen to be a script this module
        can otherwise read; the descriptor of that script is what is
        satisfiable.
        """
        raise BTClibValueError("raw() cannot be satisfied: it holds no key")

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Refuse, for the reason ``addr()`` does: bytes hold no key origin.

        Those bytes may be the script an input spends, and they are then
        its script_pub_key, which the psbt has from the utxo; what a
        descriptor is asked here is what the utxo does not say.
        """
        raise BTClibValueError("raw() cannot update a psbt: it holds no key")


@dataclass(frozen=True)
class TrDescriptor(Descriptor):
    """``tr(KEY)`` or ``tr(KEY,TREE)``: a P2TR output, BIP 386."""

    internal_key: KeyExpression
    tree: DescriptorTree | None = None

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return the internal key and every leaf key, in tree order."""
        if self.tree is None:
            return (self.internal_key,)
        return (self.internal_key, *_tree_keys(self.tree))

    def _scripts(self, index: int) -> list[bytes]:
        script_tree = (
            None
            if self.tree is None
            else _taproot_script_tree(self.tree, index, self.network)
        )
        internal_key = self.internal_key.sec(index, self.network)
        return [ScriptPubKey.p2tr(internal_key, script_tree).script]

    def _leaf(
        self, script_tree: TaprootScriptTree, index: int, leaf: int
    ) -> tuple[bytes, bytes]:
        """Return one leaf's serialized script and its control block.

        The one place either is built, a spend and an update of the same
        leaf wanting the same bytes. The tree is a parameter because both
        callers have computed it already -- and because a ``tr()`` with no
        tree has no leaf, which they answer for themselves.
        """
        internal_key = self.internal_key.sec(index, self.network)
        script, control_block = input_script_sig(internal_key, script_tree, leaf)
        return serialize(script), control_block

    def taproot_merkle_root(self, index: int = 0) -> bytes:
        """Return the root the output key commits to, b"" where there is none.

        BIP 371's PSBT_IN_TAP_MERKLE_ROOT, and empty is how that field
        says "key path only": a ``tr(KEY)`` tweaks its internal key with
        no tree, which is not the same as tweaking it with an empty one.
        """
        self._assert_index(index)
        if self.tree is None:
            return b""
        return tree_helper(_taproot_script_tree(self.tree, index, self.network))[1]

    def taproot_leaf_scripts(self, index: int = 0) -> dict[bytes, tuple[bytes, int]]:
        """Return every leaf script and its version, keyed by control block.

        The shape of BIP 371's PSBT_IN_TAP_LEAF_SCRIPT, and the field an
        Updater is needed for rather than convenient: a control block
        holds the merkle path from its leaf to the root, which is the
        whole tree seen from that leaf, and a psbt carrying one leaf's
        script has no way to compute another's.
        """
        self._assert_index(index)
        if self.tree is None:
            return {}
        script_tree = _taproot_script_tree(self.tree, index, self.network)
        leaf_scripts: dict[bytes, tuple[bytes, int]] = {}
        for leaf in range(len(_tree_keys(self.tree))):
            script, control_block = self._leaf(script_tree, index, leaf)
            leaf_scripts[control_block] = (script, _TAPSCRIPT_LEAF_VERSION)
        return leaf_scripts

    def _taproot_hd_key_paths(
        self, index: int
    ) -> dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]:
        """Return each key's origin and leaf hashes, keyed by x-only key.

        BIP 371 gives a taproot key a field of its own, keyed by the 32
        bytes a tapscript holds and carrying the tapleaf hash of every
        leaf the key appears in: none for a key that is only the internal
        one, no leaf committing to it, and one entry naming each of them
        for a key written into several, the field being keyed by key.

        Named once each: a key in two leaves of the same script is in two
        places of the tree and in one leaf of it, the tapleaf hash being
        of the script, and what a signer reads here is which scripts it
        has to sign for.
        """
        leaf_hashes: dict[bytes, list[bytes]] = {}
        for script, leaf_version in self.taproot_leaf_scripts(index).values():
            # a leaf of this module's own making is a push of the key and
            # OP_CHECKSIG, `pk()` being the only leaf BIP 386 reads here,
            # so the key is what the push holds
            hashes = leaf_hashes.setdefault(script[1:-1], [])
            if (hash_ := leaf_hash(leaf_version, script)) not in hashes:
                hashes.append(hash_)
        hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]] = {}
        for key in self.key_expressions:
            origin = _derived_origin(key, index)
            if origin is None:
                continue
            x_only = key.sec(index, self.network)[1:]
            hd_key_paths[x_only] = (leaf_hashes.get(x_only, []), origin)
        return hd_key_paths

    def _satisfy(
        self, signatures: Mapping[bytes, bytes], index: int
    ) -> tuple[bytes, Witness]:
        """Return the witness of a key path spend, or of a script path one.

        The key path whenever a signature for the internal key is
        offered, which is the preference Bitcoin Core's finalizer has:
        it is the cheaper spend and the one the output key commits to
        directly. That signature is one the *output* key verifies, the
        signer having tweaked the key it holds, and it is looked up
        under the internal key because that is the key the descriptor
        names.

        A script path witness is the signature, the leaf script and the
        control block, which is BIP 341's order. Both the parity bit and
        the merkle path in that control block are the descriptor's to
        compute, holding the whole tree as it does, where a psbt has to
        be handed them: it is the one thing satisfaction here knows that
        finalization there cannot work out.

        The script_sig is empty whichever path is taken: BIP 341 spends
        a witness v1 program with the witness alone.
        """
        internal_key = self.internal_key.sec(index, self.network)
        signature = _offered_signature(signatures, internal_key, x_only=True)
        if signature is not None:
            return b"", Witness([signature])
        if self.tree is None:
            raise BTClibValueError("no signature for the tr() internal key")
        script_tree = _taproot_script_tree(self.tree, index, self.network)
        # _tree_keys and taproot.tree_helper both walk the left subtree
        # before the right one, so the n-th key is the n-th leaf and the
        # number is the one input_script_sig takes
        for leaf, key in enumerate(_tree_keys(self.tree)):
            signature = _offered_signature(
                signatures, key.sec(index, self.network), x_only=True
            )
            if signature is not None:
                script, control_block = self._leaf(script_tree, index, leaf)
                return b"", Witness([signature, script, control_block])
        err_msg = "no signature for the tr() internal key or for any of its leaves"
        raise BTClibValueError(err_msg)

    def _update(self, psbt_in: PsbtIn, index: int) -> None:
        """Fill the four taproot fields: internal key, root, leaves, origins.

        This replaces the base method rather than adding to it: a taproot
        key origin belongs in `taproot_hd_key_paths`, keyed by the x-only
        key, and a 33-byte entry in `hd_key_paths` beside it would be the
        same key twice in two spellings, for a signer that signs with
        neither.
        """
        psbt_in.taproot_internal_key = self.internal_key.sec(index, self.network)[1:]
        psbt_in.taproot_merkle_root = self.taproot_merkle_root(index)
        psbt_in.taproot_leaf_scripts = {
            **psbt_in.taproot_leaf_scripts,
            **self.taproot_leaf_scripts(index),
        }
        psbt_in.taproot_hd_key_paths = {
            **psbt_in.taproot_hd_key_paths,
            **self._taproot_hd_key_paths(index),
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


def _assert_implemented(name: str) -> None:
    if ":" in name or name in _MINISCRIPT_FRAGMENTS:
        err_msg = f"miniscript is not implemented: {name} (issue #187)"
        raise NotImplementedError(err_msg)
    if name in _UNIMPLEMENTED:
        err_msg = f"{name}() is not implemented ({_UNIMPLEMENTED[name]})"
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
    """Return the indexes of a `/`-separated derivation path."""
    if not path:
        return []
    indexes = []
    for step in path.split("/"):
        if not _DERIVATION_INDEX.fullmatch(step):
            raise BTClibValueError(f"invalid derivation index: {step}")
        # int_from_index_str is what refuses 2**31 and above written
        # unhardened, there being no such BIP 32 index
        indexes.append(int_from_index_str(step))
    return indexes


def _key_origin(description: str) -> BIP32KeyOrigin:
    """Return the key origin of a `[fingerprint/path]` prefix."""
    fingerprint, _, path = description.partition("/")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise BTClibValueError(f"invalid key origin fingerprint: {fingerprint}")
    return BIP32KeyOrigin(fingerprint, _der_path(path))


def _pub_key_from_hex(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex key, and whether it was x-only."""
    length = len(key)
    if length == 64:
        if not x_only:
            raise BTClibValueError("x-only public keys are allowed inside tr() only")
        # the even-y lift of BIP 340, which is what an x-only key means
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


def _origin_and_rest(expression: str) -> tuple[BIP32KeyOrigin | None, str]:
    """Split the `[fingerprint/path]` prefix off a KEY expression."""
    if not expression.startswith("["):
        if "]" in expression:
            raise BTClibValueError("']' without the '[' that opens a key origin")
        return None, expression
    end = expression.find("]")
    if end < 0:
        raise BTClibValueError("missing ']' in the key origin")
    return _key_origin(expression[1:end]), expression[end + 1 :]


def _assert_key_characters(rest: str) -> None:
    """Refuse what a KEY expression cannot hold once the origin is off."""
    if "]" in rest:
        raise BTClibValueError("more than one ']' in a single key expression")
    if "<" in rest:
        err_msg = "multipath key expression: use multipath_descriptors first"
        raise BTClibValueError(err_msg)
    if "(" in rest:
        # the one KEY expression that is a function is BIP 390's musig(),
        # and a key nothing reads is not a key to guess at
        _assert_implemented(rest[: rest.index("(")])
        raise BTClibValueError("not a key expression")


def _split_wildcard(steps: list[str]) -> tuple[list[str], int | None]:
    """Split the final `/*` step, if any, off a derivation path."""
    if steps and steps[-1] in ("*", "*'", "*h"):
        return steps[:-1], 0 if steps[-1] == "*" else 0x80000000
    return steps, None


def _fixed_pub_key(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex or WIF key, and whether x-only."""
    if _HEX.fullmatch(key):
        return _pub_key_from_hex(key, x_only=x_only)
    # what is left is a WIF, and pub_keyinfo_from_key answers both for it
    # and for characters that are no key expression at all
    try:
        return pub_keyinfo_from_key(key)[0], False
    except (TypeError, ValueError) as e:
        raise BTClibValueError("invalid key expression") from e


def _parse_key(
    expression: str, *, x_only: bool = False, compressed: bool = False
) -> KeyExpression:
    """Return the KeyExpression of a BIP 380 KEY expression.

    Never echo the key in an error message: a KEY expression is a WIF or
    an xprv as often as it is a public key, and an error message ends up
    in logs and in bug reports.
    """
    origin, rest = _origin_and_rest(expression)
    _assert_key_characters(rest)
    key, separator, path = rest.partition("/")
    if _is_extended_key(key):
        steps, wildcard = _split_wildcard(path.split("/") if separator else [])
        return KeyExpression(
            origin=origin,
            xkey=key,
            der_path=tuple(_der_path("/".join(steps))),
            wildcard=wildcard,
        )
    if separator:
        raise BTClibValueError("derivation path after a key that cannot derive")
    pub_key, was_x_only = _fixed_pub_key(key, x_only=x_only)
    key_expression = KeyExpression(origin=origin, pub_key=pub_key, x_only=was_x_only)
    if compressed and not key_expression.is_compressed:
        raise BTClibValueError("uncompressed public keys are not allowed here")
    return key_expression


def _parse_tree(expression: str) -> DescriptorTree:
    """Return the script tree of a BIP 386 TREE expression."""
    if expression.startswith("{"):
        if not expression.endswith("}"):
            raise BTClibValueError(f"unbalanced braces: {expression}")
        branches = _split_arguments(expression[1:-1])
        if len(branches) != 2:
            err_msg = f"a tr() branch takes two subtrees, {len(branches)} given"
            raise BTClibValueError(err_msg)
        return (_parse_tree(branches[0]), _parse_tree(branches[1]))
    name, arguments = _split_function(expression)
    _assert_implemented(name)
    if name != "pk":
        raise NotImplementedError(f"{name}() inside tr() is not implemented")
    key = _one_argument(_split_arguments(arguments), name)
    return _parse_key(key, x_only=True, compressed=True)


# inside a witness program an uncompressed key is unspendable, so
# BIP 382 refuses one rather than describing a script nobody can spend;
# inside tr() the keys are x-only to begin with
def _no_uncompressed(context: str) -> bool:
    return context in (_P2WSH, _P2TR)


def _parse_pk(args: list[str], context: str, network: str) -> Descriptor:
    key = _parse_key(
        _one_argument(args, "pk"),
        x_only=context == _P2TR,
        compressed=_no_uncompressed(context),
    )
    return PkDescriptor(key, network=network)


def _parse_pkh(args: list[str], context: str, network: str) -> Descriptor:
    key = _parse_key(_one_argument(args, "pkh"), compressed=_no_uncompressed(context))
    return PkhDescriptor(key, network=network)


def _parse_wpkh(args: list[str], context: str, network: str) -> Descriptor:
    key = _parse_key(_one_argument(args, "wpkh"), compressed=True)
    return WpkhDescriptor(key, network=network)


def _parse_combo(args: list[str], context: str, network: str) -> Descriptor:
    return ComboDescriptor(_parse_key(_one_argument(args, "combo")), network=network)


def _parse_sh(args: list[str], context: str, network: str) -> Descriptor:
    inner = _parse_expression(_one_argument(args, "sh"), _P2SH, network)
    return ShDescriptor(inner, network=network)


def _parse_wsh(args: list[str], context: str, network: str) -> Descriptor:
    inner = _parse_expression(_one_argument(args, "wsh"), _P2WSH, network)
    return WshDescriptor(inner, network=network)


def _parse_multi(name: str, args: list[str], context: str, network: str) -> Descriptor:
    if len(args) < 2:
        raise BTClibValueError(f"{name}() takes a threshold and at least one key")
    if not _THRESHOLD.fullmatch(args[0]):
        raise BTClibValueError(f"invalid {name}() threshold: {args[0]}")
    keys = tuple(
        _parse_key(key, compressed=_no_uncompressed(context)) for key in args[1:]
    )
    return MultiDescriptor(
        int(args[0]), keys, sort=name == "sortedmulti", network=network
    )


def _parse_ordered_multi(args: list[str], context: str, network: str) -> Descriptor:
    return _parse_multi("multi", args, context, network)


def _parse_sorted_multi(args: list[str], context: str, network: str) -> Descriptor:
    return _parse_multi("sortedmulti", args, context, network)


def _parse_tr(args: list[str], context: str, network: str) -> Descriptor:
    if len(args) > 2:
        err_msg = f"tr() takes a key and at most one tree, {len(args)} given"
        raise BTClibValueError(err_msg)
    internal_key = _parse_key(args[0], x_only=True, compressed=True)
    tree = None if len(args) == 1 else _parse_tree(args[1])
    return TrDescriptor(internal_key, tree, network=network)


def _parse_addr(args: list[str], context: str, network: str) -> Descriptor:
    address = _one_argument(args, "addr")
    # the network of an addr() descriptor is the address's own: it is
    # written in the prefix, so a parameter could only contradict it
    return AddrDescriptor(address, network=ScriptPubKey.from_address(address).network)


def _parse_raw(args: list[str], context: str, network: str) -> Descriptor:
    hex_script = _one_argument(args, "raw")
    try:
        script = bytes_from_octets(hex_script)
    # bytes.fromhex raises a plain ValueError, and every other way of
    # writing a descriptor wrong raises a BTClibValueError
    except ValueError as e:
        raise BTClibValueError(f"raw() takes a hex script: {hex_script}") from e
    return RawDescriptor(script, network=network)


# every SCRIPT function, where BIP 381 to BIP 386 allow it, and what
# reads it. A table rather than a chain of comparisons because the
# position rule is the interesting half and belongs where it can be read
# beside the others
_PARSERS: dict[
    str, tuple[tuple[str, ...], Callable[[list[str], str, str], Descriptor]]
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
    "addr": ((_TOP,), _parse_addr),
    "raw": ((_TOP,), _parse_raw),
}


def _parse_expression(expression: str, context: str, network: str) -> Descriptor:
    """Return the Descriptor of a SCRIPT expression, in its context."""
    name, arguments = _split_function(expression)
    _assert_implemented(name)
    if name not in _PARSERS:
        raise BTClibValueError(f"unknown descriptor function: {name}()")
    allowed, parser = _PARSERS[name]
    _assert_position(name, context, allowed)
    return parser(_split_arguments(arguments), context, network)


def parse(descriptor: str, network: str = "mainnet") -> Descriptor:
    """Return the Descriptor of a descriptor string, checksum verified."""
    return _parse_expression(strip_checksum(descriptor), _TOP, network)


def multipath_descriptors(descriptor: str) -> list[str]:
    """Return the single-path descriptors of a BIP 389 multipath one.

    A descriptor with no ``<a;b>`` step is one descriptor, returned
    checksummed and otherwise unchanged. One with such steps is as many
    descriptors as a step has elements, the first taking the first
    element of every step, the second the second, and so on -- which is
    what makes the two-element form a receiving chain and a change chain.

    The expansion is textual, as BIP 389 defines it, and each result is a
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
