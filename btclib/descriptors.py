#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Output descriptors: the checksum, the parser, and the scripts.

A descriptor says which scripts a wallet owns, in one line of text. This
module reads that line and answers with the scripts, which is the half of
a descriptor implementation the receiving side needs: `parse` returns a
`Descriptor`, and `Descriptor.script_pub_keys` returns what the descriptor
pays to at an index. The other half, satisfying a script -- descriptor
plus signatures to a witness or a scriptSig -- is not here; the fragment
classes below are one per grammar function so that it has somewhere to go
(issue #186).

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
from collections.abc import Callable
from dataclasses import dataclass

from btclib.alias import ScriptList, TaprootScriptTree
from btclib.bip32.bip32 import BIP32KeyData, derive
from btclib.bip32.der_path import int_from_index_str
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.script.script_pub_key import ScriptPubKey
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

    def script_pub_keys(self, index: int = 0) -> list[ScriptPubKey]:
        """Return the scripts the descriptor describes at `index`.

        A list because ``combo()`` is a set of scripts and not one
        script; every other fragment answers with exactly one.
        """
        if not 0 <= index < 0x80000000:
            raise BTClibValueError(f"invalid derivation index: {index}")
        if index and not self.is_ranged:
            err_msg = f"not a ranged descriptor: no script at index {index}"
            raise BTClibValueError(err_msg)
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


@dataclass(frozen=True)
class PkDescriptor(Descriptor):
    """``pk(KEY)``: a P2PK output, BIP 381."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2pk(self.key.sec(index, self.network)).script]


@dataclass(frozen=True)
class PkhDescriptor(Descriptor):
    """``pkh(KEY)``: a P2PKH output, BIP 381."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2pkh(self.key.sec(index, self.network)).script]


@dataclass(frozen=True)
class WpkhDescriptor(Descriptor):
    """``wpkh(KEY)``: a P2WPKH output, BIP 382."""

    key: KeyExpression

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return (self.key,)

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2wpkh(self.key.sec(index, self.network)).script]


@dataclass(frozen=True)
class ShDescriptor(Descriptor):
    """``sh(SCRIPT)``: the argument, P2SH-embedded, BIP 381."""

    inner: Descriptor

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return self.inner.key_expressions

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2sh(self.inner.redeem_script(index)).script]


@dataclass(frozen=True)
class WshDescriptor(Descriptor):
    """``wsh(SCRIPT)``: the argument, P2WSH-embedded, BIP 382."""

    inner: Descriptor

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return self.inner.key_expressions

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.p2wsh(self.inner.redeem_script(index)).script]


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
        return self.keys

    def _scripts(self, index: int) -> list[bytes]:
        pub_keys = [key.sec(index, self.network) for key in self.keys]
        script_pub_key = ScriptPubKey.p2ms(
            self.threshold, pub_keys, self.network, lexicographic_sorting=self.sort
        )
        return [script_pub_key.script]


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


@dataclass(frozen=True)
class AddrDescriptor(Descriptor):
    """``addr(ADDR)``: the script the address expands to, BIP 385."""

    addr: str

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return ()

    def _scripts(self, index: int) -> list[bytes]:
        return [ScriptPubKey.from_address(self.addr).script]


@dataclass(frozen=True)
class RawDescriptor(Descriptor):
    """``raw(HEX)``: the script those bytes are, BIP 385."""

    script: bytes

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        return ()

    def _scripts(self, index: int) -> list[bytes]:
        return [self.script]


@dataclass(frozen=True)
class TrDescriptor(Descriptor):
    """``tr(KEY)`` or ``tr(KEY,TREE)``: a P2TR output, BIP 386."""

    internal_key: KeyExpression
    tree: DescriptorTree | None = None

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
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
