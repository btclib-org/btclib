# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A wallet whose output is a script no descriptor states: template, groups.

`DescriptorWallet` covers every wallet whose script is sayable in BIP380
to BIP390, and refuses the ones that are not -- correctly, and with
nothing to offer instead. This module is the something else. Multisig
wallets predating output descriptors are still holding coins, and their
scripts miss the language by a detail: a `<n> OP_CSV OP_DROP` where
miniscript writes `OP_CSV OP_VERIFY`, or a BIP67 sort applied to the
*derived* keys of a quorum, which `sortedmulti()` follows exactly and
which BIP379 has no fragment for inside a combinator. Both refusals are
right, and "right to refuse" is not "nothing to answer".

A `ScriptWallet` is three things and no more: a script **template**, the
key **groups** the template writes into it, and an **order** for the keys
of each group. That is enough to compute the script at a position, which
is enough for the two questions a wallet is for -- `address(branch,
index)` and `position_of(script_pub_key)`::

    wallet = ScriptWallet(
        [
            "OP_IF",
            KeyGroup(2, [xpub_a, xpub_b, xpub_c]),
            "OP_ELSE",
            push_int(144),
            "OP_CHECKSEQUENCEVERIFY",
            "OP_DROP",
            KeyGroup(1, [xpub_recovery]),
            "OP_ENDIF",
        ],
        script_type="p2wsh",
        order="derived",
    )

The template is a `script.serialize` command list with `KeyGroup` objects
among the commands -- a number in one is written with `script.push_int`,
which is the op code below 17 and the CScriptNum encoding above it, so
that a timelock of 16 blocks and one of 144 are written the same way --
and a group writes what OP_CHECKMULTISIG reads:
`k <key>... n OP_CHECKMULTISIG`, the keys being the ones derived at the
position -- or, with `verify=True`, `OP_CHECKMULTISIGVERIFY` in place of
that last opcode, which is the form a required quorum takes rather than
one left on the stack. So the template is Python objects and not text:
**there is no text format here, and no parser**. Inventing a second,
worse descriptor language is how this feature goes wrong, and a wallet
that cannot be written down cannot be mistaken for one that can be
handed to Bitcoin Core.

**No `from_script`.** A template is not recoverable from a script: the
bytes at one position say which keys are in it and not which account keys
derived them, so a class reading one back would be guessing, and guessing
is the parser this module refuses to have.
`DescriptorWallet.from_descriptor` is where a wallet written down in
BIP380's language is read.

**`descriptor(branch)` is the other direction, and it is a lift rather
than a conversion.** No shape is spelled out for it: the wallet derives
its own script at index 0, `miniscript.from_script` reads those bytes
back into the expression they are, each derived key is put back as the
KEY expression that produced it -- `[fingerprint/path]xpub/branch/*` --
and the text goes through `descriptors.parse`, so what comes back is the
descriptor a reader of that text gets and not an object of this module's
own making. A shape this file has never heard of therefore comes out
right, and the two shapes this class exists for come out not at all:
`NoDescriptorError` for the `OP_DROP` timelock, which is no miniscript,
and for a quorum ordered per index inside a combinator, which no ranged
expression covers. Nothing is guessed and nothing is approximated, which
is what the old "no conversion either way" was guarding against, and the
guard is now the check rather than the absence: the addresses the
descriptor derives are compared with the wallet's own before it is handed
back, so a lift that was not faithful is an exception and not a
descriptor.

**Not a signer, and an Updater.** `DescriptorWallet.satisfy` can assemble
a spend because miniscript knows what satisfies a fragment; a template
does not, so no satisfaction is here and a caller holding such a script
owns the spend. BIP174's Updater is the role that does not need to know
it: what it writes into a psbt is what the wallet has computed anyway --
`redeem_script` and `witness_script`, the two pre-images, and the origin
of each key -- and `update_psbt_input` and `update_psbt_output` are those
fields written at a position. The output half is what says an output
comes back, and it refuses unless the output being paid is the very
script the position derives.

An origin is a `KeyGroup` parameter because an account key cannot supply
one: BIP174 carries the master fingerprint and the path from the master
key down, and an extended key below the root records neither -- the same
reason `descriptors.account_descriptors` takes the fingerprint beside the
key. A group given no origin is a wallet that computes addresses and
writes no `hd_key_paths`, which is what a psbt of it then lacks -- and
what the `[fingerprint/path]` of its descriptor then lacks too, the two
being one declaration read twice rather than two places to say it.

**The order is a parameter because deployed wallets disagree about it**,
and one of the three is why this class exists at all:

- `"derived"` sorts the keys of each group at every index, which is BIP67
  on the derived keys, so the order is a property of the position and not
  of the wallet. `sortedmulti()` follows exactly that order and states it
  for a quorum that is the whole script; what states it for a quorum
  *inside* a combinator is nothing, BIP379 having no `sortedmulti`
  fragment and its `multi()` being the declared-order one. A timelocked
  branch is therefore where the order stops being expressible, which is
  the wallet #538 pins and the reason for this parameter -- and the line
  `descriptor()` draws: one quorum and nothing else is a
  ``sortedmulti()``, the same quorum inside a combinator is nothing;
- `"account"` sorts the account keys once, before deriving, so the order
  is fixed and `multi()` states it by listing the keys in it. What this
  saves a caller is the sort, not an inexpressible wallet;
- `"none"` leaves the keys in the order the group declares them.

`sort_key` changes what the sort compares, not when it runs: without one
it is byte order, which is BIP67, on the derived public key or on the
account key's public key. A wallet that sorted its xpubs
case-insensitively -- neither a byte order nor a BIP, and deployed -- is
`order="account"` with a `sort_key` of its own.

https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import replace
from typing import Any

from btclib.alias import Command, EmbeddedScriptType, KeyOrder, ScriptList
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _key_data_from_bip32_key,
    derive_from_account_,
    fingerprint,
    xpub_from_xprv,
)
from btclib.bip32.der_path import str_from_index_int
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.descriptors.descriptors import Descriptor
from btclib.descriptors.descriptors import parse as _parse_descriptor
from btclib.descriptors.key_expression import KeyExpression
from btclib.descriptors.miniscript import P2WSH, Miniscript
from btclib.descriptors.miniscript import from_script as _miniscript_from_script
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    NoDescriptorError,
)
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE
from btclib.script.script import op_int, serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.to_pub_key import pub_keyinfo_from_key
from btclib.utils import assert_type, is_integer
from btclib.wallet.wallet import RangedWallet

__all__ = [
    "KeyGroup",
    "ScriptWallet",
]

# what OP_CHECKMULTISIG can be written for: `op_int` spells 0 to 16, so a
# seventeenth key would need the threshold and the count as data pushes,
# which is a script no wallet of this shape has. Core's
# MAX_PUBKEYS_PER_MULTISIG is 20 and is the looser bound of the two
_MAX_KEYS = 16

# the three orders as a runtime list, for the caller who runs no type
# checker: `KeyOrder` is a mypy fact and not a runtime one, which is the
# same limit `bip44`'s script-type table is checked against
_KEY_ORDERS: tuple[KeyOrder, ...] = ("none", "account", "derived")

# how a script becomes an output, and what that costs the script: a p2sh
# redeem script is pushed into the script_sig, so the push limit bounds
# it, while a p2wsh witness script is bounded by the script size limit
# instead -- Bitcoin Core reads the last witness element with
# MAX_SCRIPT_SIZE and every other one with MAX_SCRIPT_ELEMENT_SIZE
_MAX_SCRIPT_FROM_SCRIPT_TYPE: dict[EmbeddedScriptType, int] = {
    "p2sh": MAX_SCRIPT_ELEMENT_SIZE,
    "p2wsh": MAX_SCRIPT_SIZE,
    "p2sh-p2wsh": MAX_SCRIPT_SIZE,
}


def _p2sh_p2wsh(script: bytes, network: str) -> ScriptPubKey:
    """Return the p2sh output wrapping the p2wsh program of a script.

    A function here and not in the table below, for `bip44._p2tr`'s
    reason: the other two entries are `ScriptPubKey` classmethods taking
    exactly these arguments, and this one is a nesting of one in the
    other.
    """
    return ScriptPubKey.p2sh(ScriptPubKey.p2wsh(script, network).script, network)


# how the descriptor of a script is written, per script type: the
# expression goes where the brace is. `sh(SCRIPT)` is BIP381's and holds a
# BIP383 quorum here and nothing else -- a miniscript is P2WSH or
# tapscript, there being no legacy context for one to be read in
_DESCRIPTOR_FROM_SCRIPT_TYPE: dict[EmbeddedScriptType, str] = {
    "p2sh": "sh({})",
    "p2wsh": "wsh({})",
    "p2sh-p2wsh": "sh(wsh({}))",
}

# how few positions a lift may be confirmed at, and why not one: index 0
# is where the expression was read, so a key left as the fixed hex it was
# derived to -- the one way a substitution can miss -- writes the very
# script that was lifted there and a different one at every other index
_MIN_CHECKED_INDEXES = 2


def _lifted(node: Miniscript, expressions: Mapping[bytes, KeyExpression]) -> Miniscript:
    """Return the miniscript with each key back as the expression it came from.

    The tree rebuilt bottom-up, `Miniscript` being frozen and its derived
    fields recomputed by `__post_init__` at every `replace`: what changes
    is the KEY expressions of `pk_k()`, `pk_h()` and `multi()`, and a key
    the mapping does not name is left exactly as it is. That last case is
    a script holding a key no account of this wallet derives -- a literal
    push in the template -- and BIP380 states one as the hex it is, so the
    honest answer is a descriptor ranged in the other keys and fixed in
    that one.
    """
    return replace(
        node,
        subs=tuple(_lifted(sub, expressions) for sub in node.subs),
        keys=tuple(
            expressions.get(key.pub_key, key) if key.pub_key else key
            for key in node.keys
        ),
    )


# the script and the network in, the output out
_SCRIPT_PUB_KEY_FROM_SCRIPT_TYPE: dict[
    EmbeddedScriptType, Callable[[bytes, str], ScriptPubKey]
] = {
    "p2sh": ScriptPubKey.p2sh,
    "p2wsh": ScriptPubKey.p2wsh,
    "p2sh-p2wsh": _p2sh_p2wsh,
}


def _assert_origin(key: BIP32KeyData, origin: BIP32KeyOrigin) -> None:
    """Refuse a key origin that is not this account key's own.

    What an extended key records of where it came from is its depth and
    its own index, and both are checked against the path: a path of
    another length is a path that does not end at this key, and a last
    step that is not the key's index is another key at the same depth.
    The levels above cannot be checked -- nothing in an extended key
    names them -- so the caller's word is taken for them, which is
    `bip44._indexes_left_to_derive`'s bargain with the same two facts.

    A master key is the one case where the fingerprint is checkable, and
    it is checked: at depth zero the origin is the empty path under the
    key's own fingerprint, and any other is a signer sent looking for a
    master key nobody has.
    """
    if len(origin.der_path) != key.depth:
        err_msg = f"invalid key origin {origin.description}:"
        err_msg += f" {len(origin.der_path)} levels for a key at depth {key.depth}"
        raise BTClibValueError(err_msg)
    if key.depth and key.index != origin.der_path[-1]:
        err_msg = f"invalid key origin {origin.description}: it ends at"
        err_msg += f" {str_from_index_int(origin.der_path[-1])}, and the key's"
        err_msg += f" own index is {str_from_index_int(key.index)}"
        raise BTClibValueError(err_msg)
    own = fingerprint(key.b58encode())
    if not key.depth and origin.master_fingerprint != own:
        err_msg = f"invalid key origin {origin.description}: the master key's"
        err_msg += f" own fingerprint is {own.hex()}"
        raise BTClibValueError(err_msg)


def _account_sec(xkey: BIP32KeyData) -> bytes:
    """Return the public key of an account key, private or not.

    What `order="account"` compares by default, and the reason it is not
    `BIP32KeyData.key`: that field is the private key prefixed with a
    zero byte for an xprv, so sorting by it would order two participants
    by material one of them does not have -- and the same wallet built
    from xpubs would order them the other way.
    """
    return pub_keyinfo_from_key(xkey)[0]


def _assert_group_arguments(
    threshold: int,
    keys: Sequence[BIP32Key],
    verify: bool,
    origins: Sequence[BIP32KeyOrigin | None] | None,
) -> None:
    """Refuse an argument of the wrong type before a group is built of one.

    A group is what a script, and therefore an address, is computed from,
    so every parameter is asked here rather than at the comparisons and
    the walks that follow: a float `threshold` was accepted outright, and
    a `keys` or `origins` of no sequence type was "not iterable" from
    underneath the library.

    A `str` is a Sequence and one of xpubs it is not, which the annotation
    cannot say: `Sequence[BIP32Key]` accepts a `str`, every character of it
    being a `BIP32Key` as far as the type goes, so one xpub handed where
    the list was meant is 111 keys.

    `verify` decides which opcode the script ends with, so it is a kind and
    not a truth, `musig2._flag`'s distinction: a wallet built from a
    configuration file where it reads "false" would compute the other
    script, and every address with it.
    """
    if not is_integer(threshold):
        raise BTClibTypeError(f"invalid threshold type: {type(threshold).__name__}")
    if isinstance(keys, str) or not isinstance(keys, Sequence):
        raise BTClibTypeError(f"invalid keys type: {type(keys).__name__}")
    if origins is not None and not isinstance(origins, Sequence):
        raise BTClibTypeError(f"invalid origins type: {type(origins).__name__}")
    assert_type(verify, bool, "verify")


def _assert_origin_types(origins: tuple[BIP32KeyOrigin | None, ...]) -> None:
    """Refuse an entry that is no origin, before the count is compared.

    The type before the value: a `str` is a Sequence, so `origins="abc"`
    is three of them as far as the count is concerned and the report would
    be about the number rather than about the type.
    """
    for origin in origins:
        if origin is not None and not isinstance(origin, BIP32KeyOrigin):
            err_msg = f"invalid origin type: {type(origin).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)


class KeyGroup:
    """A quorum of extended keys, as a template writes it into a script.

    `threshold` of as many keys as are given, which OP_CHECKMULTISIG
    needs stated twice: what a group expands to at a position is
    `k <key>... n OP_CHECKMULTISIG`, with each key derived down the two
    unhardened levels `bip32.derive_from_account` walks -- so every key
    here is an *account* key, exactly as `BIP32KeyWallet` takes one.

    An xprv is as welcome as an xpub and is what makes a wallet not
    watch-only; what goes in the script is the public key either way.

    The order the keys are given in is the order the script carries them
    in, unless the wallet holding the group says otherwise: ordering is
    the wallet's parameter, not the group's, because the wallets deployed
    with a per-index order apply it to every quorum of the script.

    `verify=True` writes `OP_CHECKMULTISIGVERIFY` in place of the last
    opcode and nothing else about the group -- the same choice miniscript
    makes with its `v:` wrapper, and the form `and_v(v:multi(...), ...)`
    compiles to.

    `origins` is where each key comes from -- the master fingerprint and
    the path down to the account key, which is what BIP174 carries and
    what an extended key below the root cannot say of itself -- one entry
    per key and in the order the keys are given, `None` for a key whose
    origin the caller does not have. It changes no script: what reads it
    is `ScriptWallet.update_psbt_input` and `update_psbt_output`, and
    what a group without it writes into a psbt is nothing.
    """

    def __init__(
        self,
        threshold: int,
        keys: Sequence[BIP32Key],
        verify: bool = False,
        origins: Sequence[BIP32KeyOrigin | None] | None = None,
    ) -> None:
        _assert_group_arguments(threshold, keys, verify, origins)

        self.keys = tuple(_key_data_from_bip32_key(key) for key in keys)
        # one per key, so that the pairing is positional and stays so
        # through the account order, which sorts the keys and not this
        self.origins: tuple[BIP32KeyOrigin | None, ...] = (
            (None,) * len(self.keys) if origins is None else tuple(origins)
        )
        _assert_origin_types(self.origins)
        if len(self.origins) != len(self.keys):
            err_msg = f"{len(self.origins)} origins for {len(self.keys)} keys:"
            err_msg += " a key origin is positional, and None is what a key"
            err_msg += " without one takes"
            raise BTClibValueError(err_msg)
        for key, origin in zip(self.keys, self.origins, strict=True):
            if origin is not None:
                _assert_origin(key, origin)
        n = len(self.keys)
        if not 0 < n <= _MAX_KEYS:
            err_msg = f"invalid n in {threshold}-of-{n}:"
            err_msg += f" 1 to {_MAX_KEYS} keys, which is what op_int spells"
            raise BTClibValueError(err_msg)
        if not 0 < threshold <= n:
            err_msg = f"invalid threshold in {threshold}-of-{n}"
            raise BTClibValueError(err_msg)
        self.threshold = threshold
        self.verify = verify

    def __repr__(self) -> str:
        """Return the quorum, and no key: one of them may be an xprv."""
        verify = ", verify=True" if self.verify else ""
        return f"KeyGroup({self.threshold}, {len(self.keys)} keys{verify})"


class ScriptWallet(RangedWallet):
    """A script template, its key groups, and the addresses they compute."""

    def __init__(
        self,
        template: Sequence[Command | KeyGroup],
        script_type: EmbeddedScriptType = "p2wsh",
        order: KeyOrder = "none",
        sort_key: Callable[[Any], Any] | None = None,
        network: str = "mainnet",
    ) -> None:
        super().__init__(network)
        if script_type not in _SCRIPT_PUB_KEY_FROM_SCRIPT_TYPE:
            known = ", ".join(sorted(_SCRIPT_PUB_KEY_FROM_SCRIPT_TYPE))
            err_msg = f"unknown script type: {script_type} not in ({known})"
            raise BTClibValueError(err_msg)
        if order not in _KEY_ORDERS:
            known = ", ".join(_KEY_ORDERS)
            err_msg = f"unknown key order: {order} not in ({known})"
            raise BTClibValueError(err_msg)
        if order == "none" and sort_key is not None:
            err_msg = 'sort_key with order "none": there is nothing to sort by,'
            err_msg += ' and the keys stay as declared -- "account" and'
            err_msg += ' "derived" are what a sort_key orders'
            raise BTClibValueError(err_msg)

        self.script_type = script_type
        # the table entry resolved once, which is also what keeps the
        # lookup typed: `Wallet.script_type` is the str every wallet
        # answers, and a str is not a key of a table keyed by the three
        self._output = _SCRIPT_PUB_KEY_FROM_SCRIPT_TYPE[script_type]
        # and the same for the descriptor function wrapping the expression,
        # for the same reason and in the same place
        self._descriptor_form = _DESCRIPTOR_FROM_SCRIPT_TYPE[script_type]
        self.order = order
        self.sort_key = sort_key
        self.template = tuple(template)
        # the account order applied once, here, which is the whole of what
        # "account" means: what is left for a position is the derivation
        # and, for "derived", a sort of what came out of it
        self._ordered_keys = {
            position: self._account_order(command.keys)
            for position, command in enumerate(self.template)
            if isinstance(command, KeyGroup)
        }
        if not self._ordered_keys:
            err_msg = "no KeyGroup in the template: a script with no key to"
            err_msg += " derive is one script, and script.serialize writes it"
            raise BTClibValueError(err_msg)

        # built once at construction, which is what refuses a template no
        # position of this wallet could be computed from -- a command
        # `serialize` cannot write, a key of another network, an account
        # key that is not hardened. The size it checks is the size at
        # every index: a derived public key is 33 bytes wherever it came
        # from, so a script that fits here fits everywhere
        script = self._script(0, 0)
        max_size = _MAX_SCRIPT_FROM_SCRIPT_TYPE[script_type]
        if len(script) > max_size:
            err_msg = f"invalid script length: {len(script)} bytes is past the"
            err_msg += f" {max_size} a {script_type} script may have"
            raise BTClibValueError(err_msg)

    @property
    def branches(self) -> tuple[int, ...]:
        """The receiving and change chains, which is what BIP44 defines.

        The two `bip32.derive_from_account` walks, and the same two
        `BIP32KeyWallet` has: every key of every group is an account key,
        so what a branch means here is the step below one.
        """
        return (0, 1)

    @property
    def is_watch_only(self) -> bool:
        """Whether no key of any group is a private one."""
        return not any(
            key.is_private for keys in self._ordered_keys.values() for key in keys
        )

    def _account_order(
        self, keys: tuple[BIP32KeyData, ...]
    ) -> tuple[BIP32KeyData, ...]:
        """Return the account keys of a group in the order they derive in."""
        if self.order != "account":
            return keys
        return tuple(sorted(keys, key=self.sort_key or _account_sec))

    def _derived_sec(self, key: BIP32KeyData, branch: int, index: int) -> bytes:
        """Return the public key a group key derives to at a position.

        The public one whatever the key is: an xprv derives to an xprv,
        whose `BIP32KeyData.key` is the private key behind a zero byte, and
        that is not what goes into a script. `bip32.derive_from_account_` is
        what imposes the bounds -- branch 0 or 1, index at most 65535 --
        and the network check is `to_pub_key`'s.

        The object spelling of that walk, `derive_from_account_`: the
        Base58Check text `derive_from_account` answers would be decoded
        straight back by `pub_keyinfo_from_key` on this same line, a
        `BIP32KeyData` being in the `PubKey` union already. 57.31 us against
        34.23 per derived key, a fresh index each call so that no decode
        cache answers (issue 886)
        """
        return pub_keyinfo_from_key(
            derive_from_account_(key, branch, index), self.network
        )[0]

    def _quorum(
        self,
        threshold: int,
        keys: tuple[BIP32KeyData, ...],
        verify: bool,
        branch: int,
        index: int,
    ) -> ScriptList:
        """Return what a group writes into the script at one position."""
        derived = [self._derived_sec(key, branch, index) for key in keys]
        if self.order == "derived":
            # `key=None` is the plain byte order sorted() would use
            # anyway, so one call spells both readings
            derived.sort(key=self.sort_key)
        opcode = "OP_CHECKMULTISIGVERIFY" if verify else "OP_CHECKMULTISIG"
        return [op_int(threshold), *derived, op_int(len(derived)), opcode]

    def _script(self, branch: int, index: int) -> bytes:
        """Return the script the template writes at one position."""
        commands: ScriptList = []
        for position, command in enumerate(self.template):
            if isinstance(command, KeyGroup):
                commands += self._quorum(
                    command.threshold,
                    self._ordered_keys[position],
                    command.verify,
                    branch,
                    index,
                )
            else:
                commands.append(command)
        return serialize(commands)

    def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
        return self._output(self._script(branch, index), self.network)

    def redeem_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a p2sh output at this position commits to.

        The template's own script where the output is a plain p2sh, and
        the p2wsh program where a p2sh wraps one: what a p2sh input
        pushes is the pre-image of the hash in the output, which for
        `p2sh-p2wsh` is the witness program and not the script that
        program commits to.
        """
        self._assert_position(branch, index)
        if self.script_type == "p2wsh":
            return b""
        script = self._script(branch, index)
        if self.script_type == "p2sh":
            return script
        return ScriptPubKey.p2wsh(script, self.network).script

    def witness_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a p2wsh output at this position commits to.

        The template's own script, wrapped in a p2sh or not, and `b""` for
        a plain p2sh, where the template script is the redeem script
        instead.
        """
        self._assert_position(branch, index)
        if self.script_type == "p2sh":
            return b""
        return self._script(branch, index)

    def _hd_key_paths(self, branch: int, index: int) -> dict[bytes, BIP32KeyOrigin]:
        """Return where each key of the script at a position comes from.

        BIP174's bip32_derivs, keyed by the derived public key the script
        holds: the account key's own origin with the two levels
        `derive_from_account` walks appended to it, which is the path a
        signer has to take to reach that key. A key given no origin is
        skipped rather than refused -- the field is keyed by key, and what
        is missing is one entry of it.

        The keys are read off the groups as declared, the order being the
        script's business and not this mapping's.
        """
        hd_key_paths: dict[bytes, BIP32KeyOrigin] = {}
        for command in self.template:
            if not isinstance(command, KeyGroup):
                continue
            for key, origin in zip(command.keys, command.origins, strict=True):
                if origin is None:
                    continue
                sec = self._derived_sec(key, branch, index)
                der_path = [*origin.der_path, branch, index]
                hd_key_paths[sec] = BIP32KeyOrigin(origin.master_fingerprint, der_path)
        return hd_key_paths

    def update_psbt_input(
        self, psbt: Psbt, vin_i: int, branch: int = 0, index: int = 0
    ) -> Psbt:
        """Return the psbt with an input told what this position is.

        BIP174's Updater, for an input spending an output of this wallet:
        the pre-image the output commits to -- the redeem script of a
        p2sh, the witness script of a p2wsh, both where one wraps the
        other -- and the origin of every key the script names, which is
        what a hardware signer derives its own key from. What still cannot
        be answered here is the satisfaction: `psbt.finalize` assembles
        such an input through the `solver` its caller passes, no language
        saying what satisfies this script.

        A copy, the psbt handed in being left alone, and the fields of the
        copy written in place, as `Descriptor.update_psbt_input` does.

        The origins are every key of the template's, as for an output:
        which of them a spend will use is what the satisfaction decides,
        and a signer signs with the keys it holds whatever else it is
        told about.

        What is not filled is what the wallet does not know: the utxo, the
        sighash type, the signatures. Nor is the script checked against
        the output being spent -- an input may not carry it yet, and
        `Psbt.assert_signable` is the role after this one.
        """
        self._assert_position(branch, index)
        # an IndexError out of a public method is not an answer, and a
        # negative index would quietly update the input at the other end
        if not 0 <= vin_i < len(psbt.inputs):
            raise BTClibValueError(f"invalid input index: {vin_i}")
        psbt = deepcopy(psbt)
        self._update(psbt.inputs[vin_i], branch, index)
        psbt.assert_valid()
        return psbt

    def update_psbt_output(
        self, psbt: Psbt, vout_i: int, branch: int = 0, index: int = 0
    ) -> Psbt:
        """Return the psbt with an output told what this position is.

        The Updater's other half, and what makes an output recognizable as
        the wallet's own: a signer reads the script and the key origins,
        derives the script for itself, and sees that the money comes back
        rather than being asked to take it on trust.

        Unlike the input half, the script *is* checked: the output being
        paid is in the psbt already, so this refuses unless the wallet
        derives exactly that script at this position. Marking an output as
        one's own is a claim about where money goes, and the only evidence
        for it is the whole script -- never a key origin whose four-byte
        fingerprint matches, which is what `position_of` says.

        Every key of the template, and not the quorum a spend will use:
        an output is not a signing instruction, and what a reader wants of
        it is the whole script, the branch nobody is spending included.
        """
        self._assert_position(branch, index)
        # an IndexError out of a public method is not an answer, and a
        # negative index would quietly update the output at the other end
        if not 0 <= vout_i < len(psbt.outputs):
            raise BTClibValueError(f"invalid output index: {vout_i}")
        paid = psbt.tx.vout[vout_i].script_pub_key.script
        if self._script_pub_key(branch, index).script != paid:
            err_msg = f"output {vout_i} pays to {paid.hex()}, which is not the"
            err_msg += f" script this wallet derives at {branch}/{index}"
            raise BTClibValueError(err_msg)
        psbt = deepcopy(psbt)
        self._update(psbt.outputs[vout_i], branch, index)
        psbt.assert_valid()
        return psbt

    def _update(self, psbt_map: PsbtIn | PsbtOut, branch: int, index: int) -> None:
        """Write what this wallet knows of a position into a psbt map.

        One method for an input and an output, as BIP174 gives the two
        maps the same three fields: a redeem script, a witness script and
        a key origin say what they say whether the psbt is spending the
        script or paying to it.

        The empty pre-image of a script type that has none is not written:
        `b""` is what those fields hold already, and writing it back would
        clear whatever an earlier Updater had put there. The key paths are
        added to for the same reason -- BIP174 keys them by public key, so
        another signer's entry stays and this wallet's wins for a key held
        by both.
        """
        if redeem_script := self.redeem_script(branch, index):
            psbt_map.redeem_script = redeem_script
        if witness_script := self.witness_script(branch, index):
            psbt_map.witness_script = witness_script
        psbt_map.hd_key_paths = {
            **psbt_map.hd_key_paths,
            **self._hd_key_paths(branch, index),
        }

    def _key_origins(self) -> dict[str, BIP32KeyOrigin]:
        """Return the origin of each account key, keyed by its xpub.

        The groups' own `origins`, which is where a caller declares them
        and what `_hd_key_paths` writes into a psbt: one fact, read twice,
        rather than a second place to say it. Keyed by the neutered
        spelling because that is what the answer carries, and what
        `descriptors.PrvKeys` keys by for the same reason.

        A key with no origin is absent, and its expression is written
        without one -- which BIP380 allows and Bitcoin Core imports. What
        it costs is the same thing an empty `hd_key_paths` costs: a signer
        cannot tell that the key is its own.
        """
        return {
            self._xpub(key): origin
            for command in self.template
            if isinstance(command, KeyGroup)
            for key, origin in zip(command.keys, command.origins, strict=True)
            if origin is not None
        }

    @staticmethod
    def _xpub(key: BIP32KeyData) -> str:
        """Return the public spelling of an account key.

        A descriptor is text that gets handed to a monitor and written to
        a log, so an xprv is neutered before it goes in one -- which is
        `descriptors.parse`'s rule for a descriptor read the other way.
        """
        return xpub_from_xprv(key) if key.is_private else key.b58encode()

    def _key_expression(
        self, key: BIP32KeyData, branch: int, origins: Mapping[str, BIP32KeyOrigin]
    ) -> KeyExpression:
        """Return the KEY expression one account key of a group derives by.

        `xpub/branch/*`, which is the ranged expression: the wildcard is
        the index, and the branch is the step the group takes above it, so
        one expression covers the whole of a chain.
        """
        xpub = self._xpub(key)
        return KeyExpression(
            origin=origins.get(xpub),
            xkey=xpub,
            der_path=(branch,),
            wildcard=0,
        )

    def _quorum_expression(
        self, branch: int, origins: Mapping[str, BIP32KeyOrigin]
    ) -> str | None:
        """Return the BIP383 quorum this wallet is, or None if it is more.

        The one shape a descriptor states without reading the script at
        all: a template that is a single group and nothing else is that
        group, so ``multi()`` or ``sortedmulti()`` writes it whatever the
        order and whatever the script type -- `sh(sortedmulti(2,...))` is
        the legacy multisig wallet, and no miniscript can be read in a
        legacy context.

        ``sortedmulti()`` is what makes the per-index order expressible
        here and nowhere else: it sorts the derived keys, in byte order,
        which is `order="derived"` with no `sort_key` exactly. A
        `sort_key` of its own is a third order that neither function
        states, and `verify=True` is an OP_CHECKMULTISIGVERIFY, which is
        no script on its own -- both fall through to the lift, which
        refuses them with its own reason.
        """
        if len(self.template) != 1:
            return None
        group = self.template[0]
        if not isinstance(group, KeyGroup) or group.verify:
            return None
        if self.order == "derived" and self.sort_key is not None:
            return None
        keys = ",".join(
            str(self._key_expression(key, branch, origins))
            for key in self._ordered_keys[0]
        )
        name = "sortedmulti" if self.order == "derived" else "multi"
        return f"{name}({group.threshold},{keys})"

    def _lifted_expression(
        self, branch: int, origins: Mapping[str, BIP32KeyOrigin]
    ) -> str:
        """Return the miniscript of the script at index 0, keys put back.

        Which is the lift: the concrete script of one position read back
        into the expression it is, and each derived key traded for the
        ranged expression that derived it. What the mapping is keyed by is
        what `from_script` puts in the tree -- the SEC bytes of the key at
        this branch and index 0 -- so the substitution is a lookup and
        never a guess at which account key a script key came from.
        """
        if self.order == "derived":
            err_msg = "a quorum sorted after derivation inside a combinator:"
            err_msg += " the order is a property of the index, so no ranged"
            err_msg += " expression states it -- sortedmulti() states one"
            err_msg += " quorum that is the whole script, and BIP379 has no"
            err_msg += " sortedmulti fragment to state one inside another"
            raise NoDescriptorError(err_msg)
        if self.script_type == "p2sh":
            err_msg = "a p2sh script that is not a bare quorum: miniscript is"
            err_msg += " read in a P2WSH or a tapscript context, and BIP379"
            err_msg += " has no legacy one for this script to be read in"
            raise NoDescriptorError(err_msg)
        script = self._script(branch, 0)
        try:
            node = _miniscript_from_script(script, P2WSH)
        except BTClibValueError as exception:
            raise NoDescriptorError(str(exception)) from exception
        expressions = {
            self._derived_sec(key, branch, 0): self._key_expression(
                key, branch, origins
            )
            for keys in self._ordered_keys.values()
            for key in keys
        }
        return str(_lifted(node, expressions))

    def _assert_lift(
        self, descriptor: Descriptor, branch: int, checked_indexes: int
    ) -> None:
        """Require the descriptor and the template to write the same script.

        The whole script and not the addresses, which is `position_of`'s
        rule here too: a script type this wallet has no address for -- and
        every position of it -- is compared just the same.

        The range is checked first because a descriptor that has none has
        no index 1 to compare at: every group key becomes a ranged
        expression, so a lift where none did is one that put no key back
        at all, and it would otherwise be reported as an index out of
        range rather than as the substitution it is.
        """
        if not descriptor.is_ranged:
            err_msg = "the lifted descriptor names one script and not a range:"
            err_msg += " no key of the template came back as the expression it"
            err_msg += " was derived from"
            raise BTClibRuntimeError(err_msg)
        for index in range(checked_indexes):
            lifted = descriptor.script_pub_key(index).script
            own = self._script_pub_key(branch, index).script
            if lifted != own:
                err_msg = f"the lifted descriptor pays to {lifted.hex()} at"
                err_msg += f" {branch}/{index}, where this wallet pays to"
                err_msg += f" {own.hex()}"
                raise BTClibRuntimeError(err_msg)

    def descriptor(
        self, branch: int = 0, checked_indexes: int = _MIN_CHECKED_INDEXES
    ) -> Descriptor:
        """Return the ranged descriptor of a branch, confirmed, or refuse to.

        The bridge between this class and `DescriptorWallet`, and the
        answer to "what do I hand a monitor, or Bitcoin Core's
        `importdescriptors`, for this wallet". `DescriptorWallet.descriptor`
        is the same question of a wallet that was built from one; this
        derives the answer, and the module docstring has how.

        `NoDescriptorError` is the refusal, and it is about the wallet: the
        `<n> OP_CSV OP_DROP` timelock no miniscript fragment emits, a
        quorum ordered per index inside a combinator, a legacy p2sh script
        that is not a bare quorum. Each of those is a script BIP380 to
        BIP390 does not state, so a caller catching it has to watch the
        addresses themselves -- which is what this class is for -- rather
        than a bug to report.

        The key origins are the groups' own, the same ones a psbt gets:
        `[fingerprint/44h/0h/0h]` in front of a key expression is what a
        hardware signer recognises its key by, it changes no script, and a
        group given none is written without one -- a descriptor BIP380
        allows and Core imports, and the same thing an empty
        `hd_key_paths` says.

        `checked_indexes` is how many positions the answer is confirmed at
        before it is handed back: the descriptor's script is compared with
        the template's at each, and a disagreement is a
        `BTClibRuntimeError` -- the lift was not faithful, which is a
        failure of this code and not of the caller's wallet. Two is the
        floor and the default, being what tells a substituted key from a
        fixed one; a caller with a committed span of addresses to stand
        behind passes its length, and pays a derivation of every key at
        every index for it.

        A `DescriptorWallet` of both chains, where that is what a caller
        wants, is `DescriptorWallet({b: w.descriptor(b) for b in
        w.branches})` -- and the two wallets then answer the same
        addresses, from the two sources.
        """
        self._assert_position(branch, 0)
        if checked_indexes < _MIN_CHECKED_INDEXES:
            err_msg = f"invalid checked_indexes: {checked_indexes} is fewer than"
            err_msg += f" the {_MIN_CHECKED_INDEXES} a lift is confirmed at"
            raise BTClibValueError(err_msg)
        origins = self._key_origins()
        expression = self._quorum_expression(
            branch, origins
        ) or self._lifted_expression(branch, origins)
        text = self._descriptor_form.format(expression)
        try:
            descriptor = _parse_descriptor(text, self.network)
        except BTClibValueError as exception:
            # what a descriptor may hold and not what miniscript can read:
            # Bitcoin Core refuses an insane expression -- one satisfiable
            # without a signature, or whose witness a third party can
            # rewrite -- and a wallet of that shape has no descriptor for
            # the same reason it has no safe spend
            raise NoDescriptorError(f"{text}: {exception}") from exception
        self._assert_lift(descriptor, branch, checked_indexes)
        return descriptor
