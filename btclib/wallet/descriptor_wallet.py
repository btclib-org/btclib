# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A wallet of output descriptors: one per chain, the rest is theirs.

`Descriptor` answers everything about the scripts it describes and knows
nothing about chains: it has one index, so a wallet is two of them --
BIP44 puts receiving addresses under `/0` and change under `/1`, and a
wallet holding one and not the other cannot recognize its own change,
which is a lost output rather than a missing feature. This module is that
pairing, and the `btclib.wallet` vocabulary over it.

So the branch here is a *label* and not a derivation step: which of the
descriptors, the path inside each having derived it already. The three
ways in put the labels there:

- the descriptors themselves, in a mapping from branch or in chain order;
- `from_descriptor`, which reads BIP389's ``<0;1>`` multipath spelling --
  one line of text for the pair, expanded positionally, so element 0 is
  branch 0. Named as `ScriptPubKey.from_address` is, and not `parse`: a
  `parse` classmethod in btclib reads octets out of a stream, and this
  reads a line of text;
- `from_account`, which is `descriptors.account_descriptors`: an account
  xpub and its master fingerprint in, the receive and change descriptors
  out.

What this adds to a descriptor is the branch, the ledger of what has been
handed out, and `position_of`; what it delegates is everything else, and
`descriptor(branch)` hands back the `Descriptor` for the questions this
does not ask -- `str()`, `key_expressions`, `satisfy` for a shape the
wallet-level one refuses. `satisfy` and the two psbt Updaters are here
because their argument is a position, and a caller holding a psbt has one
rather than an index.

A ``combo()`` is refused: it is four scripts at one index, so it is four
addresses at one position, and a wallet position that means four
addresses would make `address(branch, index)` a lie. `descriptors.parse`
reads one, and a caller wanting it uses `Descriptor.script_pub_keys`
directly.

A parsed descriptor holds no private key -- `descriptors.parse` neuters an
xprv to its xpub -- so a wallet is watch-only unless it is handed the
`prv_keys` mapping that module takes: the hardened steps an xpub cannot
walk, keyed as it keys them. That mapping is also the whole of what
`is_watch_only` reads, there being nothing else here that could sign.

BIP380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
BIP389: https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from typing_extensions import override

from btclib.alias import BIP44ScriptType, Octets
from btclib.bip32.bip32 import BIP32Key
from btclib.bip32.der_path import DerPath
from btclib.descriptors.descriptors import (
    ComboDescriptor,
    Descriptor,
    ShDescriptor,
    WshDescriptor,
    account_descriptors,
    multipath_descriptors,
)
from btclib.descriptors.descriptors import parse as _parse_descriptor
from btclib.descriptors.key_expression import PrvKeys
from btclib.descriptors.miniscript import SpendContext
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.psbt.psbt import Psbt
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.wallet.wallet import _LAST_INDEX, RangedWallet

__all__ = [
    "DescriptorWallet",
]


class DescriptorWallet(RangedWallet):
    """One descriptor per chain, and the wallet questions over the pair."""

    def __init__(
        self,
        descriptors: Descriptor | Mapping[int, Descriptor] | Sequence[Descriptor],
        prv_keys: PrvKeys | None = None,
    ) -> None:
        # a string is the mistake worth naming: `Sequence` admits one, so
        # a descriptor's text would become one branch per character
        # rather than an error. `Octets` is honoured inside btclib and
        # nowhere else, which is why the annotation has no case for it
        if isinstance(descriptors, str):
            err_msg = "a descriptor string is not a Descriptor:"
            err_msg += " DescriptorWallet.from_descriptor reads one"
            raise BTClibTypeError(err_msg)
        if isinstance(descriptors, Descriptor):
            by_branch = {0: descriptors}
        elif isinstance(descriptors, Mapping):
            by_branch = dict(descriptors)
        else:
            # a sequence is the chains in order, which is what
            # `account_descriptors` returns and how BIP389 expands
            by_branch = dict(enumerate(descriptors))
        if not by_branch:
            err_msg = "no descriptor: a wallet has at least one chain"
            raise BTClibValueError(err_msg)

        for branch, descriptor in by_branch.items():
            if branch < 0:
                raise BTClibValueError(f"invalid branch: {branch}")
            if isinstance(descriptor, ComboDescriptor):
                err_msg = f"combo() at branch {branch}: four scripts at one"
                err_msg += " index are four addresses at one position, so a"
                err_msg += " wallet cannot hold one -- Descriptor"
                err_msg += ".script_pub_keys is what answers for it"
                raise BTClibValueError(err_msg)

        networks = {descriptor.network for descriptor in by_branch.values()}
        if len(networks) != 1:
            err_msg = f"descriptors of different networks: {sorted(networks)}"
            raise BTClibValueError(err_msg)

        super().__init__(networks.pop())
        # sorted, so that `branches` is ascending and `position_of`
        # searches the receiving chain before the change one
        self._descriptors = dict(sorted(by_branch.items()))
        self.prv_keys = prv_keys
        # computed here rather than answered lazily: it is one derivation,
        # it is the same at every index -- a descriptor function is what
        # decides it -- and doing it at construction is what refuses a
        # descriptor this wallet cannot derive at all before a caller
        # asks it for an address
        self.script_type = self.script_pub_key(self.branches[0]).type

    @classmethod
    def from_descriptor(
        cls,
        descriptor: str,
        network: str = "mainnet",
        prv_keys: dict[str, str] | None = None,
    ) -> DescriptorWallet:
        """Return the wallet of a descriptor, checksum verified.

        BIP389's ``<0;1>`` is what makes one line of text a whole wallet,
        and it is expanded positionally: as many branches as the
        multipath steps have elements, branch 0 taking the first element
        of every step. A descriptor with no such step is one chain, and
        a wallet of one branch -- which is what a caller watching a
        single chain has, and not an error.
        """
        return cls(
            [
                _parse_descriptor(single, network, prv_keys)
                for single in multipath_descriptors(descriptor)
            ],
            prv_keys,
        )

    @classmethod
    def from_account(
        cls,
        xkey: BIP32Key,
        der_path: DerPath,
        master_fingerprint: Octets | None = None,
        script_type: BIP44ScriptType | None = None,
        prv_keys: PrvKeys | None = None,
    ) -> DescriptorWallet:
        """Return the wallet of a BIP44 account, both of its chains.

        `descriptors.account_descriptors` is the whole of it, and every
        argument is that function's: the account path selects the
        encoding through its purpose, the master fingerprint is what the
        key origin needs, and the network is the extended key's own.

        `BIP32KeyWallet` is the same account without the descriptors, and
        the two answer the same addresses. What this one adds is what a
        descriptor carries: the text to hand to Bitcoin Core, the key
        origins a hardware signer wants, and the psbt Updaters.
        """
        return cls(
            list(account_descriptors(xkey, der_path, master_fingerprint, script_type)),
            prv_keys,
        )

    @property
    @override
    def branches(self) -> tuple[int, ...]:
        """The chains, which are the branches the descriptors came under."""
        return tuple(self._descriptors)

    @property
    @override
    def is_watch_only(self) -> bool:
        """Whether the wallet was handed no private key.

        A parsed descriptor never holds one, `descriptors.parse` keeping
        the xpub of an xprv, so the `prv_keys` mapping is the only key
        material a wallet of descriptors can have.
        """
        return not self.prv_keys

    @property
    def is_ranged(self) -> bool:
        """Whether any chain describes a range of scripts.

        A wallet of descriptors with no wildcard is one address per
        chain, index 0 and nothing else; `Descriptor.is_ranged` is the
        same question of one chain.
        """
        return any(descriptor.is_ranged for descriptor in self._descriptors.values())

    def descriptor(self, branch: int = 0) -> Descriptor:
        """Return the descriptor of a chain."""
        self._assert_position(branch, 0)
        return self._descriptors[branch]

    @override
    def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
        return self._descriptors[branch].script_pub_key(index, self.prv_keys)

    @override
    def redeem_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a ``sh()`` at this position embeds.

        Which is the redeem script of every shape ``sh()`` wraps: the
        script of a ``sh(multi())``, and the p2wpkh or p2wsh program of
        the two wrapped segwit forms, that program being what a p2sh
        input pushes either way.
        """
        self._assert_position(branch, index)
        descriptor = self._descriptors[branch]
        if not isinstance(descriptor, ShDescriptor):
            return b""
        return descriptor.inner.redeem_script(index, self.prv_keys)

    @override
    def witness_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a ``wsh()`` at this position embeds.

        Native or wrapped in a ``sh()``, which is the same witness script
        in the same psbt field: the wrapping shows up in the redeem
        script and nowhere else.
        """
        self._assert_position(branch, index)
        descriptor = self._descriptors[branch]
        if isinstance(descriptor, ShDescriptor):
            descriptor = descriptor.inner
        if not isinstance(descriptor, WshDescriptor):
            return b""
        return descriptor.inner.redeem_script(index, self.prv_keys)

    @override
    def position_of(
        self, script_pub_key: Octets | ScriptPubKey, last_index: int = _LAST_INDEX
    ) -> tuple[int, int] | None:
        """Return the position paying to this output, None where none is.

        `Descriptor.index_of` per chain, in `branches` order, rather than
        a comparison written a second time here: it is the same whole-
        script comparison, it refuses the same spellings that name no
        output, and it is what bounds the search of a chain that is not
        ranged to the one script it has.
        """
        for branch, descriptor in self._descriptors.items():
            index = descriptor.index_of(script_pub_key, last_index, self.prv_keys)
            if index is not None:
                return branch, index
        return None

    def satisfy(
        self,
        signatures: Mapping[Octets, Octets],
        branch: int = 0,
        index: int = 0,
        spend: SpendContext | None = None,
    ) -> tuple[bytes, Witness]:
        """Return the script_sig and witness spending this position.

        `Descriptor.satisfy` with the position resolved, and every word
        of its contract: the signatures are handed in and assembled
        rather than verified, a satisfaction short of what the script
        pops is an error rather than a shorter answer, and `spend` is
        what a miniscript branch reads beside the signatures.
        """
        self._assert_position(branch, index)
        return self._descriptors[branch].satisfy(
            signatures, index, self.prv_keys, spend
        )

    def update_psbt_input(
        self, psbt: Psbt, vin_i: int, branch: int = 0, index: int = 0
    ) -> Psbt:
        """Return the psbt with an input told what this position is.

        `Descriptor.update_psbt_input`, which is BIP174's Updater: the
        scripts and the key origins of the position, for signers to fill
        in and `psbt.finalize` to assemble.
        """
        self._assert_position(branch, index)
        return self._descriptors[branch].update_psbt_input(
            psbt, vin_i, index, self.prv_keys
        )

    def update_psbt_output(
        self, psbt: Psbt, vout_i: int, branch: int = 0, index: int = 0
    ) -> Psbt:
        """Return the psbt with an output told what this position is.

        `Descriptor.update_psbt_output`, which refuses unless the output
        being paid is the very script this position derives: marking an
        output as the wallet's own is a claim about where money goes, and
        the whole script is the only evidence for it. `position_of` is
        the same claim asked as a question.
        """
        self._assert_position(branch, index)
        return self._descriptors[branch].update_psbt_output(
            psbt, vout_i, index, self.prv_keys
        )
