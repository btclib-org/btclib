# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a wallet is asked, in the words every wallet here answers to.

Three classes in this package say "these are my addresses", and they say
it from three different sources -- an extended key, an output descriptor,
a script template. The questions put to them are one set, and this module
is that set: it holds no key, no descriptor and no script of its own.

`Wallet` is the ledger half -- the addresses handed out, what is
remembered about each, and whether any private key is held -- and
`KeyWallet`, which takes individual keys and has no position to compute
them from, is a wallet on that much alone.

`RangedWallet` is the half addressed by *position*, which is the branch
and index BIP44 puts below an account, and it is where one vocabulary is
worth an abstraction:

- `script_pub_key(branch, index)` is what the wallet pays to there, and
  `address(branch, index)` the same output as text; `next_address(branch)`
  walks a branch, and `addresses` is what has been handed out;
- `redeem_script` and `witness_script` are the two pre-images BIP174 asks
  an Updater for, empty where the output commits to a key rather than to
  a script;
- `position_of(script_pub_key)` runs the comparison the other way, which
  is the question a caller gets wrong: an output is this wallet's when
  the whole script derived at a position is the script being paid, and
  never because a key origin's four-byte fingerprint matches.
  `Descriptor.index_of` asks it of one descriptor and answers the index
  alone; a wallet has branches, so the answer here is the pair.
  `assert_derives` runs it over a whole span at once, which is the
  question a caller has about a list of addresses it wrote down.

What a branch *is* differs, and the difference is the one thing not
hidden: a key wallet and a script wallet derive it, `branch/index` below
the account, so 0 is the receiving chain and 1 the change one, both bound
by `bip32.derive_from_account`; a descriptor wallet has the derivation
inside each descriptor already and reads the branch as the label of which
one. The chains are the same two chains either way, named rather than
derived.

**What no wallet here does.** No utxos, no balances, no transaction
building, no persistence to disk, no encryption at rest. Each of those is
a decision this package cannot take on its own: the first three need a
view of the chain, which btclib does not have and does not fetch, and the
last two need a file format and a key-derivation function that would
outlive any release choosing them. Without them a wallet is a pure
function of its source -- the same source gives the same addresses in the
same order, every time -- which is what makes it testable and what keeps
its whole state in memory, where the caller can see it. A spender is the
larger reading of "wallet" and belongs above this, not inside it.

https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from btclib import b32
from btclib.alias import Octets, String
from btclib.exceptions import BTClibValueError
from btclib.network import _validated_network_name
from btclib.script.script_pub_key import ScriptPubKey, _validated_script_from
from btclib.utils import str_from_string

__all__ = [
    "AddressInfo",
    "RangedWallet",
    "Wallet",
]

# how far ahead of what it has handed out a wallet looks for an output of
# its own, where the caller expresses no policy of its own. The same
# default `Descriptor.index_of` takes, and for the same reason: a gap
# limit is the caller's business and this is only a number to start from
_LAST_INDEX = 999


def _address_str(address: String) -> str:
    """Return an address spelled the way a wallet records it.

    Bech32 is case insensitive and BIP173 blesses the upper case spelling
    for QR codes, so an address read off one has to find the lower case
    one the wallet handed out. Base58 is not case insensitive -- `1Lq`
    and `1lq` are different payloads -- so it is left exactly as it came.
    """
    addr = str_from_string(address, "address").strip()
    return addr.lower() if b32.is_segwit_prefixed(addr) else addr


@dataclass(frozen=True)
class AddressInfo:
    """What a wallet remembers about one address it has handed out.

    No key material, deliberately: this is the record a caller prints,
    logs and compares, and the private key is one call away behind
    `KeyWallet.prv_key`, which reads as the request it is. Frozen for the
    same reason `addresses` hands back a tuple -- what comes out of a
    wallet is a copy of what it knows, not a handle on it.

    `script_type` is the wallet's own spelling: `bip44`'s four for a key
    wallet, which is where `p2wpkh-p2sh` is a script type at all, and how
    the script becomes an output for the other two.

    `der_path` is the whole path from the master key, so that it can be
    handed to `bip32.derive` or written into a psbt key origin as it
    stands. It is empty wherever there is not one path to write: a key
    that came into a `KeyWallet` on its own has none, and a script naming
    several keys has one per key, which a psbt key origin records and a
    single field cannot.

    `branch` and `index` are the position the address was computed from,
    and `None` for an address that was not computed from one.
    """

    address: str
    script_type: str
    der_path: str
    branch: int | None = None
    index: int | None = None


class Wallet(ABC):
    """The addresses a wallet has handed out, and what it knows of each.

    A ledger and nothing else: what puts an address in it is each
    wallet's own business -- `KeyWallet.add` takes a key, and
    `RangedWallet.address` computes a position -- and what it answers is
    the same either way.
    """

    # every wallet sets it in __init__, and the spelling is its own:
    # `bip44`'s four for a key wallet, the three ways a script becomes an
    # output for a script wallet, and the shape of the script itself for
    # a descriptor one. Annotated and not a property, so that a subclass
    # assigns it as the plain attribute it is
    script_type: str

    def __init__(self, network: str = "mainnet") -> None:
        """Bind the wallet to a network, by the name btclib resolves.

        `_validated_network_name` is the converter `descriptors.parse`
        and `p2p.magic.magic_from_network` reach for across modules, so
        the `strip().lower()` tolerance issue #216 decided to keep
        reaches a wallet too. `self.network` is a key of `NETWORKS`,
        which is what a subclass reads to derive an address.
        """
        self.network = _validated_network_name(network)
        # insertion ordered, which is the order the addresses were handed
        # out in: `addresses` is that order and nothing else records it
        self._handed_out: dict[str, AddressInfo] = {}

    def __len__(self) -> int:
        return len(self._handed_out)

    def __contains__(self, address: String) -> bool:
        """Whether the wallet has handed this address out.

        The question `address_info` raises on, asked without the
        exception: a caller deciding what to do about an unknown address
        is not handling an error, and should not have to write one.
        """
        return _address_str(address) in self._handed_out

    @property
    def addresses(self) -> tuple[str, ...]:
        """Every address handed out, in the order it was handed out."""
        return tuple(self._handed_out)

    @property
    @abstractmethod
    def is_watch_only(self) -> bool:
        """Whether the wallet holds no private key at all.

        A first-class state rather than a broken one: watching is most of
        what a wallet does, and every wallet here is asked, so that no
        caller has to know which kind of source it was built from.
        """

    def address_info(self, address: String) -> AddressInfo:
        """Return what the wallet remembers about an address.

        A miss raises rather than answering None. A wallet that has not
        handed an address out has no opinion about it -- not "no key",
        which is what a watch-only address has -- and the two are worth
        different answers; and every other lookup in btclib raises, so a
        None here would be the one place a caller has to remember not to
        use the result. `address in wallet` is the question that wants a
        boolean.

        A miss is also not evidence that the wallet cannot reach the
        address: a `RangedWallet` computes on demand, so an address of
        its own chains that it has not been asked for yet is a miss.
        `address(branch, index)` is what puts one in, and
        `position_of(address)` answers whether it is reachable at all.
        """
        addr = _address_str(address)
        if addr not in self._handed_out:
            err_msg = f"address not in the wallet: {addr}"
            raise BTClibValueError(err_msg)
        return self._handed_out[addr]

    def _record(self, info: AddressInfo) -> str:
        """Take one address into the ledger, and return it."""
        self._handed_out[info.address] = info
        return info.address


class RangedWallet(Wallet, ABC):
    """A wallet whose outputs are computed from a branch and an index.

    Three methods are the subclass's to answer -- `branches`, the
    `_script_pub_key` at a position, and `is_watch_only` -- and the rest
    of the surface is written once, here, in terms of those.

    Idempotent, all of it: asking for the same position twice computes it
    twice and records it once, a wallet being a function of its source
    rather than a generator with a position of its own. What it does
    remember is how far it has been asked, which is what `next_address`
    reads.
    """

    def __init__(self, network: str = "mainnet") -> None:
        super().__init__(network)
        # branch -> the index `next_address` will hand out next, which is
        # one past the highest asked for so far and not a count of them:
        # `address(0, 7)` on a fresh wallet leaves the next at 8, so that
        # a wallet restored by replaying the positions it issued does not
        # reissue one
        self._next_index: dict[int, int] = {}

    @property
    @abstractmethod
    def branches(self) -> tuple[int, ...]:
        """The chains this wallet has outputs on, in ascending order.

        BIP44's two, `(0, 1)`, wherever the branch is a derivation step;
        whatever the descriptors were given under, where it is a label.
        `position_of` searches these and `address` refuses anything else,
        so this is also the wallet's answer to "which chains are there".
        """

    @abstractmethod
    def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
        """Return the output at a position, the position being checked."""

    def _address(self, branch: int, index: int) -> str:
        """Return the address of the output at a position.

        The script's own address, which is the answer wherever the script
        is what the wallet computes. A key wallet overrides it: `bip44`'s
        table is the library's one mapping from a key and a network to an
        address, and going through a script to reach the same string
        would be a second one.
        """
        return self._script_pub_key(branch, index).address

    def _der_path(self, branch: int, index: int) -> str:
        """Return the whole derivation path of the position, or "".

        Empty here, which is the honest answer for a wallet whose output
        names more than one key: `AddressInfo.der_path` is one path and
        there are several. A key wallet has exactly one and overrides it.
        """
        return ""

    def _assert_position(self, branch: int, index: int) -> None:
        """Refuse a position this wallet has no output at.

        The branch against `branches`, which is the one bound every
        subclass shares; the index only for the sign, its upper bound
        being the subclass's own -- 65535 from
        `bip32.derive_from_account` where the branch is derived, and
        BIP32's own limit where a descriptor derives it.
        """
        if branch not in self.branches:
            branches = ", ".join(str(b) for b in self.branches)
            err_msg = f"invalid branch: {branch} not in ({branches})"
            raise BTClibValueError(err_msg)
        if index < 0:
            raise BTClibValueError(f"invalid index: {index}")

    def script_pub_key(self, branch: int = 0, index: int = 0) -> ScriptPubKey:
        """Return the output this wallet pays to at a position."""
        self._assert_position(branch, index)
        return self._script_pub_key(branch, index)

    def redeem_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a p2sh output at this position commits to.

        BIP174's PSBT_IN_REDEEM_SCRIPT, and `b""` where the output is not
        a p2sh -- the empty answer being what "there is no such script"
        looks like everywhere else here, as `ScriptPubKey.address` is ""
        for a script with no address.
        """
        self._assert_position(branch, index)
        return b""

    def witness_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the script a p2wsh output at this position commits to.

        BIP174's PSBT_IN_WITNESS_SCRIPT, and `b""` where the output is
        not a p2wsh, wrapped in a p2sh or not.
        """
        self._assert_position(branch, index)
        return b""

    def address(self, branch: int = 0, index: int = 0) -> str:
        """Hand out the address at a position, and remember it.

        A script with no address raises rather than recording the ""
        that names it: a wallet handing out the empty string has handed
        out nothing, and `script_pub_key` is what such a wallet answers
        with.
        """
        self._assert_position(branch, index)
        address = self._address(branch, index)
        if not address:
            err_msg = f"no address for the script at {branch}/{index}:"
            err_msg += " script_pub_key is what this output has"
            raise BTClibValueError(err_msg)
        self._next_index[branch] = max(self._next_index.get(branch, 0), index + 1)
        return self._record(
            AddressInfo(
                address,
                self.script_type,
                self._der_path(branch, index),
                branch,
                index,
            )
        )

    def next_address(self, branch: int = 0) -> str:
        """Hand out the next address of a branch not yet asked for."""
        return self.address(branch, self._next_index.get(branch, 0))

    def position_of(
        self, script_pub_key: Octets | ScriptPubKey, last_index: int = _LAST_INDEX
    ) -> tuple[int, int] | None:
        """Return the position paying to this output, None where none is.

        What makes an output *this wallet's*, and the only thing that
        does: the script is computed at each position and compared whole.
        A key origin whose fingerprint matches is not an answer -- four
        bytes of a hash160 collide, and a psbt is written by whoever
        sends it, so an output marked as change on a fingerprint is an
        output a wallet may hand to somebody else believing it keeps it.

        The output is named however the caller holds it: the
        `ScriptPubKey` that `script_pub_key` returns, that script as
        bytes or as a hex-string, or the address it renders as -- "which
        position is this address" being the question a human has.
        Anything else raises, and so does a string that names no output,
        because None is not "you passed the wrong thing" here: it is
        *this output is not this wallet's*, which is the answer a caller
        acts on.

        `last_index` bounds the search of every branch, both ends
        included, and is the caller's: how far ahead of its own gap limit
        a wallet is willing to look is a policy this package has no view
        on. The branches are searched in `branches` order, one whole
        branch before the next, and the first match wins -- two positions
        paying to one script is a wallet whose source repeats itself, not
        something this has to choose between.
        """
        script = _validated_script_from(script_pub_key)
        for branch in self.branches:
            for index in range(last_index + 1):
                if self._script_pub_key(branch, index).script == script:
                    return branch, index
        return None

    def assert_derives(
        self,
        addresses: Sequence[Octets | ScriptPubKey],
        branch: int = 0,
        first_index: int = 0,
    ) -> None:
        """Refuse a span of outputs that is not what this branch derives.

        A list of addresses written down -- a whitelist, a monitor's
        import, the deposit block a counterparty was given -- read back
        against the wallet that is supposed to have derived it: the first
        one at `first_index`, the next at the index after it, and so on to
        the end of the span. What it catches is the list that was written
        under another key, or under this key before a threshold or a
        device changed it, or shifted by one position; and what makes it
        an answer rather than the same call twice is *when* it is asked --
        deriving a list and then checking it in the same breath says
        nothing, and asking it of the file an environment has been
        operating under says everything.

        Two refusals, and each is a different accident. An address that is
        not what the position derives names the position, what was
        written and what the wallet computes. Two positions deriving one
        output is a wallet whose script ignores its index -- a span that
        is then one address repeated, every one of them "correct" at the
        position it sits at -- which the comparison above cannot see and
        nothing downstream would either.

        An empty span is refused too: there is nothing to be right about,
        and a caller that has written an empty file has not written a
        span. Outputs are named however the caller holds them, as in
        `position_of`, and the wallet's ledger is left alone -- checking
        what was handed out is not handing it out again.
        """
        if not addresses:
            err_msg = f"no addresses to check against branch {branch}"
            raise BTClibValueError(err_msg)
        scripts = [
            self.script_pub_key(branch, first_index + offset).script
            for offset in range(len(addresses))
        ]
        if len(set(scripts)) != len(scripts):
            last_index = first_index + len(scripts) - 1
            err_msg = f"branch {branch} derives one output twice"
            err_msg += f" between {first_index} and {last_index}"
            raise BTClibValueError(err_msg)
        for offset, address in enumerate(addresses):
            script = _validated_script_from(address)
            if script != scripts[offset]:
                index = first_index + offset
                err_msg = f"not what {branch}/{index} derives: {script.hex()}"
                err_msg += f" is written where {scripts[offset].hex()} is derived"
                raise BTClibValueError(err_msg)
