# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Wallets: the addresses one is holding, and what each was computed from.

Three sources of addresses, one vocabulary over them, and the vocabulary
is the point: whatever a wallet computes its outputs from, it is asked
`address(branch, index)`, `script_pub_key(branch, index)`,
`next_address(branch)` and `position_of(script_pub_key)`, and it remembers
what it has handed out.

Four modules make it up, and each imports the ones before it and none
after:

- `wallet` is that vocabulary and holds no source of its own: `Wallet` is
  the ledger, and `RangedWallet` the half addressed by a branch and an
  index;
- `key_wallet` is the wallets whose output hashes one key -- `KeyWallet`
  for individual keys and `BIP32KeyWallet` for a BIP44 account -- and
  they are the two that can `sign(address, msg)`, a single key being a
  single thing to look up;
- `descriptor_wallet` is `DescriptorWallet`, one `Descriptor` per chain,
  which covers every script BIP380 to BIP390 can state, reads the whole
  pair off BIP389's ``<0;1>`` spelling, and delegates the spend to it;
- `script_wallet` is `ScriptWallet`, a script template with `KeyGroup`
  quorums in it, for the wallets no descriptor states -- and it imports
  `descriptor_wallet` not at all, a wallet of templates being no wallet of
  descriptors. What it does reach for is `btclib.descriptors`, one layer
  below both: `ScriptWallet.descriptor` lifts the script of a branch back
  into the expression it is, where there is one, so the wallets that
  turned out to have a descriptor after all can be handed to a monitor
  and the rest say so with `NoDescriptorError`.

The flat surface is this package's: the classes above are read off
`btclib.wallet`, the four modules being where they are written rather
than how they are reached.
"""

from btclib.wallet.descriptor_wallet import DescriptorWallet
from btclib.wallet.key_wallet import BIP32KeyWallet, KeyWallet
from btclib.wallet.script_wallet import KeyGroup, ScriptWallet
from btclib.wallet.wallet import AddressInfo, RangedWallet, Wallet

__all__ = [
    "AddressInfo",
    "BIP32KeyWallet",
    "DescriptorWallet",
    "KeyGroup",
    "KeyWallet",
    "RangedWallet",
    "ScriptWallet",
    "Wallet",
]
