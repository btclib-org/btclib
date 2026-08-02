#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Which mnemonic scheme claims a sentence, and in what order.

btclib holds a validator for each scheme and had no entry point that
tries them, so a caller had to know the answer before it could ask the
question. The schemes overlap, too: the same twelve English words can be
a pre-2.0 Electrum seed, a versioned Electrum seed and a valid BIP39
mnemonic at once, and the three derive three different wallets.

The answers, one string each:

- "electrum_old", "electrum_standard", "electrum_segwit",
  "electrum_2fa", "electrum_2fa_segwit" -- the five Electrum reports.
  Prefixed, because "standard" says nothing once BIP39 is in the running.
- "bip39" -- every word in the list, a length BIP39 defines, and a
  checksum that verifies.
- "bip39_wordlist" -- every word in the list and nothing else true: the
  checksum failed, or the word count is not one of BIP39's five. Kept
  apart from "" rather than folded into it because it is exactly what
  bip39.mxprv_from_mnemonic reads with verify_checksum=False, and
  Electrum's own wizard accepts it as BIP39 too (spesmilo/electrum#8720).
- "" -- no scheme claims it.

Expect "bip39_wordlist" beside most English Electrum seeds, and read
nothing into it: Electrum's english.txt is BIP39's, byte for byte, so
every word of an English Electrum seed is a BIP39 word and only the
checksum says no. The overlap worth noticing is "bip39" beside an
Electrum type, which is one sentence that two schemes both read as
valid and derive two different wallets from.

The order is Electrum's where Electrum has one, and btclib's where it
does not, and the two halves are worth telling apart.

**Within Electrum** it is calc_seed_type's chain: "old" first, then the
version prefixes "01", "100", "101" (twelve words, or twenty and up) and
"102". Upstream's, and implemented by electrum.version_from_mnemonic
rather than again here. Old first is the load-bearing part -- a pre-2.0
seed carries no version prefix and can match one by chance, and calling
it "standard" would hand back the wrong derivation without a word.

**Electrum before BIP39** is btclib's, Electrum having no such order to
copy: its wizard asks the user which variant a sentence is, and
validate_seed then dispatches on that answer instead of guessing. The
reason for this order is the base rate. An Electrum version prefix is a
deliberate marker, present by chance in one sentence in 256 for "01" and
one in 4096 for the three-nibble prefixes, while a valid BIP39 checksum
is present by chance in one twelve-word sentence in sixteen; the rarer
signal is the one carrying information about where a sentence came from.
The choice is not hidden either: all_seed_types_from_mnemonic names every
scheme that claims the sentence, so a caller preferring the other order
has what it needs to take it.

Normalization is deliberately not done here. Each branch normalizes as
its own scheme defines -- Electrum's NFKD, lower-casing, accent dropping
and CJK rules inside electrum.py, BIP39's bare whitespace split inside
bip39.py -- so an upper-cased sentence is an Electrum seed and not a
BIP39 mnemonic. That is a difference between the two schemes as they
stand, not a decision taken here; what btclib should normalize, once and
for every scheme, is issue 201.

SLIP-0039 is the third member of the family, and mnemonic.slip39 reads
and writes it -- but this dispatcher does not ask it yet, so a share is
reported as unknown. Wiring it in is a decision and not an omission:
what a share is claimed *as* has to be settled first, a single share
being a share of a secret rather than a sentence that derives a wallet
on its own. The place it goes is the end of the chain, after BIP39; a
share carries none of the signals above -- its words come from
SLIP-0039's own 1024-word list, so no Electrum prefix and no BIP39
word-list test can match one -- which is why the order costs nothing
either way.
"""

from __future__ import annotations

from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, electrum
from btclib.mnemonic.mnemonic import Mnemonic, indexes_from_mnemonic

# the sentence lengths BIP39 defines, and so the only ones it defines a
# checksum for
_BIP39_WORD_COUNTS = (12, 15, 18, 21, 24)


def _bip39_seed_type(mnemonic: Mnemonic, lang: str) -> str:
    """Return "bip39", "bip39_wordlist" or "" for the sentence.

    The three answers are the two booleans of Electrum's
    bip39_is_checksum_valid, (is_checksum_valid, is_wordlist_valid),
    written as one string: (True, True), (False, True) and (False,
    False). Electrum reports the middle one for a wrong checksum and for
    a word count outside BIP39's five alike, and so does this.
    """
    words = mnemonic.split()
    if not words:
        # the word-list test is vacuously true of no words at all, so the
        # empty string would otherwise be "bip39_wordlist". Electrum
        # rejects it as its own case in validate_seed for the same reason
        return ""
    try:
        indexes_from_mnemonic(mnemonic, lang)
    except ValueError:
        # list.index raises a plain ValueError for a word that is not in
        # the word-list, and BTClibValueError is one, so this catches the
        # unknown word and the unknown language together
        return ""
    if len(words) not in _BIP39_WORD_COUNTS:
        return "bip39_wordlist"
    try:
        bip39.entropy_from_mnemonic(mnemonic, lang)
    except BTClibValueError:
        return "bip39_wordlist"
    return "bip39"


def all_seed_types_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> list[str]:
    """Return every seed type that claims the mnemonic, best first.

    The list is empty when nothing claims it, and holds more than one
    entry when the schemes overlap -- which is the case worth seeing,
    since seed_type_from_mnemonic can only answer with the first of them.
    Two entries at most today: Electrum resolves its own five against
    each other before answering, so at most one of those appears, and
    BIP39 gives at most one answer of its own.

    The module docstring has the order and where each half of it comes
    from.
    """
    seed_types = []

    try:
        version = electrum.version_from_mnemonic(mnemonic)[0]
    except BTClibValueError:
        pass
    else:
        seed_types.append(f"electrum_{version}")

    if bip39_seed_type := _bip39_seed_type(mnemonic, lang):
        seed_types.append(bip39_seed_type)

    # SLIP-0039 goes here, after BIP39 and last; the module docstring has
    # why mnemonic.slip39 is not asked yet
    return seed_types


def seed_type_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> str:
    """Return what the mnemonic is, "" if no scheme claims it.

    The first of all_seed_types_from_mnemonic, which is the answer the
    precedence in the module docstring picks. Where a sentence is claimed
    by two schemes this is the one that wins and the other is not
    mentioned, so a caller that has to know about the collision -- a
    restore flow, say, where the wrong choice is a wallet the user cannot
    see -- wants the plural function instead.
    """
    seed_types = all_seed_types_from_mnemonic(mnemonic, lang)
    return seed_types[0] if seed_types else ""
