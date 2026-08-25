# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which mnemonic scheme claims a sentence, and in what order.

btclib holds a validator for each scheme and had no entry point that
tries them, so a caller had to know the answer before it could ask the
question. The schemes overlap, too: the same twelve English words can be
a pre-2.0 Electrum seed, a versioned Electrum seed and a valid BIP39
mnemonic at once, and the three derive three different wallets.

The answers, one string each:

- "slip39" -- one SLIP-0039 share: every word in SLIP-0039's own
  1024-word list, a length it defines, and an RS1024 checksum that
  verifies. One share and not a set of them, a sentence at a time being
  all this is given; recovering the secret needs the threshold number of
  them, which is mnemonic.slip39's business and not this function's.
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

**Between the schemes** it is btclib's, none of them having an order to
copy: Electrum's wizard asks the user which variant a sentence is, and
validate_seed then dispatches on that answer instead of guessing. The
reason for the order is the base rate, and the principle is that the
rarer signal is the one carrying information about where a sentence came
from. A valid BIP39 checksum is present by chance in one twelve-word
sentence in sixteen. An Electrum version prefix is rarer, one sentence in
256 for "01" and one in 4096 for the three-nibble prefixes. A SLIP-0039
share is rarer again by orders of magnitude: 30 checksum bits over words
that must every one of them be among SLIP-0039's 1024, which is why it
goes first. The choice is not hidden either:
all_seed_types_from_mnemonic names every scheme that claims the sentence,
so a caller preferring another order has what it needs to take it.

**SLIP-0039 first is measured, not assumed**, and it is the one place
where the order changes an answer. Electrum's version check is an HMAC
over the sentence and consults no word-list at all, so it claims a share
whenever the HMAC happens to start "01": 80 of 20000 random 1-of-1
shares, one in 250, and 14 of the first 4000 were "electrum_standard"
with one "electrum_segwit". The reverse never happened -- 0 of 2000
Electrum seeds and 0 of 2000 BIP39 mnemonics read as a share -- because
1495 of BIP39's 2048 English words are absent from SLIP-0039's list, so a
sentence has to be built from that list to pass its checksum at all. Last
in the chain would therefore report one share in 250 as an Electrum seed
and hand the caller the wrong scheme, which is the failure "old before
standard" exists to prevent, one scheme further out.

Normalization is deliberately not done here. Each branch normalizes as
its own scheme defines -- Electrum's NFKD, lower-casing, accent dropping
and CJK rules inside electrum.py, BIP39's bare whitespace split inside
bip39.py -- so an upper-cased sentence is an Electrum seed and not a
BIP39 mnemonic. That is a difference between the two schemes as they
stand, not a decision taken here; what btclib should normalize, once and
for every scheme, is issue 201.

What "slip39" does not say is how many shares are wanted. A share names
its group and member thresholds, so the count is there to be read, but
reading one sentence cannot tell whether the others are to hand; that is
master_secret_from_mnemonics' answer, and it refuses a set that is short.
A restore flow asking this function what it has been handed gets the
scheme, and asks slip39 for the rest.
"""

from __future__ import annotations

from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, electrum, slip39
from btclib.mnemonic.mnemonic import Mnemonic, indexes_from_mnemonic

__all__ = [
    "all_seed_types_from_mnemonic",
    "seed_type_from_mnemonic",
]

# the sentence lengths BIP39 defines, and so the only ones it defines a
# checksum for
_BIP39_WORD_COUNTS = (12, 15, 18, 21, 24)


def _slip39_seed_type(mnemonic: Mnemonic) -> str:
    """Return "slip39" for one readable SLIP-0039 share, "" otherwise.

    share_from_mnemonic is the whole test: it checks the word count, looks
    every word up in SLIP-0039's list and verifies the RS1024 checksum,
    which is the same three things the other branches check for their own
    schemes. Asking it rather than repeating it is what keeps the two from
    disagreeing.

    No language parameter, unlike the BIP39 branch: SLIP-0039 defines one
    word-list and no localization, so there is nothing for a caller to
    choose.
    """
    try:
        slip39.share_from_mnemonic(mnemonic)
    except ValueError:
        # BTClibValueError for a bad checksum, length or field, and a
        # plain ValueError from list.index for a word that is not in the
        # list; BTClibValueError is a ValueError, so this catches both
        return ""
    return "slip39"


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
    Three entries at most: each of the three schemes answers at most once,
    Electrum resolving its own five against each other before it reports.

    The module docstring has the order and the measurements behind it.
    """
    seed_types = []

    if slip39_seed_type := _slip39_seed_type(mnemonic):
        seed_types.append(slip39_seed_type)

    try:
        version = electrum.version_from_mnemonic(mnemonic)[0]
    except BTClibValueError:
        pass
    else:
        seed_types.append(f"electrum_{version}")

    if bip39_seed_type := _bip39_seed_type(mnemonic, lang):
        seed_types.append(bip39_seed_type)

    return seed_types


def seed_type_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> str:
    """Return what the mnemonic is, "" if no scheme claims it.

    The first of all_seed_types_from_mnemonic, which is the answer the
    precedence in the module docstring picks. Where a sentence is claimed
    by more than one scheme this is the one that wins and the others are
    not mentioned, so a caller that has to know about the collision -- a
    restore flow, say, where the wrong choice is a wallet the user cannot
    see -- wants the plural function instead.
    """
    seed_types = all_seed_types_from_mnemonic(mnemonic, lang)
    return seed_types[0] if seed_types else ""
