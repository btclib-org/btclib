# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip39` module."""

import secrets
import unicodedata
from math import ceil
from unicodedata import normalize

import pytest

from btclib.bip32 import bip32
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import WORDLISTS, bip39, normalize_mnemonic
from btclib.mnemonic.mnemonic import WordLists
from tests import load, vector_id
from tests.mnemonic.mnemonic_test import fullwidth


def candidates(mnemonic: str) -> list[str]:
    """List the languages of the shipped word-lists that hold every word.

    A private WordLists and not the singleton bip39 reads: another test
    adds a language to that one, so a candidate list taken from it would
    depend on which test ran first.
    """
    return WordLists().langs_of_words(mnemonic.split())


def test_bip39() -> None:
    """Round-trip entropy and mnemonic; refuse a bad size or checksum."""
    lang = "en"
    mnem = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"

    raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
    mnemonic = bip39.mnemonic_from_entropy(raw_entr, lang)
    assert mnemonic == mnem

    r = bip39.entropy_from_mnemonic(mnemonic, lang)
    size = ceil(len(r) / 8)
    assert raw_entr == int(r, 2).to_bytes(size, byteorder="big", signed=False)

    wrong_mnemonic = f"{mnemonic} abandon"
    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.entropy_from_mnemonic(wrong_mnemonic, lang)

    err_msg = "invalid checksum: "
    with pytest.raises(BTClibValueError, match=err_msg):
        wr_m = "abandon abandon atom trust ankle walnut oil across awake bunker divorce oil"
        bip39.entropy_from_mnemonic(wr_m, lang)


# the language of each array of the reference implementation's vectors,
# by the ISO 639-1 code btclib keys its word-lists with
LANGUAGES = {
    "english": "en",
    "chinese_simplified": "zh",
    "chinese_traditional": "zh_tw",
    "czech": "cs",
    "french": "fr",
    "italian": "it",
    "japanese": "ja",
    "korean": "ko",
    "portuguese": "pt",
    "russian": "ru",
    "spanish": "es",
    "turkish": "tr",
}

VECTORS = load("mnemonic", "_data", "bip39_test_vectors.json", encoding="utf-8")

BIP39_VECTORS = [
    pytest.param(lang, *vector, id=vector_id(index, lang, vector[0]))
    for name, lang in LANGUAGES.items()
    for index, vector in enumerate(VECTORS[name])
]

# btclib's own case, and the only one not in the file: the last english
# vector again, its mnemonic respaced with everything split() treats as a
# separator -- doubled spaces, a tab, a newline, a CRLF, a form feed, a
# bare CR, and a run of spaces at each end. It is written here rather
# than appended to the vendored array so that the file stays upstream's
# bytes and a refresh stays a fetch; a case of ours inside it would have
# to be put back by hand every time, and would go missing the once
# nobody remembered
RESPACED = (
    " void come  effort suffer   camp survey\nwarrior heavy  shoot"
    " primary\tclutch crush\r\nopen amazing\fscreen patrol\rgroup space"
    " point ten exist slush involve unfold  "
)
ENTROPY, _, SEED, XPRV = VECTORS["english"][-1]
BIP39_VECTORS.append(
    pytest.param(
        "en",
        ENTROPY,
        RESPACED,
        SEED,
        XPRV,
        id=vector_id(len(VECTORS["english"]), "en", "respaced"),
    )
)


@pytest.mark.parametrize("lang, entr, mnemonic, seed, xprv", BIP39_VECTORS)
def test_vectors(lang: str, entr: str, mnemonic: str, seed: str, xprv: str) -> None:
    """BIP39 test vectors, all twelve languages of them.

    https://github.com/trezor/python-mnemonic/blob/master/vectors.json

    Upstream's arrays, in order and value for value: the vendored file is
    that file byte for byte, blob id included, and tests/_data/README.md
    pins the revision. The one case that is btclib's own is appended
    above, outside it.

    The sentence a vector holds is what the library is handed, the
    respaced one included: rejoining it here first would ask
    `" ".join(mnemonic.split())` whether it collapses whitespace, and
    never ask btclib. Only the *expected* sentence is rejoined, and on
    the language's own separator -- the ideographic space for japanese,
    which split() takes as whitespace, so a plain one would compare
    against a sentence upstream never wrote.
    """
    entropy = bytes.fromhex(entr)
    separator = "　" if lang == "ja" else " "
    assert separator.join(mnemonic.split()) == bip39.mnemonic_from_entropy(
        entropy, lang
    )
    assert seed == bip39.seed_from_mnemonic(mnemonic, "TREZOR").hex()

    raw_entr = bip39.entropy_from_mnemonic(mnemonic, lang)
    size = (len(raw_entr) + 7) // 8
    assert entropy == int(raw_entr, 2).to_bytes(size, byteorder="big", signed=False)
    assert bip32.rootxprv_from_seed(seed) == xprv
    # the language need not be named: the words say which it is, and the
    # four traditional-chinese vectors spelled entirely in characters
    # simplified chinese shares are the exception -- same words, same
    # indexes, same entropy, and no way to tell the two apart
    assert bip39.entropy_from_mnemonic(mnemonic) == raw_entr


JP_VECTORS = [
    pytest.param(vector, id=vector_id(index, vector["entropy"]))
    for index, vector in enumerate(
        load("mnemonic", "_data", "test_JP_BIP39.json", encoding="utf-8")
    )
]


@pytest.mark.parametrize("vector", JP_VECTORS)
def test_japanese_vectors(vector: dict[str, str]) -> None:
    """The japanese vectors BIP39 cites beside the reference implementation's.

    https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json

    "Japanese wordlist test with heavily normalized symbols as
    passphrase", says the BIP, and that is the whole point of them: the
    passphrase is `㍍ガバヴァぱばぐゞちぢ十人十色`, whose NFKD form is
    another string entirely, so a seed derived without normalizing the
    passphrase is a different seed. The sentences are published NFC, the
    word-lists are NFKD, and both spellings have to read as one mnemonic.
    """
    mnemonic = vector["mnemonic"]
    assert mnemonic != normalize("NFKD", mnemonic)
    generated = bip39.mnemonic_from_entropy(bytes.fromhex(vector["entropy"]), "ja")
    assert normalize("NFKD", generated) == normalize("NFKD", mnemonic)

    seed = bip39.seed_from_mnemonic(mnemonic, vector["passphrase"])
    assert seed.hex() == vector["seed"]
    assert bip32.rootxprv_from_seed(seed) == vector["bip32_xprv"]
    assert bip39.lang_from_mnemonic(mnemonic) == "ja"
    assert bip39.entropy_from_mnemonic(mnemonic) == bip39.entropy_from_mnemonic(
        generated, "ja"
    )


def test_lang_from_mnemonic() -> None:
    """What the words say the language is, and when they do not say."""
    entropy = bytes.fromhex("0000003974d093eda670121023cd0000")
    for lang in ("cs", "en", "es", "fr", "it", "ja", "ko", "pt", "ru", "tr", "zh_tw"):
        mnemonic = bip39.mnemonic_from_entropy(entropy, lang)
        assert bip39.lang_from_mnemonic(mnemonic) == lang

    # a word in no word-list at all
    err_msg = "unknown language for mnemonic: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.lang_from_mnemonic("btclib " * 11 + "btclib")

    # NFC in, NFKD word-list: the same mnemonic, and the same language
    spanish = bip39.mnemonic_from_entropy(entropy, "es")
    assert normalize("NFC", spanish) != spanish
    assert bip39.lang_from_mnemonic(normalize("NFC", spanish)) == "es"
    assert bip39.entropy_from_mnemonic(normalize("NFC", spanish)) == (
        bip39.entropy_from_mnemonic(spanish, "es")
    )


def test_ambiguous_language() -> None:
    """Two word-lists holding every word, and what settles it.

    English and french share a hundred words, at a different index in
    each: a sentence built from those alone is a mnemonic in both
    languages and spells a different entropy in each, so there is nothing
    to return. Found by search, one in 256 of the sentences over the
    shared words being valid in both.
    """
    ambiguous = (
        "nature distance angle abandon simple palace opinion fatigue "
        "noble volume simple wagon"
    )
    assert candidates(ambiguous) == ["en", "fr"]
    en = bip39.entropy_from_mnemonic(ambiguous, "en")
    assert en != bip39.entropy_from_mnemonic(ambiguous, "fr")
    with pytest.raises(BTClibValueError, match="ambiguous language for mnemonic: "):
        bip39.lang_from_mnemonic(ambiguous)

    # the same hundred words, and a checksum that is valid in one of the
    # two: that is the sentence the second step is there for
    english = (
        "service canal fruit exact essence virus angle brave "
        "fragile miracle noble festival"
    )
    assert candidates(english) == ["en", "fr"]
    assert bip39.lang_from_mnemonic(english) == "en"
    assert bip39.entropy_from_mnemonic(english)

    # valid in neither is not that case: the language is not what is
    # wrong with the sentence, so the checksum is what the caller hears
    invalid = (
        "exact aspect caution nation mobile brave fatigue caution "
        "puzzle muscle bonus relief"
    )
    assert candidates(invalid) == ["en", "fr"]
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        bip39.entropy_from_mnemonic(invalid)


def test_chinese_is_ambiguous_and_answerable() -> None:
    """The two chinese word-lists are aligned, so an ambiguity is not one.

    All 1275 words Simplified and Traditional share sit at the same index
    in both files. A sentence spelled in shared characters alone is
    therefore a mnemonic in both languages carrying one entropy, which is
    why lang_from_mnemonic answers instead of refusing -- and why the
    answer is "zh" for a sentence a Traditional reader wrote.
    """
    word_lists = WordLists()
    simplified = word_lists.wordlist("zh")
    traditional = word_lists.wordlist("zh_tw")
    shared = [w for w in simplified if w in traditional]
    assert len(shared) == 1275
    assert all(simplified.index(w) == traditional.index(w) for w in shared)

    # a traditional-chinese vector spelled in shared characters alone
    mnemonic = "的 的 的 的 的 的 的 的 的 的 的 在"
    assert candidates(mnemonic) == ["zh", "zh_tw"]
    assert bip39.lang_from_mnemonic(mnemonic) == "zh"
    assert bip39.entropy_from_mnemonic(mnemonic) == "0" * 128


def test_mnemonic_from_entropy() -> None:
    """Accept entropy with a leading zero bit, and none at all."""
    # zero leading bit should not throw an error
    bip39.mnemonic_from_entropy(secrets.randbits(127), "en")
    # random mnemonic
    bip39.mnemonic_from_entropy()


# BIP39's japanese vectors, from bip32JP/bip32JP.github.io's
# test_JP_BIP39.json, the file bip-0039.mediawiki links as the japanese
# test vectors. Two of the twenty-four inline, the first and the last:
# what they pin is the NFKD, and two pin it as well as twenty-four would.
#
# The words are joined here rather than written as one string, because
# the separator is the point: U+3000 IDEOGRAPHIC SPACE is what the
# vectors put between words, and NFKD is what makes it U+0020 -- so a
# separator BIP39 never names is handled by the normalization BIP39 does.
#
# The passphrase is the vectors' own and decomposes twice over: U+334D
# SQUARE MEETORU is a compatibility character NFKD expands to four kana,
# and the voiced kana carry dakuten that separate from the kana they sit
# on. Without the NFKD BIP39 mandates, all twenty-four seeds come out
# wrong while every english vector still passes, "TREZOR" and
# `english.txt` being ASCII, which is NFKD already.
#
# S105 reads the name and sees a hardcoded password: it is one, and it is
# a published test vector guarding no wallet. Renaming it around the
# check would cost the reader the one word that says what BIP39 does with
# the string
JAPANESE_PASSPHRASE = "㍍ガバヴァぱばぐゞちぢ十人十色"  # noqa: S105

JAPANESE_VECTORS = [
    pytest.param(
        ["あいこくしん"] * 11 + ["あおぞら"],
        "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c"
        "467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        "xprv9s21ZrQH143K258jAiWPAM6JYT9hLA91MV3AZUKfxmLZJCjCHeSjBvMbDy8C1mJ2FL5ytExyS97FAe6pQ6SD5Jt9SwHaLorA8i5Eojokfo1",
        id="jp-0",
    ),
    pytest.param(
        [
            "うちゅう",
            "ふそく",
            "ひしょ",
            "がちょう",
            "うけもつ",
            "めいそう",
            "みかん",
            "そざい",
            "いばる",
            "うけとる",
            "さんま",
            "さこつ",
            "おうさま",
            "ぱんつ",
            "しひょう",
            "めした",
            "たはつ",
            "いちぶ",
            "つうじょう",
            "てさぎょう",
            "きつね",
            "みすえる",
            "いりぐち",
            "かめれおん",
        ],
        "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d"
        "3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        "xprv9s21ZrQH143K2qVq43Phs1xyVc6jSxXHWJ6CDJjod3cgyEin7hgeQV6Dkw6s1LSfMYxoah4bPAnW4wmXfDUS9ghBEM18xoY634CBtX8HPrA",
        id="jp-23",
    ),
]


@pytest.mark.parametrize("words, seed, xprv", JAPANESE_VECTORS)
def test_nfkd_japanese_vectors(words: list[str], seed: str, xprv: str) -> None:
    """BIP39 stretches the NFKD of the sentence and of the passphrase.

    The checksum goes unverified because there is no japanese word-list
    to verify it against -- btclib ships english and italian -- which is
    why these are a seed test and not a round trip. The seed is what the
    normalization decides, so nothing is lost.
    """
    mnemonic = "　".join(words)
    assert bip39.seed_from_mnemonic(mnemonic, JAPANESE_PASSPHRASE, False).hex() == seed
    assert bip32.rootxprv_from_seed(seed) == xprv

    # the ideographic separator is not privileged: an ASCII space, a
    # newline or a doubled U+3000 is the same sentence and the same seed
    for separator in (" ", "\n", "　　", " \t"):
        respaced = separator.join(words)
        assert (
            bip39.seed_from_mnemonic(respaced, JAPANESE_PASSPHRASE, False).hex() == seed
        )

    # and the passphrase is normalized where it stands: handing over the
    # decomposition BIP39 asks for reaches the same seed, which is the
    # whole claim
    decomposed = unicodedata.normalize("NFKD", JAPANESE_PASSPHRASE)
    assert decomposed != JAPANESE_PASSPHRASE
    assert bip39.seed_from_mnemonic(mnemonic, decomposed, False).hex() == seed

    # the passphrase's own whitespace is content, not a separator: a
    # doubled space in it is a different passphrase and must not collapse
    spaced = f"{JAPANESE_PASSPHRASE}  x"
    collapsed = f"{JAPANESE_PASSPHRASE} x"
    assert bip39.seed_from_mnemonic(
        mnemonic, spaced, False
    ) != bip39.seed_from_mnemonic(mnemonic, collapsed, False)


def test_nfkd_fullwidth_latin() -> None:
    """A japanese IME types english words in fullwidth latin.

    U+FF41 is not "a" until NFKD decomposes it, so without the
    normalization the word-list lookup fails and a mnemonic a user can
    read back to themselves is refused.
    """
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    wide = " ".join(fullwidth(word) for word in mnemonic.split())
    assert wide != mnemonic
    assert normalize_mnemonic(wide) == mnemonic
    assert bip39.entropy_from_mnemonic(wide) == bip39.entropy_from_mnemonic(mnemonic)
    assert bip39.seed_from_mnemonic(wide, "") == bip39.seed_from_mnemonic(mnemonic, "")
    assert bip39.mxprv_from_mnemonic(wide) == bip39.mxprv_from_mnemonic(mnemonic)


def test_mxprv_from_mnemonic() -> None:
    """Reproduce the rootxprv a known mnemonic derives to."""
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "")
    exp = "xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert rootxprv == exp


def test_the_wordlist_has_to_be_bip39_sized() -> None:
    """WORDLISTS is shared, and only its 2048-word lists are BIP39's.

    slip39 is registered on the same registry, so lang="slip39" is a
    request bip39 can be given; 1024 words encode ten bits each, and
    answering would be a base-1024 sentence no BIP39 wallet reads. The
    power-of-two test inside load_lang does not catch it -- 1024 is one.
    """
    assert WORDLISTS.language_length("slip39") == 1024

    err_msg = "invalid bip39 wordlist length: 1024; expected: 2048"
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.mnemonic_from_entropy(bytes.fromhex("00" * 16), "slip39")

    # a sentence of slip39 words, so that the refusal is the word-list
    # length and not an unknown word
    mnemonic = " ".join(WORDLISTS.wordlist("slip39")[:12])
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.entropy_from_mnemonic(mnemonic, "slip39")
