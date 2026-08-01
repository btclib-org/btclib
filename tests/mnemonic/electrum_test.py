#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.electrum` module.

Most of the vectors here are electrum's own, from `spesmilo/electrum`'s
`tests/test_mnemonic.py` and `tests/test_wallet_vertical.py`, because the
question this module answers is whether btclib agrees with electrum and
nothing btclib generates can settle that. They are inline rather than in
`tests/mnemonic/_data`: each block is small, and a citation two lines
above the values it names is one a reader checks.

The exceptions are named where they appear: the collisions of
`test_skipped_candidates` are btclib's own, no upstream having a vector
for a candidate electrum passes over, and `electrum_test_vectors.json`
has no upstream at all.
"""

import pytest

from btclib.bip32 import bip32, slip132
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, electrum
from btclib.network import NETWORKS
from tests import load, vector_id

# the passphrase electrum stretches its japanese vector with, kept as the
# hex electrum states it in: an editor that normalizes or reflows the
# characters would change the seed and the vector would be testing btclib
# against btclib
UNICODE_HORROR = bytes.fromhex(
    "e282bf20f09f988020f09f98882020202020e3818620e38191e3819fe381be20"
    "e3828fe3828b2077cda2cda2cd9d68cda16fcda2cda120ccb8cda26bccb5cd9f"
    "6eccb4cd98c7ab77ccb8cc9b73cd9820cc80cc8177cd98cda2e1b8a9ccb561d2"
    "89cca1cda27420cca7cc9568cc816fccb572cd8fccb5726f7273cca120ccb6cd"
    "a1cda06cc4afccb665cd9fcd9f20ccb6cd9d696ecda220cd8f74cc9568ccb7cc"
    "a1cd9f6520cd9fcd9f64cc9b61cd9c72cc95cda16bcca2cca820cda168ccb465"
    "cd8f61ccb7cca2cca17274cc81cd8f20ccb4ccb7cda0c3b2ccb5ccb666ccb820"
    "75cca7cd986ec3adcc9bcd9c63cda2cd8f6fccb7cd8f64ccb8cda265cca1cd9d"
    "3fcd9e"
).decode()

JAPANESE = "なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん"
CHINESE = "眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬"
SPANISH = (
    "almíbar tibio superar vencer hacha peatón príncipe matar consejo "
    "polen vehículo odisea"
)

ENGLISH = (
    "wild father tree among universe such mobile favorite target "
    "dynamic credit identify"
)

# electrum's SEED_TEST_CASES. ja, zh and es are here although btclib ships
# no word-list for either of the three: a seed is a normalization and a
# PBKDF2, neither of which needs one, and these are the cases that make
# the normalization visible -- the CJK ones have their words joined, the
# Spanish ones have their accents dropped, and none of them would survive
# a bare whitespace clean
SEED_VECTORS = [
    pytest.param(
        ENGLISH,
        "",
        "segwit",
        "aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e306"
        "4342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756",
        id="english",
    ),
    pytest.param(
        ENGLISH,
        "Did you ever hear the tragedy of Darth Plagueis the Wise?",
        "segwit",
        "4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370"
        "f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f",
        id="english-passphrase",
    ),
    pytest.param(
        JAPANESE,
        "",
        "standard",
        "d3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b3"
        "5cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad",
        id="japanese",
    ),
    pytest.param(
        JAPANESE,
        UNICODE_HORROR,
        "standard",
        "251ee6b45b38ba0849e8f40794540f7e2c6d9d604c31d68d3ac50c034f8b64e4"
        "bc037c5e1e985a2fed8aad23560e690b03b120daf2e84dceb1d7857dda042457",
        id="japanese-unicode-horror",
    ),
    pytest.param(
        CHINESE,
        "",
        "segwit",
        "0b9077db7b5a50dbb6f61821e2d35e255068a5847e221138048a20e12d80b673"
        "ce306b6fe7ac174ebc6751e11b7037be6ee9f17db8040bb44f8466d519ce2abf",
        id="chinese",
    ),
    pytest.param(
        CHINESE,
        "给我一些测试向量谷歌",
        "segwit",
        "6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b"
        "8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71",
        id="chinese-passphrase",
    ),
    pytest.param(
        SPANISH,
        "",
        "standard",
        "18bffd573a960cc775bbd80ed60b7dc00bc8796a186edebe7fc7cf1f316da0fe"
        "937852a969c5c79ded8255cdf54409537a16339fbe33fb9161af793ea47faa7a",
        id="spanish",
    ),
    pytest.param(
        SPANISH,
        "araña difícil solución término cárcel",
        "standard",
        "363dec0e575b887cfccebee4c84fca5a3a6bed9d0e099c061fa6b85020b031f8"
        "fe3636d9af187bf432d451273c625e20f24f651ada41aae2c4ea62d87e9fa44c",
        id="spanish-passphrase",
    ),
    pytest.param(
        "equipo fiar auge langosta hacha calor trance cubrir carro pulmón oro áspero",
        "",
        "segwit",
        "001ebce6bfde5851f28a0d44aae5ae0c762b600daf3b33fc8fc630aee0d20764"
        "6b6f98b18e17dfe3be0a5efe2753c7cdad95860adbbb62cecad4dedb88e02a64",
        id="spanish-segwit",
    ),
    pytest.param(
        "vidrio jabón muestra pájaro capucha eludir feliz rotar fogata pez rezar oír",
        "¡Viva España! repiten veinte pueblos y al hablar dan fe del "
        "ánimo español... ¡Marquen arado martillo y clarín",
        "segwit",
        "c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3a"
        "ab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f",
        id="spanish-segwit-passphrase",
    ),
]

# electrum's Test_seeds.mnemonics, the table its calc_seed_type is
# measured against: "" is "electrum would not read this at all". Every
# case that differs from another by case or by whitespace alone is there
# on purpose -- it is the normalization under test
VERSION_VECTORS = [
    pytest.param(
        "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze",
        "old",
        id="old",
    ),
    pytest.param("cell dumb heartbeat north boom tease " * 4, "old", id="old-24-words"),
    pytest.param(
        "cell dumb heartbeat north boom tease ship baby bright kingdom rare badword",
        "",
        id="old-one-word-off-the-list",
    ),
    pytest.param(
        "cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE",
        "old",
        id="old-mixed-case",
    ),
    pytest.param(
        "   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt "
        "kInGdOm rArE SqUeEzE   ",
        "old",
        id="old-mixed-case-and-whitespace",
    ),
    pytest.param(
        # electrum calls this one "invalid old": it maps to 33 hex
        # characters, which the old decoder is too weak to notice
        "hurry idiot prefer sunset mention mist jaw inhale impossible "
        "kingdom rare squeeze",
        "old",
        id="old-invalid",
    ),
    pytest.param(
        "cram swing cover prefer miss modify ritual silly deliver chunk "
        "behind inform able",
        "standard",
        id="standard-13-words",
    ),
    pytest.param(
        "cram swing cover prefer miss modify ritual silly deliver chunk behind inform",
        "",
        id="standard-13-words-less-one",
    ),
    pytest.param(
        "ostrich security deer aunt climb inner alpha arm mutual marble solid task",
        "standard",
        id="standard",
    ),
    pytest.param(
        "OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK",
        "standard",
        id="standard-upper-case",
    ),
    pytest.param(
        "   oStRiCh sEcUrItY DeEr aUnT ClImB       InNeR AlPhA ArM "
        "MuTuAl mArBlE   SoLiD TaSk  ",
        "standard",
        id="standard-mixed-case-and-whitespace",
    ),
    pytest.param(
        "science dawn member doll dutch real can brick knife deny drive list",
        "2fa",
        id="2fa",
    ),
    pytest.param(
        "science dawn member doll dutch real ca brick knife deny drive list",
        "",
        id="2fa-one-letter-off",
    ),
    pytest.param(
        " sCience dawn   member doll Dutch rEAl can brick knife deny drive  lisT",
        "2fa",
        id="2fa-mixed-case-and-whitespace",
    ),
    pytest.param(
        # pre-2.7 "2fa", 25 words and then 24: the prefix is the same as
        # the 12-word one and the count is all that tells them apart
        "bind clever room kidney crucial sausage spy edit canvas soul "
        "liquid ribbon slam open alpha suffer gate relax voice carpet law "
        "hill woman tonight abstract",
        "2fa",
        id="2fa-25-words",
    ),
    pytest.param(
        "sibling leg cable timber patient foot occur plate travel finger "
        "chef scale radio citizen promote immune must chef fluid sea "
        "sphere common acid lab",
        "2fa",
        id="2fa-24-words",
    ),
    pytest.param(
        "frost pig brisk excite novel report camera enlist axis nation novel desert",
        "segwit",
        id="segwit",
    ),
    pytest.param(
        "  fRoSt pig brisk excIte novel rePort CamEra enlist axis nation nOVeL dEsert ",
        "segwit",
        id="segwit-mixed-case-and-whitespace",
    ),
    # electrum's "short seed cheat sheet": a version prefix is all a new
    # seed needs, so two words are a seed and so is one non-word
    pytest.param("x8", "standard", id="standard-short"),
    pytest.param("9dk", "segwit", id="segwit-short"),
    pytest.param("abandon bike", "segwit", id="segwit-two-words"),
    pytest.param("6vs", "2fa_segwit", id="2fa-segwit-short"),
    pytest.param("agree install", "2fa_segwit", id="2fa-segwit-two-words"),
]


def test_mnemonic() -> None:
    lang = "en"

    entropy = 0x110AAAA03974D093EDA670121023CD0772
    mnemonic_type = "standard"
    mnemonic = (
        "diagram crouch ball canal then hat panda spatial company "
        "liberty fetch awful ability"
    )
    assert electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang) == mnemonic

    # what the mnemonic encodes is the entropy the search stopped at, so
    # it is above the one handed in and generating from it again would
    # walk on from there: entropy + 1 is the first candidate, never the
    # entropy itself
    entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
    assert entr == 0x110AAAA03974D093EDA670121023CD09E7
    assert electrum.mnemonic_from_entropy(mnemonic_type, entr - 1, lang) == mnemonic

    xprv = "xprv9s21ZrQH143K2ASM657UjJdfQ83QaZcdZ1RVsmMbcZxTA3eyQP1arqav4L9TVQz1tf2kXhwy87vAxjngxL61rudpNqyDvtJv8LCxmzNrM2U"
    assert electrum.mxprv_from_mnemonic(mnemonic) == xprv

    mnemonic_type = "std"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)

    unkn_ver = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.entropy_from_mnemonic(unkn_ver, lang)

    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.mxprv_from_mnemonic(unkn_ver)

    # a twelve-word entropy, which is what "2fa" needs: see test_2fa_words
    entropy = 0x110AAAA03974D093EDA670121023CD077
    for mnemonic_type in ("2fa", "2fa_segwit"):
        mnemonic = electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)
        assert electrum.version_from_mnemonic(mnemonic)[0] == mnemonic_type
        with pytest.raises(
            BTClibValueError, match="unmanaged electrum mnemonic version: "
        ):
            electrum.mxprv_from_mnemonic(mnemonic)


def test_word_order() -> None:
    """The words run least-significant first, electrum's order, not BIP39's.

    The vector is electrum's own english seed, and the two directions are
    checked against each other: the integer it decodes to, and the fact
    that starting the search one below that integer lands back on it with
    the first candidate it tries.
    """
    entr = int(electrum.entropy_from_mnemonic(ENGLISH, "en"), 2)
    assert entr == 0x708661136EF5411CF61F6E07FCFD4EFD8
    assert electrum.mnemonic_from_entropy("segwit", entr - 1, "en") == ENGLISH

    # BIP39's order over the same words decodes to something else
    # entirely, which is the whole of issue 196. The public function
    # cannot be asked: the reversed sentence hashes to no version prefix,
    # so it is not an electrum mnemonic at all and is refused before it
    # is ever decoded
    reversed_mnemonic = " ".join(reversed(ENGLISH.split()))
    reversed_entr = electrum._bin_str_entropy_from_mnemonic(reversed_mnemonic, "en")
    assert int(reversed_entr, 2) == 0xFB0A779F83FEDDB0E39AA0DDE898CC384


@pytest.mark.parametrize(("mnemonic", "passphrase", "version", "seed"), SEED_VECTORS)
def test_seed_vectors(mnemonic: str, passphrase: str, version: str, seed: str) -> None:
    assert electrum._seed_from_mnemonic(mnemonic, passphrase) == (
        version,
        bytes.fromhex(seed),
    )


@pytest.mark.parametrize(("mnemonic", "version"), VERSION_VECTORS)
def test_version_vectors(mnemonic: str, version: str) -> None:
    if not version:
        with pytest.raises(
            BTClibValueError, match="unknown electrum mnemonic version: "
        ):
            electrum.version_from_mnemonic(mnemonic)
    else:
        assert electrum.version_from_mnemonic(mnemonic)[0] == version


def test_old_mnemonic() -> None:
    """A pre-2.0 seed is reported as "old", and nothing more is done with it.

    The cases are electrum's is_old_seed tests. The point of recognizing
    the scheme without implementing it is that an old seed derives keys
    another way: reporting it as one of the four new versions would be
    handing back the wrong wallet without a word.
    """
    assert electrum.version_from_mnemonic(" ".join(["like"] * 12))[0] == "old"
    assert electrum.version_from_mnemonic(" ".join(["like"] * 24))[0] == "old"
    # a 16- or 32-byte hex string is an old seed too, entropy having been
    # written out rather than encoded before the word list existed
    assert electrum.version_from_mnemonic("0123456789ABCDEF" * 2)[0] == "old"
    assert electrum.version_from_mnemonic("0123456789ABCDEF" * 4)[0] == "old"

    # eighteen words is not an old seed, whatever the words are
    for mnemonic in (" ".join(["like"] * 18), "not a seed"):
        with pytest.raises(
            BTClibValueError, match="unknown electrum mnemonic version: "
        ):
            electrum.version_from_mnemonic(mnemonic)

    old = "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze"
    with pytest.raises(BTClibValueError, match="pre-2.0 electrum mnemonic: "):
        electrum.entropy_from_mnemonic(old)
    with pytest.raises(BTClibValueError, match="unmanaged electrum mnemonic version: "):
        electrum.mxprv_from_mnemonic(old)


def test_skipped_candidates() -> None:
    """The two candidates electrum passes over, and what it returns instead.

    Both mnemonics below carry the "standard" prefix, so a search that
    only checked the prefix would return them; electrum does not, and a
    btclib that did would produce a different wallet from the same
    entropy. They are btclib's own, found by searching for the collision
    -- an old-seed one arises about once in thirty thousand generated
    mnemonics and a BIP39 one about once in sixteen, so neither is
    reachable by generating vectors and waiting.
    """
    # every word is in electrum's pre-2.0 list, so this reads as "old"
    # despite the prefix, and the search steps over it
    old_collision = (
        "control age around curtain wall velvet limb sadness struggle orange slice yard"
    )
    assert electrum.version_from_mnemonic(old_collision)[0] == "old"
    entr = 0xFED96E6F6BABDF03BC87B53621841317B
    assert electrum.mnemonic_from_entropy("standard", entr - 1, "en") == (
        "fuel age around curtain wall velvet limb sadness struggle orange slice yard"
    )

    # a valid BIP39 mnemonic that is also a "standard" electrum one: read
    # back it is a standard seed, but generating it would hand the user a
    # sentence two wallets answer to, so the search steps over it as well
    bip39_collision = (
        "park leaf system perfect top lecture rather foster best nest craft topic"
    )
    assert electrum.version_from_mnemonic(bip39_collision)[0] == "standard"
    assert bip39.entropy_from_mnemonic(bip39_collision)
    entr = 0xE50642520AA5C1649FC727A31B99FAD02
    assert electrum.mnemonic_from_entropy("standard", entr - 1, "en") == (
        "stamp leaf system perfect top lecture rather foster best nest craft topic"
    )


def test_2fa_words() -> None:
    """ "2fa" wants twelve words or twenty, and a search can end elsewhere.

    Electrum closes make_seed by asking what it would read the sentence
    back as, and this is the case where the answer is "nothing": the
    prefix is right and the word count is not, so the seed type it asked
    for is not the seed type it built.
    """
    # thirteen words' worth of entropy
    with pytest.raises(BTClibValueError, match="electrum mnemonic version: "):
        electrum.mnemonic_from_entropy(
            "2fa", 0x110AAAA03974D093EDA670121023CD0772, "en"
        )

    # the candidate that search stopped at, carrying the "2fa" prefix and
    # the wrong number of words
    thirteen_words = (
        "ginger crouch ball canal then hat panda spatial company liberty "
        "fetch awful ability"
    )
    assert electrum._seed_version(thirteen_words).startswith("101")
    with pytest.raises(BTClibValueError, match="unknown electrum mnemonic version: "):
        electrum.version_from_mnemonic(thirteen_words)


def test_italian() -> None:
    """Italian is btclib's own extension, and it round-trips.

    Electrum reads en, es, ja, pt and zh_simplified, so a mnemonic
    generated here in Italian is one electrum cannot read at all. The
    module docstring says so; this pins the behaviour rather than the
    parity, there being nothing to be in parity with.
    """
    entropy = 0x110AAAA03974D093EDA670121023CD0772
    mnemonic = electrum.mnemonic_from_entropy("standard", entropy, "it")
    assert mnemonic == (
        "buono criceto arso broccolo svedese ingrosso piacere singolo "
        "colmato mitra forbito argento abbaglio"
    )
    assert int(electrum.entropy_from_mnemonic(mnemonic, "it"), 2) > entropy


ELECTRUM_VECTORS = [
    pytest.param(*vector, id=vector_id(index, vector[4]))
    for index, vector in enumerate(
        load("mnemonic", "_data", "electrum_test_vectors.json")
    )
]


@pytest.mark.parametrize(
    ("mnemonic", "passphrase", "rmxprv", "rmxpub", "address"), ELECTRUM_VECTORS
)
def test_vectors(
    mnemonic: str, passphrase: str, rmxprv: str, rmxpub: str, address: str
) -> None:
    """Electrum vectors, and the only vendored file with no upstream at all.

    They are in no repository -- not in spesmilo/electrum's `tests/`, and a
    code search for the first mnemonic returns btclib and a fork of btclib
    -- so they were produced by running the application, and which version
    produced them is not recorded anywhere. Treat them as btclib's own:
    nothing upstream will ever refresh them. tests/_data/README.md says the
    same at greater length.
    """
    lang = "en"
    if mnemonic != "":
        assert rmxprv == electrum.mxprv_from_mnemonic(mnemonic, passphrase)

        mnemonic_type, mnemonic = electrum.version_from_mnemonic(mnemonic)
        entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
        # entr - 1 and not entr: these are electrum's own output, so the
        # entropy it was generated from is one below what it encodes and
        # the first candidate tried is the mnemonic itself
        mnem = electrum.mnemonic_from_entropy(mnemonic_type, entr - 1, lang)
        assert mnem == mnemonic

    assert rmxpub == bip32.xpub_from_xprv(rmxprv)

    xprv = bip32.derive(rmxprv, "m/0h/0")
    assert address == slip132.address_from_xkey(xprv)


def test_mnemonic_from_entropy() -> None:
    # zero leading bit should not throw an error
    electrum.mnemonic_from_entropy("standard", 2**126 + 1, "en")
    # the random default is electrum's: 132 bits, redrawn below 2**121,
    # so the sentence has twelve words and not however many the bit
    # length of a 128-bit draw happens to fill
    assert len(electrum.mnemonic_from_entropy().split()) == 12


def test_p2wpkh_p2sh() -> None:
    """Test generation of a p2wpkh-p2sh wallet."""
    # https://bitcoinelectrum.com/creating-a-p2sh-segwit-wallet-with-electrum/
    # https://www.youtube.com/watch?v=-1DBJWwA2Cw

    p2wpkh_p2sh_xkey_version = NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv
    mnemonics = [
        "matrix fitness cook logic peace mercy dinosaur sign measure rescue alert turtle",
        "chief popular furnace myth decline subject actual toddler plunge rug mixed unlock",
    ]
    versions = ["segwit", "standard"]
    addresses = [
        "38Ysa2TRwGAGLEE1pgV2HCX7MAw6XsP6BJ",
        "3A5u2RTjs3t33Kyc48zHA7Dfsr8Zsfwkoo",
    ]
    for mnemonic, version, p2wpkh_p2sh_address in zip(
        mnemonics, versions, addresses, strict=True
    ):
        # this is an electrum mnemonic
        assert electrum.version_from_mnemonic(mnemonic)[0] == version
        # of course, it is invalid as BIP39 mnemonic
        with pytest.raises(BTClibValueError, match="invalid checksum: "):
            bip39.mxprv_from_mnemonic(mnemonic, "")
        # nonetheless, let's use it as BIP39 mnemonic
        rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "", verify_checksum=False)
        # and force the xkey version to p2wpkh_p2sh
        mxprv = bip32.derive(rootxprv, "m/49h/0h/0h", p2wpkh_p2sh_xkey_version)
        mxpub = bip32.xpub_from_xprv(mxprv)
        # finally, verify the first receiving address
        xpub = bip32.derive_from_account(mxpub, 0, 0)
        assert p2wpkh_p2sh_address == slip132.address_from_xkey(xpub)
