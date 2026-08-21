# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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

import secrets
from hashlib import sha256
from unicodedata import normalize

import pytest

from btclib import slip132
from btclib.bip32 import bip32
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, electrum
from btclib.mnemonic.electrum import ELECTRUM_WORDLISTS
from btclib.mnemonic.mnemonic import BIP39_LANGUAGE_FILES, WORDLISTS
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

SPANISH_SEGWIT = (
    "equipo fiar auge langosta hacha calor trance cubrir carro pulmón oro áspero"
)
SPANISH_SEGWIT_2 = (
    "vidrio jabón muestra pájaro capucha eludir feliz rotar fogata pez rezar oír"
)

ENGLISH = (
    "wild father tree among universe such mobile favorite target "
    "dynamic credit identify"
)

# electrum's SEED_TEST_CASES: the seed of each, which is a normalization
# and a PBKDF2 and needs no word-list at all. These are the cases that
# make the normalization visible -- the CJK ones have their words joined,
# the Spanish ones have their accents dropped, and none of them would
# survive a bare whitespace clean
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
        SPANISH_SEGWIT,
        "",
        "segwit",
        "001ebce6bfde5851f28a0d44aae5ae0c762b600daf3b33fc8fc630aee0d20764"
        "6b6f98b18e17dfe3be0a5efe2753c7cdad95860adbbb62cecad4dedb88e02a64",
        id="spanish-segwit",
    ),
    pytest.param(
        SPANISH_SEGWIT_2,
        "¡Viva España! repiten veinte pueblos y al hablar dan fe del "
        "ánimo español... ¡Marquen arado martillo y clarín",
        "segwit",
        "c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3a"
        "ab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f",
        id="spanish-segwit-passphrase",
    ),
]

# the entropy field of those same SEED_TEST_CASES, i.e. what electrum's
# mnemonic_decode answers. Only now testable: decoding takes the
# word-list of the language, and btclib shipped two of electrum's five
DECODE_VECTORS = [
    pytest.param(
        JAPANESE, "ja", 1938439226660562861250521787963972783469, id="japanese"
    ),
    pytest.param(CHINESE, "zh", 3083737086352778425940060465574397809099, id="chinese"),
    pytest.param(SPANISH, "es", 3423992296655289706780599506247192518735, id="spanish"),
    pytest.param(
        SPANISH_SEGWIT, "es", 448346710104003081119421156750490206837, id="spanish-2"
    ),
    pytest.param(
        SPANISH_SEGWIT_2,
        "es",
        3444792611339130545499611089352232093648,
        id="spanish-3",
    ),
]

# generation parity, one language at a time: what electrum's make_seed
# returns when the entropy it draws is fixed. Produced by running
# electrum's own mnemonic.py with randrange patched to a constant, which
# is the same starting point mnemonic_from_entropy takes -- the search
# begins at entropy + 1 in both. Electrum publishes no vector of this
# kind for any language, so these are btclib's in the sense
# electrum_test_vectors.json is: cross-checked against the application.
#
# Not the full five-by-four matrix. The version is what the four columns
# vary and it is a hash of the sentence, language and all, so one
# language shows it; Portuguese has all four because it is the one
# word-list that is not 2048 words -- thirteen words to the sentence,
# which is what makes "2fa" impossible there and nowhere else.
#
# In a file and not inline, unlike every other vector here, and for a
# reason the values cannot defend themselves against: the two spell
# checkers of the lint gate read a python source and skip _data, and
# typos runs with --write-changes. Measured, it corrected word five of
# the Portuguese "2fa_segwit" sentence into the English word it is one
# letter away from -- a rewrite of a vector by a hook asked to fix prose,
# and it corrected this very comment when the word was written out here
LANGUAGE_VECTORS = load(
    "mnemonic", "_data", "electrum_language_vectors.json", encoding="utf-8"
)

GENERATED_VECTORS = [
    pytest.param(
        vector["lang"],
        vector["type"],
        vector["entropy"],
        vector["mnemonic"],
        vector["seed"],
        id=f"{vector['lang']}-{vector['type']}",
    )
    for vector in LANGUAGE_VECTORS["generated"]
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
    """Check generation, decoding and the unknown-version refusals."""
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


@pytest.mark.parametrize("mnemonic, passphrase, version, seed", SEED_VECTORS)
def test_seed_vectors(mnemonic: str, passphrase: str, version: str, seed: str) -> None:
    """Reproduce electrum's SEED_TEST_CASES, version and seed alike."""
    assert electrum._seed_from_mnemonic(mnemonic, passphrase) == (
        version,
        bytes.fromhex(seed),
    )


@pytest.mark.parametrize("mnemonic, version", VERSION_VECTORS)
def test_version_vectors(mnemonic: str, version: str) -> None:
    """Reproduce electrum's Test_seeds table, refusals included."""
    if not version:
        with pytest.raises(
            BTClibValueError, match="unknown electrum mnemonic version: "
        ):
            electrum.version_from_mnemonic(mnemonic)
    else:
        assert electrum.version_from_mnemonic(mnemonic)[0] == version


def test_old_mnemonic() -> None:
    """A pre-2.0 seed is reported as "old", and read by its own functions.

    The cases are electrum's is_old_seed tests. Recognizing the scheme is
    what keeps an old seed away from the four new versions, which derive
    keys another way: reporting it as one of them would be handing back
    the wrong wallet without a word. What it *is* read by is
    hex_seed_from_old_mnemonic and the two old_master_ functions, and
    both refusals below name the one to use instead.
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


# electrum's own pre-2.0 fixtures, and every one of them is a value taken
# from a test or a wallet file of spesmilo/electrum rather than from
# btclib. The scheme has no specification to check against -- it predates
# the BIPs -- so an invented vector would be testing btclib against
# btclib, and there is nothing else these could be checked with.
#
# 1. tests/test_mnemonic.py, Test_OldMnemonic.test: the only published
#    mnemonic-to-hex pair, and the only one that pins the encoder.
# 2. tests/test_wallet_vertical.py, test_electrum_seed_old: mnemonic, hex
#    seed and master public key of one wallet, restored from either form.
# 3. tests/test_wallet_vertical.py,
#    test_sending_offline_old_electrum_seed_online_mpk: a mnemonic and
#    the master public key its watch-only half is built from.
# 4. tests/test_storage_upgrade.py: a real pre-2.0 wallet file, holding
#    the hex seed and the "master_public_key" beside it.
OLD_HEX_SEEDS = [
    pytest.param(
        "8edad31a95e7d59f8837667510d75a4d",
        "hardly point goal hallway patience key stone difference ready "
        "caught listen fact",
        None,
        id="test-mnemonic",
    ),
    pytest.param(
        "acb740e454c3134901d7c8f16497cc1c",
        "powerful random nobody notice nothing important anyway look away "
        "hidden message over",
        "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df"
        "9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3",
        id="wallet-vertical",
    ),
    pytest.param(
        "14039a74100162d9d0cc3c31f100168ddc",
        "alone body father children lead goodbye phone twist exist grass kick join",
        "cd805ed20aec61c7a8b409c121c6ba60a9221f46d20edbc2be83ebd91460e979"
        "37cd7d782e77c1cb08364c6bc1c98bc040fdad53f22f29f7d3a85c8e51f9c875",
        id="offline-signing",
    ),
    pytest.param(
        "2605aafe50a45bdf2eb155302437e678",
        "flirt angel five creation swim bridge chocolate sport another "
        "hill secret whatever",
        "756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde"
        "4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb",
        id="storage-upgrade",
    ),
]


@pytest.mark.parametrize("hex_seed, mnemonic, master_pub_key", OLD_HEX_SEEDS)
def test_old_vectors(hex_seed: str, mnemonic: str, master_pub_key: str | None) -> None:
    """The pre-2.0 scheme, both directions and the stretch, against electrum.

    Only the hex seed and the master public key are upstream values in
    the third and fourth cases: the mnemonic of the third is what
    electrum publishes and the hex seed is this decoder's answer for it,
    and the fourth is the other way round, a wallet file holding a hex
    seed and no words. Each is still pinned at both ends, the master
    public key being downstream of the hex seed and upstream of nothing.
    """
    assert electrum.hex_seed_from_old_mnemonic(mnemonic) == hex_seed
    assert electrum.version_from_mnemonic(mnemonic)[0] == "old"

    if len(hex_seed) % 8:
        # electrum's offline-signing seed is the weak decoder caught in
        # the wild: two of its four groups exceeded 2**32, so twelve words
        # decoded to 34 hex characters rather than 32. Even, so it is
        # still octets and the stretch below runs on it and matches the
        # published master public key -- but electrum's own get_seed
        # cannot show the user those twelve words again, mn_encode
        # asserting a multiple of eight. Refusing the same way is what
        # agreeing means; a 17-byte seed is not a seed the encoder has an
        # answer for
        with pytest.raises(BTClibValueError, match="not a multiple of eight"):
            electrum.old_mnemonic_from_hex_seed(hex_seed)
    else:
        assert electrum.old_mnemonic_from_hex_seed(hex_seed) == mnemonic

    if master_pub_key is None:
        # no wallet was ever published for this one: it is the encoder
        # vector, and encoding is where it has been checked
        return

    assert electrum.old_master_pub_key_from_mnemonic(mnemonic) == master_pub_key

    if len(hex_seed) in {32, 64}:
        # the hex seed is a seed electrum restores from as readily as the
        # words, which is what makes the hex branch of the recognizer
        # more than a curiosity
        assert electrum.old_master_pub_key_from_mnemonic(hex_seed) == master_pub_key
    else:
        # and the same 34-character seed is not one it restores from:
        # is_old_seed takes 16 or 32 octets of hex and no other length,
        # so that wallet can be reopened from its twelve words alone
        with pytest.raises(BTClibValueError, match="not a pre-2.0 electrum mnemonic"):
            electrum.old_master_pub_key_from_mnemonic(hex_seed)


def test_old_stretch() -> None:
    """The stretch is iterated sha256 over the hex characters, not PBKDF2.

    The master private key of electrum's test_electrum_seed_old wallet,
    which is the integer its master public key is the point of. Spelled
    out here because the construction is the thing a vector has to pin:
    the digest starts as the hex seed, each round hashes the digest
    followed by that same hex seed, a hundred thousand times, and the
    seed is the sixteen ascii characters rather than the eight octets
    they spell.
    """
    mnemonic = (
        "powerful random nobody notice nothing important anyway look away "
        "hidden message over"
    )
    prv_key = electrum.old_master_prv_key_from_mnemonic(mnemonic)
    assert prv_key == 0x21B880FDA2FD30081834683A7049AC9E3941A42ADBC3A4616C9A9275AA960C0D

    # the same number, reached without the module: electrum's stretch_key
    # transcribed, so that a change to either side has to break this
    hex_seed = "acb740e454c3134901d7c8f16497cc1c"
    encoded = hex_seed.encode("ascii")
    digest = encoded
    for _ in range(100000):
        digest = sha256(digest + encoded).digest()
    assert int.from_bytes(digest, "big") == prv_key


def test_old_no_passphrase() -> None:
    """The pre-2.0 scheme has no passphrase, and says so.

    Electrum's keystore.from_seed raises "'old'-type electrum seed cannot
    have passphrase" and its can_seed_have_passphrase answers False for
    this scheme alone. Nothing but the seed enters the stretch, so a
    passphrase accepted would be a passphrase ignored -- the wallet of a
    seed the caller did not ask for, handed back without a word. None and
    the empty string are "no passphrase", there and here.
    """
    mnemonic = (
        "powerful random nobody notice nothing important anyway look away "
        "hidden message over"
    )
    master_pub_key = (
        "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df"
        "9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3"
    )
    assert electrum.old_master_pub_key_from_mnemonic(mnemonic, None) == master_pub_key
    assert electrum.old_master_pub_key_from_mnemonic(mnemonic, "") == master_pub_key

    for function in (
        electrum.old_master_prv_key_from_mnemonic,
        electrum.old_master_pub_key_from_mnemonic,
    ):
        with pytest.raises(BTClibValueError, match="cannot have a passphrase"):
            function(mnemonic, "Did you ever hear the tragedy of Darth Plagueis")


def test_old_normalization() -> None:
    """An old seed is normalized before it is decoded, as electrum does it.

    Electrum's format_seed calls normalize_text first, so the mixed-case
    and doubled-whitespace forms of its Test_seeds table are the same
    seed as the plain one. The hex form is normalized too, which is why
    the upper-case hex of is_old_seed's own test decodes at all.
    """
    plain = "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze"
    shouted = (
        "cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE"
    )
    spaced = (
        "   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt "
        "kInGdOm rArE SqUeEzE   "
    )
    hex_seed = electrum.hex_seed_from_old_mnemonic(plain)
    assert electrum.hex_seed_from_old_mnemonic(shouted) == hex_seed
    assert electrum.hex_seed_from_old_mnemonic(spaced) == hex_seed

    # a seed written as hex is lower-cased, and is its own answer
    assert electrum.hex_seed_from_old_mnemonic("0123456789ABCDEF" * 2) == (
        "0123456789abcdef" * 2
    )
    assert electrum.hex_seed_from_old_mnemonic("0123456789ABCDEF" * 4) == (
        "0123456789abcdef" * 4
    )


def test_old_weak_decoder() -> None:
    """Twelve words can decode to 33 hex characters, and electrum agrees.

    The "invalid old" seed of electrum's Test_seeds table. Three words
    carry a group that can exceed 2**32 -- the largest is 1625 * (1 +
    1626 + 1626**2), about 4.3 billion against 4.29 -- and the decoder
    writes it out as nine hex characters instead of eight without
    noticing. Electrum's decoder does the same and its stretch_key then
    asserts is_hex_str and fails, so refusing here is what agreeing means.
    """
    mnemonic = (
        "hurry idiot prefer sunset mention mist jaw inhale impossible "
        "kingdom rare squeeze"
    )
    assert electrum.version_from_mnemonic(mnemonic)[0] == "old"
    hex_seed = electrum.hex_seed_from_old_mnemonic(mnemonic)
    assert hex_seed == "025d2f2d005036911003ca78900ca155c"
    assert len(hex_seed) == 33

    with pytest.raises(BTClibValueError, match="decodes to 33 hex characters"):
        electrum.old_master_prv_key_from_mnemonic(mnemonic)


def test_old_invalid() -> None:
    """What the two pre-2.0 converters refuse, and where the line is."""
    # the encoder takes hex and only hex: bytes.fromhex would skip the
    # space and int() would take the underscore, and neither is a seed
    for hex_seed in ("nonsense", "0123456789abcde", "01234567 89abcdef", "0123_4567"):
        with pytest.raises(BTClibValueError, match="not a hex string"):
            electrum.old_mnemonic_from_hex_seed(hex_seed)

    # eight hex characters to a group, so a length that is not a multiple
    # of eight has no third word for its last group
    with pytest.raises(BTClibValueError, match="not a multiple of eight"):
        electrum.old_mnemonic_from_hex_seed("0123456789abcdef" * 2 + "abcdef")

    # the decoder takes what the recognizer accepts and nothing else: a
    # versioned electrum seed is not a pre-2.0 one, whatever it decodes to
    for mnemonic in (
        "ostrich security deer aunt climb inner alpha arm mutual marble solid task",
        " ".join(["like"] * 18),
        "",
    ):
        with pytest.raises(BTClibValueError, match="not a pre-2.0 electrum mnemonic"):
            electrum.hex_seed_from_old_mnemonic(mnemonic)


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


def test_a_wordlist_the_encoding_does_not_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The search checks its own arithmetic, and says so when it fails.

    Electrum makes the same check inside make_seed, and it is not
    reachable with the two wordlists btclib ships: `en` and `it` are
    2048 distinct ASCII words each, so encoding an integer and decoding
    the sentence hands the integer back for every candidate --
    measured over the first three thousand and three thousand more
    above 2**131. Patching the decode reaches it on the wordlists there
    are, which is what the ripemd160 fallback test does with its flag
    and what a `pragma: no cover` here would not do.

    What would run it for real is a list added later: a CJK one, where
    normalization can map two entries onto one string, or any list
    carrying a repetition. Either writes a seed that reads back as
    another, so the search refuses rather than returns it.
    """
    # a decode that answers 1 whatever it is given: the first candidate
    # is int_entropy + 1, so 1 here is a mismatch and nothing else is
    monkeypatch.setattr(electrum, "_bin_str_entropy_from_mnemonic", lambda *_: "1")

    err_msg = "cannot extract the same entropy from mnemonic: "
    with pytest.raises(BTClibValueError, match=err_msg):
        electrum._search_mnemonic(1, "01", "en")


def test_2fa_words() -> None:
    """A "2fa" seed wants twelve words or twenty; a search can end elsewhere.

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


@pytest.mark.parametrize("mnemonic, lang, entropy", DECODE_VECTORS)
def test_decode_vectors(mnemonic: str, lang: str, entropy: int) -> None:
    """The entropy electrum's mnemonic_decode reads off each sentence.

    The sentence is decoded as handed in: electrum's normalization drops
    the accents of the spanish words and joins the chinese ones, and what
    it produces is what electrum hashes rather than what it looks up.
    """
    assert int(electrum.entropy_from_mnemonic(mnemonic, lang), 2) == entropy
    # and the language need not be named
    assert int(electrum.entropy_from_mnemonic(mnemonic), 2) == entropy


@pytest.mark.parametrize(
    "lang, mnemonic_type, entropy, mnemonic, seed", GENERATED_VECTORS
)
def test_generated_vectors(
    lang: str, mnemonic_type: str, entropy: int, mnemonic: str, seed: str
) -> None:
    """The sentence electrum builds from an entropy, language by language."""
    if not mnemonic:
        with pytest.raises(BTClibValueError, match="electrum mnemonic version: "):
            electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)
        return

    # the vectors are written composed, which is how a reader types them
    # and how electrum publishes its own word-list files; the word-lists
    # are loaded NFKD, as BIP39 publishes them and as electrum normalizes
    # them, so the sentence built here is decomposed and the two are one
    # sentence. The seed below is the check that does not depend on the
    # spelling: it is derived from the vector's own text
    generated = electrum.mnemonic_from_entropy(mnemonic_type, entropy, lang)
    assert normalize("NFKD", generated) == normalize("NFKD", mnemonic)
    assert electrum._seed_from_mnemonic(mnemonic, "") == (
        mnemonic_type,
        bytes.fromhex(seed),
    )
    # the entropy the sentence encodes is above the one it was searched
    # from, and searching from one below it lands back on the sentence
    entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
    assert entr > entropy
    assert electrum.mnemonic_from_entropy(mnemonic_type, entr - 1, lang) == generated


def test_electrum_wordlists() -> None:
    """Electrum's word-lists are BIP39's, but for Portuguese."""
    # the shipped twelve, and not WORDLISTS.languages: that one is a
    # singleton another test adds a language to
    assert ELECTRUM_WORDLISTS.languages == list(BIP39_LANGUAGE_FILES)
    for lang in BIP39_LANGUAGE_FILES:
        if lang == "pt":
            continue
        assert ELECTRUM_WORDLISTS.wordlist(lang) == WORDLISTS.wordlist(lang)

    # electrum's portuguese is Monero's list: 1626 words, not 2048, and
    # 185 of them are also in BIP39's portuguese
    assert ELECTRUM_WORDLISTS.language_length("pt") == 1626
    assert WORDLISTS.language_length("pt") == 2048
    shared = set(ELECTRUM_WORDLISTS.wordlist("pt")) & set(WORDLISTS.wordlist("pt"))
    assert len(shared) == 185


def test_portuguese_word_count() -> None:
    """The first entropy needing thirteen base-1626 digits has thirteen words.

    Pin the entropy because electrum's random lower bound is slightly
    below this base-conversion boundary and can also draw twelve words.
    """
    first_thirteen_word_entropy = ELECTRUM_WORDLISTS.language_length("pt") ** 12
    mnemonic = electrum.mnemonic_from_entropy(
        "standard", first_thirteen_word_entropy, "pt"
    )
    assert len(mnemonic.split()) == 13
    assert len(electrum.entropy_from_mnemonic(mnemonic, "pt")) == 139

    # every one of its words is in electrum's list and the sentence is in
    # no other, which is what lets the language go unnamed
    assert electrum.lang_from_mnemonic(mnemonic) == "pt"
    # BIP39's portuguese is another word-list, and cannot read it
    with pytest.raises(BTClibValueError, match="unknown 'pt' word: "):
        bip39.entropy_from_mnemonic(mnemonic, "pt")


def test_portuguese_random_word_count(monkeypatch: pytest.MonkeyPatch) -> None:
    """Electrum's random lower bound permits a twelve-word Portuguese seed."""
    base = ELECTRUM_WORDLISTS.language_length("pt")
    twelve_word_entropy = base**12 - 1000

    def draw_below_thirteen_words(upper_bound: int) -> int:
        assert upper_bound == (1 << 138) - 1
        # randbelow returns one less because _random_int_entropy adds one.
        return twelve_word_entropy - 1

    monkeypatch.setattr(secrets, "randbelow", draw_below_thirteen_words)
    mnemonic = electrum.mnemonic_from_entropy("standard", None, "pt")

    assert len(mnemonic.split()) == 12
    assert len(electrum.entropy_from_mnemonic(mnemonic, "pt")) == 129


def test_is_bip39_mnemonic() -> None:
    """The skip electrum performs with the word-list of the language.

    For a 2048-word list it is BIP39's own question, and the first two
    cases pin that against bip39.py. For electrum's Portuguese it is not:
    electrum reads 1626 words with eleven bits to the word, which is not
    a BIP39 checksum of anything, and the two vectors below are what its
    bip39_is_checksum_valid answers all the same. Reproduced because the
    candidates it makes electrum skip are what shape the sentences
    electrum generates.
    """
    valid_bip39 = (
        "park leaf system perfect top lecture rather foster best nest craft topic"
    )
    assert electrum._is_bip39_mnemonic(valid_bip39, "en")
    assert bip39.entropy_from_mnemonic(valid_bip39, "en")

    assert not electrum._is_bip39_mnemonic(ENGLISH, "en")
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        bip39.entropy_from_mnemonic(ENGLISH, "en")

    # a word of no word-list, and a length BIP39 has no checksum for
    assert not electrum._is_bip39_mnemonic("btclib " * 11 + "btclib", "en")
    assert not electrum._is_bip39_mnemonic(ENGLISH + " abandon", "en")

    # electrum's portuguese, 1626 words read as though eleven bits each.
    # In the vector file for the reason stated above it: a Portuguese
    # sentence in a python source is prose to the spell checkers
    lookalike = LANGUAGE_VECTORS["bip39_lookalike"]
    assert electrum._is_bip39_mnemonic(lookalike["valid"], "pt")
    assert not electrum._is_bip39_mnemonic(lookalike["invalid"], "pt")


def test_entropy_round_trips_through_every_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The invariant electrum checks on each candidate it encodes.

    "Cannot extract same entropy from mnemonic!", says electrum, of a
    sentence that does not decode to the integer it was built from. No
    input reaches it -- a base conversion round-trips, and the word-lists
    hold no duplicate word for two indexes to answer to -- so the decoder
    is replaced to reach the raise, which is what makes it a guard rather
    than dead code.
    """
    monkeypatch.setattr(electrum, "_bin_str_entropy_from_mnemonic", lambda *_: "0")
    with pytest.raises(
        BTClibValueError, match="cannot extract the same entropy from mnemonic: "
    ):
        electrum.mnemonic_from_entropy("standard", 1, "en")


def test_lang_from_mnemonic() -> None:
    """The words say which language, or say that they cannot."""
    # a fixed entropy, and not the random one a `None` would draw: the
    # refusal below is the reason. About one chinese sentence in three
    # hundred is written in the 1275 characters both lists hold, and
    # electrum refuses that one rather than resolving it, so a random
    # entropy makes this a test that fails a few times a year for being
    # right. The same digits as bip39_test's, which pins the same thing
    entropy = 0x0000003974D093EDA670121023CD0000
    for lang in ("en", "es", "ja", "pt", "zh"):
        mnemonic = electrum.mnemonic_from_entropy("standard", entropy, lang)
        assert electrum.lang_from_mnemonic(mnemonic) == lang

    with pytest.raises(BTClibValueError, match="unknown language for mnemonic: "):
        electrum.lang_from_mnemonic("btclib " * 11 + "btclib")

    # a chinese sentence in characters both lists hold. BIP39 answers it
    # by comparing the entropies, which are equal, the two lists being
    # aligned; here there is no checksum to say the sentence was ever
    # meant to spell that entropy, so the caller is asked
    shared = "的 的 的 的 的 的 的 的 的 的 的 在"
    with pytest.raises(BTClibValueError, match="ambiguous language for mnemonic: "):
        electrum.lang_from_mnemonic(shared)


def test_italian() -> None:
    """Italian is btclib's own extension, and it round-trips.

    Electrum reads en, es, ja, pt and zh, so a mnemonic generated here in
    Italian is one electrum cannot read at all. The module docstring says
    so; this pins the behaviour rather than the parity, there being
    nothing to be in parity with.
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
    "mnemonic, passphrase, rmxprv, rmxpub, address", ELECTRUM_VECTORS
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
    # every vector carries one, so it is asserted rather than guarded: a
    # file refreshed with a case that has none would leave the round trip
    # below unrun, which is the failure a guard would have hidden
    assert mnemonic
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
    """Verify a zero leading bit is fine and the random default draws 12."""
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
