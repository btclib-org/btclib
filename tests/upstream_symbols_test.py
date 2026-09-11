# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Two sweeps over what this tree's prose credits to libsecp256k1.

A `secp256k1_*` name credited to that library is one it has, and the
wording of a refusal credited to it is `btclib_secp256k1`'s: the C
library answers a call with a return code, and turning one into a
sentence is the wrapper's work. The two are keyed differently -- the
first on the name a paragraph spells, the second on the shape of the
attribution -- and neither reads the sentence for anything more.

A credit is followed, and following it has to arrive somewhere.
`secp256k1_ecdsa_sign` is bitcoin-core/secp256k1's and a reader
following it lands on the function; `secp256k1_ecdsa_s2c_opening` is
BlockstreamResearch/secp256k1-zkp's, so a paragraph that names the
first library and spells the second name sends a reader to a library
that has neither the name nor the behaviour argued from it. That is one
question with an answer, and it is the only one the name-keyed sweep
asks: it does not read the sentence the name sits in, and it does not
decide whether a credit is fair.

The names that library has are vendored in
`tests/_data/secp256k1_symbols.txt`, pinned to a revision there, so
this reaches no network. A test that fetched would pass under every
contributor's own `uv sync` and fail wherever the access is missing,
which is the asymmetry
[ISS 1538](https://github.com/btclib-org/btclib/issues/1538) is a
reminder about; `.github/workflows/vendored-vectors.yml` is what says
the pin has moved, weekly and outside the suite, the way it does for
every other pin that README carries.

**The revision pinned there is upstream's own, not the one the bindings
vendor.** `btclib-secp256k1` builds the library a caller loads from a
submodule of bitcoin-core/secp256k1, so a name upstream has added since
that submodule's last bump is in this set and absent from the library
the suite runs against. Upstream is what a credit asks about: it is
followed into that repository's source, and the set is of what is there
to be found. Pinning to the submodule would answer for the library the
bindings ship and give that up, a name upstream has renamed away
staying in the set and a credit spelling it passing. Whether the
installed bindings expose a name is a third question, and neither pin
answers it. `tests/_data/README.md`'s entry carries the choice and the
command that names the difference.

**The authority is the library's own `src`, not its `include`.**
Publishing is a different question from having, and a credit raises the
second: `curves.curve` names `secp256k1_ge_x_on_curve_var`,
`curves.curve_group` names `secp256k1_ecmult_gen_gej` and
`number_theory` names `secp256k1_ctz64_var`, each of them defined in
that library's own `src` and declared in no header of `include`.
`src/group.h`, `src/ecmult_gen.h` and `src/util.h` are where they are
declared, which is the point: a header under `src` is not publishing.
Measured
against an `include` listing, every one of those paragraphs is an
offender and the repair on offer is to stop naming an internal function
this tree really does read, so the narrower set answers a question
nobody asked. It is also not the smaller one in the end: every name
`include` declares is named in `src` as well, the difference being names
a header comment wraps in prose rather than declares.

**What `src` spells is not what the library declares**, and the vendored
set is the first of the two. The names are read out of the text, so one
written there only inside a comment is in the set and a credit to it
passes: `secp256k1_ecmult_gen` is such a name, the one
`src/ecmult_gen_impl.h` gives the operation in its prose, where the
functions are `secp256k1_ecmult_gen_gej` and `secp256k1_ecmult_gen_ge`.
That is the whole of what this is permissive by, and the vendoring
command run again over a `src` whose comments have been blanked out is
what re-derives it.

**The name-keyed population is the paragraph that names the library.**
A paragraph naming BlockstreamResearch/secp256k1-zkp is left alone,
whether or not it names libsecp256k1 too: the fork carries the
library's names and its own, so a paragraph naming both is one where
nothing decides which name belongs to which, and a verdict there would
be a guess. That is where it is weakest, and the ways it loses are
worth naming rather than inferring:

- a credit that names **no symbol** is invisible.
  [ISS 1932](https://github.com/btclib-org/btclib/issues/1932),
  [ISS 1946](https://github.com/btclib-org/btclib/issues/1946) and
  [ISS 1949](https://github.com/btclib-org/btclib/issues/1949) were
  each that shape -- "libsecp256k1's own `grind`", the s2c module, the
  opening -- so it would have caught none of them, and it exists for
  the next one that does spell a name;
- a credit that names **no library** -- "the reference implementation",
  "the C library", "upstream" -- is invisible for the same reason from
  the other side, and no name-keyed check reaches it;
- an attribution **spanning a paragraph break**, the library named in
  one and the name spelled in the next, is invisible: the paragraph is
  the unit, so a subject carried across a blank line is not carried
  here;
- a **name broken across a wrap** is read as the fragment in front of
  the break: it fails loudly where that fragment is not a name the
  library has, which is the ordinary case, and silently where it is;
- **an f-string is not read from Python 3.12 on.** PEP 701 tokenizes
  one as `FSTRING_START`, `FSTRING_MIDDLE` and `FSTRING_END` where
  `tokenize.STRING` is what this reads, so a credit inside one is
  invisible there and swept on 3.10 and 3.11, which tokenize an
  f-string as a single `STRING` and which `os-ubuntu.yml`,
  `os-macos.yml` and `os-windows.yml` all run. The input set therefore
  differs by interpreter, and a credit belongs in a plain literal or a
  comment for that reason;
- **markdown is not read.** `CHANGELOG.md` is appended to and its
  released sections are sealed by `tests/changelog_immutability_test.py`,
  so a credit that landed in one cannot be corrected and a gate over it
  would be red with no repair available -- its entry for
  [ISS 800](https://github.com/btclib-org/btclib/issues/800) is exactly
  that, carrying the same credit `number_theory` carried. The swept
  files are `src/btclib` and `tests`, where a credit sits beside the
  code it describes and can still be edited.

**The attribution sweep is part of the first of those bullets.** A
credit that spells no name is outside the sweep above whatever it
claims; where what it claims is that a message, a wording or an error
is the library's, or that the library raises, the claim is itself the
key and no name is wanted. That much follows from the layering alone,
so it is decidable here with no upstream read at all, which is what
makes it a test rather than a report. It reads a paragraph naming the
fork too: which of the two C libraries is meant does not decide it.

**Its zero says less than the other's.** The pattern is fitted to the
phrasings it lists rather than derived from the claim -- the possessive
gap it spans admits a comma, and `coarser one` is among the nouns it
accepts, neither of which a reading of the shape alone arrives at -- so
a zero over it says that none of those phrasings is in the swept files
and never that no such credit is there. Recall against a phrasing
nobody has written is not measurable, the claim being expressible in
unbounded ways. Narrowness is what the fitting buys: the library named
beside the word message is the *correct* form of the same sentence --
"libsecp256k1 answers a bool and this is btclib's own wording for it"
-- so a rule keyed on the two co-occurring would report this tree's
correct prose paragraph after paragraph, and be worse than none.

**A credit that has gone stale is outside both.** What it asserts is a
fact about another project's present source, and nothing this tree runs
decides it: what settles one is a read of upstream at the revision
`tests/_data/README.md` pins, taken on the occasion
`.github/workflows/vendored-vectors.yml` gives by reporting that the
revision has moved.

**A paragraph is read as one string, not line by line.** The files
wrap at eighty columns, so the library and a name credited to it are
routinely on either side of a break: `_blinded_jac`'s docstring in
`curves.curve_group` names the library on one line and
`secp256k1_gej_rescale` on a later one, and neither line on its own is
a credit. The lines are joined with the wrap's own space. Joining them
with nothing instead, so as to close up a name broken at one of its own
underscores, is not done: no name this tree spells is recovered that
way, no paragraph is spared either -- the fragment in front of such a
break is reported whichever join runs, no fragment being a name the
library has -- and closing a break up runs the word in front of a name
into it, making a name of what is none.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a
line in any `needs` list.

The module's own prose obeys both rules it enforces, which is why the
controls below build their planted paragraphs out of pieces: a
paragraph here that names the library and spells a name the library
does not have, or that hands it the wording of a refusal, would be an
offender of the very sweeps defined below it, and exempting the file
would leave its real prose unread.
"""

import io
import re
import tokenize
from collections.abc import Iterator
from itertools import groupby
from pathlib import Path

_ROOT = Path(__file__).parents[1]

# every name the pinned bitcoin-core/secp256k1 spells in its own `src`,
# re-derived by the command `tests/_data/README.md`'s entry gives
_PUBLISHED = frozenset(
    (_ROOT / "tests" / "_data" / "secp256k1_symbols.txt")
    .read_text(encoding="utf-8")
    .split()
)

# where a credit sits beside the code it describes: the package and its
# suite, this module included
_SWEPT = ("src/btclib", "tests")

# a C identifier of the library's family, anchored on the left so that a
# longer identifier ending in one is not read as one: `ecc.dsa`'s own
# `_libsecp256k1_sign_` would otherwise spell a name of the library's
_NAME = re.compile(r"(?<![A-Za-z0-9_])secp256k1_[a-z0-9_]+")

# the library, in the two spellings this tree uses for it. The right
# lookahead is what keeps `ecc.dsa`'s own `_libsecp256k1_sign_` and the
# fork's `libsecp256k1-zkp` from reading as the library, a letter, a
# digit, an underscore or a hyphen after the word ruling all of both
# out; the left anchor answers the other end, a word ending in the
# library's name, which the lookahead alone would admit
_LIBRARY = re.compile(
    r"(?<![A-Za-z0-9_])libsecp256k1(?![A-Za-z0-9_-])|bitcoin-core/secp256k1"
)

# the fork, in every spelling this tree uses for it. `zkp` alone is one
# of them, and matching it as a word is deliberately wide: a paragraph
# that mentions the fork at all is one this cannot adjudicate
_FORK = re.compile(r"(?i)secp256k1-zkp|blockstreamresearch|\bzkp\b")

# the library named as the owner of a refusal's wording, or as what
# raises one. `btclib_secp256k1` is what carries a sentence: the C
# library answers a call with a return code, so a possessive here hands
# the wrapper's words to what it wraps. The fork is not spared the way
# it is above, which of the two is meant deciding nothing here; and the
# gap the possessive spans admits a comma, `own, coarser message` being
# one of the shapes this is fitted to
_ATTRIBUTION = re.compile(
    r"libsecp256k1(-zkp)?'s[\s,\w]{0,30}?(message|wording|error|coarser one)"
    r"|libsecp256k1(-zkp)? (raises|raised)"
)

# a comment's own `#` and the space after it, which is what a fold has to
# drop before the words on either side of a wrap can meet
_MARKER = re.compile(r"^#+ ?")


def _blocks(source: str) -> Iterator[list[tuple[int, str]]]:
    """Yield every comment run and every plain literal, as numbered lines.

    Plain, because from Python 3.12 an f-string is no longer one token:
    PEP 701 gives it `FSTRING_START`, `FSTRING_MIDDLE` and `FSTRING_END`,
    none of them `tokenize.STRING`, so what an f-string holds is read on
    the interpreters below that split and not on those above it. The
    module docstring carries that as a blind spot rather than this
    reading both shapes, an `FSTRING_MIDDLE` being a fragment between
    the replacement fields and not the sentence a credit is written in.

    A comment run is grouped because a wrapped sentence is spread over
    consecutive `#` lines and no single token holds it. What ends one is
    a line of code or a gap in the numbering, and neither test is
    optional: `tokenize` closes every comment line with an `NL`, so
    letting that end the run would leave each line a block of its own
    and assemble no wrapped sentence at all, while reading the run
    without its line numbers would fuse two comments a blank line
    separates into one paragraph.

    A trailing comment's code is dropped with it: `token.string` is the
    comment alone, where `token.line` would carry the statement in front
    of it. What closes such a line is a `NEWLINE` and not an `NL`, so a
    trailing comment does not run into the full-line comment beneath it.
    """
    run: list[tuple[int, str]] = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            if run and token.start[0] != run[-1][0] + 1:
                yield run
                run = []
            run.append((token.start[0], _MARKER.sub("", token.string).strip()))
            continue
        if token.type == tokenize.NL:
            continue
        if run:
            yield run
            run = []
        if token.type == tokenize.STRING:
            yield [
                (token.start[0] + offset, line.strip())
                for offset, line in enumerate(token.string.split("\n"))
            ]


def _paragraphs(block: list[tuple[int, str]]) -> Iterator[list[tuple[int, str]]]:
    """Yield the blank-line-separated paragraphs of one block.

    Grouped on emptiness rather than accumulated, which leaves no
    trailing paragraph to be flushed once the block ends.
    """
    for filled, lines in groupby(block, key=lambda numbered: bool(numbered[1])):
        if filled:
            yield list(lines)


def _fold(paragraph: list[tuple[int, str]]) -> str:
    """Return the paragraph as the one string a credit is read out of."""
    return " ".join(text for _, text in paragraph)


def _offenders(source: str) -> list[tuple[int, str, str]]:
    """Return each (line, name, paragraph) crediting a name it lacks."""
    found = []
    for block in _blocks(source):
        for paragraph in _paragraphs(block):
            folded = _fold(paragraph)
            if not _LIBRARY.search(folded) or _FORK.search(folded):
                continue
            found += [
                (paragraph[0][0], name, folded)
                for name in sorted(set(_NAME.findall(folded)) - _PUBLISHED)
            ]
    return found


def _attributions(source: str) -> list[tuple[int, str, str]]:
    """Return each (line, phrase, paragraph) handing the library a sentence."""
    found = []
    for block in _blocks(source):
        for paragraph in _paragraphs(block):
            folded = _fold(paragraph)
            found += [
                (paragraph[0][0], match.group(), folded)
                for match in _ATTRIBUTION.finditer(folded)
            ]
    return found


def test_every_name_credited_to_libsecp256k1_is_one_that_library_has() -> None:
    """The sweep, over every tracked module of the package and the suite."""
    offenders = [
        f"{path.relative_to(_ROOT)}:{line} credits libsecp256k1 with {name!r}: {folded}"
        for directory in _SWEPT
        for path in sorted((_ROOT / directory).rglob("*.py"))
        for line, name, folded in _offenders(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "bitcoin-core/secp256k1 has no such name at the revision"
        f" tests/_data/README.md pins: {offenders!r}"
    )


def test_the_sweep_reads_the_tree_rather_than_an_empty_list() -> None:
    """A zero above is a zero over files that were opened.

    A file a walk never reached reads exactly like a file with nothing
    in it, and the assertion above cannot tell the two apart. This names
    a paragraph the tree really carries -- `curves.curve_group`'s
    account of what a random Z buys -- and asks the same helpers for it.
    """
    source = (_ROOT / "src" / "btclib" / "curves" / "curve_group.py").read_text(
        encoding="utf-8"
    )
    credited = {
        name
        for block in _blocks(source)
        for paragraph in _paragraphs(block)
        if _LIBRARY.search(_fold(paragraph))
        for name in _NAME.findall(_fold(paragraph))
    }
    assert "secp256k1_gej_rescale" in credited


def test_a_name_the_library_does_not_have_is_what_fails() -> None:
    """The check can disagree with itself, on a paragraph built to make it.

    The library name and the absent name are two literals joined here
    rather than one written out: a single literal carrying both would be
    an offender of the sweep above, this module being one of the files
    it reads.
    """
    absent = "secp256k1_no_such_function"
    credited = "It is libsecp256k1's `" + absent + "`, one call and no loop."
    kept = "It is libsecp256k1's `secp256k1_ecdsa_sign`, one call and no loop."

    assert [name for _, name, _ in _offenders('"""' + credited + '"""')] == [absent]
    assert not _offenders('"""' + kept + '"""')


def test_a_paragraph_naming_the_fork_is_left_alone() -> None:
    """The fork carries the library's names and its own, so nothing decides.

    The same paragraph as above with the fork named in it, which is what
    every correct sign-to-contract paragraph in `ecc.dsa` and
    `ecc.commit_nonce` looks like.
    """
    absent = "secp256k1_ecdsa_s2c_opening"
    credited = "It is libsecp256k1's `" + absent + "`."
    forked = "It is secp256k1-zkp's `" + absent + "`, and libsecp256k1 has none."

    assert [name for _, name, _ in _offenders('"""' + credited + '"""')] == [absent]
    assert not _offenders('"""' + forked + '"""')


def test_a_credit_wrapped_across_lines_is_read_as_one_paragraph() -> None:
    """The library and the name credited to it, on either side of a break.

    `_blinded_jac`'s docstring in `curves.curve_group` is the live case
    and the ordinary shape rather than the corner one, the files
    wrapping at eighty columns. Planted here as the wrap itself, the
    library and the absent name in two literals rather than one.
    """
    absent = "secp256k1_no_such_function"
    wrapped = '"""which is libsecp256k1\'s own\n' + absent + ', in prose."""'

    assert [name for _, name, _ in _offenders(wrapped)] == [absent]


def test_a_credit_wrapped_across_two_comment_lines_is_one_run() -> None:
    """A comment run is a paragraph, which is what skipping the `NL` buys.

    `tokenize` closes every comment line with one, so a run ending there
    leaves each `#` line a block of its own and assembles no credit
    spread over two of them. `script.taproot`'s comment on the tweak is
    the live shape: it spells `secp256k1_xonly_pubkey_tweak_add` on its
    first line and names the library five lines down, and no one line of
    it is a credit.
    """
    absent = "secp256k1_no_such_function"
    wrapped = "# which is libsecp256k1's own\n# " + absent + ", in prose\n"

    assert [name for _, name, _ in _offenders(wrapped)] == [absent]


def test_two_comments_a_blank_line_apart_are_not_one_run() -> None:
    """Which is what the gap in the line numbers buys.

    A blank line emits an `NL` of its own, so a run that skipped it
    without reading the numbering would carry the library across the
    break and credit it with whatever the comment below spells. The
    paragraph is the unit here and a blank line ends one.
    """
    absent = "secp256k1_no_such_function"
    apart = "# which is libsecp256k1's own\n\n# " + absent + ", in prose\n"

    assert not _offenders(apart)


def test_a_name_broken_across_a_wrap_is_read_as_the_fragment() -> None:
    """Which fails loudly, no fragment being a name the library has.

    Joining a paragraph's lines with nothing rather than with a space
    would close such a break up, and that is not what runs: the fragment
    is reported either way, so closing it up spares no paragraph, and a
    join with nothing runs the word in front of a name into it.
    """
    published = "secp256k1_ecdsa_sign"
    fragment = published[: -len("sign")]
    wrapped = ["libsecp256k1 spells it `" + fragment, "sign`."]

    assert published in _PUBLISHED
    assert fragment not in _PUBLISHED
    assert _NAME.findall(_fold(list(enumerate(wrapped)))) == [fragment]


def test_the_vendored_set_is_the_library_and_not_the_fork() -> None:
    """What the pinned file holds, asked of the two names the decision names.

    secp256k1-zkp is a fork of this library, so a set taken from the
    fork would answer yes to both and this check would pass on the very
    prose it exists to refuse.
    """
    assert "secp256k1_ecdsa_sign" in _PUBLISHED
    assert "secp256k1_ecdsa_s2c_opening" not in _PUBLISHED


def test_btclib_s_own_dispatch_name_is_not_read_as_the_library() -> None:
    """`_libsecp256k1_sign_` is `ecc.dsa`'s function, not upstream's.

    A paragraph whose only occurrence of the word is inside that
    identifier credits nothing to anybody, so it is not a paragraph this
    reads at all.
    """
    absent = "secp256k1_no_such_function"
    ours = "`_libsecp256k1_sign_` reaches `" + absent + "` and nothing else."

    assert not _offenders('"""' + ours + '"""')


def test_no_paragraph_credits_the_c_library_with_a_sentence_of_its_own() -> None:
    """The attribution sweep, over the same files as the name-keyed one."""
    offenders = [
        f"{path.relative_to(_ROOT)}:{line} credits {phrase!r}: {folded}"
        for directory in _SWEPT
        for path in sorted((_ROOT / directory).rglob("*.py"))
        for line, phrase, folded in _attributions(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "the C library answers a call with a return code, so the wording a"
        f" caller catches is the wrapper's: {offenders!r}"
    )


def test_a_sentence_credited_to_the_c_library_is_what_fails() -> None:
    """The shapes it keys on, each planted as a paragraph of its own.

    Out of pieces, for the reason the module docstring gives: a single
    literal carrying one of them would be an offender of the sweep
    above, this module being one of the files it reads.
    """
    owner = "libsecp256k1" + "'s"
    subject = "libsecp256k1" + " raises"
    planted = [
        owner + " own, coarser message for whatever else it catches.",
        owner + " coarser message for whatever else it refuses.",
        "the message those two give it, rather than " + owner + " coarser one.",
        "The two `ValueError`s " + subject + " here are both about the key.",
    ]

    for text in planted:
        assert _attributions('"""' + text + '"""'), text


def test_the_correct_form_of_the_same_sentence_is_left_alone() -> None:
    """Co-occurrence is not the signal, and this is what it would report.

    The library beside the word message, with the sentence attributed
    where it belongs, which is the shape most of this tree's paragraphs
    about the delegated path have.
    """
    kept = (
        "libsecp256k1 answers a bool, and the message a caller reads for"
        " it is this library's own wording."
    )

    assert _LIBRARY.search(kept)
    assert not _attributions('"""' + kept + '"""')


def test_an_attribution_wrapped_across_lines_is_read_as_one_paragraph() -> None:
    """The possessive at the end of one line and its noun on the next.

    The files wrap at eighty columns, so this is the ordinary shape
    rather than the corner one, exactly as it is for a name.
    """
    owner = "libsecp256k1" + "'s"
    wrapped = '"""rather than\n' + owner + " coarser\none." + '"""'

    assert _attributions(wrapped)


def test_a_possessive_the_gap_does_not_span_reads_as_clean() -> None:
    """Which is what the module docstring means by fitted.

    The same claim with more words between the library and the noun is
    not reported, and nothing here tells that apart from a tree with no
    such claim in it.
    """
    owner = "libsecp256k1" + "'s"
    spread = owner + (
        " own account of what it refuses, phrased at length and at last"
        " reaching the word message."
    )

    assert not _attributions('"""' + spread + '"""')
