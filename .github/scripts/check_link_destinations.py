# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Refuse a markdown link whose destination does not reach its file.

Section 4 of the organization's standard is the rule for the hooks that
run this, and section 2 is the reason for `readme-absolute-link`'s:

- `--prefixed`, `local-link-prefix`: a local destination begins with
  `./` or `../`;
- `--absolute`, `readme-absolute-link`: the root `README.md` has no
  local destination at all.

A destination is local where it is not empty, does not open with `#`
and names no scheme. It is read as markdown-it renders it, its percent
escapes as written: `%68ttps:` names no scheme, and `%2E/` is no `./`.
A refusal prints it decoded, as `normalizeLinkText` gives it, `%2F` and
`%23` staying escaped, wherever the rule refuses that text too, and as
rendered otherwise.

markdown-it parses each file as CommonMark, with GitHub's tables, and
what it renders as a link or an image is what this reads: a link inside
code, inside html or inside an image's description is not one. Every
link reference definition is read too, used or not, a repeated label's
included. The parse is CommonMark's, unchanged, and GitHub's footnotes
are read off it. A definition whose label opens with `^` is a
footnote's: it is not reported as a destination, and its body, the text
after the label, is parsed again for the links it holds, at the file's
own lines. A use naming such a label alone, `[^n]` or `[^n][]`, is the
footnote's reference and is not reported, while a link naming it as its
reference, `[text][^n]`, is a link and is. So `[^n]: notes.md` reports
nothing unless a link uses it: a footnote's body and a destination are
the same text, and only the use tells them apart.

Each refusal is printed as `file:line: ...`, the line being the one the
link opens on, or the definition's first, in the order the file holds
them; the script exits 1 where it printed one, and 2 where a file named
is not there. A file over `LIMIT` bytes is refused unread, markdown-it's time
growing faster than the file on some inputs.
"""

from __future__ import annotations

import argparse
import bisect
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from markdown_it import MarkdownIt
from markdown_it.rules_inline import autolink, image, link

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence

    from markdown_it.rules_inline import StateInline
    from markdown_it.token import Token

# the size past which a file is refused unread
LIMIT = 4 * 1024 * 1024

# a scheme, which makes a destination absolute
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")

# the token a link or an image opens with
OPENING = frozenset({"link_open", "image"})

# a footnote's reference, its label alone, as a shortcut or a collapsed
# reference
FOOTNOTE_USE = re.compile(r"\[\^(?:[^\[\]\\]|\\.)*\](?:\[\])?")

# the label of a footnote's definition, up to its colon
FOOTNOTE_LABEL = re.compile(r"\[\^(?:[^\[\]\\]|\\.)*\]:")

# what opens a line inside a block quote or a list item's continuation
CONTAINER = re.compile(r"^[ \t>]*", re.MULTILINE)

# the key, in a parse's env, of the inline source last read and the
# offsets of its line breaks
NEWLINES = "check_link_destinations.newlines"


def breaks(state: StateInline) -> list[int]:
    """Give the offsets of the line breaks in an inline source.

    They are found once per source, so that each link costs a search and
    not a scan of the source before it.

    :param state: the inline parse.
    :returns: the offsets, ascending.
    """
    cached = state.env.get(NEWLINES)
    if cached is None or cached[0] is not state.src:
        offsets = [found.start() for found in re.finditer("\n", state.src)]
        cached = state.env[NEWLINES] = (state.src, offsets)
    return cached[1]


def located(
    rule: Callable[[StateInline, bool], bool],
) -> Callable[[StateInline, bool], bool]:
    """Wrap an inline rule so that the token it opens records its line.

    The line is counted within the inline content, whose first line is
    its block's: a line break inside a link's parentheses is no token,
    so counting the tokens between would miss it.

    :param rule: markdown-it's `link`, `image` or `autolink` rule.
    :returns: the rule, setting `meta["line"]` on the link or image
        token it pushes, the pending text markdown-it flushes first
        being pushed before it, and `meta["footnote"]` on a link that is
        a footnote's reference. The parse is the rule's own.
    """

    def wrapped(state: StateInline, silent: bool) -> bool:  # noqa: FBT001
        start, count = state.pos, len(state.tokens)
        if not rule(state, silent):
            return False
        for token in state.tokens[count:]:
            if token.type in OPENING:
                token.meta["line"] = bisect.bisect_left(breaks(state), start)
                token.meta["footnote"] = bool(
                    FOOTNOTE_USE.fullmatch(state.src, start, state.pos)
                )
                break
        return True

    return wrapped


PARSER = MarkdownIt("commonmark").enable("table")
for rule in (link, image, autolink):
    PARSER.inline.ruler.at(rule.__name__, located(rule))


def links(tokens: Iterable[Token]) -> Iterator[tuple[int, str]]:
    """Yield each rendered link's and image's destination.

    :param tokens: the block tokens of a parse.
    :yields: the 1-based line the link opens on, and its destination.
    """
    line = 0
    for token in tokens:
        if token.map:
            line = token.map[0]
        for child in token.children or ():
            if child.meta.get("footnote"):
                continue
            if child.type == "link_open":
                yield line + child.meta["line"] + 1, str(child.attrGet("href"))
            elif child.type == "image":
                yield line + child.meta["line"] + 1, str(child.attrGet("src"))


def footnote_links(text: str, reference: dict[str, Any]) -> list[tuple[int, str]]:
    """Read the links of a footnote's body, at the file's lines.

    The body is the definition's lines, from the text after its label to
    its last line, each line's block quote marker and indent removed so
    that a continuation reads as the paragraph it is in the footnote.

    :param text: the file.
    :param reference: the definition, as markdown-it records it.
    :returns: each link's line in the file, and its destination.
    """
    first, last = reference["map"]
    lines = text.split("\n")[first:last]
    label = FOOTNOTE_LABEL.search(lines[0])
    if label is None:
        return []
    lines[0] = lines[0][label.end() :]
    body = CONTAINER.sub("", "\n".join(lines))
    return [(first + line, href) for line, href in links(PARSER.parse(body, {}))]


def destinations(text: str) -> Iterator[tuple[int, str]]:
    """Yield every destination a markdown file links, in file order.

    Within a line the links come in the order the parse meets them.

    :param text: the file.
    :yields: the 1-based line and the destination, as markdown-it
        renders it.
    """
    text = text.replace("\r\n", "\n")
    env: dict[str, Any] = {}
    tokens = PARSER.parse(text, env)
    definitions = list(env.get("references", {}).items()) + [
        (reference["label"], reference) for reference in env.get("duplicate_refs", ())
    ]
    found = []
    for label, reference in definitions:
        if label.startswith("^"):
            found.extend(footnote_links(text, reference))
        else:
            found.append((reference["map"][0] + 1, reference["href"]))
    found.extend(links(tokens))
    yield from sorted(found, key=lambda item: item[0])


def local(destination: str) -> bool:
    """Say whether a destination is a path into the tree.

    :param destination: a destination as markdown-it renders it.
    :returns: whether it is not empty, opens with no `#` and names no
        scheme.
    """
    return (
        bool(destination)
        and not destination.startswith("#")
        and SCHEME.match(destination) is None
    )


def refused(destination: str, *, absolute: bool) -> bool:
    """Say whether the rule refuses a destination.

    :param destination: a destination.
    :param absolute: `--absolute`'s rule, rather than `--prefixed`'s.
    :returns: whether it is local and, under `--prefixed`, begins neither
        `./` nor `../`.
    """
    return local(destination) and (
        absolute or not destination.startswith(("./", "../"))
    )


def refusals(text: str, *, absolute: bool) -> Iterator[tuple[int, str]]:
    """Yield the destinations of a file the rule refuses.

    :param text: the file.
    :param absolute: `--absolute`'s rule, rather than `--prefixed`'s.
    :yields: the line and the destination of each refusal, as printed.
    """
    for line, destination in destinations(text):
        if refused(destination, absolute=absolute):
            shown = PARSER.normalizeLinkText(destination)
            yield line, shown if refused(shown, absolute=absolute) else destination


def main(argv: Sequence[str] | None = None) -> int:
    """Read each file named and print each refusal.

    :param argv: the arguments, `sys.argv[1:]` where ``None``.
    :returns: 1 where a file or a destination was refused, else 0; an
        argument parse error, a missing file among them, exits 2.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    rule = parser.add_mutually_exclusive_group(required=True)
    rule.add_argument("--prefixed", action="store_true", help="local-link-prefix")
    rule.add_argument("--absolute", action="store_true", help="readme-absolute-link")
    parser.add_argument("files", nargs="*", type=Path)
    arguments = parser.parse_args(argv)
    for path in arguments.files:
        if not path.is_file():
            parser.error(f"{path} is not a file")
    if arguments.absolute:
        why = "is local, where the page is read on the package index"
    else:
        why = "is local and begins neither ./ nor ../"
    refused = 0
    for path in arguments.files:
        if path.stat().st_size > LIMIT:
            refused += 1
            print(f"{path}: larger than {LIMIT} bytes, which this does not read")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line, destination in refusals(text, absolute=arguments.absolute):
            refused += 1
            print(f"{path}:{line}: the link destination {destination!r} {why}")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
