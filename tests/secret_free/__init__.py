# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Assert that a refusal carries no secret, in any exception it chains.

The rule is section 7 of the btclib-org standard, *A refusal carries no
secret*. Section 14 has this file copied verbatim, so a change to it is
made in btclib-org/.github and carried to every copy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "assert_secret_free",
    "chained",
    "hexes",
    "spellings",
    "text_of",
    "windows",
]

#: How many characters a piece of a string secret has; a bytes piece has half
#: as many bytes.
WINDOW = 12


def chained(exc: BaseException) -> Iterator[BaseException]:
    """Yield an exception and every one reached through its cause and context.

    `from None` hides `__context__` from a traceback and keeps it on the
    exception, so it is walked whatever `__suppress_context__` says.

    :param exc: the exception raised.
    :returns: each exception of the chain, once, so a cycle ends the walk.
    """
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        todo += [e.__cause__, e.__context__]


def hexes(values: Iterable[object]) -> list[str]:
    """Return the hex of every value that is bytes.

    `repr` shows bytes as escapes and printable characters, never as hex,
    so a key held as bytes is read in the spelling a caller feeds.

    :param values: what an exception holds.
    :returns: the `.hex()` of each `bytes` or `bytearray` among them.
    """
    return [bytes(v).hex() for v in values if isinstance(v, (bytes, bytearray))]


def text_of(e: BaseException) -> str:
    """Return every text an exception shows, lowercased.

    A `UnicodeError` keeps the whole input in `args` and in `.object`.
    `.object` is read on its own because it can be set apart from `args`,
    and `vars` shows neither. The hex is taken of top-level values only:
    bytes nested in a list or a tuple are read through `repr` alone.

    :param e: one exception.
    :returns: its `str`, `repr`, `args`, attributes and `.object`, and the
        hex of any bytes among the last three.
    """
    attributes = getattr(e, "__dict__", {})
    held = getattr(e, "object", None)
    parts = [
        str(e),
        repr(e),
        repr(e.args),
        repr(attributes),
        repr(held),
        *hexes(e.args),
        *hexes(attributes.values()),
        *hexes([held]),
    ]
    return " ".join(parts).lower()


def spellings(secret: str | bytes | bytearray) -> list[str]:
    """Return what a secret is looked for as, lowercased.

    :param secret: a spelling of the secret, or its bytes or bytearray.
    :returns: a string as given; for bytes, their hex and the body of their
        `repr`, which is what an f-string's `!r` writes.
    """
    if isinstance(secret, str):
        return [secret.lower()]
    return [secret.hex(), repr(bytes(secret))[2:-1].lower()]


def windows(secret: str | bytes | bytearray) -> list[str | bytes | bytearray]:
    """Return every piece of a secret that is looked for.

    A refusal may echo the end or the middle of a value, such as the key
    field at the end of an xprv, so every piece is looked for, not the
    start alone. A piece of bytes, whose hex is `WINDOW` characters, is
    longer than the version or prefix field section 7 lets a refusal
    print. A secret shorter than a piece is its own one piece.

    :param secret: a spelling of the secret, or its bytes or bytearray.
    :returns: its pieces.
    """
    size = WINDOW if isinstance(secret, str) else WINDOW // 2
    last = max(len(secret) - size, 0)
    return [secret[i : i + size] for i in range(last + 1)]


def assert_secret_free(
    exc: BaseException, secrets: Iterable[str | bytes | bytearray]
) -> None:
    """Assert that no piece of a secret, in any spelling, is in the chain.

    A piece is what `windows` returns, so a refusal quoting less of a
    secret than a piece passes: a mnemonic is passed word by word, and a
    passphrase shorter than a piece is passed whole. Splitting a mnemonic
    here is the rejected alternative: a short word such as "key" or "one"
    is inside many clean messages.

    A piece of a secret can also be a piece of a clean message, so a
    secret fed is a fixed random value, not a run such as all zeros, and
    a mnemonic's words are not words of the refusal's own text.

    :param exc: the exception raised.
    :param secrets: the secret fed, as bytes, as a bytearray, or in each
        spelling a refusal could print: the decimal of a scalar, its
        encodings, each word of a mnemonic.
    """
    pieces = {
        spelling
        for secret in secrets
        for piece in windows(secret)
        for spelling in spellings(piece)
    }
    for e in chained(exc):
        text = text_of(e)
        for piece in pieces:
            assert piece not in text
