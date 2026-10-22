# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `secret_free`.

Section 14 has that helper copied into each tree that owes it. Each read
the helper makes has a case that only that read can see, and a clean
refusal is the control: a helper that reads nothing passes it too, so
every planted case has to fail.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from typing_extensions import override

from .secret_free import assert_secret_free, chained

if TYPE_CHECKING:
    from collections.abc import Callable

#: A made-up key in hex, the spelling a caller would feed.
KEY = "1d2f3e4d5c6b7a8998a7b6c5d4e3f20112233445566778899aabbccddeeff0a1"

#: The same key as bytes, as a parser holds it.
KEY_BYTES = bytes.fromhex(KEY)

#: The key with its digits turned to letters, so every character changes with
#: its case.
LETTERS = KEY.translate(str.maketrans("0123456789", "ghijklmnop"))

#: A made-up secret in mixed case, as a WIF or an xprv is spelled.
MIXED = "".join(c.upper() if i % 2 else c for i, c in enumerate(LETTERS))

#: A made-up mnemonic, fed word by word.
MNEMONIC = ["sausage", "velvet", "orbit", "lizard"]

#: A made-up 78-byte xprv-shaped value: a version field, then key bytes.
VERSIONED = bytes.fromhex("0488ade4") + KEY_BYTES + KEY_BYTES[::-1] + KEY_BYTES[:10]


class _KeyInStrError(ValueError):
    """A refusal whose `str` alone shows the key."""

    @override
    def __str__(self) -> str:
        return f"bad key {KEY}"

    @override
    def __repr__(self) -> str:
        return "KeyInStrError()"


class _KeyInReprError(ValueError):
    """A refusal whose `repr` alone shows the key."""

    @override
    def __str__(self) -> str:
        return "bad key"

    @override
    def __repr__(self) -> str:
        return f"KeyInReprError({KEY})"


class _FixedTextError(ValueError):
    """A refusal whose `str` and `repr` are fixed, whatever its `args`."""

    @override
    def __str__(self) -> str:
        return "bad key"

    @override
    def __repr__(self) -> str:
        return "FixedTextError()"


def raised(make: type[BaseException], *args: object) -> BaseException:
    """Build an exception the way a refusal does, by raising it.

    :param make: the exception type.
    :param args: its arguments.
    :returns: the exception, as caught.
    """
    with pytest.raises(make) as caught:
        raise make(*args)
    return caught.value


def refuse_from_none() -> None:
    """Refuse the key with a fixed text, `from None`.

    :raises TypeError: always, with the `ValueError` quoting the key as
        its hidden context.
    """
    try:
        int(KEY)
    except ValueError:
        msg = "bad key"
        raise TypeError(msg) from None


def with_attribute(value: object) -> BaseException:
    """Build a clean refusal that keeps a value as an attribute.

    :param value: what the refusal keeps.
    :returns: the exception.
    """
    e = raised(ValueError, "bad key")
    e.data = value  # type: ignore[attr-defined]
    return e


def with_object(value: bytes) -> BaseException:
    """Build a `UnicodeDecodeError` whose `.object` is set apart from `args`.

    :param value: what `.object` holds.
    :returns: the exception.
    """
    e = UnicodeDecodeError("ascii", b"public\xc3", 6, 7, "not ascii")
    e.object = value
    return e


def with_cause() -> BaseException:
    """Build a clean refusal whose cause quotes the key, with no context.

    :returns: the exception.
    """
    e = raised(ValueError, "bad key")
    e.__cause__ = raised(ValueError, KEY)
    return e


#: Each planted key, by the read that alone finds it or by its spelling
#: or piece.
PLANTED: dict[
    str, tuple[Callable[[], BaseException], list[str | bytes | bytearray]]
] = {
    "str": (lambda: raised(_KeyInStrError), [KEY]),
    "repr": (lambda: raised(_KeyInReprError), [KEY]),
    "args": (lambda: raised(_FixedTextError, KEY), [KEY]),
    "attributes": (lambda: with_attribute(KEY), [KEY]),
    "object": (lambda: with_object(KEY.encode()), [KEY]),
    "hex of args": (lambda: raised(_FixedTextError, KEY_BYTES), [KEY]),
    "hex of attributes": (lambda: with_attribute(KEY_BYTES), [KEY]),
    "hex of a bytearray": (
        lambda: raised(_FixedTextError, bytearray(KEY_BYTES)),
        [KEY],
    ),
    "bytearray as repr": (
        lambda: raised(ValueError, f"not a point: {KEY_BYTES!r}"),
        [bytearray(KEY_BYTES)],
    ),
    "hex of object": (lambda: with_object(KEY_BYTES), [KEY]),
    "cause": (with_cause, [KEY]),
    "start": (lambda: raised(ValueError, f"bad key {KEY[:16]}"), [KEY]),
    "middle": (lambda: raised(ValueError, f"bad key {KEY[20:40]}"), [KEY]),
    "end": (lambda: raised(ValueError, f"bad key {KEY[-12:]}"), [KEY]),
    "middle of bytes": (
        lambda: raised(ValueError, f"bad key {KEY_BYTES[10:20].hex()}"),
        [KEY_BYTES],
    ),
    "one word": (
        lambda: raised(ValueError, f"unknown word {MNEMONIC[1]!r}"),
        [*MNEMONIC],
    ),
    "upper case": (
        lambda: raised(ValueError, f"bad key {LETTERS.upper()}"),
        [LETTERS],
    ),
    "mixed case": (lambda: raised(ValueError, f"bad key {MIXED}"), [MIXED]),
    "bytes as hex": (lambda: raised(ValueError, f"bad key {KEY}"), [KEY_BYTES]),
    "bytes as repr": (
        lambda: raised(ValueError, f"not a point: {KEY_BYTES!r}"),
        [KEY_BYTES],
    ),
}


def test_a_clean_refusal_passes() -> None:
    """A refusal naming a length and a place says nothing of the key."""
    e = raised(ValueError, "input 2: key of 32 bytes")
    assert_secret_free(e, [KEY, KEY_BYTES, MIXED, *MNEMONIC])


def test_a_version_field_printed_with_r_passes() -> None:
    """The version field section 7 lets a refusal print is no piece of it."""
    e = raised(ValueError, f"xprv version {VERSIONED[:4]!r} where an xpub belongs")
    assert_secret_free(e, [VERSIONED])


@pytest.mark.parametrize("case", PLANTED)
def test_each_planted_key_is_found(case: str) -> None:
    """The key planted in each case is found.

    :param case: the case, by name.
    """
    make, secrets = PLANTED[case]
    with pytest.raises(AssertionError):
        assert_secret_free(make(), secrets)


@pytest.mark.parametrize("separator", [" ", "\t", "\n", "\N{EM SPACE}"])
@pytest.mark.parametrize("secret", [KEY, KEY_BYTES, bytearray(KEY_BYTES)])
def test_grouping_a_scalar_does_not_hide_its_hex(
    separator: str, secret: str | bytes | bytearray
) -> None:
    """Four-byte groups still disclose the scalar fed as text or bytes.

    :param separator: the whitespace between groups.
    :param secret: the scalar as a caller feeds it.
    """
    grouped = separator.join(KEY[i : i + 8].upper() for i in range(0, len(KEY), 8))
    with pytest.raises(AssertionError):
        assert_secret_free(raised(ValueError, f"bad scalar {grouped}"), [secret])


@pytest.mark.parametrize(
    "secret", ["vel vet orbit", b"vel vet orbit", bytearray(b"vel vet orbit")]
)
def test_a_passphrase_with_spaces_is_still_found(
    secret: str | bytes | bytearray,
) -> None:
    """A secret's own spaces do not weaken its raw spelling check.

    :param secret: the passphrase as a caller feeds it.
    """
    with pytest.raises(AssertionError):
        assert_secret_free(raised(ValueError, secret), [secret])


@pytest.mark.parametrize("secret", ["\t\n", " \t\n", b"\t\n", bytearray(b"\t\n")])
def test_a_whitespace_passphrase_is_compared_as_given(
    secret: str | bytes | bytearray,
) -> None:
    """A whitespace-only secret is found only where a refusal quotes it.

    :param secret: the whitespace-only passphrase.
    """
    assert_secret_free(raised(ValueError, "bad key"), [secret])
    with pytest.raises(AssertionError):
        assert_secret_free(raised(ValueError, secret), [secret])


@pytest.mark.parametrize("secret", [" a", "ke y", b" a", b"ke y"])
def test_a_secret_with_spaces_does_not_flag_a_clean_refusal(
    secret: str | bytes,
) -> None:
    """A secret's own whitespace is kept, so it cannot match across words.

    :param secret: a passphrase with whitespace of its own.
    """
    assert_secret_free(raised(ValueError, "bad key"), [secret])


def test_the_input_of_a_unicode_error_is_found() -> None:
    """A `UnicodeError` hides its input from `str` and `vars`, not `args`."""
    with pytest.raises(UnicodeDecodeError) as caught:
        (KEY + "\xe9").encode().decode("ascii")
    assert KEY not in str(caught.value)
    assert not vars(caught.value)
    with pytest.raises(AssertionError):
        assert_secret_free(caught.value, [KEY])


def test_a_context_hidden_by_from_none_is_read() -> None:
    """`from None` keeps `__context__`, and the walk reaches it."""
    with pytest.raises(TypeError) as caught:
        refuse_from_none()
    assert caught.value.__suppress_context__
    with pytest.raises(AssertionError):
        assert_secret_free(caught.value, [KEY])


def test_a_cycle_ends_the_walk() -> None:
    """Each exception is yielded once, a chain pointing back included."""
    first = raised(ValueError, "first")
    second = raised(ValueError, "second")
    first.__context__ = second
    second.__context__ = first
    assert list(chained(first)) == [first, second]
