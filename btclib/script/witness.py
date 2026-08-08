# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Witness dataclass; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
)

__all__ = [
    "Witness",
]


# frozen, and a tuple rather than a list of bytes, which makes a Witness
# immutable all the way down: neither replacing the whole stack of a
# witness held by someone else (issue #140) nor mutating one in place
# through a shared default (issue #139) is expressible, and the
# generated __hash__ works, every element being immutable too.
#
# A witness is built once — parsed, or handed a signature and a script —
# and then read, so the interpreter's popping is done on a list of its own
@dataclass(frozen=True)
class Witness:
    """The witness stack of one transaction input, per BIP141.

    A tuple of byte strings, bottom of the stack first, exactly as
    serialized in the transaction's witness section after the outputs;
    a non-segwit input has an empty one. Immutable throughout, so a
    Witness can be shared and hashed; the script interpreter pops a list
    copy of its own.
    """

    stack: tuple[bytes, ...]

    def __init__(
        self, stack: Sequence[Octets] | None = None, *, check_validity: bool = True
    ) -> None:
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        object.__setattr__(
            self,
            "stack",
            tuple(bytes_from_octets(element) for element in stack) if stack else (),
        )

        if check_validity:
            self.assert_valid()

    def __len__(self) -> int:
        return len(self.stack)

    def assert_valid(self) -> None:
        """Refuse a stack element that does not read as bytes.

        Any elements are a valid witness -- what they must mean is the
        spending script's business -- so readability is the whole
        check.
        """
        for stack_element in self.stack:
            bytes(stack_element)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, list[str]]:
        """Return the witness as a dict of hex strings, for json.

        from_dict reads the same shape back, and the round trip is
        exact, hex being a spelling of the bytes and nothing less.
        """
        if check_validity:
            self.assert_valid()

        return {"stack": [v.hex() for v in self.stack]}

    @classmethod
    def from_dict(
        cls: type[Witness],
        dict_: Mapping[str, Sequence[Octets]],
        *,
        check_validity: bool = True,
    ) -> Witness:
        """Build a Witness from the dict shape to_dict writes."""
        return cls(dict_["stack"], check_validity=check_validity)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the serialization of the Witness."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.stack))
        return out + b"".join([var_bytes.serialize(w) for w in self.stack])

    @classmethod
    def parse(
        cls: type[Witness], data: BinaryData, *, check_validity: bool = True
    ) -> Witness:
        """Return a Witness by parsing binary data.

        Octets are one whole witness and a stream is the caller's:
        btclib/utils.py states the rule both halves of this contract read.
        The stream case is what a transaction is parsed with -- one witness
        per input, out of the stream the transaction is read from -- and the
        octet case is what a PSBT_IN_FINAL_SCRIPTWITNESS value is.
        """
        stream = bytesio_from_binarydata(data)
        n = var_int.parse(stream)
        stack = [var_bytes.parse(stream) for _ in range(n)]
        assert_no_trailing(data, stream, "witness")
        return cls(stack, check_validity=check_validity)
