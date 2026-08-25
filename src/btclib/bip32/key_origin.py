# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIP32KeyOrigin dataclass and the bip32_derivs codecs."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from io import BytesIO

from typing_extensions import override

from btclib.alias import Octets
from btclib.bip32.der_path import (
    DerPath,
    bytes_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
)
from btclib.exceptions import BTClibValueError
from btclib.utils import (
    bytes_from_octets,
    fields_from_json_object,
    list_from_json_array,
    read_exactly,
)

__all__ = [
    "BIP32KeyOrigin",
    "HdKeyPaths",
    "assert_valid_hd_key_paths",
    "decode_from_bip32_derivs",
    "decode_hd_key_paths",
    "encode_to_bip32_derivs",
]


@dataclass(frozen=True)
class BIP32KeyOrigin:
    """Where a key comes from: master fingerprint and derivation path.

    What BIP174's bip32_derivs and a descriptor's [fingerprint/path]
    prefix carry; the path is held as indexes, hardened ones offset
    by 0x80000000. The wire form is serialize and parse, the bracketed
    text form description and from_description.
    """

    master_fingerprint: bytes
    der_path: Sequence[int]

    @property
    def description(self) -> str:
        """Return the descriptor spelling: fingerprint/path, h for hardened."""
        return str_from_der_path(self.der_path, self.master_fingerprint)

    def __init__(
        self,
        master_fingerprint: Octets,
        der_path: DerPath,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "master_fingerprint", bytes_from_octets(master_fingerprint)
        )
        object.__setattr__(self, "der_path", indexes_from_der_path(der_path))

        if check_validity:
            self.assert_valid()

    def __len__(self) -> int:
        return len(self.der_path)

    def assert_valid(self) -> None:
        """Refuse a fingerprint not of 4 bytes, a path too long or out of range.

        Btclib bounds a BIP32 path at 255 indexes; each serialized index
        occupies 4 bytes.
        """
        if len(self.master_fingerprint) != 4:
            err_msg = "invalid master fingerprint length: "
            err_msg += f"{len(self.master_fingerprint)}"
            raise BTClibValueError(err_msg)
        if len(self) > 255:
            raise BTClibValueError(f"invalid der_path size: {len(self.der_path)}")
        if any(not 0 <= i <= 0xFFFFFFFF for i in self.der_path):
            raise BTClibValueError("invalid der_path element")

    def to_dict(self, *, check_validity: bool = True) -> dict[str, str]:
        """Return {"master_fingerprint", "path"} as hex and m/ text."""
        if check_validity:
            self.assert_valid()

        return {
            "master_fingerprint": self.master_fingerprint.hex(),
            "path": str_from_der_path(self.der_path),
        }

    @classmethod
    def from_dict(
        cls: type[BIP32KeyOrigin],
        dict_: Mapping[str, str],
        *,
        check_validity: bool = True,
    ) -> BIP32KeyOrigin:
        """Build a BIP32KeyOrigin from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "key origin")
        return cls(
            dict_["master_fingerprint"],
            dict_["path"],
            check_validity=check_validity,
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return BIP174's key-origin bytes: fingerprint, then the indexes."""
        if check_validity:
            self.assert_valid()

        return self.master_fingerprint + bytes_from_der_path(self.der_path)

    @classmethod
    def parse(
        cls: type[BIP32KeyOrigin], data: Octets, *, check_validity: bool = True
    ) -> BIP32KeyOrigin:
        """Return a BIP32KeyOrigin by parsing binary data.

        The four fingerprint octets are the encoding's boundary and not an
        opinion about what it means, so they are required whatever
        `check_validity` says: a slice of a shorter buffer answers with
        whatever is there, and the object serializes back longer than what
        it was parsed from. The other half of the same boundary is already
        unconditional -- `indexes_from_der_path` refuses a remainder that is
        not a whole number of 4-octet indexes.
        """
        data = bytes_from_octets(data)
        stream = BytesIO(data)
        master_fingerprint = read_exactly(stream, 4, "master fingerprint")
        der_path = indexes_from_der_path(stream.read())

        return cls(master_fingerprint, der_path, check_validity=check_validity)

    @classmethod
    def from_description(
        cls: type[BIP32KeyOrigin], data: str, *, check_validity: bool = True
    ) -> BIP32KeyOrigin:
        """Build a BIP32KeyOrigin from its fingerprint/path spelling."""
        data = data.strip()
        return cls(data[:8], data[9:], check_validity=check_validity)

    @override
    def __hash__(self: BIP32KeyOrigin) -> int:
        return hash(self.serialize())


# a mutable mapping from pub_key to fingerprint and derivation path
HdKeyPaths = MutableMapping[bytes, BIP32KeyOrigin]


def assert_valid_hd_key_paths(hd_key_paths: Mapping[bytes, BIP32KeyOrigin]) -> None:
    """Raise an exception if the dataclass element is not valid."""
    if len(hd_key_paths.values()) > len(
        {der_path.serialize() for der_path in hd_key_paths.values()}
    ):
        raise BTClibValueError("Duplicated key origin values in hd_key_paths")
    for pub_key, key_origin in hd_key_paths.items():
        # the length and not the point: BIP174 test vector 6 carries a
        # pub_key that is not on the curve, so parsing it here would
        # refuse a psbt the specification calls valid
        if len(pub_key) not in {78, 33, 65}:
            err_msg = f"invalid public key length: {len(pub_key)}"
            raise BTClibValueError(err_msg)
        key_origin.assert_valid()


def decode_hd_key_paths(map_: Mapping[Octets, BIP32KeyOrigin] | None) -> HdKeyPaths:
    """Return the dataclass element from its json representation."""
    hd_key_paths = {bytes_from_octets(k): v for k, v in map_.items()} if map_ else {}
    hd_key_paths = dict(sorted(hd_key_paths.items()))
    # the keys went through bytes_from_octets and the values came across
    # untouched, so this is a public entry through which an unchecked
    # origin enters a psbt's hd_key_paths -- and travels on to the json
    # `encode_to_bip32_derivs` writes. The validating counterpart sits
    # right above
    assert_valid_hd_key_paths(hd_key_paths)
    return hd_key_paths


_BIP32Deriv = Mapping[str, str]


def encode_to_bip32_derivs(
    hd_key_paths: Mapping[bytes, BIP32KeyOrigin],
) -> list[_BIP32Deriv]:
    """Return the json representation of the dataclass element."""
    assert_valid_hd_key_paths(hd_key_paths)
    return [
        {
            "pub_key": pub_key.hex(),
            "master_fingerprint": key_origin.master_fingerprint.hex(),
            "path": str_from_der_path(key_origin.der_path),
        }
        for pub_key, key_origin in sorted(hd_key_paths.items())
    ]


def _decode_from_bip32_deriv(
    bip32_deriv: Mapping[str, str],
    *,
    check_validity: bool,
) -> tuple[bytes, BIP32KeyOrigin]:
    bip32_deriv = fields_from_json_object(bip32_deriv, "bip32 derivation")
    master_fingerprint = bytes_from_octets(
        bip32_deriv["master_fingerprint"], 4 if check_validity else None
    )
    der_path = indexes_from_der_path(bip32_deriv["path"])
    key_origin = BIP32KeyOrigin(
        master_fingerprint, der_path, check_validity=check_validity
    )
    return bytes_from_octets(bip32_deriv["pub_key"]), key_origin


def decode_from_bip32_derivs(
    bip32_derivs: Sequence[Mapping[str, str]],
    *,
    check_validity: bool = True,
) -> HdKeyPaths:
    """Return the dataclass element from its json representation."""
    return dict(
        sorted(
            _decode_from_bip32_deriv(item, check_validity=check_validity)
            for item in list_from_json_array(bip32_derivs, "bip32 derivations")
        )
    )
