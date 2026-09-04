# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Base58 address and WIF functions.

**The bitcoin semantics.** Base58 encoding of public keys and scripts as
addresses, and of private keys as WIFs: the version prefixes, the networks,
p2pkh, p2sh, and the p2sh-wrapped segwit forms.

The encoding itself is btclib.base58, which knows nothing about bitcoin, and
the rule between the two is that direction: this module imports base58, never
the other way round. `bech32` and `b32` are the same pair for the segwit
address encoding.

A WIF is this module's object in both directions. `wif_from_prv_key` writes
one from a scalar, a network and a compression flag, and
`prv_key_data_from_wif` reads one back into a `key.PrvKeyData`. Nothing
above this module parses the format, and `to_prv_key` does not spell it:
that converter sits below this module and has no way to reach a parser
living here (issue #1188).
"""

from __future__ import annotations

from typing import Literal

from btclib import b32
from btclib.alias import Integer, Octets, ScriptType, String
from btclib.base58 import decode as b58decode
from btclib.base58 import encode as b58encode
from btclib.curves import scalar_from_prv_key
from btclib.exceptions import BTClibValueError, InvalidPrvKeyError, NotAPrvKeyError
from btclib.hashes import hash160, sha256
from btclib.key import PrvKeyData
from btclib.network import network_from_key_value, network_from_name
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "address_from_h160",
    "h160_from_address",
    "p2pkh",
    "p2sh",
    "p2wpkh_p2sh",
    "p2wsh_p2sh",
    "prv_key_data_from_wif",
    "wif_from_prv_key",
]


def wif_from_prv_key(
    prv_key: Integer, network: str = "mainnet", compressed: bool = True
) -> str:
    """Return the WIF encoding of a private key.

    A scalar, a network and whether the public key is compressed are the
    three things a WIF encodes, and they are the three arguments. A
    spelling that carries the other two with it is parsed first -- a WIF
    by `prv_key_data_from_wif` below, an xprv by `to_prv_key` -- and the
    fields of what comes back are handed here.
    """
    assert_type(compressed, bool, "compressed")
    net = network_from_name(network)
    q = scalar_from_prv_key(prv_key, net.curve)
    payload = b"".join(
        [
            net.wif,
            q.to_bytes(net.curve.n_size, byteorder="big", signed=False),
            b"\x01" if compressed else b"",
        ]
    )
    return b58encode(payload).decode("ascii")


def _wif_network(prefix: bytes, network: str | None) -> str:
    """Return the network a WIF version prefix belongs to.

    NotAPrvKeyError for a prefix no network claims: the text is not a
    WIF. InvalidPrvKeyError once a network has claimed it and the caller
    asked for another one: that is a WIF, and the wrong one.
    """
    net = network_from_key_value("wif", prefix)
    if net is None:
        raise NotAPrvKeyError(f"not a WIF (invalid prefix 0x{prefix.hex()})")

    if network is None:
        return net

    # the forward check, and not a `net != network` name comparison:
    # the reverse lookup answers "testnet" for the 0xef that testnet,
    # regtest, signet and testnet4 all use, so comparing names would
    # reject a signet WIF as "not a signet wif: prefix 0xef" --
    # naming the very prefix signet asks for (issue #207).
    # `bip32.prv_keyinfo_from_xprv` makes the same membership check
    if prefix != network_from_name(network).wif:
        raise InvalidPrvKeyError(f"not a {network} wif: prefix 0x{prefix.hex()}")
    # the declared network, not the lookup's guess: for a caller who
    # said "signet" the answer is signet, and it is the one that ends
    # up in the returned key
    return network


def _wif_prv_key_and_compression(
    payload: bytes, n_size: int, compressed: bool | None
) -> tuple[bytes, bool]:
    """Return the key bytes of a WIF payload, and whether it is compressed.

    The size is what says which of the two it is, the compressed
    spelling carrying one byte more; the caller's `compressed`, if it
    said anything, then has to agree with the answer.
    """
    if len(payload) == n_size + 2:  # compressed WIF
        compr = True
        if payload[-1] != 0x01:  # must have a trailing 0x01
            raise InvalidPrvKeyError("not a compressed WIF: missing trailing 0x01")
        prv_key = payload[1:-1]
    elif len(payload) == n_size + 1:  # uncompressed WIF
        compr = False
        prv_key = payload[1:]
    else:
        raise InvalidPrvKeyError(f"wrong WIF size: {len(payload)}")

    if compressed is not None and compr != compressed:
        raise InvalidPrvKeyError("compression requirement mismatch")

    return prv_key, compr


def prv_key_data_from_wif(
    wif: String, network: str | None = None, compressed: bool | None = None
) -> PrvKeyData:
    """Return the private key a WIF encodes, with its network and compression.

    A WIF carries both, so `network` and `compressed` are consistency
    checks and not overrides: `None` takes what the WIF says, and a value
    the WIF contradicts is refused. `network` is also what names a
    network sharing its prefix with others -- the 0xef that testnet,
    regtest, signet and testnet4 all use answers "testnet" on its own,
    and a caller who said "signet" gets signet (issue #207).

    Two error classes, in refusal order. Everything up to and including
    the version prefix answers "is this a WIF at all", and a no is a
    NotAPrvKeyError; everything after it answers "is this WIF sound", and
    a no is an InvalidPrvKeyError. Both are BTClibValueError. No message
    echoes the input, which is candidate key material: a checksum, a
    prefix and a size are not secret.
    """
    # None is a declared value here and means "whatever the WIF says", so
    # it is the one non-bool this position takes
    if compressed is not None:
        assert_type(compressed, bool, "compressed")
    if isinstance(wif, str):
        wif = wif.strip()

    # only a value no WIF has is re-classed: a wrong type leaves b58decode
    # as the BTClibTypeError it is, that being the caller's own mistake
    try:
        payload = b58decode(wif)
    except BTClibValueError as e:
        raise NotAPrvKeyError(f"not a WIF ({e})") from e

    net = _wif_network(payload[:1], network)
    ec = network_from_name(net).curve
    prv_key, compr = _wif_prv_key_and_compression(payload, ec.n_size, compressed)

    q = int.from_bytes(prv_key, byteorder="big")
    if not 0 < q < ec.n:
        raise InvalidPrvKeyError("private key not in 1..n-1")

    # every field has just been checked -- the name resolved to a network,
    # the scalar ranged on that network's curve, the flag read off the
    # size -- so the constructor is not asked to check them again
    return PrvKeyData(q, net, compr, check_validity=False)


# 1. Hash/WitnessProgram from pub_key/script_pub_key
# imported from the hashes module

# 2. base58 address from HASH and vice versa


def address_from_h160(
    script_type: ScriptType, h160: Octets, network: str = "mainnet"
) -> str:
    """Return a base58 address from the payload."""
    # the whole ScriptType and not a Literal of the two encoded here:
    # base58 encodes a subset of the vocabulary, so the raise below is
    # this function's answer to a caller holding the "p2tr"
    # type_and_payload has just returned -- and a parameter that cannot
    # spell it makes that a cast at every call site rather than a
    # message from here
    if script_type == "p2sh":
        prefix = network_from_name(network).p2sh
    elif script_type == "p2pkh":
        prefix = network_from_name(network).p2pkh
    else:
        raise BTClibValueError(f"invalid script type: {script_type}")

    payload = prefix + bytes_from_octets(h160, 20)
    return b58encode(payload).decode("ascii")


def h160_from_address(b58addr: String) -> tuple[ScriptType, bytes, str]:
    """Return the payload from a base58 address."""
    if isinstance(b58addr, str):
        b58addr = b58addr.strip()
    payload = b58decode(b58addr, 21)
    prefix = payload[:1]

    # the two script types a base58 address encodes -- and, the same two
    # spellings, the two Network fields holding their version prefixes,
    # which is what lets one loop variable be both a script type and a
    # lookup key. Annotated because inference widens a tuple of two
    # str literals to tuple[str, str], and str is neither
    script_types: tuple[Literal["p2pkh", "p2sh"], ...] = ("p2pkh", "p2sh")
    for script_type in script_types:
        if network := network_from_key_value(script_type, prefix):
            return script_type, payload[1:], network

    err_msg = f"invalid base58 address prefix: 0x{prefix.hex()}"
    raise BTClibValueError(err_msg)


# 1.+2. = 3. base58 address from pub_key/script_pub_key


def _pub_keyinfo_from_key(
    key: Key, network: str | None, compressed: bool | None
) -> tuple[bytes, str]:
    """Return (SEC octets, network) from a `Key`, a WIF included.

    A WIF is tried first: it is this module's own object, and disjoint
    from every other spelling `Key` carries -- 51 or 52 base58
    characters, where the shortest of the others is 64 hex digits, so
    trying it ahead of `to_pub_key.pub_keyinfo_from_key` costs nothing an
    ambiguous input could exploit. `to_pub_key` resolves everything else,
    and cannot resolve a WIF itself: it sits below this module and has no
    way back up to `prv_key_data_from_wif` (issue #1188).

    What falls through to `pub_keyinfo_from_key` is text that is no WIF
    at all -- a checksum that does not verify, a version prefix no
    network claims -- because there is another spelling left to try it
    as, and that call fails on the same text with the message callers
    already see. A WIF a network has claimed and that is then faulty --
    the wrong compression, a network other than the one asked for --
    raises here: `InvalidPrvKeyError` is what says the format was
    recognised, and swallowing it would answer "not a key" about
    something that is one.
    """
    if isinstance(key, (str, bytes, bytearray, memoryview)):
        try:
            data = prv_key_data_from_wif(key, network, compressed)
        except NotAPrvKeyError:
            pass
        else:
            return data.pub.sec, data.network
    return pub_keyinfo_from_key(key, network, compressed=compressed)


def p2pkh(key: Key, network: str | None = None, compressed: bool | None = None) -> str:
    """Return the p2pkh base58 address corresponding to a public key."""
    pub_key, network = _pub_keyinfo_from_key(key, network, compressed)
    return address_from_h160("p2pkh", hash160(pub_key), network)


def p2sh(script_pub_key: Octets, network: str = "mainnet") -> str:
    """Return the p2sh base58 address corresponding to a script_pub_key."""
    h160 = hash160(script_pub_key)
    return address_from_h160("p2sh", h160, network)


# 2b. base58 address from WitnessProgram
# it cannot be inverted because of the hash performed by p2sh


def _address_from_v0_witness(wit_prg: Octets, network: str) -> str:
    """Return the legacy base58 p2sh-wrapped segwit v0 address."""
    wit_prg = b32.bytes_from_witness_program(0, wit_prg)
    # the redeem script is [OP_0, wit_prg], spelled out here instead of
    # asking script.serialize for it: this module must not import
    # btclib.script, because script.script_pub_key imports this one to
    # render an address, and importing any script submodule executes the
    # package __init__, which pulls script_pub_key in — so the import
    # would close a cycle (issue #147).
    # bytes_from_witness_program has just restricted a v0 program to 20 or
    # 32 bytes, and serialize pushes anything shorter than 76 bytes with a
    # bare length byte, so no OP_PUSHDATA can be needed here
    redeem_script = b"\x00" + len(wit_prg).to_bytes(1, "big") + wit_prg
    return p2sh(redeem_script, network)


# 1.+2b. = 3b. base58 (p2sh-wrapped) segwit address from pub_key/script_pub_key


def p2wpkh_p2sh(key: Key, network: str | None = None) -> str:
    """Return the base58 p2sh-wrapped address of a p2wpkh."""
    pub_key, network = _pub_keyinfo_from_key(key, network, True)
    witness_program = hash160(pub_key)
    return _address_from_v0_witness(witness_program, network)


def p2wsh_p2sh(redeem_script: Octets, network: str = "mainnet") -> str:
    """Return the base58 p2sh-wrapped address of a p2wsh."""
    witness_program = sha256(redeem_script)
    return _address_from_v0_witness(witness_program, network)
