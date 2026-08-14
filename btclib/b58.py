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
"""

from __future__ import annotations

from typing import Literal

from btclib import b32
from btclib.alias import Octets, ScriptType, String
from btclib.base58 import decode as b58decode
from btclib.base58 import encode as b58encode
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.network import network_from_key_value, network_from_name
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "address_from_h160",
    "h160_from_address",
    "p2pkh",
    "p2sh",
    "p2wpkh_p2sh",
    "p2wsh_p2sh",
    "wif_from_prv_key",
]


def wif_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> str:
    """Return the WIF encoding of a private key."""
    # asked here rather than passed down: `prv_keyinfo_from_prv_key` is
    # called without it, so what the key says is what comes back and this
    # is where a caller's own choice is read
    if compressed is not None:
        assert_type(compressed, bool, "compressed")
    q, net, compr = prv_keyinfo_from_prv_key(prv_key)

    # the private key might provide network and compressed information
    # e.g., wif or xprv
    network = net if network is None else network
    compressed = compr if compressed is None else compressed

    ec = network_from_name(network).curve
    payload = b"".join(
        [
            network_from_name(network).wif,
            q.to_bytes(ec.n_size, byteorder="big", signed=False),
            b"\x01" if compressed else b"",
        ]
    )
    return b58encode(payload).decode("ascii")


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


def p2pkh(key: Key, network: str | None = None, compressed: bool | None = None) -> str:
    """Return the p2pkh base58 address corresponding to a public key."""
    pub_key, network = pub_keyinfo_from_key(key, network, compressed=compressed)
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
    pub_key, network = pub_keyinfo_from_key(key, network, compressed=True)
    witness_program = hash160(pub_key)
    return _address_from_v0_witness(witness_program, network)


def p2wsh_p2sh(redeem_script: Octets, network: str = "mainnet") -> str:
    """Return the base58 p2sh-wrapped address of a p2wsh."""
    witness_program = sha256(redeem_script)
    return _address_from_v0_witness(witness_program, network)
