#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin message signing (BMS).

Bitcoin uses a P2PKH address-based scheme for message signature: such
a signature does prove the control of the private key corresponding to
the address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65-bytes (fixed size)
serialization format (i.e. not the ASN.1 DER format used for
transactions, which would results in 71-bytes average signature).

One should never sign a vague statement that could be reused
out of the context it was intended for. Always include at least:

- name (nickname, customer id, e-mail, etc.)
- date and time
- who the message is intended for (name, business name, e-mail, etc.)
- specific purpose of the message

To mitigate the risk of signing a possibly deceiving message,
for any given message a *magic* "Bitcoin Signed Message:\\n" prefix is
added, then the hash of the resulting message is signed.

This BMS scheme relies on ECDSA,
i.e. it works with private/public key pairs, not addresses:
the address is only used to identify a key pair.
At signing time, a wallet infrastructure is required to access
the private key corresponding to a given address;
alternatively, the private key must be provided explicitly.

To verify the ECDSA signature the public key is not needed
because (EC)DSA allows public key recovery:
public keys that correctly verify the signature
can be implied from the signature itself.
In the case of the Bitcoin secp256k1 curve,
two public keys are recovered
(up to four with non-zero but negligible probability);
at verification time the address must match
that public key in the recovery set
marked as the right one at signature time.

The (r, s) DSA signature is serialized as
[1-byte recovery flag][32-bytes r][32-bytes s],
in a compact 65-bytes (fixed-size) encoding.

The serialized signature is then base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash).
The equal sign '=' is used as encoding end marker.

The recovery flag is used
at verification time to discriminate among recovered
public keys (and among address types in the case
of scheme extension beyond P2PKH).
Explicitly, the recovery flag value is:

    key_id + (4 if compressed else 0) + 27

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address
- compressed indicates if the address is the hash of the compressed
  public key representation
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bitcoin Core;
  when the recovery flag is in the [31, 34] range of compressed
  addresses, Electrum also check for P2WPKH-P2SH and P2WPKH
  (SegWit always uses compressed public keys);
  BIP137 (Trezor) uses, instead, 35 and 39 instead of 27
  for P2WPKH-P2SH and P2WPKH (respectively)

+----------+---------+-----------------------------------------------------+
| rec flag |  key id | address type                                        |
+==========+=========+=====================================================+
|    27    |    0    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    28    |    1    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    29    |    2    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    30    |    3    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    31    |    0    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    32    |    1    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    33    |    2    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    34    |    3    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    35    |    0    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    36    |    1    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    37    |    2    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    38    |    3    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    39    |    0    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    40    |    1    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    41    |    2    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    42    |    3    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+

This implementation endorses the Electrum approach: a signature
generated with a compressed WIF (i.e. without explicit address or
with a compressed P2PKH address) is valid also for the
P2WPKH-P2SH and P2WPKH addresses derived from the same WIF.

Nonetheless, it is possible to obtain the BIP137 behaviour if
at signing time the compressed WIF is supplemented with
a P2WPKH-P2SH or P2WPKH address:
in this case the signature will be valid only for that same
address.

https://github.com/bitcoin/bitcoin/pull/524

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
"""

import secrets
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Optional, Tuple

from . import dsa
from .alias import BMSig, BMSigTuple, PrvKey, String
from .base58address import h160_from_b58address, p2pkh, p2wpkh_p2sh
from .base58wif import wif_from_prvkey
from .bech32address import p2wpkh, witness_from_b32address
from .curvemult import mult
from .curves import secp256k1
from .network import NETWORKS
from .secpoint import bytes_from_point
from .to_prvkey import prvkeyinfo_from_prvkey
from .utils import hash160


def _validate_sig(rf: int, r: int, s: int) -> None:

    if rf < 27 or rf > 42:
        raise ValueError(f"invalid recovery flag: {rf}")
    dsa._validate_sig(r, s, secp256k1)


def deserialize(sig: BMSig) -> BMSigTuple:
    """Return the verified components of the provided BSM signature.

    The address-based BSM signature can be represented
    as (rf, r, s) tuple or as base64-encoding of the compact format
    [1-byte rf][32-bytes r][32-bytes s].
    """
    if isinstance(sig, tuple):
        rf, r, s = sig
    else:
        if isinstance(sig, str):
            try:
                # hex-string of the encoded base64 signature string
                sig2 = b64decode(bytes.fromhex(sig))
            except Exception:
                # not encoded base64 signature string
                sig2 = b64decode(sig.encode())
        else:
            # encoded base64 signature string
            sig2 = b64decode(sig)

        if len(sig2) != 65:
            raise ValueError(f"wrong signature length: {len(sig)} instead of 65")
        rf = sig2[0]
        r = int.from_bytes(sig2[1:33], byteorder="big")
        s = int.from_bytes(sig2[33:], byteorder="big")

    _validate_sig(rf, r, s)
    return rf, r, s


def serialize(rf: int, r: int, s: int) -> bytes:
    """Return the BSM address-based signature as base64-encoding.

    First off, the signature is serialized in the
    [1-byte rf][32-bytes r][32-bytes s] compact format,
    then it is base64-encoded.
    """
    _validate_sig(rf, r, s)
    sig = bytes([rf]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64encode(sig)


def gen_keys(
    prvkey: PrvKey = None,
    network: Optional[str] = None,
    compressed: Optional[bool] = None,
) -> Tuple[bytes, bytes]:
    """Return a private/public key pair.

    The private key is a WIF, the public key is a base58 P2PKH address.
    """

    if prvkey is None:
        if network is None:
            network = "mainnet"
        ec = NETWORKS[network]["curve"]
        # q in the range [1, ec.n-1]
        q = 1 + secrets.randbelow(ec.n - 1)
        wif = wif_from_prvkey(q, network, compressed)
    else:
        wif = wif_from_prvkey(prvkey, network, compressed)

    address = p2pkh(wif)

    return wif, address


def _magic_message(msg: String) -> bytes:

    # Electrum does strip leading and trailing spaces;
    # Bitcoin Core does not
    if isinstance(msg, str):
        msg = msg.encode()

    t = b"\x18Bitcoin Signed Message:\n" + len(msg).to_bytes(1, "big") + msg
    return sha256(t).digest()


def sign(msg: String, prvkey: PrvKey, addr: Optional[String] = None) -> BMSigTuple:
    """Generate address-based compact signature for the provided message."""

    if isinstance(addr, str):
        addr = addr.strip()
        addr = addr.encode("ascii")

    # first sign the message
    magic_msg = _magic_message(msg)
    q, network, compressed = prvkeyinfo_from_prvkey(prvkey)
    r, s = dsa.sign(magic_msg, q)

    # now calculate the key_id
    # TODO do the match in Jacobian coordinates avoiding mod_inv
    pubkeys = dsa.recover_pubkeys(magic_msg, (r, s))
    Q = mult(q)
    # key_id is in [0, 3]
    # first two bits in rf are reserved for it
    key_id = pubkeys.index(Q)
    pubkey = bytes_from_point(Q, compressed=compressed)

    # finally, calculate the recovery flag
    if addr is None or addr == p2pkh(pubkey, network, compressed):
        rf = key_id + 27
        # third bit in rf is reserved for the 'compressed' boolean
        rf += 4 if compressed else 0
    # BIP137
    elif addr == p2wpkh_p2sh(pubkey, network):
        rf = key_id + 35
    elif addr == p2wpkh(pubkey, network):
        rf = key_id + 39
    else:
        raise ValueError("mismatch between private key and address")

    return rf, r, s


def assert_as_valid(msg: String, addr: String, sig: BMSig) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    rf, r, s = deserialize(sig)

    magic_msg = _magic_message(msg)
    c = dsa.challenge(magic_msg, secp256k1, sha256)
    # first two bits in rf are reserved for key_id
    #    key_id = 00;     key_id = 01;     key_id = 10;     key_id = 11
    # 27-27 = 000000;  28-27 = 000001;  29-27 = 000010;  30-27 = 000011
    # 31-27 = 000100;  32-27 = 000101;  33-27 = 000110;  34-27 = 000111
    # 35-27 = 001000;  36-27 = 001001;  37-27 = 001010;  38-27 = 001011
    # 39-27 = 001100;  40-27 = 001101;  41-27 = 001110;  42-27 = 001111
    key_id = rf - 27 & 0b11

    Recovered = dsa.__recover_pubkey(key_id, c, r, s, secp256k1)
    Q = secp256k1._aff_from_jac(Recovered)

    try:
        _, h160, _, is_script_hash = h160_from_b58address(addr)
        is_b58 = True
    except Exception:
        _, h160, _, is_script_hash = witness_from_b32address(addr)
        is_b58 = False

    compressed = False if rf < 31 else True
    # signature is valid only if the provided address is matched
    pubkey = bytes_from_point(Q, compressed=compressed)
    if is_b58:
        if is_script_hash and 30 < rf and rf < 39:  # P2WPKH-P2SH
            script_pk = b"\x00\x14" + hash160(pubkey)
            if hash160(script_pk) != h160:
                raise ValueError(f"wrong p2wpkh-p2sh address: {addr!r}")
        elif rf < 35:  # P2PKH
            if hash160(pubkey) != h160:
                raise ValueError(f"wrong p2pkh address: {addr!r}")
        else:
            err_msg = f"invalid recovery flag: {rf} (base58 address {addr!r})"
            raise ValueError(err_msg)
    else:
        if rf > 38 or rf > 30 and rf < 35:  # P2WPKH
            if hash160(pubkey) != h160:
                raise ValueError(f"wrong p2wpkh address: {addr!r}")
        else:
            err_msg = f"invalid recovery flag: {rf} (bech32 address {addr!r})"
            raise ValueError(err_msg)


def verify(msg: String, addr: String, sig: BMSig) -> bool:
    """Verify address-based compact signature for the provided message."""

    # try/except wrapper for the Errors raised by assert_as_valid
    try:
        assert_as_valid(msg, addr, sig)
    except Exception:
        return False
    else:
        return True
