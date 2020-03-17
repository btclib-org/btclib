#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Bitcoin address-based compact signature for messages.

Bitcoin uses an address-based scheme for message signature:
this signature proves the control of the private key corresponding to
a given address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65-bytes signature encoding
(i.e. not the DER encoding used for transactions,
which would results in 71-bytes average signature).

As it is the case for all digital signature scheme,
this scheme actually works with private/public key pairs, not addresses:
the address is only used to uniquely identify a private/public key pair.
At signing time a wallet infrastructure is required to access the
private key corresponding to a given address;
alternatively, the private key must be provided explicitly.
The resulting signature goes along with its address:
public key recovery from the signature is used at verification time,
i.e. given a message, the public key that would have created that signature
is found and compared with the provided address.

One should never sign a vague statement that could be reused
out of the context it was intended for. Always include at least

- name (nickname, customer id, email, etc.)
- date and time
- who the message is intended for (name, business name, email, etc.)
- specific purpose of the message

To mitigate the risk of signing a possibly deceiving message,
for any given message a *magic* "Bitcoin Signed Message" prefix is added,
then the hash of the resulting message is ECDSA signed.

The resulting (r, s) signature is serialized as
[1 byte][r][s], where the first byte is a recovery flag used
during signature verification to discriminate among recovered
public keys and address types.
Explicitly, the recovery flag value is:

    key_id + 27 + (4 if compressed else 0)

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address;
  it is stored in the least significant 2 bits of the recovery flag
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bicoin Core;
  straightforward extensions to SegWit P2WPKH-P2SH and P2WPKH are obtained
  using 35 and 39 (respectively) instead of 27: this is the BIP137 (Trezor)
  specification (Electrum has a different incompatible specification);
- compressed indicates if the address is the hash of the compressed
  public key representation (SegWit is always compressed)

+-----------+--------+--------------------+
| rec. flag | key_id |    address type    |
+===========+========+====================+
|     27    |    0   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     28    |    1   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     29    |    2   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     30    |    3   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     31    |    0   | P2PKH compressed   |
+-----------+--------+--------------------+
|     32    |    1   | P2PKH compressed   |
+-----------+--------+--------------------+
|     33    |    2   | P2PKH compressed   |
+-----------+--------+--------------------+
|     34    |    3   | P2PKH compressed   |
+-----------+--------+--------------------+
|     35    |    0   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     36    |    1   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     37    |    2   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     38    |    3   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     39    |    0   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     40    |    1   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     41    |    2   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     42    |    3   | P2WPKH (bech32)    |
+-----------+--------+--------------------+

Finally, the serialized signature is base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash);
the equal sign '=' is used as end marker of the encoded message.

https://bitcoin.stackexchange.com/questions/10759/how-does-the-signature-verification-feature-in-bitcoin-qt-work-without-a-public

https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

https://bitcoin.stackexchange.com/questions/34135/what-is-the-strmessagemagic-good-for

https://bitcoin.stackexchange.com/questions/36838/why-does-the-standard-bitcoin-message-signature-include-a-message-prefix

https://bitcoin.stackexchange.com/questions/68844/explicit-message-length-in-bitcoin-signed-message

https://github.com/bitcoinjs/bitcoinjs-lib/blob/1079bf95c1095f7fb018f6e4757277d83b7b9d07/src/message.js#L13

https://bitcointalk.org/index.php?topic=6428

https://bitcointalk.org/index.php?topic=6430

https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106?newreg=670c5855241d4340af0cbbc960fd2dc3

https://github.com/bitcoin/bitcoin/pull/524

https://www.reddit.com/r/Bitcoin/comments/bgcgs2/can_bitcoin_core_0171_sign_message_from_segwit/

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki

https://github.com/brianddk/bips/blob/legacysignverify/bip-0xyz.mediawiki

"""

import base64
from hashlib import sha256
from typing import Optional, Union

from .address import h160_from_base58_address, p2pkh_address
from .curvemult import mult
from .dsa import pubkey_recovery, sign
from .segwitaddress import (hash_from_bech32_address, p2wpkh_address,
                            p2wpkh_p2sh_address)
from .utils import hash160, octets_from_point
from .wif import prvkey_from_wif

# TODO: support msg as bytes
# TODO: add small wallet (address <-> private key) infrastructure
# TODO:                           then also add sign(address, msg)
# TODO: decouple serialization from address-based signature
# TODO: add test vectors from P. Todd's library


def _magic_hash(msg: str) -> bytes:
    # Electrum does strip leading and trailing spaces;
    # bitcoin core does not
    # TODO: report Electrum bug
    # msg = msg.strip()
    msgstring = chr(len(msg)) + msg
    t = b'\x18Bitcoin Signed Message:\n' + msgstring.encode()
    return sha256(t).digest()


def msgsign(msg: str, wif: Union[str, bytes], 
            addr: Optional[Union[str, bytes]] = None) -> bytes:
    """Generate the message signature."""

    if isinstance(addr, str):
        addr = addr.strip()
        addr = addr.encode("ascii")

    # first sign the message
    magic_msg = _magic_hash(msg)
    q, compressedwif, _ = prvkey_from_wif(wif)
    sig = sign(magic_msg, q)

    # now calculate the recovery flag, aka recId
    pubkeys = pubkey_recovery(magic_msg, sig)
    Q = mult(q)
    rf = pubkeys.index(Q)
    pubkey = octets_from_point(Q, compressedwif)

    if addr is None or addr == p2pkh_address(pubkey):
        rf += 27
        rf += 4 if compressedwif else 0
    # BIP137
    elif addr == p2wpkh_p2sh_address(pubkey):
        rf += 35
    elif addr == p2wpkh_address(pubkey):
        rf += 39
    else:
        raise ValueError("Mismatch between private key and address")
    
    # [rf][r][s]
    t = bytes([rf]) + sig[0].to_bytes(32, 'big') + sig[1].to_bytes(32, 'big')
    return base64.b64encode(t)


def verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    """Verify message signature for a given P2PKH address."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, addr, sig)
    except Exception:
        return False


def _verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # [rf][r][s]
    sig = base64.b64decode(sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong encoding length: {len(sig)} instead of 65")

    rf = sig[0]
    if rf < 27 or rf > 42:
        raise ValueError(f"Invalid recovery flag: {rf}")
    r = int.from_bytes(sig[1:33], byteorder='big')
    s = int.from_bytes(sig[33:], byteorder='big')
    magic_msg = _magic_hash(msg)
    pubkeys = pubkey_recovery(magic_msg, (r, s))
    i = rf + 1 & 3  # the right pubkey for both BIP137 and Electrum
    pubkey = pubkeys[i]

    # signature is valid only if the provided address is matched
    if rf < 31:
        # P2PKH, uncompressed
        pk = octets_from_point(pubkey, False)
        _, _, h160 = h160_from_base58_address(addr)
        return hash160(pk) == h160

    pk = octets_from_point(pubkey, True)
    if rf < 35:
        try:
            # P2PKH, compressed
            _, _, h160 = h160_from_base58_address(addr)
            if hash160(pk) == h160:
                # P2PKH, compressed
                return True
            else:
                # Electrum p2wpkh-p2sh
                script_pubkey = b'\x00\x14' + hash160(pk)
                return hash160(script_pubkey) == h160
        except Exception:
            # Electrum p2wpkh
            _, _, h160 = hash_from_bech32_address(addr)
            return hash160(pk) == h160
    elif rf < 39:
        # BIP137 p2wpkh-ps2h
        _, _, h160 = h160_from_base58_address(addr)
        script_pubkey = b'\x00\x14' + hash160(pk)
        return hash160(script_pubkey) == h160
    else:
        # BIP137 p2wpkh
        _, _, h160 = hash_from_bech32_address(addr)
        return hash160(pk) == h160
