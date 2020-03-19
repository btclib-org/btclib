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
the address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65-bytes encoding
(i.e. not the DER encoding used for transactions,
which would results in 71-bytes average signature).

One should never sign a vague statement that could be reused
out of the context it was intended for. Always include at least:

- name (nickname, customer id, e-mail, etc.)
- date and time
- who the message is intended for (name, business name, e-mail, etc.)
- specific purpose of the message

To mitigate the risk of signing a possibly deceiving message,
for any given message a *magic* "Bitcoin Signed Message" prefix is added,
then the hash of the resulting message is ECDSA signed.

As it is the case for all digital signature schemes,
this scheme works with private/public key pairs, not addresses:
the address is only used to uniquely identify a private/public key pair.
At signing time, a wallet infrastructure is required to access the
private key corresponding to a given address;
alternatively, the private key must be provided explicitly.

To verify the signature the public key is not needed
because (EC)DSA allows public key recovery:
public keys that correctly verify the signature
can be implied from the signature itself.
In the case of the Bitcoin secp256k1 curve,
up to four public keys are recovered:
at verification time the address must match
the public key in the recovery set
that was explicitly marked as the right one
at signature time using a dedicated recovery flag.

The (r, s) DSA signature is serialized as
[1 byte][r][s], where the first byte is the recovery flag used
at verification time to discriminate among recovered
public keys (and address types).
Explicitly, the recovery flag value is:

    key_id + (4 if compressed else 0) + 27

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address;
- compressed indicates if the address is the hash of the compressed
  public key representation
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bitcoin Core;
  when the recovery flag is in the [31, 34] range of compressed addresses,
  Electrum also check for P2WPKH-P2SH and P2WPKH
  (SegWit always uses compressed public keys);
  BIP137 (Trezor) uses, instead, 35 and 39 instead of 27
  for P2WPKH-P2SH and P2WPKH (respectively).

+-----------+--------+-------------------------------------------------------+
| recflag | key_id | address type                                            |
+=========+========+=========================================================+
|    27   |    0   | P2PKH uncompressed                                      |
+--------+--------+----------------------------------------------------------+
|    28   |    1   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    29   |    2   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    30   |    3   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    31   |    0   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    32   |    1   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    33   |    2   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    34   |    3   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    35   |    0   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    36   |    1   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    37   |    2   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    38   |    3   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    39   |    0   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    40   |    1   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    41   |    2   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    42   |    3   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+

Finally, the serialized signature is base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash).
The equal sign '=' is used as end marker of the encoded message.

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

# TODO: add small wallet (address <-> private key) infrastructure
# TODO:                           then also add sign(address, msg)
# TODO: decouple serialization from address-based signature
# TODO: check test vectors from P. Todd's library


def _magic_hash(msg: Union[str, bytes]) -> bytes:
    t = b'\x18Bitcoin Signed Message:\n' + len(msg).to_bytes(1, 'big')
    if isinstance(msg, str):
        # Electrum does strip leading and trailing spaces;
        # bitcoin core does not
        # TODO: report Electrum bug
        # msg = msg.strip()
        t += msg.encode()
    else:
        t += msg
    return sha256(t).digest()


def msgsign(msg: Union[str, bytes], wif: Union[str, bytes], 
            addr: Optional[Union[str, bytes]] = None) -> bytes:
    """Generate the message signature."""

    if isinstance(addr, str):
        addr = addr.strip()
        addr = addr.encode("ascii")

    # first sign the message
    magic_msg = _magic_hash(msg)
    q, compressed, _ = prvkey_from_wif(wif)
    sig = sign(magic_msg, q)

    # now calculate the key_id
    pubkeys = pubkey_recovery(magic_msg, sig)
    Q = mult(q)
    key_id = pubkeys.index(Q)
    pubkey = octets_from_point(Q, compressed)

    # finally, calculate the recovery flag
    if addr is None or addr == p2pkh_address(pubkey):
        rf = key_id + 27
        rf += 4 if compressed else 0
    # BIP137
    elif addr == p2wpkh_p2sh_address(pubkey):
        rf = key_id + 35
    elif addr == p2wpkh_address(pubkey):
        rf = key_id + 39
    else:
        raise ValueError("Mismatch between private key and address")
    
    # serialize [rf][r][s]
    t = bytes([rf]) + sig[0].to_bytes(32, 'big') + sig[1].to_bytes(32, 'big')
    return base64.b64encode(t)


def verify(msg: Union[str, bytes],
           addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    """Verify message signature for a given address."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, addr, sig)
    except Exception:
        return False


def _verify(msg: Union[str, bytes],
            addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # signature is serialized as 65-bytes in base64 encoding
    sig = base64.b64decode(sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong encoding length: {len(sig)} instead of 65")

    # sig = [rf][r][s]
    rf = sig[0]
    if rf < 27 or rf > 42:
        raise ValueError(f"Invalid recovery flag: {rf}")
    r = int.from_bytes(sig[1:33], byteorder='big')
    s = int.from_bytes(sig[33:], byteorder='big')
    magic_msg = _magic_hash(msg)
    Qs = pubkey_recovery(magic_msg, (r, s))
    # key_id can be retireved as least significant 2 bits of the recovery flag
    #    key_id = 00;     key_id = 01;     key_id = 10;     key_id = 11
    # 27-27 = 000000;  28-27 = 000001;  29-27 = 000010;  30-27 = 000011
    # 31-27 = 000100;  32-27 = 000101;  33-27 = 000110;  34-27 = 000111
    # 35-27 = 001000;  36-27 = 001001;  37-27 = 001010;  38-27 = 001011
    # 39-27 = 001100;  40-27 = 001101;  41-27 = 001110;  42-27 = 001111
    key_id = rf - 27 & 0b11
    Q = Qs[key_id]

    # signature is valid only if the provided address is matched
    compressed = True
    if rf < 31:
        compressed = False
    pubkey = octets_from_point(Q, compressed)
    try:
        # base58 address
        _, _, h160 = h160_from_base58_address(addr)
        if rf < 35 and hash160(pubkey) == h160:
            # P2PKH
            return True
        elif rf < 39:
            # P2WPKH-P2SH
            script_pubkey = b'\x00\x14' + hash160(pubkey)
            return hash160(script_pubkey) == h160
        else:
            errmsg = f"Invalid recovery flag ({rf}) for base58 address ({addr})"
            raise ValueError(errmsg)
    except Exception:
        # bech32 address
        _, _, h160 = hash_from_bech32_address(addr)
        if rf > 38 or (30 < rf and rf < 35) :
            # P2WPKH
            return hash160(pubkey) == h160
        else:
            errmsg = f"Invalid recovery flag ({rf}) for bech32 address ({addr})"
            raise ValueError(errmsg)
