btclib
======

btclib is a
Python3 type annotated
library intended for teaching, learning, and using bitcoin,
its blockchain, and the associated elliptic curve cryptography.

It is rigorously and extensively tested: the test suite
covers 100%
of the code base and reproduces results from both informal
and major reference sources.

Originally developed for the
"Bitcoin and Blockchain Technology"
course at the University of Milano-Bicocca,
btclib is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility; moreover,
some of its algorithms could be broken using side-channel attacks.

btclib does not have external requirements or dependencies;
to install (and/or upgrade) it:

```shell
python -m pip install --upgrade btclib
```

Some dev tools are required to develop and test btclib;
they can be installed with:

```shell
python -m pip install -r requirements-dev.txt
```

The library features are:

* modulo algebra functions (gcd, inverse, legendre symbol, square root)
* octets / integer / var_int / point conversion functions
* elliptic curve class

  * fast algebra implemented using Jacobian coordinates
  * double scalar multiplication (Straus's algorithm, also known as Shamir's trick)
  * multi scalar multiplication (Bos-coster's algorithm)
  * point simmetry solution: odd/even, low/high, and quadratic residue
* elliptic curves: SEC 1 v1 and v2, NIST, Brainpool, and
  low cardinality test curves
* ECDSA signature with (transaction) DER encoding
* ECDSA signature with (message) compact encoding: standard p2pkh
  and BIP137/Electrum
  extensions to p2wpkh and p2wpkh-p2sh
* EC Schnorr signature (according to BIP340 standardization)

  * batch validation
  * threshold signature (see test-suite)
  * MuSig multi-signature (see test-suite)
* Borromean ring signature
* RFC 6979 to make signature schemes deterministic
* Sign-to-contract commitment
* Diffie-Hellman
* Pedersen committment
* Base58 encoding/decoding
* p2pkh/p2sh addresses and WIFs
* Bech32 encoding/decoding
* p2wpkh/p2wsh native SegWit addresses and their legacy p2sh-wrapped versions
* BIP32 hierarchical deterministic wallets
* SLIP132
  key versions (xprv, yprv, zprv, Yprv, Zprv, tprv, uprv, vprv, and Uprv)
  with corresponding mapping to
  p2pkh/p2sh, p2wpkh-p2sh, p2wpkh, p2wsh-p2sh, and p2wsh addresses
* BIP39 wordlists and mnemonic for generating deterministic keys
* Electrum standard for mnemonic
* Script encoding/decoding
* nulldata, p2pk, p2pkh, multi-sig, p2sh, p2wpkh, and p2wsh ScriptPubKeys
* BlockHeader and Block data classes
* OutPoint, TxIn, TxOut, and TX data classes
* segwit_v0_sig_hash
* BIP174 partially signed bitcoin transactions (PSBT):
  PsbtIn, PbstOut, and Psbt data classes

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Contents:
---------
.. toctree::
   :maxdepth: 2

   btclib.rst
