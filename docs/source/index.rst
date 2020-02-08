btclib
======

btclib is a python3 type annotated library intended for
teaching/learning/using bitcoin, its blockchain,
and the associatec elliptic curve cryptography.

It does not have external requirements or dependencies;
to install (and upgrade) it:

```shell
python -m pip install --upgrade btclib
```

Originally developed for the
Bitcoin and Blockchain Technology
course at the University of Milano-Bicocca,
the library is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility;
moreover, some of its algorithms could be broken using side-channel attacks.

The library includes:

* modulo algebra functions (gcd, inverse, legendre symbol, square root)
* octets / integer / varint / point conversion functions
* elliptic curve class

  * fast algebra implemented using Jacobian coordinates
  * double scalar multiplication (Straus's algorithm, also known as Shamir's trick)
  * multi scalar multiplication (Bos-coster's algorithm)
  * point simmetry solution: odd/even, low/high, and quadratic residue
* available curves: SEC 1 v1 and v2, NIST, Brainpool, and low cardinality test curves
* DSA signature with (transaction) DER encoding
* DSA signature with (message) compact encoding: standard p2pkh
  and BIP137/Electrum
  extensions to p2wpkh and p2wpkh-p2sh
* Schnorr signature (according to bip-schnorr bitcoin standardization)

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
* BIP39 wordlists and mnemonic for generating deterministic keys
* Electrum standard for mnemonic
* Script encoding/decoding
* nulldata, p2pk, p2pkh, multi-sig, p2sh, p2wpkh, and p2wsh ScriptPubKeys

A very extensive test suite reproduces results from major official sources
and covers 100%
of the library code base.

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
