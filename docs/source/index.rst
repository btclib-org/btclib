btclib
======

btclib is a python3 type annotated library intended for teaching and demonstration of the cryptography used in bitcoin.

Originally developed for the 'Bitcoin and Blockchain Technology Course' at Milano Bicocca and Politecnico di Milano, its algorithms are not intended for production environments: they could be broken using side-channel attacks; moreover, they might be subjected to major refactoring without care for backward compatibility.

The library includes:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octet / integer / point conversion functions
- elliptic curve class
  - fast algebra implemented using Jacobian coordinates
  - double scalar multiplication (Shamir's trick)
  - point simmetry solution: odd/even, high/low, and quadratic residue
  - available curves: SEC 1 v1 and v2, NIST, Brainpool, and low cardinality test curves
- DSA signature with (transaction) DER encoding and (message) compact encoding
- EC sign-to-contract notarization
- EC Schnorr signature (according to bip-schnorr bitcoin standardization)
  - batch validation
  - threshold signature
  - MuSig multi-signature
- EC Borromean ring signature
- RFC 6979 to make signature schemes deterministic
- EC Diffie-Hellman
- Pedersen Committment
- base58 encoding, addresses, WIFs
- BIP32 hierarchical deterministic wallets
- BIP39 mnemonic code for generating deterministic keys
- Electrum standard for mnemonic code

A very extensive test suite reproduces results from major official sources and covers basically 100% of the library code base.

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