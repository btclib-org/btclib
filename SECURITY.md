# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/btclib/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to _security at btclib dot org_ is
equally welcome.

## What belongs here, and what belongs upstream

Signing, verification and generator multiplication on secp256k1 are
delegated to
[btclib_libsecp256k1](https://github.com/btclib-org/btclib_libsecp256k1/security/advisories/new),
the python bindings, and through them to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/security/advisories/new)
itself, which has its own security policy and its own address. A flaw in
the elliptic curve arithmetic, or in how the bindings drive it, most
likely belongs to one of those.

What belongs here is everything btclib does around them:

- the parsing and serialization of what comes from outside — keys,
    addresses, signatures, scripts, transactions, PSBTs — and the
    validation that decides what is accepted
- the derivation paths: BIP32, BIP39, Electrum mnemonics, SLIP132
- the script engine, and the taproot construction it validates against
- the pure python implementations, which are what runs whenever the
    conditions below are not met
- the distributions published to PyPI and their provenance

Report it wherever you found it, though: routing a report is the
maintainers' job, not the reporter's, and a doubt about which of three
projects owns a flaw is not a reason to keep it to yourself.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

## Limitations, not vulnerabilities

These are known and inherent. They are worth stating because btclib is
used to teach and to prototype as much as to build:

- secret material handed to btclib lives in python objects, which are
    immutable and not zeroized: it stays in the process memory until
    garbage collection, and may have been copied by the interpreter
    meanwhile. The constant-time properties of libsecp256k1 apply to the
    C side of the boundary, not to what happens before and after it
- not every operation crosses that boundary. `mult` reaches the bindings
    for secp256k1 and the generator alone; `dsa.sign` for secp256k1 with
    sha256, the lower-s form, no caller-imposed nonce and no commitment;
    `ssa.sign` for secp256k1 with sha256, a 32-byte message and no
    commitment. Anything else — another
    curve, another hash function, another message size, a nonce of your
    own — runs the python implementation, whose scalar multiplication is
    a double-and-add in Jacobian coordinates: it is validated against the
    bindings, which are the authority on the answer, but it is not
    constant-time and does not try to be. Using it
    on key material that matters is a choice, and this is the notice of it
- a sign-to-contract commitment is the signer's to open, and opening it
    twice over one message is safe only because the committed value
    reaches the nonce derivation: that is what keeps two such signatures
    from sharing an untweaked nonce and handing out the key. The
    derivation is `btclib.ecc.commit_nonce`, and the property is worth
    knowing about for anyone building the anti-exfil protocol on top,
    which btclib does not yet offer: there, the ordering matters as
    well — the signer must publish its `R` before learning the host's
    randomness, and `sign` alone cannot enforce that
- randomness comes from the operating system through the `secrets`
    module: the auxiliary randomness of BIP340 signing, the entropy of a
    generated mnemonic, and the private keys of the key generation
    helpers. Nothing here seeds a generator of its own
