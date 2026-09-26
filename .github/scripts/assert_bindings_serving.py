# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Assert the floor resolution's bindings still import and serve.

deps-oldest.yml's caller job passes this file's path as `pre-suite-script`
to btclib-org/.github's `reusable-deps-oldest.yml`, which runs it against
the floor resolution `uv lock --resolution lowest-direct` just wrote,
before the suite.

ellipticcurves imports the bindings' whole surface in one `try` whose
`except ImportError` sets `INSTALLED = False`, so a floor release of
`btclib_secp256k1` short of one name loses every delegation rather than
that one, and `tests/conftest.py`'s
`pytest_collection_modifyitems` then skips every `bindings`-marked test.
A bare pytest run over that skip reports green, `--no-cov` giving up the
one ratchet that would otherwise notice the shortfall, which is why this
step runs ahead of it and by name rather than folded into it.

`is_libsecp256k1_serving` and not the installation: serving is installed
and not refused, and nothing here sets `ELLIPTICCURVES_NO_LIBSECP256K1`,
so the two agree, and it is the public reading of the seam deps-latest.yml's own
`suite-bindings-latest` job asserts the same way against the newest
bindings instead of the floor.
"""

from __future__ import annotations

from btclib.curves import is_libsecp256k1_serving


def main() -> int:
    """Return 0 where the bindings serve, 1 otherwise."""
    if not is_libsecp256k1_serving():
        print("btclib_secp256k1 at its declared floor does not import")  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
