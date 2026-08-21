# The package-content policy

A release publishes two files, a wheel and an sdist. This page states
what may be in them, what may never be, and what has to be: the wheel is
what lands on `sys.path`, the sdist is what a build starts from, and both
are read before either is published.

`.github/scripts/verify_dist_contents.py` enforces every rule down to the
last section — the `dist` job of `test.yml` runs it on a build of every
pull request, and the same job, reached through `release.yml`'s `test`
call, on the files it is about to upload. The last section is the rules
nothing here enforces, which say so one by one rather than leaving the
list looking complete.

The script's constants are those rules, and the paragraph introducing
each list below names the ones the list states.
`tests/verify_dist_contents_test.py` compares the two in both directions,
so this page cannot state a rule the script does not have, and the script
cannot grow a rule this page does not state. The prose around the lists
is prose, and is checked by nobody.

## What may never be in either file

Checked against every member of both archives, the ones the `_data/`
amnesty below admits by directory rather than by extension included:
`FORBIDDEN_SUFFIXES` and `FORBIDDEN_NAMES`.

- `.pth` — executed at interpreter startup, before the first import
- `.dll`, `.dylib`, `.pyd`, `.so` — a compiled extension, which this
    project has none of: the secp256k1 bindings are a separate
    distribution, resolved at install time and never vendored
- `.exe` — a program rather than an extension, and refused for the same
    reason: nothing here is compiled, so nothing here ships a binary
- `.pyc` — a compiled module whose source nobody reviewed
- `.egg`, `.tar.gz`, `.whl`, `.zip` — an archive inside an archive, that
    is, a second package installing with the first
- `sitecustomize.py`, `usercustomize.py` — the two names Python imports
    for their side effects alone, at startup, from the root of
    site-packages. Both end in `.py`, which the wheel's allowlist would
    otherwise admit under `btclib/`: the rule is about the name, not
    about where it happens to be harmless

A `__pycache__` directory is refused too, by name rather than by suffix:
an empty one is a member in its own right and carries no `.pyc`.

## What the wheel may hold

An allowlist, it being what lands on `sys.path`: Python source under
`btclib/`, `btclib/py.typed`, whatever sits in a `_data/` directory, and
the `.dist-info` metadata setuptools writes. Anything else fails, which
is what makes a `.pth` file, a stray top-level module and a bundled
shared object one rule rather than three.

Under `btclib-<version>.dist-info/` — `WHEEL_METADATA_FILES`, beside the
`licenses/` directory setuptools copies `LICENSE`, `COPYRIGHT` and
`AUTHORS.md` into:

- `METADATA`, `RECORD`, `WHEEL`, `top_level.txt` — what setuptools
    writes for a package configured as this one is

`entry_points.txt` is deliberately not among them: pyproject.toml
declares no `[project.scripts]`, and an entry point is a code path a user
runs without importing anything, so one appearing there is a packaging
change that has to be read.

## What the sdist may hold

A structural check rather than an extension allowlist, `MANIFEST.in`
already being one: `recursive-include tests *.json` is the statement of
what a vendored vector may be, and a second copy of it here would be one
more edit per vector while catching nothing that file lets through. What
this adds is what `MANIFEST.in` cannot say — that every member sits under
the archive's own root directory, that every member is a regular file or
a directory (a tar can carry a symlink, a hardlink or a device node,
where a zip cannot), and that no directory holds the metadata of some
other distribution.

The directories, `SDIST_DIRECTORIES`:

- `btclib` — the package
- `tests` — its suite
- `docs` — the documentation sources
- `btclib.egg-info` — the metadata setuptools generates beside them

The files at that root, `SDIST_ROOT_SUFFIXES` and `SDIST_ROOT_NAMES`.
`MANIFEST.in` ships most of them by glob, `include *.md` and the two
beside it, so a file landing at the root is shipped without a packaging
decision being made; this is where that decision is recorded:

- `.md`, `.toml`, `.yaml`, `.jsonc` — what a reader of an unpacked sdist
    reads, and the configuration of the tools it names
- `LICENSE`, `COPYRIGHT` — the licence and the copyright notice, which
    `project.license-files` copies into the wheel as well
- `PKG-INFO`, `setup.cfg` — written by setuptools while it builds the
    archive, and not files of this tree
- `MANIFEST.in`, `uv.lock`, `.python-version`, `.secrets.baseline` —
    what makes an unpacked sdist buildable, and its lint gate runnable,
    which is `MANIFEST.in`'s own reason for carrying the last two

Under `btclib.egg-info/`, generated metadata and nothing else:
`SDIST_EGG_INFO_NAMES` and `SDIST_EGG_INFO_SUFFIXES`.

- `PKG-INFO`, `.txt` — what setuptools writes there; anything else is
    the tree the archive was built in leaking into it

## What has to be in there

The wheel, `WHEEL_REQUIRED`, beside the metadata files above, which are
required as well as allowed:

- `btclib/__init__.py` — a wheel with no package in it at all is the
    shape a misconfigured `packages.find` produces
- `btclib/py.typed` — PEP 561 makes its absence silent: the package
    installs, imports, and type checks as `Any`

And the sdist, `SDIST_REQUIRED`:

- `PKG-INFO` — the metadata PyPI reads off the archive
- `pyproject.toml` — what makes the archive buildable at all

The two carry one payload. `uv build` builds the sdist and then the wheel
from it, so `btclib/` is the same set of files in both; a difference
either way is a file that reaches a user installing from source and not
one installing the wheel, or the reverse.

## check-wheel-contents needs no configuration here

`check-wheel-contents` runs unconfigured, in the one job
`verify_dist_contents.py` runs in — `test.yml`'s `dist` job, on every pull
request and, through `release.yml`'s `test` call, on the files a release
publishes — and btclib-org/btclib#1160 is where that was decided rather than
merely left alone. `btclib-secp256k1` configures `[tool.check-wheel-contents]`
— `ignore = ["W003", "W009"]`, for the shared library its dynamic wheel ships
beside the package — because its wheel is not one package tree: a legitimate
top-level member outside `btclib_secp256k1/` is exactly what those two checks
exist to flag.
Nothing here ships outside `btclib/`, so neither check would ever fire,
and an `ignore` list naming codes that can never trigger would be a line
asserting a fact instead of preventing one.

The stronger question is whether `check-wheel-contents --package btclib`
would catch something this script does not: a full diff of the wheel's
`btclib/` against this checkout's own, the same completeness
`bitcoin-core-rpc` gained by configuring `package = ["bitcoin_core_rpc"]`
in that repository's own pull request (btclib-org/bitcoin-core-rpc#178),
for a project with no second check standing behind it. This project
already has two: `check-manifest`, a pre-commit hook gated by the lint
workflow, diffs the sdist against this same tree, and the completeness
check above — `uv build` builds the sdist and then the wheel from it, so
`btclib/` is the same set of files in both, and a difference either way
is reported — diffs the wheel against the sdist. Chained, checkout tree
== sdist == wheel, which is what `--package` would assert directly and
in one hop; configuring it here would be a third way of asking a question
two already answer, watching the same failure from a different angle
rather than closing a gap neither covers.

## The rules nothing here enforces

Three rules of the policy `diybitcoinhardware/embit` publishes beside its
own checker are not lists of members, and no list of members can show
them. That project does not check them either — its policy says so, in as
many words — so what follows each here is what stands in for a check.

- **No install-time execution hook.** Three shapes could carry one, and
    each is refused by a rule above: `setup.py` is not a root file the
    sdist ships, `entry_points.txt` is not one of the wheel's metadata
    files, and a `.pth` carries a forbidden suffix. None of those rules
    was written for this, which is worth knowing before trimming one to
    what a build happens to produce: it would take a guard with it.
    There is no `setup.py` in the tree at all — `[build-system]` names
    `setuptools.build_meta`, the configuration is declarative, and
    pyproject.toml has no field for a command class.
- **No network access while the package installs.** Which follows from
    the rule above and is not a check of its own: an installed wheel is
    Python source and data, pip runs none of it, and the three shapes
    that would run are the three that are refused.
- **No code generated from the network while a release is built.**
    `[build-system] requires` is the one line that can put somebody
    else's code in a build here, and it is one requirement long:
    `tests/build_system_test.py` asserts it names setuptools and nothing
    else, so a build requirement cannot be added in silence. A diff is
    what reads it; the test is what says a reader has to.

What none of this claims is that a build made no network request.
Proving that needs a sandboxed build, which is a different undertaking at
a different cost, and naming it as policy is the honest version. What is
checkable instead is the *result*: the build is reproducible from
`SOURCE_DATE_EPOCH`, and RELEASING.md has the command that rebuilds a
release from its tag and the bounds on it.
