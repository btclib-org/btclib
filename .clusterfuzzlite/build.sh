#!/bin/bash -eu
# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# Runs inside the container the Dockerfile beside this file builds, cwd
# at $SRC/btclib (the Dockerfile's WORKDIR). $CC, $CXX, $CFLAGS and
# $LIB_FUZZING_ENGINE are ClusterFuzzLite's own, exported before this
# script runs; installing here is what puts them in front of any
# extension a dependency compiles, which is why the install has to
# happen inside this container and not in the Dockerfile.
#
# The shape -- install, discover, compile -- is
# docs/build-integration/python_lang.md's own example build.sh for a
# Python project, and google/oss-fuzz's projects/idna/build.sh, a
# pure-Python parser of untrusted input the way Message.parse is.
#
# What the install takes is uv.lock's and not the index's.
# requirements.txt beside this file is the lock exported -- btclib's
# runtime dependencies and the `fuzz` dependency group's build backend,
# each with its hashes -- and the uv-export hook of
# .pre-commit-config.yaml rewrites it whenever uv.lock moves.
# --require-hashes refuses a file the lock does not name. btclib itself
# follows with --no-deps, and --no-build-isolation builds it with the
# backend just installed rather than one resolved off the index.
#
# Editable, because OpenSSF Scorecard's Pinned-Dependencies check reads a
# pip install as pinned only with --require-hashes, a wheel file, or `-e`
# and --no-deps (isUnpinnedPipInstall, ossf/scorecard's
# checks/raw/shell_download_validate.go), and pip refuses
# --require-hashes for a directory. The tree `-e` points at is the one
# the Dockerfile copied in, so pinned is what it is.
pip3 install --require-hashes --no-deps -r .clusterfuzzlite/requirements.txt
pip3 install --no-deps --no-build-isolation -e .

# compile_python_fuzzer forwards every extra argument straight to
# pyinstaller, ahead of the fuzzer's own path (base-builder's own
# compile_python_fuzzer script). --collect-data is what closes a gap
# PyInstaller's own analysis does not: btclib.network and btclib_ecc's
# curves.curve each read a JSON file under their own package's `_data/`
# directory at import time, from a path built off `__file__`,
# and a frozen onefile executable bundles no non-Python file
# PyInstaller cannot trace a reference to -- confirmed against this
# fuzzer's own import chain (btclib.p2p -> ... -> btclib.network ->
# btclib.curves), which crashed a real ClusterFuzzLite run on exactly
# this, `FileNotFoundError` on `curves/_data/ec_Brainpool.json` inside
# a PyInstaller `_MEI` extraction directory. `--collect-data` walks the
# whole of each package's tree rather than naming a `_data` directory
# alone, so a `_data/` directory the next harness reaches is bundled
# with no edit here.
#
# The same loop also zips each target's own seed corpus, one
# fuzz/corpus/<name>/ directory per fuzzer (google/fuzzing's glossary,
# "Seed Corpus": inputs "checked into source alongside fuzz targets"),
# under the name libFuzzer picks up next to a target's own binary with
# no configuration -- so a new fuzz_*.py with a corpus directory beside
# it is picked up here without a second list of names to keep in step
# with the first.
for fuzzer in $(find "$SRC/btclib/fuzz" -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --collect-data=btclib \
    --collect-data=btclib_ecc
  name=$(basename "$fuzzer" .py)
  if [ -d "fuzz/corpus/$name" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "fuzz/corpus/$name"/*.bin
  fi
done
