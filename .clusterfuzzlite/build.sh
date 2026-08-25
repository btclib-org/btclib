#!/bin/bash -eu
# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# Runs inside the container the Dockerfile beside this file builds, cwd
# at $SRC/btclib (the Dockerfile's WORKDIR). $CC, $CXX, $CFLAGS and
# $LIB_FUZZING_ENGINE are ClusterFuzzLite's own, exported before this
# script runs; `pip3 install .` is what puts them in front of any
# extension a dependency compiles, which is why the install has to
# happen inside this container and not in the Dockerfile.
#
# The three-line shape -- install, discover, compile -- is
# docs/build-integration/python_lang.md's own example build.sh for a
# Python project, and google/oss-fuzz's projects/idna/build.sh, a
# pure-Python parser of untrusted input the way Message.parse is.
pip3 install .

# compile_python_fuzzer forwards every extra argument straight to
# pyinstaller, ahead of the fuzzer's own path (base-builder's own
# compile_python_fuzzer script). --collect-data=btclib is what closes a
# gap PyInstaller's own analysis does not: btclib.curves.curve and
# btclib.network each read a JSON file under their own package's
# `_data/` directory at import time, from a path built off `__file__`,
# and a frozen onefile executable bundles no non-Python file
# PyInstaller cannot trace a reference to -- confirmed against this
# fuzzer's own import chain (btclib.p2p -> ... -> btclib.network ->
# btclib.curves), which crashed a real ClusterFuzzLite run on exactly
# this, `FileNotFoundError` on `curves/_data/ec_Brainpool.json` inside
# a PyInstaller `_MEI` extraction directory. `--collect-data` walks the
# whole of `btclib`'s own tree rather than naming `curves/_data` alone,
# so `mnemonic/_data` -- outside this harness's own import chain today
# -- is bundled too, ahead of the next harness that reaches it.
for fuzzer in $(find "$SRC/btclib/fuzz" -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --collect-data=btclib
done

# The seed corpus this repository checked in beside the target
# (google/fuzzing's glossary, "Seed Corpus": inputs "checked into source
# alongside fuzz targets"), zipped under the name libFuzzer picks up next
# to a target's own binary with no configuration.
zip -j "$OUT/fuzz_p2p_message_seed_corpus.zip" \
  fuzz/corpus/fuzz_p2p_message/*.bin
