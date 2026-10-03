# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# The container `build.sh` runs in. `base-builder-python` is the image
# docs/build-integration/python_lang.md names for a Python project --
# atheris and its runtime dependencies are pre-installed there, which is
# why neither is listed here or in build.sh.
#
# ClusterFuzzLite copies the checked-out tree in rather than cloning it,
# unlike a plain OSS-Fuzz integration (docs/build_integration.md,
# "Prerequisites"): the build_fuzzers action clones the repository at
# the run's own commit and hands that clone to `docker build` as its
# context (ExternalGithub.prepare_for_fuzzer_build, in google/oss-fuzz's
# infra/cifuzz/continuous_integration.py), so no `git clone` belongs here.
#
# The digest is what `docker build` pulls; the tag beside it is the one
# the digest was read from, and the one Dependabot's docker ecosystem
# (.github/dependabot.yml) follows to propose the next digest. `latest`
# rather than the `v1` google/clusterfuzzlite's docs/build_integration.md
# writes: dependabot-core parses `v1` as a version, and a version tag is
# the kind its `digest_only_update_suppressed?` can hold at the digest it
# has, where `latest` is exempt from it.
FROM gcr.io/oss-fuzz-base/base-builder-python:latest@sha256:cfcc123c40d4ecab777ac0f32f868177cb752950bf9f5d880f55e452adda5106

COPY . $SRC/btclib
WORKDIR $SRC/btclib
COPY ./.clusterfuzzlite/build.sh $SRC/
