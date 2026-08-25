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
# "Prerequisites"): the workflow's own checkout step is what puts the
# source `docker build` sees on disk, so no `git clone` belongs here.
FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/btclib
WORKDIR $SRC/btclib
COPY ./.clusterfuzzlite/build.sh $SRC/
