#!/bin/bash

set -euo pipefail

git submodule update --init --recursive --force
export PATH="$HOME/.rustup/toolchains/nightly-aarch64-apple-darwin/bin:$PATH"

UV_CACHE_DIR=/tmp/uv-cache uv run make -C core build_unix

UV_CACHE_DIR=/tmp/uv-cache uv run make -C core test TESTOPTS="\
test_apps.common.kv.py \
test_apps.common.kv_auth.py \
test_apps.common.kv_serialize.py \
test_apps.common.kv_smt.py \
test_apps.misc.kv_get_authority.py"

UV_CACHE_DIR=/tmp/uv-cache uv run core/emu.py \
  --disable-animation \
  --headless \
  --temporary-profile \
  -c pytest tests/device_tests/misc/test_msg_kv_get_authority.py -q --lang=en
