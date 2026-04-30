#!/bin/bash
  
git submodule update --init --recursive --force
export PATH="$HOME/.rustup/toolchains/nightly-aarch64-apple-darwin/bin:$PATH"
UV_CACHE_DIR=/tmp/uv-cache uv run make -C core build_unix
UV_CACHE_DIR=/tmp/uv-cache uv run make -C core test TESTOPTS="test_apps.common.kv_serialize.py test_apps.common.kv_smt.py"
