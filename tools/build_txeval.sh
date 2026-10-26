#!/bin/sh
# Build txeval against the static libraries of the GSR node build.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
gsr=${GSR_ROOT:-$here/../../gsr-stark-verifier}
b=$gsr/build/bitcoin
mkdir -p "$here/../build"
c++ -std=c++20 -O1 -I "$gsr/bitcoin/src" -I "$b/src" -I "$gsr/bitcoin/src/univalue/include" \
  "$here/txeval.cpp" \
  "$b/lib/libbitcoin_common.a" "$b/lib/libbitcoin_consensus.a" "$b/lib/libbitcoin_util.a" \
  "$b/lib/libbitcoin_crypto.a" "$b/lib/libbitcoin_clientversion.a" "$b/src/univalue/libunivalue.a" \
  "$b/src/secp256k1/lib/libsecp256k1.a" "$b/src/libcrc32c.a" -o "$here/../build/txeval"
echo "$here/../build/txeval"
