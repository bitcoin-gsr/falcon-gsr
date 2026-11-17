#!/bin/sh
# Build txeval against the static libraries of a jmoik/bitcoin gsr build.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src=${BITCOIN_GSR:-$here/../../bitcoin}
b=${BITCOIN_GSR_BUILD:-$src/build}
mkdir -p "$here/../build"
c++ -std=c++20 -O1 -I "$src/src" -I "$b/src" -I "$src/src/univalue/include" \
  "$here/txeval.cpp" \
  "$b/lib/libbitcoin_common.a" "$b/lib/libbitcoin_consensus.a" "$b/lib/libbitcoin_util.a" \
  "$b/lib/libbitcoin_crypto.a" "$b/lib/libbitcoin_clientversion.a" "$b/src/univalue/libunivalue.a" \
  "$b/src/secp256k1/lib/libsecp256k1.a" "$b/src/libcrc32c.a" -o "$here/../build/txeval"
echo "$here/../build/txeval"
