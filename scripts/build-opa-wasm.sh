#!/usr/bin/env bash
# Builds the OPA policies under core/src/main/resources/opa into the WASM modules OpaPolicy loads.
# The Rego sources are Rego v1 and the build is pinned to one OPA release: the same sources and the
# same OPA give byte-identical policy.wasm (line endings of the source do not change it), so the
# committed modules can be checked against a rebuild.
#
# Each policy has one entrypoint, because OpaPolicy.eval always evaluates entrypoint 0.
#
# Run from the bifrost repo root (OPA defaults to `opa` on PATH):
#   OPA=/path/to/opa bash scripts/build-opa-wasm.sh          # rebuild the committed .wasm files
#   OPA=/path/to/opa bash scripts/build-opa-wasm.sh --check  # fail if a rebuild differs
set -euo pipefail
cd "$(dirname "$0")/.."

OPA_VERSION="1.21.4"
OPA="${OPA:-opa}"
DIR="core/src/main/resources/opa"
# <source>:<entrypoint>
POLICIES=("command_authz:acl/command_authz/decision" "spike:spike/decision")

fail() { echo "[OPA] FAIL: $*"; exit 1; }

have=$("$OPA" version | sed -n 's/^Version: //p')
[ "$have" = "$OPA_VERSION" ] || fail "opa is $have, the policies are built with $OPA_VERSION"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$OPA" check --strict "$DIR"/*.rego || fail "opa check --strict"

for p in "${POLICIES[@]}"; do
  name=${p%%:*}; entry=${p#*:}
  mkdir "$work/$name"
  "$OPA" build -t wasm -e "$entry" "$DIR/$name.rego" -o "$work/$name/bundle.tar.gz"
  tar -xzf "$work/$name/bundle.tar.gz" -C "$work/$name" /policy.wasm 2>/dev/null \
    || tar -xzf "$work/$name/bundle.tar.gz" -C "$work/$name" policy.wasm
  if [ "${1:-}" = "--check" ]; then
    cmp -s "$work/$name/policy.wasm" "$DIR/$name.wasm" || fail "$DIR/$name.wasm is not the build of $DIR/$name.rego"
    echo "[OPA] $name.wasm matches $name.rego ($entry)"
  else
    cp "$work/$name/policy.wasm" "$DIR/$name.wasm"
    echo "[OPA] built $DIR/$name.wasm ($entry)"
  fi
done
