#!/usr/bin/env bash
# LEDGER SCALE BENCHMARK: how fast does the activation ledger grow, and how long does
# `activation verify-chain` take as it does?
#
# This is not a gate. It asserts nothing and always exits 0; it prints numbers so that
# docs/ENTERPRISE.md §11 cites a measurement anyone can repeat rather than a claim.
#
#   bash scripts/bench-ledger.sh            # default ladder, ~2000 activations
#   LADDER="25 50 100" bash scripts/bench-ledger.sh
#
# Every activation is one JVM start, so the default ladder takes several minutes. The JVM
# start is also why the fixed cost is reported separately: below a few hundred entries it
# dominates the per-entry work completely, and a single "verify takes N ms" number would be
# mostly a measurement of `java -jar`.
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this this script only runs on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

FIX="scripts/fixtures/activation"
WORK="target/bench-ledger"
JAR="gates/target/bifrost-gates.jar"
LADDER="${LADDER:-25 50 100 250 500 1000 2000}"

[ -f "$JAR" ] || mvn -q -pl core,gates -am install

rm -rf "$WORK"
mkdir -p "$WORK/registry/udt/Line1-Mixer" "$WORK/registry/conformance/Line1-Mixer" "$WORK/registry/spec/mix-recipe"
cp "$FIX/udt-Line1-Mixer.json"       "$WORK/registry/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"    "$WORK/registry/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json" "$WORK/registry/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json" "$WORK/registry/spec/mix-recipe/1.1.0.json"
cp "$FIX/policy.json"                "$WORK/registry/policy.json"

REG="$(cygpath -m "$(pwd)/$WORK/registry")"
JARW="$(cygpath -m "$(pwd)/$JAR")"
LEDGER="$WORK/registry/activation/Line1.jsonl"

ms()      { date +%s%3N; }
median3() { printf '%s\n' "$@" | sort -n | sed -n 2p; }

# Bare JVM start, doing no work at all: the floor every CLI measurement below sits on.
base=(); for _ in 1 2 3; do t0=$(ms); java -jar "$JARW" >/dev/null 2>&1 || true; t1=$(ms); base+=($((t1-t0))); done
echo "# bare JVM start (median of 3): $(median3 "${base[@]}") ms"
echo "n,ledger_bytes,verify_chain_ms"

n=0
for target in $LADDER; do
  while [ "$n" -lt "$target" ]; do
    # alternate versions so each activation is a real change rather than a re-activation
    if [ $((n % 2)) -eq 0 ]; then v=1.0.0; else v=1.1.0; fi
    java -jar "$JARW" activate "$REG" Line1 recipe mix-recipe "$v" --by alice --approved-by bob >/dev/null 2>&1
    n=$((n+1))
  done
  runs=(); for _ in 1 2 3; do
    t0=$(ms); java -jar "$JARW" activation verify-chain "$REG" Line1 >/dev/null 2>&1; t1=$(ms)
    runs+=($((t1-t0)))
  done
  echo "$n,$(wc -c < "$LEDGER"),$(median3 "${runs[@]}")"
done
