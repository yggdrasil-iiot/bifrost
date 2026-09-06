#!/usr/bin/env bash
# ③ MASTER-SPEC CONFORMANCE GATE (Chunk-1 acceptance): prove `gates spec <registry> <masterSpec>`
# actually discriminates — a conformant master spec (all setpoints in range) is accepted, an
# out-of-range master spec (a setpoint above the pinned equipment member's max) is rejected.
#
# The gate loads the PINNED equipment definition by path convention
# (<registryDir>/udt/<equipmentRef>/<equipmentVersion>.json) named by the master spec.
#
# Fixtures (committed, scripts/fixtures/gates/spec/):
#   udt/Line1-Mixer/1.0.0.json    — registered Mixer equipment (Rpm 0..3000, Temp 0..450, Running)
#   conformant-master-spec.json   — Rpm 1500, Temp 200 (both in range) → accept
#   out-of-range-master-spec.json — Rpm 9999 (> 3000 max) → reject
#
# Run from the bifrost repo root:
#   bash scripts/run-spec-gate.sh
#   # expect: [GATE] PASS run-spec-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

FIXTURES="scripts/fixtures/gates/spec"
GATES_JAR="gates/target/bifrost-gates.jar"

fail() { echo "[GATE] FAIL: $*"; exit 1; }

echo "[GATE] step 0: build jars if missing"
if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates install
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"

[ -f "$FIXTURES/udt/Line1-Mixer/1.0.0.json" ] || fail "fixture missing: $FIXTURES/udt/Line1-Mixer/1.0.0.json"
[ -f "$FIXTURES/conformant-master-spec.json" ] || fail "fixture missing: $FIXTURES/conformant-master-spec.json"
[ -f "$FIXTURES/out-of-range-master-spec.json" ] || fail "fixture missing: $FIXTURES/out-of-range-master-spec.json"

GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"
REGISTRY="$(cygpath -m "$(pwd)/$FIXTURES")"
CONFORMANT="$(cygpath -m "$(pwd)/$FIXTURES/conformant-master-spec.json")"
OUT_OF_RANGE="$(cygpath -m "$(pwd)/$FIXTURES/out-of-range-master-spec.json")"

echo "[GATE] step 1: accept — conformant master spec must PASS (exit 0)"
set +e
java -jar "$GJ" spec "$REGISTRY" "$CONFORMANT"
code=$?
set -e
[ "$code" -eq 0 ] || fail "conformant master spec was rejected (exit $code) — expected accept"
echo "[GATE] accept OK: conformant master spec returned 0"

echo "[GATE] step 2: reject — out-of-range master spec must FAIL (exit 1)"
set +e
java -jar "$GJ" spec "$REGISTRY" "$OUT_OF_RANGE"
code=$?
set -e
[ "$code" -eq 1 ] || fail "out-of-range master spec returned $code — expected reject (exit 1)"
echo "[GATE] reject OK: out-of-range master spec returned 1"

echo ""
echo "[GATE] PASS run-spec-gate.sh"
exit 0
