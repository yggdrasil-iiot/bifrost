#!/usr/bin/env bash
# ① SCHEMA-COMPAT GATE (Chunk-2 acceptance): prove `gates schema <registry> <proposal>` actually
# discriminates — a compatible (additive, FORWARD-mode) proposal is accepted, a breaking (member
# removal, FORWARD-mode) proposal is rejected.
#
# Fixtures (committed, scripts/fixtures/gates/schema/):
#   policy.json               — {"mode":"FORWARD"}
#   udt/Motor/1.0.0.json       — registered Motor UDT (Rpm, Running)
#   compatible-proposal.json   — Motor 1.1.0, adds Temperature (compatible under FORWARD)
#   breaking-proposal.json     — Motor 1.1.0, removes Running (breaking under FORWARD)
#
# Run from the bifrost repo root:
#   bash scripts/run-schema-gate.sh
#   # expect: [GATE] PASS run-schema-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURES="scripts/fixtures/gates/schema"
GATES_JAR="gates/target/bifrost-gates.jar"

fail() { echo "[GATE] FAIL: $*"; exit 1; }

echo "[GATE] step 0: build jars if missing"
if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates install
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"

[ -f "$FIXTURES/policy.json" ] || fail "fixture missing: $FIXTURES/policy.json"
[ -f "$FIXTURES/udt/Motor/1.0.0.json" ] || fail "fixture missing: $FIXTURES/udt/Motor/1.0.0.json"
[ -f "$FIXTURES/compatible-proposal.json" ] || fail "fixture missing: $FIXTURES/compatible-proposal.json"
[ -f "$FIXTURES/breaking-proposal.json" ] || fail "fixture missing: $FIXTURES/breaking-proposal.json"

GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"
REGISTRY="$(cygpath -m "$(pwd)/$FIXTURES")"
COMPATIBLE="$(cygpath -m "$(pwd)/$FIXTURES/compatible-proposal.json")"
BREAKING="$(cygpath -m "$(pwd)/$FIXTURES/breaking-proposal.json")"

echo "[GATE] step 1: accept — compatible (additive) proposal must PASS (exit 0)"
set +e
java -jar "$GJ" schema "$REGISTRY" "$COMPATIBLE"
code=$?
set -e
[ "$code" -eq 0 ] || fail "compatible proposal was rejected (exit $code) — expected accept"
echo "[GATE] accept OK: compatible proposal returned 0"

echo "[GATE] step 2: reject — breaking (member-removal, FORWARD) proposal must FAIL (non-zero)"
set +e
java -jar "$GJ" schema "$REGISTRY" "$BREAKING"
code=$?
set -e
[ "$code" -ne 0 ] || fail "breaking proposal was accepted (exit 0) — expected reject"
echo "[GATE] reject OK: breaking proposal returned $code (non-zero)"

echo ""
echo "[GATE] PASS run-schema-gate.sh"
exit 0
