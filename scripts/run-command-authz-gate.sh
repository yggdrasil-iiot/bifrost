#!/usr/bin/env bash
# ② POLICY LINT GATE (Chunk-2 acceptance): prove `gates policy <policyJson>` actually discriminates —
# a valid deny-by-default policy is accepted, a policy with "default":"allow" is rejected.
#
# Fixtures:
#   heimdall/registry/policy.json                 — real deny-by-default policy (good)
#   scripts/fixtures/gates/policy/bad-policy.json — same shape but "default":"allow" (bad)
#
# Run from the bifrost repo root:
#   bash scripts/run-command-authz-gate.sh
#   # expect: [GATE] PASS run-command-authz-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

GATES_JAR="gates/target/bifrost-gates.jar"
GOOD_POLICY="heimdall/registry/policy.json"
BAD_POLICY="scripts/fixtures/gates/policy/bad-policy.json"

fail() { echo "[GATE] FAIL: $*"; exit 1; }

echo "[GATE] step 0: build jars if missing"
if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates install
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"

[ -f "$GOOD_POLICY" ] || fail "fixture missing: $GOOD_POLICY"
[ -f "$BAD_POLICY" ] || fail "fixture missing: $BAD_POLICY"

GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"
GOOD="$(cygpath -m "$(pwd)/$GOOD_POLICY")"
BAD="$(cygpath -m "$(pwd)/$BAD_POLICY")"

echo "[GATE] step 1: accept — valid deny-by-default policy must PASS (exit 0)"
set +e
java -jar "$GJ" policy "$GOOD"
code=$?
set -e
[ "$code" -eq 0 ] || fail "good policy was rejected (exit $code) — expected accept"
echo "[GATE] accept OK: good policy returned 0"

echo "[GATE] step 2: reject — default:\"allow\" policy must FAIL (non-zero)"
set +e
java -jar "$GJ" policy "$BAD"
code=$?
set -e
[ "$code" -ne 0 ] || fail "bad (default:allow) policy was accepted (exit 0) — expected reject"
echo "[GATE] reject OK: bad policy returned $code (non-zero)"

echo ""
echo "[GATE] PASS run-command-authz-gate.sh"
exit 0
