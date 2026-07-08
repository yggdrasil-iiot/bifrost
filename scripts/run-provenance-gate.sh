#!/usr/bin/env bash
# ③ PROVENANCE GATE (Chunk-2 acceptance): prove `gates provenance publish|verify` actually
# discriminates — mint a recipe canonical from a clean git commit, independently recompute its
# sha256 and cross-check against the manifest's self-attested contentSha256, verify OK, then
# tamper the materialized canonical on disk and confirm verify now fails (non-zero).
#
# Builds a throwaway git repo + registry under build/gate/prov-* at runtime (cleaned up on exit).
#
# Run from the bifrost repo root:
#   bash scripts/run-provenance-gate.sh
#   # expect: [GATE] PASS run-provenance-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

GATES_JAR="gates/target/bifrost-gates.jar"
WORK="build/gate"
REPO_DIR="$WORK/prov-repo"
REGISTRY_DIR="$WORK/prov-registry"

fail() { echo "[GATE] FAIL: $*"; exit 1; }

cleanup() {
  rm -rf "$REPO_DIR" "$REGISTRY_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "[GATE] step 0: build jars if missing"
if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates install
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"

GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"

echo "[GATE] step 1: seed a clean git repo with a committed recipe canonical"
rm -rf "$REPO_DIR" "$REGISTRY_DIR"
mkdir -p "$REPO_DIR/model"
printf 'endpoint: line1\nsetpoints: {rpm: 1500, temp: 220}\n' > "$REPO_DIR/model/recipe-setpoints.yaml"
REPO_WIN="$(cygpath -m "$(pwd)/$REPO_DIR")"
git -C "$REPO_WIN" init -q
git -C "$REPO_WIN" config user.email "gate@bifrost.local"
git -C "$REPO_WIN" config user.name "bifrost-gate"
git -C "$REPO_WIN" add .
git -C "$REPO_WIN" commit -q -m seed

REGISTRY_WIN="$(cygpath -m "$(pwd)/$REGISTRY_DIR")"

echo "[GATE] step 2: publish (mint) — must succeed (exit 0)"
set +e
java -jar "$GJ" provenance publish "$REGISTRY_WIN" "$REPO_WIN" model/recipe-setpoints.yaml line1 1.0.0
code=$?
set -e
[ "$code" -eq 0 ] || fail "publish failed (exit $code) — expected success on a clean commit"
echo "[GATE] publish OK"

MANIFEST="$REGISTRY_DIR/recipe/line1/1.0.0/manifest.json"
CANONICAL="$REGISTRY_DIR/recipe/line1/1.0.0/recipe-setpoints.yaml"
[ -f "$MANIFEST" ] || fail "manifest not written: $MANIFEST"
[ -f "$CANONICAL" ] || fail "materialized canonical not written: $CANONICAL"

echo "[GATE] step 3: independent sha256 cross-check (raw bytes, no CLI reuse)"
INDEPENDENT_SHA=$(sha256sum "$REPO_DIR/model/recipe-setpoints.yaml" | awk '{print $1}')
MANIFEST_SHA=$(grep -o '"contentSha256"[^,}]*' "$MANIFEST" | sed -E 's/.*: *"([0-9a-f]+)".*/\1/')
[ -n "$MANIFEST_SHA" ] || fail "could not extract contentSha256 from manifest.json"
[ "$INDEPENDENT_SHA" = "$MANIFEST_SHA" ] || fail "independent sha256 ($INDEPENDENT_SHA) != manifest contentSha256 ($MANIFEST_SHA)"
echo "[GATE] independent sha256 OK: $INDEPENDENT_SHA == manifest contentSha256"

echo "[GATE] step 4: accept — verify against the untouched canonical must PASS (exit 0)"
set +e
java -jar "$GJ" provenance verify "$REGISTRY_WIN" line1
code=$?
set -e
[ "$code" -eq 0 ] || fail "verify of untampered canonical was rejected (exit $code) — expected accept"
echo "[GATE] verify accept OK"

echo "[GATE] step 5: reject — tamper the materialized canonical, verify must FAIL (non-zero)"
printf 'endpoint: line1\nsetpoints: {rpm: 9999, temp: 999}  # TAMPERED\n' > "$CANONICAL"
set +e
java -jar "$GJ" provenance verify "$REGISTRY_WIN" line1
code=$?
set -e
[ "$code" -ne 0 ] || fail "verify of a TAMPERED canonical was accepted (exit 0) — expected reject"
echo "[GATE] verify reject OK: tamper detected (exit $code)"

echo ""
echo "[GATE] PASS run-provenance-gate.sh"
exit 0
