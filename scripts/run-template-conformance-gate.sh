#!/usr/bin/env bash
# ④ SITE ⊨ ENTERPRISE TEMPLATE CONFORMANCE GATE (T1 killer gate): prove `gates template <registry> <siteDef>`
# discriminates site defs against a governed enterprise template, AND that three FOREIGN external-standard
# templates (Ignition / CFIHOS / AAS) — each in its OWN vocabulary — adapt to a canonical UdtDefinition that
# drives IDENTICAL verdicts to the hand-authored native template.
#
#   P1 accept:  a conforming site (tightens ranges + extends) → exit 0
#   P2 reject:  exceeds-envelope / missing-member / semanticId-mismatch → exit 1 with the matching rule
#   P3 equiv:   for each of ignition|cfihos|aas — the file is genuinely foreign (non-circularity grep),
#               `adapt-template` yields a canonical template, and that adapted template reproduces the
#               SAME P1 accept + P2 reject verdicts as the native template.
#
# Fixtures (committed, scripts/fixtures/template/):
#   native-template.json  — enterprise template WeldController-corp@1.0.0 (3 members, envelope ranges)
#   site-conforming.json / site-exceeds.json / site-missing.json / site-semanticid.json
#   ext-ignition.json / ext-cfihos.json / ext-aas.json — three foreign externals
#
# Run from the bifrost repo root:
#   bash scripts/run-template-conformance-gate.sh
#   # expect: [GATE] PASS run-template-conformance-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURES="scripts/fixtures/template"
GATES_JAR="gates/target/bifrost-gates.jar"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "[GATE] FAIL: $*"
  if [ -f "$WORK/last.log" ]; then
    echo "---- last java output (tail) ----"
    tail -n 40 "$WORK/last.log"
    echo "---------------------------------"
  fi
  exit 1
}

echo "[GATE] step 0: build jars if missing"
if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates -am install -DskipTests
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"

for f in native-template.json site-conforming.json site-exceeds.json site-missing.json \
         site-semanticid.json ext-ignition.json ext-cfihos.json ext-aas.json; do
  [ -f "$FIXTURES/$f" ] || fail "fixture missing: $FIXTURES/$f"
done

GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"
SITE_CONFORMING="$(cygpath -m "$(pwd)/$FIXTURES/site-conforming.json")"
SITE_EXCEEDS="$(cygpath -m "$(pwd)/$FIXTURES/site-exceeds.json")"
SITE_MISSING="$(cygpath -m "$(pwd)/$FIXTURES/site-missing.json")"
SITE_SEMANTICID="$(cygpath -m "$(pwd)/$FIXTURES/site-semanticid.json")"

# install the NATIVE enterprise template into a registry at the path-convention location
mkdir -p "$WORK/reg/udt/WeldController-corp"
cp "$FIXTURES/native-template.json" "$WORK/reg/udt/WeldController-corp/1.0.0.json"
REG_NATIVE="$(cygpath -m "$WORK/reg")"

# run `gates template <registry> <siteDef>`; capture output to $WORK/last.log, return the exit code in $code
run_template() {
  set +e
  java -jar "$GJ" template "$1" "$2" >"$WORK/last.log" 2>&1
  code=$?
  set -e
  cat "$WORK/last.log"
}

echo ""
echo "[P1] accept — conforming site (tightens ranges + extends WeldVoltage) must PASS (exit 0)"
run_template "$REG_NATIVE" "$SITE_CONFORMING"
[ "$code" -eq 0 ] || fail "[P1] conforming site rejected (exit $code) — expected accept"
echo "[P1] OK: conforming site returned 0"

echo ""
echo "[P2] reject ×3 — each non-conforming site must FAIL (exit 1) with its rule"
echo "[P2:exceeds] WeldCurrent [0,20] exceeds envelope [0,15]"
run_template "$REG_NATIVE" "$SITE_EXCEEDS"
[ "$code" -eq 1 ] || fail "[P2:exceeds] returned $code — expected reject (exit 1)"
grep -q "template.range.exceeds-envelope" "$WORK/last.log" || fail "[P2:exceeds] missing rule template.range.exceeds-envelope"
echo "[P2:exceeds] OK: exit 1 + template.range.exceeds-envelope"

echo "[P2:missing] site drops required member WeldTime"
run_template "$REG_NATIVE" "$SITE_MISSING"
[ "$code" -eq 1 ] || fail "[P2:missing] returned $code — expected reject (exit 1)"
grep -q "template.member.missing" "$WORK/last.log" || fail "[P2:missing] missing rule template.member.missing"
echo "[P2:missing] OK: exit 1 + template.member.missing"

echo "[P2:semanticid] WeldCurrent semanticId ulsan:current != corp:weld/current"
run_template "$REG_NATIVE" "$SITE_SEMANTICID"
[ "$code" -eq 1 ] || fail "[P2:semanticid] returned $code — expected reject (exit 1)"
grep -q "template.semanticId.mismatch" "$WORK/last.log" || fail "[P2:semanticid] missing rule template.semanticId.mismatch"
echo "[P2:semanticid] OK: exit 1 + template.semanticId.mismatch"

echo ""
echo "[P3] three-adapter equivalence — Ignition / CFIHOS / AAS adapt to a template with IDENTICAL verdicts"
for kind in ignition cfihos aas; do
  EXT="$FIXTURES/ext-$kind.json"
  case "$kind" in
    ignition) token="engLow" ;;
    cfihos)   token="propertyId" ;;
    aas)      token="submodelElements" ;;
  esac

  echo "[P3:$kind] non-circularity — must contain foreign '$token' and NO Bifrost keys \"members\"/\"low\""
  grep -q "$token" "$EXT" || fail "[P3:$kind] foreign token '$token' NOT found in $EXT (not genuinely foreign)"
  if grep -q '"members"' "$EXT"; then fail "[P3:$kind] $EXT contains Bifrost key \"members\" — not foreign"; fi
  if grep -q '"low"'     "$EXT"; then fail "[P3:$kind] $EXT contains Bifrost key \"low\" — not foreign"; fi
  echo "[P3:$kind] OK: genuinely foreign vocabulary"

  EXT_M="$(cygpath -m "$(pwd)/$EXT")"
  OUT_M="$(cygpath -m "$WORK/adapted-$kind.json")"
  echo "[P3:$kind] adapt-template $kind -> canonical UdtDefinition"
  set +e
  java -jar "$GJ" adapt-template "$kind" "$EXT_M" "$OUT_M" WeldController-corp 1.0.0 >"$WORK/last.log" 2>&1
  code=$?
  set -e
  cat "$WORK/last.log"
  [ "$code" -eq 0 ] || fail "[P3:$kind] adapt-template returned $code — expected 0"
  [ -f "$WORK/adapted-$kind.json" ] || fail "[P3:$kind] adapted file not written"

  # install the ADAPTED template into its own registry, then re-run P1/P2 against it
  mkdir -p "$WORK/reg-$kind/udt/WeldController-corp"
  cp "$WORK/adapted-$kind.json" "$WORK/reg-$kind/udt/WeldController-corp/1.0.0.json"
  REG_K="$(cygpath -m "$WORK/reg-$kind")"

  echo "[P3:$kind] adapted template must ACCEPT conforming site (same as P1)"
  run_template "$REG_K" "$SITE_CONFORMING"
  [ "$code" -eq 0 ] || fail "[P3:$kind] adapted template rejected conforming site (exit $code) — NOT equivalent to native"

  echo "[P3:$kind] adapted template must REJECT exceeds site (same as P2)"
  run_template "$REG_K" "$SITE_EXCEEDS"
  [ "$code" -eq 1 ] || fail "[P3:$kind] adapted template accepted exceeds site (exit $code) — NOT equivalent to native"
  grep -q "template.range.exceeds-envelope" "$WORK/last.log" || fail "[P3:$kind] adapted reject missing rule template.range.exceeds-envelope"
  echo "[P3:$kind] OK: adapted template drives IDENTICAL verdicts to native (accept + reject)"
done

echo ""
echo "[GATE] PASS run-template-conformance-gate.sh"
exit 0
