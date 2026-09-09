#!/usr/bin/env bash
# MODEL RECONCILIATION GATE (R6 acceptance): the governed model against the vendor's copy of it.
#
# ENTERPRISE.md row 13 asks which copy is currently authoritative. Until now the TemplateAdapter
# port read a vendor's model IN and nothing read one BACK, so in practice the vendor's copy was
# authored and the registry followed it -- the opposite of the intent. This gate proves the verify
# direction: a vendor export is normalized through the EXISTING adapter and the result is diffed
# against the governed UdtDefinition, so core gains no new vendor knowledge.
#
# WHAT THIS DOES NOT DO, said before the assertions rather than after: it does not connect to a
# live Kepware, Ignition or ThingWorx. None of them is in this repository. The vendor's copy
# arrives as a FILE -- which is what a Composer export, an Ignition tags/export and a Kepware GET
# all produce, and what ADOPTION.md 2 asks for: read the copy back, read-only, the same way the
# traffic side is handled. The comparison is built and gated; the fetch is not.
#
#   V1  the agreed export reports NO divergence, exit 0. Run first and deliberately: without it a
#       later "divergence found" proves the fixture differs, not that the comparison works
#   V2  a member the vendor lacks           -> vendor.member.missing, exit 1
#   V3  a member only the vendor has        -> vendor.member.unexpected, exit 1
#   V4  a retyped tag                       -> vendor.member.type-mismatch
#   V5  a widened range                     -> vendor.member.range-mismatch
#   V6  a repointed semanticId              -> vendor.member.semantic-id-mismatch
#   V7  GRANULARITY IS THE PRODUCT'S, NOT THE FILE'S: the same divergent export under
#       --granularity whole-set yields the SAME finding and a DIFFERENT remediation unit. This is
#       the assertion the port exists for -- two booleans would report every product as equal
#   V8  fail-closed inputs: a missing export, a malformed export, an unknown adapter and an
#       unrecognized granularity are each exit 2, and NONE of them prints AGREED
#   V9  an unregistered governed ref is exit 2 and prints NO findings. An empty governed side
#       would report every vendor member as unexpected: confident, long and meaningless
#
# Broker-free: no Docker, no sim, no edge.
#   bash scripts/run-model-reconciliation-gate.sh
#   # expect: [MR] GATE PASS (V1-V9)  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM wants.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/model-reconciliation-gate"
REF="WeldController-corp"
VER="1.0.0"

fail() {
  echo "[MR] FAIL: $*"
  exit 1
}

echo "[MR] step 0: build the gates jar"
mvn -q -pl core,gates -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/vendor"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

# ---------------------------------------------------------------------------
echo "[MR] step 1: stage a registry holding the governed definition"
rm -rf "$WORK"
REG="$WORK/registry"
mkdir -p "$REG/udt/$REF"
# The governed side is the canonical template the Ignition fixture already adapts onto exactly, so
# V1's agreement is a property of the two documents rather than of a tolerant comparison.
cp scripts/fixtures/template/native-template.json "$REG/udt/$REF/$VER.json"
REG_WIN="$(cygpath -m "$(pwd)/$REG")"
FIX_WIN="$(cygpath -m "$(pwd)/$FIX")"

reconcile() {  # $1 = fixture basename; $2.. = extra flags. Sets $rc and writes $WORK/$1.txt
  local f="$1"; shift
  set +e
  gates model-reconcile "$REG_WIN" "$REF" "$VER" \
        --vendor "$FIX_WIN/$f" --adapter ignition "$@" >"$WORK/$f.txt" 2>&1
  rc=$?
  set -e
}

# ---------------------------------------------------------------------------
echo "[MR] ===== V1: the agreed export reports no divergence ====="
reconcile ignition-agreed.json
[ "$rc" -eq 0 ] || { cat "$WORK/ignition-agreed.json.txt"; fail "V1 returned $rc - expected 0 (agreed)"; }
grep -q "AGREED" "$WORK/ignition-agreed.json.txt" \
  || { cat "$WORK/ignition-agreed.json.txt"; fail "V1 did not report AGREED"; }
grep -q "vendor.member" "$WORK/ignition-agreed.json.txt" \
  && { cat "$WORK/ignition-agreed.json.txt"; fail "V1 reported a finding on an identical pair"; }
echo "[MR] V1 => PASS (the baseline agrees, so every row below means something)"

# ---------------------------------------------------------------------------
assert_finding() {  # $1 = fixture, $2 = expected rule, $3 = label
  reconcile "$1"
  [ "$rc" -eq 1 ] || { cat "$WORK/$1.txt"; fail "$3 returned $rc - expected 1 (divergence)"; }
  grep -q "$2" "$WORK/$1.txt" || { cat "$WORK/$1.txt"; fail "$3 missing $2"; }
  grep -q "AGREED" "$WORK/$1.txt" && { cat "$WORK/$1.txt"; fail "$3 reported AGREED as well"; }
  echo "[MR] $3 => PASS ($2)"
}

echo "[MR] ===== V2-V6: each divergence is found, and named exactly ====="
assert_finding ignition-missing-member.json  "vendor.member.missing"             V2
assert_finding ignition-extra-member.json    "vendor.member.unexpected"          V3
assert_finding ignition-type-drift.json      "vendor.member.type-mismatch"       V4
assert_finding ignition-range-drift.json     "vendor.member.range-mismatch"      V5
assert_finding ignition-semantic-drift.json  "vendor.member.semantic-id-mismatch" V6

# The finding must name the member, or an operator cannot act on it.
grep -q "ElectrodeForce" "$WORK/ignition-missing-member.json.txt" \
  || { cat "$WORK/ignition-missing-member.json.txt"; fail "V2 did not name the missing member"; }
grep -q "CoolantTemp" "$WORK/ignition-extra-member.json.txt" \
  || { cat "$WORK/ignition-extra-member.json.txt"; fail "V3 did not name the unexpected member"; }

# ---------------------------------------------------------------------------
echo "[MR] ===== V7: granularity is the product's property, not the file's ====="
# The SAME file, declared as a blob product. The findings come from the data; only the remediation
# unit comes from the product. If these two diverged, the port would be inferring granularity from
# the export -- which is exactly the mistake it exists to prevent.
reconcile ignition-type-drift.json
cp "$WORK/ignition-type-drift.json.txt" "$WORK/v7-per-object.txt"
reconcile ignition-type-drift.json --granularity whole-set
cp "$WORK/ignition-type-drift.json.txt" "$WORK/v7-whole-set.txt"
[ "$rc" -eq 1 ] || { cat "$WORK/v7-whole-set.txt"; fail "V7 whole-set returned $rc - expected 1"; }

grep -q "remediation=per-object" "$WORK/v7-per-object.txt" \
  || { cat "$WORK/v7-per-object.txt"; fail "V7 per-object run did not report its remediation unit"; }
grep -q "remediation=whole-set" "$WORK/v7-whole-set.txt" \
  || { cat "$WORK/v7-whole-set.txt"; fail "V7 whole-set run did not report its remediation unit"; }

PER_FINDINGS="$(grep -c "vendor.member" "$WORK/v7-per-object.txt" || true)"
SET_FINDINGS="$(grep -c "vendor.member" "$WORK/v7-whole-set.txt" || true)"
[ "$PER_FINDINGS" = "$SET_FINDINGS" ] && [ "$PER_FINDINGS" -gt 0 ] \
  || fail "V7 the two granularities produced different findings ($PER_FINDINGS vs $SET_FINDINGS)"
grep -q "re-imports the whole entity set" "$WORK/v7-whole-set.txt" \
  || { cat "$WORK/v7-whole-set.txt"; fail "V7 whole-set did not say what a correction costs"; }
grep -q "re-imports the whole entity set" "$WORK/v7-per-object.txt" \
  && fail "V7 the per-object run claimed a whole-set correction"
echo "[MR] V7 => PASS (same findings, different remediation unit)"

# ---------------------------------------------------------------------------
echo "[MR] ===== V8: every unreadable input is exit 2, and none of them agrees ====="
refuses() {  # $1 = label, $2 = output file, rest = args after the ref/version
  local label="$1" out="$2"; shift 2
  set +e
  gates model-reconcile "$REG_WIN" "$REF" "$VER" "$@" >"$out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 2 ] || { cat "$out"; fail "$label returned $rc - expected 2"; }
  grep -q "AGREED" "$out" && { cat "$out"; fail "$label printed AGREED"; }
  return 0
}

refuses "V8 missing export" "$WORK/v8-missing.txt" \
  --vendor "$FIX_WIN/nope.json" --adapter ignition
grep -q "vendor.export.absent" "$WORK/v8-missing.txt" \
  || { cat "$WORK/v8-missing.txt"; fail "V8 a missing export was refused without saying so"; }

printf 'this is not json\n' > "$WORK/malformed.json"
refuses "V8 malformed export" "$WORK/v8-malformed.txt" \
  --vendor "$(cygpath -m "$(pwd)/$WORK/malformed.json")" --adapter ignition

refuses "V8 unknown adapter" "$WORK/v8-adapter.txt" \
  --vendor "$FIX_WIN/ignition-agreed.json" --adapter kepware

refuses "V8 unknown granularity" "$WORK/v8-granularity.txt" \
  --vendor "$FIX_WIN/ignition-agreed.json" --adapter ignition --granularity sometimes
echo "[MR] V8 => PASS (absent, malformed, unknown adapter and unknown granularity all refuse)"

# ---------------------------------------------------------------------------
echo "[MR] ===== V9: an unregistered governed ref refuses, with NO findings ====="
set +e
gates model-reconcile "$REG_WIN" "NoSuchTemplate" "$VER" \
      --vendor "$FIX_WIN/ignition-agreed.json" --adapter ignition >"$WORK/v9.txt" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$WORK/v9.txt"; fail "V9 returned $rc - expected 2"; }
grep -q "governed.definition.absent" "$WORK/v9.txt" \
  || { cat "$WORK/v9.txt"; fail "V9 missing governed.definition.absent"; }
# The absence of findings is as much the assertion as the exit code: an empty governed side that
# reported every vendor member as unexpected would still exit non-zero and look plausible.
grep -q "vendor.member" "$WORK/v9.txt" \
  && { cat "$WORK/v9.txt"; fail "V9 reported findings against an absent governed definition"; }
echo "[MR] V9 => PASS (refused, and silent about members it could not have compared)"

echo ""
echo "[MR] GATE PASS (V1-V9)"
exit 0
