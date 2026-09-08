#!/usr/bin/env bash
# BREAK-GLASS GATE: proves the emergency path over the activation ladder. Four-eyes is not removed, it is
# MOVED EARLIER IN TIME: two registered people mint a duty key ahead of the emergency, and afterwards one
# person can activate alone by signing with their own key plus the duty key. The record says so because the
# marking is DERIVED -- a duty principal is granted BREAK_GLASS_APPROVE and never APPROVE, so it has no way
# to produce an unmarked activation. Nothing about the ledger format changed: to SignedLedgerVerifier this
# is an ordinary two-signature, two-principal, two-key entry, which is why every trust tier still verifies.
#
# Assertions (all broker-free; B6 runs the real Heimdall main, whose activation bind precedes every
# network connect, so no broker or OPC-UA server is needed to reach it):
#   B1  minting a duty key with ONE key file used twice is refused -- the four-eyes at mint is real
#   B2  an ordinary two-person activation still yields action=ACTIVATE (the regression that matters)
#   B3  one person signing with their own key PLUS the duty key activates; the entry reads
#       action=BREAK_GLASS with the duty principal as approver, and is NOT an ACTIVATE
#   B4  it is loud: a [GATE] BREAK-GLASS line naming the duty principal and the target
#   B5  the ledger still verifies at EVERY tier -- activation verify-chain (T4), identity verify-signed
#       (T5) and identity verify-anchored (T7). A design that marked the emergency by weakening the
#       signature rule would fail here
#   B6  the edge still binds after a break-glass, with REQUIRE_SIGNED_ACTIVATION=on and then again with
#       REQUIRE_ANCHORED_ACTIVATION=on. The emergency must RESTORE the line, not take it down
#   B7  the duty principal is not an ordinary approver: a policy granting it both approve and
#       break_glass_approve over overlapping resources is refused at load, and it holds no ACTIVATE
#   B8  scope holds: a duty key granted on Line1 cannot approve on Line2
#   B9  THE LANDMINE -- deleting the duty key's authorized-keys line retroactively breaks the whole
#       ledger (identity.key.unregistered) and the edge refuses to start. Retire a duty key by removing
#       its POLICY GRANTS, never by deleting its key line. Proved here so nobody learns it in an outage
#
# Run from anywhere:
#   bash scripts/run-break-glass-gate.sh
#   # expect: [BG] GATE PASS (B1-B9)  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM wants, so
# shim it to identity (drop the -m, keep the last argument) rather than making every call site conditional.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/break-glass-gate"
BRIDGE_PID=""

fail() {
  echo "[BG] FAIL: $*"
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || kill -9 "$p" >/dev/null 2>&1 || true
  done
}

cleanup() {
  [ -n "$BRIDGE_PID" ] && { taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || kill -9 "$BRIDGE_PID" >/dev/null 2>&1 || true; }
  kill_by_mainclass "bifrost-heimdall.jar" || true
}
trap cleanup EXIT
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[BG] step 0: build the gates + heimdall jars"
mvn -q -pl core,gates,heimdall -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall/target/bifrost-heimdall.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

# ---------------------------------------------------------------------------
echo "[BG] step 1: keygen alice + bob (the two minters)"
rm -rf "$WORK"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"          # the canonical trust anchor copied into every fresh registry
: > "$AKF"
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" || fail "authorized-keys.jsonl not built with alice/bob"

# alice may ACTIVATE on Line1 AND Line2, bob may APPROVE on Line1, the duty key may BREAK_GLASS_APPROVE on
# Line1 only. alice's reach over Line2 is what makes B8 unambiguous: the denial there can only be the
# approver leg, because the activator leg is permitted.
write_policy() {  # $1 = registry dir
  cat > "$1/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-activate-l2","principal":"alice","action":"activate","target":"Line2","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-bg","principal":"breakglass-duty","action":"break_glass_approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
}

# the policy B7 refuses: the duty principal ALSO holds a plain approve grant over the same resource, so it
# could approve normally and the emergency would never be recorded as one.
write_policy_dual() {  # $1 = registry dir
  cat > "$1/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-bg","principal":"breakglass-duty","action":"break_glass_approve","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-also-approve","principal":"breakglass-duty","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
}

stage_reg() {  # $1 = registry dir; sets $reg / $reg_win globals
  reg="$1"
  rm -rf "$reg"
  mkdir -p "$reg/spec/mix-recipe" "$reg/identity"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$reg/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$reg/spec/mix-recipe/1.1.0.json"
  cp "$AKF"                            "$reg/identity/authorized-keys.jsonl"
  write_policy "$reg"
  reg_win="$(cygpath -m "$(pwd)/$reg")"
}

sactivate() {  # $1=target $2=version $3=by $4=approver $5=byKeyName $6=approverKeyName
  gates activate "$reg_win" "$1" recipe mix-recipe "$2" \
        --by "$3" --approved-by "$4" \
        --by-key "$KEYS_WIN/$5" --approved-by-key "$KEYS_WIN/$6"
}

# ---------------------------------------------------------------------------
echo "[BG] ===== B1: minting with ONE key file used twice is refused ====="
stage_reg "$WORK/reg-b1"
OUT_WIN="$(cygpath -m "$(pwd)/$KEYS")"
set +e
gates activation duty-key-mint "$reg_win" breakglass-duty --out "$OUT_WIN" \
      --by alice --by-key "$KEYS_WIN/alice.key" \
      --approved-by bob --approved-by-key "$KEYS_WIN/alice.key" >"$WORK/b1.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/b1.txt"; fail "B1 one-key mint returned $rc - expected 1 (refused)"; }
grep -q "identity.key.principal-mismatch" "$WORK/b1.txt" \
  || { cat "$WORK/b1.txt"; fail "B1 missing identity.key.principal-mismatch"; }
[ ! -f "$KEYS/breakglass-duty.key" ] || fail "B1 a refused mint must not write a duty key"
echo "[BG] B1 => PASS (four-eyes at mint: one key file cannot stand for two people)"

# ---------------------------------------------------------------------------
echo "[BG] step 2: alice + bob mint the duty key for real; register it"
set +e
gates activation duty-key-mint "$reg_win" breakglass-duty --out "$OUT_WIN" \
      --by alice --by-key "$KEYS_WIN/alice.key" \
      --approved-by bob --approved-by-key "$KEYS_WIN/bob.key" >"$WORK/mint.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/mint.txt"; fail "duty-key-mint returned $rc - expected 0"; }
[ -f "$KEYS/breakglass-duty.key" ] || fail "duty key file not written"
grep -qi "not recorded in the ledger" "$WORK/mint.txt" \
  || { cat "$WORK/mint.txt"; fail "the mint must say plainly that it writes no ledger entry"; }
grep '^{"principal"' "$WORK/mint.txt" >>"$AKF" || fail "mint printed no authorized-keys line"
grep -q '"breakglass-duty"' "$AKF" || fail "duty principal not registered in the trust anchor"
echo "[BG] duty key minted and registered"

# ---------------------------------------------------------------------------
echo "[BG] ===== B2: an ordinary two-person activation still yields action=ACTIVATE ====="
stage_reg "$WORK/reg-b2"
set +e
sactivate Line1 1.0.0 alice bob alice.key bob.key >"$WORK/b2.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/b2.txt"; fail "B2 ordinary activation returned $rc - expected 0"; }
grep -q "action=ACTIVATE" "$WORK/b2.txt" || { cat "$WORK/b2.txt"; fail "B2 ordinary activation is not action=ACTIVATE"; }
grep -q "BREAK" "$WORK/b2.txt" && { cat "$WORK/b2.txt"; fail "B2 an ordinary activation must not mention break-glass"; }
echo "[BG] B2 => PASS (the ordinary path is unchanged)"

# ---------------------------------------------------------------------------
echo "[BG] ===== B3/B4/B5: one person + the duty key -> BREAK_GLASS, loud, and verifiable at every tier ====="
stage_reg "$WORK/reg-bg"
set +e
sactivate Line1 1.1.0 alice breakglass-duty alice.key breakglass-duty.key >"$WORK/b3.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/b3.txt"; fail "B3 break-glass activation returned $rc - expected 0"; }
grep -q "action=BREAK_GLASS" "$WORK/b3.txt" || { cat "$WORK/b3.txt"; fail "B3 entry is not action=BREAK_GLASS"; }
grep -q "action=ACTIVATE" "$WORK/b3.txt" && { cat "$WORK/b3.txt"; fail "B3 a break-glass must not read as an ordinary ACTIVATE"; }
grep -q "approvedBy=breakglass-duty" "$WORK/b3.txt" \
  || { cat "$WORK/b3.txt"; fail "B3 the record must name the duty principal that approved"; }
echo "[BG] B3 => PASS (one person + the duty key, recorded as BREAK_GLASS)"

# B4: loudness. The [GATE] BREAK-GLASS line goes to stderr, which b3.txt captured with 2>&1.
grep -q "\[GATE\] BREAK-GLASS" "$WORK/b3.txt" || { cat "$WORK/b3.txt"; fail "B4 missing the [GATE] BREAK-GLASS line"; }
grep "\[GATE\] BREAK-GLASS" "$WORK/b3.txt" | grep -q "breakglass-duty" \
  || { cat "$WORK/b3.txt"; fail "B4 the BREAK-GLASS line does not name the duty principal"; }
grep "\[GATE\] BREAK-GLASS" "$WORK/b3.txt" | grep -q "Line1" \
  || { cat "$WORK/b3.txt"; fail "B4 the BREAK-GLASS line does not name the target"; }
echo "[BG] B4 => PASS (loud, naming the duty principal and the target)"

# B5: every trust tier. This is the assertion a design that marked the emergency by relaxing the
# signature rule would fail -- and, the ledger being append-only, would fail forever.
set +e
gates activation verify-chain "$reg_win" Line1 >"$WORK/b5-t4.txt" 2>&1; rc4=$?
gates identity verify-signed  "$reg_win" Line1 >"$WORK/b5-t5.txt" 2>&1; rc5=$?
gates identity verify-anchored "$reg_win" Line1 >"$WORK/b5-t7.txt" 2>&1; rc7=$?
set -e
[ "$rc4" -eq 0 ] || { cat "$WORK/b5-t4.txt"; fail "B5 verify-chain returned $rc4 - expected 0 (intact)"; }
grep -q "INTACT" "$WORK/b5-t4.txt" || { cat "$WORK/b5-t4.txt"; fail "B5 verify-chain did not report INTACT"; }
[ "$rc5" -eq 0 ] || { cat "$WORK/b5-t5.txt"; fail "B5 verify-signed returned $rc5 - expected 0 (intact)"; }
grep -q "INTACT" "$WORK/b5-t5.txt" || { cat "$WORK/b5-t5.txt"; fail "B5 verify-signed did not report INTACT"; }
[ "$rc7" -eq 0 ] || { cat "$WORK/b5-t7.txt"; fail "B5 verify-anchored returned $rc7 - expected 0 (intact)"; }
grep -q "INTACT" "$WORK/b5-t7.txt" || { cat "$WORK/b5-t7.txt"; fail "B5 verify-anchored did not report INTACT"; }
echo "[BG] B5 => PASS (T4 chain, T5 signed, T7 anchored all INTACT over a break-glass entry)"

# ---------------------------------------------------------------------------
echo "[BG] ===== B6: the edge still binds after a break-glass (signed, then anchored) ====="
# A full conformance registry, so Heimdall reaches the recipe/activationTarget bind branch. No broker and
# no OPC-UA server: loadConformance() -- which runs the ledger-trust and authZ checks and prints the bind
# line -- happens before the first network connect, so the assertion is reachable offline.
BREG="$WORK/reg-edge"
rm -rf "$BREG"
mkdir -p "$BREG/udt/Line1-Mixer" "$BREG/conformance/Line1-Mixer" "$BREG/spec/mix-recipe" "$BREG/identity"
cp "$FIX/udt-Line1-Mixer.json"       "$BREG/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"    "$BREG/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json" "$BREG/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json" "$BREG/spec/mix-recipe/1.1.0.json"
cp "$FIX/policy.json"                "$BREG/policy.json"
cp "$AKF"                            "$BREG/identity/authorized-keys.jsonl"
write_policy "$BREG"
reg="$BREG"; reg_win="$(cygpath -m "$(pwd)/$BREG")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$BREG/policy.json")"

set +e
sactivate Line1 1.1.0 alice breakglass-duty alice.key breakglass-duty.key >"$WORK/b6-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/b6-act.txt"; fail "B6 break-glass activation returned $rc - expected 0"; }

start_edge() {  # $1 = log file; $2 = signed|anchored
  : > "$1"
  local anchored="off"
  [ "$2" = "anchored" ] && anchored="on"
  MQTT_URL="tcp://localhost:1" OPCUA_URL="opc.tcp://localhost:1" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" HEALTH_PORT="9097" \
  POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$reg_win" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
  ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" \
  REQUIRE_SIGNED_ACTIVATION="on" REQUIRE_ANCHORED_ACTIVATION="$anchored" \
    java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  BRIDGE_PID=$!
}
stop_edge() {
  [ -n "$BRIDGE_PID" ] && { taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || kill -9 "$BRIDGE_PID" >/dev/null 2>&1 || true; }
  BRIDGE_PID=""
  kill_by_mainclass "bifrost-heimdall.jar" || true
}

# $1 = tier label, $2 = log file. Waits for the bind line or any activation.edge.* fail-close.
await_bind() {
  local ok=0 i
  for i in $(seq 1 20); do
    grep -q "\[BRIDGE\] activation bound" "$2" 2>/dev/null && { ok=1; break; }
    grep -q "activation.edge." "$2" 2>/dev/null && break
    sleep 1
  done
  [ "$ok" = "1" ] || { tail -30 "$2" 2>/dev/null || true; fail "B6 ($1) the edge did not bind after a break-glass activation"; }
  grep -q "\[BRIDGE\] BREAK-GLASS activation bound" "$2" \
    || { tail -30 "$2"; fail "B6 ($1) the edge bound without saying it was a break-glass"; }
}

for tier in signed anchored; do
  ELOG="$WORK/edge-$tier.log"
  start_edge "$ELOG" "$tier"
  await_bind "$tier" "$ELOG"
  grep -q "\[BRIDGE\] activation trust = $tier" "$ELOG" \
    || { tail -30 "$ELOG"; fail "B6 ($tier) the edge did not run the $tier trust tier"; }
  stop_edge
  echo "[BG] B6 ($tier) => edge bound the break-glass version"
done
echo "[BG] B6 => PASS (the emergency restores the line at both trust tiers, and the edge says BREAK-GLASS)"

# ---------------------------------------------------------------------------
echo "[BG] ===== B7: the duty principal is not an ordinary approver ====="
# (i) a policy that would let it approve normally is refused at LOAD, not at some later decision.
stage_reg "$WORK/reg-b7"
write_policy_dual "$reg"
set +e
sactivate Line1 1.0.0 alice breakglass-duty alice.key breakglass-duty.key >"$WORK/b7-dual.txt" 2>&1; rc=$?
set -e
[ "$rc" -ne 0 ] || { cat "$WORK/b7-dual.txt"; fail "B7 a dual-role policy must not activate"; }
grep -q "activation.authz.policy.dual-approve-role" "$WORK/b7-dual.txt" \
  || { cat "$WORK/b7-dual.txt"; fail "B7 missing activation.authz.policy.dual-approve-role"; }
[ ! -f "$reg/activation/Line1.jsonl" ] || fail "B7 a refused policy must leave the ledger untouched"

# (ii) it holds no ACTIVATE, so it cannot drive an activation itself.
stage_reg "$WORK/reg-b7b"
set +e
sactivate Line1 1.0.0 breakglass-duty bob breakglass-duty.key bob.key >"$WORK/b7-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/b7-act.txt"; fail "B7 duty-as-activator returned $rc - expected 1 (refused)"; }
grep -q "activation.authz.denied" "$WORK/b7-act.txt" || { cat "$WORK/b7-act.txt"; fail "B7 missing activation.authz.denied"; }
grep -q "activator 'breakglass-duty'" "$WORK/b7-act.txt" \
  || { cat "$WORK/b7-act.txt"; fail "B7 the denial must be the activator leg"; }
echo "[BG] B7 => PASS (dual-role policy refused at load; the duty key cannot activate)"

# ---------------------------------------------------------------------------
echo "[BG] ===== B8: a duty grant on Line1 does not reach Line2 ====="
stage_reg "$WORK/reg-b8"
set +e
sactivate Line2 1.0.0 alice breakglass-duty alice.key breakglass-duty.key >"$WORK/b8.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/b8.txt"; fail "B8 out-of-scope duty approval returned $rc - expected 1 (refused)"; }
grep -q "activation.authz.denied" "$WORK/b8.txt" || { cat "$WORK/b8.txt"; fail "B8 missing activation.authz.denied"; }
grep -q "approver 'breakglass-duty'" "$WORK/b8.txt" \
  || { cat "$WORK/b8.txt"; fail "B8 the denial must be the approver leg (alice may activate Line2)"; }
[ ! -f "$reg/activation/Line2.jsonl" ] || fail "B8 a refused activation must leave the ledger untouched"
echo "[BG] B8 => PASS (scope binds a duty grant exactly like any other)"

# ---------------------------------------------------------------------------
echo "[BG] ===== B9: THE LANDMINE -- deleting a key line breaks the ledger and stops the edge ====="
# Pre-existing behaviour (SignedLedgerVerifier resolves forPrincipal for EVERY historical entry), which
# break-glass makes routine: duty keys are the ones an operator is most tempted to "revoke" by deletion.
BREG9="$WORK/reg-b9"
rm -rf "$BREG9"
cp -r "$BREG" "$BREG9"
reg="$BREG9"; reg_win="$(cygpath -m "$(pwd)/$BREG9")"
grep -v '"breakglass-duty"' "$BREG/identity/authorized-keys.jsonl" > "$BREG9/identity/authorized-keys.jsonl"
grep -q '"breakglass-duty"' "$BREG9/identity/authorized-keys.jsonl" && fail "B9 the duty key line was not removed"
grep -q '"alice"' "$BREG9/identity/authorized-keys.jsonl" || fail "B9 removed more than the duty key line"

set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/b9-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/b9-vs.txt"; fail "B9 verify-signed returned $rc - expected 1 (broken)"; }
grep -q "identity.key.unregistered" "$WORK/b9-vs.txt" \
  || { cat "$WORK/b9-vs.txt"; fail "B9 missing identity.key.unregistered"; }

ELOG9="$WORK/edge-b9.log"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG9/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$BREG9/policy.json")"
start_edge "$ELOG9" signed
ok=0
for i in $(seq 1 20); do
  grep -q "activation.edge.signed-ledger-broken" "$ELOG9" 2>/dev/null && { ok=1; break; }
  sleep 1
done
[ "$ok" = "1" ] || { tail -30 "$ELOG9" 2>/dev/null || true; fail "B9 the edge did not fail closed on the broken ledger"; }
grep -q "\[BRIDGE\] activation bound" "$ELOG9" && fail "B9 the edge bound despite an unverifiable ledger"
stop_edge
echo "[BG] B9 => PASS (deleting a key line breaks the ledger and stops the edge -- retire by policy, never by deletion)"

echo ""
echo "[BG] GATE PASS (B1-B9)"
exit 0
