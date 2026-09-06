#!/usr/bin/env bash
# ACTIVATION GATE (T3 end-to-end): proves the governed activation ledger is the SINGLE source of the
# runtime recipe VERSION, and that Heimdall's edge binds that version verify-then-trust. One governed
# act (`activate`) — four-eyes attested, content-sealed — flips BOTH the CLI audit trail AND the live
# edge's admissible setpoint. The dial's activeRecipeVersion is deliberately unused; the ledger wins.
#
# Topology (broker phase on one HiveMQ CE + one embedded OPC-UA sim):
#   gates/target/bifrost-gates.jar       — the control plane: activate / active / activation-log
#   heimdall/target/bifrost-heimdall.jar — the edge: ① authz then ② recipe-conformance bound to the
#                                          ledger's active pointer (ACTIVATION_PATH/ACTIVATION_TARGET)
#   sim/target/bifrost-sim.jar           — OPC-UA sim exposing writable ns=2;s=Recipe/Rpm
#
# Assertions:
#   A1 activate + audit (pure CLI): activate mix-recipe@1.0.0 by alice/bob -> exit 0; active => 1.0.0;
#                                   activation-log shows ACTIVATE recipe/mix-recipe@1.0.0.
#   A2 SoD refuse (pure CLI):       --approved-by alice (self) -> exit 1 activation.approval.self;
#                                   no approver -> exit 1 activation.approval.missing.
#   A3a activate-time refuse (CLI): activate mix-recipe@9.9.9 -> exit 1 activation.artifact.unresolved;
#                                   ledger event count unchanged (still just A1's one event).
#   A3b edge provenance (broker):   tamper one byte of the active spec -> bridge throws
#                                   activation.edge.content-mismatch and NEVER prints [BRIDGE] ready.
#   A4 runtime flip (broker):       1.0.0 active -> Rpm=1500 APPLY, Rpm=1600 DENY deviation. activate
#                                   1.1.0 -> Rpm=1600 APPLY, Rpm=1500 DENY deviation (one act moved the edge).
#   A5 rollback (broker):           activate 1.0.0 --rollback -> exit 0; active => 1.0.0; log shows the 3
#                                   events ACTIVATE@1.0.0, ACTIVATE@1.1.0, ROLLBACK@1.0.0 in order;
#                                   restart -> Rpm=1500 APPLY again.
#
# Run from anywhere (needs Docker Desktop running + host port 1883 free):
#   bash scripts/run-activation-gate.sh
#   # expect: [GATE] PASS run-activation-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/activation-gate"
SIM_LOG="$WORK/sim.log"
PUB_LOG="$WORK/pub.log"
BLOG_A3B="$WORK/bridge-a3b.log"
BLOG_A4="$WORK/bridge-a4.log"
BLOG_A4B="$WORK/bridge-a4b.log"
BLOG_A5="$WORK/bridge-a5.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH — Docker Desktop is required for the MQTT broker"; exit 1; }

fail() {
  echo "[GATE] FAIL: $*"
  echo "--- sim log tail ---";        tail -60 "$SIM_LOG"   2>/dev/null || true
  echo "--- bridge a3b log tail ---"; tail -60 "$BLOG_A3B"  2>/dev/null || true
  echo "--- bridge a4 log tail ---";  tail -60 "$BLOG_A4"   2>/dev/null || true
  echo "--- bridge a4b log tail ---"; tail -60 "$BLOG_A4B"  2>/dev/null || true
  echo "--- bridge a5 log tail ---";  tail -60 "$BLOG_A5"   2>/dev/null || true
  echo "--- pub log tail ---";        tail -40 "$PUB_LOG"   2>/dev/null || true
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

cleanup() {
  [ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
  # `$!` from an MSYS-backgrounded native `java -jar` does not reliably match the real Win32 PID
  # (a known MSYS fork/exec quirk); match on the jar filename via jps -lm instead — best-effort.
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Mop up orphans from a prior aborted run BEFORE we start anything new.
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing (core, sim, gates, heimdall)"
if [ ! -f core/target/bifrost-core-0.1.0-SNAPSHOT.jar ] || [ ! -f heimdall/target/bifrost-heimdall.jar ] \
   || [ ! -f sim/target/bifrost-sim.jar ] || [ ! -f gates/target/bifrost-gates.jar ]; then
  mvn -q -pl core,sim,gates,heimdall install
fi
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall/target/bifrost-heimdall.jar missing after build"
[ -f sim/target/bifrost-sim.jar ]           || fail "sim/target/bifrost-sim.jar missing after build"
[ -f gates/target/bifrost-gates.jar ]       || fail "gates/target/bifrost-gates.jar missing after build"

HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

echo "[GATE] gates=$GATES_JAR_WIN"
echo "[GATE] heimdall=$HEIMDALL_JAR_WIN"
echo "[GATE] sim=$SIM_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[GATE] step 1: stage the governed registry (udt + recipe conformance + spec 1.0.0 + acl)"
rm -rf "$WORK"
mkdir -p "$WORK/registry/udt/Line1-Mixer" \
         "$WORK/registry/conformance/Line1-Mixer" \
         "$WORK/registry/spec/mix-recipe"
cp "$FIX/udt-Line1-Mixer.json"        "$WORK/registry/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"     "$WORK/registry/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json"  "$WORK/registry/spec/mix-recipe/1.0.0.json"
cp "$FIX/policy.json"                 "$WORK/registry/policy.json"
# pristine copy of the active spec bytes — A3b tampers the live one then restores from this.
cp "$FIX/spec-mix-recipe-1.0.0.json"  "$WORK/pristine-1.0.0.json"

REG="$WORK/registry"
SPEC_1_0_0="$WORK/registry/spec/mix-recipe/1.0.0.json"
REG_WIN="$(cygpath -m "$(pwd)/$REG")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$WORK/registry/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$WORK/registry/policy.json")"
ACTIVATION_TARGET="Line1"
RPM_NODE="ns=2;s=Recipe/Rpm"

# convenience: run the gates CLI on the win registry path
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

# ---------------------------------------------------------------------------
echo "[GATE] ===== A1: activate + audit (pure CLI, no broker) ====="
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "A1 activate mix-recipe@1.0.0 returned $code — expected 0"
gates active "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe | tee "$WORK/active-a1.txt" | grep -q "version=1.0.0" \
  || fail "A1 active did not report version=1.0.0"
gates activation-log "$REG_WIN" "$ACTIVATION_TARGET" | tee "$WORK/log-a1.txt" | grep -q "ACTIVATE recipe/mix-recipe@1.0.0" \
  || fail "A1 activation-log missing 'ACTIVATE recipe/mix-recipe@1.0.0'"
echo "[GATE] A1 OK: mix-recipe@1.0.0 activated (alice/bob), active pointer + audit trail written"

# ---------------------------------------------------------------------------
echo "[GATE] ===== A2: SoD refuse (self-approval + missing approver) ====="
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --by alice --approved-by alice > "$WORK/a2-self.txt" 2>&1
code=$?
set -e
[ "$code" -eq 1 ] || fail "A2 self-approval returned $code — expected 1 (refused)"
grep -q "activation.approval.self" "$WORK/a2-self.txt" || fail "A2 self-approval missing rule activation.approval.self"
echo "[GATE] A2a: self-approval REFUSED (activation.approval.self)"

set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --by alice > "$WORK/a2-missing.txt" 2>&1
code=$?
set -e
[ "$code" -eq 1 ] || fail "A2 missing-approver returned $code — expected 1 (refused)"
grep -q "activation.approval.missing" "$WORK/a2-missing.txt" || fail "A2 missing-approver missing rule activation.approval.missing"
echo "[GATE] A2 OK: four-eyes enforced — self-approval and missing approver both refused"

# ---------------------------------------------------------------------------
echo "[GATE] ===== A3a: activate-time refuse — unresolvable artifact, ledger untouched ====="
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 9.9.9 --by alice --approved-by bob > "$WORK/a3a.txt" 2>&1
code=$?
set -e
[ "$code" -eq 1 ] || fail "A3a activate mix-recipe@9.9.9 returned $code — expected 1 (refused)"
grep -q "activation.artifact.unresolved" "$WORK/a3a.txt" || fail "A3a missing rule activation.artifact.unresolved"
gates activation-log "$REG_WIN" "$ACTIVATION_TARGET" > "$WORK/log-a3a.txt"
grep -q "events=1" "$WORK/log-a3a.txt" || fail "A3a ledger event count changed — expected events=1 (still only A1's ACTIVATE); got: $(grep events= "$WORK/log-a3a.txt")"
echo "[GATE] A3a OK: unresolvable version refused (fail-closed), ledger unchanged (events=1)"

# ---------------------------------------------------------------------------
echo "[GATE] step 2: start HiveMQ CE (broker) + wait for :1883"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
ok=0
for i in $(seq 1 30); do
  bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
if [ "$ok" != "1" ]; then
  docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true
  fail "HiveMQ CE did not open :1883"
fi
echo "[GATE] HiveMQ CE up on :1883"

echo "[GATE] step 3: start the OPC-UA sim"
: > "$SIM_LOG"
java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
SIM_PID=$!
ok=0
for i in $(seq 1 30); do
  grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "OPC-UA sim did not start (pid $SIM_PID)"
echo "[GATE] OPC-UA sim listening (pid $SIM_PID)"
: > "$PUB_LOG"

# ---------------------------------------------------------------------------
# Helpers. RogueNcmd is the single-metric NCMD publisher; the Sparkplug identity
# (Bifrost:Line1 / recipe-edge) matches what the ACL policy.json allows for Rpm.
pub() {  # $1=nodeId $2=value $3=dataType
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}

# start_bridge with the ledger-bound activation edge (ACTIVATION_PATH + ACTIVATION_TARGET set).
start_bridge() {  # $1=bridge log
  : > "$1"
  MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
  POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$REG_WIN" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
  ACTIVATION_PATH="$REG_WIN" ACTIVATION_TARGET="$ACTIVATION_TARGET" \
    java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  BRIDGE_PID=$!
  local ok=0
  for i in $(seq 1 45); do
    if grep -q "\[BRIDGE\] ready" "$1" 2>/dev/null && grep -q "\[BRIDGE\] conformance loaded" "$1" 2>/dev/null; then
      ok=1; break
    fi
    sleep 2
  done
  [ "$ok" = "1" ] || fail "Heimdall did not reach '[BRIDGE] ready' + '[BRIDGE] conformance loaded' (log $1)"
}

stop_bridge() {
  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  BRIDGE_PID=""
  sleep 2   # let the broker drop the fixed-clientId session before the next daemon connects
}

wait_apply() {  # $1=node  $2=bridge log
  local ok=0
  for i in $(seq 1 12); do
    grep -q "\[BRIDGE\] APPLY cmd=$1 ok=true" "$2" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ]
}

wait_deny() {  # $1=node  $2=reason substring  $3=bridge log
  local ok=0
  for i in $(seq 1 12); do
    grep -qE "\[BRIDGE\] DENY cmd=$1 .*$2" "$3" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ]
}

# ---------------------------------------------------------------------------
echo "[GATE] ===== A3b: edge provenance — tamper the active spec, edge refuses to bind ====="
# 1.0.0 is active. Append one byte to the runtime spec bytes: its sha256 no longer matches the
# four-eyes-attested seal in the ledger, so the edge MUST throw activation.edge.content-mismatch
# and MUST NOT print [BRIDGE] ready. BESPOKE launcher (NOT start_bridge — that fail()s on no-ready).
printf 'X' >> "$SPEC_1_0_0"
: > "$BLOG_A3B"
MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$REG_WIN" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
ACTIVATION_PATH="$REG_WIN" ACTIVATION_TARGET="$ACTIVATION_TARGET" \
  java -jar "$HEIMDALL_JAR_WIN" >"$BLOG_A3B" 2>&1 &
BRIDGE_PID=$!
ok=0
for i in $(seq 1 15); do
  grep -q "activation.edge.content-mismatch" "$BLOG_A3B" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "A3b edge did not throw activation.edge.content-mismatch on tampered spec"
grep -q "\[BRIDGE\] ready" "$BLOG_A3B" && fail "A3b edge printed [BRIDGE] ready despite content-mismatch — must fail closed"
echo "[GATE] A3b OK: tampered spec bytes rejected by the edge (content-mismatch, no [BRIDGE] ready)"
stop_bridge
# restore the pristine active bytes so the sha256 seal matches again for A4.
cp "$WORK/pristine-1.0.0.json" "$SPEC_1_0_0"

# ---------------------------------------------------------------------------
echo "[GATE] ===== A4: runtime flip — activate 1.1.0 moves the edge's admissible setpoint ====="
start_bridge "$BLOG_A4"
grep -q "\[BRIDGE\] activation bound mix-recipe@1.0.0" "$BLOG_A4" \
  || fail "A4 edge did not bind mix-recipe@1.0.0 from the ledger"
echo "[GATE] A4a: edge bound mix-recipe@1.0.0 (ledger-driven)"

pub "$RPM_NODE" 1500 Double
wait_apply "$RPM_NODE" "$BLOG_A4" || fail "A4 Rpm=1500 (matches active 1.0.0 setpoint) was not APPLYed"
echo "[GATE] A4b: Rpm=1500 APPLYed (matches active recipe 1.0.0)"

pub "$RPM_NODE" 1600 Double
wait_deny "$RPM_NODE" "conformance.recipe.deviation" "$BLOG_A4" \
  || fail "A4 Rpm=1600 was not DENYed as a deviation from active recipe 1.0.0 (setpoint 1500)"
echo "[GATE] A4c: Rpm=1600 DENIED (conformance.recipe.deviation vs 1.0.0)"
stop_bridge

# Governed flip: stage 1.1.0 then activate it. ONE act re-scopes the edge's admissible setpoint.
cp "$FIX/spec-mix-recipe-1.1.0.json" "$WORK/registry/spec/mix-recipe/1.1.0.json"
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.1.0 --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "A4 activate mix-recipe@1.1.0 returned $code — expected 0"
gates active "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe | grep -q "version=1.1.0" \
  || fail "A4 active did not report version=1.1.0 after flip"

start_bridge "$BLOG_A4B"
grep -q "\[BRIDGE\] activation bound mix-recipe@1.1.0" "$BLOG_A4B" \
  || fail "A4 edge did not re-bind mix-recipe@1.1.0 after the flip"
pub "$RPM_NODE" 1600 Double
wait_apply "$RPM_NODE" "$BLOG_A4B" || fail "A4 after flip Rpm=1600 (matches 1.1.0) was not APPLYed"
echo "[GATE] A4d: after activating 1.1.0, Rpm=1600 APPLYed (edge moved)"
pub "$RPM_NODE" 1500 Double
wait_deny "$RPM_NODE" "conformance.recipe.deviation" "$BLOG_A4B" \
  || fail "A4 after flip Rpm=1500 was not DENYed as a deviation from 1.1.0 (setpoint 1600)"
echo "[GATE] A4 OK: one governed activation flipped the edge's admissible setpoint 1500 -> 1600"
stop_bridge

# ---------------------------------------------------------------------------
echo "[GATE] ===== A5: rollback — return the edge to 1.0.0 via an audited ROLLBACK ====="
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --rollback --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "A5 rollback to 1.0.0 returned $code — expected 0"
gates active "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe | grep -q "version=1.0.0" \
  || fail "A5 active did not report version=1.0.0 after rollback"

# audit trail must show all three events, in order: ACTIVATE@1.0.0, ACTIVATE@1.1.0, ROLLBACK@1.0.0.
gates activation-log "$REG_WIN" "$ACTIVATION_TARGET" > "$WORK/log-a5.txt"
grep -q "events=3" "$WORK/log-a5.txt" || fail "A5 activation-log expected events=3; got: $(grep events= "$WORK/log-a5.txt")"
ORDER="$(grep -E '  (ACTIVATE|ROLLBACK) recipe/mix-recipe@' "$WORK/log-a5.txt" | awk '{print $1"@"$2}' | tr '\n' ' ')"
EXPECT="ACTIVATE@recipe/mix-recipe@1.0.0 ACTIVATE@recipe/mix-recipe@1.1.0 ROLLBACK@recipe/mix-recipe@1.0.0 "
[ "$ORDER" = "$EXPECT" ] || fail "A5 audit order wrong. got: [$ORDER] expected: [$EXPECT]"
echo "[GATE] A5a: audit trail intact — ACTIVATE@1.0.0, ACTIVATE@1.1.0, ROLLBACK@1.0.0 in order"

start_bridge "$BLOG_A5"
grep -q "\[BRIDGE\] activation bound mix-recipe@1.0.0" "$BLOG_A5" \
  || fail "A5 edge did not re-bind mix-recipe@1.0.0 after rollback"
pub "$RPM_NODE" 1500 Double
wait_apply "$RPM_NODE" "$BLOG_A5" || fail "A5 after rollback Rpm=1500 was not APPLYed again"
echo "[GATE] A5 OK: audited rollback returned the edge to 1.0.0 (Rpm=1500 APPLYed again)"
stop_bridge

# ---------------------------------------------------------------------------
echo "[GATE] step 9: teardown"
[ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true

echo ""
echo "[GATE] PASS run-activation-gate.sh"
exit 0
