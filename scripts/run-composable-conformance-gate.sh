#!/usr/bin/env bash
# COMPOSABLE-RUNTIME-CONFORMANCE GATE (the killer gate): proves that ONE governed conformance policy
# composes the model's structural/type/envelope rules with cross-member + recipe rules, and that the
# SAME governed artifact drives BOTH the CI design-time gate (`gates spec`) AND the runtime edge
# (Heimdall ② conformance) — flip the governed policy once and BOTH boundaries move together.
#
# Topology (all on one HiveMQ CE broker + one embedded OPC-UA sim):
#   sim/target/bifrost-sim.jar        — WeldControllerType + BodyShop/Weld1 (ElectrodeForce=2.5 seeded)
#                                       + writable ns=2;s=Weld/WeldCurrent -> BodyShop/Weld1.WeldCurrent
#   heimdall/target/bifrost-heimdall.jar — the edge daemon: ① authz (POLICY_PATH) then ② conformance
#                                       (CONFORMANCE_PATH over REGISTRY_PATH); RogueNcmd = NCMD publisher
#   gates/target/bifrost-gates.jar    — the CI governor: `spec` (design-time conformance) + `provenance`
#
# The five assertions:
#   C1 (composition, runtime):   envelope policy loaded; NCMD WeldCurrent=9 -> DENY conformance.cross.weld-lobe
#                                (ElectrodeForce=2.5<3 requires WeldCurrent<=8); WeldCurrent=7 -> APPLY ok=true.
#   C2 (design==runtime):        `gates spec` on a master spec (ElectrodeForce=2.5,WeldCurrent=9) -> exit 1
#                                (mirrors the C1 runtime DENY); control spec (ElectrodeForce=4.0) -> exit 0.
#   C3 (single-source flip):     edit the ONE governed policy's weld-lobe thenValue 8->10 (authz policy.json
#                                UNTOUCHED). Re-run `gates spec` -> now exit 0; restart the edge -> the SAME
#                                WeldCurrent=9 NCMD now APPLYs. Both boundaries flipped from one source.
#   C4 (dial):                   swap the dial to recipe-mode (active WeldSchedule WeldCurrent=9, tol 0) ->
#                                WeldCurrent=7 -> DENY conformance.recipe.deviation; WeldCurrent=9 -> APPLY.
#   C5 (lifecycle):              `provenance publish` the governed policy bytes -> `verify` clean (exit 0);
#                                tamper one byte -> `verify` -> exit 1 (content-hash).
#
# Run from the bifrost repo root (needs Docker Desktop running + host port 1883 free):
#   timeout 600 bash scripts/run-composable-conformance-gate.sh
#   # expect: [GATE] PASS run-composable-conformance-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/conformance-gate"
SIM_LOG="$WORK/sim.log"
PUB_LOG="$WORK/pub.log"
BLOG_C1="$WORK/bridge-c1.log"
BLOG_C3="$WORK/bridge-c3.log"
BLOG_C4="$WORK/bridge-c4.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH — Docker Desktop is required for the MQTT broker"; exit 1; }

fail() {
  echo "[GATE] FAIL: $*"
  echo "--- sim log tail ---";       tail -60 "$SIM_LOG"  2>/dev/null || true
  echo "--- bridge c1 log tail ---"; tail -60 "$BLOG_C1"  2>/dev/null || true
  echo "--- bridge c3 log tail ---"; tail -60 "$BLOG_C3"  2>/dev/null || true
  echo "--- bridge c4 log tail ---"; tail -60 "$BLOG_C4"  2>/dev/null || true
  echo "--- pub log tail ---";       tail -40 "$PUB_LOG"  2>/dev/null || true
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
  # (a known MSYS fork/exec quirk); jps -lm on a `-jar` launch reports the JAR PATH, not the main
  # class, so match on the jar filename instead — the taskkills above are best-effort only.
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

FIX="scripts/fixtures/conformance"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

echo "[GATE] heimdall=$HEIMDALL_JAR_WIN"
echo "[GATE] sim=$SIM_JAR_WIN"
echo "[GATE] gates=$GATES_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[GATE] step 1: start HiveMQ CE (broker) + wait for :1883"
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

# ---------------------------------------------------------------------------
echo "[GATE] step 2: set up the work registry (copy governed fixtures) + start the OPC-UA sim"
rm -rf "$WORK"
mkdir -p "$WORK/registry" "$WORK/srcrepo"
# The governed registry the CI gate AND the edge both read: udt/, conformance/, spec/.
cp -r "$FIX/udt"         "$WORK/registry/udt"
cp -r "$FIX/conformance" "$WORK/registry/conformance"
cp -r "$FIX/spec"        "$WORK/registry/spec"

REGISTRY_WIN="$(cygpath -m "$(pwd)/$WORK/registry")"
WELD_POLICY_WIN="$(cygpath -m "$(pwd)/$FIX/weld-policy.json")"
CONF_ENVELOPE="$WORK/registry/conformance/Weld-Controller/1.0.0.json"          # edited in C3
CONF_ENVELOPE_WIN="$(cygpath -m "$(pwd)/$CONF_ENVELOPE")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$WORK/registry/conformance/Weld-Controller/recipe-1.0.0.json")"
REJECT_SPEC_WIN="$(cygpath -m "$(pwd)/$FIX/specs/reject-master-spec.json")"
ACCEPT_SPEC_WIN="$(cygpath -m "$(pwd)/$FIX/specs/accept-master-spec.json")"

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

WELD_NODE="ns=2;s=Weld/WeldCurrent"

# ---------------------------------------------------------------------------
# Helpers (mirror run-ncmd-runtime-gate.sh idioms). RogueNcmd is the single-metric NCMD publisher;
# the Sparkplug identity (Bifrost:Line1 / recipe-edge) matches what the weld authz policy allows.
pub() {  # $1=nodeId $2=value $3=dataType
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}

start_bridge() {  # $1=CONFORMANCE_PATH(win)  $2=bridge log
  : > "$2"
  MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
  POLICY_PATH="$WELD_POLICY_WIN" REGISTRY_PATH="$REGISTRY_WIN" CONFORMANCE_PATH="$1" \
    java -jar "$HEIMDALL_JAR_WIN" >"$2" 2>&1 &
  BRIDGE_PID=$!
  local ok=0
  for i in $(seq 1 45); do
    if grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && grep -q "\[BRIDGE\] conformance loaded" "$2" 2>/dev/null; then
      ok=1; break
    fi
    sleep 2
  done
  [ "$ok" = "1" ] || fail "Heimdall did not reach '[BRIDGE] ready' + '[BRIDGE] conformance loaded' (log $2)"
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
echo "[GATE] ===== C1: composition (runtime) — envelope cross-member DENY then APPLY ====="
start_bridge "$CONF_ENVELOPE_WIN" "$BLOG_C1"
echo "[GATE] edge up with envelope conformance loaded (pid $BRIDGE_PID)"

pub "$WELD_NODE" 9 Double
wait_deny "$WELD_NODE" "conformance.cross.weld-lobe" "$BLOG_C1" \
  || fail "C1 expected DENY conformance.cross.weld-lobe for WeldCurrent=9 (ElectrodeForce=2.5<3 => WeldCurrent must be <=8)"
echo "[GATE] C1a: WeldCurrent=9 DENIED by composed cross-member rule (conformance.cross.weld-lobe)"

pub "$WELD_NODE" 7 Double
wait_apply "$WELD_NODE" "$BLOG_C1" \
  || fail "C1 expected APPLY ok=true for WeldCurrent=7 (within the composed envelope + cross bound)"
echo "[GATE] C1 OK: composition holds at runtime (9 denied, 7 applied)"

# ---------------------------------------------------------------------------
echo "[GATE] ===== C2: design==runtime — same governed policy drives the CI gate ====="
set +e
java -jar "$GATES_JAR_WIN" spec "$REGISTRY_WIN" "$REJECT_SPEC_WIN"
code=$?
set -e
[ "$code" -eq 1 ] || fail "C2 reject spec (ElectrodeForce=2.5,WeldCurrent=9) returned $code — expected 1 (mirrors the C1 runtime DENY)"
echo "[GATE] C2a: design-time gate REJECTED the same-shape spec (exit 1)"

set +e
java -jar "$GATES_JAR_WIN" spec "$REGISTRY_WIN" "$ACCEPT_SPEC_WIN"
code=$?
set -e
[ "$code" -eq 0 ] || fail "C2 accept-control spec (ElectrodeForce=4.0 => antecedent false) returned $code — expected 0"
echo "[GATE] C2 OK: design==runtime — one governed policy, identical verdict on gate and edge"

# ---------------------------------------------------------------------------
echo "[GATE] ===== C3: single-source flip — edit ONE governed policy, BOTH boundaries move ====="
stop_bridge
# Flip the governed conformance policy's weld-lobe consequent 8 -> 10. The Heimdall authz policy.json
# is NOT touched — this is the ONLY change, and it must move both the CI gate and the runtime edge.
sed -i 's/"thenValue": *8\.0/"thenValue": 10.0/' "$CONF_ENVELOPE"
grep -q '"thenValue": 10.0' "$CONF_ENVELOPE" || fail "C3 sed did not flip thenValue 8.0 -> 10.0 in $CONF_ENVELOPE"

set +e
java -jar "$GATES_JAR_WIN" spec "$REGISTRY_WIN" "$REJECT_SPEC_WIN"
code=$?
set -e
[ "$code" -eq 0 ] || fail "C3 after the flip the previously-rejected spec returned $code — expected 0 (design boundary moved)"
echo "[GATE] C3a: design-time gate now ACCEPTS the same spec (flip seen by the CI gate)"

start_bridge "$CONF_ENVELOPE_WIN" "$BLOG_C3"
pub "$WELD_NODE" 9 Double
wait_apply "$WELD_NODE" "$BLOG_C3" \
  || fail "C3 after the flip WeldCurrent=9 was not APPLYed at runtime — the runtime boundary did not move"
echo "[GATE] C3 OK: one governed edit moved BOTH the CI gate and the runtime edge (single source of truth)"

# ---------------------------------------------------------------------------
echo "[GATE] ===== C4: dial — swap envelope -> recipe-mode (active WeldSchedule, tol 0) ====="
stop_bridge
start_bridge "$CONF_RECIPE_WIN" "$BLOG_C4"

pub "$WELD_NODE" 7 Double
wait_deny "$WELD_NODE" "conformance.recipe.deviation" "$BLOG_C4" \
  || fail "C4 expected DENY conformance.recipe.deviation for WeldCurrent=7 (approved WeldSchedule setpoint is 9, tol 0)"
echo "[GATE] C4a: WeldCurrent=7 DENIED as a deviation from the approved recipe (conformance.recipe.deviation)"

pub "$WELD_NODE" 9 Double
wait_apply "$WELD_NODE" "$BLOG_C4" \
  || fail "C4 expected APPLY ok=true for WeldCurrent=9 (matches the approved WeldSchedule setpoint)"
echo "[GATE] C4 OK: the governed dial re-scoped the SAME node from envelope to exact-recipe conformance"
stop_bridge

# ---------------------------------------------------------------------------
echo "[GATE] ===== C5: lifecycle — provenance publish/verify the governed policy bytes ====="
# Publish the governed conformance-policy bytes as a provenance-tracked recipe entry, then prove
# verify accepts clean bytes and rejects a single-byte tamper (mirrors the spine gate's throwaway
# git-repo + core.autocrlf=false pattern so the committed blob stays byte-verbatim).
cp "$CONF_ENVELOPE" "$WORK/srcrepo/Weld-Controller-policy-1.0.0.json"
SRCREPO_WIN="$(cygpath -m "$(pwd)/$WORK/srcrepo")"
git -C "$SRCREPO_WIN" init -q
git -C "$SRCREPO_WIN" config core.autocrlf false
git -C "$SRCREPO_WIN" config user.email gate@local
git -C "$SRCREPO_WIN" config user.name gate
git -C "$SRCREPO_WIN" add Weld-Controller-policy-1.0.0.json
git -C "$SRCREPO_WIN" commit -qm seed

set +e
java -jar "$GATES_JAR_WIN" provenance publish "$REGISTRY_WIN" "$SRCREPO_WIN" \
  Weld-Controller-policy-1.0.0.json Weld-Controller-policy 1.0.0
code=$?
set -e
[ "$code" -eq 0 ] || fail "C5 provenance publish returned $code — expected 0"
PUBLISHED="$WORK/registry/recipe/Weld-Controller-policy/1.0.0/recipe-setpoints.yaml"
[ -f "$PUBLISHED" ] || fail "C5 provenance publish did not write $PUBLISHED"

set +e
java -jar "$GATES_JAR_WIN" provenance verify "$REGISTRY_WIN" Weld-Controller-policy
code=$?
set -e
[ "$code" -eq 0 ] || fail "C5 provenance verify of untampered governed policy returned $code — expected clean accept (0)"
echo "[GATE] C5a: provenance verify accepted the clean published policy (exit 0)"

printf 'X' >> "$PUBLISHED"
set +e
java -jar "$GATES_JAR_WIN" provenance verify "$REGISTRY_WIN" Weld-Controller-policy
code=$?
set -e
[ "$code" -eq 1 ] || fail "C5 provenance verify of a TAMPERED policy returned $code — expected reject (exit 1 = content-hash mismatch)"
echo "[GATE] C5 OK: provenance verify accepted clean, rejected a one-byte tamper (governed-policy lifecycle)"

# ---------------------------------------------------------------------------
echo "[GATE] step 9: teardown"
[ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true

echo ""
echo "[GATE] PASS run-composable-conformance-gate.sh"
exit 0
