#!/usr/bin/env bash
# YGGDRASIL FULL-LOOP GATE: prove a governed + authorized command changes the northbound UNS
# observation (observe -> command -> observe). Composes BOTH axes on ONE broker + ONE sim:
#
#   ../mimir/target/mimir.jar       — model the equipment type (northbound, design-time)
#   gates/target/bifrost-gates.jar  — govern (schema ① + provenance ③)
#   sim/target/bifrost-sim.jar      — embedded OPC-UA sim (Recipe/* setpoints + Line1/Mixer1 PV;
#                                     internal setpoint->PV transfer)
#   heimdall/target/bifrost-heimdall.jar — southbound write-boundary daemon (② authz -> OPC write)
#   ../muninn/target/muninn.jar     — northbound feeder/observer (NBIRTH/NDATA over Sparkplug B)
#   docker-compose.yml (hivemq-ce)  — the MQTT broker
#
# Assertions:
#   L1 OBSERVE#1 : muninn NDATA Rpm == 1535.0 (initial governed observation).
#   L2 COMMAND   : authorized NCMD Recipe/Rpm=1500 -> [BRIDGE] APPLY ok=true, witnessed by
#                  [SIM] SET and [SIM] transfer Line1/Mixer1.Rpm=1500.
#   L3 OBSERVE#2 : muninn NDATA Rpm == 1500.0  <-- THE closed loop.
#   L4 rogue     : NCMD Recipe/Secret -> [BRIDGE] DENY, never APPLY (deny-by-default).
#   L5 d-i-d     : NCMD Recipe/Rpm=9999 -> [BRIDGE] DENY above-max, no new APPLY;
#                  OBSERVE#3 still Rpm == 1500.0 (a denied command does NOT move the UNS).
#
# Run from anywhere (needs Docker Desktop running + host port 1883 free):
#   bash scripts/run-yggdrasil-full-loop-gate.sh
#   # expect: [GATE] PASS run-yggdrasil-full-loop-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="build/loopgate"

GATES_JAR="gates/target/bifrost-gates.jar"
SIM_JAR="sim/target/bifrost-sim.jar"
HEIMDALL_JAR="heimdall/target/bifrost-heimdall.jar"
MIMIR_JAR="../mimir/target/mimir.jar"
MUNINN_JAR="../muninn/target/muninn.jar"

ENDPOINT="opc.tcp://localhost:48400"
NS_URI="urn:bifrost:opcua:sim"
TYPE="MixerType"
REF="Line1-Mixer"
VER="1.0.0"
GROUP="Bifrost:Line1"
EDGE="recipe-edge"
INSTANCE="Line1/Mixer1"
MQTT="tcp://localhost:1883"
RPM_NODE="ns=2;s=Recipe/Rpm"
SECRET_NODE="ns=2;s=Recipe/Secret"

fail() {
  echo "[GATE] FAIL: $*"
  echo "--- sim log tail ---";    tail -40 "$WORK/sim.log"    2>/dev/null || true
  echo "--- bridge log tail ---"; tail -40 "$WORK/bridge.log" 2>/dev/null || true
  for f in "$WORK"/feed-*.log "$WORK"/observe-*.log; do
    [ -f "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -20 "$f" 2>/dev/null; } || true
  done
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

SIM_PID=""; BRIDGE_PID=""; OBS_PID=""; COMPOSE_WIN=""
cleanup() {
  [ -n "$SIM_PID" ]    && taskkill //F //T //PID "$SIM_PID"    >/dev/null 2>&1 || true
  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
  [ -n "$OBS_PID" ]    && taskkill //F //T //PID "$OBS_PID"    >/dev/null 2>&1 || true
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  kill_by_mainclass "muninn.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
echo "[GATE] step 1: preflight + build (5 jars)"
command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }

if [ ! -f "$GATES_JAR" ] || [ ! -f "$SIM_JAR" ] || [ ! -f "$HEIMDALL_JAR" ]; then
  mvn -q -pl core,sim,gates,heimdall install
fi
[ -f "$GATES_JAR" ]    || fail "$GATES_JAR missing after build"
[ -f "$SIM_JAR" ]      || fail "$SIM_JAR missing after build"
[ -f "$HEIMDALL_JAR" ] || fail "$HEIMDALL_JAR missing after build"
[ -f "$MIMIR_JAR" ]  || ( cd ../mimir  && mvn -q package )
[ -f "$MUNINN_JAR" ] || ( cd ../muninn && mvn -q package )
[ -f "$MIMIR_JAR" ]  || fail "$MIMIR_JAR missing after build"
[ -f "$MUNINN_JAR" ] || fail "$MUNINN_JAR missing after build"

kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
kill_by_mainclass "muninn.jar" || true
docker rm -f bifrost-hivemq-ce muninn-hivemq-ce >/dev/null 2>&1 || true

GATES_JAR_WIN="$(cygpath -m "$(pwd)/$GATES_JAR")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/$SIM_JAR")"
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/$HEIMDALL_JAR")"
MIMIR_JAR_WIN="$(cygpath -m "$(pwd)/$MIMIR_JAR")"
MUNINN_JAR_WIN="$(cygpath -m "$(pwd)/$MUNINN_JAR")"
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"
POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")"
[ -f "$(pwd)/heimdall/registry/policy.json" ] || fail "heimdall/registry/policy.json fixture missing"

# ---------------------------------------------------------------------------
echo "[GATE] step 2: start ONE HiveMQ CE broker + sim"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
ok=0
for i in $(seq 1 30); do
  bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || { docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true; fail "HiveMQ CE did not open :1883"; }
echo "[GATE] HiveMQ CE up on :1883"

rm -rf "$WORK"
mkdir -p "$WORK/registry" "$WORK/srcrepo" "$WORK/out"
# SchemaGate reads <registryDir>/policy.json for the compat mode (fail-closed if absent).
echo '{"mode":"FORWARD"}' > "$WORK/registry/policy.json"

: > "$WORK/sim.log"
java -jar "$SIM_JAR_WIN" > "$WORK/sim.log" 2>&1 &
SIM_PID=$!
ok=0
for i in $(seq 1 30); do
  grep -q "OPC-UA sim listening" "$WORK/sim.log" 2>/dev/null && { ok=1; break; }
  sleep 1
done
[ "$ok" = "1" ] || fail "OPC-UA sim did not start (pid $SIM_PID)"
echo "[GATE] OPC-UA sim listening (pid $SIM_PID)"

REGISTRY_WIN="$(cygpath -m "$(pwd)/$WORK/registry")"

# ---------------------------------------------------------------------------
# Observer helpers (mirror the spine gate).
wait_observer_ready() {  # $1=observe log
  local t=0
  while [ "$t" -lt 20 ]; do
    grep -q "\[OBSERVE\] subscribed" "$1" 2>/dev/null && return 0
    sleep 0.5; t=$((t + 1))
  done
  return 1
}
poll_ndata() {  # $1=birth file  $2=ndata file
  local t=0
  while [ "$t" -lt 40 ]; do
    if [ -s "$1" ] && [ -s "$2" ]; then return 0; fi
    sleep 0.5; t=$((t + 1))
  done
  return 1
}
# Run one observe#N + feed#N cycle; capture the Rpm value line into $WORK/out/values-$1.txt
# $1 = run label (1|2|3) ; $2..= extra feed args (none here)
observe_and_feed() {
  local tag="$1"; shift
  local blog="$WORK/out/birth-$tag.bin" ndlog="$WORK/out/ndata-$tag.txt" vlog="$WORK/out/values-$tag.txt"
  : > "$WORK/observe-$tag.log"
  java -jar "$MUNINN_JAR_WIN" observe "$MQTT" "$GROUP" \
    "$(cygpath -m "$(pwd)/$blog")" "$(cygpath -m "$(pwd)/$ndlog")" \
    --expect-ndata 4 --timeout-ms 20000 --ndata-values "$(cygpath -m "$(pwd)/$vlog")" \
    > "$WORK/observe-$tag.log" 2>&1 &
  OBS_PID=$!
  wait_observer_ready "$WORK/observe-$tag.log" || fail "$tag: observer never printed '[OBSERVE] subscribed'"
  set +e
  java -jar "$MUNINN_JAR_WIN" feed "$REGISTRY_WIN" "$REF" "$VER" "$ENDPOINT" "$NS_URI" "$INSTANCE" \
    "$MQTT" "$GROUP" "$EDGE" "$@" > "$WORK/feed-$tag.log" 2>&1
  local code=$?
  set -e
  [ "$code" -eq 0 ] || fail "$tag: feed returned $code — expected 0"
  poll_ndata "$blog" "$ndlog" || fail "$tag: observer never captured birth+ndata"
  OBS_PID=""
}

# ---------------------------------------------------------------------------
echo "[GATE] step 3: govern the MODEL (schema ① + provenance ③) to populate the registry"
set +e
java -jar "$MIMIR_JAR_WIN" derive "$ENDPOINT" "$NS_URI" "$TYPE" "$REF" "$VER" "$(cygpath -m "$(pwd)/$WORK/def.json")"
[ $? -eq 0 ] || { set -e; fail "mimir derive returned non-zero"; }
java -jar "$GATES_JAR_WIN" schema "$REGISTRY_WIN" "$(cygpath -m "$(pwd)/$WORK/def.json")" --promote
[ $? -eq 0 ] || { set -e; fail "schema gate rejected the derive"; }
set -e
[ -f "$WORK/registry/udt/$REF/$VER.json" ] || fail "schema gate did not promote udt/$REF/$VER.json"

cp "$WORK/registry/udt/$REF/$VER.json" "$WORK/srcrepo/$REF-$VER.json"
SRCREPO_WIN="$(cygpath -m "$(pwd)/$WORK/srcrepo")"
git -C "$SRCREPO_WIN" init -q
git -C "$SRCREPO_WIN" config core.autocrlf false
git -C "$SRCREPO_WIN" config user.email gate@local
git -C "$SRCREPO_WIN" config user.name gate
git -C "$SRCREPO_WIN" add "$REF-$VER.json"
git -C "$SRCREPO_WIN" commit -qm seed
set +e
java -jar "$GATES_JAR_WIN" provenance publish "$REGISTRY_WIN" "$SRCREPO_WIN" "$REF-$VER.json" "$REF" "$VER"
[ $? -eq 0 ] || { set -e; fail "provenance publish returned non-zero"; }
set -e
[ -f "$WORK/registry/recipe/$REF/$VER/recipe-setpoints.yaml" ] || fail "provenance publish did not mint the recipe"
echo "[GATE] registry populated (udt + recipe) for $REF@$VER"

# ---------------------------------------------------------------------------
echo "[GATE] step 4: start the Heimdall daemon (southbound write boundary)"
export MQTT_URL="$MQTT"
export OPCUA_URL="$ENDPOINT"
export SPB_GROUP="$GROUP"
export SPB_EDGE="$EDGE"
export POLICY_PATH="$POLICY_PATH"
# Rpm range moved from policy.json to the governed model (conformance track): activate ② so L5's
# Rpm=9999 above-max DENY comes from the governed Mixer model, not a hand-authored policy.json bound.
export REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")"
: > "$WORK/bridge.log"
java -jar "$HEIMDALL_JAR_WIN" > "$WORK/bridge.log" 2>&1 &
BRIDGE_PID=$!
ok=0
for i in $(seq 1 45); do
  grep -q "\[BRIDGE\] ready" "$WORK/bridge.log" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "Heimdall daemon did not reach '[BRIDGE] ready' (pid $BRIDGE_PID)"
echo "[GATE] Heimdall ready (pid $BRIDGE_PID)"

pub() {  # $1=nodeId $2=value $3=dataType
  MQTT_URL="$MQTT" SPB_GROUP="$GROUP" SPB_EDGE="$EDGE" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$WORK/pub.log" 2>&1
}
apply_count() { grep -c "\[BRIDGE\] APPLY cmd=$1" "$WORK/bridge.log" 2>/dev/null || echo 0; }

# ---------------------------------------------------------------------------
echo "[GATE] ===== L1 OBSERVE#1 (before): NDATA Rpm == 1535.0 ====="
observe_and_feed 1
grep -q "^Rpm=1535" "$WORK/out/values-1.txt" || fail "L1: NDATA Rpm != 1535 (got: $(grep '^Rpm=' "$WORK/out/values-1.txt" || echo none))"
echo "[GATE] L1 OK: initial UNS observation Rpm=1535.0"

# ---------------------------------------------------------------------------
echo "[GATE] ===== L2 COMMAND: authorized NCMD Recipe/Rpm=1500 -> APPLY + transfer ====="
pub "$RPM_NODE" 1500 Double
ok=0
for i in $(seq 1 10); do
  grep -q "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" "$WORK/bridge.log" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "L2: '[BRIDGE] APPLY cmd=$RPM_NODE ok=true' never observed"
ok=0
for i in $(seq 1 10); do
  grep -q "\[SIM\] transfer Line1/Mixer1.Rpm = 1500" "$WORK/sim.log" 2>/dev/null && { ok=1; break; }
  sleep 1
done
[ "$ok" = "1" ] || fail "L2: '[SIM] transfer Line1/Mixer1.Rpm = 1500' never observed (transfer not wired?)"
echo "[GATE] L2 OK: authorized command applied + transferred to the instance PV"

# ---------------------------------------------------------------------------
echo "[GATE] ===== L3 OBSERVE#2 (after): NDATA Rpm == 1500.0 — THE CLOSED LOOP ====="
observe_and_feed 2
grep -q "^Rpm=1500" "$WORK/out/values-2.txt" || fail "L3: NDATA Rpm != 1500 after command (got: $(grep '^Rpm=' "$WORK/out/values-2.txt" || echo none))"
echo "[GATE] L3 OK: the governed+authorized command changed the UNS observation 1535 -> 1500"

# ---------------------------------------------------------------------------
echo "[GATE] ===== L4 rogue deny-by-default: Recipe/Secret -> DENY, never APPLY ====="
pub "$SECRET_NODE" 1.0 Double
sleep 3
grep -q "\[BRIDGE\] DENY cmd=$SECRET_NODE" "$WORK/bridge.log" || fail "L4: bridge did not DENY the rogue $SECRET_NODE"
! grep -q "\[BRIDGE\] APPLY cmd=$SECRET_NODE" "$WORK/bridge.log" || fail "L4: bridge APPLIED a deny-by-default node"
echo "[GATE] L4 OK: rogue node denied, never applied"

# ---------------------------------------------------------------------------
echo "[GATE] ===== L5 defense-in-depth: Recipe/Rpm=9999 -> DENY above-max, UNS unchanged ====="
APPLY_BEFORE=$(apply_count "$RPM_NODE")
pub "$RPM_NODE" 9999 Double
sleep 3
grep -qE "\[BRIDGE\] DENY cmd=$RPM_NODE .*above-max" "$WORK/bridge.log" || fail "L5: bridge did not DENY Rpm=9999 as above-max"
APPLY_AFTER=$(apply_count "$RPM_NODE")
[ "$APPLY_AFTER" = "$APPLY_BEFORE" ] || fail "L5: an APPLY for $RPM_NODE appeared after the out-of-range rogue (before=$APPLY_BEFORE after=$APPLY_AFTER)"
observe_and_feed 3
grep -q "^Rpm=1500" "$WORK/out/values-3.txt" || fail "L5: UNS Rpm changed after a DENIED command (got: $(grep '^Rpm=' "$WORK/out/values-3.txt" || echo none))"
echo "[GATE] L5 OK: out-of-range command denied; UNS observation still Rpm=1500.0"

# ---------------------------------------------------------------------------
echo "[GATE] step 9: teardown"
[ -n "$SIM_PID" ]    && taskkill //F //T //PID "$SIM_PID"    >/dev/null 2>&1 || true
[ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
kill_by_mainclass "muninn.jar" || true
docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true

echo ""
echo "[GATE] PASS run-yggdrasil-full-loop-gate.sh"
exit 0
