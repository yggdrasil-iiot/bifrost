#!/usr/bin/env bash
# EDGE RESILIENCE GATE (R0 acceptance): prove the Heimdall edge survives an unattended night.
# Every assertion here is made by BREAKING something and requiring recovery with no human action.
#
#   E0 cold start    : the edge reaches [BRIDGE] ready with NO OPC-UA server running at all. A site
#                      power event restarts the server and the edge together; an edge that exits
#                      here crash-loops under a restart policy instead of waiting.
#   E1 broker restart: restart HiveMQ; the edge reconnects AND resubscribes. Asserted by a command
#                      APPLIED AFTER the restart (an APPLY *count increase*), because a reconnect
#                      that failed to resubscribe still logs "reconnected" and then hears nothing.
#   E2 death cert    : taskkill //F the edge (bypassing the JVM shutdown hook) and require the
#                      BROKER to deliver the retained will. The topic is cleared first, so a
#                      previous run's retained "offline" cannot satisfy this one.
#   E3 outage != deny: kill the OPC-UA sim, send an AUTHORIZED command, require [BRIDGE] UNREACHABLE,
#                      NO new [BRIDGE] DENY line, no conformance-error, and an NDATA response detail
#                      that says plant-unreachable.
#   E4 plant recovery: restart the sim, wait out the backoff, send again -> session re-established
#                      and the APPLY count increases. NO bridge restart in between.
#   E5 health        : /healthz is 200 healthy, 503 while the plant is unreachable, 200 again after.
#   E6 two edges     : a second edge (mixer-edge, its own HEALTH_PORT) coexists on one broker.
#                      Neither may lose its session to the other.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 9090, 9091, 48400 free):
#   timeout 900 bash scripts/run-edge-resilience-gate.sh
#   # expect: [GATE] PASS run-edge-resilience-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument).
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
SIM_LOG="$WORK/res-sim.log"
A_LOG="$WORK/res-edge-a.log"
B_LOG="$WORK/res-edge-b.log"
COLD_LOG="$WORK/res-cold.log"
WATCH_LOG="$WORK/res-watch.log"
PUB_LOG="$WORK/res-pub.log"
: > "$PUB_LOG"; : > "$WATCH_LOG"

GROUP="Bifrost:Line1"
EDGE_A="recipe-edge"
EDGE_B="mixer-edge"
RPM_NODE="ns=2;s=Recipe/Rpm"
STATUS_A="bifrost/$GROUP/STATUS/$EDGE_A"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH — Docker Desktop is required for the MQTT broker"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "[GATE] FAIL: curl not found on PATH — needed for the /healthz assertions"; exit 1; }

HEIMDALL_JAR_WIN=""
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$COLD_LOG" "$A_LOG" "$B_LOG" "$WATCH_LOG" "$PUB_LOG"; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -50 "$f"; } || true
  done
  exit 1
}

# jps -lm reports the JAR PATH for a `-jar` launch, so two heimdall JVMs are indistinguishable
# there. `jps -v` reports JVM ARGS, so each edge is started with a -D naming it and can be killed
# on its own — which E6 needs, because it runs two edges at once and must kill only one.
kill_by_jvmarg() {   # $1 = the -D value substring
  { jps -v 2>/dev/null | grep -F "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}
kill_by_mainclass() {  # $1 = substring of the jps -lm line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

cleanup() {
  kill_by_jvmarg "heimdall.gate=" || true
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "TopicWatcher" || true
  # Leave no retained state that could pre-satisfy the NEXT run of this gate.
  [ -n "$HEIMDALL_JAR_WIN" ] && java -cp "$HEIMDALL_JAR_WIN" \
      dev.krillin.bifrost.heimdall.TopicWatcher --clear "$STATUS_A" >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Mop up orphans from a prior aborted run BEFORE starting anything new.
kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-sim.jar" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ]; then
  mvn -q -pl core,heimdall,sim install -DskipTests
fi
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall/target/bifrost-heimdall.jar missing after build"
[ -f sim/target/bifrost-sim.jar ] || fail "sim/target/bifrost-sim.jar missing after build"

HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
[ -f "$(pwd)/heimdall/registry/policy.json" ] || fail "heimdall/registry/policy.json fixture missing"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")"

# ---------------------------------------------------------------------------
# HiveMQ opens :1883 BEFORE its security extension finishes loading, and a client that connects in
# that window is disconnected with an EOF. Waiting only on the port makes this gate flaky, so wait
# on the log line that means the broker is actually serving.
#
# `docker compose logs` ACCUMULATES across restarts, so a bare grep matches the PREVIOUS boot and
# returns instantly - the same accumulating-log trap the APPLY assertions below are written to
# avoid. Take a baseline count and require it to increase.
broker_boots() {
  docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true
}
wait_broker() {   # $1 = the boot count observed BEFORE this start/restart
  for _ in $(seq 1 45); do
    [ "$(broker_boots)" -gt "$1" ] && return 0
    sleep 2
  done
  return 1
}

echo "[GATE] step 1: start HiveMQ CE and wait until it is actually serving"
BROKER_BOOTS="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$BROKER_BOOTS" || { docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true; fail "HiveMQ CE never reported 'Started HiveMQ'"; }
echo "[GATE] HiveMQ CE serving on :1883"

start_sim() {
  : > "$SIM_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && return 0; sleep 2; done
  return 1
}

# $1 = gate tag (A|B|COLD), $2 = log file, $3 = edge name, $4 = health port
start_edge() {
  : > "$2"
  SPB_EDGE="$3" HEALTH_PORT="$4" \
    java "-Dheimdall.gate=$1" -jar "$HEIMDALL_JAR_WIN" >"$2" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && return 0; sleep 2; done
  return 1
}

wait_line() {   # $1=file $2=regex $3=tries (2s each)
  for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done
  return 1
}

# `grep -c` PRINTS 0 and EXITS 1 when it matches nothing, so a `|| echo 0` fallback would print a
# SECOND zero and break every comparison. Same shape as run-ncmd-runtime-gate.sh's apply_count.
count_in() {   # $1=pattern $2=file
  grep -c "$1" "$2" 2>/dev/null || true
}
apply_count() {  # $1=node $2=log
  count_in "\[BRIDGE\] APPLY cmd=$1 ok=true" "$2"
}

pub() {  # $1=node $2=value $3=type $4=edge
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="$GROUP" SPB_EDGE="$4" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}

health_code() { curl -s -m 5 -o /dev/null -w "%{http_code}" "http://localhost:$1/healthz" 2>/dev/null || echo "000"; }

# ---------------------------------------------------------------------------
echo "[GATE] ===== E0: the edge starts with NO OPC-UA server ====="
start_edge COLD "$COLD_LOG" "$EDGE_A" 9090 \
  || fail "E0 the edge did not reach '[BRIDGE] ready' with the plant down — it still dies at startup"
grep -q "OPC-UA not reachable at start" "$COLD_LOG" \
  || fail "E0 the edge did not report the plant as unreachable at start"
[ "$(health_code 9090)" = "503" ] || fail "E0 /healthz should be 503 with no plant, got $(health_code 9090)"
echo "[GATE] E0 OK: ready without a plant, and honest about it on /healthz"
kill_by_jvmarg "heimdall.gate=COLD"
sleep 3

# Clear any retained status BEFORE the real edge starts: E2 must observe THIS run's will, and a
# stale retained "offline" would satisfy it even with setWill deleted.
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher --clear "$STATUS_A" >>"$WATCH_LOG" 2>&1 || true

# ---------------------------------------------------------------------------
echo "[GATE] step 2: start the OPC-UA sim and edge A"
start_sim || fail "the OPC-UA sim did not start"
start_edge A "$A_LOG" "$EDGE_A" 9090 || fail "edge A did not reach '[BRIDGE] ready'"

pub "$RPM_NODE" 1500.0 Double "$EDGE_A"
wait_line "$A_LOG" "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" 10 || fail "the baseline command was not applied"
for _ in $(seq 1 10); do [ "$(health_code 9090)" = "200" ] && break; sleep 2; done
[ "$(health_code 9090)" = "200" ] || fail "E5 /healthz is not 200 with both legs up"
echo "[GATE] baseline OK: command applied, /healthz 200"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E1: a broker restart is survived without human action ====="
BEFORE="$(apply_count "$RPM_NODE" "$A_LOG")"
BROKER_BOOTS="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" restart hivemq-ce >/dev/null 2>&1 || fail "E1 could not restart the broker"
wait_broker "$BROKER_BOOTS" || fail "E1 the broker did not come back"
# Paho's auto-reconnect backoff doubles (1s, 2s, 4s...), so allow generously.
wait_line "$A_LOG" "\[BRIDGE\] reconnected to .*resubscribed" 30 \
  || fail "E1 the edge never reported reconnect+resubscribe"
sleep 2
pub "$RPM_NODE" 1500.0 Double "$EDGE_A"
# THE load-bearing assertion: a reconnect that did NOT resubscribe still logs "reconnected", so the
# only proof that the subscription came back is a NEW apply after the restart.
for _ in $(seq 1 20); do [ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] \
  || fail "E1 no NEW command was applied after the broker restart — reconnected but not resubscribed"
echo "[GATE] E1 OK: reconnected, resubscribed, and a new command was applied"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E3: an OPC-UA outage is a refusal, never a denial ====="
kill_by_mainclass "bifrost-sim.jar"
sleep 3
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher "spBv1.0/$GROUP/NDATA/$EDGE_A" 60 >>"$WATCH_LOG" 2>&1 &
wait_line "$WATCH_LOG" "\[WATCH\] subscribed spBv1.0/$GROUP/NDATA/$EDGE_A" 10 || fail "E3 the NDATA watcher did not subscribe"
DENY_BEFORE="$(count_in "\[BRIDGE\] DENY cmd=" "$A_LOG")"
pub "$RPM_NODE" 1500.0 Double "$EDGE_A"
wait_line "$A_LOG" "\[BRIDGE\] UNREACHABLE cmd=$RPM_NODE" 15 || fail "E3 the edge did not report UNREACHABLE"
[ "$(count_in "\[BRIDGE\] DENY cmd=" "$A_LOG")" = "$DENY_BEFORE" ] \
  || fail "E3 an outage produced a DENY line — unreachable was reported as a denial"
if grep -q "conformance-error" "$A_LOG"; then fail "E3 an outage was reported as conformance-error"; fi
wait_line "$WATCH_LOG" "plant-unreachable" 15 || fail "E3 the NDATA response detail did not say plant-unreachable"
for _ in $(seq 1 10); do [ "$(health_code 9090)" = "503" ] && break; sleep 2; done
[ "$(health_code 9090)" = "503" ] || fail "E5 /healthz is not 503 while the plant is unreachable"
echo "[GATE] E3+E5 OK: UNREACHABLE, no DENY, response says plant-unreachable, /healthz 503"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E4: the plant leg recovers with NO bridge restart ====="
BEFORE="$(apply_count "$RPM_NODE" "$A_LOG")"
start_sim || fail "E4 the sim did not restart"
sleep 7      # outlast the applier's 5s reconnect backoff
pub "$RPM_NODE" 1500.0 Double "$EDGE_A"
wait_line "$A_LOG" "OPC-UA session re-established" 20 || fail "E4 the session was never re-established"
for _ in $(seq 1 20); do [ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] || fail "E4 no NEW command applied after the sim returned"
for _ in $(seq 1 10); do [ "$(health_code 9090)" = "200" ] && break; sleep 2; done
[ "$(health_code 9090)" = "200" ] || fail "E5 /healthz did not return to 200 after recovery"
echo "[GATE] E4+E5 OK: session re-established with no restart, new command applied, /healthz 200"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E6: two edges coexist on one broker ====="
LOST_A_BEFORE="$(count_in "connection lost" "$A_LOG")"
start_edge B "$B_LOG" "$EDGE_B" 9091 || fail "E6 edge B did not reach '[BRIDGE] ready'"
sleep 15
[ "$(count_in "connection lost" "$A_LOG")" = "$LOST_A_BEFORE" ] \
  || fail "E6 edge A lost its session after edge B started — the client id is shared"
[ "$(count_in "connection lost" "$B_LOG")" = "0" ] \
  || fail "E6 edge B lost its session — the client id is shared"
[ "$(health_code 9091)" != "000" ] || fail "E6 edge B is not serving /healthz — it did not stay up"
echo "[GATE] E6 OK: both edges held their sessions for 15s"
kill_by_jvmarg "heimdall.gate=B"
sleep 2

# ---------------------------------------------------------------------------
echo "[GATE] ===== E2: the broker announces a death the process did not report ====="
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher "$STATUS_A" 120 >>"$WATCH_LOG" 2>&1 &
wait_line "$WATCH_LOG" "\[WATCH\] $STATUS_A = online" 15 \
  || fail "E2 no retained 'online' — the edge never announced itself on its status topic"
# taskkill //F is a hard kill: the JVM shutdown hook does NOT run, so bridge.close()'s own
# "offline" publish cannot happen. An "offline" that arrives now came from the BROKER's will.
kill_by_jvmarg "heimdall.gate=A"
# The keepalive is 20s, so the broker needs up to ~30s to declare the session dead.
wait_line "$WATCH_LOG" "\[WATCH\] $STATUS_A = offline" 45 || fail "E2 the broker never published the will"
echo "[GATE] E2 OK: the will fired on a hard kill"

echo ""
echo "[GATE] PASS run-edge-resilience-gate.sh"
exit 0
