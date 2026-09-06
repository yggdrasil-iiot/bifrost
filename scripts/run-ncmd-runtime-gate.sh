#!/usr/bin/env bash
# BIFROST-LOCAL RUNTIME NCMD GATE (Chunk-1 acceptance): prove Heimdall stands ALONE end-to-end —
# an MQTT broker + a real embedded OPC-UA sim + the shaded heimdall daemon. An AUTHORIZED
# Sparkplug NCMD is applied to the sim and confirmed by OPC-UA read-back; UNAUTHORIZED NCMDs are
# denied deny-by-default (both a wholly unknown node and an allowed node with an out-of-range
# value — defense in depth).
#
# Asserts:
#   T1 authorized  : pub Rpm=1500 -> bridge APPLY ok=true (write+read-back confirmed against the
#                    live sim; the sim's own AttributeObserver optionally corroborates).
#   T2 rogue        : pub an unregistered node (Recipe/Secret) -> bridge DENY (deny-by-default),
#                    never APPLYed.
#   T3 defense-in-depth : pub Rpm=9999 (allowed node, out of policy range 0..3000) -> bridge DENY
#                    above-max, no new APPLY for Rpm.
#   T4 log-only     : restart the edge with ENFORCEMENT_LOG_ONLY=on and re-send BOTH rogues. Each is
#                    logged LOG-ONLY would-deny and then APPLIED, the live sim witnesses the
#                    out-of-range 9999 landing on the OPC-UA node, and NO DENY line appears. This is
#                    the rollout mode from docs/ADOPTION.md phase 4 — proving it does what it claims
#                    means proving the edge stopped blocking, which is why it is asserted against a
#                    real broker and a real server rather than only in unit tests.
#   T5 revert       : restart enforcing (flag removed) and re-send the rogue -> DENY again, never
#                    APPLYed. The mode is reversible by a restart, which is the property the rollout
#                    plan actually leans on.
#
# Run from the bifrost repo root:
#   timeout 600 bash scripts/run-ncmd-runtime-gate.sh
#   # expect: [GATE] PASS run-ncmd-runtime-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
SIM_LOG="$WORK/sim.log"
BRIDGE_LOG="$WORK/bridge.log"
LOGONLY_LOG="$WORK/bridge-logonly.log"
REVERT_LOG="$WORK/bridge-revert.log"
PUB_LOG="$WORK/pub.log"
: > "$PUB_LOG"

SIM_PID=""
BRIDGE_PID=""

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH — Docker Desktop is required for the MQTT broker"; exit 1; }

fail() {
  echo "[GATE] FAIL: $*"
  echo "--- sim log tail ---";    tail -60 "$SIM_LOG"    2>/dev/null || true
  for f in "$BRIDGE_LOG" "$LOGONLY_LOG" "$REVERT_LOG"; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -60 "$f" 2>/dev/null; } || true
  done
  echo "--- pub log tail ---";    tail -40 "$PUB_LOG"    2>/dev/null || true
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
  # (a known MSYS fork/exec quirk) — the taskkills above are best-effort only. jps -lm on a `-jar`
  # launch reports the JAR PATH, not the main class, so match on the jar filename instead.
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  docker compose -f "$(cygpath -m "$(pwd)/docker-compose.yml")" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Mop up orphans from a prior aborted run BEFORE we start anything new.
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing"
if [ ! -f core/target/bifrost-core-0.1.0-SNAPSHOT.jar ] || [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ]; then
  mvn -q -pl core,heimdall,sim install
fi
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall/target/bifrost-heimdall.jar missing after build"
[ -f sim/target/bifrost-sim.jar ] || fail "sim/target/bifrost-sim.jar missing after build"

HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")"
[ -f "$(pwd)/heimdall/registry/policy.json" ] || fail "heimdall/registry/policy.json fixture missing"

COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

echo "[GATE] heimdall=$HEIMDALL_JAR_WIN"
echo "[GATE] sim=$SIM_JAR_WIN"
echo "[GATE] policy=$POLICY_PATH"

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
echo "[GATE] step 2: start the embedded OPC-UA sim"
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

# ---------------------------------------------------------------------------
echo "[GATE] step 3: start the Heimdall daemon + wait for [BRIDGE] ready"
export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="Bifrost:Line1"
export SPB_EDGE="recipe-edge"
export POLICY_PATH="$POLICY_PATH"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")"

# The edge is (re)started three times in this gate — enforcing, log-only, enforcing again — so the
# start/stop is a function. Each run gets its own log file: the assertions below are about which
# lines a given RUN produced, and greping one accumulated file would let an earlier run's DENY
# satisfy a later run's assertion.
start_bridge() {  # $1 = log file for this run
  : > "$1"
  java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  BRIDGE_PID=$!
  for _ in $(seq 1 45); do
    grep -q "\[BRIDGE\] ready" "$1" 2>/dev/null && return 0
    sleep 2
  done
  return 1
}

stop_bridge() {
  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  BRIDGE_PID=""
  sleep 3      # let the broker drop the session before the next edge claims the same client id
}

start_bridge "$BRIDGE_LOG" || fail "Heimdall daemon did not reach '[BRIDGE] ready' (pid $BRIDGE_PID)"
grep -q "\[BRIDGE\] enforcement = enforcing" "$BRIDGE_LOG"   || fail "the edge did not announce 'enforcement = enforcing' — the mode must be readable from the log"
echo "[GATE] Heimdall ready, enforcing (pid $BRIDGE_PID)"

# ---------------------------------------------------------------------------
# Rogue/legit NCMD publisher — RogueNcmd is the general single-metric NCMD publisher.
pub() {  # $1=nodeId $2=value $3=dataType
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}
# `grep -c` PRINTS 0 and EXITS 1 when it matches nothing, so an `|| echo 0` fallback prints a
# SECOND zero and every comparison against a literal 0 then fails. T3 never noticed because it
# compared two equally-broken values; T5 compares against 0 and does. Capture, then default on rc.
apply_count() {  # $1=node id  $2=log file (default: the enforcing run's log)
  local n
  n=$(grep -c "\[BRIDGE\] APPLY cmd=$1" "${2:-$BRIDGE_LOG}" 2>/dev/null) || n=0
  printf '%s' "$n"
}
wait_line() {  # $1=log $2=extended regex $3=tries
  for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done
  return 1
}

RPM_NODE="ns=2;s=Recipe/Rpm"
SECRET_NODE="ns=2;s=Recipe/Secret"

# ---------------------------------------------------------------------------
echo "[GATE] ===== T1: authorized — Rpm=1500 -> bridge APPLY ok=true (write+read-back confirmed) ====="
pub "$RPM_NODE" 1500 Double
ok=0
for i in $(seq 1 10); do
  grep -q "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" "$BRIDGE_LOG" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "T1 expected '[BRIDGE] APPLY cmd=$RPM_NODE ok=true' — never observed"
if grep -q "\[SIM\] SET ns=2;s=Recipe/Rpm = 1500" "$SIM_LOG" 2>/dev/null; then
  echo "[GATE] T1 sim witness: [SIM] SET ns=2;s=Recipe/Rpm = 1500.0 (or 1500) observed"
fi
echo "[GATE] T1 OK: authorized NCMD applied and confirmed by OPC-UA read-back"

# ---------------------------------------------------------------------------
echo "[GATE] ===== T2: rogue deny-by-default — unregistered node -> bridge DENY, never APPLY ====="
pub "$SECRET_NODE" 1.0 Double
sleep 3
grep -q "\[BRIDGE\] DENY cmd=$SECRET_NODE" "$BRIDGE_LOG" || fail "T2 bridge did not DENY the rogue deny-by-default node $SECRET_NODE"
if grep -q "\[BRIDGE\] APPLY cmd=$SECRET_NODE" "$BRIDGE_LOG"; then fail "T2 bridge APPLIED a deny-by-default node — edge authz breached"; fi
echo "[GATE] T2 OK: rogue deny-by-default node denied at the edge, never applied"

# ---------------------------------------------------------------------------
echo "[GATE] ===== T3: defense-in-depth — Rpm=9999 (allowed node, out of range) -> DENY above-max ====="
APPLY_BEFORE=$(apply_count "$RPM_NODE")
pub "$RPM_NODE" 9999 Double
sleep 3
grep -qE "\[BRIDGE\] DENY cmd=$RPM_NODE .*above-max" "$BRIDGE_LOG" || fail "T3 bridge did not DENY Rpm=9999 as above-max"
APPLY_AFTER=$(apply_count "$RPM_NODE")
[ "$APPLY_AFTER" = "$APPLY_BEFORE" ] || fail "T3 an APPLY for $RPM_NODE appeared after the out-of-range rogue (before=$APPLY_BEFORE after=$APPLY_AFTER) — defense-in-depth breached"
echo "[GATE] T3 OK: out-of-range command denied at the edge (above-max), no new APPLY"

# ---------------------------------------------------------------------------
echo "[GATE] ===== T4: log-only — restart with ENFORCEMENT_LOG_ONLY=on, both rogues APPLIED ====="
stop_bridge
export ENFORCEMENT_LOG_ONLY=on
start_bridge "$LOGONLY_LOG" || fail "T4 Heimdall did not reach '[BRIDGE] ready' in log-only mode"
grep -q "\[BRIDGE\] enforcement = LOG-ONLY" "$LOGONLY_LOG"   || fail "T4 the edge did not announce 'enforcement = LOG-ONLY' — a mode that disables blocking MUST be visible at startup"
echo "[GATE] T4 edge restarted in LOG-ONLY"

# ① authz: the unregistered node is the command an unlisted device would send.
pub "$SECRET_NODE" 1.0 Double
wait_line "$LOGONLY_LOG" "\[BRIDGE\] LOG-ONLY would-deny cmd=$SECRET_NODE" 10   || fail "T4 no LOG-ONLY would-deny for $SECRET_NODE — the verdict must still be reached and recorded"
# NB: this asserts APPLY, not ok=true. Recipe/Secret does not exist on the OPC-UA server, so the
# write fails AT THE APPLIER (ok=false) — which is the point: the refusal is now the server's, not
# the edge's. Requiring ok=true here would be asserting that the sim has a node it must not have.
wait_line "$LOGONLY_LOG" "\[BRIDGE\] APPLY cmd=$SECRET_NODE" 10   || fail "T4 $SECRET_NODE was not APPLIED — log-only did not let the command through"

# ② conformance: the out-of-range value on an allowed node.
pub "$RPM_NODE" 9999 Double
wait_line "$LOGONLY_LOG" "\[BRIDGE\] LOG-ONLY would-deny cmd=$RPM_NODE .*above-max" 10   || fail "T4 no LOG-ONLY would-deny above-max for $RPM_NODE — log-only must cover conformance, not only authz"
wait_line "$LOGONLY_LOG" "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" 10   || fail "T4 out-of-range $RPM_NODE was not APPLIED — log-only did not let the command through"

# The token separation matters operationally: a log scraper counting DENY must not see one here.
if grep -q "\[BRIDGE\] DENY cmd=" "$LOGONLY_LOG"; then
  fail "T4 a DENY line appeared in log-only mode — nothing may be blocked, and no line may read as a block"
fi

# The strongest witness is not in Heimdall's own log: the out-of-range value reached the live server.
wait_line "$SIM_LOG" "\[SIM\] SET ns=2;s=Recipe/Rpm = 9999" 5   || fail "T4 the sim never witnessed Rpm=9999 — the command was reported applied but did not reach OPC-UA"
echo "[GATE] T4 OK: both rogues logged would-deny and APPLIED; sim witnessed the out-of-range 9999; zero DENY lines"

# ---------------------------------------------------------------------------
echo "[GATE] ===== T5: revert — restart enforcing, the rogue is denied again ====="
stop_bridge
unset ENFORCEMENT_LOG_ONLY
start_bridge "$REVERT_LOG" || fail "T5 Heimdall did not reach '[BRIDGE] ready' after reverting to enforcing"
grep -q "\[BRIDGE\] enforcement = enforcing" "$REVERT_LOG" || fail "T5 the edge did not revert to 'enforcement = enforcing'"
pub "$SECRET_NODE" 1.0 Double
wait_line "$REVERT_LOG" "\[BRIDGE\] DENY cmd=$SECRET_NODE" 10   || fail "T5 the reverted edge did not DENY $SECRET_NODE — log-only was not reversible by a restart"
[ "$(apply_count "$SECRET_NODE" "$REVERT_LOG")" = "0" ]   || fail "T5 the reverted edge APPLIED $SECRET_NODE — enforcement did not come back"
echo "[GATE] T5 OK: enforcement restored by a restart, rogue denied and never applied"

echo ""
echo "[GATE] PASS run-ncmd-runtime-gate.sh"
exit 0
