#!/usr/bin/env bash
# WRITE EXCLUSIVITY GATE (R3 acceptance): prove the governed edge can present an OPC-UA identity and
# that a server configured to require it refuses everyone else's WRITES while still serving reads.
#
# This is the evidence for ENTERPRISE.md row 12 moving open -> partial. Read that row's caveats:
# it is proved here against the bundled sim on the OPC-UA surface. Modbus has no identity and is
# untouched, and a plant's own server still has to be configured.
#
#   X5 default posture : sim WITHOUT SIM_REQUIRE_IDENTITY -> an anonymous write SUCCEEDS. Run first
#                        and deliberately: without it the gate cannot show that X2's refusal came
#                        from the new configuration rather than from something incidental.
#   X6 no downgrade    : sim WITHOUT identity, edge WITH one -> the edge REFUSES ("no
#                        Basic256Sha256/SignAndEncrypt endpoint") instead of quietly connecting
#                        anonymously, and applies nothing.
#   X1 governed writes : sim WITH identity + the edge's thumbprint -> an authorized NCMD is applied
#                        (APPLY count INCREASE) and the live sim witnesses the value.
#   X2 second client   : an anonymous client writes a DISTINCT value to the same node and is refused
#                        by the SERVER with Bad_UserAccessDenied specifically; the value is unchanged
#                        from a baseline read taken between X1 and X2.
#   X3 reads still open: the SAME process and session reads the node successfully - the mechanism is
#                        write permission, not a lockout. This is also what proves the X2 client was
#                        genuinely connected.
#   X4 untrusted cert  : an edge with a DIFFERENT identity directory never applies, and the node is
#                        unchanged.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 9090, 9091, 48400 free):
#   timeout 900 bash scripts/run-write-exclusivity-gate.sh
#   # expect: [GATE] PASS run-write-exclusivity-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
SIM_OPEN_LOG="$WORK/wx-sim-open.log"
SIM_SEC_LOG="$WORK/wx-sim-sec.log"
EDGE_OPEN_LOG="$WORK/wx-edge-open.log"
EDGE_GOV_LOG="$WORK/wx-edge-gov.log"
EDGE_BAD_LOG="$WORK/wx-edge-bad.log"
ANON_LOG="$WORK/wx-anon.log"
PUB_LOG="$WORK/wx-pub.log"
PKI_GOOD="$WORK/wx-pki-good"
PKI_BAD="$WORK/wx-pki-bad"
: > "$PUB_LOG"; : > "$ANON_LOG"

GROUP="Bifrost:Line1"
EDGE_A="recipe-edge"
RPM_NODE="ns=2;s=Recipe/Rpm"
GOOD_VALUE="1500.0"
ROGUE_VALUE="4242.0"      # distinct from GOOD_VALUE on purpose: see X2
# X4 publishes through the EDGE, so its value must be one the edge policy ALLOWS. ROGUE_VALUE is
# above Rpm's max of 3000, so using it here made X4 green because ②conformance denied the command
# before OPC-UA was ever reached - nothing to do with the certificate. In range and distinct.
X4_VALUE="1600.0"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }

COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_OPEN_LOG" "$SIM_SEC_LOG" "$EDGE_OPEN_LOG" "$EDGE_GOV_LOG" "$EDGE_BAD_LOG" "$ANON_LOG" "$PUB_LOG"; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -40 "$f"; } || true
  done
  exit 1
}

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
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT
kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-sim.jar" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ]; then
  mvn -q -pl core,heimdall,sim install -DskipTests
fi
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export SPB_EDGE="$EDGE_A"
export POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")"

# `docker compose logs` ACCUMULATES across restarts, so a bare grep matches a PREVIOUS boot and
# returns instantly. Baseline the count and require it to increase.
broker_boots() {
  docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true
}
wait_broker() {   # $1 = boot count before this start
  for _ in $(seq 1 45); do [ "$(broker_boots)" -gt "$1" ] && return 0; sleep 2; done
  return 1
}

echo "[GATE] step 1: HiveMQ CE"
BROKER_BOOTS="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$BROKER_BOOTS" || fail "HiveMQ CE never reported 'Started HiveMQ'"

# ---------------------------------------------------------------------------
# The edge's identity must exist BEFORE the sim starts, because the sim is configured to trust its
# thumbprint. --print-thumbprint exists for exactly this ordering. Its POSIX warning goes to stderr,
# so stdout is the thumbprint and nothing else.
echo "[GATE] step 2: mint the governed and the untrusted identities"
rm -rf "$PKI_GOOD" "$PKI_BAD"
APP_URI="urn:bifrost:heimdall:Bifrost-Line1:$EDGE_A"
GOOD_THUMB="$(java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.EdgeIdentity \
    --print-thumbprint "$PKI_GOOD" "$APP_URI" 2>/dev/null | tr -d '\r')"
BAD_THUMB="$(java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.EdgeIdentity \
    --print-thumbprint "$PKI_BAD" "$APP_URI" 2>/dev/null | tr -d '\r')"
[ -n "$GOOD_THUMB" ] || fail "could not mint the governed identity"
[ "$GOOD_THUMB" != "$BAD_THUMB" ] || fail "the two identities share a thumbprint - X4 would prove nothing"
echo "[GATE] governed thumbprint  = $GOOD_THUMB"
echo "[GATE] untrusted thumbprint = $BAD_THUMB"

start_sim_open() {
  : > "$SIM_OPEN_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_OPEN_LOG" 2>&1 &
  for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_OPEN_LOG" 2>/dev/null && return 0; sleep 2; done
  return 1
}
start_sim_secured() {
  : > "$SIM_SEC_LOG"
  SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$GOOD_THUMB" \
    java -jar "$SIM_JAR_WIN" >"$SIM_SEC_LOG" 2>&1 &
  for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_SEC_LOG" 2>/dev/null && return 0; sleep 2; done
  return 1
}

# $1 = gate tag, $2 = log, $3 = identity dir ("" for none), $4 = health port
start_edge() {
  : > "$2"
  HEIMDALL_IDENTITY_DIR="$3" HEALTH_PORT="$4" \
    java "-Dheimdall.gate=$1" -jar "$HEIMDALL_JAR_WIN" >"$2" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && return 0; sleep 2; done
  return 1
}

wait_line() { for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
count_in()  { grep -c "$1" "$2" 2>/dev/null || true; }
apply_count() { count_in "\[BRIDGE\] APPLY cmd=$1 ok=true" "$2"; }

pub() { java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" Double >>"$PUB_LOG" 2>&1; }

anon() {  # $1 = value to attempt; appends READ + WRITE lines to ANON_LOG
  # stderr is KEPT: swallowing it once hid an AnonymousWriter that never connected at all, and
  # set -e killed the gate with no assertion message to say why.
  java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.AnonymousWriter "$RPM_NODE" "$1" >>"$ANON_LOG" 2>&1     || fail "the anonymous client did not run - see $ANON_LOG"
}
last_anon() { grep "\[ANON\] $1 " "$ANON_LOG" | tail -1; }

# ---------------------------------------------------------------------------
echo "[GATE] ===== X5: the default posture is unchanged — an anonymous write SUCCEEDS ====="
start_sim_open || fail "the open sim did not start"
grep -q "secured endpoint" "$SIM_OPEN_LOG" && fail "X5 the sim announced a secured endpoint without being asked"
anon "$ROGUE_VALUE"
echo "$(last_anon WRITE)" | grep -q "status=Good" \
  || fail "X5 an anonymous write was NOT allowed by the default sim: $(last_anon WRITE)"
echo "[GATE] X5 OK: without SIM_REQUIRE_IDENTITY the same write succeeds"

# ---------------------------------------------------------------------------
echo "[GATE] ===== X6: an edge with an identity refuses to run degraded ====="
start_edge X6 "$EDGE_OPEN_LOG" "$(cygpath -m "$(pwd)/$PKI_GOOD")" 9090 \
  || fail "X6 the edge did not reach ready (it must start, then refuse the plant)"
BEFORE="$(apply_count "$RPM_NODE" "$EDGE_OPEN_LOG")"
pub "$RPM_NODE" "$GOOD_VALUE"
wait_line "$EDGE_OPEN_LOG" "no Basic256Sha256/SignAndEncrypt endpoint" 15 \
  || fail "X6 the edge did not refuse - it may have silently connected to the anonymous endpoint"
[ "$(apply_count "$RPM_NODE" "$EDGE_OPEN_LOG")" = "$BEFORE" ] \
  || fail "X6 the edge APPLIED a command while holding an identity it could not present"
echo "[GATE] X6 OK: refused the anonymous endpoint and applied nothing"
kill_by_jvmarg "heimdall.gate=X6"
kill_by_mainclass "bifrost-sim.jar"
sleep 3

# ---------------------------------------------------------------------------
echo "[GATE] ===== X1: the governed edge writes ====="
start_sim_secured || fail "the secured sim did not start"
grep -q "\[SIM\] secured endpoint Basic256Sha256/SignAndEncrypt" "$SIM_SEC_LOG" \
  || fail "X1 the sim did not announce a secured endpoint - a failed bind is only a WARN, so it would otherwise look listening"
start_edge X1 "$EDGE_GOV_LOG" "$(cygpath -m "$(pwd)/$PKI_GOOD")" 9090 || fail "X1 the governed edge did not reach ready"
grep -q "\[BRIDGE\] OPC-UA identity $GOOD_THUMB" "$EDGE_GOV_LOG" \
  || fail "X1 the edge did not announce the governed thumbprint"

BEFORE="$(apply_count "$RPM_NODE" "$EDGE_GOV_LOG")"
pub "$RPM_NODE" "$GOOD_VALUE"
for _ in $(seq 1 20); do [ "$(apply_count "$RPM_NODE" "$EDGE_GOV_LOG")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$RPM_NODE" "$EDGE_GOV_LOG")" -gt "$BEFORE" ] \
  || fail "X1 the governed edge did not apply an authorized command"
wait_line "$SIM_SEC_LOG" "\[SIM\] SET $RPM_NODE = $GOOD_VALUE" 10 \
  || fail "X1 the live sim never witnessed the value - the edge reported an apply that did not land"
echo "[GATE] X1 OK: the governed identity wrote, and the server witnessed it"

# ---------------------------------------------------------------------------
echo "[GATE] ===== X2/X3: a second client is refused the write, and still reads ====="
# The baseline is taken HERE, between X1 and X2. X1 has just written GOOD_VALUE, so asserting
# "unchanged" against anything earlier would be satisfied even by a write that landed.
anon "$ROGUE_VALUE"
BASELINE_READ="$(last_anon READ)"
echo "$BASELINE_READ" | grep -q "status=Good" \
  || fail "X3 the anonymous client could not even READ - it was locked out, not write-restricted: $BASELINE_READ"
echo "$BASELINE_READ" | grep -q "= $GOOD_VALUE" \
  || fail "X2 baseline read is not the value X1 wrote: $BASELINE_READ"
echo "$(last_anon WRITE)" | grep -q "status=Bad_UserAccessDenied" \
  || fail "X2 the anonymous write was not refused with Bad_UserAccessDenied: $(last_anon WRITE)"

# Read again, in a fresh session, to prove the rogue value did not land.
anon "$ROGUE_VALUE"
echo "$(last_anon READ)" | grep -q "= $GOOD_VALUE" \
  || fail "X2 the node changed after the refused write: $(last_anon READ)"
grep -q "\[SIM\] SET $RPM_NODE = $ROGUE_VALUE" "$SIM_SEC_LOG" \
  && fail "X2 the sim witnessed the rogue value - the write was not actually refused"
echo "[GATE] X2+X3 OK: read Good, write Bad_UserAccessDenied, value unchanged"

# ---------------------------------------------------------------------------
echo "[GATE] ===== X4: an untrusted certificate never writes ====="
kill_by_jvmarg "heimdall.gate=X1"
sleep 3
start_edge X4 "$EDGE_BAD_LOG" "$(cygpath -m "$(pwd)/$PKI_BAD")" 9091 \
  || fail "X4 the untrusted edge did not reach ready (it must start, then be refused by the server)"
# THE assertion for the identity validator. Without it, X4 proves only what X2 already proves —
# that the write filter denies the write — because the filter stops this edge even when the server
# has accepted its certificate. Bad_IdentityTokenRejected is the server refusing at the IDENTITY
# layer, by name, and it is the only thing here that tests the thumbprint predicate.
wait_line "$EDGE_BAD_LOG" "Bad_IdentityTokenRejected" 15 \
  || fail "X4 the server did not reject the untrusted certificate - it was accepted, and only the write filter stopped it"
BEFORE="$(apply_count "$RPM_NODE" "$EDGE_BAD_LOG")"
pub "$RPM_NODE" "$X4_VALUE"
sleep 12
[ "$(apply_count "$RPM_NODE" "$EDGE_BAD_LOG")" = "$BEFORE" ] \
  || fail "X4 an edge with an untrusted certificate APPLIED a command"
grep -q "\[SIM\] SET $RPM_NODE = $X4_VALUE" "$SIM_SEC_LOG" \
  && fail "X4 the sim witnessed a value from the untrusted edge"
echo "[GATE] X4 OK: certificate rejected at the identity layer, and nothing applied"

echo ""
echo "[GATE] PASS run-write-exclusivity-gate.sh"
exit 0
