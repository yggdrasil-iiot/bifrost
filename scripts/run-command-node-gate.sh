#!/usr/bin/env bash
# COMMAND NODE GATE (G4, stage A): Heimdall is its own Sparkplug edge node, the command edge, and the
# data edge is left to Muninn. Live: HiveMQ CE and the OPC-UA sim requiring the edge's identity, so a
# governed write only lands through Heimdall's own certificate.
#
#   N1 birth           : NBIRTH on spBv1.0/<group>/NBIRTH/<command-edge>, seq 0, declaring exactly
#                        bdSeq, Node Control/Rebirth and bifrost/command/v1; not retained
#   N2 rebirth         : an NCMD Node Control/Rebirth=true yields a second NBIRTH, seq 0, SAME bdSeq,
#                        and no answer on RESULT
#   N3 signed setpoint : a signed setpoint on the command edge applies, answered on
#                        bifrost/<group>/RESULT/<command-edge> under its cmdId
#   N4 malformed       : a two-metric payload and a Rebirth mixed with a command are each refused
#                        command.malformed and answered; nothing is written and no NBIRTH follows
#   N5 data edge       : a watcher on spBv1.0/<group>/+/<data-edge> sees nothing at all
#   N6 no STATUS       : a watcher on bifrost/<group>/STATUS/# sees nothing (no retained liveness)
#   N7 death           : taskkill //F (no shutdown hook) -> the broker publishes the NDEATH Will
#                        carrying the live bdSeq
#   N8 rapid restart   : kill and restart at once -> the new NBIRTH carries bdSeq+1, the old session's
#                        NDEATH carries the old number, and no NDEATH names the new one
#   N9 URI mismatch    : renamed edge over the existing certificate, no override -> refused at start
#                        identity.uri.mismatch, no MQTT CONNECT, no OPC-UA connect, certificate unchanged
#   N10 override, none : HEIMDALL_APPLICATION_URI over an empty identity directory -> refused
#                        identity.uri.override-without-certificate, no certificate written
#   N11 rename+override: renamed edge with the override set to the certificate's URI -> same thumbprint,
#                        a governed write applies with the server's trust unchanged, NBIRTH on the new
#                        edge with its own bdSeq counter
#
# Run from the bifrost repo root (Docker Desktop, host ports 1883 and 48400 free):
#   timeout 900 bash scripts/run-command-node-gate.sh
#   # expect: [GATE] PASS run-command-node-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/command-node-gate"
rm -rf "$WORK"; mkdir -p "$WORK"
REG="$WORK/reg"
PKI="$WORK/keys"
EDGE_PKI="$WORK/edge-identity"
EMPTY_PKI="$WORK/empty-identity"
TRUST="$WORK/server-trust"
LED="$WORK/command-ledger"
SIM_LOG="$WORK/sim.log"
PUB_LOG="$WORK/pub.log"
SPB_LOG="$WORK/watch-command-edge.log"
REN_LOG="$WORK/watch-renamed-edge.log"
DATA_LOG="$WORK/watch-data-edge.log"
RESULT_LOG="$WORK/watch-result.log"
STATUS_LOG="$WORK/watch-status.log"
: > "$PUB_LOG"

GROUP="Bifrost:Line1"
CMD_EDGE="recipe-edge-cmd"
DATA_EDGE="recipe-edge"
RENAMED="recipe-edge-cmd2"
CMD_URI="urn:bifrost:heimdall:Bifrost-Line1:$CMD_EDGE"
RPM="ns=2;s=Recipe/Rpm"
TEMP="ns=2;s=Recipe/Temp"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$PUB_LOG" "$SPB_LOG" "$REN_LOG" "$DATA_LOG" "$STATUS_LOG" "$WORK"/edge-*.log; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -30 "$f"; } || true
  done
  exit 1
}

kill_by_jvmarg() { { jps -v 2>/dev/null | grep -F "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || kill -9 "$p" >/dev/null 2>&1 || true; done; }
kill_by_mainclass() { { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || kill -9 "$p" >/dev/null 2>&1 || true; done; }

cleanup() {
  kill_by_jvmarg "heimdall.gate=" || true
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "TopicWatcher" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT
kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "TopicWatcher" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ] \
   || [ ! -f gates/target/bifrost-gates.jar ]; then
  mvn -q -pl core,heimdall,sim,gates install -DskipTests
fi
H="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
S="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
G="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"

# ---------------------------------------------------------------------------
echo "[GATE] step 1: a registry whose policy names the command edges, a signing key, the edge identity"
mkdir -p "$REG/identity" "$PKI"
cp -r heimdall/registry/* "$REG/"
sed 's/"edge": "recipe-edge"/"edge": "recipe-edge-cmd"/' heimdall/registry/policy.json > "$REG/policy.json"
sed 's/"edge": "recipe-edge"/"edge": "recipe-edge-cmd2"/' heimdall/registry/policy.json > "$REG/policy-renamed.json"
grep -q "\"edge\": \"$CMD_EDGE\"" "$REG/policy.json" || fail "could not derive the command-edge policy"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"
java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen recipe-writer --out "$PKI_WIN" 2>/dev/null | head -1 \
  > "$REG/identity/authorized-keys.jsonl"
[ -s "$REG/identity/authorized-keys.jsonl" ] || fail "could not register recipe-writer"
THUMB="$(java -cp "$H" dev.krillin.bifrost.heimdall.EdgeIdentity --print-thumbprint \
    "$(cygpath -m "$(pwd)/$EDGE_PKI")" "$CMD_URI" 2>/dev/null | tr -d '\r')"
[ -n "$THUMB" ] || fail "could not mint the edge identity"
echo "[GATE] edge identity $THUMB ($CMD_URI)"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/$REG")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/$REG/conformance/Line1-Mixer/1.0.0.json")"
export COMMAND_LEDGER_PATH="$(cygpath -m "$(pwd)/$LED")"
export HEIMDALL_SERVER_TRUST_DIR="$(cygpath -m "$(pwd)/$TRUST")"
export REQUIRE_SIGNED_COMMAND=on
export HEALTH_PORT=0
unset HEIMDALL_APPLICATION_URI HEIMDALL_IDENTITY_DIR SPB_EDGE POLICY_PATH || true

broker_boots() { docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true; }
wait_broker() { for _ in $(seq 1 45); do [ "$(broker_boots)" -gt "$1" ] && return 0; sleep 2; done; return 1; }

echo "[GATE] step 2: HiveMQ CE and the sim trusting only the edge identity"
B0="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$B0" || fail "HiveMQ CE never reported 'Started HiveMQ'"
mkdir -p "$TRUST/trusted/certs"
: > "$SIM_LOG"
SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$THUMB" \
SIM_SERVER_CERT_OUT="$(cygpath -m "$(pwd)/$TRUST/trusted/certs/sim-server.der")" \
  java -jar "$S" >"$SIM_LOG" 2>&1 &
for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && break; sleep 2; done
grep -q "OPC-UA sim listening" "$SIM_LOG" || fail "the sim did not start"
[ -s "$TRUST/trusted/certs/sim-server.der" ] || fail "the sim did not export its server certificate"

wait_line() { for _ in $(seq 1 "$3"); do grep -qE -- "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
count_in()  { grep -cE -- "$1" "$2" 2>/dev/null || true; }

# $1 = tag, $2 = edge, $3 = policy file, [$4 = override URI], [$5 = identity dir]
edge_env() {
  local vars=(SPB_EDGE="$2" POLICY_PATH="$(cygpath -m "$(pwd)/$REG/$3")"
              HEIMDALL_IDENTITY_DIR="$(cygpath -m "$(pwd)/${5:-$EDGE_PKI}")")
  [ -n "$4" ] && vars+=(HEIMDALL_APPLICATION_URI="$4")
  env "${vars[@]}" "${@:6}"
}
start_edge() {  # $1 tag $2 edge $3 policy [$4 override]
  local log="$WORK/edge-$1.log"; : > "$log"
  edge_env "$1" "$2" "$3" "${4:-}" "" java "-Dheimdall.gate=$1" -jar "$H" >"$log" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$log" 2>/dev/null && return 0; sleep 2; done
  return 1
}
# A start that must be refused: foreground, bounded, and its exit code returned.
refused_start() {  # $1 tag $2 edge $3 policy $4 override $5 identity dir
  local log="$WORK/edge-$1.log"; : > "$log"
  set +e
  edge_env "$1" "$2" "$3" "$4" "$5" timeout 90 java "-Dheimdall.gate=$1" -jar "$H" >"$log" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}
pub() {  # $1 edge, then RogueNcmd arguments
  SPB_EDGE="$1" java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "${@:2}" >>"$PUB_LOG" 2>&1
}
signed() {  # $1 edge $2 node $3 value $4 cmdId [extra RogueNcmd arguments]
  pub "$1" "$2" "$3" Double --sign recipe-writer "$PKI_WIN/recipe-writer.key" --cmd-id "$4" "${@:5}"
}
births() { count_in "^\[WATCH\] spBv1.0/$GROUP/NBIRTH/$1 retained=false seq=0 metrics=\[bdSeq:Int64=$2, Node Control/Rebirth:Boolean=false, bifrost/command/v1:String=\]$" "$3"; }
deaths() { count_in "^\[WATCH\] spBv1.0/$GROUP/NDEATH/$1 retained=false seq=- metrics=\[bdSeq:Int64=$2\]$" "$3"; }
applies() { count_in "\[BRIDGE\] APPLY cmd=$RPM ok=true" "$1"; }
result_has() { for _ in $(seq 1 10); do tr -d '\r\n' < "$RESULT_LOG" | grep -aq -- "$1" && return 0; sleep 2; done; return 1; }

watch() {  # $1 log, then TopicWatcher arguments
  : > "$1"
  java -cp "$H" dev.krillin.bifrost.heimdall.TopicWatcher "${@:2}" >"$1" 2>&1 &
  wait_line "$1" "\[WATCH\] subscribed" 15 || fail "the watcher for ${*: -2:1} did not subscribe"
}
watch "$SPB_LOG" --sparkplug "spBv1.0/$GROUP/+/$CMD_EDGE" 900
watch "$REN_LOG" --sparkplug "spBv1.0/$GROUP/+/$RENAMED" 900
watch "$DATA_LOG" --sparkplug "spBv1.0/$GROUP/+/$DATA_EDGE" 900
watch "$RESULT_LOG" "bifrost/$GROUP/RESULT/$CMD_EDGE" 900
watch "$STATUS_LOG" "bifrost/$GROUP/STATUS/#" 900

# ---------------------------------------------------------------------------
echo "[GATE] ===== N1: the command node births ====="
start_edge A "$CMD_EDGE" policy.json || fail "N1 Heimdall did not start"
A_LOG="$WORK/edge-A.log"
grep -q "OPC-UA identity $THUMB ($CMD_URI)" "$A_LOG" || fail "N1 Heimdall is not presenting the derived identity"
for _ in $(seq 1 10); do [ "$(births "$CMD_EDGE" 0 "$SPB_LOG")" -ge 1 ] && break; sleep 1; done
[ "$(births "$CMD_EDGE" 0 "$SPB_LOG")" = "1" ] || fail "N1 no NBIRTH seq=0 bdSeq=0 declaring exactly the three metrics"
echo "[GATE] N1 OK: NBIRTH seq=0 bdSeq=0 with bdSeq, Node Control/Rebirth, bifrost/command/v1, not retained"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N2: Rebirth ====="
pub "$CMD_EDGE" "Node Control/Rebirth" true Boolean --cmd-id g4-rebirth
for _ in $(seq 1 10); do [ "$(births "$CMD_EDGE" 0 "$SPB_LOG")" -ge 2 ] && break; sleep 1; done
[ "$(births "$CMD_EDGE" 0 "$SPB_LOG")" = "2" ] || fail "N2 a Rebirth did not yield exactly one more NBIRTH with the same bdSeq"
echo "[GATE] N2 OK: a second NBIRTH, seq=0, the same bdSeq"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N3: a signed setpoint on the command edge ====="
signed "$CMD_EDGE" "$RPM" 1500.0 g4-setpoint
wait_line "$A_LOG" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "N3 the signed setpoint was not applied"
result_has "g4-setpoint" || fail "N3 no RESULT answer under the command edge for cmdId g4-setpoint"
echo "[GATE] N3 OK: applied through the identity-gated sim and answered on RESULT/$CMD_EDGE"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N4: one command per payload ====="
APPLIED="$(applies "$A_LOG")"
signed "$CMD_EDGE" "$RPM" 1600.0 g4-two --extra "$TEMP" Double 80.0
wait_line "$A_LOG" "\[BRIDGE\] MALFORMED cmdId=g4-two \(more than one metric\)" 15 \
  || fail "N4 a two-metric payload was not refused command.malformed"
pub "$CMD_EDGE" "Node Control/Rebirth" true Boolean --cmd-id g4-mixed --extra "$RPM" Double 1600.0
wait_line "$A_LOG" "\[BRIDGE\] MALFORMED cmdId=g4-mixed \(more than one metric\)" 15 \
  || fail "N4 a Rebirth mixed with a command was not refused command.malformed"
result_has "g4-two" || fail "N4 the two-metric refusal was not answered"
result_has "g4-mixed" || fail "N4 the mixed refusal was not answered"
[ "$(applies "$A_LOG")" = "$APPLIED" ] || fail "N4 a refused payload was applied"
! grep -q "\[SIM\] .*1600" "$SIM_LOG" || fail "N4 the sim saw 1600 from a refused payload"
[ "$(births "$CMD_EDGE" 0 "$SPB_LOG")" = "2" ] || fail "N4 the mixed payload triggered a rebirth"
# The Rebirth of N2 was answered by nothing: its RESULT would precede the answers above.
! tr -d '\r\n' < "$RESULT_LOG" | grep -aq "g4-rebirth" || fail "N2 the Rebirth was answered on RESULT"
echo "[GATE] N4 OK: both refused command.malformed and answered, nothing written, no rebirth; N2 unanswered"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N5 + N6: nothing on the data edge, no STATUS ====="
! grep -aq "^\[WATCH\] spBv1.0/" "$DATA_LOG" || fail "N5 Heimdall published on the data edge's Sparkplug topics"
! grep -aq "^\[WATCH\] bifrost/" "$STATUS_LOG" || fail "N6 a STATUS message exists"
echo "[GATE] N5 + N6 OK: the data edge is silent and no STATUS topic carries anything"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N7: the broker announces a hard kill with the live bdSeq ====="
kill_by_jvmarg "heimdall.gate=A"
wait_line "$SPB_LOG" "NDEATH/$CMD_EDGE retained=false seq=- metrics=\[bdSeq:Int64=0\]" 45 \
  || fail "N7 no NDEATH Will with bdSeq=0 after the kill"
echo "[GATE] N7 OK: NDEATH bdSeq=0 from the Will"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N8: a rapid restart is not killed by the earlier Will ====="
start_edge B "$CMD_EDGE" policy.json || fail "N8 Heimdall B did not start"
for _ in $(seq 1 10); do [ "$(births "$CMD_EDGE" 1 "$SPB_LOG")" -ge 1 ] && break; sleep 1; done
[ "$(births "$CMD_EDGE" 1 "$SPB_LOG")" = "1" ] || fail "N8 the restart did not birth with bdSeq=1"
kill_by_jvmarg "heimdall.gate=B"
start_edge C "$CMD_EDGE" policy.json || fail "N8 Heimdall C did not start"
for _ in $(seq 1 10); do [ "$(births "$CMD_EDGE" 2 "$SPB_LOG")" -ge 1 ] && break; sleep 1; done
[ "$(births "$CMD_EDGE" 2 "$SPB_LOG")" = "1" ] || fail "N8 the rapid restart did not birth with bdSeq=2"
wait_line "$SPB_LOG" "NDEATH/$CMD_EDGE retained=false seq=- metrics=\[bdSeq:Int64=1\]" 45 \
  || fail "N8 the killed session's NDEATH did not carry its own bdSeq=1"
sleep 5
[ "$(deaths "$CMD_EDGE" 2 "$SPB_LOG")" = "0" ] || fail "N8 an NDEATH names the live bdSeq=2"
signed "$CMD_EDGE" "$RPM" 1500.0 g4-after-restart
wait_line "$WORK/edge-C.log" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "N8 the restarted node did not apply"
echo "[GATE] N8 OK: NBIRTH bdSeq=2 lives on; the stale NDEATH carries bdSeq=1"
kill_by_jvmarg "heimdall.gate=C"
sleep 3

# ---------------------------------------------------------------------------
echo "[GATE] ===== N9: a renamed edge over the existing certificate is refused at start ====="
RC="$(refused_start N9 "$RENAMED" policy-renamed.json "" "$EDGE_PKI")"
N9_LOG="$WORK/edge-N9.log"
[ "$RC" != "0" ] && [ "$RC" != "124" ] || fail "N9 Heimdall did not exit refused (rc=$RC)"
grep -q "identity.uri.mismatch" "$N9_LOG" || fail "N9 no identity.uri.mismatch"
! grep -qE "NBIRTH|subscribed NCMD|OPC-UA connected|OPC-UA not reachable" "$N9_LOG" \
  || fail "N9 Heimdall connected before refusing"
[ "$(count_in "^\[WATCH\] spBv1.0/" "$REN_LOG")" = "0" ] || fail "N9 something was published on the renamed edge"
[ "$(java -cp "$H" dev.krillin.bifrost.heimdall.EdgeIdentity show "$(cygpath -m "$(pwd)/$EDGE_PKI")" x 2>/dev/null \
    | tr -d '\r' | grep -o "$THUMB" | head -1)" = "$THUMB" ] || fail "N9 the certificate changed"
echo "[GATE] N9 OK: refused identity.uri.mismatch before any connect; the certificate is unchanged"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N10: the override cannot mint an identity ====="
RC="$(refused_start N10 "$RENAMED" policy-renamed.json "urn:bifrost:heimdall:chosen" "$EMPTY_PKI")"
[ "$RC" != "0" ] && [ "$RC" != "124" ] || fail "N10 Heimdall did not exit refused (rc=$RC)"
grep -q "identity.uri.override-without-certificate" "$WORK/edge-N10.log" || fail "N10 no identity.uri.override-without-certificate"
[ ! -e "$EMPTY_PKI/edge-cert.der" ] || fail "N10 a certificate was written under the override"
echo "[GATE] N10 OK: refused, and no certificate exists"

# ---------------------------------------------------------------------------
echo "[GATE] ===== N11: rename with the override keeps the certificate and the server's trust ====="
start_edge R "$RENAMED" policy-renamed.json "$CMD_URI" || fail "N11 the renamed Heimdall did not start"
R_LOG="$WORK/edge-R.log"
grep -q "OPC-UA identity $THUMB ($CMD_URI)" "$R_LOG" || fail "N11 the thumbprint or URI changed across the rename"
for _ in $(seq 1 10); do [ "$(births "$RENAMED" 0 "$REN_LOG")" -ge 1 ] && break; sleep 1; done
[ "$(births "$RENAMED" 0 "$REN_LOG")" = "1" ] || fail "N11 no NBIRTH bdSeq=0 on the renamed edge"
signed "$RENAMED" "$RPM" 1500.0 g4-renamed
wait_line "$R_LOG" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "N11 the governed write did not apply after the rename"
echo "[GATE] N11 OK: same thumbprint, the identity-gated sim accepts the write, NBIRTH on $RENAMED"

echo ""
echo "[GATE] PASS run-command-node-gate.sh"
exit 0
