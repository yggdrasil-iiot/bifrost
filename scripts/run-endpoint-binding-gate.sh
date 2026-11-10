#!/usr/bin/env bash
# ENDPOINT GATE (G5, mapping contract 2.26.0 endpointRef): a command link names the OPC UA server it may
# call, and Heimdall calls no other - not even one its trust list accepts.
#
# Live: HiveMQ CE, two OPC-UA sims that both require the edge's identity - sim A on 48400 and sim B on
# 48401, each with a certificate minted at its start and both certificates in the edge's trust list - and
# Heimdall, restarted against one sim or the other. Releases are published with this repository's CLI from
# the vor-read fixture, re-pinned to the live certificates by scripts/pin-server-certificate.py.
#
#   G5 publish     : a link whose thumbprint is not its certificate's SHA-1, and one whose applicationUri is
#                    not its certificate's subjectAltName URI, are refused command-binding.endpoint at
#                    mapping approve; no head is written
#   G5a pass       : release 1.0.0 names sim A; an approved proposal is applied on sim A, and approve's
#                    report names sim A's thumbprint
#   G5b not named  : Heimdall pointed at sim B - trusted, but not the link's server - refuses
#                    command.link.endpoint before the reservation; sim B's Method is not called
#   G5c 2.25.0     : release 1.0.1 is the bundle as contract 2.25.0 wrote it; approve refuses
#                    command.link.endpoint (missing), and so does the edge once the proposal is co-signed past
#                    approve; no Method is called
#   G5d overlap    : release 1.0.2 lists sim A's and sim B's certificates; a proposal is applied on B, and
#                    after a restart against A, another is applied on A
#   G5e removal    : release 1.0.3 lists sim B's only; against A, refused command.link.endpoint
#   G5f untrusted  : (G1 kept) against sim B, which release 1.0.3 names, with a trust list holding only sim
#                    A's certificate: no Method is called and sim B's certificate lands in rejected/
#
# A reconnect to another server between Heimdall's two comparisons cannot be scripted deterministically; the
# unit test NcmdBridgeMethodTest.aReconnectToAnotherServerBeforeTheCallIsRefusedAndConsumesTheCmdId covers it.
#
# Negative control (a code injection, run by hand and reverted - no switch in Heimdall can weaken it): in
# NcmdOpcUaBridge.handleMethod replace both endpoint.refusal(...) calls with null, rebuild
# heimdall/target/bifrost-heimdall.jar, and run this gate: G5b fails because sim B's Method is called.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 48400, 48401 free):
#   timeout 900 bash scripts/run-endpoint-binding-gate.sh
#   # expect: [GATE] PASS run-endpoint-binding-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
PKI="$WORK/eg-pki"
EDGE_PKI="$WORK/eg-edge-pki"
TRUST="$WORK/eg-server-trust"
TRUST_A="$WORK/eg-server-trust-a"
CERT_A="$WORK/eg-sim-a.der"
CERT_B="$WORK/eg-sim-b.der"
REG="$WORK/eg-reg"
LED="$WORK/eg-ledger"
PROP="$WORK/eg-proposals"
SIM_A_LOG="$WORK/eg-sim-a.log"
SIM_B_LOG="$WORK/eg-sim-b.log"
EDGE_LOG="$WORK/eg-edge.log"
CLI_LOG="$WORK/eg-cli.log"
: > "$CLI_LOG"

GROUP="Bifrost:Line1"
EDGE="recipe-edge-cmd"
URL_A="opc.tcp://localhost:48400"
URL_B="opc.tcp://localhost:48401"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_A_LOG" "$SIM_B_LOG" "$EDGE_LOG" "$CLI_LOG"; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -25 "$f"; } || true
  done
  exit 1
}

kill_by_jvmarg() { { jps -v 2>/dev/null | grep -F "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true; done; }
kill_by_mainclass() { { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true; done; }

cleanup() {
  kill_by_jvmarg "heimdall.gate=" || true
  kill_by_mainclass "bifrost-sim.jar" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ] \
   || [ ! -f gates/target/bifrost-gates.jar ]; then
  mvn -q -pl core,heimdall,sim,gates install -DskipTests
fi
H="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
S="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
G="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$G" "$@" >>"$CLI_LOG" 2>&1; }
fixture() { java -cp "$G" yggdrasil.bifrost.gates.ProposalFixture "$@" 2>>"$CLI_LOG"; }

echo "[GATE] step 1: keys, grants and an edge policy rule for Mixer1's Method"
rm -rf "$PKI" "$REG" "$LED" "$PROP"; mkdir -p "$PKI" "$REG/identity" "$PROP"
cp -r heimdall/registry/* "$REG/"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"
REG_WIN="$(cygpath -m "$(pwd)/$REG")"
: > "$REG/identity/authorized-keys.jsonl"
for who in proposer approver agent operator; do
  java -cp "$G" yggdrasil.bifrost.gates.IdentityGate keygen "$who" --out "$PKI_WIN" 2>/dev/null | head -1 \
    >> "$REG/identity/authorized-keys.jsonl"
done
[ "$(wc -l < "$REG/identity/authorized-keys.jsonl" | tr -d ' ')" = "4" ] || fail "expected four registered keys"
cat > "$REG/identity/activation-policy.json" <<'JSON'
{"version":"1.0.0","default":"deny","rules":[
 {"id":"publish-line1","principal":"proposer","action":"publish","target":"mapping-publication","kind":"mapping-release","ref":"line1"},
 {"id":"approve-line1","principal":"approver","action":"approve","target":"mapping-publication","kind":"mapping-release","ref":"line1"},
 {"id":"agent-proposes","principal":"agent","action":"propose_command","target":"command","kind":"method","ref":"line1"},
 {"id":"operator-co-signs","principal":"operator","action":"approve_command","target":"command","kind":"method","ref":"line1"}]}
JSON
python - "$REG/policy.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["rules"].append({"id": "set-temperature", "principal": "agent",
                   "target": {"group": "Bifrost:Line1", "edge": "recipe-edge-cmd", "device": "synthetic-site:line1:mixer1"},
                   "command": "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature",
                   "constraint": {"type": "Double", "min": 0.0, "max": 100.0}})
json.dump(d, open(p, "w"), indent=2)
PY
SIGNERS=(--by proposer --by-key "$PKI_WIN/proposer.key" --approved-by approver --approved-by-key "$PKI_WIN/approver.key")

export MQTT_URL="tcp://localhost:1883"
export SPB_GROUP="$GROUP"
export SPB_EDGE="$EDGE"
export REGISTRY_PATH="$REG_WIN"
export POLICY_PATH="$REG_WIN/policy.json"
export COMMAND_LEDGER_PATH="$(cygpath -m "$(pwd)/$LED")"
export HEIMDALL_IDENTITY_DIR="$(cygpath -m "$(pwd)/$EDGE_PKI")"
export HEALTH_PORT=0

echo "[GATE] step 2: the edge identity, HiveMQ CE, and two sims trusting only that identity"
rm -rf "$EDGE_PKI" "$TRUST" "$TRUST_A" "$CERT_A" "$CERT_B"
THUMB="$(java -cp "$H" yggdrasil.bifrost.heimdall.EdgeIdentity --print-thumbprint "$HEIMDALL_IDENTITY_DIR" \
    "urn:bifrost:heimdall:Bifrost-Line1:$EDGE" 2>/dev/null | tr -d '\r')"
[ -n "$THUMB" ] || fail "could not mint the edge identity"
broker_boots() { docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true; }
wait_broker() { for _ in $(seq 1 45); do [ "$(broker_boots)" -gt "$1" ] && return 0; sleep 2; done; return 1; }
B0="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$B0" || fail "HiveMQ CE never reported 'Started HiveMQ'"
wait_line() { for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
# start_sim <log> <port> <cert out>
start_sim() {
  : > "$1"
  SIM_BIND_PORT="$2" SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$THUMB" SIM_SERVER_CERT_OUT="$(cygpath -m "$(pwd)/$3")" \
    java -jar "$S" >"$1" 2>&1 &
  wait_line "$1" "OPC-UA sim listening" 30
}
start_sim "$SIM_A_LOG" 48400 "$CERT_A" || fail "sim A did not start"
start_sim "$SIM_B_LOG" 48401 "$CERT_B" || fail "sim B did not start"
{ [ -s "$CERT_A" ] && [ -s "$CERT_B" ]; } || fail "a sim did not export its server certificate"
! cmp -s "$CERT_A" "$CERT_B" || fail "the two sims present one certificate"
# Both servers are trusted: trust alone cannot tell the edge which one a command may reach.
mkdir -p "$TRUST/trusted/certs" "$TRUST_A/trusted/certs"
cp "$CERT_A" "$TRUST/trusted/certs/sim-a.der"
cp "$CERT_B" "$TRUST/trusted/certs/sim-b.der"
cp "$CERT_A" "$TRUST_A/trusted/certs/sim-a.der"
sha1() { python -c "import hashlib,sys;print(hashlib.sha1(open(sys.argv[1],'rb').read()).hexdigest())" "$1"; }
THUMB_A="$(sha1 "$CERT_A")"; THUMB_B="$(sha1 "$CERT_B")"

# release <version> <pin args...>: the fixture re-pinned, rebased on the current head after the first, published.
release() {
  local v="$1"; shift
  local b="$WORK/eg-bundle-$v" r="$WORK/eg-rebased-$v"
  rm -rf "$b" "$r"; cp -r core/src/test/resources/mapping-fixtures/vor-read "$b"
  python scripts/pin-server-certificate.py "$b" "$@" >>"$CLI_LOG" || fail "could not pin release $v"
  if [ -e "$REG/mappings/heads/line1.json" ]; then
    fixture rebase "$(cygpath -m "$(pwd)/$b")" "$REG_WIN" "$(cygpath -m "$(pwd)/$r")" "vor-read-$v" || fail "rebase $v failed"
  else
    cp -r "$b" "$r"
  fi
  gates mapping approve "$REG_WIN" "$(cygpath -m "$(pwd)/$r")" "approval-$v" "${SIGNERS[@]}" || return 1
  gates mapping publish "$REG_WIN" "$(cygpath -m "$(pwd)/$r")" vor-read "$v" --approval "approval-$v" "${SIGNERS[@]}" || return 1
  grep -q "\"version\":\"$v\"" "$REG/mappings/heads/line1.json" || fail "release $v did not move the head"
}

READY=0
# start_edge <tag> <url> <trust dir>: the ledger survives restarts; each start is a fresh OPC UA session.
start_edge() {
  kill_by_jvmarg "heimdall.gate=" || true
  sleep 3
  READY=$((READY + 1))
  OPCUA_URL="$2" HEIMDALL_SERVER_TRUST_DIR="$(cygpath -m "$(pwd)/$3")" java "-Dheimdall.gate=$1" -jar "$H" >>"$EDGE_LOG" 2>&1 &
  for _ in $(seq 1 45); do [ "$(grep -c "\[BRIDGE\] ready" "$EDGE_LOG" 2>/dev/null || true)" -ge "$READY" ] && return 0; sleep 2; done
  return 1
}
iso() { date -u -d "@$(( $(date +%s) + $1 ))" +%Y-%m-%dT%H:%M:%SZ; }
propose() {
  fixture propose "$REG_WIN" "$(cygpath -m "$(pwd)/$PROP/$1.json")" --by agent --by-key "$PKI_WIN/agent.key" \
    --approved-by operator --value "$2" --not-before "$(iso -60)" --not-after "$(iso 600)" | tr -d '\r'
}
approve() {
  gates command approve "$REG_WIN" "$(cygpath -m "$(pwd)/$PROP/$1.json")" --approved-by operator \
    --approved-by-key "$PKI_WIN/operator.key" --policy "$REG_WIN/policy.json" \
    --out "$(cygpath -m "$(pwd)/$PROP/$1.approved.json")"
}
cosign() {
  fixture cosign "$(cygpath -m "$(pwd)/$PROP/$1.json")" "$(cygpath -m "$(pwd)/$PROP/$1.approved.json")" \
    --by operator --by-key "$PKI_WIN/operator.key"
}
publish() { gates command publish "$(cygpath -m "$(pwd)/$PROP/$1.json")" --broker "$MQTT_URL"; }
count_in() { grep -cF -- "$1" "$2" 2>/dev/null || true; }
# transfers <value> <sim log>
transfers() { count_in "[SIM] transfer Line1/Mixer1.Temp = $1" "$2"; }
applied() { wait_line "$EDGE_LOG" "METHOD cmdId=$1 .* ok=true" 20; }
denied() { wait_line "$EDGE_LOG" "DENY cmd=bifrost/command/v1 cmdId=$1 reason=$2" 20; }
since() { tail -n +"$(( $1 + 1 ))" "$CLI_LOG"; }

# applies <leg> <value> <sim log>: proposed, approved, delivered, applied on that sim only
applies() {
  local c; c="$(propose "$1" "$2")"; [ -n "$c" ] || fail "$1 no proposal"
  approve "$1" || fail "$1 approval refused"
  publish "$1.approved" || fail "$1 publish failed"
  applied "$c" || fail "$1 the Method was not applied"
  [ "$(transfers "$2" "$3")" = "1" ] || fail "$1 the sim did not transfer Line1/Mixer1.Temp = $2 exactly once"
}
# refused_at_edge <leg> <value> <detail>: approved, delivered, refused command.link.endpoint (<detail>) by the edge
# before the reservation; neither sim is called
refused_at_edge() {
  local c; c="$(propose "$1" "$2")"; [ -n "$c" ] || fail "$1 no proposal"
  approve "$1" || fail "$1 approval refused"
  publish "$1.approved" || fail "$1 publish failed"
  denied "$c" "command.link.endpoint" || fail "$1 the edge did not refuse command.link.endpoint"
  grep -F "cmdId=$c reason=command.link.endpoint ($3" "$EDGE_LOG" | grep -vq "after reservation" \
    || fail "$1 the refusal was not '$3' before the reservation"
  sleep 2
  { [ "$(transfers "$2" "$SIM_A_LOG")" = "0" ] && [ "$(transfers "$2" "$SIM_B_LOG")" = "0" ]; } || fail "$1 a sim's Method was called"
  ! grep "\"cmdId\":\"$c\"" "$LED"/commands/Bifrost-Line1/"$EDGE"/*.jsonl | grep -q '"outcome":"reserved"' \
    || fail "$1 the refused cmdId was reserved"
}

: > "$EDGE_LOG"

# ---------------------------------------------------------------------------
echo "[GATE] ===== G5 publish: what a link says about its certificate is re-derived ====="
N="$(wc -l < "$CLI_LOG")"
! release 1.0.0 "$CERT_A" --thumbprint 0000000000000000000000000000000000000000 || fail "G5 publish: a wrong thumbprint was published"
since "$N" | grep -q "command-binding.endpoint" || fail "G5 publish: a wrong thumbprint was not refused command-binding.endpoint"
N="$(wc -l < "$CLI_LOG")"
! release 1.0.0 "$CERT_A" --application-uri urn:bifrost:opcua:other-server || fail "G5 publish: a wrong applicationUri was published"
since "$N" | grep -q "command-binding.endpoint" || fail "G5 publish: a wrong applicationUri was not refused command-binding.endpoint"
[ ! -e "$REG/mappings/heads/line1.json" ] || fail "G5 publish: a head exists after the refusals"
echo "[GATE] G5 publish OK: wrong thumbprint and wrong applicationUri refused command-binding.endpoint"

echo "[GATE] ===== G5a: the link's server ====="
release 1.0.0 "$CERT_A" || fail "release 1.0.0 failed"
start_edge A "$URL_A" "$TRUST" || fail "Heimdall did not start against sim A"
grep -q "OPC-UA server trust list .* (2 trusted certificate" "$EDGE_LOG" || fail "Heimdall did not load the two-entry trust list"
N="$(wc -l < "$CLI_LOG")"
applies g5a 61.0 "$SIM_A_LOG"
since "$N" | grep -q "\"thumbprintsSha1\":\[\"$THUMB_A\"\]" || fail "G5a approve's report does not name sim A's certificate"
echo "[GATE] G5a OK: applied on sim A; approve reports sim A's thumbprint"

echo "[GATE] ===== G5b: a trusted server the link does not name ====="
start_edge B "$URL_B" "$TRUST" || fail "Heimdall did not start against sim B"
refused_at_edge g5b 62.0 "certificate $THUMB_B"
echo "[GATE] G5b OK: sim B is trusted and refused command.link.endpoint; no Method called"

echo "[GATE] ===== G5c: a 2.25.0 link names no server ====="
release 1.0.1 --legacy || fail "release 1.0.1 (2.25.0) failed"
CC="$(propose g5c 63.0)"; [ -n "$CC" ] || fail "G5c no proposal"
N="$(wc -l < "$CLI_LOG")"
! approve g5c || fail "G5c approve accepted a 2.25.0 link"
since "$N" | grep -q '"error":"command.link.endpoint"' || fail "G5c approve did not refuse command.link.endpoint"
since "$N" | grep -q '"detail":"missing"' || fail "G5c approve did not name missing"
cosign g5c || fail "G5c co-sign failed"
publish g5c.approved || fail "G5c publish failed"
denied "$CC" command.link.endpoint || fail "G5c the edge did not refuse command.link.endpoint"
grep -qF "cmdId=$CC reason=command.link.endpoint (missing)" "$EDGE_LOG" || fail "G5c the edge did not name missing"
sleep 2
{ [ "$(transfers 63.0 "$SIM_A_LOG")" = "0" ] && [ "$(transfers 63.0 "$SIM_B_LOG")" = "0" ]; } || fail "G5c a sim's Method was called"
echo "[GATE] G5c OK: refused command.link.endpoint (missing) by approve and by the edge"

echo "[GATE] ===== G5d: a rotation overlap lists both certificates ====="
release 1.0.2 "$CERT_A" "$CERT_B" || fail "release 1.0.2 failed"
applies g5d-b 64.0 "$SIM_B_LOG"
start_edge A2 "$URL_A" "$TRUST" || fail "Heimdall did not restart against sim A"
applies g5d-a 65.0 "$SIM_A_LOG"
echo "[GATE] G5d OK: applied on sim B, then on sim A"

echo "[GATE] ===== G5e: the predecessor removed ====="
release 1.0.3 "$CERT_B" || fail "release 1.0.3 failed"
refused_at_edge g5e 66.0 "certificate $THUMB_A"
echo "[GATE] G5e OK: sim A is no longer the link's server: refused command.link.endpoint"

echo "[GATE] ===== G5f: the link's server, untrusted ====="
start_edge F "$URL_B" "$TRUST_A" || fail "Heimdall did not start with sim A's trust list"
CF="$(propose g5f 67.0)"; [ -n "$CF" ] || fail "G5f no proposal"
approve g5f || fail "G5f approval refused"
publish g5f.approved || fail "G5f publish failed"
wait_line "$EDGE_LOG" "cmdId=$CF" 30 || fail "G5f Heimdall never answered the proposal"
sleep 3
[ "$(transfers 67.0 "$SIM_B_LOG")" = "0" ] || fail "G5f sim B's Method was called through an untrusted channel"
! grep -q "METHOD cmdId=$CF .* ok=true" "$EDGE_LOG" || fail "G5f Heimdall reports the Method applied"
[ -n "$(ls "$TRUST_A/rejected" 2>/dev/null)" ] || fail "G5f sim B's certificate was not quarantined in rejected/"
echo "[GATE] G5f OK: the link names sim B, the trust list does not: no Method called, sim B's certificate in rejected/"

echo ""
echo "[GATE] PASS run-endpoint-binding-gate.sh (G5 publish, G5a-f)"
exit 0
