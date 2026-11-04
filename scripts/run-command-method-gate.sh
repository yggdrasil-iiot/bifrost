#!/usr/bin/env bash
# METHOD GATE (Vor M2 gate iii): an approved two-signature proposal reaches the plant through Heimdall's
# op=method path once, and only once.
#
# Live: HiveMQ CE, the OPC-UA sim requiring the edge's identity (so only Heimdall's session may call
# Line1/Mixer1.SetTemperature), a running Heimdall with a command ledger, and a mapping registry
# published with this repository's own CLI. Proposals are signed by the agent key through
# gates/ProposalFixture, co-signed with `gates command approve` and delivered with `gates command publish`.
#
#   M1 normal          : 42.0 is applied - the sim transfers Line1/Mixer1.Temp = 42.0, the ledger holds
#                        a reservation and an applied outcome, and the RESULT answer reports the call;
#                        nothing is published on the node's Sparkplug NDATA (Muninn owns that session)
#   M2 replay          : the same envelope again is refused command.replay; the sim is not touched
#   M3 replay+restart  : after Heimdall is killed and restarted, still command.replay - the reservation
#                        was on disk, not in memory
#   M4 window          : an envelope whose notAfter has passed is refused command.window
#   M5 one signature   : the agent's proposal without the co-signature is refused command.signature
#   M6 precondition    : with the sim's Temp StatusCode set Bad, refused command.precondition
#   M7 stale head      : a release published on the stream after approval refuses command.head.mismatch
#   M8 rogue server    : (G1) the sim is replaced at the same URL by one with a fresh certificate that
#                        also trusts the edge's identity, and Heimdall is restarted so its session is new;
#                        it trusts only the first server, so an approved proposal reaches no Method and
#                        the rogue certificate lands in rejected/
#   M9 no identity     : (G1) Heimdall restarted without HEIMDALL_IDENTITY_DIR, against a sim whose
#                        Method anyone may call, refuses command.identity.required; nothing is called
#
# G3 (contract 2.25.0 command binding, proposal v2): the release links each mixer's read binding to that
# mixer's Method, and approve and the edge both resolve the proposal through that link.
#   G3 publish         : a bundle whose Mixer2 link names Mixer1's read binding is refused
#                        command-binding.device-path at mapping approve, and nothing is published
#   G3a own link       : a proposal for synthetic-site:line1:mixer2 with Mixer2's evidence is applied, and
#                        the sim transfers Line1/Mixer2.Temp, not Line1/Mixer1.Temp
#   G3b cross-equipment: Mixer1's evidence on Mixer2's Method is refused command.link.mismatch
#                        (binding.source) by approve and - co-signed past approve - by the edge
#   G3c v1 statement   : a command-proposal/v1 predicate is refused command.malformed, by both
#   G3d object path    : device Line1/Mixer1 is no device of the release: command.link.missing, by both
#   G3e binding digest : a wrong binding.source.sha256 is refused command.link.mismatch, by both
#   No refused proposal reaches either mixer's Method.
#
#   --negative-control : M3 expects the restarted edge to APPLY the replay. The reservation survives, so
#                        that expectation fails and the gate exits non-zero - the M3 assertion can fail.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 48400 free):
#   timeout 900 bash scripts/run-command-method-gate.sh
#   # expect: [GATE] PASS run-command-method-gate.sh ... exit 0
#   timeout 900 bash scripts/run-command-method-gate.sh --negative-control
#   # expect: [GATE] FAIL: NC ... exit 1
#
# G1's negative controls are code injections, run by hand and reverted (no switch in Heimdall can
# weaken it): (NC1) delete the setCertificateValidator line in OpcUaApplier.createGoverned, so Milo's
# default accepts any server - M8 fails because the rogue is called; (NC2) delete the
# command.identity.required check in NcmdOpcUaBridge.handleMethod - M9 fails because the anonymous
# edge calls the Method; (NC3) delete the CommandLink.match line in CommandProposal.link - G3b fails
# because the co-signed cross-equipment proposal calls Mixer2's Method. Rebuild
# heimdall/target/bifrost-heimdall.jar after each injection.
set -euo pipefail
cd "$(dirname "$0")/.."

NC=false
[ "${1:-}" = "--negative-control" ] && NC=true

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
PKI="$WORK/mg-pki"
EDGE_PKI="$WORK/mg-edge-pki"
TRUST="$WORK/mg-server-trust"
SIM_CERT="$WORK/mg-sim-server.der"
ROGUE_CERT="$WORK/mg-rogue-server.der"
ROGUE_LOG="$WORK/mg-rogue.log"
REG="$WORK/mg-reg"
LED="$WORK/mg-ledger"
PROP="$WORK/mg-proposals"
SIM_LOG="$WORK/mg-sim.log"
EDGE_LOG="$WORK/mg-edge.log"
WATCH_LOG="$WORK/mg-result.log"
SPB_LOG="$WORK/mg-spb.log"
CLI_LOG="$WORK/mg-cli.log"
: > "$CLI_LOG"

GROUP="Bifrost:Line1"
EDGE="recipe-edge"
STATUS_NODE="ns=2;s=Sim/Line1/Mixer1.Temp.StatusCode"
SEG_DIR="$LED/commands/Bifrost-Line1/recipe-edge"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$ROGUE_LOG" "$EDGE_LOG" "$WATCH_LOG" "$SPB_LOG" "$CLI_LOG"; do
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
  kill_by_mainclass "TopicWatcher" || true
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
fixture() { java -cp "$G" dev.krillin.bifrost.gates.ProposalFixture "$@" 2>>"$CLI_LOG"; }

echo "[GATE] step 1: keys, grants, an edge policy rule for the Method, and a published mapping release"
rm -rf "$PKI" "$REG" "$LED" "$PROP"; mkdir -p "$PKI" "$REG/identity" "$PROP"
cp -r heimdall/registry/* "$REG/"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"
REG_WIN="$(cygpath -m "$(pwd)/$REG")"
: > "$REG/identity/authorized-keys.jsonl"
for who in proposer approver agent operator; do
  java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen "$who" --out "$PKI_WIN" 2>/dev/null | head -1 \
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
# The edge's own CommandPolicy gains one rule per mixer: the agent may call that mixer's Method, 0..100.
# The device is the Sparkplug device id the release's read binding names (the ISA-95 path).
python - "$REG/policy.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
for rid, n in (("set-temperature", 1), ("set-temperature-mixer2", 2)):
    d["rules"].append({"id": rid, "principal": "agent",
                       "target": {"group": "Bifrost:Line1", "edge": "recipe-edge", "device": f"synthetic-site:line1:mixer{n}"},
                       "command": f"nsu=urn:bifrost:opcua:sim;s=Line1/Mixer{n}.SetTemperature",
                       "constraint": {"type": "Double", "min": 0.0, "max": 100.0}})
json.dump(d, open(p, "w"), indent=2)
PY
SIGNERS=(--by proposer --by-key "$PKI_WIN/proposer.key" --approved-by approver --approved-by-key "$PKI_WIN/approver.key")
BUNDLE="$(cygpath -m "$(pwd)/core/src/test/resources/mapping-fixtures/vor-read")"
# G3 publish: Mixer2's link pointed at Mixer1's read binding, every digest re-pinned so only that rule fails.
CROSSED="$WORK/mg-crossed-bundle"
rm -rf "$CROSSED"; cp -r core/src/test/resources/mapping-fixtures/vor-read "$CROSSED"
python - "$CROSSED" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
dump = lambda rel, d: (root / rel).write_bytes((json.dumps(d, indent=2) + "\n").encode())
sha = lambda rel: hashlib.sha256((root / rel).read_bytes()).hexdigest()
rel = "command-bindings/mixer2-set-temperature.json"
d = json.loads((root / rel).read_bytes()); d["readBindingRef"]["id"] = "vor-binding-mixer1-temp"; dump(rel, d)
p = json.loads((root / "proposal.json").read_bytes())
for f in p["files"]:
    if f["path"] == rel: f["sha256"] = sha(rel)
dump("proposal.json", p)
s = json.loads((root / "submission.json").read_bytes()); s["proposalSha256"] = sha("proposal.json"); dump("submission.json", s)
PY
! gates mapping approve "$REG_WIN" "$(cygpath -m "$(pwd)/$CROSSED")" approval-crossed "${SIGNERS[@]}" \
  || fail "G3 publish: a link to another mixer's read binding was approved"
grep -q "command-binding.device-path" "$CLI_LOG" || fail "G3 publish: the crossed link was not refused command-binding.device-path"
[ ! -e "$REG/mappings/heads/line1.json" ] || fail "G3 publish: a head exists after the refusal"
echo "[GATE] G3 publish OK: a link to another mixer's read binding is refused command-binding.device-path"
gates mapping approve "$REG_WIN" "$BUNDLE" approval-vor-read "${SIGNERS[@]}" || fail "mapping approve failed"
gates mapping publish "$REG_WIN" "$BUNDLE" vor-read 1.0.0 --approval approval-vor-read "${SIGNERS[@]}" \
  || fail "mapping publish failed"
[ -f "$REG/mappings/heads/line1.json" ] || fail "no head for stream line1"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export SPB_EDGE="$EDGE"
export REGISTRY_PATH="$REG_WIN"
export POLICY_PATH="$REG_WIN/policy.json"
export COMMAND_LEDGER_PATH="$(cygpath -m "$(pwd)/$LED")"
export HEIMDALL_IDENTITY_DIR="$(cygpath -m "$(pwd)/$EDGE_PKI")"
export HEIMDALL_SERVER_TRUST_DIR="$(cygpath -m "$(pwd)/$TRUST")"
export HEALTH_PORT=0

echo "[GATE] step 2: the edge identity, then HiveMQ CE and the sim trusting only that identity"
rm -rf "$EDGE_PKI" "$TRUST" "$SIM_CERT" "$ROGUE_CERT"
THUMB="$(java -cp "$H" dev.krillin.bifrost.heimdall.EdgeIdentity --print-thumbprint "$HEIMDALL_IDENTITY_DIR" \
    "urn:bifrost:heimdall:Bifrost-Line1:$EDGE" 2>/dev/null | tr -d '\r')"
[ -n "$THUMB" ] || fail "could not mint the edge identity"
broker_boots() { docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true; }
wait_broker() { for _ in $(seq 1 45); do [ "$(broker_boots)" -gt "$1" ] && return 0; sleep 2; done; return 1; }
B0="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$B0" || fail "HiveMQ CE never reported 'Started HiveMQ'"
: > "$SIM_LOG"
SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$THUMB" SIM_SERVER_CERT_OUT="$(cygpath -m "$(pwd)/$SIM_CERT")" \
  java -jar "$S" >"$SIM_LOG" 2>&1 &
for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && break; sleep 2; done
grep -q "OPC-UA sim listening" "$SIM_LOG" || fail "the sim did not start"
# The edge trusts exactly this server: its certificate, minted at this start, is the whole trust list.
[ -s "$SIM_CERT" ] || fail "the sim did not export its server certificate"
mkdir -p "$TRUST/trusted/certs"
cp "$SIM_CERT" "$TRUST/trusted/certs/sim-server.der"

# The ledger is NOT wiped between edge starts: M3 is about what survives a restart.
start_edge() {
  java "-Dheimdall.gate=$1" -jar "$H" >>"$EDGE_LOG" 2>&1 &
  for _ in $(seq 1 45); do [ "$(grep -c "\[BRIDGE\] ready" "$EDGE_LOG" 2>/dev/null || true)" -ge "$2" ] && return 0; sleep 2; done
  return 1
}
stop_edge() { kill_by_jvmarg "heimdall.gate=$1"; sleep 3; }
wait_line() { for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
count_in() { grep -cF -- "$1" "$2" 2>/dev/null || true; }
iso() { date -u -d "@$(( $(date +%s) + $1 ))" +%Y-%m-%dT%H:%M:%SZ; }

# propose <name> <value> <notBefore offset s> <notAfter offset s> [fixture options] -> prints the cmdId
propose() {
  fixture propose "$REG_WIN" "$(cygpath -m "$(pwd)/$PROP/$1.json")" --by agent --by-key "$PKI_WIN/agent.key" \
    --approved-by operator --value "$2" --not-before "$(iso "$3")" --not-after "$(iso "$4")" "${@:5}" | tr -d '\r'
}
# The operator's signature over a proposal approve refused: only the edge's own checks are left.
cosign() {
  fixture cosign "$(cygpath -m "$(pwd)/$PROP/$1.json")" "$(cygpath -m "$(pwd)/$PROP/$1.approved.json")" \
    --by operator --by-key "$PKI_WIN/operator.key"
}
approve() {
  gates command approve "$REG_WIN" "$(cygpath -m "$(pwd)/$PROP/$1.json")" --approved-by operator \
    --approved-by-key "$PKI_WIN/operator.key" --policy "$REG_WIN/policy.json" \
    --out "$(cygpath -m "$(pwd)/$PROP/$1.approved.json")"
}
publish() { gates command publish "$(cygpath -m "$(pwd)/$PROP/$1.json")" --broker "$MQTT_URL"; }
denied() { wait_line "$EDGE_LOG" "DENY cmd=bifrost/command/v1 cmdId=$1 reason=$2" 15; }
transfers() { count_in "[SIM] transfer Line1/Mixer${2:-1}.Temp = $1" "$SIM_LOG"; }

: > "$EDGE_LOG"
start_edge M 1 || fail "Heimdall did not start"
grep -q "OPC-UA identity $THUMB" "$EDGE_LOG" || fail "Heimdall is not presenting the identity the sim trusts"
grep -q "OPC-UA server trust list .* (1 trusted certificate" "$EDGE_LOG" || fail "Heimdall did not load the one-entry server trust list"

: > "$WATCH_LOG"
java -cp "$H" dev.krillin.bifrost.heimdall.TopicWatcher "bifrost/$GROUP/RESULT/$EDGE" 900 >"$WATCH_LOG" 2>&1 &
wait_line "$WATCH_LOG" "\[WATCH\] subscribed" 15 || fail "the RESULT watcher did not subscribe"
: > "$SPB_LOG"
java -cp "$H" dev.krillin.bifrost.heimdall.TopicWatcher "spBv1.0/$GROUP/NDATA/$EDGE" 900 >"$SPB_LOG" 2>&1 &
wait_line "$SPB_LOG" "\[WATCH\] subscribed" 15 || fail "the NDATA watcher did not subscribe"

# ---------------------------------------------------------------------------
echo "[GATE] ===== M1: an approved proposal is applied ====="
C1="$(propose m1 42.0 -60 600)"
[ -n "$C1" ] || fail "M1 no proposal"
approve m1 || fail "M1 approval refused"
publish m1.approved || fail "M1 publish failed"
wait_line "$EDGE_LOG" "METHOD cmdId=$C1 .* ok=true" 20 || fail "M1 the Method was not applied"
[ "$(transfers 42.0)" = "1" ] || fail "M1 the sim did not transfer Line1/Mixer1.Temp = 42.0 exactly once"
SEG="$(ls "$SEG_DIR"/*.jsonl | head -1)"
grep "\"cmdId\":\"$C1\"" "$SEG" | grep -q '"phase":"intent".*"outcome":"reserved"' || fail "M1 no reservation in the ledger"
grep "\"cmdId\":\"$C1\"" "$SEG" | grep -q '"phase":"outcome".*"outcome":"applied"' || fail "M1 no applied outcome in the ledger"
java -cp "$G" dev.krillin.bifrost.gates.CommandLogGate verify "$(cygpath -m "$SEG")" >/dev/null || fail "M1 the ledger chain is broken"
# The watcher prints raw Sparkplug bytes: the detail metric precedes the uuid and the bytes carry
# newlines, so one answer is joined back into one line and matched within itself.
result_has() { for _ in $(seq 1 10); do tr -d '\r\n' < "$WATCH_LOG" | grep -aqE "$1" && return 0; sleep 2; done; return 1; }
result_has "called [^ ]*SetTemperature\(42\.0\) -> 42\.0.{0,80}$C1" || fail "M1 no affirmative RESULT answer"
# The answer is already here, so an NDATA copy of it would be too.
! grep -aq "^\[WATCH\] spBv1.0/" "$SPB_LOG" || fail "M1 Heimdall published on the node's Sparkplug NDATA"
echo "[GATE] M1 OK: applied once, reserved and recorded, answered on RESULT, nothing on NDATA"

echo "[GATE] ===== M2: the same envelope again ====="
publish m1.approved || fail "M2 publish failed"
denied "$C1" command.replay || fail "M2 the replay was not refused command.replay"
sleep 2
[ "$(transfers 42.0)" = "1" ] || fail "M2 the sim was touched by the replay"
echo "[GATE] M2 OK: refused command.replay, the sim untouched"

echo "[GATE] ===== M3: the same envelope after a restart ====="
stop_edge M
start_edge M3 2 || fail "Heimdall did not restart"
publish m1.approved || fail "M3 publish failed"
# Counted, not matched: M1's apply line and M2's refusal line for this cmdId are already in the log,
# so waiting for a match would return at once and assert nothing about the restarted edge.
wait_count() { for _ in $(seq 1 "$3"); do [ "$(count_in "$1" "$EDGE_LOG")" -ge "$2" ] && return 0; sleep 2; done; return 1; }
if [ "$NC" = true ]; then
  wait_count "METHOD cmdId=$C1 " 2 10 \
    || fail "NC the restarted edge did not apply the replay - the reservation survived the restart, as M3 asserts"
  echo "[GATE] NC: the replay was applied after the restart"
  exit 0
fi
wait_count "cmdId=$C1 reason=command.replay" 2 10 || fail "M3 after a restart the replay was not refused command.replay"
[ "$(count_in "METHOD cmdId=$C1 " "$EDGE_LOG")" = "1" ] || fail "M3 the restarted edge called the Method again"
sleep 2
[ "$(transfers 42.0)" = "1" ] || fail "M3 the sim was touched by the replay after the restart"
echo "[GATE] M3 OK: the reservation survived the restart"

echo "[GATE] ===== G3a: Mixer2 through its own link ====="
CA="$(propose g3a 49.0 -60 600 --mixer 2)"
approve g3a || fail "G3a approval refused"
publish g3a.approved || fail "G3a publish failed"
wait_line "$EDGE_LOG" "METHOD cmdId=$CA .*Mixer2.SetTemperature.* ok=true" 20 || fail "G3a Mixer2's Method was not applied"
[ "$(transfers 49.0 2)" = "1" ] || fail "G3a the sim did not transfer Line1/Mixer2.Temp = 49.0 exactly once"
[ "$(transfers 49.0)" = "0" ] || fail "G3a Mixer1 was touched by Mixer2's command"
echo "[GATE] G3a OK: applied to Mixer2 only"

# g3_refused <leg> <value> <code> <detail or -> [fixture options]: refused by approve, then co-signed past
# approve and refused by the edge with the same code; neither mixer's Method is called.
g3_refused() {
  local leg="$1" value="$2" code="$3" detail="$4"; shift 4
  local c; c="$(propose "$leg" "$value" -60 600 "$@")"
  [ -n "$c" ] || fail "$leg no proposal"
  local before; before="$(wc -l < "$CLI_LOG")"
  ! approve "$leg" || fail "$leg approve accepted the proposal"
  tail -n +"$((before + 1))" "$CLI_LOG" | grep -q "\"error\":\"$code\"" || fail "$leg approve did not refuse $code"
  [ "$detail" = "-" ] || tail -n +"$((before + 1))" "$CLI_LOG" | grep -q "\"detail\":\"$detail\"" \
    || fail "$leg approve did not name $detail"
  cosign "$leg" || fail "$leg co-sign failed"
  publish "$leg.approved" || fail "$leg publish failed"
  denied "$c" "$code" || fail "$leg the edge did not refuse $code"
  [ "$detail" = "-" ] || grep -qF "cmdId=$c reason=$code ($detail)" "$EDGE_LOG" || fail "$leg the edge did not name $detail"
  sleep 2
  { [ "$(transfers "$value")" = "0" ] && [ "$(transfers "$value" 2)" = "0" ]; } || fail "$leg a mixer's Method was called"
  echo "[GATE] $leg OK: refused $code by approve and by the edge, no Method called"
}
echo "[GATE] ===== G3b-e: proposals the link refuses ====="
g3_refused G3b 51.0 command.link.mismatch binding.source --mixer 2 --evidence-mixer 1
g3_refused G3c 52.0 command.malformed - --predicate "https://github.com/yggdrasil-iiot/bifrost/attestation/command-proposal/v1"
g3_refused G3d 53.0 command.link.missing - --device Line1/Mixer1
g3_refused G3e 54.0 command.link.mismatch binding.source \
  --binding-sha256 0000000000000000000000000000000000000000000000000000000000000000

echo "[GATE] ===== M4: an expired window ====="
C4="$(propose m4 43.0 -60 20)"
approve m4 || fail "M4 approval refused"
sleep 25
publish m4.approved || fail "M4 publish failed"
denied "$C4" command.window || fail "M4 the expired envelope was not refused command.window"
[ "$(transfers 43.0)" = "0" ] || fail "M4 the sim was touched"
echo "[GATE] M4 OK: refused command.window"

echo "[GATE] ===== M5: no co-signature ====="
C5="$(propose m5 44.0 -60 600)"
publish m5 || fail "M5 publish failed"
denied "$C5" command.signature || fail "M5 the single-signature proposal was not refused command.signature"
[ "$(transfers 44.0)" = "0" ] || fail "M5 the sim was touched"
echo "[GATE] M5 OK: refused command.signature"

echo "[GATE] ===== M6: a Bad precondition ====="
C6="$(propose m6 45.0 -60 600)"
approve m6 || fail "M6 approval refused"
java -cp "$H" dev.krillin.bifrost.heimdall.SimStatusWriter "$STATUS_NODE" 2147483648 >>"$CLI_LOG" 2>&1 \
  || fail "M6 could not set the Temp StatusCode Bad"
sleep 2
publish m6.approved || fail "M6 publish failed"
denied "$C6" command.precondition || fail "M6 a Bad Temp sample was not refused command.precondition"
[ "$(transfers 45.0)" = "0" ] || fail "M6 the sim was touched"
java -cp "$H" dev.krillin.bifrost.heimdall.SimStatusWriter "$STATUS_NODE" 0 >>"$CLI_LOG" 2>&1 \
  || fail "M6 could not restore the Temp StatusCode"
echo "[GATE] M6 OK: refused command.precondition"

echo "[GATE] ===== M7: a release published after approval ====="
C7="$(propose m7 46.0 -60 600)"
approve m7 || fail "M7 approval refused"
REBASED="$WORK/mg-rebased"
rm -rf "$REBASED"
fixture rebase "$BUNDLE" "$REG_WIN" "$(cygpath -m "$(pwd)/$REBASED")" vor-read-rebased || fail "M7 rebase failed"
gates mapping approve "$REG_WIN" "$(cygpath -m "$(pwd)/$REBASED")" approval-vor-read-2 "${SIGNERS[@]}" || fail "M7 mapping approve failed"
gates mapping publish "$REG_WIN" "$(cygpath -m "$(pwd)/$REBASED")" vor-read 1.0.1 --approval approval-vor-read-2 "${SIGNERS[@]}" \
  || fail "M7 mapping publish failed"
grep -q '"version":"1.0.1"' "$REG/mappings/heads/line1.json" || fail "M7 the head did not move"
publish m7.approved || fail "M7 publish failed"
denied "$C7" command.head.mismatch || fail "M7 a stale head was not refused command.head.mismatch"
[ "$(transfers 46.0)" = "0" ] || fail "M7 the sim was touched"
echo "[GATE] M7 OK: refused command.head.mismatch"

echo "[GATE] ===== M8: a rogue server at the same URL ====="
C8="$(propose m8 47.0 -60 600)"
approve m8 || fail "M8 approval refused"
kill_by_mainclass "bifrost-sim.jar"
sleep 3
: > "$ROGUE_LOG"
# The rogue is as permissive as a rogue can be: it trusts the edge's identity, so only the edge's own
# check of the server certificate stands between the approved proposal and its Method.
SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$THUMB" SIM_SERVER_CERT_OUT="$(cygpath -m "$(pwd)/$ROGUE_CERT")" \
  java -jar "$S" >"$ROGUE_LOG" 2>&1 &
wait_line "$ROGUE_LOG" "OPC-UA sim listening" 30 || fail "M8 the rogue sim did not start"
! cmp -s "$SIM_CERT" "$ROGUE_CERT" || fail "M8 the rogue presents the trusted certificate - not a rogue"
# A new session, not the old one: a session reconnecting to the endpoint it already holds encrypts to
# the old server's certificate and the rogue fails that on its own, so the validator would go untested.
# An edge restarting while the rogue answers discovers the rogue's endpoint and certificate afresh.
stop_edge M3
start_edge M8 3 || fail "M8 Heimdall did not restart"
publish m8.approved || fail "M8 publish failed"
wait_line "$EDGE_LOG" "cmdId=$C8" 30 || fail "M8 Heimdall never answered the proposal"
sleep 5
[ "$(count_in "[SIM] transfer Line1/Mixer1.Temp = 47.0" "$ROGUE_LOG")" = "0" ] || fail "M8 the rogue server's Method was called"
! grep -q "METHOD cmdId=$C8 .* ok=true" "$EDGE_LOG" || fail "M8 Heimdall reports the Method applied"
[ -n "$(ls "$TRUST/rejected" 2>/dev/null)" ] || fail "M8 the rogue certificate was not quarantined in rejected/"
echo "[GATE] M8 OK: the rogue server reached no Method, its certificate is in rejected/"

echo "[GATE] ===== M9: no identity ====="
C9="$(propose m9 48.0 -60 600)"
approve m9 || fail "M9 approval refused"
stop_edge M8
kill_by_mainclass "bifrost-sim.jar"
sleep 3
# Without SIM_REQUIRE_IDENTITY the sim lets anyone call the Method: Heimdall's refusal is the only barrier.
: > "$SIM_LOG"
java -jar "$S" >"$SIM_LOG" 2>&1 &
wait_line "$SIM_LOG" "OPC-UA sim listening" 30 || fail "M9 the anonymous sim did not start"
# The same edge, the same registry and ledger, with only the identity (and so the trust list) unset.
( unset HEIMDALL_IDENTITY_DIR HEIMDALL_SERVER_TRUST_DIR; exec java "-Dheimdall.gate=M9" -jar "$H" >>"$EDGE_LOG" 2>&1 ) &
for _ in $(seq 1 45); do [ "$(grep -c "\[BRIDGE\] ready" "$EDGE_LOG" 2>/dev/null || true)" -ge 4 ] && break; sleep 2; done
[ "$(grep -c "\[BRIDGE\] ready" "$EDGE_LOG" 2>/dev/null || true)" -ge 4 ] || fail "M9 Heimdall did not start without an identity"
publish m9.approved || fail "M9 publish failed"
denied "$C9" command.identity.required || fail "M9 the anonymous edge did not refuse command.identity.required"
sleep 2
[ "$(transfers 48.0)" = "0" ] || fail "M9 the anonymous edge called the Method"
echo "[GATE] M9 OK: refused command.identity.required, the sim untouched"

echo ""
echo "[GATE] PASS run-command-method-gate.sh (M1-M9, G3)"
exit 0
