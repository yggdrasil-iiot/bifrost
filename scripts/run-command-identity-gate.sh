#!/usr/bin/env bash
# COMMAND IDENTITY GATE (R1 acceptance): prove a runtime command carries a VERIFIED requester, so
# the edge's deny-by-default is an ACL over principals and not only an allowlist over metrics.
#
# Rule.principal has been populated on every rule in policy.json since it was written and read by
# nothing; BrokerAclProjector had no caller. This gate is the evidence for the edge half.
#
#   C1 signed+authorized : a command signed by the principal the rule names is APPLIED (count increase)
#   C2 unsigned          : the same command without sub/sig is refused command.unsigned
#   C3 bad signature     : a REGISTERED principal name signed with someone else's key is refused
#                          command.sig.invalid
#   C4 unknown principal : a sub naming someone absent from the trust anchor is refused
#                          command.principal.unknown -- distinct from C3, which is a REGISTERED name
#                          with a bad signature
#   C5 wrong principal   : a validly signed command from a registered principal the RULE does not
#                          name is refused principal-mismatch
#   C6 replay            : re-publishing C1's exact signed payload is refused command.replay
#   C7 bar off           : with REQUIRE_SIGNED_COMMAND unset, C2's unsigned command is APPLIED --
#                          proving the refusals came from the bar and not from something incidental
#   C8 bar + log-only    : with ENFORCEMENT_LOG_ONLY ALSO on, the unsigned command is STILL refused.
#                          refuse() returns null under log-only and its caller applies; routing the
#                          signature refusals through it would have shadowed an unsigned command and
#                          then applied it, reaching authorize() with a null subject that skips the
#                          principal check. This is the assertion the first draft of the plan failed.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 48400 free):
#   timeout 900 bash scripts/run-command-identity-gate.sh
#   # expect: [GATE] PASS run-command-identity-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
PKI="$WORK/ci-pki"
REG="$WORK/ci-reg"
SIM_LOG="$WORK/ci-sim.log"
PUB_LOG="$WORK/ci-pub.log"
: > "$PUB_LOG"

GROUP="Bifrost:Line1"
EDGE="recipe-edge"
RPM="ns=2;s=Recipe/Rpm"
OK_VALUE="1500.0"
ALT_VALUE="1600.0"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$PUB_LOG" "$WORK"/ci-edge-*.log; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -30 "$f"; } || true
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
kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-sim.jar" || true

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
# AuthorizedKeys.load resolves <REGISTRY_PATH>/identity/authorized-keys.jsonl, and REGISTRY_PATH is
# the SAME root DefinitionStore reads udt/ from. So the anchor cannot live in a scratch directory of
# its own: stage a whole registry, the way run-activation-authz-gate.sh does.
echo "[GATE] step 1: stage a registry with a trust anchor, and mint three identities"
rm -rf "$PKI" "$REG"; mkdir -p "$PKI" "$REG/identity"
cp -r heimdall/registry/* "$REG/"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"

# recipe-writer  : registered AND named by every rule in policy.json  -> C1
# other-writer   : registered but named by NO rule                    -> C5
# stranger       : never registered at all                            -> C4
java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen recipe-writer --out "$PKI_WIN" 2>/dev/null | head -1  > "$REG/identity/authorized-keys.jsonl"
java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen other-writer  --out "$PKI_WIN" 2>/dev/null | head -1 >> "$REG/identity/authorized-keys.jsonl"
java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen stranger      --out "$PKI_WIN" 2>/dev/null >/dev/null   # deliberately NOT registered
[ "$(wc -l < "$REG/identity/authorized-keys.jsonl")" = "2" ] || fail "expected exactly two registered principals"
grep -q "stranger" "$REG/identity/authorized-keys.jsonl" && fail "stranger must NOT be in the trust anchor - C4 would prove nothing"
echo "[GATE] anchor: recipe-writer + other-writer registered; stranger deliberately absent"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export SPB_EDGE="$EDGE"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/$REG")"
export POLICY_PATH="$(cygpath -m "$(pwd)/$REG/policy.json")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/$REG/conformance/Line1-Mixer/1.0.0.json")"
export HEALTH_PORT=0

broker_boots() { docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true; }
wait_broker() { for _ in $(seq 1 45); do [ "$(broker_boots)" -gt "$1" ] && return 0; sleep 2; done; return 1; }

echo "[GATE] step 2: HiveMQ CE + the OPC-UA sim"
B0="$(broker_boots)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
wait_broker "$B0" || fail "HiveMQ CE never reported 'Started HiveMQ'"
: > "$SIM_LOG"
java -jar "$S" >"$SIM_LOG" 2>&1 &
for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && break; sleep 2; done
grep -q "OPC-UA sim listening" "$SIM_LOG" || fail "the sim did not start"

# $1 = tag, $2 = log, $3 = REQUIRE_SIGNED_COMMAND, $4 = ENFORCEMENT_LOG_ONLY
# Each run gets its OWN log: C6 (replay), C7 (bar off) and C8 (log-only) are exactly where a shared
# accumulating file would let an earlier line satisfy a later assertion.
start_edge() {
  : > "$2"
  REQUIRE_SIGNED_COMMAND="$3" ENFORCEMENT_LOG_ONLY="$4" \
    java "-Dheimdall.gate=$1" -jar "$H" >"$2" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && return 0; sleep 2; done
  return 1
}
stop_edge() { kill_by_jvmarg "heimdall.gate=$1"; sleep 3; }

wait_line()   { for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
count_in()    { grep -c "$1" "$2" 2>/dev/null || true; }
apply_count() { count_in "\[BRIDGE\] APPLY cmd=$RPM ok=true" "$1"; }

pub_unsigned() { java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "$RPM" "$1" Double >>"$PUB_LOG" 2>&1; }
pub_signed()   { # $1=value $2=principal $3=keyfile [$4=cmdId]
  if [ -n "${4:-}" ]; then
    java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "$RPM" "$1" Double \
      --sign "$2" "$PKI_WIN/$3" --cmd-id "$4" >>"$PUB_LOG" 2>&1
  else
    java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "$RPM" "$1" Double \
      --sign "$2" "$PKI_WIN/$3" >>"$PUB_LOG" 2>&1
  fi
}

# ---------------------------------------------------------------------------
echo "[GATE] ===== C1-C6: the bar ON ====="
L="$WORK/ci-edge-on.log"
start_edge ON "$L" on false || fail "the barred edge did not reach ready"
grep -q "REQUIRE_SIGNED_COMMAND on" "$L" || fail "the edge did not announce the bar"

BEFORE="$(apply_count "$L")"
pub_signed "$OK_VALUE" recipe-writer recipe-writer.key "cid-c1"
for _ in $(seq 1 15); do [ "$(apply_count "$L")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$L")" -gt "$BEFORE" ] || fail "C1 a correctly signed, authorized command was not applied"
echo "[GATE] C1 OK: signed by the principal the rule names, applied"

pub_unsigned "$OK_VALUE"
wait_line "$L" "reason=command.unsigned" 15 || fail "C2 an unsigned command was not refused"
echo "[GATE] C2 OK: unsigned refused"

# A REGISTERED principal name with somebody else's key. The publisher always signs exactly what it
# publishes, so a value/signature mismatch cannot be produced from the command line - but signing as
# recipe-writer using other-writer's key is the same failure at the same place, and it keeps C3
# (registered name, signature does not verify) cleanly distinct from C4 (name not registered at all).
pub_signed "$OK_VALUE" recipe-writer other-writer.key "cid-c3"
wait_line "$L" "reason=command.sig.invalid" 15 || fail "C3 a signature from the wrong key was not refused"
echo "[GATE] C3 OK: registered principal, signature does not verify"

pub_signed "$OK_VALUE" stranger stranger.key "cid-c4"
wait_line "$L" "reason=command.principal.unknown" 15 || fail "C4 an unregistered principal was not refused"
echo "[GATE] C4 OK: unknown principal refused, distinctly from a bad signature"

pub_signed "$OK_VALUE" other-writer other-writer.key "cid-c5"
wait_line "$L" "reason=principal-mismatch" 15 \
  || fail "C5 a registered principal the rule does not name was not refused"
echo "[GATE] C5 OK: wrong principal refused by the rule"

pub_signed "$OK_VALUE" recipe-writer recipe-writer.key "cid-c1"
wait_line "$L" "reason=command.replay" 15 || fail "C6 a replayed command id was not refused"
echo "[GATE] C6 OK: replayed command id refused"
stop_edge ON

# ---------------------------------------------------------------------------
echo "[GATE] ===== C7: the bar OFF - the same unsigned command is applied ====="
L7="$WORK/ci-edge-off.log"
start_edge OFF "$L7" false false || fail "the unbarred edge did not reach ready"
grep -q "REQUIRE_SIGNED_COMMAND on" "$L7" && fail "C7 the bar is on when it should be off"
BEFORE="$(apply_count "$L7")"
pub_unsigned "$OK_VALUE"
for _ in $(seq 1 15); do [ "$(apply_count "$L7")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$L7")" -gt "$BEFORE" ] \
  || fail "C7 the unsigned command was refused with the bar OFF - the refusals are not the bar's doing"
echo "[GATE] C7 OK: without the bar the same command is applied"
stop_edge OFF

# ---------------------------------------------------------------------------
echo "[GATE] ===== C8: bar ON plus ENFORCEMENT_LOG_ONLY - still refused ====="
L8="$WORK/ci-edge-logonly.log"
start_edge L8 "$L8" on on || fail "the log-only barred edge did not reach ready"
grep -q "enforcement = LOG-ONLY" "$L8" || fail "C8 the edge is not in log-only mode"
BEFORE="$(apply_count "$L8")"
pub_unsigned "$OK_VALUE"
wait_line "$L8" "reason=command.unsigned" 15 \
  || fail "C8 log-only shadowed the signature bar - an unsigned command was let through"
sleep 4
[ "$(apply_count "$L8")" = "$BEFORE" ] \
  || fail "C8 an unsigned command was APPLIED under log-only - refuse() shadowed the bar"
if grep -q "LOG-ONLY would-deny cmd=$RPM val=$OK_VALUE reason=command.unsigned" "$L8"; then
  fail "C8 the unsigned refusal went through refuse() - it must return directly"
fi
echo "[GATE] C8 OK: the bar is not a verdict, so log-only does not invert it"

echo ""
echo "[GATE] PASS run-command-identity-gate.sh"
exit 0
