#!/usr/bin/env bash
# COMMAND LEDGER GATE (R2 acceptance): prove the commands that move the plant leave a tamper-evident
# record — an INTENT entry written before the plant is touched and an OUTCOME entry written after.
#
# Before R2 the board's tamper-evidence and audit rows described the ACTIVATION ledger only. The
# commands themselves were audited by stdout.
#
#   D1 intent then outcome : an applied command leaves two entries, the intent naming the signing
#                            principal (R1's bar ON, or the subject is null and D1 proves nothing
#                            about "who"), and command-log verify says INTACT
#   D2 a refusal is recorded: a denied command leaves ONE entry - the refusal is the entry an
#                            auditor came for, and there is no outcome because the applier never ran
#   D3 an edit is caught   : changing one entry's value makes verify report a break AT THAT INDEX
#   D4 log-only, two facts : a shadowed command leaves an intent carrying the would-deny reason AND
#                            an outcome saying applied - they are not alternatives
#   D5 unwritable refuses  : bar ON with the segment's parent path occupied by a REGULAR FILE, the
#                            command is refused command.ledger.unwritable and the sim never
#                            witnesses the value
#   D6 unwritable+log-only : still refused. log-only inverts verdicts, and "I could not record this"
#                            is not one - the same reasoning as R1's signature bar
#   D7 bar off             : the same unwritable path APPLIES the command, proving D5 came from the
#                            bar and not from something incidental
#   D8 segments link       : a second day's segment starts from the first segment's tail hash, and
#                            the first still verifies with --expect-prev
#
# NOT asserted here: concurrency. Over a broker, MQTT round-trips and an OPC-UA write space the
# appends so far apart that removing `synchronized` would still pass. That evidence is CommandLedger's
# unit test, where the race can actually be driven.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 48400 free):
#   timeout 900 bash scripts/run-command-ledger-gate.sh
#   # expect: [GATE] PASS run-command-ledger-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
PKI="$WORK/cl-pki"
REG="$WORK/cl-reg"
LED="$WORK/cl-ledger"
SIM_LOG="$WORK/cl-sim.log"
PUB_LOG="$WORK/cl-pub.log"
: > "$PUB_LOG"

GROUP="Bifrost:Line1"
EDGE="recipe-edge"
RPM="ns=2;s=Recipe/Rpm"
OK_VALUE="1500.0"
SEG_DIR="$LED/commands/Bifrost-Line1/recipe-edge"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$PUB_LOG" "$WORK"/cl-edge-*.log; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -25 "$f"; } || true
  done
  ls -R "$LED" 2>/dev/null | head -20 || true
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

echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ] \
   || [ ! -f gates/target/bifrost-gates.jar ]; then
  mvn -q -pl core,heimdall,sim,gates install -DskipTests
fi
H="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
S="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
G="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"

echo "[GATE] step 1: stage a registry with a trust anchor"
rm -rf "$PKI" "$REG" "$LED"; mkdir -p "$PKI" "$REG/identity"
cp -r heimdall/registry/* "$REG/"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"
java -cp "$G" dev.krillin.bifrost.gates.IdentityGate keygen recipe-writer --out "$PKI_WIN" 2>/dev/null | head -1 > "$REG/identity/authorized-keys.jsonl"

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

# $1=tag $2=log $3=ledger-path $4=REQUIRE_COMMAND_LEDGER $5=REQUIRE_SIGNED_COMMAND $6=LOG_ONLY
# The ledger directory is WIPED per edge start, exactly as each log is: a ledger under build/gate
# accumulates across runs, and every count-based assertion would otherwise inherit the defect the
# log rule exists to prevent.
start_edge() {
  : > "$2"
  COMMAND_LEDGER_PATH="$3" REQUIRE_COMMAND_LEDGER="$4" \
  REQUIRE_SIGNED_COMMAND="$5" ENFORCEMENT_LOG_ONLY="$6" \
    java "-Dheimdall.gate=$1" -jar "$H" >"$2" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && return 0; sleep 2; done
  return 1
}
stop_edge() { kill_by_jvmarg "heimdall.gate=$1"; sleep 3; }
wait_line() { for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done; return 1; }
count_in() { grep -c "$1" "$2" 2>/dev/null || true; }

seg_file() { ls "$SEG_DIR"/*.jsonl 2>/dev/null | head -1; }
seg_count() { local f; f="$(seg_file)"; [ -n "$f" ] && wc -l < "$f" | tr -d ' ' || echo 0; }
verify_seg() { java -cp "$G" dev.krillin.bifrost.gates.CommandLogGate verify "$(cygpath -m "$(seg_file)")" "$@"; }

pub_signed() { java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" Double \
  --sign recipe-writer "$PKI_WIN/recipe-writer.key" >>"$PUB_LOG" 2>&1; }
pub_plain()  { java -cp "$H" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" Double >>"$PUB_LOG" 2>&1; }

# ---------------------------------------------------------------------------
echo "[GATE] ===== D1/D2: an applied command and a refusal, both recorded ====="
rm -rf "$LED"
L="$WORK/cl-edge-on.log"
# R1's bar ON: without it the subject is null and D1 proves nothing about "who".
start_edge D1 "$L" "$(cygpath -m "$(pwd)/$LED")" false on false || fail "the recording edge did not start"

pub_signed "$RPM" "$OK_VALUE"
wait_line "$L" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "D1 the signed command was not applied"
sleep 2
[ "$(seg_count)" = "2" ] || fail "D1 expected intent+outcome, got $(seg_count) entries"
grep -q '"phase":"intent"' "$(seg_file)"  || fail "D1 no intent entry"
grep -q '"phase":"outcome"' "$(seg_file)" || fail "D1 no outcome entry"
grep -q '"subject":"recipe-writer"' "$(seg_file)" || fail "D1 the intent does not name the principal"
verify_seg >/dev/null || fail "D1 command-log verify did not say INTACT"
echo "[GATE] D1 OK: intent then outcome, principal named, chain intact"

BEFORE="$(seg_count)"
pub_signed "ns=2;s=Recipe/Secret" 1.0
wait_line "$L" "\[BRIDGE\] DENY cmd=ns=2;s=Recipe/Secret" 15 || fail "D2 the rogue node was not denied"
sleep 2
[ "$(seg_count)" = "$((BEFORE + 1))" ] \
  || fail "D2 a refusal must leave exactly ONE entry, got $(( $(seg_count) - BEFORE ))"
grep -q '"outcome":"denied"' "$(seg_file)" || fail "D2 the denial was not recorded"
echo "[GATE] D2 OK: the refusal is one entry, and it is in the record"

echo "[GATE] ===== D3: an edited entry is caught at its index ====="
SEG="$(seg_file)"
cp "$SEG" "$WORK/cl-seg-backup.jsonl"
sed -i 's/"value":"1500.0"/"value":"9999.0"/' "$SEG"
verify_seg >/dev/null && fail "D3 an edited entry verified as intact"
# Capture BEFORE grepping: `set -o pipefail` makes a pipeline inherit verify's exit 1, so
# `verify_seg | grep -q ...` fails even when grep matches.
D3_OUT="$(verify_seg 2>&1 || true)"
echo "$D3_OUT" | grep -q "BROKEN at" || fail "D3 the break was not reported with an index: $D3_OUT"
cp "$WORK/cl-seg-backup.jsonl" "$SEG"
verify_seg >/dev/null || fail "D3 restoring the backup did not restore INTACT"
echo "[GATE] D3 OK: the edit is reported at its index, and the restore verifies again"
stop_edge D1

# ---------------------------------------------------------------------------
echo "[GATE] ===== D4: log-only records BOTH facts ====="
rm -rf "$LED"
L4="$WORK/cl-edge-logonly.log"
start_edge D4 "$L4" "$(cygpath -m "$(pwd)/$LED")" false on on || fail "the log-only edge did not start"
# Rpm=9999 - a node that EXISTS, with a value outside the conformance envelope. Recipe/Secret is
# denied for the right reason but is not a node the sim can write, so its outcome is apply-failed:
# the ledger records that correctly, and it is not the fact D4 is about.
pub_signed "$RPM" 9999.0
wait_line "$L4" "LOG-ONLY would-deny cmd=$RPM" 15 || fail "D4 the command was not shadowed"
sleep 3
[ "$(seg_count)" = "2" ] || fail "D4 expected intent+outcome for a shadowed apply, got $(seg_count)"
grep '"phase":"intent"' "$(seg_file)" | grep -q '"reason"' \
  || fail "D4 the intent does not carry the would-deny reason"
grep '"phase":"outcome"' "$(seg_file)" | grep -q '"outcome":"applied"' \
  || fail "D4 the outcome does not say applied - log-only applies what it would have denied"
echo "[GATE] D4 OK: would-deny reason on the intent, applied on the outcome"
stop_edge D4

# ---------------------------------------------------------------------------
# A REGULAR FILE where the segment's parent directory must be: createDirectories then fails on every
# platform. chmod -w on a directory does not reliably deny a JVM under Windows, which is where these
# gates run.
echo "[GATE] ===== D5/D6/D7: an unwritable ledger ====="
rm -rf "$LED"; mkdir -p "$LED/commands/Bifrost-Line1"
printf 'not a directory' > "$LED/commands/Bifrost-Line1/recipe-edge"

L5="$WORK/cl-edge-unwritable.log"
start_edge D5 "$L5" "$(cygpath -m "$(pwd)/$LED")" true on false || fail "the D5 edge did not start"
SIM_BEFORE="$(count_in "\[SIM\] SET $RPM = $OK_VALUE" "$SIM_LOG")"
pub_signed "$RPM" "$OK_VALUE"
wait_line "$L5" "reason=command.ledger.unwritable" 15 || fail "D5 an unwritable ledger did not refuse"
sleep 3
[ "$(count_in "\[SIM\] SET $RPM = $OK_VALUE" "$SIM_LOG")" = "$SIM_BEFORE" ] \
  || fail "D5 the sim witnessed the value - the plant was touched without a record"
echo "[GATE] D5 OK: refused, and the plant was never touched"
stop_edge D5

L6="$WORK/cl-edge-unwritable-logonly.log"
start_edge D6 "$L6" "$(cygpath -m "$(pwd)/$LED")" true on on || fail "the D6 edge did not start"
SIM_BEFORE="$(count_in "\[SIM\] SET $RPM = $OK_VALUE" "$SIM_LOG")"
pub_signed "$RPM" "$OK_VALUE"
wait_line "$L6" "reason=command.ledger.unwritable" 15 \
  || fail "D6 log-only shadowed an unwritable ledger"
sleep 3
[ "$(count_in "\[SIM\] SET $RPM = $OK_VALUE" "$SIM_LOG")" = "$SIM_BEFORE" ] \
  || fail "D6 the plant was touched under log-only with no record"
echo "[GATE] D6 OK: log-only does not invert a bar that is not a verdict"
stop_edge D6

L7="$WORK/cl-edge-baroff.log"
start_edge D7 "$L7" "$(cygpath -m "$(pwd)/$LED")" false on false || fail "the D7 edge did not start"
pub_signed "$RPM" "$OK_VALUE"
wait_line "$L7" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 \
  || fail "D7 with the bar OFF the command was still refused - D5 is not the bar's doing"
echo "[GATE] D7 OK: without the bar the same unwritable ledger still applies"
stop_edge D7

# ---------------------------------------------------------------------------
echo "[GATE] ===== D8: a new segment links to the previous tail ====="
rm -rf "$LED"
L8="$WORK/cl-edge-seg.log"
start_edge D8 "$L8" "$(cygpath -m "$(pwd)/$LED")" false on false || fail "the D8 edge did not start"
pub_signed "$RPM" "$OK_VALUE"
wait_line "$L8" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "D8 setup command was not applied"
sleep 2
stop_edge D8
SEG1="$(seg_file)"
TAIL="$(tail -1 "$SEG1" | sed -n 's/.*"entryHash":"\([^"]*\)".*/\1/p')"
[ -n "$TAIL" ] || fail "D8 could not read the segment tail hash"
# Simulate tomorrow by renaming today's segment back a day; the ledger picks the lexicographically
# previous segment as its predecessor.
mv "$SEG1" "$SEG_DIR/2026-01-01.jsonl"
start_edge D8b "$L8" "$(cygpath -m "$(pwd)/$LED")" false on false || fail "the D8b edge did not start"
pub_signed "$RPM" "1600.0"
wait_line "$L8" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "D8 the second-segment command was not applied"
sleep 2
NEW="$(ls "$SEG_DIR"/*.jsonl | grep -v 2026-01-01 | head -1)"
[ -n "$NEW" ] || fail "D8 no new segment was created"
head -1 "$NEW" | grep -q "\"prevHash\":\"$TAIL\"" \
  || fail "D8 the new segment restarted at genesis - it could be deleted with nothing to contradict it"
java -cp "$G" dev.krillin.bifrost.gates.CommandLogGate verify "$(cygpath -m "$SEG_DIR/2026-01-01.jsonl")" >/dev/null \
  || fail "D8 the archived segment no longer verifies on its own"
echo "[GATE] D8 OK: the new segment links to the previous tail, and the old one still verifies"
stop_edge D8b

echo ""
echo "[GATE] PASS run-command-ledger-gate.sh"
exit 0
