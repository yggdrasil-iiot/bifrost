#!/usr/bin/env bash
# CHUNK-5 ACCEPTANCE GATE (the ONE end-to-end integration gate): compose the three
# separately-built, ZERO-shared-code sibling repos to prove the northbound governance spine
# end-to-end — a "Line1 Mixer" flows Mímir(model) → Bifrost(govern) → Muninn(feed UNS):
#
#   ../mimir/target/mimir.jar            — the modeler: live OPC-UA browse -> canonical UdtDefinition
#   gates/target/bifrost-gates.jar       — the governor: ① schema-compat, master-spec conformance,
#                                          ③ provenance publish/verify
#   sim/target/bifrost-sim.jar           — the embedded OPC-UA MixerType server + Line1/Mixer1
#   ../muninn/target/muninn.jar          — the feeder/observer: NBIRTH/NDATA over Sparkplug B
#   docker-compose.yml (hivemq-ce)       — the MQTT broker
#
# The five spine assertions:
#   HAPPY  : mimir derive -> schema ① admits + promotes -> provenance ③ publish mints the recipe;
#            spec conformance accepts; muninn feeds — NBIRTH bytes are byte-IDENTICAL to BOTH the
#            promoted udt JSON AND the published recipe-setpoints.yaml (the load-bearing seam),
#            all 4 members (Rpm/Temp/Running/Secret) reach NDATA, 0 drops.
#   (a)    : a breaking re-derive (Running omitted) is REJECTED by schema ① (member.removed, exit 1).
#   (b)    : an out-of-range master spec (Rpm=9999) is REJECTED by conformance (exit 1).
#   (c)    : a tampered published master-spec is REJECTED by provenance ③ verify (content-hash).
#   (d)    : a non-conformant NDATA sample (--inject-bogus Secret) is DROPPED by egress-validate.
#
# Run from anywhere (needs Docker Desktop running + host port 1883 free):
#   bash scripts/run-yggdrasil-spine-gate.sh
#   # expect: [GATE] PASS run-yggdrasil-spine-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="build/gate"

GATES_JAR="gates/target/bifrost-gates.jar"
SIM_JAR="sim/target/bifrost-sim.jar"
MIMIR_JAR="../mimir/target/mimir.jar"
MUNINN_JAR="../muninn/target/muninn.jar"

ENDPOINT="opc.tcp://localhost:48400"
NS_URI="urn:bifrost:opcua:sim"
TYPE="MixerType"
REF="Line1-Mixer"
VER="1.0.0"
GROUP="Bifrost-Line1"
EDGE="recipe-edge"
INSTANCE="Line1/Mixer1"
MQTT="tcp://localhost:1883"

fail() {
  echo "[GATE] FAIL: $*"
  echo "--- sim log tail ---";        tail -40 "$WORK/sim.log"        2>/dev/null || true
  echo "--- feed-happy log tail ---"; tail -40 "$WORK/feed-happy.log" 2>/dev/null || true
  echo "--- feed-drop log tail ---";  tail -40 "$WORK/feed-drop.log"  2>/dev/null || true
  echo "--- observe log tail ---";    tail -40 "$WORK/observe.log"    2>/dev/null || true
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

SIM_PID=""
OBS_PID=""
COMPOSE_WIN=""
cleanup() {
  [ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
  [ -n "$OBS_PID" ] && taskkill //F //T //PID "$OBS_PID" >/dev/null 2>&1 || true
  # `$!` from an MSYS-backgrounded native `java -jar` does not reliably match the real Win32 PID
  # (a known MSYS fork/exec quirk); jps -lm on a `-jar` launch reports the JAR PATH, not the main
  # class, so match on the jar filename instead — the taskkills above are best-effort only.
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "muninn.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
echo "[GATE] step 1: preflight + build (all four jars)"
command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH — Docker Desktop required for the MQTT broker"; exit 1; }

if [ ! -f "$GATES_JAR" ] || [ ! -f "$SIM_JAR" ]; then
  mvn -q -pl core,sim,gates install
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"
[ -f "$SIM_JAR" ]   || fail "$SIM_JAR missing after build"

if [ ! -f "$MIMIR_JAR" ]; then
  ( cd ../mimir && mvn -q package )
fi
[ -f "$MIMIR_JAR" ] || fail "$MIMIR_JAR missing after build"

if [ ! -f "$MUNINN_JAR" ]; then
  ( cd ../muninn && mvn -q package )
fi
[ -f "$MUNINN_JAR" ] || fail "$MUNINN_JAR missing after build"

# Mop up orphans + any foreign broker holding host :1883 BEFORE starting anything new.
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "muninn.jar" || true
docker rm -f bifrost-hivemq-ce muninn-hivemq-ce >/dev/null 2>&1 || true

GATES_JAR_WIN="$(cygpath -m "$(pwd)/$GATES_JAR")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/$SIM_JAR")"
MIMIR_JAR_WIN="$(cygpath -m "$(pwd)/$MIMIR_JAR")"
MUNINN_JAR_WIN="$(cygpath -m "$(pwd)/$MUNINN_JAR")"
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"
echo "[GATE] gates=$GATES_JAR_WIN"
echo "[GATE] sim=$SIM_JAR_WIN"
echo "[GATE] mimir=$MIMIR_JAR_WIN"
echo "[GATE] muninn=$MUNINN_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[GATE] step 2: start HiveMQ CE (broker) + wait for :1883, then the OPC-UA sim"
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

rm -rf "$WORK"
mkdir -p "$WORK/registry" "$WORK/srcrepo" "$WORK/specrepo" "$WORK/out"
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
# MSYS-safe observer helpers (NOT `wait $PID` — a backgrounded native JVM's $! may not be the
# real Win32 PID). Parameterized on the per-sub-run log/capture files.
wait_observer_ready() {  # $1=observe log to watch for '[OBSERVE] subscribed'
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

# ---------------------------------------------------------------------------
echo "[GATE] ===== HAPPY step 3: govern the MODEL (schema ① + provenance ③) ====="
set +e
java -jar "$MIMIR_JAR_WIN" derive "$ENDPOINT" "$NS_URI" "$TYPE" "$REF" "$VER" "$(cygpath -m "$(pwd)/$WORK/def.json")"
code=$?
set -e
[ "$code" -eq 0 ] || fail "mimir derive (happy) returned $code — expected 0"

set +e
java -jar "$GATES_JAR_WIN" schema "$REGISTRY_WIN" "$(cygpath -m "$(pwd)/$WORK/def.json")" --promote
code=$?
set -e
[ "$code" -eq 0 ] || fail "schema gate rejected the faithful derive (exit $code) — expected accept"
[ -f "$WORK/registry/udt/$REF/$VER.json" ] || fail "schema gate did not promote to registry/udt/$REF/$VER.json"
echo "[GATE] schema ① admitted + promoted $REF@$VER"

# The load-bearing seam: publish the PROMOTED governed udt bytes (NOT the compact def.json).
# The promoted JSON is CRLF (Jackson writerWithDefaultPrettyPrinter uses System.lineSeparator());
# core.autocrlf=false after init/before add keeps the committed blob CRLF verbatim so the
# provenance-published recipe-setpoints.yaml (written from the blob) stays byte-equal to the udt
# file (assertion (e) cmp). This is MANDATORY — empirically reproduced.
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
code=$?
set -e
[ "$code" -eq 0 ] || fail "provenance publish returned $code — expected 0"
RECIPE="$WORK/registry/recipe/$REF/$VER/recipe-setpoints.yaml"
[ -f "$RECIPE" ] || fail "provenance publish did not write $RECIPE"
echo "[GATE] provenance ③ minted recipe/$REF/$VER/recipe-setpoints.yaml"

# ---------------------------------------------------------------------------
echo "[GATE] ===== HAPPY step 4: govern the SPEC (conformance) + feed the UNS ====="
set +e
java -jar "$GATES_JAR_WIN" spec "$REGISTRY_WIN" "$(cygpath -m "$(pwd)/scripts/fixtures/gates/spec/conformant-master-spec.json")"
code=$?
set -e
[ "$code" -eq 0 ] || fail "conformant master spec was rejected (exit $code) — expected accept"
echo "[GATE] conformance accepted the conformant master spec"

: > "$WORK/observe.log"
java -jar "$MUNINN_JAR_WIN" observe "$MQTT" "$GROUP" \
  "$(cygpath -m "$(pwd)/$WORK/out/birth.bin")" "$(cygpath -m "$(pwd)/$WORK/out/ndata.txt")" \
  --expect-ndata 4 --timeout-ms 20000 > "$WORK/observe.log" 2>&1 &
OBS_PID=$!
wait_observer_ready "$WORK/observe.log" || fail "happy: observer never printed '[OBSERVE] subscribed'"

set +e
java -jar "$MUNINN_JAR_WIN" feed "$REGISTRY_WIN" "$REF" "$VER" "$ENDPOINT" "$NS_URI" "$INSTANCE" \
  "$MQTT" "$GROUP" "$EDGE" > "$WORK/feed-happy.log" 2>&1
code=$?
set -e
[ "$code" -eq 0 ] || fail "feed (happy) returned $code — expected 0"

poll_ndata "$WORK/out/birth.bin" "$WORK/out/ndata.txt" || fail "happy: observer never captured birth+ndata"
OBS_PID=""

# Assert (e): NBIRTH bytes byte-equal BOTH the published recipe AND the promoted udt JSON.
cmp -s "$WORK/out/birth.bin" "$RECIPE" \
  || fail "NBIRTH bytes NOT byte-identical to published recipe-setpoints.yaml (spine seam)"
cmp -s "$WORK/out/birth.bin" "$WORK/registry/udt/$REF/$VER.json" \
  || fail "NBIRTH bytes NOT byte-identical to promoted udt/$REF/$VER.json (autocrlf seam)"
echo "[GATE] (e) NBIRTH byte-identical to BOTH promoted udt JSON and published recipe"

# Assert 4 members (anchored) reach NDATA + 0 drops on the happy path.
for mem in Rpm Temp Running Secret; do
  grep -q "^$mem$" "$WORK/out/ndata.txt" || fail "happy: NDATA missing member $mem"
done
! grep -q '\[MUNINN\] drop' "$WORK/feed-happy.log" \
  || fail "happy: a member was DROPPED on the conformant path (vocabulary drift?)"
echo "[GATE] HAPPY OK: Rpm/Temp/Running/Secret reached NDATA, 0 drops"

# ---------------------------------------------------------------------------
echo "[GATE] ===== (a) schema compat-break REJECT (Running omitted -> member.removed) ====="
set +e
java -jar "$MIMIR_JAR_WIN" derive "$ENDPOINT" "$NS_URI" "$TYPE" "$REF" 1.1.0 \
  "$(cygpath -m "$(pwd)/$WORK/def-breaking.json")" --omit Running
code=$?
set -e
[ "$code" -eq 0 ] || fail "mimir derive (breaking) returned $code — expected 0 (deriving succeeds)"

set +e
java -jar "$GATES_JAR_WIN" schema "$REGISTRY_WIN" "$(cygpath -m "$(pwd)/$WORK/def-breaking.json")"
code=$?
set -e
[ "$code" -eq 1 ] || fail "schema gate did not reject the breaking re-derive (exit $code, wanted 1 = member.removed)"
echo "[GATE] (a) OK: schema ① rejected member.removed (exit 1, NO --promote)"

# ---------------------------------------------------------------------------
echo "[GATE] ===== (b) spec out-of-range REJECT (Rpm=9999 above max) ====="
set +e
java -jar "$GATES_JAR_WIN" spec "$REGISTRY_WIN" "$(cygpath -m "$(pwd)/scripts/fixtures/gates/spec/out-of-range-master-spec.json")"
code=$?
set -e
[ "$code" -eq 1 ] || fail "out-of-range master spec returned $code — expected reject (exit 1)"
echo "[GATE] (b) OK: conformance rejected spec.range.above-max (exit 1)"

# ---------------------------------------------------------------------------
echo "[GATE] ===== (c) tampered published master-spec REJECT (provenance ③ verify) ====="
cp scripts/fixtures/gates/spec/conformant-master-spec.json "$WORK/specrepo/master-spec.json"
SPECREPO_WIN="$(cygpath -m "$(pwd)/$WORK/specrepo")"
git -C "$SPECREPO_WIN" init -q
git -C "$SPECREPO_WIN" config core.autocrlf false
git -C "$SPECREPO_WIN" config user.email gate@local
git -C "$SPECREPO_WIN" config user.name gate
git -C "$SPECREPO_WIN" add master-spec.json
git -C "$SPECREPO_WIN" commit -qm seed

set +e
java -jar "$GATES_JAR_WIN" provenance publish "$REGISTRY_WIN" "$SPECREPO_WIN" master-spec.json MixProductA 1.0.0 --kind master-spec
code=$?
set -e
[ "$code" -eq 0 ] || fail "provenance publish (master-spec) returned $code — expected 0"

set +e
java -jar "$GATES_JAR_WIN" provenance verify "$REGISTRY_WIN" MixProductA
code=$?
set -e
[ "$code" -eq 0 ] || fail "provenance verify of untampered master-spec was rejected (exit $code) — expected clean accept"

printf 'X' >> "$WORK/registry/recipe/MixProductA/1.0.0/recipe-setpoints.yaml"
set +e
java -jar "$GATES_JAR_WIN" provenance verify "$REGISTRY_WIN" MixProductA
code=$?
set -e
[ "$code" -ne 0 ] || fail "provenance verify of a TAMPERED master-spec was accepted (exit 0) — expected reject"
echo "[GATE] (c) OK: provenance ③ verify accepted clean, rejected tampered master-spec (exit $code)"

# ---------------------------------------------------------------------------
echo "[GATE] ===== (d) non-conformant NDATA DROPPED (--inject-bogus Secret) ====="
: > "$WORK/observe-drop.log"
java -jar "$MUNINN_JAR_WIN" observe "$MQTT" "$GROUP" \
  "$(cygpath -m "$(pwd)/$WORK/out/birth-drop.bin")" "$(cygpath -m "$(pwd)/$WORK/out/ndata-drop.txt")" \
  --expect-ndata 3 --timeout-ms 20000 > "$WORK/observe-drop.log" 2>&1 &
OBS_PID=$!
wait_observer_ready "$WORK/observe-drop.log" || fail "drop: observer never printed '[OBSERVE] subscribed'"

set +e
java -jar "$MUNINN_JAR_WIN" feed "$REGISTRY_WIN" "$REF" "$VER" "$ENDPOINT" "$NS_URI" "$INSTANCE" \
  "$MQTT" "$GROUP" "$EDGE" --inject-bogus Secret > "$WORK/feed-drop.log" 2>&1
code=$?
set -e
[ "$code" -eq 0 ] || fail "feed (drop) returned $code — expected 0"

poll_ndata "$WORK/out/birth-drop.bin" "$WORK/out/ndata-drop.txt" || fail "drop: observer never captured birth+ndata"
OBS_PID=""

grep -q "^Rpm$" "$WORK/out/ndata-drop.txt"      || fail "drop: NDATA missing Rpm"
grep -q "^Temp$" "$WORK/out/ndata-drop.txt"     || fail "drop: NDATA missing Temp"
grep -q "^Running$" "$WORK/out/ndata-drop.txt"  || fail "drop: NDATA missing Running"
! grep -q "^Secret$" "$WORK/out/ndata-drop.txt" || fail "drop: Secret reached NDATA — inject-bogus did NOT drop it"
grep -q "\[MUNINN\] drop Secret" "$WORK/feed-drop.log" \
  || fail "drop: feed log did not show '[MUNINN] drop Secret'"
echo "[GATE] (d) OK: Rpm/Temp/Running birthed, Secret dropped by egress-validate"

# ---------------------------------------------------------------------------
echo "[GATE] step 9: teardown"
[ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "muninn.jar" || true
docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true

echo ""
echo "[GATE] PASS run-yggdrasil-spine-gate.sh"
exit 0
