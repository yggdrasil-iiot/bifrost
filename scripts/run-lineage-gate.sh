#!/usr/bin/env bash
# LINEAGE GATE (T4 end-to-end): proves the activation ledger is a TAMPER-EVIDENT hash chain, and that a
# broken chain fail-closes the edge. Every governed activation is one JSONL LedgerEntry
# {"event":{…},"prevHash":"…","entryHash":"…"} whose entryHash commits to the event fields AND the prior
# entry's hash. Any retroactive edit/delete/reorder of history breaks the chain — the gate CLI detects it,
# and Heimdall REFUSES to bind the active version over a broken chain (never reaches [BRIDGE] activation
# bound). Modeled on run-activation-gate.sh — same JAR/registry/A4 broker harness, reused verbatim.
#
# Topology (LN4 only; LN1-LN3 are pure CLI):
#   gates/target/bifrost-gates.jar       — control plane: activate / activation-log / activation verify-chain
#   heimdall/target/bifrost-heimdall.jar — the edge: verifyChain BEFORE binding the ledger's active version
#   sim/target/bifrost-sim.jar           — OPC-UA sim exposing writable ns=2;s=Recipe/Rpm
#
# Assertions:
#   LN1 chain intact + audited (CLI): activate 1.0.0 then 1.1.0 (alice/bob) -> verify-chain exit 0,
#                                     entries=2 INTACT; activation-log shows both; raw ledger chains
#                                     (entry#1 prevHash==GENESIS[64x0], entry#2 prevHash==entry#1 entryHash).
#   LN2 edit past event (CLI):        tamper first line ("bob"->"mallory") -> verify-chain exit 1,
#                                     ledger.chain.entry-hash-mismatch at index=0. Restore.
#   LN3 delete middle event (CLI):    append a 3rd entry (rollback 1.0.0), delete the middle line ->
#                                     verify-chain exit 1, ledger.chain.prev-link-broken. Restore.
#   LN4 edge enforcement (broker):    (a) intact chain, 1.1.0 active -> edge binds 1.1.0, NCMD Rpm=1600
#                                     APPLY (T3 still works atop the chain). (b) tamper a past line, restart
#                                     -> log has activation.edge.ledger-chain-broken and NEVER binds.
#
# Run from anywhere (needs Docker Desktop running + host port 1883 free):
#   bash scripts/run-lineage-gate.sh
#   # expect: [LINEAGE] GATE PASS (LN1-LN4)  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="build/lineage-gate"
SIM_LOG="$WORK/sim.log"
PUB_LOG="$WORK/pub.log"
BLOG_LN4A="$WORK/bridge-ln4a.log"
BLOG_LN4B="$WORK/bridge-ln4b.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "[LINEAGE] FAIL: docker not found on PATH — Docker Desktop is required for the MQTT broker"; exit 1; }
command -v python >/dev/null 2>&1 || { echo "[LINEAGE] FAIL: python not found on PATH"; exit 1; }

fail() {
  echo "[LINEAGE] FAIL: $*"
  echo "--- sim log tail ---";         tail -60 "$SIM_LOG"    2>/dev/null || true
  echo "--- bridge ln4a log tail ---"; tail -60 "$BLOG_LN4A"  2>/dev/null || true
  echo "--- bridge ln4b log tail ---"; tail -60 "$BLOG_LN4B"  2>/dev/null || true
  echo "--- pub log tail ---";         tail -40 "$PUB_LOG"    2>/dev/null || true
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
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Mop up orphans from a prior aborted run BEFORE we start anything new.
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[LINEAGE] step 0: build jars if missing (core, sim, gates, heimdall)"
if [ ! -f core/target/bifrost-core-0.1.0-SNAPSHOT.jar ] || [ ! -f heimdall/target/bifrost-heimdall.jar ] \
   || [ ! -f sim/target/bifrost-sim.jar ] || [ ! -f gates/target/bifrost-gates.jar ]; then
  mvn -q -pl core,sim,gates,heimdall install
fi
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall/target/bifrost-heimdall.jar missing after build"
[ -f sim/target/bifrost-sim.jar ]           || fail "sim/target/bifrost-sim.jar missing after build"
[ -f gates/target/bifrost-gates.jar ]       || fail "gates/target/bifrost-gates.jar missing after build"

HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

echo "[LINEAGE] gates=$GATES_JAR_WIN"
echo "[LINEAGE] heimdall=$HEIMDALL_JAR_WIN"
echo "[LINEAGE] sim=$SIM_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[LINEAGE] step 1: stage the governed registry (udt + recipe conformance + spec 1.0.0/1.1.0 + policy)"
rm -rf "$WORK"
mkdir -p "$WORK/registry/udt/Line1-Mixer" \
         "$WORK/registry/conformance/Line1-Mixer" \
         "$WORK/registry/spec/mix-recipe"
cp "$FIX/udt-Line1-Mixer.json"        "$WORK/registry/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"     "$WORK/registry/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json"  "$WORK/registry/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json"  "$WORK/registry/spec/mix-recipe/1.1.0.json"   # 1.1.0 staged up front — LN1 activates it
cp "$FIX/policy.json"                 "$WORK/registry/policy.json"

REG="$WORK/registry"
LEDGER="$REG/activation/Line1.jsonl"
REG_WIN="$(cygpath -m "$(pwd)/$REG")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$WORK/registry/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$WORK/registry/policy.json")"
ACTIVATION_TARGET="Line1"
RPM_NODE="ns=2;s=Recipe/Rpm"
GENESIS="0000000000000000000000000000000000000000000000000000000000000000"

# convenience: run the gates CLI on the win registry path
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

# portable single-line edit helpers (sed -i is fragile on Git Bash) — python is available.
tamper_bob_to_mallory() {  # $1=file $2=1-based line number
  python - "$1" "$2" <<'PY'
import sys
p=sys.argv[1]; n=int(sys.argv[2])-1
ls=open(p,encoding='utf-8').read().splitlines()
ls[n]=ls[n].replace('"bob"','"mallory"',1)
open(p,'w',encoding='utf-8').write("\n".join(ls)+"\n")
PY
}
delete_line() {  # $1=file $2=1-based line number
  python - "$1" "$2" <<'PY'
import sys
p=sys.argv[1]; n=int(sys.argv[2])-1
ls=open(p,encoding='utf-8').read().splitlines()
del ls[n]
open(p,'w',encoding='utf-8').write("\n".join(ls)+"\n")
PY
}

# ---------------------------------------------------------------------------
echo "[LINEAGE] ===== LN1: chain intact + audited (pure CLI, no broker) ====="
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "LN1 activate mix-recipe@1.0.0 returned $code — expected 0"
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.1.0 --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "LN1 activate mix-recipe@1.1.0 returned $code — expected 0"

set +e
gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" | tee "$WORK/vc-ln1.txt"
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "LN1 verify-chain returned $rc — expected 0 (intact)"
grep -q "entries=2" "$WORK/vc-ln1.txt" || fail "LN1 verify-chain did not report entries=2"
grep -q "INTACT"    "$WORK/vc-ln1.txt" || fail "LN1 verify-chain did not report INTACT"
echo "[LINEAGE] LN1a: verify-chain => INTACT entries=2 (exit 0)"

gates activation-log "$REG_WIN" "$ACTIVATION_TARGET" | tee "$WORK/log-ln1.txt" >/dev/null
grep -q "events=2" "$WORK/log-ln1.txt"                          || fail "LN1 activation-log expected events=2"
grep -q "ACTIVATE recipe/mix-recipe@1.0.0" "$WORK/log-ln1.txt"  || fail "LN1 activation-log missing ACTIVATE@1.0.0"
grep -q "ACTIVATE recipe/mix-recipe@1.1.0" "$WORK/log-ln1.txt"  || fail "LN1 activation-log missing ACTIVATE@1.1.0"
echo "[LINEAGE] LN1b: activation-log shows both entries (events=2)"

# raw-ledger chain assertion (prevHash is not projected by activation-log): entry#1 prevHash==GENESIS,
# entry#2 prevHash==entry#1 entryHash. Fail-closed via python exit code.
set +e
GENESIS="$GENESIS" python - "$LEDGER" <<'PY'
import sys, os, json
p=sys.argv[1]; ls=[l for l in open(p,encoding='utf-8').read().splitlines() if l.strip()]
assert len(ls)==2, f"expected 2 entries, got {len(ls)}"
e0=json.loads(ls[0]); e1=json.loads(ls[1])
gen=os.environ["GENESIS"]
assert e0["prevHash"]==gen, f"entry#1 prevHash {e0['prevHash']} != GENESIS"
assert e1["prevHash"]==e0["entryHash"], f"entry#2 prevHash {e1['prevHash']} != entry#1 entryHash {e0['entryHash']}"
print("[LINEAGE] LN1c: raw ledger chained - entry#1 prevHash==GENESIS, entry#2 prevHash==entry#1 entryHash")
PY
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "LN1 raw-ledger chain assertion failed"
echo "[LINEAGE] LN1 chain intact + audited => PASS"

# ---------------------------------------------------------------------------
echo "[LINEAGE] ===== LN2: edit past event detected ====="
cp "$LEDGER" "$LEDGER.ln2.bak"
tamper_bob_to_mallory "$LEDGER" 1     # rewrite approvedBy "bob"->"mallory" in the FIRST (past) event
set +e
gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" > "$WORK/vc-ln2.txt" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/vc-ln2.txt"; fail "LN2 verify-chain on tampered ledger returned $rc — expected 1"; }
grep -q "entry-hash-mismatch" "$WORK/vc-ln2.txt" || { cat "$WORK/vc-ln2.txt"; fail "LN2 output missing entry-hash-mismatch"; }
grep -q "index=0"             "$WORK/vc-ln2.txt" || { cat "$WORK/vc-ln2.txt"; fail "LN2 output missing index=0"; }
cp "$LEDGER.ln2.bak" "$LEDGER"        # restore the intact chain
set +e; gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 0 ] || fail "LN2 restore failed — chain not intact after restoring backup"
echo "[LINEAGE] LN2 edit past event => PASS (entry-hash-mismatch at index=0, exit 1; chain restored)"

# ---------------------------------------------------------------------------
echo "[LINEAGE] ===== LN3: delete middle event detected ====="
# append a 3rd entry (audited rollback to 1.0.0) so a genuine MIDDLE line exists.
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.0.0 --rollback --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "LN3 rollback activate 1.0.0 returned $code — expected 0"
set +e; gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" > "$WORK/vc-ln3-pre.txt" 2>&1; rc=$?; set -e
[ "$rc" -eq 0 ] || { cat "$WORK/vc-ln3-pre.txt"; fail "LN3 pre-condition: 3-entry chain not intact"; }
grep -q "entries=3" "$WORK/vc-ln3-pre.txt" || fail "LN3 pre-condition: expected entries=3"

cp "$LEDGER" "$LEDGER.ln3.bak"
delete_line "$LEDGER" 2                # delete the MIDDLE line (line 2 of 3)
set +e
gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" > "$WORK/vc-ln3.txt" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/vc-ln3.txt"; fail "LN3 verify-chain after middle-delete returned $rc — expected 1"; }
grep -q "prev-link-broken" "$WORK/vc-ln3.txt" || { cat "$WORK/vc-ln3.txt"; fail "LN3 output missing prev-link-broken"; }
cp "$LEDGER.ln3.bak" "$LEDGER"        # restore
set +e; gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 0 ] || fail "LN3 restore failed — chain not intact after restoring backup"
echo "[LINEAGE] LN3 delete middle event => PASS (prev-link-broken, exit 1; chain restored)"

# ---------------------------------------------------------------------------
# LN4 needs the broker + sim. LN1-LN3 established a valid 3-entry chain ending in ROLLBACK@1.0.0.
echo "[LINEAGE] step 2: start HiveMQ CE (broker) + wait for :1883"
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
echo "[LINEAGE] HiveMQ CE up on :1883"

echo "[LINEAGE] step 3: start the OPC-UA sim"
: > "$SIM_LOG"
java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
SIM_PID=$!
ok=0
for i in $(seq 1 30); do
  grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "OPC-UA sim did not start (pid $SIM_PID)"
echo "[LINEAGE] OPC-UA sim listening (pid $SIM_PID)"
: > "$PUB_LOG"

# Helpers — reused verbatim from run-activation-gate.sh (A4 plumbing).
pub() {  # $1=nodeId $2=value $3=dataType
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}

start_bridge() {  # $1=bridge log
  : > "$1"
  MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
  POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$REG_WIN" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
  ACTIVATION_PATH="$REG_WIN" ACTIVATION_TARGET="$ACTIVATION_TARGET" \
    java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  BRIDGE_PID=$!
  local ok=0
  for i in $(seq 1 45); do
    if grep -q "\[BRIDGE\] ready" "$1" 2>/dev/null && grep -q "\[BRIDGE\] conformance loaded" "$1" 2>/dev/null; then
      ok=1; break
    fi
    sleep 2
  done
  [ "$ok" = "1" ] || fail "Heimdall did not reach '[BRIDGE] ready' + '[BRIDGE] conformance loaded' (log $1)"
}

stop_bridge() {
  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  BRIDGE_PID=""
  sleep 2   # let the broker drop the fixed-clientId session before the next daemon connects
}

wait_apply() {  # $1=node  $2=bridge log
  local ok=0
  for i in $(seq 1 12); do
    grep -q "\[BRIDGE\] APPLY cmd=$1 ok=true" "$2" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ]
}

# ---------------------------------------------------------------------------
echo "[LINEAGE] ===== LN4: edge enforcement (the closed loop) ====="
# (a) intact chain, 1.1.0 active. After LN3 the active pointer is 1.0.0 (rollback); re-activate 1.1.0.
set +e
gates activate "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe 1.1.0 --by alice --approved-by bob
code=$?
set -e
[ "$code" -eq 0 ] || fail "LN4 activate mix-recipe@1.1.0 returned $code — expected 0"
gates active "$REG_WIN" "$ACTIVATION_TARGET" recipe mix-recipe | grep -q "version=1.1.0" \
  || fail "LN4 active did not report version=1.1.0"
set +e; gates activation verify-chain "$REG_WIN" "$ACTIVATION_TARGET" >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 0 ] || fail "LN4a pre-condition: chain not intact before edge bind"

start_bridge "$BLOG_LN4A"
grep -q "\[BRIDGE\] activation bound mix-recipe@1.1.0" "$BLOG_LN4A" \
  || fail "LN4a edge did not bind mix-recipe@1.1.0 from the (intact) ledger"
echo "[LINEAGE] LN4a: edge bound mix-recipe@1.1.0 over an intact chain"
pub "$RPM_NODE" 1600 Double
wait_apply "$RPM_NODE" "$BLOG_LN4A" || fail "LN4a Rpm=1600 (matches active 1.1.0) was not APPLYed"
echo "[LINEAGE] LN4b: authorized NCMD Rpm=1600 APPLYed (T3 behavior intact atop the chained ledger)"
stop_bridge

# (b) tamper a PAST line, restart the SAME env — the edge must fail-closed on the broken chain and NEVER bind.
cp "$LEDGER" "$LEDGER.ln4.bak"
tamper_bob_to_mallory "$LEDGER" 1
: > "$BLOG_LN4B"
MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$REG_WIN" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
ACTIVATION_PATH="$REG_WIN" ACTIVATION_TARGET="$ACTIVATION_TARGET" \
  java -jar "$HEIMDALL_JAR_WIN" >"$BLOG_LN4B" 2>&1 &
BRIDGE_PID=$!
ok=0
for i in $(seq 1 20); do
  grep -q "activation.edge.ledger-chain-broken" "$BLOG_LN4B" 2>/dev/null && { ok=1; break; }
  sleep 2
done
[ "$ok" = "1" ] || fail "LN4b edge did not fail-closed with activation.edge.ledger-chain-broken on a tampered ledger"
grep -q "\[BRIDGE\] activation bound" "$BLOG_LN4B" \
  && fail "LN4b edge printed [BRIDGE] activation bound despite a broken chain — must fail-closed"
grep -q "\[BRIDGE\] ready" "$BLOG_LN4B" \
  && fail "LN4b edge printed [BRIDGE] ready despite a broken chain — must fail-closed"
echo "[LINEAGE] LN4c: tampered chain -> activation.edge.ledger-chain-broken, edge NEVER bound (fail-closed)"
stop_bridge
cp "$LEDGER.ln4.bak" "$LEDGER"        # restore
echo "[LINEAGE] LN4 edge enforcement => PASS"

# ---------------------------------------------------------------------------
echo "[LINEAGE] step 9: teardown"
[ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true
kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true

echo ""
echo "[LINEAGE] GATE PASS (LN1-LN4)"
exit 0
