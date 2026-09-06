#!/usr/bin/env bash
# ANCHORED GATE (T7 end-to-end): proves each governed activation is not only dual-signed (T5) and
# authorized (T6) but also ANCHORED to an external witness plus a four-eyes head, so the two rollback
# attacks T5's signed head still leaves open are DETECTED, and Heimdall fail-closes on an anchor fault
# before binding (REQUIRE_ANCHORED_ACTIVATION=on). Modeled on run-identity-gate.sh — same JAR build /
# registry-staging / python-mutation / broker harness.
#
# The two attacks (a signed head alone cannot stop either):
#   ATTACK #1  lone re-anchor / truncation. An insider truncates the ledger to an earlier version and
#              rewrites the signed head to match. T5's signed head re-signs cleanly over the shorter tail,
#              so signed-verification passes. The APPEND-ONLY anchor witness still records the higher seq,
#              so ANCHORED verification sees head.seq < anchor.seq -> identity.anchor.rollback (AN2).
#   ATTACK #2  co-rollback. The insider rolls back the ledger, the head AND the on-box anchor file
#              together. A FileAnchorStore is a LOCAL PROJECTION — rolled back with everything else, it
#              cannot witness the higher seq. The GIT anchor's whole defensive value is that latest()
#              reads the COMMITTED HEAD (git show HEAD:<file>), never the mutable working tree, so a
#              witness committed to a protected remote survives the co-rollback -> rollback (AN3), and
#              even a working-tree tamper of the git anchor is ignored (AN4).
#
# Threat model / HONEST residual: the git witness only helps if its history is genuinely off-box and
# tamper-resistant (protected remote / signed tag / append-only store). FileAnchorStore alone defends
# ATTACK #1 (append-only) but NOT ATTACK #2; the trust ultimately rests on the anchor's off-box
# protection, not on this gate.
#
# Assertions (AN1-AN7 pure CLI, no broker; AN8 broker, optional):
#   AN1  signed activate -> verify-anchored INTACT (anchored) (exit 0).
#   AN2  two activations, then truncate ledger + rewrite head to seq0 (append-only FILE anchor still seq1)
#        -> verify-anchored BROKEN identity.anchor.rollback (exit 1).
#   AN3  co-rollback (ledger+head+working state to seq0) but a GIT witness committed seq1
#        -> verify-anchored --anchor-store git BROKEN identity.anchor.rollback (exit 1).
#   AN4  git witness survives a working-tree anchor tamper (working tree rolled to seq0, HEAD still seq1)
#        -> verify-anchored --anchor-store git BROKEN identity.anchor.rollback (exit 1).
#   AN5  strip the head's four-eyes co-pair -> verify-anchored BROKEN identity.head.four-eyes.missing (1).
#   AN6  crash window: head advanced to seq1 but the anchor still seq0
#        -> verify-anchored BROKEN identity.anchor.behind (exit 1).
#   AN7  rollback-to-empty: delete ledger+head, keep the anchor witness
#        -> verify-anchored BROKEN identity.anchor.rollback (exit 1).
#   AN8  (broker, OPTIONAL) Heimdall vs a rolled-back ledger with REQUIRE_ANCHORED_ACTIVATION=on
#        -> log has activation.edge.anchor-denied and the edge NEVER binds (fail-closed).
#
# Run from anywhere:
#   bash scripts/run-anchored-activation-gate.sh              # AN8 runs if Docker Desktop is up
#   SKIP_AN8=1 bash scripts/run-anchored-activation-gate.sh   # force-skip the broker leg (AN1-AN7 only)
#   # expect: [ANCHORED] GATE PASS (AN1-AN7 [+AN8])  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/anchored-gate"
SIM_LOG="$WORK/sim.log"
BLOG_AN8="$WORK/bridge-an8.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
command -v python >/dev/null 2>&1 || { echo "[ANCHORED] FAIL: python not found on PATH"; exit 1; }

fail() {
  echo "[ANCHORED] FAIL: $*"
  echo "--- sim log tail ---";        tail -60 "$SIM_LOG"   2>/dev/null || true
  echo "--- bridge an8 log tail ---"; tail -60 "$BLOG_AN8"  2>/dev/null || true
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

kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[ANCHORED] step 0: build the identity-aware gates jar (core+gates)"
mvn -q -pl core,gates -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"
echo "[ANCHORED] gates=$GATES_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[ANCHORED] step 1: keygen alice/bob + build the canonical authorized-keys.jsonl"
rm -rf "$WORK"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"          # the canonical trust anchor copied into each fresh registry
: > "$AKF"

# alice (activator) / bob (approver) -> registered; keygen prints the authorized-keys line on stdout.
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" || fail "authorized-keys.jsonl not built with alice/bob"
echo "[ANCHORED] keys ready (alice activator, bob approver — both registered)"

# stage a fresh governed registry: resolvable recipe artifacts (spec/mix-recipe/{1.0.0,1.1.0}) + trust anchor
stage_reg() {  # $1 = registry dir (bash path); sets $reg / $reg_win globals
  reg="$1"
  rm -rf "$reg"
  mkdir -p "$reg/spec/mix-recipe" "$reg/identity"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$reg/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$reg/spec/mix-recipe/1.1.0.json"
  cp "$AKF"                            "$reg/identity/authorized-keys.jsonl"
  # T6: seed the activation-policy so legitimate alice/bob signed activations pass deny-by-default authZ.
  cat > "$reg/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
  reg_win="$(cygpath -m "$(pwd)/$reg")"
}

# python helpers ------------------------------------------------------------
delete_line() {  # $1=file $2=1-based line number
  python - "$1" "$2" <<'PY'
import sys
p=sys.argv[1]; n=int(sys.argv[2])-1
ls=open(p,encoding='utf-8').read().splitlines()
del ls[n]
open(p,'w',encoding='utf-8').write("\n".join(ls)+"\n")
PY
}
# print entry-0's entryHash (ledger line 1) to stdout.
entry0_hash() {  # $1=ledger file
  python - "$1" <<'PY'
import sys, json
p=sys.argv[1]
ls=[json.loads(l) for l in open(p,encoding='utf-8').read().splitlines() if l.strip()]
print(ls[0]['entryHash'])
PY
}
# rewrite the head JSON: seq=0, tailEntryHash=<arg2>; leave signedBy/sig/coSignedBy/coSig AS-IS (stale,
# but the anchor check fires before the signed-head check, so staleness is never reached).
rewrite_head_seq0() {  # $1=head file $2=entry-0 hash
  python - "$1" "$2" <<'PY'
import sys, json
p=sys.argv[1]; h=sys.argv[2]
d=json.loads(open(p,encoding='utf-8').read())
d['seq']=0
d['tailEntryHash']=h
open(p,'w',encoding='utf-8').write(json.dumps(d,separators=(',',':'))+"\n")
PY
}
# strip the four-eyes co-pair (coSignedBy/coSig) from the head; seq/tail/sig unchanged so anchor +
# signed-head checks pass and the four-eyes check is what fires.
strip_head_copair() {  # $1=head file
  python - "$1" <<'PY'
import sys, json
p=sys.argv[1]
d=json.loads(open(p,encoding='utf-8').read())
d.pop('coSignedBy', None); d.pop('coSig', None)
open(p,'w',encoding='utf-8').write(json.dumps(d,separators=(',',':'))+"\n")
PY
}

# convenience: signed activation of a recipe version on $reg_win. Extra args ("$@") pass anchor flags.
sactivate() {  # $1=version $2=by $3=approver $4=byKeyName $5=approverKeyName [--anchor-store ... --anchor-dir ...]
  local ver="$1" by="$2" appr="$3" bkey="$4" akey="$5"; shift 5
  gates activate "$reg_win" Line1 recipe mix-recipe "$ver" \
        --by "$by" --approved-by "$appr" \
        --by-key "$KEYS_WIN/$bkey" --approved-by-key "$KEYS_WIN/$akey" "$@"
}

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN1: signed activate -> verify-anchored INTACT (file anchor) ====="
stage_reg "$WORK/reg-an1"
set +e
sactivate 1.0.0 alice bob alice.key bob.key >"$WORK/an1-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/an1-act.txt"; fail "AN1 signed activate returned $rc — expected 0"; }
grep -q "signed=true" "$WORK/an1-act.txt" || { cat "$WORK/an1-act.txt"; fail "AN1 activate did not report signed=true"; }
[ -f "$reg/anchor/Line1.anchor.jsonl" ] || fail "AN1 signed activate did not record a file anchor"
set +e
gates identity verify-anchored "$reg_win" Line1 >"$WORK/an1-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/an1-va.txt"; fail "AN1 verify-anchored returned $rc — expected 0 (intact)"; }
grep -q "INTACT (anchored)" "$WORK/an1-va.txt" || { cat "$WORK/an1-va.txt"; fail "AN1 missing 'INTACT (anchored)'"; }
echo "[ANCHORED] AN1 => PASS (INTACT (anchored), exit 0)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN2: truncation re-anchor caught by append-only FILE anchor -> identity.anchor.rollback ====="
stage_reg "$WORK/reg-an2"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1   # anchor now seq=1 (append-only: seq0 + seq1)
LEDGER="$reg/activation/Line1.jsonl"
HEAD="$reg/identity/Line1.head"
E0="$(entry0_hash "$LEDGER")"
[ -n "$E0" ] || fail "AN2 could not read entry-0 hash"
delete_line "$LEDGER" 2                         # truncate the ledger tail (back to entry-0 only)
rewrite_head_seq0 "$HEAD" "$E0"                 # rewrite the head to match seq0 (append-only anchor still seq1)
set +e
gates identity verify-anchored "$reg_win" Line1 >"$WORK/an2-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an2-va.txt"; fail "AN2 verify-anchored returned $rc — expected 1"; }
grep -q "identity.anchor.rollback" "$WORK/an2-va.txt" || { cat "$WORK/an2-va.txt"; fail "AN2 missing identity.anchor.rollback"; }
echo "[ANCHORED] AN2 => PASS (identity.anchor.rollback, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN3: co-rollback caught by GIT witness (committed HEAD) -> identity.anchor.rollback ====="
stage_reg "$WORK/reg-an3"
GITREPO="$WORK/anchor-an3"
GITREPO_WIN="$(cygpath -m "$(pwd)/$GITREPO")"
sactivate 1.0.0 alice bob alice.key bob.key --anchor-store git --anchor-dir "$GITREPO_WIN" >/dev/null 2>&1
# snapshot the seq-0 ledger+head so we can co-roll-back the whole on-box state after seq1 commits.
SNAP="$WORK/an3-snap"; mkdir -p "$SNAP"
cp "$reg/activation/Line1.jsonl" "$SNAP/Line1.jsonl"
cp "$reg/identity/Line1.head"    "$SNAP/Line1.head"
sactivate 1.1.0 alice bob alice.key bob.key --anchor-store git --anchor-dir "$GITREPO_WIN" >/dev/null 2>&1
# co-rollback: restore the seq-0 ledger+head over the reg. The git witness committed up to seq1 is UNTOUCHED.
cp "$SNAP/Line1.jsonl" "$reg/activation/Line1.jsonl"
cp "$SNAP/Line1.head"  "$reg/identity/Line1.head"
set +e
gates identity verify-anchored "$reg_win" Line1 --anchor-store git --anchor-dir "$GITREPO_WIN" >"$WORK/an3-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an3-va.txt"; fail "AN3 verify-anchored (git) returned $rc — expected 1"; }
grep -q "identity.anchor.rollback" "$WORK/an3-va.txt" || { cat "$WORK/an3-va.txt"; fail "AN3 missing identity.anchor.rollback"; }
echo "[ANCHORED] AN3 => PASS (git witness catches the co-rollback, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN4: git witness survives a working-tree anchor tamper -> identity.anchor.rollback ====="
stage_reg "$WORK/reg-an4"
GITREPO4="$WORK/anchor-an4"
GITREPO4_WIN="$(cygpath -m "$(pwd)/$GITREPO4")"
sactivate 1.0.0 alice bob alice.key bob.key --anchor-store git --anchor-dir "$GITREPO4_WIN" >/dev/null 2>&1
SNAP4="$WORK/an4-snap"; mkdir -p "$SNAP4"
cp "$reg/activation/Line1.jsonl" "$SNAP4/Line1.jsonl"
cp "$reg/identity/Line1.head"    "$SNAP4/Line1.head"
sactivate 1.1.0 alice bob alice.key bob.key --anchor-store git --anchor-dir "$GITREPO4_WIN" >/dev/null 2>&1  # commits seq1
# tamper the git repo's WORKING-TREE anchor file back to seq0 (uncommitted) AND co-roll-back ledger+head.
delete_line "$GITREPO4/Line1.anchor.jsonl" 2    # drop the seq1 line from the working tree (HEAD keeps it)
cp "$SNAP4/Line1.jsonl" "$reg/activation/Line1.jsonl"
cp "$SNAP4/Line1.head"  "$reg/identity/Line1.head"
set +e
gates identity verify-anchored "$reg_win" Line1 --anchor-store git --anchor-dir "$GITREPO4_WIN" >"$WORK/an4-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an4-va.txt"; fail "AN4 verify-anchored (git) returned $rc — expected 1"; }
grep -q "identity.anchor.rollback" "$WORK/an4-va.txt" || { cat "$WORK/an4-va.txt"; fail "AN4 missing identity.anchor.rollback (latest() must ignore the working tree)"; }
echo "[ANCHORED] AN4 => PASS (committed HEAD ignores the tampered working tree, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN5: four-eyes head required -> identity.head.four-eyes.missing ====="
stage_reg "$WORK/reg-an5"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
HEAD="$reg/identity/Line1.head"
strip_head_copair "$HEAD"                        # remove coSignedBy/coSig; seq/tail/sig unchanged
set +e
gates identity verify-anchored "$reg_win" Line1 >"$WORK/an5-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an5-va.txt"; fail "AN5 verify-anchored returned $rc — expected 1"; }
grep -q "identity.head.four-eyes.missing" "$WORK/an5-va.txt" || { cat "$WORK/an5-va.txt"; fail "AN5 missing identity.head.four-eyes.missing"; }
echo "[ANCHORED] AN5 => PASS (identity.head.four-eyes.missing, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN6: anchor-behind (crash window: head advanced, anchor lagging) -> identity.anchor.behind ====="
stage_reg "$WORK/reg-an6"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1   # head seq1, anchor seq1
ANCHOR="$reg/anchor/Line1.anchor.jsonl"
delete_line "$ANCHOR" 2                          # anchor back to seq0 (crash after head advanced, before anchor caught up)
set +e
gates identity verify-anchored "$reg_win" Line1 >"$WORK/an6-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an6-va.txt"; fail "AN6 verify-anchored returned $rc — expected 1"; }
grep -q "identity.anchor.behind" "$WORK/an6-va.txt" || { cat "$WORK/an6-va.txt"; fail "AN6 missing identity.anchor.behind"; }
echo "[ANCHORED] AN6 => PASS (identity.anchor.behind, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN7: rollback-to-empty (delete ledger+head, keep anchor) -> identity.anchor.rollback ====="
stage_reg "$WORK/reg-an7"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1   # anchor seq0 recorded
rm -f "$reg/activation/Line1.jsonl" "$reg/identity/Line1.head"   # KEEP the anchor witness
[ -f "$reg/anchor/Line1.anchor.jsonl" ] || fail "AN7 pre-condition: anchor witness must remain"
set +e
gates identity verify-anchored "$reg_win" Line1 >"$WORK/an7-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/an7-va.txt"; fail "AN7 verify-anchored returned $rc — expected 1"; }
grep -q "identity.anchor.rollback" "$WORK/an7-va.txt" || { cat "$WORK/an7-va.txt"; fail "AN7 missing identity.anchor.rollback"; }
echo "[ANCHORED] AN7 => PASS (witness attests a tail now gone: identity.anchor.rollback, exit 1)"

# ---------------------------------------------------------------------------
echo "[ANCHORED] ===== AN8: edge fail-closed on a rolled-back ledger (REQUIRE_ANCHORED_ACTIVATION=on) ====="
if [ -n "${SKIP_AN8:-}" ]; then
  echo "[ANCHORED] AN8 skipped (SKIP_AN8 set)"
elif ! command -v docker >/dev/null 2>&1; then
  echo "[ANCHORED] AN8 skipped (no docker)"
else
  # stage a FULL conformance registry (udt + recipe conformance + spec + policy + trust anchor) so Heimdall
  # reaches the recipe/activationTarget bind branch where assertLedgerTrustworthy() runs.
  AN8REG="$WORK/reg-an8"
  rm -rf "$AN8REG"
  mkdir -p "$AN8REG/udt/Line1-Mixer" "$AN8REG/conformance/Line1-Mixer" "$AN8REG/spec/mix-recipe" "$AN8REG/identity"
  cp "$FIX/udt-Line1-Mixer.json"       "$AN8REG/udt/Line1-Mixer/1.0.0.json"
  cp "$FIX/conformance-recipe.json"    "$AN8REG/conformance/Line1-Mixer/recipe.json"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$AN8REG/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$AN8REG/spec/mix-recipe/1.1.0.json"
  cp "$FIX/policy.json"                "$AN8REG/policy.json"
  cp "$AKF"                            "$AN8REG/identity/authorized-keys.jsonl"
  cat > "$AN8REG/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
  reg="$AN8REG"; reg_win="$(cygpath -m "$(pwd)/$AN8REG")"
  AN8LEDGER="$AN8REG/activation/Line1.jsonl"
  AN8HEAD="$AN8REG/identity/Line1.head"
  CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$AN8REG/conformance/Line1-Mixer/recipe.json")"
  POLICY_WIN="$(cygpath -m "$(pwd)/$AN8REG/policy.json")"

  echo "[ANCHORED] AN8: build heimdall + sim jars"
  mvn -q -pl heimdall,sim -am install -DskipTests
  [ -f heimdall/target/bifrost-heimdall.jar ] || fail "AN8 heimdall jar missing after build"
  [ -f sim/target/bifrost-sim.jar ]           || fail "AN8 sim jar missing after build"
  HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
  SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
  COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

  # two signed activations (file anchor now seq1), then AN2-style rollback: truncate ledger + head to seq0.
  set +e
  sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1; rc=$?
  sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1; rc=$((rc+$?))
  set -e
  [ "$rc" -eq 0 ] || fail "AN8 signed activations returned nonzero — expected both 0"
  E0="$(entry0_hash "$AN8LEDGER")"; [ -n "$E0" ] || fail "AN8 could not read entry-0 hash"
  delete_line "$AN8LEDGER" 2
  rewrite_head_seq0 "$AN8HEAD" "$E0"             # head seq0 < anchor seq1 -> identity.anchor.rollback

  echo "[ANCHORED] AN8: start HiveMQ CE + wait for :1883"
  docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "AN8 failed to start hivemq-ce"
  ok=0
  for i in $(seq 1 30); do
    bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true; fail "AN8 HiveMQ CE did not open :1883"; }

  echo "[ANCHORED] AN8: start the OPC-UA sim"
  : > "$SIM_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  SIM_PID=$!
  ok=0
  for i in $(seq 1 30); do
    grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || fail "AN8 OPC-UA sim did not start (pid $SIM_PID)"

  echo "[ANCHORED] AN8: start Heimdall with REQUIRE_ANCHORED_ACTIVATION=on against the rolled-back ledger"
  : > "$BLOG_AN8"
  MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
  POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$reg_win" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
  ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" \
  REQUIRE_ANCHORED_ACTIVATION="on" ANCHOR_STORE="file" ANCHOR_DIR="$reg_win" \
    java -jar "$HEIMDALL_JAR_WIN" >"$BLOG_AN8" 2>&1 &
  BRIDGE_PID=$!
  ok=0
  for i in $(seq 1 20); do
    grep -q "activation.edge.anchor-denied" "$BLOG_AN8" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || fail "AN8 edge did not fail-closed with activation.edge.anchor-denied"
  grep -q "\[BRIDGE\] activation bound" "$BLOG_AN8" && fail "AN8 edge printed [BRIDGE] activation bound despite a rolled-back ledger"
  grep -q "\[BRIDGE\] ready"            "$BLOG_AN8" && fail "AN8 edge printed [BRIDGE] ready despite a rolled-back ledger"
  echo "[ANCHORED] AN8 => PASS (activation.edge.anchor-denied, edge NEVER bound)"
  AN8_RAN=1

  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true; BRIDGE_PID=""
  [ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true; SIM_PID=""
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
fi

echo ""
echo "[ANCHORED] GATE PASS (AN1-AN7${AN8_RAN:+ +AN8})"
exit 0
