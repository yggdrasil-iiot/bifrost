#!/usr/bin/env bash
# IDENTITY GATE (T5 end-to-end): proves each governed activation is dual-signed (activator+approver
# Ed25519) and the ledger tail is anchored by a signed head, so full-re-chain and tail-truncation — the
# two gaps T4's hash chain leaves open — are DETECTED, and Heimdall fail-closes on a broken SIGNED ledger
# before binding (REQUIRE_SIGNED_ACTIVATION=on). Every signed activation is one JSONL LedgerEntry
# {"event":{…},"prevHash":"…","entryHash":"…","activatorSig":"…","approverSig":"…"} plus a
# registry/identity/<target>.head signed over (target ␟ seq ␟ tailEntryHash). Modeled on
# run-lineage-gate.sh — same JAR build / registry-staging / python byte-tamper / broker harness.
#
# Assertions (I1-I6 pure CLI, no broker; I7 broker, optional):
#   I1  signed activate -> identity verify-signed INTACT (exit 0).
#   I2  tamper one activatorSig base64 byte -> verify-signed BROKEN identity.sig.invalid (exit 1). Fresh reg.
#   I3  activate --by mallory (a keypair NOT in authorized-keys) -> activate REFUSED at write time,
#       identity.key.principal-mismatch (exit 1). NOTE: this is the ACTIVATE-TIME refusal path (preflight
#       binds each key file to its REGISTERED pubkey; an unregistered principal folds into principal-mismatch).
#       This is a documented drift from spec §8-I3's verify-time identity.key.unregistered (which overlaps
#       I4b's activate-time code); the verifier's identity.key.unregistered is covered by the JUnit
#       SignedLedgerVerifierTest.unregistered_signer_is_rejected (Task 8), not this gate.
#   I4a same principal (--by alice --approved-by alice) -> REFUSED activation.approval.self (exit 1).
#   I4b approver key file is actually alice's (--approved-by bob --approved-by-key alice.key)
#       -> REFUSED identity.key.principal-mismatch (exit 1) — fires in preflight before the signer-identity check.
#   I4c two principals sharing one registered pubkey (carol/dave) -> REFUSED identity.four-eyes.same-key (exit 1).
#   I5  activate TWICE (two signed entries) then delete the last ledger line, keep the head
#       -> verify-signed BROKEN identity.head.tail-mismatch (exit 1). Fresh reg.
#   I6  edit a past event + recompute ALL entryHash (structural re-chain) WITHOUT re-signing
#       -> structural chain re-validates but the sig over the new hash fails: BROKEN identity.sig.invalid (1).
#       Fresh reg. (The python re-chain replicates LedgerChain.preimage; if it drifts, verify-signed would
#       report a ledger.chain.* rule instead — so this case self-validates the replication.)
#   I7  (broker, OPTIONAL) Heimdall vs a broken SIGNED ledger with REQUIRE_SIGNED_ACTIVATION=on
#       -> log has activation.edge.signed-ledger-broken and the edge NEVER binds (fail-closed).
#
# Run from anywhere:
#   bash scripts/run-identity-gate.sh              # I7 runs if Docker Desktop is up
#   SKIP_I7=1 bash scripts/run-identity-gate.sh    # force-skip the broker leg (I1-I6 only)
#   # expect: [IDENTITY] GATE PASS (I1-I6 [+I7])  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/identity-gate"
SIM_LOG="$WORK/sim.log"
BLOG_I7="$WORK/bridge-i7.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
command -v python >/dev/null 2>&1 || { echo "[IDENTITY] FAIL: python not found on PATH"; exit 1; }

fail() {
  echo "[IDENTITY] FAIL: $*"
  echo "--- sim log tail ---";        tail -60 "$SIM_LOG"   2>/dev/null || true
  echo "--- bridge i7 log tail ---";  tail -60 "$BLOG_I7"   2>/dev/null || true
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
echo "[IDENTITY] step 0: build the identity-aware gates jar (core+gates)"
mvn -q -pl core,gates -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"
echo "[IDENTITY] gates=$GATES_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[IDENTITY] step 1: keygen the principals + build the canonical authorized-keys.jsonl"
rm -rf "$WORK"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"          # the canonical trust anchor copied into each fresh registry
: > "$AKF"

# alice / bob -> registered; keygen prints the authorized-keys line on stdout, diagnostics on stderr.
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
# carol -> registered; dave -> shares carol's key (I4c: two principals, one pubkey).
gates identity keygen carol --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
cp "$KEYS/carol.key" "$KEYS/dave.key"
cp "$KEYS/carol.pub" "$KEYS/dave.pub"
printf '{"principal":"dave","publicKey":"%s"}\n' "$(cat "$KEYS/carol.pub")" >>"$AKF"
# mallory -> keypair generated but deliberately NOT registered (I3).
gates identity keygen mallory --out "$KEYS_WIN" >/dev/null 2>&1

grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" && grep -q '"carol"' "$AKF" && grep -q '"dave"' "$AKF" \
  || fail "authorized-keys.jsonl not built with alice/bob/carol/dave"
[ -f "$KEYS/mallory.key" ] || fail "mallory keypair not generated"
echo "[IDENTITY] keys ready (alice,bob,carol,dave registered; dave⊇carol pubkey; mallory unregistered)"

# stage a fresh governed registry: resolvable recipe artifacts (spec/mix-recipe/{1.0.0,1.1.0}) + trust anchor
stage_reg() {  # $1 = registry dir (bash path); echoes nothing, sets $reg / $reg_win globals
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
# deterministic base64-sig-char flip on a ledger line (never a no-op — flips to a DIFFERENT fixed char).
tamper_sig_byte() {  # $1=file $2=1-based line number
  python - "$1" "$2" <<'PY'
import sys
p=sys.argv[1]; n=int(sys.argv[2])-1
ls=open(p,encoding='utf-8').read().splitlines()
line=ls[n]; key='"activatorSig":"'
i=line.index(key)+len(key)
c=line[i]; repl='B' if c=='A' else 'A'
ls[n]=line[:i]+repl+line[i+1:]
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
# forge a PAST event (line 1 approvedBy -> mallory) and recompute EVERY entryHash/prevHash in append order,
# preserving the (now-stale) signatures. Replicates LedgerChain.preimage exactly so the structural chain
# re-validates; the dual-sig then fails over the new entryHash (-> identity.sig.invalid).
rechain_edit() {  # $1=file
  python - "$1" <<'PY'
import sys, json, hashlib
p=sys.argv[1]
SEP=chr(0x1f); NULL=chr(0)+'null'+chr(0); GEN='0'*64   # match LedgerChain.SEP / NULL_SENTINEL (chr() avoids raw control bytes)
def f(v): return NULL if v is None else str(v)
def eh(ev, prev):
    parts=[f(ev['target']),f(ev['kind']),f(ev['ref']),f(ev['version']),f(ev['contentSha256']),
           f(ev['activatedBy']),f(ev['approvedBy']),str(ev['activatedAt']),f(ev.get('priorVersion')),
           f(ev['action']),f(prev)]
    return hashlib.sha256(SEP.join(parts).encode('utf-8')).hexdigest()
ls=[json.loads(l) for l in open(p,encoding='utf-8').read().splitlines() if l.strip()]
ls[0]['event']['version']='9.9.9'               # forge the past event (a business field); keep the registered
                                                # activator/approver so the break surfaces as sig-invalid, not key-unregistered
prev=GEN
for e in ls:
    e['prevHash']=prev
    e['entryHash']=eh(e['event'], prev)
    prev=e['entryHash']
open(p,'w',encoding='utf-8').write("\n".join(json.dumps(e,separators=(',',':')) for e in ls)+"\n")
PY
}

# convenience: signed activation of a recipe version on $reg_win with a given by/approver + key files.
sactivate() {  # $1=version $2=by $3=approver $4=byKeyName $5=approverKeyName [--rollback]
  local ver="$1" by="$2" appr="$3" bkey="$4" akey="$5"; shift 5
  gates activate "$reg_win" Line1 recipe mix-recipe "$ver" \
        --by "$by" --approved-by "$appr" \
        --by-key "$KEYS_WIN/$bkey" --approved-by-key "$KEYS_WIN/$akey" "$@"
}

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I1: signed activate -> verify-signed INTACT ====="
stage_reg "$WORK/reg-i1"
set +e
sactivate 1.0.0 alice bob alice.key bob.key >"$WORK/i1-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/i1-act.txt"; fail "I1 signed activate returned $rc — expected 0"; }
grep -q "signed=true" "$WORK/i1-act.txt" || { cat "$WORK/i1-act.txt"; fail "I1 activate did not report signed=true"; }
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/i1-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/i1-vs.txt"; fail "I1 verify-signed returned $rc — expected 0 (intact)"; }
grep -q "INTACT" "$WORK/i1-vs.txt" || { cat "$WORK/i1-vs.txt"; fail "I1 verify-signed did not report INTACT"; }
echo "[IDENTITY] I1 => PASS (signed activate + verify-signed INTACT)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I2: tamper a signature byte -> identity.sig.invalid ====="
stage_reg "$WORK/reg-i2"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
LEDGER="$reg/activation/Line1.jsonl"
tamper_sig_byte "$LEDGER" 1
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/i2-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i2-vs.txt"; fail "I2 verify-signed on tampered sig returned $rc — expected 1"; }
grep -q "identity.sig.invalid" "$WORK/i2-vs.txt" || { cat "$WORK/i2-vs.txt"; fail "I2 missing identity.sig.invalid"; }
echo "[IDENTITY] I2 => PASS (identity.sig.invalid, exit 1)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I3: activate with an unregistered principal -> identity.key.principal-mismatch ====="
stage_reg "$WORK/reg-i3"
set +e
gates activate "$reg_win" Line1 recipe mix-recipe 1.0.0 \
      --by mallory --approved-by bob \
      --by-key "$KEYS_WIN/mallory.key" --approved-by-key "$KEYS_WIN/bob.key" >"$WORK/i3.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i3.txt"; fail "I3 activate --by mallory returned $rc — expected 1 (refused)"; }
grep -q "identity.key.principal-mismatch" "$WORK/i3.txt" || { cat "$WORK/i3.txt"; fail "I3 missing identity.key.principal-mismatch"; }
[ ! -f "$reg/activation/Line1.jsonl" ] || fail "I3 refused activation must leave the ledger untouched"
echo "[IDENTITY] I3 => PASS (activate-time identity.key.principal-mismatch, ledger untouched)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I4: four-eyes / key-binding refusals ====="
stage_reg "$WORK/reg-i4"

# I4a: activator == approver -> activation.approval.self (fires before the signer preflight)
set +e
gates activate "$reg_win" Line1 recipe mix-recipe 1.0.0 \
      --by alice --approved-by alice \
      --by-key "$KEYS_WIN/alice.key" --approved-by-key "$KEYS_WIN/alice.key" >"$WORK/i4a.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i4a.txt"; fail "I4a returned $rc — expected 1"; }
grep -q "activation.approval.self" "$WORK/i4a.txt" || { cat "$WORK/i4a.txt"; fail "I4a missing activation.approval.self"; }
echo "[IDENTITY] I4a => PASS (activation.approval.self)"

# I4b: --approved-by bob but the approver key file is alice's -> identity.key.principal-mismatch
set +e
gates activate "$reg_win" Line1 recipe mix-recipe 1.0.0 \
      --by alice --approved-by bob \
      --by-key "$KEYS_WIN/alice.key" --approved-by-key "$KEYS_WIN/alice.key" >"$WORK/i4b.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i4b.txt"; fail "I4b returned $rc — expected 1"; }
grep -q "identity.key.principal-mismatch" "$WORK/i4b.txt" || { cat "$WORK/i4b.txt"; fail "I4b missing identity.key.principal-mismatch"; }
echo "[IDENTITY] I4b => PASS (identity.key.principal-mismatch on a mismatched approver key file)"

# I4c: carol & dave are distinct principals sharing ONE registered pubkey -> identity.four-eyes.same-key
set +e
gates activate "$reg_win" Line1 recipe mix-recipe 1.0.0 \
      --by carol --approved-by dave \
      --by-key "$KEYS_WIN/carol.key" --approved-by-key "$KEYS_WIN/dave.key" >"$WORK/i4c.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i4c.txt"; fail "I4c returned $rc — expected 1"; }
grep -q "identity.four-eyes.same-key" "$WORK/i4c.txt" || { cat "$WORK/i4c.txt"; fail "I4c missing identity.four-eyes.same-key"; }
[ ! -f "$reg/activation/Line1.jsonl" ] || fail "I4 refusals must leave the ledger untouched"
echo "[IDENTITY] I4c => PASS (identity.four-eyes.same-key)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I5: tail-truncation (delete last line, keep head) -> identity.head.tail-mismatch ====="
stage_reg "$WORK/reg-i5"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1
LEDGER="$reg/activation/Line1.jsonl"
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/i5-pre.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/i5-pre.txt"; fail "I5 pre-condition: 2 signed entries not INTACT"; }
lines=$(grep -c . "$LEDGER"); [ "$lines" -eq 2 ] || fail "I5 pre-condition: expected 2 ledger entries, got $lines"
delete_line "$LEDGER" 2                         # drop the last entry; the signed head still says seq=1
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/i5-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i5-vs.txt"; fail "I5 verify-signed after tail-delete returned $rc — expected 1"; }
grep -q "identity.head.tail-mismatch" "$WORK/i5-vs.txt" || { cat "$WORK/i5-vs.txt"; fail "I5 missing identity.head.tail-mismatch"; }
echo "[IDENTITY] I5 => PASS (identity.head.tail-mismatch, exit 1)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I6: full structural re-chain without re-signing -> identity.sig.invalid ====="
stage_reg "$WORK/reg-i6"
sactivate 1.0.0 alice bob alice.key bob.key >/dev/null 2>&1
sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1
LEDGER="$reg/activation/Line1.jsonl"
rechain_edit "$LEDGER"                           # forge past event + recompute all hashes, keep stale sigs
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/i6-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/i6-vs.txt"; fail "I6 verify-signed after re-chain returned $rc — expected 1"; }
grep -q "identity.sig.invalid" "$WORK/i6-vs.txt" \
  || { cat "$WORK/i6-vs.txt"; fail "I6 expected identity.sig.invalid (a ledger.chain.* rule means the python re-chain drifted from LedgerChain.preimage)"; }
echo "[IDENTITY] I6 => PASS (structural chain re-validates but identity.sig.invalid)"

# ---------------------------------------------------------------------------
echo "[IDENTITY] ===== I7: edge fail-closed on a broken SIGNED ledger (REQUIRE_SIGNED_ACTIVATION=on) ====="
if [ -n "${SKIP_I7:-}" ]; then
  echo "[IDENTITY] I7 skipped (SKIP_I7 set)"
elif ! command -v docker >/dev/null 2>&1; then
  echo "[IDENTITY] I7 skipped (no docker)"
else
  # stage a FULL conformance registry (udt + recipe conformance + spec + policy + trust anchor) so Heimdall
  # reaches the recipe/activationTarget bind branch where assertLedgerTrustworthy() runs.
  I7REG="$WORK/reg-i7"
  rm -rf "$I7REG"
  mkdir -p "$I7REG/udt/Line1-Mixer" "$I7REG/conformance/Line1-Mixer" "$I7REG/spec/mix-recipe" "$I7REG/identity"
  cp "$FIX/udt-Line1-Mixer.json"       "$I7REG/udt/Line1-Mixer/1.0.0.json"
  cp "$FIX/conformance-recipe.json"    "$I7REG/conformance/Line1-Mixer/recipe.json"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$I7REG/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$I7REG/spec/mix-recipe/1.1.0.json"
  cp "$FIX/policy.json"                "$I7REG/policy.json"
  cp "$AKF"                            "$I7REG/identity/authorized-keys.jsonl"
  # T6: seed the activation-policy so the signed activation below passes deny-by-default authZ.
  cat > "$I7REG/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
  reg="$I7REG"; reg_win="$(cygpath -m "$(pwd)/$I7REG")"
  I7LEDGER="$I7REG/activation/Line1.jsonl"
  CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$I7REG/conformance/Line1-Mixer/recipe.json")"
  POLICY_WIN="$(cygpath -m "$(pwd)/$I7REG/policy.json")"

  echo "[IDENTITY] I7: build heimdall + sim jars"
  mvn -q -pl heimdall,sim -am install -DskipTests
  [ -f heimdall/target/bifrost-heimdall.jar ] || fail "I7 heimdall jar missing after build"
  [ -f sim/target/bifrost-sim.jar ]           || fail "I7 sim jar missing after build"
  HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
  SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
  COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

  # a single INTACT signed activation, then tamper its sig so the SIGNED verification breaks.
  set +e
  sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1; rc=$?
  set -e
  [ "$rc" -eq 0 ] || fail "I7 signed activate 1.1.0 returned $rc — expected 0"
  tamper_sig_byte "$I7LEDGER" 1

  echo "[IDENTITY] I7: start HiveMQ CE + wait for :1883"
  docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "I7 failed to start hivemq-ce"
  ok=0
  for i in $(seq 1 30); do
    bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true; fail "I7 HiveMQ CE did not open :1883"; }

  echo "[IDENTITY] I7: start the OPC-UA sim"
  : > "$SIM_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  SIM_PID=$!
  ok=0
  for i in $(seq 1 30); do
    grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || fail "I7 OPC-UA sim did not start (pid $SIM_PID)"

  echo "[IDENTITY] I7: start Heimdall with REQUIRE_SIGNED_ACTIVATION=on against the broken signed ledger"
  : > "$BLOG_I7"
  MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
  SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
  POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$reg_win" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
  ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" REQUIRE_SIGNED_ACTIVATION="on" \
    java -jar "$HEIMDALL_JAR_WIN" >"$BLOG_I7" 2>&1 &
  BRIDGE_PID=$!
  ok=0
  for i in $(seq 1 20); do
    grep -q "activation.edge.signed-ledger-broken" "$BLOG_I7" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || fail "I7 edge did not fail-closed with activation.edge.signed-ledger-broken"
  grep -q "\[BRIDGE\] activation bound" "$BLOG_I7" && fail "I7 edge printed [BRIDGE] activation bound despite a broken signed ledger"
  grep -q "\[BRIDGE\] ready"            "$BLOG_I7" && fail "I7 edge printed [BRIDGE] ready despite a broken signed ledger"
  echo "[IDENTITY] I7 => PASS (activation.edge.signed-ledger-broken, edge NEVER bound)"
  I7_RAN=1

  [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true; BRIDGE_PID=""
  [ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true; SIM_PID=""
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
fi

echo ""
echo "[IDENTITY] GATE PASS (I1-I6${I7_RAN:+ +I7})"
exit 0
