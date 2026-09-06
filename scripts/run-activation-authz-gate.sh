#!/usr/bin/env bash
# ACTIVATION AUTHZ GATE (T6 end-to-end): proves the deny-by-default authorization plane over the activation
# act. A registry/identity/activation-policy.json says which authenticated principal may ACTIVATE and which
# may APPROVE which (target, kind, ref); the gate enforces it at pre-deploy (gates activate --by-key) and
# re-verifies it at the Heimdall edge (REQUIRE_SIGNED_ACTIVATION=on). authN (T5 dual-signature) is a
# prerequisite: authZ only runs on the signed path. Modeled on run-identity-gate.sh — same JAR build /
# keygen / registry-staging / broker harness.
#
# Assertions (AZ1-AZ5 pure CLI, no broker; AZ6/AZ7 broker, optional):
#   AZ1  authorized policy (alice->ACTIVATE, bob->APPROVE) + signed activate -> exit 0, verify-signed INTACT.
#   AZ2  same seeded policy; signed activate --by carol --approved-by bob (carol registered+keyed, NO ACTIVATE
#        rule) -> REFUSED activation.authz.denied (exit 1), ledger untouched. Proves the denial is the authZ
#        layer, not authN (carol has a valid registered key).
#   AZ3  same seeded policy; signed activate --by alice --approved-by carol (carol has NO APPROVE rule)
#        -> REFUSED activation.authz.denied (exit 1). maker-checker: the approver leg is enforced too.
#   AZ4  registry WITHOUT activation-policy.json (absent = deny-all); authorized-keyed signed activate
#        -> REFUSED activation.authz.denied (exit 1). Deny-by-default: no policy denies every signed activation.
#   AZ5  gates identity authorize: allow case (alice activate) exit 0 + deny case (alice approve) exit 1.
#   AZ6  (broker, OPTIONAL) authorized signed activation, then rewrite the policy REMOVING alice's ACTIVATE,
#        restart Heimdall REQUIRE_SIGNED_ACTIVATION=on -> log has activation.edge.authz-denied and the edge
#        NEVER binds (revocation is bind-fresh: the policy is re-read at the edge, not baked into the ledger).
#   AZ7  (broker, OPTIONAL) authorized policy + intact signed ledger, REQUIRE_SIGNED_ACTIVATION=on
#        -> edge binds; log has [BRIDGE] activation authz = ok.
#
# Run from anywhere:
#   bash scripts/run-activation-authz-gate.sh            # AZ6/AZ7 run if Docker Desktop is up
#   # expect: [AUTHZ] GATE PASS (AZ1-AZ5 [+AZ6-AZ7])  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

WORK="build/activation-authz-gate"
SIM_LOG="$WORK/sim.log"
BLOG="$WORK/bridge.log"

SIM_PID=""
BRIDGE_PID=""
COMPOSE_WIN=""

# ---------------------------------------------------------------------------
command -v python >/dev/null 2>&1 || { echo "[AUTHZ] FAIL: python not found on PATH"; exit 1; }

fail() {
  echo "[AUTHZ] FAIL: $*"
  echo "--- sim log tail ---";     tail -60 "$SIM_LOG" 2>/dev/null || true
  echo "--- bridge log tail ---";  tail -60 "$BLOG"    2>/dev/null || true
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
echo "[AUTHZ] step 0: build the identity-aware gates jar (core+gates)"
mvn -q -pl core,gates -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"
echo "[AUTHZ] gates=$GATES_JAR_WIN"

# ---------------------------------------------------------------------------
echo "[AUTHZ] step 1: keygen the principals (alice,bob,carol) + build authorized-keys.jsonl"
rm -rf "$WORK"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"          # the canonical trust anchor copied into each fresh registry
: > "$AKF"

# alice / bob / carol all registered — carol is registered+keyed so AZ2/AZ3 denials are the AUTHZ layer, not
# an authN principal-mismatch (she simply has no ACTIVATE/APPROVE rule).
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen carol --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" && grep -q '"carol"' "$AKF" \
  || fail "authorized-keys.jsonl not built with alice/bob/carol"
echo "[AUTHZ] keys ready (alice,bob,carol registered)"

# the authorized policy: alice may ACTIVATE, bob may APPROVE, on (Line1, recipe, mix-recipe). deny-by-default.
write_policy() {  # $1 = registry dir (bash path)
  cat > "$1/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
}

# a policy that REVOKES alice's ACTIVATE (bob->APPROVE only) — used by AZ6 to prove bind-fresh revocation.
write_policy_revoked() {  # $1 = registry dir (bash path)
  cat > "$1/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
}

# stage a lean CLI registry: resolvable recipe artifacts + trust anchor (+ policy unless mode=nopolicy).
stage_reg() {  # $1 = registry dir; $2 = seed|nopolicy (default seed); sets $reg / $reg_win globals
  reg="$1"
  rm -rf "$reg"
  mkdir -p "$reg/spec/mix-recipe" "$reg/identity"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$reg/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$reg/spec/mix-recipe/1.1.0.json"
  cp "$AKF"                            "$reg/identity/authorized-keys.jsonl"
  [ "${2:-seed}" = "seed" ] && write_policy "$reg"
  reg_win="$(cygpath -m "$(pwd)/$reg")"
}

# convenience: signed activation of a recipe version on $reg_win with a given by/approver + key files.
sactivate() {  # $1=version $2=by $3=approver $4=byKeyName $5=approverKeyName [--rollback]
  local ver="$1" by="$2" appr="$3" bkey="$4" akey="$5"; shift 5
  gates activate "$reg_win" Line1 recipe mix-recipe "$ver" \
        --by "$by" --approved-by "$appr" \
        --by-key "$KEYS_WIN/$bkey" --approved-by-key "$KEYS_WIN/$akey" "$@"
}

# ---------------------------------------------------------------------------
echo "[AUTHZ] ===== AZ1: authorized alice(ACTIVATE)+bob(APPROVE) signed activate -> exit 0, INTACT ====="
stage_reg "$WORK/reg-az1"
set +e
sactivate 1.0.0 alice bob alice.key bob.key >"$WORK/az1-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/az1-act.txt"; fail "AZ1 authorized signed activate returned $rc — expected 0"; }
grep -q "signed=true" "$WORK/az1-act.txt" || { cat "$WORK/az1-act.txt"; fail "AZ1 activate did not report signed=true"; }
set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/az1-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/az1-vs.txt"; fail "AZ1 verify-signed returned $rc — expected 0 (intact)"; }
grep -q "INTACT" "$WORK/az1-vs.txt" || { cat "$WORK/az1-vs.txt"; fail "AZ1 verify-signed did not report INTACT"; }
echo "[AUTHZ] AZ1 => PASS (authorized signed activate + verify-signed INTACT)"

# ---------------------------------------------------------------------------
echo "[AUTHZ] ===== AZ2: unauthorized activator (carol, no ACTIVATE) -> activation.authz.denied ====="
stage_reg "$WORK/reg-az2"
set +e
sactivate 1.0.0 carol bob carol.key bob.key >"$WORK/az2.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/az2.txt"; fail "AZ2 activate --by carol returned $rc — expected 1 (refused)"; }
grep -q "activation.authz.denied" "$WORK/az2.txt" || { cat "$WORK/az2.txt"; fail "AZ2 missing activation.authz.denied"; }
[ ! -f "$reg/activation/Line1.jsonl" ] || fail "AZ2 refused activation must leave the ledger untouched"
echo "[AUTHZ] AZ2 => PASS (activation.authz.denied on unauthorized activator, ledger untouched)"

# ---------------------------------------------------------------------------
echo "[AUTHZ] ===== AZ3: unauthorized approver (carol, no APPROVE) -> activation.authz.denied ====="
stage_reg "$WORK/reg-az3"
set +e
sactivate 1.0.0 alice carol alice.key carol.key >"$WORK/az3.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/az3.txt"; fail "AZ3 activate --approved-by carol returned $rc — expected 1 (refused)"; }
grep -q "activation.authz.denied" "$WORK/az3.txt" || { cat "$WORK/az3.txt"; fail "AZ3 missing activation.authz.denied"; }
echo "[AUTHZ] AZ3 => PASS (activation.authz.denied on unauthorized approver)"

# ---------------------------------------------------------------------------
echo "[AUTHZ] ===== AZ4: absent policy = deny-all -> activation.authz.denied ====="
stage_reg "$WORK/reg-az4" nopolicy
[ ! -f "$reg/identity/activation-policy.json" ] || fail "AZ4 registry must have NO activation-policy.json"
set +e
sactivate 1.0.0 alice bob alice.key bob.key >"$WORK/az4.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/az4.txt"; fail "AZ4 signed activate against absent policy returned $rc — expected 1 (deny-all)"; }
grep -q "activation.authz.denied" "$WORK/az4.txt" || { cat "$WORK/az4.txt"; fail "AZ4 missing activation.authz.denied"; }
echo "[AUTHZ] AZ4 => PASS (absent policy denies every signed activation, deny-by-default)"

# ---------------------------------------------------------------------------
echo "[AUTHZ] ===== AZ5: gates identity authorize — allow (activate) exit 0 / deny (approve) exit 1 ====="
stage_reg "$WORK/reg-az5"
set +e
gates identity authorize "$reg_win" alice activate Line1 recipe mix-recipe >"$WORK/az5-allow.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/az5-allow.txt"; fail "AZ5 authorize alice activate returned $rc — expected 0 (allow)"; }
grep -q "ALLOW" "$WORK/az5-allow.txt" || { cat "$WORK/az5-allow.txt"; fail "AZ5 allow case did not print ALLOW"; }
set +e
gates identity authorize "$reg_win" alice approve Line1 recipe mix-recipe >"$WORK/az5-deny.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/az5-deny.txt"; fail "AZ5 authorize alice approve returned $rc — expected 1 (deny)"; }
grep -q "DENY" "$WORK/az5-deny.txt" || { cat "$WORK/az5-deny.txt"; fail "AZ5 deny case did not print DENY"; }
echo "[AUTHZ] AZ5 => PASS (authorize allow=0 / deny=1)"

# ---------------------------------------------------------------------------
# AZ6/AZ7 — broker legs. Need a FULL conformance registry (udt + conformance + spec + policy + trust anchor)
# so Heimdall reaches the recipe/activationTarget bind branch where assertActivationAuthorized() runs.
echo "[AUTHZ] ===== AZ6/AZ7: edge authZ re-check (REQUIRE_SIGNED_ACTIVATION=on) ====="
if ! command -v docker >/dev/null 2>&1; then
  echo "[AUTHZ] AZ6/AZ7 skipped (no docker)"
else
  BREG="$WORK/reg-broker"
  rm -rf "$BREG"
  mkdir -p "$BREG/udt/Line1-Mixer" "$BREG/conformance/Line1-Mixer" "$BREG/spec/mix-recipe" "$BREG/identity"
  cp "$FIX/udt-Line1-Mixer.json"       "$BREG/udt/Line1-Mixer/1.0.0.json"
  cp "$FIX/conformance-recipe.json"    "$BREG/conformance/Line1-Mixer/recipe.json"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$BREG/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$BREG/spec/mix-recipe/1.1.0.json"
  cp "$FIX/policy.json"                "$BREG/policy.json"
  cp "$AKF"                            "$BREG/identity/authorized-keys.jsonl"
  write_policy "$BREG"                                             # authorized: alice ACTIVATE, bob APPROVE
  reg="$BREG"; reg_win="$(cygpath -m "$(pwd)/$BREG")"
  CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG/conformance/Line1-Mixer/recipe.json")"
  POLICY_WIN="$(cygpath -m "$(pwd)/$BREG/policy.json")"

  echo "[AUTHZ] AZ6/AZ7: build heimdall + sim jars"
  mvn -q -pl heimdall,sim -am install -DskipTests
  [ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall jar missing after build"
  [ -f sim/target/bifrost-sim.jar ]           || fail "sim jar missing after build"
  HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
  SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
  COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

  # one INTACT, authorized signed activation of 1.1.0 (alice/bob) — the version the edge will bind.
  set +e
  sactivate 1.1.0 alice bob alice.key bob.key >/dev/null 2>&1; rc=$?
  set -e
  [ "$rc" -eq 0 ] || fail "AZ6/AZ7 signed activate 1.1.0 returned $rc — expected 0"

  echo "[AUTHZ] AZ6/AZ7: start HiveMQ CE + wait for :1883"
  docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
  ok=0
  for i in $(seq 1 30); do
    bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { docker compose -f "$COMPOSE_WIN" logs --tail 40 hivemq-ce 2>/dev/null || true; fail "HiveMQ CE did not open :1883"; }

  echo "[AUTHZ] AZ6/AZ7: start the OPC-UA sim"
  : > "$SIM_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  SIM_PID=$!
  ok=0
  for i in $(seq 1 30); do
    grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || fail "OPC-UA sim did not start (pid $SIM_PID)"

  start_bridge() {  # $1 = bridge log file
    : > "$1"
    MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
    SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" \
    POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$reg_win" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
    ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" REQUIRE_SIGNED_ACTIVATION="on" \
      java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
    BRIDGE_PID=$!
  }
  stop_bridge() {
    [ -n "$BRIDGE_PID" ] && taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || true; BRIDGE_PID=""
    kill_by_mainclass "bifrost-heimdall.jar" || true
  }

  # --- AZ7: authorized policy + intact signed ledger -> edge binds, log has authz = ok --------------------
  echo "[AUTHZ] AZ7: start Heimdall (authorized policy, REQUIRE_SIGNED_ACTIVATION=on) -> expect authz=ok + bind"
  BLOG7="$WORK/bridge-az7.log"
  start_bridge "$BLOG7"
  ok=0
  for i in $(seq 1 20); do
    grep -q "\[BRIDGE\] activation bound" "$BLOG7" 2>/dev/null && { ok=1; break; }
    grep -q "activation.edge.authz-denied" "$BLOG7" 2>/dev/null && break
    sleep 2
  done
  [ "$ok" = "1" ] || { tail -40 "$BLOG7" 2>/dev/null || true; fail "AZ7 edge did not bind under an authorized policy"; }
  grep -q "\[BRIDGE\] activation authz = ok" "$BLOG7" || { tail -40 "$BLOG7"; fail "AZ7 missing [BRIDGE] activation authz = ok"; }
  echo "[AUTHZ] AZ7 => PASS (edge authz = ok, activation bound)"
  stop_bridge

  # --- AZ6: revoke alice's ACTIVATE, restart -> edge fail-closes, never binds ----------------------------
  echo "[AUTHZ] AZ6: rewrite policy REMOVING alice's ACTIVATE, restart Heimdall -> expect authz-denied, no bind"
  write_policy_revoked "$BREG"
  BLOG6="$WORK/bridge-az6.log"
  start_bridge "$BLOG6"
  ok=0
  for i in $(seq 1 20); do
    grep -q "activation.edge.authz-denied" "$BLOG6" 2>/dev/null && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { tail -40 "$BLOG6" 2>/dev/null || true; fail "AZ6 edge did not fail-closed with activation.edge.authz-denied"; }
  grep -q "\[BRIDGE\] activation bound" "$BLOG6" && fail "AZ6 edge printed [BRIDGE] activation bound despite a revoked activator"
  grep -q "\[BRIDGE\] ready"            "$BLOG6" && fail "AZ6 edge printed [BRIDGE] ready despite a revoked activator"
  echo "[AUTHZ] AZ6 => PASS (activation.edge.authz-denied, edge NEVER bound — revocation is bind-fresh)"
  stop_bridge

  [ -n "$SIM_PID" ] && taskkill //F //T //PID "$SIM_PID" >/dev/null 2>&1 || true; SIM_PID=""
  kill_by_mainclass "bifrost-sim.jar" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
  AZ_BROKER_RAN=1
fi

echo ""
echo "[AUTHZ] GATE PASS (AZ1-AZ5${AZ_BROKER_RAN:+ +AZ6-AZ7})"
exit 0
