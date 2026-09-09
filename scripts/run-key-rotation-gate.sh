#!/usr/bin/env bash
# KEY ROTATION GATE (R5 acceptance): an identity that outlives its first credential.
#
# Two halves of ENTERPRISE.md axis 10, both of them the half that needs no CA.
#
# Signing keys. A principal may hold a predecessor and a successor at once, so retirement has a safe
# path: verification asks which of a principal's registered keys signed an entry (an entry carries no
# key id, and its timestamp is self-asserted, so no honest time filter exists), while the validity
# window restricts SIGNING. That is what gives ADOPTION.md's "retire by policy, never by deleting the
# line" a mechanism instead of only a warning.
#
# Certificates. Renewal and rotation are the same act when the certificate is self-signed: the
# successor has a different thumbprint and the server has to be told. The only way that does not stop
# the line is an OVERLAP -- the trust list holding both for a while -- which is what K8 proves.
#
#   K1  rotate-key on an unregistered principal is refused: rotation replaces, it does not enrol
#   K2  entries signed with the RETIRED key still verify at every tier (T4 chain, T5 signed,
#       T7 anchored). The R4 landmine, defused rather than only documented
#   K3  the retired key cannot sign a NEW activation -- identity.key.expired, refused at preflight
#   K4  the successor can, and the resulting ledger verifies at every tier
#   K5  the EDGE still boots on a rotated registry, with REQUIRE_SIGNED_ACTIVATION=on and again with
#       REQUIRE_ANCHORED_ACTIVATION=on. A rotation that stops the edge is not a rotation
#   K6  one person holding TWO distinct keys is still one person: signing both legs is refused. A
#       regression guard -- the rule that fires here (activation.approval.self) predates rotation,
#       and the point is that it still fires in the two-key world, where a key-only check would not
#       have. The verifier's own identity.four-eyes.same-principal rule (added in R5) cannot be
#       reached from the write path, because the service refuses before an entry is ever written;
#       it is pinned by SignedLedgerVerifierRotationTest against a hand-built ledger instead
#   K7  DELETING the retired line still breaks the ledger (identity.key.unregistered) and stops the
#       edge. Rotation gives retirement a safe path; it does not disarm the landmine
#   K9  the operator surface: EdgeIdentity show reports notAfter and days; renew mints a successor
#       with a DIFFERENT thumbprint, preserves the predecessor on disk, and prints both
#   K10 the edge announces a certificate inside the warning window (identity.cert.expiring) with the
#       days remaining
#   K8  (Docker, OPTIONAL) THE OVERLAP: with the server trusting BOTH thumbprints, the predecessor
#       identity writes and the successor identity writes. A third, untrusted identity does not
#
# What this gate cannot prove, and where it is proved instead: an EXPIRED certificate. A gate cannot
# move the clock, and generating a certificate that is already expired would need production code to
# grow a knob that exists only for testing. The decision that matters -- an expired certificate does
# NOT stop the edge, it is diagnosed instead -- is pinned by EdgeIdentityExpiryTest and
# NcmdOpcUaBridgeMainDefaultsTest with an injected Clock.
#
# Run from anywhere (K8 runs if Docker Desktop is up; ports 1883, 9096, 48400):
#   bash scripts/run-key-rotation-gate.sh
#   # expect: [KR] GATE PASS (K1-K7 K9 K10 [+K8])  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM wants.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/key-rotation-gate"
BRIDGE_PID=""
COMPOSE_WIN=""

fail() {
  echo "[KR] FAIL: $*"
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || kill -9 "$p" >/dev/null 2>&1 || true
  done
}
kill_by_jvmarg() {  # $1 = the -D value substring
  { jps -v 2>/dev/null | grep -F "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || kill -9 "$p" >/dev/null 2>&1 || true
  done
}

cleanup() {
  [ -n "$BRIDGE_PID" ] && { taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || kill -9 "$BRIDGE_PID" >/dev/null 2>&1 || true; }
  kill_by_jvmarg "heimdall.gate=" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  kill_by_mainclass "bifrost-sim.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT
kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-heimdall.jar" || true
kill_by_mainclass "bifrost-sim.jar" || true

# ---------------------------------------------------------------------------
echo "[KR] step 0: build the gates + heimdall + sim jars"
mvn -q -pl core,gates,heimdall,sim -am install -DskipTests
for j in gates/target/bifrost-gates.jar heimdall/target/bifrost-heimdall.jar sim/target/bifrost-sim.jar; do
  [ -f "$j" ] || fail "$j missing after build"
done
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

# ---------------------------------------------------------------------------
echo "[KR] step 1: keygen alice + bob"
rm -rf "$WORK"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"
: > "$AKF"
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" || fail "trust anchor not built with alice/bob"

write_policy() {  # $1 = registry dir
  cat > "$1/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON
}

stage_reg() {  # $1 = registry dir; $2 = the trust-anchor file to install; sets $reg / $reg_win
  reg="$1"
  rm -rf "$reg"
  mkdir -p "$reg/spec/mix-recipe" "$reg/identity"
  cp "$FIX/spec-mix-recipe-1.0.0.json" "$reg/spec/mix-recipe/1.0.0.json"
  cp "$FIX/spec-mix-recipe-1.1.0.json" "$reg/spec/mix-recipe/1.1.0.json"
  cp "$2"                              "$reg/identity/authorized-keys.jsonl"
  write_policy "$reg"
  reg_win="$(cygpath -m "$(pwd)/$reg")"
}

sactivate() {  # $1=version $2=by $3=approver $4=byKeyName $5=approverKeyName
  gates activate "$reg_win" Line1 recipe mix-recipe "$1" \
        --by "$2" --approved-by "$3" \
        --by-key "$KEYS_WIN/$4" --approved-by-key "$KEYS_WIN/$5"
}

verify_all_tiers() {  # $1 = label
  local rc4 rc5 rc7
  set +e
  gates activation verify-chain  "$reg_win" Line1 >"$WORK/$1-t4.txt" 2>&1; rc4=$?
  gates identity verify-signed   "$reg_win" Line1 >"$WORK/$1-t5.txt" 2>&1; rc5=$?
  gates identity verify-anchored "$reg_win" Line1 >"$WORK/$1-t7.txt" 2>&1; rc7=$?
  set -e
  [ "$rc4" -eq 0 ] && grep -q INTACT "$WORK/$1-t4.txt" || { cat "$WORK/$1-t4.txt"; fail "$1 T4 chain not INTACT"; }
  [ "$rc5" -eq 0 ] && grep -q INTACT "$WORK/$1-t5.txt" || { cat "$WORK/$1-t5.txt"; fail "$1 T5 signed not INTACT"; }
  [ "$rc7" -eq 0 ] && grep -q INTACT "$WORK/$1-t7.txt" || { cat "$WORK/$1-t7.txt"; fail "$1 T7 anchored not INTACT"; }
}

# ---------------------------------------------------------------------------
echo "[KR] ===== K1: rotate-key on an unregistered principal is refused ====="
stage_reg "$WORK/reg-k1" "$AKF"
OUT_WIN="$(cygpath -m "$(pwd)/$KEYS")"
set +e
gates identity rotate-key "$reg_win" carol --out "$OUT_WIN" >"$WORK/k1.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/k1.txt"; fail "K1 rotate-key on carol returned $rc - expected 1 (refused)"; }
grep -q "identity.principal.not-registered" "$WORK/k1.txt" \
  || { cat "$WORK/k1.txt"; fail "K1 missing identity.principal.not-registered"; }
[ ! -f "$KEYS/carol.key" ] || fail "K1 a refused rotation must mint nothing"
echo "[KR] K1 => PASS (rotation replaces a key; it does not enrol a principal)"

# ---------------------------------------------------------------------------
echo "[KR] step 2: alice signs with her ORIGINAL key, then rotates"
stage_reg "$WORK/reg-rot" "$AKF"
set +e
sactivate 1.0.0 alice bob alice.key bob.key >"$WORK/pre.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/pre.txt"; fail "the pre-rotation activation returned $rc - expected 0"; }
verify_all_tiers pre

# Keep the predecessor key file under a distinct name: rotate-key overwrites alice.key with the
# successor, and K3 has to present the retired one.
cp "$KEYS/alice.key" "$KEYS/alice-old.key"
set +e
gates identity rotate-key "$reg_win" alice --out "$OUT_WIN" >"$WORK/rot.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/rot.txt"; fail "rotate-key returned $rc - expected 0"; }
grep -qi "do not delete" "$WORK/rot.txt" \
  || { cat "$WORK/rot.txt"; fail "rotate-key must say plainly that the retired lines are not deleted"; }

# Apply the printed block: every line for alice replaced, bob untouched. This is exactly what the
# command tells the operator to do, so the gate does it the same way rather than a shortcut.
AKF_ROT="$WORK/authorized-keys.rotated.jsonl"
grep -v '"alice"' "$AKF" > "$AKF_ROT"
grep '^{"principal"' "$WORK/rot.txt" >> "$AKF_ROT"
[ "$(grep -c '"alice"' "$AKF_ROT")" -eq 2 ] \
  || { cat "$AKF_ROT"; fail "the rotated anchor must carry BOTH of alice's keys"; }
grep -q '"bob"' "$AKF_ROT" || fail "the rotation must not touch another principal"
cp "$AKF_ROT" "$reg/identity/authorized-keys.jsonl"
echo "[KR] alice rotated; the anchor now carries her predecessor and her successor"

# ---------------------------------------------------------------------------
echo "[KR] ===== K2: entries signed with the RETIRED key still verify at every tier ====="
verify_all_tiers k2
echo "[KR] K2 => PASS (T4, T5 and T7 all INTACT over an entry the retired key signed)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K3: the retired key cannot sign a NEW activation ====="
set +e
sactivate 1.1.0 alice bob alice-old.key bob.key >"$WORK/k3.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/k3.txt"; fail "K3 signing with the retired key returned $rc - expected 1"; }
grep -q "identity.key.expired" "$WORK/k3.txt" || { cat "$WORK/k3.txt"; fail "K3 missing identity.key.expired"; }
echo "[KR] K3 => PASS (retirement stops new signing, at preflight)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K4: the SUCCESSOR key signs, and the ledger still verifies ====="
set +e
sactivate 1.1.0 alice bob alice.key bob.key >"$WORK/k4.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/k4.txt"; fail "K4 signing with the successor returned $rc - expected 0"; }
verify_all_tiers k4
grep -q "signed=true" "$WORK/k4.txt" || { cat "$WORK/k4.txt"; fail "K4 activation did not report signed=true"; }
echo "[KR] K4 => PASS (both keys' entries verify together in one ledger)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K5: the edge still boots on a rotated registry ====="
BREG="$WORK/reg-edge"
rm -rf "$BREG"
mkdir -p "$BREG/udt/Line1-Mixer" "$BREG/conformance/Line1-Mixer" "$BREG/spec/mix-recipe" "$BREG/identity"
cp "$FIX/udt-Line1-Mixer.json"       "$BREG/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"    "$BREG/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json" "$BREG/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json" "$BREG/spec/mix-recipe/1.1.0.json"
cp "$FIX/policy.json"                "$BREG/policy.json"
cp "$AKF"                            "$BREG/identity/authorized-keys.jsonl"
write_policy "$BREG"
reg="$BREG"; reg_win="$(cygpath -m "$(pwd)/$BREG")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$BREG/policy.json")"

# sign 1.1.0 with the ORIGINAL key, then rotate the anchor underneath it: the edge must bind an
# entry whose signer has since been retired, which is the whole point.
set +e
sactivate 1.1.0 alice bob alice-old.key bob.key >"$WORK/k5-act.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/k5-act.txt"; fail "K5 pre-rotation activation returned $rc"; }
cp "$AKF_ROT" "$BREG/identity/authorized-keys.jsonl"

start_edge() {  # $1 = log file; $2 = signed|anchored; $3 = extra env assignments (may be empty)
  : > "$1"
  local anchored="off"
  [ "$2" = "anchored" ] && anchored="on"
  # No broker and no OPC-UA server needed: loadConformance() -- which runs the ledger-trust and authZ
  # checks and prints the bind line -- happens before the first network connect.
  env MQTT_URL="tcp://localhost:1" OPCUA_URL="opc.tcp://localhost:1" \
      SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" HEALTH_PORT="9096" \
      POLICY_PATH="$POLICY_WIN" REGISTRY_PATH="$reg_win" CONFORMANCE_PATH="$CONF_RECIPE_WIN" \
      ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" \
      REQUIRE_SIGNED_ACTIVATION="on" REQUIRE_ANCHORED_ACTIVATION="$anchored" \
      ${3:-} \
      java "-Dheimdall.gate=KR" -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  BRIDGE_PID=$!
}
stop_edge() {
  [ -n "$BRIDGE_PID" ] && { taskkill //F //T //PID "$BRIDGE_PID" >/dev/null 2>&1 || kill -9 "$BRIDGE_PID" >/dev/null 2>&1 || true; }
  BRIDGE_PID=""
  kill_by_jvmarg "heimdall.gate=KR" || true
}
await_bind() {  # $1 = label, $2 = log
  local ok=0 i
  for i in $(seq 1 20); do
    grep -q "\[BRIDGE\] activation bound" "$2" 2>/dev/null && { ok=1; break; }
    grep -q "activation.edge." "$2" 2>/dev/null && break
    sleep 1
  done
  [ "$ok" = "1" ] || { tail -30 "$2" 2>/dev/null || true; fail "K5 ($1) the edge did not bind on a rotated registry"; }
}

for tier in signed anchored; do
  ELOG="$WORK/edge-$tier.log"
  start_edge "$ELOG" "$tier"
  await_bind "$tier" "$ELOG"
  grep -q "\[BRIDGE\] activation trust = $tier" "$ELOG" \
    || { tail -30 "$ELOG"; fail "K5 ($tier) the edge did not run the $tier trust tier"; }
  stop_edge
  echo "[KR] K5 ($tier) => edge bound a version signed by a since-retired key"
done
echo "[KR] K5 => PASS (a rotation does not stop the edge, at either trust tier)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K6: one person holding two keys is still one person ====="
# BOUNDARY, stated because a green light here is easy to over-read. The write path refuses this at
# the SERVICE, with activation.approval.self, and that rule predates rotation -- so this leg is a
# REGRESSION guard: it proves the pre-existing four-eyes still fires now that alice legitimately
# holds two distinct keys, which is exactly the situation in which a key-only check would not have.
# The verifier's own same-principal rule cannot be reached from here, because the service refuses
# before an entry is ever written; SignedLedgerVerifierRotationTest pins it instead.
stage_reg "$WORK/reg-k6" "$AKF_ROT"

# Prove the premise first, or the refusal below could be a key collision rather than a person check.
K6_OLD_LINE="$(grep '"alice"' "$AKF_ROT" | grep    'notAfter' | head -1)"
K6_NEW_LINE="$(grep '"alice"' "$AKF_ROT" | grep -v 'notAfter' | head -1)"
[ -n "$K6_OLD_LINE" ] && [ -n "$K6_NEW_LINE" ] || fail "K6 could not find both of alice's lines"
[ "$K6_OLD_LINE" != "$K6_NEW_LINE" ] || fail "K6 alice's two lines are identical - the premise is false"

set +e
gates activate "$reg_win" Line1 recipe mix-recipe 1.0.0 \
      --by alice --approved-by alice \
      --by-key "$KEYS_WIN/alice-old.key" --approved-by-key "$KEYS_WIN/alice.key" \
      >"$WORK/k6.txt" 2>&1; rc=$?
set -e
[ "$rc" -ne 0 ] || { cat "$WORK/k6.txt"; fail "K6 one person signed both legs and was ALLOWED"; }
grep -q "activation.approval.self" "$WORK/k6.txt" \
  || { cat "$WORK/k6.txt"; fail "K6 refused, but not by the four-eyes rule"; }
[ ! -f "$reg/activation/Line1.jsonl" ] || fail "K6 a refused activation must leave the ledger untouched"
echo "[KR] K6 => PASS (alice holds two distinct keys and is still one person to the gate)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K7: deleting the retired line still breaks the ledger and stops the edge ====="
BREG7="$WORK/reg-k7"
rm -rf "$BREG7"
cp -r "$BREG" "$BREG7"
reg="$BREG7"; reg_win="$(cygpath -m "$(pwd)/$BREG7")"
# remove ONLY the retired line: the successor stays, so this is the mistake an operator actually
# makes -- "I rotated, the old one is dead, tidy it away".
RETIRED_KEY="$(grep '"alice"' "$AKF_ROT" | grep 'notAfter' | head -1)"
[ -n "$RETIRED_KEY" ] || fail "K7 could not identify the retired line"
grep -vF "$RETIRED_KEY" "$AKF_ROT" > "$BREG7/identity/authorized-keys.jsonl"
[ "$(grep -c '"alice"' "$BREG7/identity/authorized-keys.jsonl")" -eq 1 ] \
  || fail "K7 expected exactly the successor line to remain"

set +e
gates identity verify-signed "$reg_win" Line1 >"$WORK/k7-vs.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/k7-vs.txt"; fail "K7 verify-signed returned $rc - expected 1 (broken)"; }
grep -q "identity.sig.invalid\|identity.key.unregistered" "$WORK/k7-vs.txt" \
  || { cat "$WORK/k7-vs.txt"; fail "K7 the deletion did not break verification"; }

CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG7/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$BREG7/policy.json")"
ELOG7="$WORK/edge-k7.log"
start_edge "$ELOG7" signed
ok=0
for i in $(seq 1 20); do
  grep -q "activation.edge.signed-ledger-broken" "$ELOG7" 2>/dev/null && { ok=1; break; }
  sleep 1
done
[ "$ok" = "1" ] || { tail -30 "$ELOG7" 2>/dev/null || true; fail "K7 the edge did not fail closed"; }
grep -q "\[BRIDGE\] activation bound" "$ELOG7" && fail "K7 the edge bound despite an unverifiable ledger"
stop_edge
echo "[KR] K7 => PASS (rotation gives retirement a safe path; it does not disarm the landmine)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K9: the certificate operator surface ====="
PKI="$WORK/pki"
rm -rf "$PKI"
PKI_WIN="$(cygpath -m "$(pwd)/$PKI")"
APP_URI="urn:bifrost:heimdall:Bifrost-Line1:recipe-edge"
identity_cli() { java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.EdgeIdentity "$@"; }

set +e
identity_cli show "$PKI_WIN" "$APP_URI" >"$WORK/k9-show-empty.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$WORK/k9-show-empty.txt"; fail "K9 show on an empty dir returned $rc - expected 2"; }
[ ! -f "$PKI/edge-cert.der" ] || fail "K9 inspecting an identity must never create one"

THUMB1="$(identity_cli --print-thumbprint "$PKI_WIN" "$APP_URI" 2>/dev/null | tr -d '\r')"
[ -n "$THUMB1" ] || fail "K9 could not mint the first identity"
identity_cli show "$PKI_WIN" "$APP_URI" >"$WORK/k9-show.txt" 2>&1 || fail "K9 show failed"
grep -q "$THUMB1" "$WORK/k9-show.txt" || { cat "$WORK/k9-show.txt"; fail "K9 show did not report the thumbprint"; }
grep -q "notAfter" "$WORK/k9-show.txt" || { cat "$WORK/k9-show.txt"; fail "K9 show did not report notAfter"; }
grep -q "^days " "$WORK/k9-show.txt" || { cat "$WORK/k9-show.txt"; fail "K9 show did not report days remaining"; }

identity_cli renew "$PKI_WIN" "$APP_URI" >"$WORK/k9-renew.txt" 2>&1 || fail "K9 renew failed"
THUMB2="$(identity_cli --print-thumbprint "$PKI_WIN" "$APP_URI" 2>/dev/null | tr -d '\r')"
[ "$THUMB1" != "$THUMB2" ] || fail "K9 renewal produced the SAME thumbprint - nothing was rotated"
grep -q "$THUMB1" "$WORK/k9-renew.txt" || { cat "$WORK/k9-renew.txt"; fail "K9 renew did not print the predecessor thumbprint"; }
grep -q "$THUMB2" "$WORK/k9-renew.txt" || { cat "$WORK/k9-renew.txt"; fail "K9 renew did not print the successor thumbprint"; }
grep -qi "before" "$WORK/k9-renew.txt" \
  || { cat "$WORK/k9-renew.txt"; fail "K9 renew must spell out that the server is told BEFORE the edge restarts"; }
ls "$PKI"/edge-cert.der.* >/dev/null 2>&1 || fail "K9 the predecessor certificate was not preserved"
ls "$PKI"/edge-key.pkcs8.* >/dev/null 2>&1 || fail "K9 the predecessor private key was not preserved"
echo "[KR] K9 => PASS (show reports the lifetime; renew rotates, preserves and says the order)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K10: the edge announces a certificate inside the warning window ====="
# A fresh certificate has ~2 years left, so the warning window is widened rather than the clock
# moved. What is under test is the branch and its numbers, not the arithmetic of "30".
reg="$BREG"; reg_win="$(cygpath -m "$(pwd)/$BREG")"
CONF_RECIPE_WIN="$(cygpath -m "$(pwd)/$BREG/conformance/Line1-Mixer/recipe.json")"
POLICY_WIN="$(cygpath -m "$(pwd)/$BREG/policy.json")"
ELOG10="$WORK/edge-k10.log"
start_edge "$ELOG10" signed "HEIMDALL_IDENTITY_DIR=$PKI_WIN HEIMDALL_CERT_WARN_DAYS=99999"
ok=0
for i in $(seq 1 20); do
  grep -q "identity.cert.expiring" "$ELOG10" 2>/dev/null && { ok=1; break; }
  sleep 1
done
[ "$ok" = "1" ] || { tail -30 "$ELOG10" 2>/dev/null || true; fail "K10 the edge did not announce the expiring certificate"; }
grep -E "identity.cert.expiring days=[0-9]+" "$ELOG10" >/dev/null \
  || { tail -30 "$ELOG10"; fail "K10 the warning carries no day count"; }
grep -q "notAfter=" "$ELOG10" || { tail -30 "$ELOG10"; fail "K10 the warning carries no notAfter"; }
stop_edge
echo "[KR] K10 => PASS (the warning names the days remaining and the end date)"

# ---------------------------------------------------------------------------
echo "[KR] ===== K8: THE OVERLAP - the server trusts both thumbprints ====="
# `command -v docker` succeeds while Docker Desktop is merely installed and stopped, which turned a
# skip into a hard failure. Ask the daemon, not the PATH.
if ! docker info >/dev/null 2>&1; then
  echo "[KR] K8 skipped (docker not running)"
else
  COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"
  SIM_LOG="$WORK/k8-sim.log"
  PUB_LOG="$WORK/k8-pub.log"
  : > "$PUB_LOG"
  RPM_NODE="ns=2;s=Recipe/Rpm"

  # The predecessor identity is restored from the backups renew left behind. That is not a shortcut
  # around the API: it is the assertion that preserving them was worth doing, since the overlap is
  # only usable if the certificate currently in the server's trust list still exists.
  PKI_OLD="$WORK/pki-old"
  rm -rf "$PKI_OLD"; mkdir -p "$PKI_OLD"
  cp "$(ls "$PKI"/edge-cert.der.* | head -1)"   "$PKI_OLD/edge-cert.der"
  cp "$(ls "$PKI"/edge-key.pkcs8.* | head -1)"  "$PKI_OLD/edge-key.pkcs8"
  PKI_OLD_WIN="$(cygpath -m "$(pwd)/$PKI_OLD")"
  RESTORED="$(identity_cli --print-thumbprint "$PKI_OLD_WIN" "$APP_URI" 2>/dev/null | tr -d '\r')"
  [ "$RESTORED" = "$THUMB1" ] \
    || fail "K8 the preserved predecessor did not reload as itself ($RESTORED != $THUMB1)"

  # A third identity nobody trusts, so the list is proved to be a list and not "everybody".
  PKI_THIRD="$WORK/pki-third"
  rm -rf "$PKI_THIRD"
  PKI_THIRD_WIN="$(cygpath -m "$(pwd)/$PKI_THIRD")"
  THUMB3="$(identity_cli --print-thumbprint "$PKI_THIRD_WIN" "$APP_URI" 2>/dev/null | tr -d '\r')"
  [ -n "$THUMB3" ] && [ "$THUMB3" != "$THUMB1" ] && [ "$THUMB3" != "$THUMB2" ] \
    || fail "K8 could not mint a distinct third identity"

  broker_boots() {
    docker compose -f "$COMPOSE_WIN" logs hivemq-ce 2>/dev/null | grep -c "Started HiveMQ in" || true
  }
  BOOTS="$(broker_boots)"
  docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "K8 failed to start hivemq-ce"
  ok=0
  for i in $(seq 1 45); do [ "$(broker_boots)" -gt "$BOOTS" ] && { ok=1; break; }; sleep 2; done
  [ "$ok" = "1" ] || fail "K8 HiveMQ CE never reported 'Started HiveMQ'"

  echo "[KR] K8: sim trusting BOTH thumbprints"
  : > "$SIM_LOG"
  SIM_REQUIRE_IDENTITY=on SIM_GOVERNED_THUMBPRINT="$THUMB1,$THUMB2" \
    java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  ok=0
  for i in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && { ok=1; break; }; sleep 2; done
  [ "$ok" = "1" ] || { tail -30 "$SIM_LOG"; fail "K8 the secured sim did not start"; }
  grep -q "secured endpoint" "$SIM_LOG" || { tail -30 "$SIM_LOG"; fail "K8 the sim did not announce a secured endpoint"; }

  start_governed_edge() {  # $1 = log, $2 = identity dir (win path), $3 = tag
    : > "$1"
    env MQTT_URL="tcp://localhost:1883" OPCUA_URL="opc.tcp://localhost:48400" \
        SPB_GROUP="Bifrost:Line1" SPB_EDGE="recipe-edge" HEALTH_PORT="9096" \
        POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")" \
        REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")" \
        CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")" \
        HEIMDALL_IDENTITY_DIR="$2" \
        java "-Dheimdall.gate=KR8-$3" -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
    for i in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$1" 2>/dev/null && return 0; sleep 2; done
    return 1
  }
  pub() { java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$RPM_NODE" "$1" Double >>"$PUB_LOG" 2>&1; }
  applies() { grep -c "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" "$1" 2>/dev/null || true; }

  # --- the PREDECESSOR still writes: this is the overlap ---
  ELOG_OLD="$WORK/k8-edge-old.log"
  start_governed_edge "$ELOG_OLD" "$PKI_OLD_WIN" old || { tail -40 "$ELOG_OLD"; fail "K8 the predecessor edge did not reach ready"; }
  grep -q "\[BRIDGE\] OPC-UA identity $THUMB1" "$ELOG_OLD" || { tail -20 "$ELOG_OLD"; fail "K8 the predecessor edge announced the wrong thumbprint"; }
  BEFORE="$(applies "$ELOG_OLD")"
  pub 1500.0
  for i in $(seq 1 20); do [ "$(applies "$ELOG_OLD")" -gt "$BEFORE" ] && break; sleep 2; done
  [ "$(applies "$ELOG_OLD")" -gt "$BEFORE" ] \
    || { tail -40 "$ELOG_OLD"; fail "K8 the PREDECESSOR identity could not write while both are trusted"; }
  kill_by_jvmarg "heimdall.gate=KR8-old"
  sleep 3
  echo "[KR] K8: the predecessor wrote (the overlap holds)"

  # --- the SUCCESSOR writes too, on the same trust list ---
  ELOG_NEW="$WORK/k8-edge-new.log"
  start_governed_edge "$ELOG_NEW" "$PKI_WIN" new || { tail -40 "$ELOG_NEW"; fail "K8 the renewed edge did not reach ready"; }
  grep -q "\[BRIDGE\] OPC-UA identity $THUMB2" "$ELOG_NEW" || { tail -20 "$ELOG_NEW"; fail "K8 the renewed edge announced the wrong thumbprint"; }
  BEFORE="$(applies "$ELOG_NEW")"
  pub 1600.0
  for i in $(seq 1 20); do [ "$(applies "$ELOG_NEW")" -gt "$BEFORE" ] && break; sleep 2; done
  [ "$(applies "$ELOG_NEW")" -gt "$BEFORE" ] \
    || { tail -40 "$ELOG_NEW"; fail "K8 the RENEWED identity could not write - the rotation stopped the line"; }
  kill_by_jvmarg "heimdall.gate=KR8-new"
  sleep 3
  echo "[KR] K8: the successor wrote (the cutover works)"

  # --- a third identity is still refused: the trust list is a list, not "everybody" ---
  ELOG_3="$WORK/k8-edge-third.log"
  start_governed_edge "$ELOG_3" "$PKI_THIRD_WIN" third || true
  BEFORE="$(applies "$ELOG_3")"
  pub 1700.0
  sleep 12
  [ "$(applies "$ELOG_3")" = "$BEFORE" ] \
    || { tail -40 "$ELOG_3"; fail "K8 an UNTRUSTED identity applied a write - the list admits everybody"; }
  kill_by_jvmarg "heimdall.gate=KR8-third"
  echo "[KR] K8: the untrusted third identity applied nothing"

  kill_by_mainclass "bifrost-sim.jar" || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
  K8_RAN=1
  echo "[KR] K8 => PASS (both thumbprints write, a third does not)"
fi

echo ""
echo "[KR] GATE PASS (K1-K7 K9 K10${K8_RAN:+ +K8})"
exit 0
