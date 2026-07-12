#!/usr/bin/env bash
# FEDERATION GATE (multi-site): prove ENTERPRISE (not single-line) governance — two per-site
# brokers/edges consuming ONE federated Bifrost authority — by recombining existing primitives
# (T1 template conformance, T7 git anchor, per-site Heimdall). Modeled on run-anchored-activation-gate.sh
# (same JAR build / registry-staging / cygpath / broker+sim harness).
#
# Topology (one machine): an ENTERPRISE git registry (authority) + a separate ENTERPRISE anchor repo;
# two SITE mirror-clones (busan, ulsan), each a full local clone (local-first). Identity trust
# (authorized-keys + activation-policy) federates DOWN with the mirror; each site's activation ledger
# is per-site and anchored UP to the enterprise anchor.
#
# Assertions (F1/F5/F6 pure CLI, ALWAYS run; F2/F3/F4 runtime, Docker-gated + skippable):
#   F1  enterprise template governs both sites. Each site's conforming specialization passes
#       site ⊨ enterprise (T1); a non-conforming specialization is REJECTED (exit 1).
#   F5  cross-domain anchor rollback. A site insider co-rolls-back the site's local ledger+head+anchor;
#       the ENTERPRISE anchor (a different trust domain) still witnesses the higher seq
#       -> verify-anchored --anchor-store git BROKEN identity.anchor.rollback (exit 1).
#       HONEST: this is AN3 re-run with the anchor RELOCATED to the enterprise domain. The
#       "cannot rewrite" is TOPOLOGICAL (a separate repo the site never rewrites), NOT cryptographic
#       — true closure needs a protected off-box remote, out of scope exactly as in T7.
#   F6  enterprise federated audit. `gates federation audit` aggregates both sites' activation ledgers
#       into one cross-site view (who has what active, where).
#   F2  governance propagation. Enterprise updates policy -> site `git pull` -> takes effect at the
#       site's next Heimdall RESTART (Heimdall reads policy/conformance/ledger/anchor once at start).
#   F3  per-site independent activation + enforcement. Each site's Heimdall binds ITS OWN activated
#       version; a rogue command at a site is denied independently (deny-by-default).
#   F4  local-first (WAN outage). Cut a site's enterprise link -> the site's broker+sim+Heimdall keep
#       serving from the local clone.
#
# Run from anywhere:
#   bash scripts/run-federation-gate.sh                 # F2/F3/F4 run if Docker Desktop is up
#   SKIP_RUNTIME=1 bash scripts/run-federation-gate.sh  # force pure-CLI only (F1 F5 F6)
#   # expect: [FED] GATE PASS (F1 F5 F6 [+F2 F3 F4])  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="build/fed-gate"
SIM_A_LOG="$WORK/sim-busan.log"
SIM_B_LOG="$WORK/sim-ulsan.log"
BLOG_A="$WORK/bridge-busan.log"
BLOG_B="$WORK/bridge-ulsan.log"

SIM_A_PID=""; SIM_B_PID=""; BRIDGE_A_PID=""; BRIDGE_B_PID=""; COMPOSE_WIN=""

command -v python >/dev/null 2>&1 || { echo "[FED] FAIL: python not found on PATH"; exit 1; }

fail() {
  echo "[FED] FAIL: $*"
  for f in "$SIM_A_LOG" "$SIM_B_LOG" "$BLOG_A" "$BLOG_B"; do
    [ -f "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -40 "$f" 2>/dev/null; } || true
  done
  exit 1
}

kill_by_mainclass() {  # $1=substring of the jps -lm main-class/jar line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

cleanup() {
  for p in "$SIM_A_PID" "$SIM_B_PID" "$BRIDGE_A_PID" "$BRIDGE_B_PID"; do
    [ -n "$p" ] && taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "bifrost-heimdall.jar" || true
  [ -n "$COMPOSE_WIN" ] && docker compose -f "$COMPOSE_WIN" stop hivemq-ce hivemq-ce-b >/dev/null 2>&1 || true
}
trap cleanup EXIT

kill_by_mainclass "bifrost-sim.jar" || true
kill_by_mainclass "bifrost-heimdall.jar" || true

# ---------------------------------------------------------------------------
echo "[FED] step 0: build core+gates(+heimdall+sim) jars"
mvn -q -pl core,gates,heimdall,sim -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ]       || fail "gates jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

FIX="scripts/fixtures/activation"
[ -d "$FIX" ] || fail "fixture dir $FIX missing"

# git identity for the repos this gate creates (GitAnchorStore configures its own repo separately).
gitcfg() {  # $1 = repo dir (bash path)
  git -C "$1" config core.autocrlf false
  git -C "$1" config user.email fed-gate@local
  git -C "$1" config user.name  fed-gate
}

# ---------------------------------------------------------------------------
echo "[FED] step 1: keygen alice/bob -> enterprise authorized-keys.jsonl"
rm -rf "$WORK"
mkdir -p "$WORK"
KEYS="$WORK/keys"; mkdir -p "$KEYS"
KEYS_WIN="$(cygpath -m "$(pwd)/$KEYS")"
AKF="$WORK/authorized-keys.jsonl"; : > "$AKF"
gates identity keygen alice --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
gates identity keygen bob   --out "$KEYS_WIN" >>"$AKF" 2>/dev/null
grep -q '"alice"' "$AKF" && grep -q '"bob"' "$AKF" || fail "authorized-keys.jsonl not built with alice/bob"
echo "[FED] keys ready (alice activator, bob approver — both enterprise-registered)"

# ---------------------------------------------------------------------------
echo "[FED] step 2: build the ENTERPRISE git registry (authority) + enterprise anchor"
ENT="$WORK/enterprise"
mkdir -p "$ENT/udt/Mixer" "$ENT/udt/Line1-Mixer" "$ENT/conformance/Line1-Mixer" \
         "$ENT/spec/mix-recipe" "$ENT/identity"

# F1 enterprise TEMPLATE: Mixer@1.0.0 — the envelope each site must conform to (Rpm 0-3000, Temp 0-450).
cat > "$ENT/udt/Mixer/1.0.0.json" <<'JSON'
{
  "templateRef": "Mixer",
  "version": "1.0.0",
  "members": [
    { "name": "Rpm",  "type": "Double", "semanticId": "urn:bifrost:sem:Mixer/Rpm",  "range": { "low": 0, "high": 3000 } },
    { "name": "Temp", "type": "Double", "semanticId": "urn:bifrost:sem:Mixer/Temp", "range": { "low": 0, "high": 450 } }
  ],
  "params": [],
  "conformsTo": null
}
JSON

# runtime fixtures (F3 Heimdall bind): equipment udt + recipe conformance + recipe spec artifacts + command policy.
cp "$FIX/udt-Line1-Mixer.json"       "$ENT/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"    "$ENT/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json" "$ENT/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json" "$ENT/spec/mix-recipe/1.1.0.json"
# command policy — PER-SITE scoped slices (each site enforces the rule keyed to its own group/edge).
cat > "$ENT/policy.json" <<'JSON'
{
  "version": "1.0.0",
  "rules": [
    { "id": "busan-rpm", "principal": "recipe-writer", "target": { "group": "Bifrost:busan", "edge": "recipe-edge" },
      "command": "ns=2;s=Recipe/Rpm", "constraint": { "type": "Double" } },
    { "id": "ulsan-rpm", "principal": "recipe-writer", "target": { "group": "Bifrost:ulsan", "edge": "recipe-edge" },
      "command": "ns=2;s=Recipe/Rpm", "constraint": { "type": "Double" } }
  ],
  "default": "deny"
}
JSON
cp "$AKF"                            "$ENT/identity/authorized-keys.jsonl"
# T6 deny-by-default activation policy (federates DOWN with the mirror): alice=activate, bob=approve.
cat > "$ENT/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON

git -C "$ENT" init -q
gitcfg "$ENT"
git -C "$ENT" add -A
git -C "$ENT" commit -qm "enterprise governed registry seed"
echo "[FED] enterprise registry committed (templates + policy + identity + recipe artifacts)"

# enterprise anchor domain: PER-SITE anchor repos under one enterprise-owned dir (different trust
# domain than the site clones). Per-site because the anchor's seq is monotonic PER TARGET — both sites
# activate the same target Line1, so a single shared anchor would collide; the enterprise witnesses each
# site's ledger in its own anchor repo (still off the site's own registry).
ENT_ANCHOR="$WORK/enterprise-anchor"
mkdir -p "$ENT_ANCHOR"
ENT_ANCHOR_BUSAN_WIN="$(cygpath -m "$(pwd)/$ENT_ANCHOR/busan")"
ENT_ANCHOR_ULSAN_WIN="$(cygpath -m "$(pwd)/$ENT_ANCHOR/ulsan")"

# ---------------------------------------------------------------------------
echo "[FED] step 3: mirror-clone the enterprise registry to two SITES (full clone = local-first)"
ENT_WIN="$(cygpath -m "$(pwd)/$ENT")"
git clone -q -c core.autocrlf=false "$ENT_WIN" "$WORK/site-busan"
git clone -q -c core.autocrlf=false "$ENT_WIN" "$WORK/site-ulsan"
gitcfg "$WORK/site-busan"
gitcfg "$WORK/site-ulsan"
BUSAN_WIN="$(cygpath -m "$(pwd)/$WORK/site-busan")"
ULSAN_WIN="$(cygpath -m "$(pwd)/$WORK/site-ulsan")"
echo "[FED] sites cloned: busan, ulsan"

# convenience: signed activation of a recipe version on a site clone, anchored to that site's
# enterprise anchor repo.
sactivate_ent() {  # $1=siteRegWin $2=siteAnchorWin $3=version [extra args...]
  local reg="$1" anc="$2" ver="$3"; shift 3
  gates activate "$reg" Line1 recipe mix-recipe "$ver" \
        --by alice --approved-by bob \
        --by-key "$KEYS_WIN/alice.key" --approved-by-key "$KEYS_WIN/bob.key" \
        --anchor-store git --anchor-dir "$anc" "$@"
}

# python helpers (from the anchored gate) --------------------------------------
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
echo "[FED] ===== F1: enterprise template governs both sites (site ⊨ enterprise) ====="
# per site: a CONFORMING specialization (tightens Rpm 0-2500 within the 0-3000 envelope) and a
# VIOLATING one (widens Rpm high to 4000 > 3000 envelope). semanticId/type must match the template.
mk_site_def() {  # $1=out file  $2=rpm-high
  cat > "$1" <<JSON
{
  "templateRef": "Line1-Mixer-site",
  "version": "1.0.0",
  "members": [
    { "name": "Rpm",  "type": "Double", "semanticId": "urn:bifrost:sem:Mixer/Rpm",  "range": { "low": 0, "high": $2 } },
    { "name": "Temp", "type": "Double", "semanticId": "urn:bifrost:sem:Mixer/Temp", "range": { "low": 0, "high": 450 } }
  ],
  "params": [],
  "conformsTo": "Mixer@1.0.0"
}
JSON
}
for site in busan ulsan; do
  reg_win="$(cygpath -m "$(pwd)/$WORK/site-$site")"
  mk_site_def "$WORK/$site-def-ok.json"  2500
  mk_site_def "$WORK/$site-def-bad.json" 4000
  set +e
  gates template "$reg_win" "$(cygpath -m "$(pwd)/$WORK/$site-def-ok.json")"  >"$WORK/f1-$site-ok.txt"  2>&1; rc_ok=$?
  gates template "$reg_win" "$(cygpath -m "$(pwd)/$WORK/$site-def-bad.json")" >"$WORK/f1-$site-bad.txt" 2>&1; rc_bad=$?
  set -e
  [ "$rc_ok" -eq 0 ] || { cat "$WORK/f1-$site-ok.txt"; fail "F1 $site conforming def expected exit 0"; }
  grep -q "PASS" "$WORK/f1-$site-ok.txt" || { cat "$WORK/f1-$site-ok.txt"; fail "F1 $site conforming def missing PASS"; }
  [ "$rc_bad" -eq 1 ] || { cat "$WORK/f1-$site-bad.txt"; fail "F1 $site non-conforming def expected exit 1"; }
  grep -q "exceeds-envelope" "$WORK/f1-$site-bad.txt" || { cat "$WORK/f1-$site-bad.txt"; fail "F1 $site violation not range-envelope"; }
done
echo "[FED] F1 => PASS (both sites conform to the enterprise template; non-conforming rejected)"

# ---------------------------------------------------------------------------
echo "[FED] ===== F5: cross-domain anchor rollback caught by the ENTERPRISE anchor ====="
# busan: two signed activations to the enterprise anchor, snapshot seq0, activate seq1, then co-rollback
# the site's LOCAL ledger+head to seq0. The enterprise anchor (separate repo) still witnesses seq1.
set +e
sactivate_ent "$BUSAN_WIN" "$ENT_ANCHOR_BUSAN_WIN" 1.0.0 >"$WORK/f5-act0.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/f5-act0.txt"; fail "F5 busan first signed activate expected 0"; }
grep -q "signed=true" "$WORK/f5-act0.txt" || { cat "$WORK/f5-act0.txt"; fail "F5 activate not signed"; }
SNAP="$WORK/f5-snap"; mkdir -p "$SNAP"
cp "$WORK/site-busan/activation/Line1.jsonl" "$SNAP/Line1.jsonl"
cp "$WORK/site-busan/identity/Line1.head"    "$SNAP/Line1.head"
sactivate_ent "$BUSAN_WIN" "$ENT_ANCHOR_BUSAN_WIN" 1.1.0 >/dev/null 2>&1   # busan enterprise anchor now seq1
# co-rollback the site's local state to seq0 (enterprise anchor untouched).
cp "$SNAP/Line1.jsonl" "$WORK/site-busan/activation/Line1.jsonl"
cp "$SNAP/Line1.head"  "$WORK/site-busan/identity/Line1.head"
set +e
gates identity verify-anchored "$BUSAN_WIN" Line1 --anchor-store git --anchor-dir "$ENT_ANCHOR_BUSAN_WIN" >"$WORK/f5-va.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$WORK/f5-va.txt"; fail "F5 verify-anchored expected exit 1"; }
grep -q "identity.anchor.rollback" "$WORK/f5-va.txt" || { cat "$WORK/f5-va.txt"; fail "F5 missing identity.anchor.rollback"; }
echo "[FED] F5 => PASS (enterprise anchor catches the site co-rollback, exit 1)"
echo "[FED] NOTE: F5 un-rewritability is TOPOLOGICAL (enterprise anchor is a separate repo the site"
echo "[FED]       never rewrites), NOT cryptographic — production needs a protected off-box remote"
echo "[FED]       (out of scope, same honest residual as T7)."

# ---------------------------------------------------------------------------
echo "[FED] ===== F6: enterprise federated audit across both sites ====="
# give ulsan its own independent ledger (1.0.0 then 1.1.0) so the audit shows DIFFERENT per-site state:
# busan active=1.0.0 (post-rollback, 1 event) vs ulsan active=1.1.0 (2 events).
sactivate_ent "$ULSAN_WIN" "$ENT_ANCHOR_ULSAN_WIN" 1.0.0 >/dev/null 2>&1
sactivate_ent "$ULSAN_WIN" "$ENT_ANCHOR_ULSAN_WIN" 1.1.0 >/dev/null 2>&1
set +e
gates federation audit Line1 --site busan="$BUSAN_WIN" --site ulsan="$ULSAN_WIN" >"$WORK/f6.txt" 2>&1; rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/f6.txt"; fail "F6 federation audit expected exit 0"; }
grep -q "sites=2" "$WORK/f6.txt" || { cat "$WORK/f6.txt"; fail "F6 audit did not report 2 sites"; }
grep -q "site=busan" "$WORK/f6.txt" && grep -q "site=ulsan" "$WORK/f6.txt" || { cat "$WORK/f6.txt"; fail "F6 audit missing a site"; }
grep -q "site=ulsan active=1.1.0" "$WORK/f6.txt" || { cat "$WORK/f6.txt"; fail "F6 ulsan not active=1.1.0"; }
echo "[FED] F6 => PASS (cross-site audit view):"
sed 's/^/[FED]   /' "$WORK/f6.txt"

# ===========================================================================
# F2/F3/F4 — runtime legs (Docker-gated + skippable)
# ===========================================================================
RUNTIME_RAN=""
if [ -n "${SKIP_RUNTIME:-}" ]; then
  echo "[FED] F2/F3/F4 skipped (SKIP_RUNTIME set)"
elif ! command -v docker >/dev/null 2>&1; then
  echo "[FED] F2/F3/F4 skipped (no docker)"
else
  ENT_WIN="$(cygpath -m "$(pwd)/$ENT")"
  bash scripts/_federation-runtime.sh "$GATES_JAR_WIN" "$KEYS_WIN" "$ENT_WIN" "$WORK" \
    && RUNTIME_RAN=1 || fail "F2/F3/F4 runtime leg failed"
fi

echo ""
echo "[FED] GATE PASS (F1 F5 F6${RUNTIME_RAN:+ +F2 F3 F4})"
exit 0
