#!/usr/bin/env bash
# Runtime legs (F2/F3/F4) of run-federation-gate.sh — split out to keep the main gate readable.
# Two per-site brokers + sims + Heimdalls consuming their own mirror clone. Docker-gated (the caller
# only invokes this when docker is present). Modeled on run-anchored-activation-gate.sh's AN8 leg
# (heimdall+sim+broker staged from a registry) + run-yggdrasil-full-loop-gate.sh's RogueNcmd publisher.
#
# Args (all from the caller): $1=GATES_JAR_WIN $2=KEYS_WIN $3=ENT_WIN(enterprise git repo, win path
# to clone from) $4=WORK(bash path, build/fed-gate)
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this these gates only run on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s
' "${@: -1}"; }

GATES_JAR_WIN="$1"; KEYS_WIN="$2"; ENT_WIN="$3"; WORK="$4"
ENT="$WORK/enterprise"                       # bash path to the enterprise repo (for F2 edit / F4 outage)

SIM_A_LOG="$WORK/sim-busan.log"; SIM_B_LOG="$WORK/sim-ulsan.log"
BLOG_A="$WORK/bridge-busan.log"; BLOG_B="$WORK/bridge-ulsan.log"
SIM_A_PID=""; SIM_B_PID=""; BRIDGE_A_PID=""; BRIDGE_B_PID=""; COMPOSE_WIN=""

gates() { java -jar "$GATES_JAR_WIN" "$@"; }

fail() {
  echo "[FED] FAIL(runtime): $*"
  for f in "$SIM_A_LOG" "$SIM_B_LOG" "$BLOG_A" "$BLOG_B"; do
    [ -f "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -30 "$f" 2>/dev/null; } || true
  done
  exit 1
}
kill_by_mainclass() {
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
  # restore the enterprise repo if an F4 outage left it moved.
  [ -d "$ENT.off" ] && [ ! -d "$ENT" ] && mv "$ENT.off" "$ENT" || true
}
trap cleanup EXIT

echo "[FED] runtime: build heimdall + sim jars"
mvn -q -pl heimdall,sim -am install -DskipTests
[ -f heimdall/target/bifrost-heimdall.jar ] || fail "heimdall jar missing"
[ -f sim/target/bifrost-sim.jar ]           || fail "sim jar missing"
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

gitcfg() { git -C "$1" config core.autocrlf false; git -C "$1" config user.email fed-gate@local; git -C "$1" config user.name fed-gate; }

# fresh runtime clones (isolated from F5's tamper state) --------------------
echo "[FED] runtime: fresh mirror clones rt-busan / rt-ulsan"
rm -rf "$WORK/rt-busan" "$WORK/rt-ulsan"
# clone with autocrlf=false so the working tree keeps LF (matching the committed blobs); otherwise a
# global autocrlf=true rewrites checked-out files to CRLF, which git then reports as local changes and
# a later `git pull` (F2) refuses to overwrite.
git clone -q -c core.autocrlf=false "$ENT_WIN" "$WORK/rt-busan"
git clone -q -c core.autocrlf=false "$ENT_WIN" "$WORK/rt-ulsan"
gitcfg "$WORK/rt-busan"; gitcfg "$WORK/rt-ulsan"
RT_BUSAN_WIN="$(cygpath -m "$(pwd)/$WORK/rt-busan")"
RT_ULSAN_WIN="$(cygpath -m "$(pwd)/$WORK/rt-ulsan")"

sactivate() {  # $1=regWin $2=version  (signed, file anchor; REQUIRE_ANCHORED off so bind needs no anchor)
  gates activate "$1" Line1 recipe mix-recipe "$2" --by alice --approved-by bob \
        --by-key "$KEYS_WIN/alice.key" --approved-by-key "$KEYS_WIN/bob.key"
}
echo "[FED] runtime: per-site activation (busan=1.0.0, ulsan=1.1.0)"
sactivate "$RT_BUSAN_WIN" 1.0.0 >/dev/null 2>&1 || fail "busan runtime activate failed"
sactivate "$RT_ULSAN_WIN" 1.1.0 >/dev/null 2>&1 || fail "ulsan runtime activate failed"

# brokers -------------------------------------------------------------------
echo "[FED] runtime: start both brokers (:1883 busan, :1884 ulsan)"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce hivemq-ce-b >/dev/null 2>&1 || fail "failed to start brokers"
for port in 1883 1884; do
  ok=0
  for i in $(seq 1 30); do
    bash -c "echo > /dev/tcp/localhost/$port" >/dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { docker compose -f "$COMPOSE_WIN" logs --tail 30 2>/dev/null || true; fail "broker :$port did not open"; }
done
# TCP-open != MQTT-ready: HiveMQ CE is secure-by-default and only accepts CONNECT once the bundled
# allow-all extension has loaded (a few seconds after the listener opens). Settle before connecting.
sleep 8

# sims ----------------------------------------------------------------------
echo "[FED] runtime: start both sims (:48400 busan, :48401 ulsan)"
: > "$SIM_A_LOG"; : > "$SIM_B_LOG"
SIM_BIND_PORT=48400 java -jar "$SIM_JAR_WIN" >"$SIM_A_LOG" 2>&1 & SIM_A_PID=$!
SIM_BIND_PORT=48401 java -jar "$SIM_JAR_WIN" >"$SIM_B_LOG" 2>&1 & SIM_B_PID=$!
for lg in "$SIM_A_LOG" "$SIM_B_LOG"; do
  ok=0
  for i in $(seq 1 30); do grep -q "OPC-UA sim listening" "$lg" 2>/dev/null && { ok=1; break; }; sleep 1; done
  [ "$ok" = "1" ] || fail "sim did not start ($lg)"
done

wait_ready() {  # $1=log
  local ok=0
  for i in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$1" 2>/dev/null && { ok=1; break; }; sleep 2; done
  [ "$ok" = "1" ]
}
# $6 is the health port, with no default on purpose: two federated edges run side by side here and
# EdgeHealth binds eagerly, so a shared port kills the SECOND edge at startup with a BindException that
# reads like a federation fault. Every call site names its own port.
start_heimdall() {  # $1=logfile $2=mqtt $3=opcua $4=group $5=regBash $6=healthPort -> sets REPLY to the pid
  local reg_win; reg_win="$(cygpath -m "$(pwd)/$5")"
  : > "$1"
  MQTT_URL="$2" OPCUA_URL="$3" SPB_GROUP="$4" SPB_EDGE="recipe-edge" HEALTH_PORT="$6" \
  POLICY_PATH="$reg_win/policy.json" REGISTRY_PATH="$reg_win" \
  CONFORMANCE_PATH="$reg_win/conformance/Line1-Mixer/recipe.json" \
  ACTIVATION_PATH="$reg_win" ACTIVATION_TARGET="Line1" \
    java -jar "$HEIMDALL_JAR_WIN" >"$1" 2>&1 &
  REPLY=$!
}
# taskkill returns as soon as the kill is signalled, not when the JVM is gone, and EdgeHealth binds its
# port eagerly at startup. Restarting an edge without waiting therefore fails with a BindException that
# reads like a policy fault. Wait for the port to actually close.
stop_heimdall() {  # $1=pid $2=healthPort
  [ -n "$1" ] && { taskkill //F //T //PID "$1" >/dev/null 2>&1 || kill -9 "$1" >/dev/null 2>&1 || true; }
  # The shell's job pid is not always the JVM's Windows pid, and killing by main class is not an option
  # here: the OTHER site's edge is the same jar and must stay up for F4. The health port is the one
  # unambiguous handle -- whoever is LISTENING on it IS this edge.
  local t=0 owner
  while [ "$t" -lt 20 ]; do
    bash -c "echo > /dev/tcp/localhost/$2" >/dev/null 2>&1 || return 0
    owner="$( { netstat -ano 2>/dev/null || true; } | grep LISTENING | grep -E "[:.]$2[[:space:]]" \
              | awk '{print $NF}' | head -1 )"
    [ -n "$owner" ] && { taskkill //F //T //PID "$owner" >/dev/null 2>&1 || kill -9 "$owner" >/dev/null 2>&1 || true; }
    sleep 1; t=$((t+1))
  done
  fail "edge on health port $2 did not release it after being killed"
}
pub() {  # $1=mqtt $2=group $3=node $4=val $5=type
  MQTT_URL="$1" SPB_GROUP="$2" SPB_EDGE="recipe-edge" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$3" "$4" "$5" >>"$WORK/pub.log" 2>&1 || true
}
wait_grep() {  # $1=file $2=pattern $3=tries
  local t=0; while [ "$t" -lt "${3:-15}" ]; do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 1; t=$((t+1)); done; return 1
}
RPM="ns=2;s=Recipe/Rpm"; SECRET="ns=2;s=Recipe/Secret"

# ===========================================================================
echo "[FED] ===== F3: per-site independent activation + enforcement ====="
# start serially (busan ready before ulsan) so a startup race can't cross the two edges.
start_heimdall "$BLOG_A" "tcp://localhost:1883" "opc.tcp://localhost:48400" "Bifrost:busan" "$WORK/rt-busan" 9090; BRIDGE_A_PID=$REPLY
wait_ready "$BLOG_A" || fail "busan Heimdall not ready"
start_heimdall "$BLOG_B" "tcp://localhost:1884" "opc.tcp://localhost:48401" "Bifrost:ulsan" "$WORK/rt-ulsan" 9091; BRIDGE_B_PID=$REPLY
wait_ready "$BLOG_B" || fail "ulsan Heimdall not ready"
grep -q "activation bound mix-recipe@1.0.0" "$BLOG_A" || fail "F3 busan did not bind mix-recipe@1.0.0"
grep -q "activation bound mix-recipe@1.1.0" "$BLOG_B" || fail "F3 ulsan did not bind mix-recipe@1.1.0"
echo "[FED] F3: busan bound @1.0.0, ulsan bound @1.1.0 (independent per-site versions)"
# rogue deny, independently per site: a Secret command to busan is denied in busan's log, and does NOT
# appear in ulsan's log (the sites are isolated on separate brokers/groups).
pub "tcp://localhost:1883" "Bifrost:busan" "$SECRET" 1.0 Double
wait_grep "$BLOG_A" "\[BRIDGE\] DENY cmd=$SECRET" 15 || fail "F3 busan did not DENY the rogue Secret"
sleep 2
grep -q "\[BRIDGE\] DENY cmd=$SECRET" "$BLOG_B" && fail "F3 ulsan saw busan's rogue (sites not isolated)" || true
pub "tcp://localhost:1884" "Bifrost:ulsan" "$SECRET" 1.0 Double
wait_grep "$BLOG_B" "\[BRIDGE\] DENY cmd=$SECRET" 15 || fail "F3 ulsan did not DENY the rogue Secret"
echo "[FED] F3 => PASS (per-site bind + independent rogue deny)"

# ===========================================================================
echo "[FED] ===== F2: governance propagation (enterprise policy edit -> git pull -> restart) ====="
# baseline: an authorized Rpm command at busan APPLIES (busan-rpm rule present).
pub "tcp://localhost:1883" "Bifrost:busan" "$RPM" 1500 Double
wait_grep "$BLOG_A" "\[BRIDGE\] APPLY cmd=$RPM ok=true" 15 || fail "F2 baseline: busan did not APPLY an authorized Rpm"
echo "[FED] F2 baseline: busan APPLYs Rpm (rule present)"
# enterprise TIGHTENS the policy: remove busan's Rpm rule (Rpm now hits default-deny), commit.
cat > "$ENT/policy.json" <<'JSON'
{
  "version": "1.0.0",
  "rules": [
    { "id": "ulsan-rpm", "principal": "recipe-writer", "target": { "group": "Bifrost:ulsan", "edge": "recipe-edge" },
      "command": "ns=2;s=Recipe/Rpm", "constraint": { "type": "Double" } }
  ],
  "default": "deny"
}
JSON
git -C "$ENT" add -A; git -C "$ENT" commit -qm "tighten: revoke busan Rpm authorization"
git -C "$WORK/rt-busan" pull -q --no-edit || fail "F2 busan git pull failed"
grep -q "busan-rpm" "$WORK/rt-busan/policy.json" && fail "F2 pull did not remove busan-rpm from the clone" || true
echo "[FED] F2: enterprise revoked busan Rpm; busan pulled the change"
# restart busan Heimdall (Heimdall reads policy once at start — the change takes effect on RESTART).
stop_heimdall "$BRIDGE_A_PID" 9090
start_heimdall "$BLOG_A" "tcp://localhost:1883" "opc.tcp://localhost:48400" "Bifrost:busan" "$WORK/rt-busan" 9090; BRIDGE_A_PID=$REPLY
wait_ready "$BLOG_A" || fail "F2 busan Heimdall did not restart"
# now the SAME Rpm command is DENIED (propagated revocation in force).
pub "tcp://localhost:1883" "Bifrost:busan" "$RPM" 1500 Double
wait_grep "$BLOG_A" "\[BRIDGE\] DENY cmd=$RPM" 15 || fail "F2 busan still allows Rpm after the revocation propagated"
! grep -q "\[BRIDGE\] APPLY cmd=$RPM ok=true" "$BLOG_A" || fail "F2 busan APPLYed Rpm after revocation (post-restart log)"
echo "[FED] F2 => PASS (enterprise revocation propagated via git pull; enforced at next restart)"

# ===========================================================================
echo "[FED] ===== F4: local-first (WAN outage — site keeps enforcing offline) ====="
# simulate the enterprise link dropping: move the enterprise repo away (origin unreachable).
mv "$ENT" "$ENT.off"
set +e
git -C "$WORK/rt-ulsan" fetch -q 2>/dev/null; pull_rc=$?
set -e
[ "$pull_rc" -ne 0 ] || fail "F4 expected the enterprise fetch to FAIL while 'offline'"
echo "[FED] F4: enterprise unreachable — ulsan git fetch fails (as expected)"
# ulsan's Heimdall + broker + sim keep serving from the local clone: a rogue is still denied.
pub "tcp://localhost:1884" "Bifrost:ulsan" "$SECRET" 2.0 Double
wait_grep "$BLOG_B" "\[BRIDGE\] DENY cmd=$SECRET" 15 || fail "F4 ulsan stopped enforcing while offline"
DENY_COUNT=$(grep -c "\[BRIDGE\] DENY cmd=$SECRET" "$BLOG_B" 2>/dev/null || true)
[ "$DENY_COUNT" -ge 2 ] || fail "F4 ulsan did not process a NEW command offline (deny count=$DENY_COUNT)"
echo "[FED] F4: ulsan still enforces locally while offline"
# reconnect: restore the enterprise repo and fetch succeeds (reconcile).
mv "$ENT.off" "$ENT"
git -C "$WORK/rt-ulsan" fetch -q 2>/dev/null || fail "F4 reconnect: fetch did not succeed after the link restored"
echo "[FED] F4 => PASS (offline serving + reconnect reconcile)"

echo "[FED] runtime: F2 F3 F4 all PASS"
exit 0
