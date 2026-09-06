#!/usr/bin/env bash
# FEDERATION AUDIT BENCHMARK: what does `gates federation audit` cost as the number of sites grows?
#
# This is not a gate. It asserts nothing and always exits 0; it prints numbers so that
# docs/ENTERPRISE.md §11 cites a measurement anyone can repeat rather than a claim.
#
#   bash scripts/bench-federation.sh
#   MAXN=100 SITES="1 5 25" bash scripts/bench-federation.sh
#
# `federation audit` reads each site's activation ledger and rolls it up (FederationAudit.merge).
# It verifies nothing — no chain walk, no signature check — so the only cost that can scale is
# reading and parsing lines. That makes TOTAL ENTRIES the quantity to test against, not site count,
# and the two sweeps below split the same totals differently on purpose.
#
# The ledger is built ONCE by real signed activations and then copied into each site directory:
# every site holds a genuine signed ledger, and the copy is sound precisely because audit is
# read-only. Building one 200-entry signed ledger is ~5 minutes of JVM starts; building 100 of
# them would be a day.
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument) rather than making every
# call site conditional. Without this this script only runs on Windows.
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

FIX="scripts/fixtures/activation"
WORK="target/bench-federation"
JAR="gates/target/bifrost-gates.jar"
MAXN="${MAXN:-200}"                       # entries in the staged ledger = the deepest per-site ledger
SITES="${SITES:-1 2 5 10 25 50 100}"      # sweep A: site count, each site at MAXN entries
DEPTHS="${DEPTHS:-25 50 100 200}"         # sweep B: per-site depth, at a fixed site count
FIXED_SITES="${FIXED_SITES:-25}"

[ -f "$JAR" ] || mvn -q -pl core,gates -am install
JARW="$(cygpath -m "$(pwd)/$JAR")"

ms()      { date +%s%3N; }
median3() { printf '%s\n' "$@" | sort -n | sed -n 2p; }

# ---------------------------------------------------------------------------
# stage: one real signed ledger of MAXN entries
rm -rf "$WORK"
STAGE="$WORK/stage"
mkdir -p "$STAGE/udt/Line1-Mixer" "$STAGE/conformance/Line1-Mixer" "$STAGE/spec/mix-recipe" \
         "$STAGE/identity" "$WORK/keys"
cp "$FIX/udt-Line1-Mixer.json"       "$STAGE/udt/Line1-Mixer/1.0.0.json"
cp "$FIX/conformance-recipe.json"    "$STAGE/conformance/Line1-Mixer/recipe.json"
cp "$FIX/spec-mix-recipe-1.0.0.json" "$STAGE/spec/mix-recipe/1.0.0.json"
cp "$FIX/spec-mix-recipe-1.1.0.json" "$STAGE/spec/mix-recipe/1.1.0.json"
cp "$FIX/policy.json"                "$STAGE/policy.json"

KEYSW="$(cygpath -m "$(pwd)/$WORK/keys")"
java -jar "$JARW" identity keygen alice --out "$KEYSW" >  "$STAGE/identity/authorized-keys.jsonl" 2>/dev/null
java -jar "$JARW" identity keygen bob   --out "$KEYSW" >> "$STAGE/identity/authorized-keys.jsonl" 2>/dev/null
cat > "$STAGE/identity/activation-policy.json" <<'JSON'
{"version":"1","default":"deny","rules":[
  {"id":"r-activate","principal":"alice","action":"activate","target":"Line1","kind":"recipe","ref":"mix-recipe"},
  {"id":"r-approve","principal":"bob","action":"approve","target":"Line1","kind":"recipe","ref":"mix-recipe"}
]}
JSON

STAGEW="$(cygpath -m "$(pwd)/$STAGE")"
echo "# staging one signed ledger of $MAXN entries (one JVM start each) ..." >&2
for ((i=0; i<MAXN; i++)); do
  if [ $((i % 2)) -eq 0 ]; then v=1.0.0; else v=1.1.0; fi
  java -jar "$JARW" activate "$STAGEW" Line1 recipe mix-recipe "$v" \
       --by alice --approved-by bob \
       --by-key "$KEYSW/alice.key" --approved-by-key "$KEYSW/bob.key" >/dev/null 2>&1
done
LEDGER="$STAGE/activation/Line1.jsonl"
echo "# staged: $(wc -l < "$LEDGER") entries, $(wc -c < "$LEDGER") bytes" >&2

# ---------------------------------------------------------------------------
# Bare JVM start, doing no work at all: the floor every CLI measurement below sits on.
base=(); for _ in 1 2 3; do t0=$(ms); java -jar "$JARW" >/dev/null 2>&1 || true; t1=$(ms); base+=($((t1-t0))); done
BASE="$(median3 "${base[@]}")"
echo "# bare JVM start (median of 3): $BASE ms"

# build S site dirs each holding the first N lines of the staged ledger, then time the audit.
run_audit() {  # $1=sites $2=entries-per-site  -> echoes median ms
  local s="$1" n="$2" d="$WORK/sites" i args=() runs=()
  rm -rf "$d"
  for ((i=0; i<s; i++)); do
    mkdir -p "$d/s$i/activation"
    head -n "$n" "$LEDGER" > "$d/s$i/activation/Line1.jsonl"
    args+=(--site "s$i=$(cygpath -m "$(pwd)/$d/s$i")")
  done
  for _ in 1 2 3; do
    t0=$(ms); java -jar "$JARW" federation audit Line1 "${args[@]}" >/dev/null 2>&1; t1=$(ms)
    runs+=($((t1-t0)))
  done
  median3 "${runs[@]}"
}

echo "sweep,sites,entries_per_site,total_entries,audit_ms,minus_jvm_ms"
for s in $SITES; do
  t="$(run_audit "$s" "$MAXN")"
  echo "A,$s,$MAXN,$((s*MAXN)),$t,$((t-BASE))"
done
for n in $DEPTHS; do
  t="$(run_audit "$FIXED_SITES" "$n")"
  echo "B,$FIXED_SITES,$n,$((FIXED_SITES*n)),$t,$((t-BASE))"
done
