#!/usr/bin/env bash
# Admits and publishes the two Line2 definition candidates Mimir derives (station-model, tool-model).
#
#   scripts/fixtures/line2/candidates/       the Mimir files, byte for byte, and a SOURCE note
#   scripts/fixtures/line2/schema-registry/  `gates schema --promote` of both under FORWARD
#   scripts/fixtures/line2/published/        `gates provenance publish` pairs, recipe/<ref>/1.0.0/
#
# The source repo of the publish is a Mimir checkout (MIMIR_DIR, default ../mimir), so defRef is the
# Mimir commit that last changed each file and sourcePath is fixtures/line2/<file>.
#
#   bash scripts/publish-line2-definitions.sh            # rewrite the three directories
#   bash scripts/publish-line2-definitions.sh --check    # compare them with a fresh run, exit 1 on any difference
#
# --check ignores only publishedAt (a time) and the SOURCE line naming the Mimir HEAD.
set -euo pipefail
cd "$(dirname "$0")/.."

# cygpath exists only under Git Bash / Cygwin. Elsewhere a POSIX path is already what the JVM
# wants, so shim it to identity (drop the -m, keep the last argument).
command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

OUT="scripts/fixtures/line2"
WORK="build/line2-definitions"
GATES_JAR="gates/target/bifrost-gates.jar"
MIMIR_DIR="${MIMIR_DIR:-../mimir}"
REFS="station-model tool-model"
VERSION="1.0.0"

fail() { echo "[LINE2] FAIL: $*"; exit 1; }

[ -d "$MIMIR_DIR/fixtures/line2" ] || fail "no Mimir checkout at $MIMIR_DIR (set MIMIR_DIR)"
MIMIR_ABS="$(cd "$MIMIR_DIR" && pwd)"
MIMIR_WIN="$(cygpath -m "$MIMIR_ABS")"

if [ ! -f "$GATES_JAR" ]; then
  mvn -q -pl core,gates install -DskipTests
fi
[ -f "$GATES_JAR" ] || fail "$GATES_JAR missing after build"
GJ="$(cygpath -m "$(pwd)/$GATES_JAR")"

sha() { sha256sum "$1" | awk '{print $1}'; }

# derive <dir>: write candidates/, schema-registry/ and published/ under <dir>.
derive() {
  local d="$1" ref src head
  rm -rf "$d"; mkdir -p "$d/candidates" "$d/schema-registry" "$d/published"
  head="$(git -C "$MIMIR_ABS" rev-parse HEAD)"
  {
    echo "Copied byte for byte from yggdrasil-iiot/mimir by scripts/publish-line2-definitions.sh."
    echo "mimir HEAD: $head"
    echo "commit = the last commit that changed the file; provenance publish records it as defRef."
  } > "$d/candidates/SOURCE"
  echo '{"mode":"FORWARD"}' > "$d/schema-registry/policy.json"
  local reg_win pub_win
  reg_win="$(cygpath -m "$(pwd)/$d/schema-registry")"
  pub_win="$(cygpath -m "$(pwd)/$d/published")"
  for ref in $REFS; do
    src="fixtures/line2/$ref-$VERSION.json"
    [ -z "$(git -C "$MIMIR_ABS" status --porcelain -- "$src")" ] || fail "$src is dirty in $MIMIR_DIR"
    cp "$MIMIR_ABS/$src" "$d/candidates/$ref-$VERSION.json"
    echo "$src commit=$(git -C "$MIMIR_ABS" log -1 --format=%H -- "$src") sha256=$(sha "$MIMIR_ABS/$src")" \
      >> "$d/candidates/SOURCE"
    java -jar "$GJ" schema "$reg_win" "$(cygpath -m "$(pwd)/$d/candidates/$ref-$VERSION.json")" --promote \
      || fail "schema gate refused $ref@$VERSION"
    [ -f "$d/schema-registry/udt/$ref/$VERSION.json" ] || fail "schema gate did not promote $ref@$VERSION"
    java -jar "$GJ" provenance publish "$pub_win" "$MIMIR_WIN" "$src" "$ref" "$VERSION" \
      || fail "provenance publish $ref@$VERSION returned non-zero"
  done
}

if [ "$CHECK" = "0" ]; then
  derive "$WORK"
  rm -rf "$OUT/candidates" "$OUT/schema-registry" "$OUT/published"
  mkdir -p "$OUT"
  cp -r "$WORK/candidates" "$WORK/schema-registry" "$WORK/published" "$OUT/"
  echo "[LINE2] wrote $OUT/{candidates,schema-registry,published}"
  exit 0
fi

derive "$WORK"
rc=0
no_head() { grep -v '^mimir HEAD: ' "$1"; }
cmp -s <(no_head "$OUT/candidates/SOURCE") <(no_head "$WORK/candidates/SOURCE") \
  || { echo "[LINE2] DIFF candidates/SOURCE"; rc=1; }
diff -r "$OUT/schema-registry" "$WORK/schema-registry" >/dev/null \
  || { echo "[LINE2] DIFF schema-registry"; rc=1; }
no_time() { grep -v '"publishedAt"' "$1"; }
for ref in $REFS; do
  src="fixtures/line2/$ref-$VERSION.json"
  pair="$OUT/published/recipe/$ref/$VERSION"
  cmp -s "$OUT/candidates/$ref-$VERSION.json" "$MIMIR_ABS/$src" \
    || { echo "[LINE2] DIFF candidates/$ref-$VERSION.json vs Mimir $src"; rc=1; }
  cmp -s "$pair/recipe-setpoints.yaml" "$WORK/published/recipe/$ref/$VERSION/recipe-setpoints.yaml" \
    || { echo "[LINE2] DIFF $pair/recipe-setpoints.yaml"; rc=1; }
  cmp -s <(no_time "$pair/manifest.json") <(no_time "$WORK/published/recipe/$ref/$VERSION/manifest.json") \
    || { echo "[LINE2] DIFF $pair/manifest.json (fields other than publishedAt)"; rc=1; }
  grep -q "\"contentSha256\" : \"$(sha "$pair/recipe-setpoints.yaml")\"" "$pair/manifest.json" \
    || { echo "[LINE2] $pair: contentSha256 is not the sha256 of recipe-setpoints.yaml"; rc=1; }
  grep -q "\"defRef\" : \"$(git -C "$MIMIR_ABS" log -1 --format=%H -- "$src")\"" "$pair/manifest.json" \
    || { echo "[LINE2] $pair: defRef is not the Mimir commit of $src"; rc=1; }
  java -jar "$GJ" provenance verify "$(cygpath -m "$(pwd)/$OUT/published")" "$ref" \
    || { echo "[LINE2] provenance verify $ref refused"; rc=1; }
done
[ "$rc" = "0" ] || fail "committed Line2 definitions differ from a fresh admit and publish"
echo "[LINE2] PASS publish-line2-definitions.sh --check"
