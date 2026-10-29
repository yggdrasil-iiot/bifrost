# Sourced by the gates that activate a recipe. Activation of kind recipe binds only a published canonical
# (recipe/<ref>/<version>/recipe-setpoints.yaml), so a gate publishes its MasterSpec fixture the way a site
# would: commit it to a throwaway source repo, then `gates provenance publish`.
#
#   publish_recipe <gates.jar> <registry> <spec.json> <ref> <version> [--by <principal> --by-key <keyFile>]
#
# <gates.jar> and <registry> are paths the JVM can open (cygpath -m on Windows). The source repo goes under
# PUBLISH_SRC_ROOT (default build/recipe-src), one per ref@version, with core.autocrlf off so the committed
# blob is byte-identical to the fixture. Extra arguments go to `provenance publish` unchanged (a signed publish).
publish_recipe() {
  local jar="$1" reg="$2" spec="$3" ref="$4" ver="$5"; shift 5
  local src="${PUBLISH_SRC_ROOT:-build/recipe-src}/$ref-$ver"
  rm -rf "$src"; mkdir -p "$src"
  git -C "$src" init -q
  git -C "$src" config core.autocrlf false
  git -C "$src" config user.email gate@local
  git -C "$src" config user.name gate
  cp "$spec" "$src/$ref.json"
  git -C "$src" add "$ref.json"
  git -C "$src" commit -qm "$ref $ver"
  java -jar "$jar" provenance publish "$reg" "$(cygpath -m "$(pwd)/$src")" "$ref.json" "$ref" "$ver" "$@" \
    || { echo "[GATE] FAIL: provenance publish $ref@$ver returned non-zero"; return 1; }
  [ -f "$(cygpath -u "$reg" 2>/dev/null || echo "$reg")/recipe/$ref/$ver/recipe-setpoints.yaml" ] \
    || { echo "[GATE] FAIL: provenance publish did not write recipe/$ref/$ver"; return 1; }
}
