#!/usr/bin/env bash
# HUGINN SEAM GATE (R7 acceptance): is the governed edge the only write path?
#
# ADOPTION.md calls this "the Huginn <-> Bifrost seam, including the surface mismatch" and
# hard-blocks phase 4 on it. The mismatch is deeper than vocabulary: Huginn decodes Modbus/S7comm
# and identifies by IP; Bifrost speaks MQTT then OPC-UA and identifies by principal. The two
# surfaces do not overlap on protocol AT ALL, so any design that maps the vocabularies is a lie --
# there is no shared observation to map.
#
# What the seam can honestly answer needs no overlap, and in fact the reverse: a Modbus or S7 write
# landing on governed equipment, over a protocol the edge does not even speak, IS the bypass.
# ENTERPRISE.md already says that blind spot is Huginn's reason to exist.
#
# The one irreducible input is DECLARED, not discovered: which governed equipment is which peer.
# No byte on the wire says 10.10.10.10 is Line1-Mixer.
#
#   H1  conduit-project emits a document and HUGINN PARSES IT. A contract error exits 2, so this is
#       the seam's minimum claim -- the projection satisfies an existing contract, unmodified
#   H2  the bypass is visible at all: 10.10.10.30 is reported writing to 10.10.10.10 over S7COMM.
#       NECESSARY BUT NOT SUFFICIENT -- Huginn is deny-by-default over the whole capture, so a
#       violation here appears under any policy. H3, H5 and H8 attribute it to the projection
#   H3  THE DECLARATION IS HONOURED: 10.10.10.20, the declared edge, is NOT reported. Without this,
#       H2 is satisfied by deny-by-default flagging everything, which proves nothing
#   H4  Huginn exits 1 (violations), not 2 (contract error) -- easy to confuse from non-zero alone
#   H5  swapping the binding moves the violation. The projection drives the verdict; the capture is
#       constant, so the finding cannot be an artifact of the pcap
#   H6  a ref not in the governed registry is refused and NO output file is written
#   H7  the emitted document names the registry and says the binding is declared
#   H8  against a CONTROL policy that says nothing about the PLC, both hosts are violations; under
#       the projection exactly one stops being reported. That difference IS the contribution --
#       the projection exempts the declared edge, and nothing else
#
# INJECTION COVERAGE, stated because it is not 8 of 8 and pretending otherwise would be the exact
# failure this discipline exists to catch. Five rows have an isolating injection -- a defect that
# flips that row and no earlier one: H1, H3, H5, H6, H7. Three cannot have one, structurally:
#
#   H2  cannot be flipped by ANY defect in Bifrost's code. Huginn is deny-by-default over the whole
#       capture, so the bypass stops being reported only if the policy ALLOWS it -- and the writer
#       only ever emits rules FROM the edge. Making 10.10.10.30 allowed means declaring it the edge,
#       which is H5's legitimate behaviour, not a defect. H2 is a precondition, and labelled as one.
#   H4  its unique claim over H1 is "exit 1, not 0". Exit 0 needs every observed conversation to be
#       allowed, which two peers and four rules cannot cover. Any contract error trips H1 first.
#   H8  tests the SAME code property as H3 -- that the declared edge is exempted -- and adds the
#       control that makes the property attributable rather than a second behaviour. Every defect
#       that breaks it breaks H3, which runs earlier on the same report.
#
# Needs the Huginn repository beside Bifrost (or $HUGINN_HOME). SKIPS cleanly and exits 0 without
# it, which is why this gate is NOT in CI. No broker, no Docker.
#
#   bash scripts/run-huginn-seam-gate.sh
#   # expect: [HS] GATE PASS (H1-H8)  exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/huginn-seam-gate"
PLC="10.10.10.10"          # the S7 device both hosts write to in the capture
EDGE_HOST="10.10.10.20"    # declared as the governed edge in the main run
OTHER_HOST="10.10.10.30"   # the bypass: writes to the PLC without being the edge

fail() {
  echo "[HS] FAIL: $*"
  exit 1
}

# ---------------------------------------------------------------------------
HUGINN_HOME="${HUGINN_HOME:-$(pwd)/../huginn}"
if [ ! -d "$HUGINN_HOME" ]; then
  echo "[HS] SKIP: no Huginn checkout at $HUGINN_HOME (set HUGINN_HOME to point at one)."
  echo "[HS] The seam cannot be proved without running the tool that reads the projection."
  exit 0
fi
HUGINN_JAR="$HUGINN_HOME/cli/target/huginn.jar"
PCAP="$HUGINN_HOME/samples/4SICS-GeekLounge-151020.pcap"
if [ ! -f "$HUGINN_JAR" ]; then
  echo "[HS] building Huginn at $HUGINN_HOME"
  ( cd "$HUGINN_HOME" && mvn -q install -DskipTests ) || fail "could not build Huginn"
fi
[ -f "$HUGINN_JAR" ] || { echo "[HS] SKIP: no huginn.jar at $HUGINN_JAR"; exit 0; }
[ -f "$PCAP" ] || { echo "[HS] SKIP: no sample capture at $PCAP"; exit 0; }

echo "[HS] step 0: build the gates jar"
mvn -q -pl core,gates -am install -DskipTests
[ -f gates/target/bifrost-gates.jar ] || fail "gates/target/bifrost-gates.jar missing after build"
GATES_JAR_WIN="$(cygpath -m "$(pwd)/gates/target/bifrost-gates.jar")"
HUGINN_JAR_WIN="$(cygpath -m "$HUGINN_JAR")"
PCAP_WIN="$(cygpath -m "$PCAP")"
gates() { java -jar "$GATES_JAR_WIN" "$@"; }

# Huginn's report is in Korean. Match ONLY the ASCII parts -- addresses, S7COMM, WRITE, [HIGH] --
# so this gate never couples a Bifrost assertion to another repository's prose.
huginn() {  # $1 = policy file (bash path); writes $2; sets $hrc
  set +e
  java -jar "$HUGINN_JAR_WIN" "$PCAP_WIN" "$(cygpath -m "$(pwd)/$1")" >"$2" 2>&1
  hrc=$?
  set -e
}
violates() {  # $1 = report, $2 = source host -> is that host reported writing to the PLC?
  grep -E "^ +\[HIGH\] $2:[0-9]+ .* $PLC:102 +S7COMM +WRITE" "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
echo "[HS] step 1: stage a registry governing Line1-Mixer and an unrelated second equipment"
rm -rf "$WORK"
REG="$WORK/registry"
for ref in Line1-Mixer Line2-Welder; do
  mkdir -p "$REG/udt/$ref"
  cat > "$REG/udt/$ref/1.0.0.json" <<JSON
{"templateRef":"$ref","version":"1.0.0","members":[
  {"name":"Rpm","type":"Double","semanticId":null,"range":{"low":0.0,"high":3000.0}}
],"params":[],"conformsTo":null}
JSON
done
REG_WIN="$(cygpath -m "$(pwd)/$REG")"

# ---------------------------------------------------------------------------
echo "[HS] ===== H1: the projection is emitted and Huginn parses it ====="
POLICY="$WORK/conduits.yaml"
set +e
gates conduit-project "$REG_WIN" --edge "$EDGE_HOST" --bind "Line1-Mixer=$PLC" \
      --out "$(cygpath -m "$(pwd)/$POLICY")" >"$WORK/h1-project.txt" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$WORK/h1-project.txt"; fail "H1 conduit-project returned $rc - expected 0"; }
[ -f "$POLICY" ] || fail "H1 no policy was written"

huginn "$POLICY" "$WORK/h1-report.txt"
[ "$hrc" -ne 2 ] || { tail -20 "$WORK/h1-report.txt"; fail "H1 Huginn rejected the projected policy (exit 2 = contract error)"; }
echo "[HS] H1 => PASS (Huginn read a policy Bifrost wrote, with no Huginn changes)"

# ---------------------------------------------------------------------------
echo "[HS] ===== H2/H3/H4: the bypass is found, the declared edge is not ====="
violates "$WORK/h1-report.txt" "$OTHER_HOST" \
  || { grep -c "HIGH" "$WORK/h1-report.txt"; fail "H2 $OTHER_HOST was not reported writing to $PLC"; }
echo "[HS] H2 => PASS ($OTHER_HOST writes governed equipment without being the edge)"
echo "[HS]    (necessary, not sufficient: a violation here appears under any policy. H3/H5/H8"
echo "[HS]     are what attribute it to the projection.)"

violates "$WORK/h1-report.txt" "$EDGE_HOST" \
  && { grep -E "\[HIGH\] $EDGE_HOST" "$WORK/h1-report.txt" | head -3; \
       fail "H3 the DECLARED EDGE $EDGE_HOST was reported as a violation - the projection was not honoured"; }
echo "[HS] H3 => PASS (the declared edge is not flagged, so H2 is not deny-by-default noise)"

[ "$hrc" -eq 1 ] || { tail -5 "$WORK/h1-report.txt"; fail "H4 Huginn exited $hrc - expected 1 (violations found)"; }
echo "[HS] H4 => PASS (exit 1 = violations, not 2 = contract error)"

# ---------------------------------------------------------------------------
echo "[HS] ===== H5: swapping the binding moves the violation ====="
# The capture never changes. Only the declaration does, so whatever moves is the projection's doing.
POLICY_SWAP="$WORK/conduits-swapped.yaml"
gates conduit-project "$REG_WIN" --edge "$OTHER_HOST" --bind "Line1-Mixer=$PLC" \
      --out "$(cygpath -m "$(pwd)/$POLICY_SWAP")" >"$WORK/h5-project.txt" 2>&1 \
  || { cat "$WORK/h5-project.txt"; fail "H5 conduit-project failed"; }
huginn "$POLICY_SWAP" "$WORK/h5-report.txt"

violates "$WORK/h5-report.txt" "$EDGE_HOST" \
  || fail "H5 after swapping, $EDGE_HOST should now be the bypass and was not reported"
violates "$WORK/h5-report.txt" "$OTHER_HOST" \
  && fail "H5 after swapping, $OTHER_HOST is the declared edge and must not be reported"
echo "[HS] H5 => PASS (same capture, swapped declaration, the finding follows the declaration)"

# ---------------------------------------------------------------------------
echo "[HS] ===== H6: equipment nobody governs is refused, and writes nothing ====="
GHOST="$WORK/ghost.yaml"
set +e
gates conduit-project "$REG_WIN" --edge "$EDGE_HOST" --bind "NoSuchEquipment=$PLC" \
      --out "$(cygpath -m "$(pwd)/$GHOST")" >"$WORK/h6.txt" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$WORK/h6.txt"; fail "H6 returned $rc - expected 2 (refused)"; }
grep -q "conduit.equipment.ungoverned" "$WORK/h6.txt" \
  || { cat "$WORK/h6.txt"; fail "H6 missing conduit.equipment.ungoverned"; }
[ ! -f "$GHOST" ] || fail "H6 a refused projection wrote a file"
echo "[HS] H6 => PASS (the registry check is what separates this from a YAML template)"

# ---------------------------------------------------------------------------
echo "[HS] ===== H7: the document says where it came from ====="
grep -q "DECLARED, NOT DISCOVERED" "$POLICY" \
  || { head -12 "$POLICY"; fail "H7 the document does not say the binding was declared"; }
grep -q "FRAGMENT" "$POLICY" \
  || { head -12 "$POLICY"; fail "H7 the document does not say it is a fragment"; }
# Match the directory NAME, not the path: the header carries whatever absolute form the JVM
# normalized to, which is backslash-separated on Windows and would never equal the bash path here.
grep -qF "huginn-seam-gate" "$POLICY" \
  || { head -12 "$POLICY"; fail "H7 the document does not name the registry it came from"; }
echo "[HS] H7 => PASS (provenance and scope are in the artifact, not only in a README)"

# ---------------------------------------------------------------------------
echo "[HS] ===== H8: what the projection actually contributes, measured against a control ====="
# H2 on its own proves NOTHING about the projection. Huginn is deny-by-default over the WHOLE
# capture -- a policy says what is allowed, it does not narrow what is examined -- so a violation
# against the PLC appears under any policy, including one that mentions neither host. The first
# draft of this row asserted the opposite and failed, correctly.
#
# The projection's entire contribution is that it EXEMPTS THE DECLARED EDGE. So the honest
# attribution is a control: run the same capture under a policy that says nothing about the PLC,
# and show the finding set differs by exactly the declared edge's writes.
CONTROL="$WORK/control.yaml"
cat > "$CONTROL" <<'YAML'
# Control for H8. Declares an unrelated pair, nothing about the PLC, so both hosts writing to it
# are violations. Hand-written on purpose: conduit-project refuses to emit a policy governing
# nothing, which is the right refusal and makes it the wrong tool for a control.
version: 1
peers:
  - id: unrelated-a
    address: 10.10.10.98
  - id: unrelated-b
    address: 10.10.10.99
allowed:
  - from: unrelated-a
    to: unrelated-b
    protocol: MODBUS_TCP
    access: [READ]
YAML
huginn "$CONTROL" "$WORK/h8-control.txt"

violates "$WORK/h8-control.txt" "$EDGE_HOST"   || fail "H8 control: $EDGE_HOST should be a violation when nothing exempts it"
violates "$WORK/h8-control.txt" "$OTHER_HOST"   || fail "H8 control: $OTHER_HOST should be a violation when nothing exempts it"

# ...and under the projection exactly one of the two stops being reported.
violates "$WORK/h1-report.txt" "$EDGE_HOST"   && fail "H8 the projection did not exempt the declared edge"
violates "$WORK/h1-report.txt" "$OTHER_HOST"   || fail "H8 the projection exempted more than the declared edge"
echo "[HS] H8 => PASS (control flags both hosts; the projection exempts the declared edge and only it)"

echo ""
echo "[HS] GATE PASS (H1-H8)"
exit 0
