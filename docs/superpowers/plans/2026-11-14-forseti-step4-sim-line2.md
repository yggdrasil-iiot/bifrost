# Forseti Step 4: Bifrost Sim Line2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Bifrost OPC UA sim (module `sim`) gains a `Line2` folder with three stations and two nutrunners under Station1, value control nodes and a configurable scan period, so forseti's step-5 scenario driver can drive plc-stamped attribution through the sim. Existing Mixer1 behaviour and the existing address space stay unchanged.
**Architecture:** All changes are in `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java` (inner class `SimNamespace`) and `SimMain.java`, plus new tests under `sim/src/test/java/yggdrasil/bifrost/sim/` and one test resource. `GovernedWriteFilter.java` is unchanged. Mimir, Muninn and vor are unchanged.
**Tech Stack:** Java 17, Maven module `sim`, Eclipse Milo 1.1.8 server API (`milo.version` in the root POM) as already used in EmbeddedMiloSim, JUnit 5. Branch `feat/sim-line2` off `main` (`4d79b87`). Files use LF.

---

## Spec and rules applied

- Spec: `yggdrasil-iiot/forseti`, `docs/superpowers/specs/2026-11-05-forseti-design.md`:
  - Delivery plan row 4 (line 747): Line2 implementation requirements and completion gate.
  - Decision 16 (line 95): Two of the three regimes run in the sim.
  - Scope (line 111): Attribution and sim requirements.
  - The `plc-stamped` paragraph (line 519): each identified equipment reports `UnitId`, `VisitId` and `VisitPresent` in the same scan snapshot as its activity and measurements.
  - The scenario driver paragraph (line 639): A tool not used in a visit reports the visit's IDs with VisitPresent=true and Running=false.
  - Fault injection 3 (line 648): Fault injection via `Sim/<member>.StatusCode`.
  - The full-loop gate (line 726): Full loop verification requirements.
- Row 4 requirements:
  - New folder `Line2` with three `StationType` instances: `{Running: Boolean, UnitId: String, VisitId: String, VisitPresent: Boolean}`.
  - Two `ToolType` nutrunners under `Station1`: `{Torque: Double, Running: Boolean, UnitId: String, VisitId: String, VisitPresent: Boolean}`.
  - Every member re-stamped every scan; tool members updated as one snapshot.
  - All new Line2 members of one scan share one source timestamp.
  - `Sim/<member>.Value` value control nodes outside the governance filter beside existing `Sim/<member>.StatusCode`.
  - Writes to Line2 `Sim/<member>.Value` and `Sim/<member>.StatusCode` take effect together at the next scan.
  - Scan period configured as a system property.
  - Existing Mixer1 behaviour and bytes unchanged.
  - Hierarchy and mapping sets live in forseti fixtures authored in Tyr and approved by Bifrost.
  - Completion gate: sim tests pass; Mimir and Muninn gates unchanged.
- Node IDs (namespace `urn:bifrost:opcua:sim`, string identifiers):
  - 13 fixture IDs: `Line2/Station1.Running`, `Line2/Station2.Running`, `Line2/Station3.Running`, `Line2/Station1.UnitId`, `Line2/Station1.VisitId`, `Line2/Station1.VisitPresent`, `Line2/Station1/Nutrunner1.Torque`, `Line2/Station1/Nutrunner1.Running`, `Line2/Station1/Nutrunner1.UnitId`, `Line2/Station1/Nutrunner1.VisitId`, `Line2/Station1/Nutrunner1.VisitPresent`, `Line2/Station1/Nutrunner2.Torque`, `Line2/Station1/Nutrunner2.Running`.
  - Remaining 9 members required by row 4: `Line2/Station2.UnitId`, `Line2/Station2.VisitId`, `Line2/Station2.VisitPresent`, `Line2/Station3.UnitId`, `Line2/Station3.VisitId`, `Line2/Station3.VisitPresent`, `Line2/Station1/Nutrunner2.UnitId`, `Line2/Station1/Nutrunner2.VisitId`, `Line2/Station1/Nutrunner2.VisitPresent` (22 members in total).
- Current code baseline:
  - `SimNamespace.SCAN_MS = 1000` (constant).
  - Single-thread scheduler runs `scan()` at fixed rate.
  - `scan()` is `synchronized` and re-stamps five nodes (four Mixer1 members and `Line1/Mixer2.Temp`) through `stamped()`, which takes `DateTime.now()` per member.
  - `addStatusControl` creates `Sim/<member>.StatusCode` (UInt32, access 3, not a component, outside governed-write filter) whose observer applies code immediately.
  - Existing tests: `SimStatusControlTest`, `MixerTypeNodeTest`, `WeldControllerNodeTest`, `SetTemperatureMethodTest`, `GovernedWriteFilterTest`, `EmbeddedMiloSimConfigTest`.
- Consumers:
  - Mimir gate derives type `MixerType`.
  - Muninn gate reads `Line1/Mixer1`.
  - vor scripts start the sim.
  - Bifrost CI runs no gate that starts the sim; 19 scripts under `scripts/` use `sim/target/bifrost-sim.jar` (including `run-yggdrasil-spine-gate.sh` and `run-yggdrasil-full-loop-gate.sh`, running Mimir and Muninn from sibling checkouts).

## Decisions

1. Address space: `Line2` is a FolderType node with id `Line2`, organized by the Objects folder (inverse Organizes, the pattern Mixer1 uses). It organizes `Line2/Station1`, `Line2/Station2`, `Line2/Station3`. `StationType` and `ToolType` are non-abstract ObjectTypes, subtypes of BaseObjectType, with HasComponent members. Browse names are local names (`Station1`, `Nutrunner1`, `Running`). The nutrunners `Line2/Station1/Nutrunner1` and `Line2/Station1/Nutrunner2` hang under Station1 by Organizes, not HasComponent.
   - Reason: The sim keeps an instance's components equal to its type's members, and forseti and Muninn take the ISA-95 hierarchy from the published hierarchy fixture, not from browsing. No EURange on Torque; its unit (N.m) lives in the mapping fixture. The new types add no reference or member to MixerType or Line1.
2. Defaults: Every Running and VisitPresent false, every UnitId and VisitId the empty string, both Torques 0.0, every status Good.
   - Reason: The sim runs no pattern of its own; the step-5 driver sets every value. Empty strings, not null, keep the typed String read valid.
3. Value controls: Each of the 22 members gets `Sim/<memberId>.Value` (the member's exact DataType) and `Sim/<memberId>.StatusCode` (UInt32), access level 3, not components, outside GovernedWriteFilter, writable anonymously also when identity is required. A read of a control returns the last accepted requested setting. Line2 controls have no immediate-apply observer: the live member keeps its committed snapshot until the next scan. Each Line2 scan commits every accepted pending value and status together; settings not written persist; repeated writes before a scan are last-write-wins. Mixer1's StatusCode controls keep their immediate behaviour unchanged.
   - Reason: Preserves live snapshot stability between scans and aligns control updates with the discrete scan boundary, while leaving legacy Mixer1 controls unaffected.
4. Control validation: A write to a Line2 control is validated before anything changes. A wrong DataType, a null or an array is rejected with Bad_TypeMismatch, without numeric coercion. A rejected write changes neither the requested nor the pending state.
   - Reason: The rejection semantics then do not depend on Milo defaults.
5. Write-request atomicity: The namespace's Write dispatch runs under the same lock as the scan, so the accepted items of one Write request cannot straddle a scan. Separate requests can. Read is not serialized: a Read that straddles a scan shows unequal source timestamps, which forseti's `incoherent-snapshot` rule already covers. The exact Milo 1.1.8 override signature is checked against the jar in Task 5.
   - Reason: The step-5 driver writes one equipment snapshot per Write request, and that snapshot must reach the members in one scan; a straddling Read is already detectable by its unequal source timestamps.
6. Snapshots: The Line2 scan takes one timestamp, builds all 22 DataValues, then sets them in a fixed order (stations, then each tool's five members contiguously) under the lock, with SourceTimestamp = ServerTimestamp = that time. Successive Line2 scan timestamps are strictly increasing: if the clock returns a time not after the previous scan's, the scan uses the previous time plus one tick. The startup values form one initial snapshot with one shared timestamp. The five existing nodes keep their unchanged `stamped()` loop.
   - Reason: OPC UA monitoring is per variable, so a subscriber sees one snapshot as members with equal source timestamps; row 4 already defines coherence this way, so no owner decision remains.
7. Scan period: System property `bifrost.sim.scanMs`, integer milliseconds 1..86400000, default 1000 (`SCAN_MS`, kept as the default constant). It is resolved once before startup; a blank, malformed, overflowing or out-of-range value fails the start with a message, without a silent fallback. It sets the one shared scheduler, so it governs Mixer1's scan too; at the default the schedule is the same `scheduleAtFixedRate(1000, 1000)` as today.
   - Reason: Fails fast on misconfiguration rather than running with an unexpected scan rate; sharing the scheduler maintains a single timing thread across the sim.
8. Governance: Line2 live members have AccessLevel and UserAccessLevel 1 (client-read-only, as `typeMember` builds them), no `govern()` and no methods.
   - Reason: Live members change only through the `Sim/` controls at the scan, so no client needs to write them.
9. Unchanged bytes: A committed baseline of every pre-existing node (Recipe, Weld, MixerType, the weld type, Line1, BodyShop, the existing Sim controls): NodeId, node class, browse and display name, DataType, access levels, type definition, sorted references, initial value and status; namespace indexes written as URIs; timestamps excluded. Captured from `4d79b87` before any change. A test also asserts that `Line2` is the only new child of Objects.
   - Reason: Guarantees full backwards compatibility and ensures existing nodes and references are byte-for-byte and property-for-property unchanged.

## File Structure

| File | Responsibility |
|---|---|
| `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java` | StationType, ToolType, Line2 nodes, Line2 controls with validation, pending state, Line2 scan, scan period configuration, Write lock. |
| `sim/src/main/java/yggdrasil/bifrost/sim/SimMain.java` | Resolves `bifrost.sim.scanMs` system property at startup. |
| `sim/src/test/java/yggdrasil/bifrost/sim/LegacySimCompatibilityTest.java` | Tests the legacy address space against the committed baseline snapshot. |
| `sim/src/test/resources/legacy-address-space.json` | Baseline dump of all pre-existing address space nodes and metadata from `4d79b87`. |
| `sim/src/test/java/yggdrasil/bifrost/sim/Line2NodeTest.java` | Tests Line2 address space structure, types, components, references, defaults, and single new child of Objects. |
| `sim/src/test/java/yggdrasil/bifrost/sim/Line2ControlTest.java` | Tests control node generation, staging semantics, persistence, last-write-wins, and type validation. |
| `sim/src/test/java/yggdrasil/bifrost/sim/Line2SnapshotTest.java` | Tests timestamp synchronization, monotonic increase across scans, tool snapshot contiguous updates, and Write atomicity. |
| `sim/src/test/java/yggdrasil/bifrost/sim/EmbeddedMiloSimConfigTest.java` | Extended tests for `bifrost.sim.scanMs` parsing, range checks, and scheduler configuration. |
| `README.md` | Documents Line2 nodes, control node semantics, and `bifrost.sim.scanMs` property. |

## Tasks

### Task 0: Branch

- [ ] Create worktree and branch `feat/sim-line2` off `main` at `4d79b87`.
- [ ] Verify clean worktree and confirm HEAD is at commit `4d79b87`.

### Task 1: Compatibility baseline (red-free on main)

- [ ] Write `sim/src/test/java/yggdrasil/bifrost/sim/LegacySimCompatibilityTest.java` and generate `sim/src/test/resources/legacy-address-space.json` from `4d79b87` recording NodeId, node class, browse name, display name, DataType, access levels, type definition, sorted references, initial value, and initial status (namespace indexes formatted as URIs, timestamps excluded).
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=LegacySimCompatibilityTest` on `4d79b87` to verify baseline passes (green).
- [ ] Commit baseline test and JSON resource before introducing any sim modifications.

### Task 2: Scan period property

- [ ] Write tests in `sim/src/test/java/yggdrasil/bifrost/sim/EmbeddedMiloSimConfigTest.java` covering `bifrost.sim.scanMs`: default (1000), valid custom value, blank, non-numeric, 0, negative, value above 86400000, overflow, and a bounded-polling test verifying scheduler honours small periods.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=EmbeddedMiloSimConfigTest` to verify failure for new scan period test cases (red).
- [ ] Implement system property resolution in `sim/src/main/java/yggdrasil/bifrost/sim/SimMain.java` and update `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java` to accept and apply the resolved period to the scheduler.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=EmbeddedMiloSimConfigTest` to verify all pass (green).
- [ ] Commit scan period implementation and tests.

### Task 3: Line2 types and instances

- [ ] Write `sim/src/test/java/yggdrasil/bifrost/sim/Line2NodeTest.java` testing:
  - Presence and DataType of all 13 fixture IDs and all 22 members.
  - AccessLevel and UserAccessLevel = 1.
  - Default values (Boolean false, String empty string, Double 0.0, StatusCode Good).
  - `StationType` and `ToolType` as non-abstract subtypes of BaseObjectType.
  - Station components are exactly their four member variables.
  - Nutrunner1 and Nutrunner2 organized under Station1 via Organizes (not HasComponent).
  - Initial snapshot shares one source timestamp.
  - `Line2` is the only new child node under Objects folder.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2NodeTest` to verify failure (red).
- [ ] Implement `StationType`, `ToolType`, `Line2` folder, three stations, two nutrunners under Station1, and 22 members with defaults in `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java`.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2NodeTest,LegacySimCompatibilityTest` to verify all Line2 and compatibility tests pass (green).
- [ ] Commit Line2 types, instances, and address space tests.

### Task 4: Value controls, staged commit and the Line2 scan

- [ ] Write `sim/src/test/java/yggdrasil/bifrost/sim/Line2ControlTest.java` and `sim/src/test/java/yggdrasil/bifrost/sim/Line2SnapshotTest.java` testing:
  - Value controls `Sim/<memberId>.Value` and status controls `Sim/<memberId>.StatusCode` created for all 22 members (access level 3, outside governance, anonymous write permitted).
  - Writes to controls do not affect live member before scan, and take effect together at scan.
  - Unwritten settings persist across scans.
  - Last write wins for multiple writes preceding a scan.
  - Transitions through Bad, Uncertain, and Good status codes.
  - Direct writes to live members are refused.
  - Controls are not component children of the instances.
  - Package-private scan execution for deterministic non-scheduled testing.
  - Re-stamping of all 22 members on each scan with shared source timestamp.
  - Strictly increasing timestamps across successive scans (using previous plus one tick if clock does not advance).
  - Nutrunner members updated contiguously.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2ControlTest,Line2SnapshotTest` to verify failure (red).
- [ ] Implement value controls, pending state staging, package-private direct scan hook, and Line2 scan loop in `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java`.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2ControlTest,Line2SnapshotTest,LegacySimCompatibilityTest` to verify all pass (green).
- [ ] Commit control nodes, staging logic, and scan snapshot implementation.

### Task 5: Write-request atomicity and control validation

- [ ] Verify the Eclipse Milo 1.1.8 server API jar to confirm the exact method signature for overriding namespace Write dispatch.
- [ ] Write tests in `sim/src/test/java/yggdrasil/bifrost/sim/Line2ControlTest.java` and `sim/src/test/java/yggdrasil/bifrost/sim/Line2SnapshotTest.java` testing:
  - Write validation rejecting wrong DataType, null, or array with `Bad_TypeMismatch`.
  - No numeric coercion (rejecting Int32 write to Double control).
  - Rejected writes leave requested and pending states unchanged.
  - Write-request atomicity ensuring all items of a single Write request commit in the same scan.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2ControlTest,Line2SnapshotTest` to verify failure (red).
- [ ] Implement control input validation and synchronize namespace Write dispatch under the scan lock in `sim/src/main/java/yggdrasil/bifrost/sim/EmbeddedMiloSim.java`.
- [ ] Run `mvn -B -ntp -pl sim test -Dtest=Line2ControlTest,Line2SnapshotTest` to verify all pass (green).
- [ ] Commit Write atomicity and control validation.

### Task 6: Documentation, full build, gates, pull request

- [ ] Update `README.md` sim section and `EmbeddedMiloSim` class javadoc with Line2 details, control nodes, and `bifrost.sim.scanMs` property documentation.
- [ ] Run `mvn -B -ntp clean install` to verify complete project build.
- [ ] Run verification test suite and gates.
- [ ] Open pull request for `feat/sim-line2` targeting `main` with body containing:
  - Summary
  - Changes
  - Verification
  - Deviations from plan or spec
  - Out of scope

## Note for step 5

- The forseti scenario driver must write each equipment snapshot (all member values and statuses for a given station or tool) in a single Write request to ensure atomic commit at the sim's scan boundary.
- The sim's scan period is set with `bifrost.sim.scanMs` when the sim is started.
- The full-loop configuration must set the Muninn sampling period at or below the sim scan period and must record repeated source timestamps.
- Milo 1.1.8 returns the time of the read as the ServerTimestamp of a variable value, so only the source timestamp identifies a scan's snapshot.

## Verification

```bash
# Sim module test execution (clean removes any stale reports)
mvn -B -ntp -pl sim -am clean test

# Full repository build
mvn -B -ntp clean install

# Core spine and full-loop gates (sibling checkouts of Mimir and Muninn at their default-branch heads with their jars built; HiveMQ CE in Docker)
bash scripts/run-yggdrasil-spine-gate.sh
bash scripts/run-yggdrasil-full-loop-gate.sh

# Additional sim-dependent verification gates
bash scripts/run-activation-gate.sh
bash scripts/run-activation-authz-gate.sh
bash scripts/run-anchored-activation-gate.sh
bash scripts/run-command-identity-gate.sh
bash scripts/run-command-ledger-gate.sh
bash scripts/run-command-method-gate.sh
bash scripts/run-command-node-gate.sh
bash scripts/run-composable-conformance-gate.sh
bash scripts/run-edge-resilience-gate.sh
bash scripts/run-endpoint-binding-gate.sh
bash scripts/run-federation-gate.sh
bash scripts/run-identity-gate.sh
bash scripts/run-key-rotation-gate.sh
bash scripts/run-lineage-gate.sh
bash scripts/run-ncmd-runtime-gate.sh
bash scripts/run-write-exclusivity-gate.sh

# Consumer gates in the sibling repositories, against the updated sim jar
(cd ../mimir && bash scripts/run-mimir-gate.sh)
(cd ../muninn && bash scripts/run-muninn-gate.sh)
```

- `mvn -B -ntp -pl sim -am clean test` must complete with 0 failures.
- `mvn -B -ntp clean install` must yield `BUILD SUCCESS`.
- Every gate passes as it does on main (the spine and full-loop gates print `[GATE] PASS`).
- Sibling Mimir and Muninn checkouts must be at their default-branch heads with their jars built.
- Docker must be active for HiveMQ CE container execution during full-loop and spine gates.
- GitHub CI must report green on the opened pull request.
