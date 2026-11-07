# Forseti Step 1: Bifrost Mapping Contract 2.27.0 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bifrost accepts, validates, and approves the two forseti rule kinds of mapping contract 2.27.0 (`attribution-rule`, `impact-rule`) and the two binding profiles they reference (`occupancy-binding`, `incident-binding`, carried as evidence-artifact 1.1.0 files). It implements every refusal code from the spec's three tables, the member checks of spec line 132, and the refusal assignments of spec lines 133-135. It adds the `String` value type for typed (OPC UA) sources in the 2.27.0 contract (with its 2.27.0 source-definition schema), enforces the `rule.envelope` refusal that keeps every 2.27.0 document in a 2.27.0 proposal, applies the compatibility rules of the step-1 row, provides two fixture bundles (`occupancy-join` and `plc-stamped`) that pass `gates mapping approve`, and includes a MAPPING-PUBLICATION section.

**Architecture:** The architecture follows 2.24 (`MetricDefinitions`) and 2.25/2.26 (`CommandBindings` + `ReadBindingProfile`). It adds a new resource folder `mapping-contracts/2.27.0/` (a copy of the 2.26.0 `common` with three edits, a 2.27.0 `mapping-proposal`, a 2.27.0 `source-definition` for the plc branch so that a typed `String` source can be published, and two new document schemas). `MappingBundle.validate` calls two package-private fail-first validators (`AttributionRules`, `ImpactRules`) right after `CommandBindings.validate`. Two public profile readers (`OccupancyBindingProfile`, `IncidentBindingProfile`) match the strictness of `ReadBindingProfile`. Two data-only fixture bundles reside under `mapping-fixtures/`. Every rule check throws `IllegalArgumentException(code)`; `MappingBundle` turns the first one into the single finding the tests assert. No forseti code exists and none is referenced; Bifrost reads the published bytes alone.

**Tech Stack:** Java 17, Maven multi-module (`core`, `gates`), Jackson, networknt json-schema-validator (draft 2020-12), JUnit 5. Branch `feat/attribution-impact-rules` off `main` (`cc103e9`). Files use LF; product names in prose are ASCII (Mimir, Tyr). Fixture bytes under `core/src/test/resources/mapping-fixtures/**` and contract bytes under `core/src/main/resources/mapping-contracts/**` are already `-text` in `.gitattributes`.

---

## Spec and rules applied

- Spec: `yggdrasil-iiot/forseti`, `docs/superpowers/specs/2026-11-05-forseti-design.md`, as corrected by forseti PR #2 (every "spec line N" below is a line of that file): Delivery plan row 1 (line 711); Contracts (lines 115-227): attribution rule (119-154; `equipmentRef` 130, `stations[]` 131, `members[]` 132, `activity[]` 133, `identity` 135, `coverage` 138, `attribution.identity-member` row 152), impact rule (156-188; `incidentScope[]` 168, `retention` 172), binding profiles (190-227; strictness 192, artifact prefix and media type 204, occupancy fields 206-215, incident fields 217-222, `sources[]`/`kinds[]` 224, pattern subset 225-226); Decisions 3 (line 37), 4 (41), 8 (59), 9 (63), 15 (87), 17 (96).
- Rules the plan applies, as the spec states them. Row 1 (line 711): The 2.27.0 common schema defines the `String` value type for typed (OPC UA) source representations, and a 2.27.0 source-definition schema uses it. `MappingBundle` accepts 2.27.0 in its proposal-version, document-kind, `mapping.required`, and envelope sets; allows 2.26.0 and 2.27.0 for the command-binding envelope; and refuses any document whose `schemaVersion` is 2.27.0 outside a 2.27.0 proposal with `rule.envelope`. A 2.26.0 proposal cannot carry the new kinds (its proposal schema refuses them). Line 130: An invalid hierarchy keeps its own `hierarchy.*` refusal. Line 131: `stations[]` is non-empty and distinct. Line 132: Member references are `mappingId` strings naming one `members[]` entry of the same rule. `metric` is the semantic leaf's `name` byte for byte, and `semanticId` is the leaf's. The `memberPath` has one `member` step. Within each semantic definition a rule uses, no two leaf members share a `name`. An `opcua-node` identifier ends with `.` + `metric`. `members[]` is non-empty, lists each `mappingId` once, and holds one entry per (equipment path, metric); each failure yields `attribution.member-unresolved`. Each entry has exactly one role, given by the references that name it. A `mappingId` named by both an activity and an identity reference, or by more than one identity reference, is `attribution.identity-member` (row at line 152). Two activity references to one `mappingId` are two activity entries for one equipment (`attribution.activity-member`). Line 133: The `activity[]` failures fall under `attribution.activity-member`; an equipment without an activity entry is allowed. Line 135: Identity entry coverage falls under `attribution.identity-equipment`, member types fall under `attribution.identity-member`, `namespace` is optional under `occupancy-join`, and `crossCheck: occupancy` applies under both modes. Line 138: `expectedPeriodMs` is 1-86400000. Line 168: `incidentScope[]` is non-empty and distinct. Lines 192 and 204: Artifact prefix and media type fall under `*.binding-profile`; an artifact that is not an evidence artifact 1.1.0 of the bundle falls under `*.binding-unresolved`; `scope` is not compared; `schemaSha256` form only. Line 213: `reasons` is a non-empty list of distinct values from the two EPCIS reasons. Line 224: `kinds[]` is non-empty and unique. Lines 225-226: The `identity.pattern` subset.
- Bifrost precedents: PR #39 (`07b18e3`, metric definition 2.24.0), `9ae9255` (command binding 2.25.0), `76490e5` (endpointRef 2.26.0), `91a8584` (Tyr fixture), merges `2c7d584`, `3bd48e9`, `cc103e9`. Source-definition schema precedent: `mapping-contracts/2.10.0/source-definition.schema.json` (one branch of 2.7.0 re-issued under a later version).

## File Structure

| File | Responsibility |
|---|---|
| `core/src/main/resources/mapping-contracts/2.27.0/common.schema.json` | **new** - byte copy of 2.26.0 `common` with three edits: `$id` `urn:tyr:contract:2.27.0:common`; `attribution-rule`, `impact-rule` appended to `$defs/fileEntry/properties/kind/enum`; `String` appended to the `typed` branch of `$defs/rawRepresentation` |
| `core/src/main/resources/mapping-contracts/2.27.0/mapping-proposal.schema.json` | **new** - copy of 2.26.0 with both `2.26.0` constants replaced by `2.27.0` |
| `core/src/main/resources/mapping-contracts/2.27.0/source-definition.schema.json` | **new** - the `plc` branch of 2.7.0 `source-definition` as one object with `schemaVersion` const `2.27.0`, so a typed OPC UA `String` source validates against the 2.27.0 `common` |
| `core/src/main/resources/mapping-contracts/2.27.0/attribution-rule.schema.json` | **new** - the attribution rule document shape (spec 119-140), no additional properties |
| `core/src/main/resources/mapping-contracts/2.27.0/impact-rule.schema.json` | **new** - the impact rule document shape (spec 156-173) |
| `core/src/main/java/dev/krillin/bifrost/core/mapping/OccupancyBindingProfile.java` | **new** - reader of the `occupancy-binding` 0.1.0 file (spec lines 206-215, 224-226), including the regex-subset check of `identity.pattern` |
| `core/src/main/java/dev/krillin/bifrost/core/mapping/IncidentBindingProfile.java` | **new** - reader of the `incident-binding` 0.1.0 file (spec lines 217-224) |
| `core/src/main/java/dev/krillin/bifrost/core/mapping/AttributionRules.java` | **new** - the eleven `attribution.*` checks over the bundle, plus the hierarchy path and lookup helpers `ImpactRules` reuses |
| `core/src/main/java/dev/krillin/bifrost/core/mapping/ImpactRules.java` | **new** - the five `impact.*` checks over the bundle |
| `core/src/main/java/dev/krillin/bifrost/core/mapping/MappingBundle.java` | **+2.27.0** in the proposal-version set (line 38), document-kind set (48), `mapping.required` set (63), `broadcast.envelope` and `record-field.envelope` sets (105-106); `command-binding.envelope` becomes `Set.of("2.26.0","2.27.0")` (107); the `rule.envelope` check after line 107; two validator calls after line 102 |
| `core/src/test/resources/mapping-fixtures/attribution-impact/**` | **new** - data-only bundle (29 files): hierarchy (site, line2, station1, station2, nutrunner1 and nutrunner2 under station1), four mapping sets, both profiles as evidence-artifact 1.1.0 files, one `occupancy-join` attribution rule, one impact rule |
| `core/src/test/resources/mapping-fixtures/attribution-plc-stamped/**` | **new** - data-only bundle (37 files): the bundle above plus String `UnitId`/`VisitId` and Boolean `VisitPresent` members for station1 and nutrunner1 (2.27.0 source definitions), and a `plc-stamped` attribution rule |
| `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingAttributionRuleTest.java` | **new** - acceptance, release/attestation, the compatibility tests, every `attribution.*` code reachable from the `occupancy-join` bundle, occupancy profile refusals, pattern subset |
| `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingPlcStampedRuleTest.java` | **new** - the `plc-stamped` bundle: acceptance with typed String sources, `attribution.identity-equipment`, `attribution.identity-member`, the 2.7.0 regression |
| `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingImpactRuleTest.java` | **new** - every `impact.*` code and incident profile refusals |
| `gates/src/test/java/dev/krillin/bifrost/gates/MappingGateTest.java` | **+3 tests** - both fixture bundles through `gates mapping approve` (the completion gate), and a refused bundle that leaves no receipt |
| `docs/MAPPING-PUBLICATION.md` | **+1 section** "Attribution and impact rules 2.27" |

Nothing else changes. `heimdall`, `sim`, scripts, the CI workflow and `README.md` are untouched (no script or doc outside `MAPPING-PUBLICATION.md` registers mapping contract versions: `git grep -n "2\.26\.0"` outside the resource folders hits only `MappingBundle`, `CommandBindings`, `CommandLink`, `ServerCertificates`, their tests, `COMMAND-PROPOSAL.md`, `ENTERPRISE.md` and two gate scripts, all about command bindings). `EquipmentHierarchy`, `CommandBindings`, `ReadBindingProfile` and `MappingJson` are not modified; the hierarchy-path helper is repeated privately in `AttributionRules`, as `CommandBindings.path` is.

## Conventions the tasks follow

- **Refusal codes** match the spec verbatim. A validator uses `MappingJson.require(boolean, code)` and stops at the first failure, matching `MetricDefinitions` and `CommandBindings`. `MappingBundle` catches the failure (line 112) and emits one finding, so a negative test asserts `List.of(code)`.
- **Document references** `{id, version}` resolve inside the bundle by `(kind, id, version)`.
- **Hierarchy paths** start at the root and join segments with `:` (the string Muninn publishes as the Sparkplug device id, per `CommandBindings.path`). Ids carry no `:`, so `startsWith(station + ":")` is an exact descendant test.
- **Member references** (`activity[].memberRef`, `identity.members[].unitMemberRef`, `visitMemberRef`, `presentMemberRef`) are strings. Each reference is the `mappingId` of exactly one `members[]` entry of the same rule (spec line 132). A `members[]` entry resolves by `mappingSetRef` + `mappingId` to one mapping of the bundle (`mappingId` is bundle-unique: `mapping.duplicate-id` in `MappingBundle.mappings()`, line 430, uses one set for the whole bundle). The mapping set's `equipmentInstanceId` gives the member's hierarchy path, and the semantic member its `memberPath` resolves to (`LogicalStructure.resolve`) gives `valueType`, `name` (the metric) and `semanticId`. Thus, a Boolean activity member and the String/Boolean identity members are themselves `members[]` entries.
- **Leaf-name uniqueness** follows the spec (line 132, `members[]` bullet, forseti PR #2): "Within each semantic definition a rule uses, no two leaf members share a `name` (a station and a tool may each have a member of the same name, because Sparkplug metric names are scoped to one device)". The check runs per definition; `station-model` and `tool-model` of the fixture both carry `Running`.
- **Member classification** follows the spec (line 132, `members[]` bullet, forseti PR #2): "Each `members[]` entry has exactly one role, given by the references that name it: an entry named by an `activity[].memberRef` is an activity member, an entry named by an identity entry's `unitMemberRef`, `visitMemberRef` or `presentMemberRef` is an identity member, and every other entry is a measurement member. A `mappingId` named by both an activity reference and an identity reference, or by more than one identity reference, fails with `attribution.identity-member`; two activity references to one `mappingId` are two activity entries for one equipment and fail with `attribution.activity-member`." The `attribution.identity-member` row (spec line 152) adds the same condition. "Every equipment that has measurement or activity members" (spec 135) is therefore the set of equipment paths of the activity entries and of the `members[]` entries no identity entry names; an equipment whose only members are identity members may not carry an identity entry. Bifrost checks only the roles and their overlap; how the job aggregates measurement members (coverage, bad share, required members, work-record `memberRefs` and `samplesDigest`) is outside step 1.
- **Tests** copy a fixture into `@TempDir`, mutate one file, re-pin its `sha256` in `proposal.json` (and in the evidence artifact when the file is a data file), reseal `submission.json`, and read `findings[].ruleCode`, matching `MappingCommandBindingTest.change`.
- **Maven**: `mvn -q -pl core -Dtest=<Class> test` runs one core test class (core depends on no other module). Testing gates requires installing core and its inherited parent POM first (`-am` installs `bifrost-parent` as well, so a local repository without it still resolves the `bifrost-core` descriptor): `mvn -q -pl core -am install -DskipTests && mvn -q -pl gates -Dtest=MappingGateTest test`. The full build is `mvn -B -ntp install` (CI runs this on Linux and Windows).
- **Commits**: One per task, using conventional subjects matching repository usage (`feat(mapping): ...`, `test(mapping): ...`, `docs(mapping): ...`). Never commit on `main`. Keep `git diff --check` clean before each commit.

---

## Chunk 1: Fixture bundle, contract resources, MappingBundle sets

### Task 0: Branch

**Files:** none

- [ ] `git -C bifrost status --short` is empty and `git -C bifrost log -1 --format=%h main` prints `cc103e9` (if `main` has moved, record the new head in the PR body and re-check the `MappingBundle.java` line numbers of Task 2 against it).
- [ ] `git -C bifrost switch -c feat/attribution-impact-rules main`.

### Task 1: The `attribution-impact` fixture bundle (data only) and a red acceptance test

**Files:**
- Create: `core/src/test/resources/mapping-fixtures/attribution-impact/` (29 files, listed below)
- Create: `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingAttributionRuleTest.java` (first test only)

The fixture is the bundle Tyr will produce in step 2, written by hand now. Equipment: `synthetic-site` (SITE_1) > `line2` (PRODUCTIONLINE_5) > `station1`, `station2` (WORKCELL_6); `nutrunner1`, `nutrunner2` (WORKUNIT_11, see Open point 1) under `station1`. Paths: `synthetic-site:line2:station1`, `synthetic-site:line2:station2`, `synthetic-site:line2:station1:nutrunner1`, `synthetic-site:line2:station1:nutrunner2`. Members: each station has `Running` (Boolean); each nutrunner has `Torque` (Double, `N.m`) and `Running` (Boolean). The attribution rule is `occupancy-join`, stations `[station1, station2]`, `members[]` the two torques and the four `Running`s, `activity[]` the four `Running`s. Stream id `line2`.

- [ ] **Step 1.1** Create the folder layout:

```
attribution-impact/
  proposal.json
  submission.json
  hierarchy/0.json
  evidence/hierarchy-0.json             data/hierarchy-0.csv
  evidence/manual-line2.json            data/manual-line2.txt
  evidence/occupancy-binding-line2.json data/occupancy-binding-line2.json
  evidence/incident-binding-line2.json  data/incident-binding-line2.json
  semantics/station.json  semantics/tool.json
  sources/station1-running.json sources/station2-running.json
  sources/nutrunner1-torque.json sources/nutrunner1-running.json
  sources/nutrunner2-torque.json sources/nutrunner2-running.json
  targets/station1.json targets/station2.json targets/nutrunner1.json targets/nutrunner2.json
  mappings/station1.json mappings/station2.json mappings/nutrunner1.json mappings/nutrunner2.json
  rules/attribution-line2.json
  rules/impact-line2.json
```

- [ ] **Step 1.2** `data/hierarchy-0.csv` (LF, 7 lines):

```
equipmentInstanceId,label,equipmentLevel,parent
synthetic-site,Synthetic site,SITE_1,
line2,Line 2,PRODUCTIONLINE_5,synthetic-site
station1,Station 1,WORKCELL_6,line2
station2,Station 2,WORKCELL_6,line2
nutrunner1,Nutrunner 1,WORKUNIT_11,station1
nutrunner2,Nutrunner 2,WORKUNIT_11,station1
```

- [ ] **Step 1.3** `data/manual-line2.txt` (LF, 8 lines; cited by line; Task 6 appends six more lines in its own copy):

```
Station1 running: nsu=urn:bifrost:opcua:sim;s=Line2/Station1.Running, Boolean
Station2 running: nsu=urn:bifrost:opcua:sim;s=Line2/Station2.Running, Boolean
Nutrunner1 torque: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner1.Torque, Double, N.m
Nutrunner1 running: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner1.Running, Boolean
Nutrunner2 torque: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner2.Torque, Double, N.m
Nutrunner2 running: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner2.Running, Boolean
Occupancy: topic mfg.occupancy, EPCIS ObjectEvent field names, MES unit ids
Incidents: topic mfg.incidents, kinds tool-check-failed and gauge-drift
```

- [ ] **Step 1.4** `hierarchy/0.json` (2.23.0, the `vor-read` shape, six nodes; `evidenceRefs` of node *n* cites `hierarchy-plant-register` text-line *n+1* in CSV order):

```json
{
  "kind": "equipment-hierarchy",
  "schemaVersion": "2.23.0",
  "id": "line2-plant",
  "version": "1.0.0",
  "label": "Synthetic plant, line 2",
  "levelVocabulary": "opc-10030-1.00-isa95-equipment-element-level-enum",
  "nodes": [
    {"equipmentInstanceId": "synthetic-site", "label": "Synthetic site", "equipmentLevel": "SITE_1", "parentEquipmentInstanceId": null,
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 2}}]},
    {"equipmentInstanceId": "line2", "label": "Line 2", "equipmentLevel": "PRODUCTIONLINE_5", "parentEquipmentInstanceId": "synthetic-site",
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 3}}]},
    {"equipmentInstanceId": "station1", "label": "Station 1", "equipmentLevel": "WORKCELL_6", "parentEquipmentInstanceId": "line2",
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 4}}]},
    {"equipmentInstanceId": "station2", "label": "Station 2", "equipmentLevel": "WORKCELL_6", "parentEquipmentInstanceId": "line2",
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 5}}]},
    {"equipmentInstanceId": "nutrunner1", "label": "Nutrunner 1", "equipmentLevel": "WORKUNIT_11", "parentEquipmentInstanceId": "station1",
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 6}}]},
    {"equipmentInstanceId": "nutrunner2", "label": "Nutrunner 2", "equipmentLevel": "WORKUNIT_11", "parentEquipmentInstanceId": "station1",
     "evidenceRefs": [{"artifactId": "hierarchy-plant-register", "locator": {"kind": "text-line", "line": 7}}]}
  ],
  "evidenceRefs": []
}
```

(Write every fixture JSON pretty-printed with two-space indent and a trailing newline, as Tyr writes them; the step 1.12 script normalises this.)

- [ ] **Step 1.5** Evidence artifacts. `evidence/hierarchy-0.json` and `evidence/manual-line2.json` are 1.0.0 like the `vor-read` ones; the two profile artifacts are 1.1.0 (spec 192). `sha256` values are filled by step 1.12.

```json
{"kind": "evidence-artifact", "schemaVersion": "1.0.0", "id": "hierarchy-plant-register", "version": "1.0.0", "origin": "synthetic",
 "file": {"path": "data/hierarchy-0.csv", "sha256": "<pinned>", "mediaType": "text/csv"},
 "capturedAt": "2026-11-06T00:00:00Z", "product": null,
 "scope": ["synthetic-site", "line2", "station1", "station2", "nutrunner1", "nutrunner2"]}
```
```json
{"kind": "evidence-artifact", "schemaVersion": "1.0.0", "id": "manual-line2", "version": "1.0.0", "origin": "synthetic",
 "file": {"path": "data/manual-line2.txt", "sha256": "<pinned>", "mediaType": "text/plain"},
 "capturedAt": "2026-11-06T00:00:00Z", "product": null,
 "scope": ["station1", "station2", "nutrunner1", "nutrunner2"]}
```
```json
{"kind": "evidence-artifact", "schemaVersion": "1.1.0", "id": "occupancy-binding-line2", "version": "1.0.0", "origin": "synthetic",
 "file": {"path": "data/occupancy-binding-line2.json", "sha256": "<pinned>", "mediaType": "application/vnd.forseti.occupancy-binding+json"},
 "capturedAt": "2026-11-06T00:00:00Z", "product": null,
 "scope": ["station1", "station2"]}
```
```json
{"kind": "evidence-artifact", "schemaVersion": "1.1.0", "id": "incident-binding-line2", "version": "1.0.0", "origin": "synthetic",
 "file": {"path": "data/incident-binding-line2.json", "sha256": "<pinned>", "mediaType": "application/vnd.forseti.incident-binding+json"},
 "capturedAt": "2026-11-06T00:00:00Z", "product": null,
 "scope": ["station1", "station2"]}
```

- [ ] **Step 1.6** Profile data files (spec lines 206-222). `schemaSha256` is a placeholder digest until forseti publishes its schemas (step 3); Bifrost checks only its form (64 lowercase hex characters, spec line 204), so the fixture stays valid when the real digests arrive.

`data/occupancy-binding-line2.json`:
```json
{
  "profileVersion": "0.1.0",
  "topic": "mfg.occupancy",
  "format": {"schemaId": "urn:forseti:schema:occupancy:1.0.0",
             "schemaSha256": "0000000000000000000000000000000000000000000000000000000000000001"},
  "identity": {"scheme": "mes-unit-id", "pattern": "[A-Z0-9]{17}"},
  "enter": {"bizStep": "urn:epcglobal:cbv:bizstep:arriving"},
  "leave": {"bizStep": "urn:epcglobal:cbv:bizstep:departing"},
  "correction": {"errorDeclaration": "reissue-same-event-id",
                 "reasons": ["urn:epcglobal:cbv:er:did_not_occur", "urn:epcglobal:cbv:er:incorrect_data"]},
  "timestampBasis": "eventTime",
  "sources": ["mes-line2"]
}
```
`data/incident-binding-line2.json`:
```json
{
  "profileVersion": "0.1.0",
  "topic": "mfg.incidents",
  "format": {"schemaId": "urn:forseti:schema:incident:1.0.0",
             "schemaSha256": "0000000000000000000000000000000000000000000000000000000000000002"},
  "kinds": ["tool-check-failed", "gauge-drift"],
  "equipmentRefBasis": "isa95-path"
}
```

- [ ] **Step 1.7** Semantic definitions (2.12.0, the `vor-read` shape; `valueType` comes from the common `resultType` enum `Double | Int32 | Boolean | String`).

`semantics/station.json`:
```json
{"kind": "semantic-definition", "schemaVersion": "2.12.0", "id": "station-model", "version": "1.0.0",
 "members": [
  {"memberId": "running", "name": "Running", "semanticId": "urn:bifrost:sem:Station/Running", "description": "Station is working",
   "valueType": "Boolean", "unit": {"status": "not-applicable"}, "role": "status", "range": null}]}
```
`semantics/tool.json`:
```json
{"kind": "semantic-definition", "schemaVersion": "2.12.0", "id": "tool-model", "version": "1.0.0",
 "members": [
  {"memberId": "torque", "name": "Torque", "semanticId": "urn:bifrost:sem:Tool/Torque", "description": "Tightening torque",
   "valueType": "Double", "unit": {"status": "known", "code": "N.m"}, "role": "measurement", "range": {"low": "0", "high": "100"}},
  {"memberId": "running", "name": "Running", "semanticId": "urn:bifrost:sem:Tool/Running", "description": "Tool is working",
   "valueType": "Boolean", "unit": {"status": "not-applicable"}, "role": "status", "range": null}]}
```

- [ ] **Step 1.8** Source definitions (2.7.0, the `vor-read` `mixer1-temp` shape; `inputStage` `already-engineered` for every source, as the Boolean constant `valid/sources/5.json` and the Float64 `vor-read/sources/0.json` do). Template for a Boolean one; the table gives the six variants.

```json
{"kind": "source-definition", "schemaVersion": "2.7.0", "id": "station1-running", "version": "1.0.0",
 "equipmentInstanceId": "station1", "connectionProfileRef": "sim-opcua-station1", "accessProfileRef": "s7-1500-opcua-v1",
 "status": "ready", "rawAddressText": "nsu=urn:bifrost:opcua:sim;s=Line2/Station1.Running", "addressRadix": null,
 "access": {"kind": "opcua-node", "namespaceUri": "urn:bifrost:opcua:sim", "identifierType": "string", "identifier": "Line2/Station1.Running"},
 "rawRepresentation": {"mode": "typed", "valueType": "Boolean"},
 "inputStage": "already-engineered", "unit": {"status": "not-applicable"},
 "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 1}}],
 "viewOf": null, "sourceKind": "plc", "accessMode": "read"}
```

| id | equipmentInstanceId | connectionProfileRef | identifier | valueType | unit | line |
|---|---|---|---|---|---|---|
| `station1-running` | `station1` | `sim-opcua-station1` | `Line2/Station1.Running` | `Boolean` | not-applicable | 1 |
| `station2-running` | `station2` | `sim-opcua-station2` | `Line2/Station2.Running` | `Boolean` | not-applicable | 2 |
| `nutrunner1-torque` | `nutrunner1` | `sim-opcua-nutrunner1` | `Line2/Station1/Nutrunner1.Torque` | `Float64` | `{"status":"known","code":"N.m"}` | 3 |
| `nutrunner1-running` | `nutrunner1` | `sim-opcua-nutrunner1` | `Line2/Station1/Nutrunner1.Running` | `Boolean` | not-applicable | 4 |
| `nutrunner2-torque` | `nutrunner2` | `sim-opcua-nutrunner2` | `Line2/Station1/Nutrunner2.Torque` | `Float64` | `{"status":"known","code":"N.m"}` | 5 |
| `nutrunner2-running` | `nutrunner2` | `sim-opcua-nutrunner2` | `Line2/Station1/Nutrunner2.Running` | `Boolean` | not-applicable | 6 |

(`rawAddressText` is `nsu=urn:bifrost:opcua:sim;s=` + identifier. Every identifier ends with `.` + the metric name, which spec line 132 requires for `opcua-node` sources.)

- [ ] **Step 1.9** Target instances (2.0.0) and mapping sets (2.12.0).

`targets/station1.json` (vary id/equipmentInstanceId/label/semanticDefinitionRef per the table):
```json
{"kind": "target-instance", "schemaVersion": "2.0.0", "id": "station1", "version": "1.0.0", "equipmentInstanceId": "station1",
 "label": "Station 1", "semanticDefinitionRef": {"id": "station-model", "version": "1.0.0"},
 "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 1}}]}
```

| target id | label | semanticDefinitionRef.id | evidence line |
|---|---|---|---|
| `station1` | Station 1 | `station-model` | 1 |
| `station2` | Station 2 | `station-model` | 2 |
| `nutrunner1` | Nutrunner 1 | `tool-model` | 3 |
| `nutrunner2` | Nutrunner 2 | `tool-model` | 5 |

`mappings/nutrunner1.json` (the Boolean mapping has `"transform": []`; the torque mapping has the `cast` to `Double` of the `vor-read` fixture; a mapping's `evidenceRefs` equal its source's, which `mapping.evidence-incomplete` requires; `mappingId`s are bundle-unique):
```json
{"kind": "mapping-set", "schemaVersion": "2.12.0", "id": "nutrunner1-mapping", "version": "1.0.0", "equipmentInstanceId": "nutrunner1",
 "targetInstanceRef": {"id": "nutrunner1", "version": "1.0.0"},
 "mappings": [
  {"mappingId": "nutrunner1-torque",
   "valueRef": {"kind": "source", "sourceRef": {"id": "nutrunner1-torque", "version": "1.0.0"}},
   "memberPath": [{"kind": "member", "memberId": "torque"}],
   "transform": [{"op": "cast", "to": "Double", "rounding": "exact", "overflow": "error"}],
   "outputUnit": {"status": "known", "code": "N.m"}, "invalidValuePolicy": "bad-quality",
   "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 3}}],
   "temporalPolicy": {"timestampBasis": "source", "maxAgeMs": 5000, "maxSkewMs": 0, "uncertainInput": "reject",
                      "missingInput": "reject", "badInput": "propagate", "assembly": "latest"}},
  {"mappingId": "nutrunner1-running",
   "valueRef": {"kind": "source", "sourceRef": {"id": "nutrunner1-running", "version": "1.0.0"}},
   "memberPath": [{"kind": "member", "memberId": "running"}],
   "transform": [],
   "outputUnit": {"status": "not-applicable"}, "invalidValuePolicy": "bad-quality",
   "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 4}}],
   "temporalPolicy": {"timestampBasis": "source", "maxAgeMs": 5000, "maxSkewMs": 0, "uncertainInput": "reject",
                      "missingInput": "reject", "badInput": "propagate", "assembly": "latest"}}]}
```

| mapping-set id | equipmentInstanceId | targetInstanceRef.id | mappings (mappingId -> sourceRef.id, memberId, line) |
|---|---|---|---|
| `station1-mapping` | `station1` | `station1` | `station1-running` -> `station1-running`, `running`, 1 |
| `station2-mapping` | `station2` | `station2` | `station2-running` -> `station2-running`, `running`, 2 |
| `nutrunner1-mapping` | `nutrunner1` | `nutrunner1` | `nutrunner1-torque` (3), `nutrunner1-running` (4) |
| `nutrunner2-mapping` | `nutrunner2` | `nutrunner2` | `nutrunner2-torque` (5), `nutrunner2-running` (6) |

- [ ] **Step 1.10** The two rules (spec lines 119-173; field values from spec Decision 8, line 59: out-of-orderness 30 s, allowed lateness 12 min, horizon 24 h, tolerances 45 s, period 1000 ms; Decision 9, line 63: work records 7 d). `members[]` lists every member the rule reads, measurement and activity alike (spec line 132); `metric` is the semantic leaf `name`, `semanticId` the leaf's.

`rules/attribution-line2.json`:
```json
{
  "kind": "attribution-rule",
  "schemaVersion": "2.27.0",
  "id": "line2-attribution",
  "version": "1.0.0",
  "label": "Line 2 occupancy-join attribution",
  "description": "Joins nutrunner torque samples with MES occupancy at station 1 and station 2 by event time.",
  "equipmentRef": {"id": "line2-plant", "version": "1.0.0"},
  "stations": ["synthetic-site:line2:station1", "synthetic-site:line2:station2"],
  "members": [
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-torque",
     "semanticId": "urn:bifrost:sem:Tool/Torque", "metric": "Torque"},
    {"mappingSetRef": {"id": "nutrunner2-mapping", "version": "1.0.0"}, "mappingId": "nutrunner2-torque",
     "semanticId": "urn:bifrost:sem:Tool/Torque", "metric": "Torque"},
    {"mappingSetRef": {"id": "station1-mapping", "version": "1.0.0"}, "mappingId": "station1-running",
     "semanticId": "urn:bifrost:sem:Station/Running", "metric": "Running"},
    {"mappingSetRef": {"id": "station2-mapping", "version": "1.0.0"}, "mappingId": "station2-running",
     "semanticId": "urn:bifrost:sem:Station/Running", "metric": "Running"},
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-running",
     "semanticId": "urn:bifrost:sem:Tool/Running", "metric": "Running"},
    {"mappingSetRef": {"id": "nutrunner2-mapping", "version": "1.0.0"}, "mappingId": "nutrunner2-running",
     "semanticId": "urn:bifrost:sem:Tool/Running", "metric": "Running"}
  ],
  "activity": [
    {"equipmentPath": "synthetic-site:line2:station1", "memberRef": "station1-running", "activeWhen": true},
    {"equipmentPath": "synthetic-site:line2:station2", "memberRef": "station2-running", "activeWhen": true},
    {"equipmentPath": "synthetic-site:line2:station1:nutrunner1", "memberRef": "nutrunner1-running", "activeWhen": true},
    {"equipmentPath": "synthetic-site:line2:station1:nutrunner2", "memberRef": "nutrunner2-running", "activeWhen": true}
  ],
  "occupancyBindingRef": {"id": "occupancy-binding-line2", "version": "1.0.0"},
  "identity": {"mode": "occupancy-join", "crossCheck": "none"},
  "temporal": {"timestampBasis": "source", "outOfOrdernessMs": 30000, "allowedLatenessMs": 720000, "horizonMs": 86400000,
               "enterToleranceMs": 45000, "leaveToleranceMs": 45000},
  "quality": {"uncertainInput": "reject", "maxBadShare": 0.1},
  "coverage": {"expectedPeriodMs": 1000, "maxMissingPeriods": 3},
  "overlap": {"policy": "reject-ambiguous"},
  "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 7}}]
}
```

`rules/impact-line2.json`:
```json
{
  "kind": "impact-rule",
  "schemaVersion": "2.27.0",
  "id": "line2-impact",
  "version": "1.0.0",
  "label": "Line 2 tool incident impact",
  "description": "Marks visits in which a nutrunner shows activity inside an incident's suspect interval.",
  "attributionRuleRef": {"id": "line2-attribution", "version": "1.0.0"},
  "incidentScope": ["synthetic-site:line2:station1:nutrunner1", "synthetic-site:line2:station1:nutrunner2"],
  "incidentBindingRef": {"id": "incident-binding-line2", "version": "1.0.0"},
  "interval": {"start": "suspectFrom", "overlap": "any-overlap", "openEnd": "provisional-until-closed"},
  "evidence": {"match": "equipment-evidence", "onBasisRetracted": "by-cause", "onWithdrawn": "not-affected"},
  "retention": {"workRecordsMs": 604800000},
  "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 8}}]
}
```

- [ ] **Step 1.11** `proposal.json` and `submission.json` (the `vor-read` shape).

`proposal.json` (`sha256` pinned by step 1.12; order: hierarchy, evidence, semantics, sources, targets, mappings, rules):
```json
{"kind": "mapping-proposal", "schemaVersion": "2.27.0", "id": "local-workspace", "version": "1.0.0", "baseRelease": null,
 "files": [
  {"path": "hierarchy/0.json", "kind": "equipment-hierarchy", "id": "line2-plant", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "evidence/hierarchy-0.json", "kind": "evidence-artifact", "id": "hierarchy-plant-register", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "evidence/manual-line2.json", "kind": "evidence-artifact", "id": "manual-line2", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "evidence/occupancy-binding-line2.json", "kind": "evidence-artifact", "id": "occupancy-binding-line2", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "evidence/incident-binding-line2.json", "kind": "evidence-artifact", "id": "incident-binding-line2", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "semantics/station.json", "kind": "semantic-definition", "id": "station-model", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "semantics/tool.json", "kind": "semantic-definition", "id": "tool-model", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/station1-running.json", "kind": "source-definition", "id": "station1-running", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/station2-running.json", "kind": "source-definition", "id": "station2-running", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner1-torque.json", "kind": "source-definition", "id": "nutrunner1-torque", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner1-running.json", "kind": "source-definition", "id": "nutrunner1-running", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner2-torque.json", "kind": "source-definition", "id": "nutrunner2-torque", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner2-running.json", "kind": "source-definition", "id": "nutrunner2-running", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "targets/station1.json", "kind": "target-instance", "id": "station1", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "targets/station2.json", "kind": "target-instance", "id": "station2", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "targets/nutrunner1.json", "kind": "target-instance", "id": "nutrunner1", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "targets/nutrunner2.json", "kind": "target-instance", "id": "nutrunner2", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "mappings/station1.json", "kind": "mapping-set", "id": "station1-mapping", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "mappings/station2.json", "kind": "mapping-set", "id": "station2-mapping", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "mappings/nutrunner1.json", "kind": "mapping-set", "id": "nutrunner1-mapping", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "mappings/nutrunner2.json", "kind": "mapping-set", "id": "nutrunner2-mapping", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "rules/attribution-line2.json", "kind": "attribution-rule", "id": "line2-attribution", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "rules/impact-line2.json", "kind": "impact-rule", "id": "line2-impact", "version": "1.0.0", "sha256": "<pinned>"}
 ]}
```

`submission.json`:
```json
{"kind": "mapping-submission", "schemaVersion": "2.9.0", "id": "attribution-impact-fixture", "streamId": "line2", "version": "1.0.0",
 "workspaceSha256": "<pinned>", "proposalSha256": "<pinned>", "baseRelease": null, "proposedBy": "proposer", "execution": "excluded",
 "context": {
  "equipment": [
   {"id": "synthetic-site", "label": "Synthetic site"}, {"id": "line2", "label": "Line 2"},
   {"id": "station1", "label": "Station 1"}, {"id": "station2", "label": "Station 2"},
   {"id": "nutrunner1", "label": "Nutrunner 1"}, {"id": "nutrunner2", "label": "Nutrunner 2"}],
  "connections": [
   {"id": "sim-opcua-station1", "label": "Bifrost OPC-UA sim", "equipmentInstanceId": "station1", "accessProfileRef": "s7-1500-opcua-v1"},
   {"id": "sim-opcua-station2", "label": "Bifrost OPC-UA sim", "equipmentInstanceId": "station2", "accessProfileRef": "s7-1500-opcua-v1"},
   {"id": "sim-opcua-nutrunner1", "label": "Bifrost OPC-UA sim", "equipmentInstanceId": "nutrunner1", "accessProfileRef": "s7-1500-opcua-v1"},
   {"id": "sim-opcua-nutrunner2", "label": "Bifrost OPC-UA sim", "equipmentInstanceId": "nutrunner2", "accessProfileRef": "s7-1500-opcua-v1"}]}}
```

- [ ] **Step 1.12** Pin every digest and normalise formatting. Save the script outside the repository (any temporary folder) and run it from the bifrost root with `python -I`; it is the procedure `scripts/run-command-method-gate.sh` lines 161-171 use inline for one file, applied to the whole bundle:

```python
# pin-fixture.py <bundle-dir>   (python -I pin-fixture.py core/src/test/resources/mapping-fixtures/attribution-impact)
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
def dump(rel, d): (root / rel).write_bytes((json.dumps(d, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
def sha(rel): return hashlib.sha256((root / rel).read_bytes()).hexdigest()
def load(rel): return json.loads((root / rel).read_bytes())
p = load("proposal.json")
for f in p["files"]:                       # 1. normalise every document, then pin evidence files
    d = load(f["path"]); dump(f["path"], d)
for f in p["files"]:
    if f["kind"] == "evidence-artifact":
        d = load(f["path"]); d["file"]["sha256"] = sha(d["file"]["path"]); dump(f["path"], d)
for f in p["files"]:                       # 2. pin every listed document
    f["sha256"] = sha(f["path"])
dump("proposal.json", p)
s = load("submission.json"); s["proposalSha256"] = s["workspaceSha256"] = sha("proposal.json"); dump("submission.json", s)
print("pinned", len(p["files"]), "files")
```

Expected: `pinned 23 files`. Check with `git -C bifrost status --short` that 29 new files appear and `file core/src/test/resources/mapping-fixtures/attribution-impact/proposal.json` reports no `CRLF`.

- [ ] **Step 1.13** The first test, red. Create `MappingAttributionRuleTest.java` with the setup of `MappingMetricDefinitionTest` (fixture `/mapping-fixtures/attribution-impact`, policy `ref` `line2`, clock `2026-11-06T00:00:00Z`) and one test:

```java
package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.27 attribution rule (occupancy-join): Tyr's wire bundle, Bifrost's own checks, real keys. */
class MappingAttributionRuleTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-06T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/attribution-impact").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    @Test void acceptsTyrBundle() {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
        assertEquals("2.27.0",text(c.proposal(),"schemaVersion"));
        assertEquals(1,c.documents().values().stream().filter(d->text(d,"kind").equals("attribution-rule")).count());
        assertEquals(1,c.documents().values().stream().filter(d->text(d,"kind").equals("impact-rule")).count());
    }
}
```

- [ ] **Step 1.14** Run: `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`
  Expected: `Tests run: 1, Failures: 1` with the report showing `"ruleCode":"mapping.schema-capability"` (no 2.27.0 resources yet: `MappingJson.resource` finds no `/mapping-contracts/2.27.0/mapping-proposal.schema.json`). If the failure is `bundle.unlisted-file:...` or `bundle.digest:...` first, the fixture is mis-pinned: re-run step 1.12.

- [ ] **Step 1.15** Commit: `test(mapping): add attribution-impact fixture bundle for contract 2.27.0`

### Task 2: 2.27.0 contract resources and the MappingBundle sets

**Files:**
- Create: `core/src/main/resources/mapping-contracts/2.27.0/{common,mapping-proposal,source-definition,attribution-rule,impact-rule}.schema.json`
- Modify: `core/src/main/java/dev/krillin/bifrost/core/mapping/MappingBundle.java`
- Test: `MappingAttributionRuleTest` (+6 tests)

- [ ] **Step 2.1** Add the compatibility tests to `MappingAttributionRuleTest` (the two of the step-1 row, the two older envelopes the MAPPING-PUBLICATION sections of 2.23 and 2.24 claim, the 2.7.0 regression for the new `String` value type, and the `rule.envelope` case of spec line 711):

```java
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void reseal() throws Exception {ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code){assertEquals(List.of(code),codes());}
    void accepted(){assertEquals(List.of(),codes());}
    /** A copy of another fixture whose proposal is re-stamped 2.27.0 and resealed; nothing else changes. */
    MappingBundle.Checked upgraded(String fixture) throws Exception {
        Path other=tmp.resolve(fixture);MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/"+fixture).toURI()),other);
        ObjectNode p=(ObjectNode)read(other.resolve("proposal.json"));p.put("schemaVersion","2.27.0");Files.write(other.resolve("proposal.json"),bytes(p));
        ObjectNode s=(ObjectNode)read(other.resolve("submission.json"));s.put("proposalSha256",sha(other.resolve("proposal.json")));Files.write(other.resolve("submission.json"),bytes(s));
        var c=new MappingBundle().validate(other);assertTrue(c.accepted(),c.report().toString());return c;
    }
    static long count(MappingBundle.Checked c,String field,String value){return c.documents().values().stream().filter(d->text(d,field).equals(value)).count();}
    /** A 2.26.0 proposal cannot list the new kinds: its fileEntry kind enum refuses them at the proposal schema, before any envelope check. */
    @Test void a226ProposalCannotCarryTheRules() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.26.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        refused("mapping.schema:2.26.0/mapping-proposal");
    }
    /** Spec line 711: a 2.27.0 document of any kind needs a 2.27.0 proposal. One plc source of vor-read re-issued at 2.27.0 under its
     *  2.26.0 proposal is refused rule.envelope (the source itself validates: the 2.27.0 plc schema admits it). */
    @Test void a227SourceAloneNeedsA227Proposal() throws Exception {
        Path other=tmp.resolve("vor-read");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/vor-read").toURI()),other);
        Path source=other.resolve("sources/0.json");ObjectNode s=(ObjectNode)read(source);s.put("schemaVersion","2.27.0");Files.write(source,bytes(s));
        ObjectNode p=(ObjectNode)read(other.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"path").equals("sources/0.json"))((ObjectNode)e).put("sha256",sha(source));Files.write(other.resolve("proposal.json"),bytes(p));
        ObjectNode sub=(ObjectNode)read(other.resolve("submission.json"));sub.put("proposalSha256",sha(other.resolve("proposal.json")));Files.write(other.resolve("submission.json"),bytes(sub));
        assertEquals(List.of("rule.envelope"),new MappingBundle().validate(other).report().path("findings").findValuesAsText("ruleCode"));
    }
    /** The vor-read bundle (2.26.0 command bindings, server certificate, read bindings) rides unchanged in a 2.27.0 proposal. */
    @Test void a226CommandBindingRidesInA227Proposal() throws Exception {assertEquals(2,count(upgraded("vor-read"),"kind","command-binding"));}
    /** The 2.22 broadcast and 2.21 record-field envelope checks accept a 2.27.0 proposal, as the 2.23-2.26 sections state. */
    @Test void a222BroadcastRidesInA227Proposal() throws Exception {assertTrue(count(upgraded("broadcast"),"schemaVersion","2.22.0")>0);}
    @Test void a221RecordFieldRidesInA227Proposal() throws Exception {assertTrue(count(upgraded("mixed-objects"),"schemaVersion","2.21.0")>0);}
    /** The String value type is a 2.27.0 addition: a 2.7.0 plc source still cannot declare it. */
    @Test void aTypedStringSourceIsStillRefusedAt270() throws Exception {
        change("sources/station1-running.json",s->((ObjectNode)s.path("rawRepresentation")).put("valueType","String"));
        refused("mapping.schema:2.7.0/source-definition");
    }
    /** Changes one listed file and re-pins it in the proposal and the submission, so only the rule under test fails. */
    void change(String path,Consumer<ObjectNode> mutation) throws Exception {
        Path file=bundle.resolve(path);ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"path").equals(path))((ObjectNode)e).put("sha256",sha(file));
        rewrite(bundle.resolve("proposal.json"),proposal);reseal();
    }
```

(`MappingBundle.Checked` is the record `validate` returns, with `report()`, `proposal()`, `submission()`, `documents()`, `files()` and `accepted()`; `MappingMetricDefinitionTest` uses the same accessors.)

- [ ] **Step 2.2** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: 7 run, 6 failures, every one on `mapping.schema-capability`: `MappingBundle.validate` reads the proposal schema (line 37) before the version set (line 38), and `MappingJson.resource` (lines 43-47) throws that code when a `/mapping-contracts/2.27.0/` resource is absent, so `acceptsTyrBundle`, the three `upgraded` tests and `aTypedStringSourceIsStillRefusedAt270` (their proposals are 2.27.0) and `a227SourceAloneNeedsA227Proposal` (its source schema is 2.27.0) all stop there. Only `a226ProposalCannotCarryTheRules` passes: the existing 2.26.0 proposal schema refuses the new kinds, which is the behaviour the step-1 row asks for; it stays as a regression guard.

- [ ] **Step 2.3** `common.schema.json`: copy `2.26.0/common.schema.json` byte for byte, then make exactly three edits: (a) line 3 `"$id": "urn:tyr:contract:2.27.0:common"`; (b) in `$defs/rawRepresentation/oneOf`, the branch whose `mode` is `const "typed"` (2.26.0 lines 552-576), append `"String"` after `"Boolean"` in its `valueType` enum (the other branches, including the `bytes` branch with `valueType` const `String` and a codec, are unchanged); (c) in `$defs/fileEntry/properties/kind/enum` (2.26.0 lines 968-987), after `"command-binding"` add `"attribution-rule"` and `"impact-rule"`. Verify: `diff core/src/main/resources/mapping-contracts/2.26.0/common.schema.json core/src/main/resources/mapping-contracts/2.27.0/common.schema.json` prints the `$id` line pair, a two-line hunk at the typed enum (`"Boolean"` -> `"Boolean",` + `"String"`) and a three-line hunk at the kind enum (`"command-binding"` -> `"command-binding",` + two new lines), nothing else. (The 2.24 -> 2.25 diff had the same shape for the kind enum.)

- [ ] **Step 2.4** `mapping-proposal.schema.json`: copy 2.26.0 and replace both `2.26.0` with `2.27.0` (the `schemaVersion` const and the `$id`). `diff` against 2.26.0 shows exactly those two lines.

- [ ] **Step 2.5** `source-definition.schema.json` (complete). A source-definition validates against `mapping-contracts/<its own schemaVersion>/source-definition.schema.json` (`MappingJson.schema`, lines 81-91, through `resource`, lines 43-48), so the typed `String` of the 2.27.0 `common` is reachable only through a 2.27.0 source-definition schema. This is the `plc` branch of `2.7.0/source-definition.schema.json` (its first `oneOf` member, lines 5-125) issued as one object, exactly as `2.10.0/source-definition.schema.json` re-issued that branch; `access`, `rawRepresentation`, `unit`, `evidenceRef`, `documentRef` and `fixedArray` resolve in the local 2.27.0 `common`. Constant and solution-tag sources keep their 2.7.0 schema (their inline typed enum already carries `String`).

```json
{
  "type": "object",
  "properties": {
    "kind": {"const": "source-definition"},
    "schemaVersion": {"const": "2.27.0"},
    "id": {"$ref": "common.schema.json#/$defs/id"},
    "version": {"$ref": "common.schema.json#/$defs/version"},
    "equipmentInstanceId": {"$ref": "common.schema.json#/$defs/id"},
    "connectionProfileRef": {"$ref": "common.schema.json#/$defs/id"},
    "accessProfileRef": {"enum": ["ab-logix-symbol-v1", "s7-1500-opcua-v1", "s7-300-db-v1", "melsec-device-v1"]},
    "status": {"enum": ["draft", "ready"]},
    "rawAddressText": {"type": "string", "minLength": 1},
    "addressRadix": {"anyOf": [{"enum": [8, 10, 16]}, {"type": "null"}]},
    "access": {"$ref": "common.schema.json#/$defs/access"},
    "rawRepresentation": {"$ref": "common.schema.json#/$defs/rawRepresentation"},
    "inputStage": {"enum": ["raw", "already-engineered"]},
    "unit": {"$ref": "common.schema.json#/$defs/unit"},
    "evidenceRefs": {"type": "array", "items": {"$ref": "common.schema.json#/$defs/evidenceRef"}, "minItems": 1},
    "viewOf": {"anyOf": [{"$ref": "common.schema.json#/$defs/documentRef"}, {"type": "null"}]},
    "fixedArray": {"$ref": "common.schema.json#/$defs/fixedArray"},
    "sourceKind": {"const": "plc"},
    "accessMode": {"enum": ["read", "write", "read-write"]}
  },
  "required": ["kind", "schemaVersion", "id", "version", "equipmentInstanceId", "connectionProfileRef", "accessProfileRef", "status",
               "rawAddressText", "addressRadix", "access", "rawRepresentation", "inputStage", "unit", "evidenceRefs", "viewOf",
               "sourceKind", "accessMode"],
  "additionalProperties": false,
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:tyr:contract:2.27.0:source-definition"
}
```

Write it pretty-printed in the two-space style of the 2.26.0 files (one property per line), so it reads beside the 2.10.0 file. `MappingBundle.source()` (lines 140-195) already handles a typed `String`: `WIDTH` has no entry for it, so no width check applies; `sourceSig` carries the type to `mappings()`, where an empty `transform` leaves it `String` and `mapping.type` compares it with the semantic leaf.

- [ ] **Step 2.6** `attribution-rule.schema.json` (complete):

```json
{
  "type": "object",
  "properties": {
    "kind": {"const": "attribution-rule"},
    "schemaVersion": {"const": "2.27.0"},
    "id": {"$ref": "common.schema.json#/$defs/id"},
    "version": {"$ref": "common.schema.json#/$defs/version"},
    "label": {"type": "string", "minLength": 1, "maxLength": 256},
    "description": {"type": "string", "minLength": 1, "maxLength": 4096},
    "equipmentRef": {"$ref": "common.schema.json#/$defs/documentRef"},
    "stations": {"type": "array", "items": {"$ref": "#/$defs/equipmentPath"}, "minItems": 1, "maxItems": 256, "uniqueItems": true},
    "members": {
      "type": "array", "maxItems": 1024,
      "items": {
        "type": "object",
        "properties": {
          "mappingSetRef": {"$ref": "common.schema.json#/$defs/documentRef"},
          "mappingId": {"$ref": "common.schema.json#/$defs/id"},
          "semanticId": {"type": "string", "format": "uri", "maxLength": 2048},
          "metric": {"type": "string", "minLength": 1, "maxLength": 256}
        },
        "required": ["mappingSetRef", "mappingId", "semanticId", "metric"],
        "additionalProperties": false
      }
    },
    "activity": {
      "type": "array", "minItems": 1, "maxItems": 256,
      "items": {
        "type": "object",
        "properties": {
          "equipmentPath": {"$ref": "#/$defs/equipmentPath"},
          "memberRef": {"$ref": "common.schema.json#/$defs/id"},
          "activeWhen": {"const": true}
        },
        "required": ["equipmentPath", "memberRef", "activeWhen"],
        "additionalProperties": false
      }
    },
    "occupancyBindingRef": {"$ref": "common.schema.json#/$defs/documentRef"},
    "identity": {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "mode": {"const": "occupancy-join"},
            "namespace": {"type": "string", "minLength": 1, "maxLength": 256},
            "crossCheck": {"enum": ["none", "occupancy"]}
          },
          "required": ["mode", "crossCheck"],
          "additionalProperties": false
        },
        {
          "type": "object",
          "properties": {
            "mode": {"const": "plc-stamped"},
            "namespace": {"type": "string", "minLength": 1, "maxLength": 256},
            "members": {
              "type": "array", "minItems": 1, "maxItems": 256,
              "items": {
                "type": "object",
                "properties": {
                  "equipmentPath": {"$ref": "#/$defs/equipmentPath"},
                  "unitMemberRef": {"$ref": "common.schema.json#/$defs/id"},
                  "visitMemberRef": {"$ref": "common.schema.json#/$defs/id"},
                  "presentMemberRef": {"$ref": "common.schema.json#/$defs/id"}
                },
                "required": ["equipmentPath", "unitMemberRef", "visitMemberRef", "presentMemberRef"],
                "additionalProperties": false
              }
            },
            "crossCheck": {"enum": ["none", "occupancy"]}
          },
          "required": ["mode", "namespace", "members", "crossCheck"],
          "additionalProperties": false
        }
      ]
    },
    "temporal": {
      "type": "object",
      "properties": {
        "timestampBasis": {"const": "source"},
        "outOfOrdernessMs": {"$ref": "#/$defs/ms"},
        "allowedLatenessMs": {"$ref": "#/$defs/ms"},
        "horizonMs": {"$ref": "#/$defs/ms"},
        "enterToleranceMs": {"$ref": "#/$defs/ms"},
        "leaveToleranceMs": {"$ref": "#/$defs/ms"}
      },
      "required": ["timestampBasis", "outOfOrdernessMs", "allowedLatenessMs", "horizonMs", "enterToleranceMs", "leaveToleranceMs"],
      "additionalProperties": false
    },
    "quality": {
      "type": "object",
      "properties": {
        "uncertainInput": {"enum": ["propagate", "reject"]},
        "maxBadShare": {"type": "number", "minimum": 0, "maximum": 1}
      },
      "required": ["uncertainInput", "maxBadShare"],
      "additionalProperties": false
    },
    "coverage": {
      "type": "object",
      "properties": {
        "expectedPeriodMs": {"type": "integer", "minimum": 1, "maximum": 86400000},
        "maxMissingPeriods": {"type": "integer", "minimum": 0}
      },
      "required": ["expectedPeriodMs", "maxMissingPeriods"],
      "additionalProperties": false
    },
    "overlap": {
      "type": "object",
      "properties": {"policy": {"const": "reject-ambiguous"}},
      "required": ["policy"],
      "additionalProperties": false
    },
    "evidenceRefs": {"type": "array", "items": {"$ref": "common.schema.json#/$defs/evidenceRef"}, "maxItems": 64}
  },
  "required": ["kind", "schemaVersion", "id", "version", "label", "description", "equipmentRef", "stations", "members", "activity",
               "occupancyBindingRef", "identity", "temporal", "quality", "coverage", "overlap", "evidenceRefs"],
  "additionalProperties": false,
  "$defs": {
    "equipmentPath": {"type": "string", "pattern": "^[a-z][a-z0-9._/-]*(:[a-z][a-z0-9._/-]*)*$", "maxLength": 4096},
    "ms": {"type": "integer", "minimum": 0, "maximum": 86400000}
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:tyr:contract:2.27.0:attribution-rule"
}
```

Notes. `MappingJson.expand` strips `$defs` from the expanded tree but resolves `#/$defs/...` against the raw document first (`doc.at(parts[1])`, line 58), so local refs are fine (2.12.0 `semantic-definition` already uses `#/$defs/member`). Where each list rule lives follows the code the spec assigns to it. `members[]` carries neither `minItems` nor `uniqueItems`: spec line 132 makes an empty list, a `mappingId` listed twice and two entries for one equipment and metric `attribution.member-unresolved`, so the validator checks them. `stations` carries `minItems 1` and `uniqueItems` (spec line 131, "non-empty and has no duplicates", no code named; refused as `mapping.schema:2.27.0/attribution-rule`), and `incidentScope` the same (spec line 168). `activity[]` carries `minItems 1` but no `uniqueItems`: spec line 133 says "The list is non-empty." as its own sentence, before the sentence that lists what "fail[s] with `attribution.activity-member`", so the plan reads non-emptiness as a rule with no code (schema) and only duplicates as `attribution.activity-member`; if the maintainers read the empty list as `attribution.activity-member`, drop that `minItems` and add a `require(r.path("activity").size()>0, ...)` before the activity loop, and `emptyActivityIsRefusedByTheSchema` changes its expected code. `identity.members[]` carries `minItems 1` (spec line 135, "required and non-empty when `plc-stamped`") and no `uniqueItems`, because a duplicated entry must reach `attribution.identity-equipment`. `reasons` and `kinds[]` non-emptiness is the profile readers' (spec lines 213, 224 and 226 assign `*.binding-profile`). `expectedPeriodMs` is 1-86400000 (spec line 138). The `ms` bound is the 2.x `temporalPolicy` bound (spec 136). `crossCheck: occupancy` is admitted under both modes (spec line 135). `namespace` is optional under `occupancy-join` and required under `plc-stamped`, and `identity.members` exists only under `plc-stamped` (spec 135). String lengths and `maxItems` follow the 2.24-2.26 schemas.

- [ ] **Step 2.7** `impact-rule.schema.json` (complete):

```json
{
  "type": "object",
  "properties": {
    "kind": {"const": "impact-rule"},
    "schemaVersion": {"const": "2.27.0"},
    "id": {"$ref": "common.schema.json#/$defs/id"},
    "version": {"$ref": "common.schema.json#/$defs/version"},
    "label": {"type": "string", "minLength": 1, "maxLength": 256},
    "description": {"type": "string", "minLength": 1, "maxLength": 4096},
    "attributionRuleRef": {"$ref": "common.schema.json#/$defs/documentRef"},
    "incidentScope": {
      "type": "array", "minItems": 1, "maxItems": 256, "uniqueItems": true,
      "items": {"type": "string", "pattern": "^[a-z][a-z0-9._/-]*(:[a-z][a-z0-9._/-]*)*$", "maxLength": 4096}
    },
    "incidentBindingRef": {"$ref": "common.schema.json#/$defs/documentRef"},
    "interval": {
      "type": "object",
      "properties": {
        "start": {"const": "suspectFrom"},
        "overlap": {"enum": ["any-overlap", "fully-within", "enter-within"]},
        "openEnd": {"const": "provisional-until-closed"}
      },
      "required": ["start", "overlap", "openEnd"],
      "additionalProperties": false
    },
    "evidence": {
      "type": "object",
      "properties": {
        "match": {"enum": ["equipment-evidence", "station-visit"]},
        "onBasisRetracted": {"enum": ["by-cause", "always-insufficient"]},
        "onWithdrawn": {"enum": ["not-affected", "insufficient"]}
      },
      "required": ["match", "onBasisRetracted", "onWithdrawn"],
      "additionalProperties": false
    },
    "retention": {
      "type": "object",
      "properties": {"workRecordsMs": {"type": "integer", "minimum": 0, "maximum": 7776000000}},
      "required": ["workRecordsMs"],
      "additionalProperties": false
    },
    "evidenceRefs": {"type": "array", "items": {"$ref": "common.schema.json#/$defs/evidenceRef"}, "maxItems": 64}
  },
  "required": ["kind", "schemaVersion", "id", "version", "label", "description", "attributionRuleRef", "incidentScope",
               "incidentBindingRef", "interval", "evidence", "retention", "evidenceRefs"],
  "additionalProperties": false,
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:tyr:contract:2.27.0:impact-rule"
}
```

(`7776000000` = 90 d, spec 172; `incidentScope` non-empty and distinct, spec line 168.)

- [ ] **Step 2.8** `MappingBundle.java`, seven one-line edits (line numbers of `cc103e9`):
  - line 38: append `"2.27.0"` to the `capability.proposal-version` set.
  - line 48: the `capability.document-kind` set ends `...,CommandBindings.KIND,"attribution-rule","impact-rule"` (literals now; Tasks 5 and 7 replace them with `AttributionRules.KIND` and `ImpactRules.KIND` when those classes exist).
  - line 63: append `"2.27.0"` to the `mapping.required` version set.
  - lines 105 and 106: append `"2.27.0"` to the `broadcast.envelope` and `record-field.envelope` sets.
  - line 107: `if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.26.0")))require(Set.of("2.26.0","2.27.0").contains(text(p,"schemaVersion")),"command-binding.envelope");` (the trigger stays a 2.26.0 document; only the proposal set widens).
  - after line 107, the envelope of the whole contract version (spec line 711; new line 108): `if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.27.0")))require(text(p,"schemaVersion").equals("2.27.0"),"rule.envelope");` Any document whose `schemaVersion` is 2.27.0, a rule, a 2.27.0 source definition or a kind added later at 2.27.0, needs a 2.27.0 proposal. The rule kinds themselves never reach it in an older proposal: that proposal's schema refuses them first (step 2.1).

- [ ] **Step 2.9** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: `Tests run: 7, Failures: 0` (no rule semantics are checked yet, so the fixture passes on schema and structure alone). If `acceptsTyrBundle` fails with `mapping.schema:2.27.0/attribution-rule`, print the report and fix the fixture against the schema, not the schema against the fixture. If `a222BroadcastRidesInA227Proposal` or `a221RecordFieldRidesInA227Proposal` fails with a `mapping.schema:2.27.0/mapping-proposal` finding, a file kind of that fixture is missing from the 2.27.0 `fileEntry` kind enum compared with the 2.21.0/2.22.0 enum: diff the two enums and report it in the PR rather than deleting the test.

- [ ] **Step 2.10** Run the whole core suite once, to see nothing older moved: `mvn -q -pl core test`. Expected: `BUILD SUCCESS`, failures 0 (`MappingCommandBindingTest.a226LinkNeedsA226Proposal` still passes: it downgrades the proposal to 2.25.0, which is outside the `command-binding.envelope` set and does not trigger `rule.envelope`; and `a226CommandBindingRidesInA227Proposal` shows the 2.26.0 link accepted in a 2.27.0 proposal).

- [ ] **Step 2.11** `git diff --check`; commit: `feat(mapping): accept proposal 2.27.0 with attribution-rule, impact-rule and typed String sources`

---

## Chunk 2: Binding profile readers

Both readers follow `ReadBindingProfile`: `parse(byte[] bytes, String code)` reads the published bytes, requires the exact field set, constant versions, non-empty values, and throws `IllegalArgumentException(code)` on the first violation. The caller passes `attribution.binding-profile` or `impact.binding-profile` (spec 192). Artifact id prefix and media type (spec lines 194-204) are checked by the rule validators in Chunk 3, next to the artifact lookup, as `CommandBindings.endpoint` checks `ServerCertificates.ID_PREFIX` and `MEDIA_TYPE`.

### Task 3: `OccupancyBindingProfile`

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/mapping/OccupancyBindingProfile.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingAttributionRuleTest.java` (direct `parse` tests)

- [ ] **Step 3.1** Add direct parse tests (red: class does not exist). Helper and cases:

```java
    static byte[] occupancy(java.util.function.Consumer<ObjectNode> edit) throws Exception {
        ObjectNode b=(ObjectNode)read(Path.of(MappingAttributionRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/occupancy-binding-line2.json").toURI()));
        edit.accept(b);return bytes(b);
    }
    static void occupancyRefused(byte[] profile){
        assertEquals("attribution.binding-profile",assertThrows(IllegalArgumentException.class,()->OccupancyBindingProfile.parse(profile,"attribution.binding-profile")).getMessage());
    }
    static void occupancyRefused(java.util.function.Consumer<ObjectNode> edit) throws Exception {occupancyRefused(occupancy(edit));}
    @Test void parsesTheFixtureProfile() throws Exception {
        var p=OccupancyBindingProfile.parse(occupancy(b->{}),"x");
        assertEquals("mfg.occupancy",p.topic());assertEquals("[A-Z0-9]{17}",p.identityPattern());assertEquals(List.of("mes-line2"),p.sources());
        assertEquals(List.of("urn:epcglobal:cbv:er:did_not_occur","urn:epcglobal:cbv:er:incorrect_data"),p.correctionReasons());
    }
    @Test void profileAcceptsASingleCorrectionReason() throws Exception {
        var p=OccupancyBindingProfile.parse(occupancy(b->((ArrayNode)b.path("correction").path("reasons")).remove(1)),"x");
        assertEquals(List.of("urn:epcglobal:cbv:er:did_not_occur"),p.correctionReasons());
    }
    @Test void profileRefusesAnExtraField() throws Exception {occupancyRefused(b->b.put("note","x"));}
    @Test void profileRefusesAMissingField() throws Exception {occupancyRefused(b->b.remove("leave"));}
    @Test void profileRefusesAnotherVersion() throws Exception {occupancyRefused(b->b.put("profileVersion","0.2.0"));}
    @Test void profileRefusesAnEmptyTopic() throws Exception {occupancyRefused(b->b.put("topic",""));}
    @Test void profileRefusesATopicOfAnotherType() throws Exception {occupancyRefused(b->b.put("topic",1));}
    @Test void profileRefusesAnotherSchemaId() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaId","urn:forseti:schema:occupancy:2.0.0"));}
    @Test void profileRefusesAShortSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","abc"));}
    @Test void profileRefusesAnUppercaseSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","A".repeat(64)));}
    @Test void profileRefusesANumericSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256",new java.math.BigInteger("1".repeat(64))));}
    @Test void profileRefusesAnotherIdentityScheme() throws Exception {occupancyRefused(b->((ObjectNode)b.path("identity")).put("scheme","vin"));}
    @Test void profileRefusesAnotherCorrectionMode() throws Exception {occupancyRefused(b->((ObjectNode)b.path("correction")).put("errorDeclaration","tombstone"));}
    @Test void profileRefusesAnUnknownCorrectionReason() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).add("urn:epcglobal:cbv:er:other"));}
    @Test void profileRefusesDuplicateCorrectionReasons() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).add("urn:epcglobal:cbv:er:did_not_occur"));}
    @Test void profileRefusesEmptyCorrectionReasons() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).removeAll());}
    @Test void profileRefusesAnotherTimestampBasis() throws Exception {occupancyRefused(b->b.put("timestampBasis","recordTime"));}
    @Test void profileRefusesEmptySources() throws Exception {occupancyRefused(b->((ArrayNode)b.path("sources")).removeAll());}
    @Test void profileRefusesDuplicateSources() throws Exception {occupancyRefused(b->((ArrayNode)b.path("sources")).add("mes-line2"));}
    @Test void profileRefusesSourcesThatAreNotAnArray() throws Exception {occupancyRefused(b->b.put("sources","mes-line2"));}
    @Test void profileRefusesBytesThatAreNotJson() {occupancyRefused("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    @Test void profileRefusesDuplicateKeys() {occupancyRefused("{\"topic\":\"a\",\"topic\":\"b\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    // identity.pattern: the syntax common to Java and ECMA-262 only (spec 225-226)
    static void pattern(String p) throws Exception {OccupancyBindingProfile.parse(occupancy(b->((ObjectNode)b.path("identity")).put("pattern",p)),"x");}
    static void patternRefused(String p) throws Exception {occupancyRefused(b->((ObjectNode)b.path("identity")).put("pattern",p));}
    @Test void patternAcceptsTheCommonSyntax() throws Exception {
        for(String p:List.of("[A-Z0-9]{17}","KMH[A-HJ-NPR-Z0-9]{14}","(?:VIN|BODY)-[0-9]+","[^ ]+","a.c","x?y*z+","[0-9]{2,}","[0-9]{2,4}","\\.[a-z]\\-","[A-Z0-9-]+","[a&b]","\\\\x"))pattern(p);
    }
    @Test void patternRefusesAnchors() throws Exception {patternRefused("^[A-Z]{3}$");patternRefused("BODY$");}
    @Test void patternRefusesLookaround() throws Exception {patternRefused("(?=A)[A-Z]{3}");patternRefused("(?<!X)[A-Z]{3}");}
    @Test void patternRefusesBackreferences() throws Exception {patternRefused("(?:A)\\1");}
    @Test void patternRefusesNamedAndCapturingGroups() throws Exception {patternRefused("(?<v>[A-Z]+)");patternRefused("([A-Z]+)");}
    @Test void patternRefusesFlags() throws Exception {patternRefused("(?i)abc");patternRefused("(?i:abc)");}
    @Test void patternRefusesClassShorthandsAndProperties() throws Exception {patternRefused("\\d{17}");patternRefused("\\p{Lu}+");patternRefused("[[:alpha:]]+");patternRefused("\\x41");}
    @Test void patternRefusesLazyAndPossessiveQuantifiers() throws Exception {patternRefused("[A-Z]+?");patternRefused("[A-Z]*+");}
    /** Java reads && inside brackets as class intersection; ECMA-262 reads two literal characters. Not common syntax. */
    @Test void patternRefusesClassIntersection() throws Exception {patternRefused("[a&&b]");patternRefused("[a-z&&def]");}
    @Test void patternRefusesMalformedSyntax() throws Exception {patternRefused("");patternRefused("[A-Z");patternRefused("(?:A");patternRefused("{3}");patternRefused("a{");patternRefused("A{4,2}");}
```

- [ ] **Step 3.2** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: compilation error (`OccupancyBindingProfile` cannot be resolved).

- [ ] **Step 3.3** Create `OccupancyBindingProfile.java` (complete):

```java
package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import java.util.regex.Pattern;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Bifrost's own reader of a forseti occupancy binding, profile 0.1.0: the data file an evidence-artifact (schemaVersion 1.1.0)
 *  carries, naming how an attribution rule accepts MES occupancy events. Read from the published bytes alone, no forseti code.
 *  An unsupported version, a missing or extra field, an empty value, or an identity pattern outside the syntax common to Java
 *  and ECMA-262 is refused with the caller's code (the rule validators pass attribution.binding-profile). schemaSha256 is
 *  checked for its form only; whether it equals the job's built-in schema is the job's start-up check. */
public record OccupancyBindingProfile(String topic,String schemaId,String schemaSha256,String identityScheme,String identityPattern,
                                      String enterBizStep,String leaveBizStep,List<String> correctionReasons,List<String> sources) {
 public static final String VERSION="0.1.0",SCHEMA_ID="urn:forseti:schema:occupancy:1.0.0",ID_PREFIX="occupancy-binding-",
  MEDIA_TYPE="application/vnd.forseti.occupancy-binding+json";
 static final Set<String> REASONS=Set.of("urn:epcglobal:cbv:er:did_not_occur","urn:epcglobal:cbv:er:incorrect_data");
 private static final Set<String> FIELDS=Set.of("profileVersion","topic","format","identity","enter","leave","correction","timestampBasis","sources");
 public static OccupancyBindingProfile parse(byte[] bytes,String code){
  JsonNode b;
  try{b=JSON.readTree(bytes);}catch(Exception e){throw new IllegalArgumentException(code);}
  require(b!=null&&b.isObject()&&names(b).equals(FIELDS),code);
  require(text(b,"profileVersion").equals(VERSION)&&nonEmpty(b,"topic")&&text(b,"timestampBasis").equals("eventTime"),code);
  JsonNode f=b.path("format"),id=b.path("identity"),enter=b.path("enter"),leave=b.path("leave"),c=b.path("correction");
  require(names(f).equals(Set.of("schemaId","schemaSha256"))&&text(f,"schemaId").equals(SCHEMA_ID)&&f.path("schemaSha256").isTextual()&&text(f,"schemaSha256").matches("[0-9a-f]{64}"),code);
  require(names(id).equals(Set.of("scheme","pattern"))&&text(id,"scheme").equals("mes-unit-id")&&nonEmpty(id,"pattern"),code);
  require(names(enter).equals(Set.of("bizStep"))&&nonEmpty(enter,"bizStep")&&names(leave).equals(Set.of("bizStep"))&&nonEmpty(leave,"bizStep"),code);
  require(names(c).equals(Set.of("errorDeclaration","reasons"))&&text(c,"errorDeclaration").equals("reissue-same-event-id"),code);
  List<String> reasons=strings(c.path("reasons"),code),sources=strings(b.path("sources"),code);
  require(REASONS.containsAll(reasons),code);
  require(BindingPattern.accepted(text(id,"pattern")),code);
  return new OccupancyBindingProfile(text(b,"topic"),text(f,"schemaId"),text(f,"schemaSha256"),text(id,"scheme"),text(id,"pattern"),
   text(enter,"bizStep"),text(leave,"bizStep"),reasons,sources);
 }
 static Set<String> names(JsonNode n){Set<String> s=new HashSet<>();if(n.isObject())n.fieldNames().forEachRemaining(s::add);return s;}
 static boolean nonEmpty(JsonNode n,String k){return n.path(k).isTextual()&&!n.path(k).asText().isEmpty();}
 /** A non-empty array of distinct non-empty strings. */
 static List<String> strings(JsonNode a,String code){
  require(a.isArray()&&a.size()>0,code);List<String> out=new ArrayList<>();
  for(JsonNode x:a){require(x.isTextual()&&!x.asText().isEmpty()&&!out.contains(x.asText()),code);out.add(x.asText());}
  return List.copyOf(out);
 }
 /** The regex subset of spec "Binding profiles": literals, '.', bracket classes with ranges and negation, a backslash before a
  *  non-alphanumeric ASCII character as a literal, the quantifiers * + ? {m} {m,} {m,n}, alternation and non-capturing groups.
  *  Anchors, lookaround, backreferences, flags, named or capturing groups, shorthand or property or POSIX classes, lazy or
  *  possessive quantifiers, Java's class intersection '&&' and a bare '{' are refused. Java compiles the accepted expression last. */
 static final class BindingPattern {
  private final String s;private int i;
  private BindingPattern(String s){this.s=s;}
  static boolean accepted(String p){
   if(p.isEmpty())return false;
   BindingPattern b=new BindingPattern(p);
   try{b.alternation();if(b.i!=p.length())return false;Pattern.compile(p);return true;}catch(RuntimeException e){return false;}
  }
  private boolean at(char c){return i<s.length()&&s.charAt(i)==c;}
  private void alternation(){sequence();while(at('|')){i++;sequence();}}
  private void sequence(){while(i<s.length()&&!at('|')&&!at(')')){atom();quantifier();}}
  private void atom(){
   char c=s.charAt(i);
   switch(c){
    case '(' -> {require(s.startsWith("(?:",i),"group");i+=3;alternation();require(at(')'),"group");i++;}
    case '[' -> charClass();
    case '\\' -> escape();
    case '.' -> i++;
    case '^','$',')','*','+','?','{','}','|',']' -> throw new IllegalArgumentException("meta");
    default -> i++;
   }
  }
  private void escape(){require(i+1<s.length(),"escape");char n=s.charAt(i+1);require(n<128&&!Character.isLetterOrDigit(n),"escape");i+=2;}
  private void charClass(){
   i++;if(at('^'))i++;require(!at(']'),"class");
   while(!at(']')){
    require(i<s.length(),"class");classChar();
    if(at('-')&&i+1<s.length()&&s.charAt(i+1)!=']'){i++;classChar();}
   }
   i++;
  }
  private void classChar(){
   char c=s.charAt(i);
   if(c=='\\')escape();
   else{require(c!='['&&c!=']'&&!(c=='&'&&i+1<s.length()&&s.charAt(i+1)=='&'),"class");i++;}
  }
  private void quantifier(){
   if(i>=s.length())return;
   char c=s.charAt(i);
   if(c=='*'||c=='+'||c=='?')i++;
   else if(c=='{'){
    int close=s.indexOf('}',i);require(close>i,"quantifier");String q=s.substring(i+1,close);
    require(q.matches("[0-9]+|[0-9]+,|[0-9]+,[0-9]+"),"quantifier");
    if(q.contains(",")&&!q.endsWith(","))require(Long.parseLong(q.split(",")[0])<=Long.parseLong(q.split(",")[1]),"quantifier");
    i=close+1;
   }else return;
   require(!(at('?')||at('+')||at('*')||at('{')),"quantifier");
  }
 }
}
```

Behaviour notes: `names(f).equals(...)` on a non-object yields an empty set and fails; `{` and `}` outside a quantifier are refused as metacharacters (ECMA-262 Annex B tolerates a lone `{`, Java does not; the common syntax is the strict one); the last `require` in `quantifier()` refuses a quantifier on a quantifier, which covers lazy `+?` and possessive `*+`; `escape()` accepts `\.`, `\-`, `\\`, `\]` and refuses `\d`, `\p`, `\x`, `\1`; a single `&` in a class is a literal in both engines, but `&&` is refused (Java intersection, ECMA-262 two literals); `JSON` is `MappingJson.JSON`, whose `STRICT_DUPLICATE_DETECTION` and `FAIL_ON_TRAILING_TOKENS` turn duplicate keys and trailing tokens into the caller's code. `MappingJson.text` is `asText()`, which renders a number as its digits, so `schemaSha256` is tested with `isTextual()` before the regex (a 64-digit integer would otherwise pass); every other field read with `text` is either compared with a constant no non-string renders to (`profileVersion`, `schemaId`, `scheme`, `errorDeclaration`, `timestampBasis`, and `equipmentRefBasis` in the incident reader) or goes through `nonEmpty`/`strings`, which test `isTextual` first. In the rule validators every `text` read is of a field the 2.27.0 schemas type as a string or of a bundle document already schema-checked.

- [ ] **Step 3.4** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: every test of the class passes (7 earlier + 32 new = 39). A failure inside `patternAcceptsTheCommonSyntax` names the first pattern the checker wrongly refuses; fix the checker, not the list.

- [ ] **Step 3.5** Commit: `feat(mapping): read the forseti occupancy binding profile 0.1.0`

### Task 4: `IncidentBindingProfile`

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/mapping/IncidentBindingProfile.java`
- Create: `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingImpactRuleTest.java` (setup + direct parse tests)

- [ ] **Step 4.1** Create `MappingImpactRuleTest` with the same imports and `setup` as `MappingAttributionRuleTest` (fixture `/mapping-fixtures/attribution-impact`, stream `line2`; the registry fields may be omitted, the class does not publish) and these direct parse tests (red):

```java
    static byte[] incident(java.util.function.Consumer<ObjectNode> edit) throws Exception {
        ObjectNode b=(ObjectNode)read(Path.of(MappingImpactRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/incident-binding-line2.json").toURI()));
        edit.accept(b);return bytes(b);
    }
    static void incidentRefused(byte[] profile){
        assertEquals("impact.binding-profile",assertThrows(IllegalArgumentException.class,()->IncidentBindingProfile.parse(profile,"impact.binding-profile")).getMessage());
    }
    static void incidentRefused(java.util.function.Consumer<ObjectNode> edit) throws Exception {incidentRefused(incident(edit));}
    @Test void parsesTheFixtureProfile() throws Exception {
        var p=IncidentBindingProfile.parse(incident(b->{}),"x");
        assertEquals("mfg.incidents",p.topic());assertEquals(List.of("tool-check-failed","gauge-drift"),p.kinds());assertEquals("isa95-path",p.equipmentRefBasis());
    }
    @Test void profileAcceptsASingleKind() throws Exception {assertEquals(List.of("tool-check-failed"),IncidentBindingProfile.parse(incident(b->((ArrayNode)b.path("kinds")).remove(1)),"x").kinds());}
    @Test void profileRefusesAnExtraField() throws Exception {incidentRefused(b->b.put("note","x"));}
    @Test void profileRefusesAMissingField() throws Exception {incidentRefused(b->b.remove("kinds"));}
    @Test void profileRefusesAnotherVersion() throws Exception {incidentRefused(b->b.put("profileVersion","0.2.0"));}
    @Test void profileRefusesAnEmptyTopic() throws Exception {incidentRefused(b->b.put("topic",""));}
    @Test void profileRefusesAnotherSchemaId() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaId","urn:forseti:schema:occupancy:1.0.0"));}
    @Test void profileRefusesAShortSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","abc"));}
    @Test void profileRefusesAnUppercaseSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","A".repeat(64)));}
    @Test void profileRefusesANumericSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256",new java.math.BigInteger("1".repeat(64))));}
    @Test void profileRefusesEmptyKinds() throws Exception {incidentRefused(b->((ArrayNode)b.path("kinds")).removeAll());}
    @Test void profileRefusesDuplicateKinds() throws Exception {incidentRefused(b->((ArrayNode)b.path("kinds")).add("gauge-drift"));}
    @Test void profileRefusesAnotherEquipmentRefBasis() throws Exception {incidentRefused(b->b.put("equipmentRefBasis","node-id"));}
    @Test void profileRefusesBytesThatAreNotJson() {incidentRefused("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    @Test void profileRefusesDuplicateKeys() {incidentRefused("{\"topic\":\"a\",\"topic\":\"b\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
```

- [ ] **Step 4.2** Run `mvn -q -pl core -Dtest=MappingImpactRuleTest test`. Expected: compilation error.

- [ ] **Step 4.3** Create `IncidentBindingProfile.java` (complete):

```java
package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static dev.krillin.bifrost.core.mapping.OccupancyBindingProfile.*;
/** Bifrost's own reader of a forseti incident binding, profile 0.1.0: the data file an evidence-artifact (schemaVersion 1.1.0)
 *  carries, naming how an impact rule accepts quality incidents. Read from the published bytes alone, no forseti code. An
 *  unsupported version, a missing or extra field or an empty value is refused with the caller's code (impact.binding-profile).
 *  kinds[] is a non-empty list of distinct names; whether the incident schema supports each kind is the job's check. */
public record IncidentBindingProfile(String topic,String schemaId,String schemaSha256,List<String> kinds,String equipmentRefBasis) {
 public static final String VERSION="0.1.0",SCHEMA_ID="urn:forseti:schema:incident:1.0.0",ID_PREFIX="incident-binding-",
  MEDIA_TYPE="application/vnd.forseti.incident-binding+json";
 private static final Set<String> FIELDS=Set.of("profileVersion","topic","format","kinds","equipmentRefBasis");
 public static IncidentBindingProfile parse(byte[] bytes,String code){
  JsonNode b;
  try{b=JSON.readTree(bytes);}catch(Exception e){throw new IllegalArgumentException(code);}
  require(b!=null&&b.isObject()&&names(b).equals(FIELDS),code);
  require(text(b,"profileVersion").equals(VERSION)&&nonEmpty(b,"topic")&&text(b,"equipmentRefBasis").equals("isa95-path"),code);
  JsonNode f=b.path("format");
  require(names(f).equals(Set.of("schemaId","schemaSha256"))&&text(f,"schemaId").equals(SCHEMA_ID)&&f.path("schemaSha256").isTextual()&&text(f,"schemaSha256").matches("[0-9a-f]{64}"),code);
  return new IncidentBindingProfile(text(b,"topic"),text(f,"schemaId"),text(f,"schemaSha256"),strings(b.path("kinds"),code),text(b,"equipmentRefBasis"));
 }
}
```

(The static import of `OccupancyBindingProfile.*` brings `names`, `nonEmpty`, `strings`; keep those three package-private static in `OccupancyBindingProfile`. Both records are `public` like `ReadBindingProfile`, so step 2 Tyr acceptance tests and later forseti gates can name the constants.)

- [ ] **Step 4.4** Run `mvn -q -pl core -Dtest=MappingImpactRuleTest test`. Expected: 15 run, 0 failures.

- [ ] **Step 4.5** Commit: `feat(mapping): read the forseti incident binding profile 0.1.0`

---

## Chunk 3: Attribution validator and the plc-stamped identity

### Task 5: `AttributionRules` - the `attribution.*` codes reachable from the `occupancy-join` bundle

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/mapping/AttributionRules.java` (everything except the `plc-stamped` identity block, which Task 6 adds against its own red tests)
- Modify: `core/src/main/java/dev/krillin/bifrost/core/mapping/MappingBundle.java` (+1 call after line 102, constant at line 48)
- Test: `MappingAttributionRuleTest.java`

Check order inside one rule (fail-first, so the tests below are built against it): hierarchy resolves -> stations resolve -> stations not nested -> `members[]` non-empty -> each `members[]` entry resolves and matches (set, one `member` step, metric = leaf name, semanticId, distinct leaf names in its definition, opcua identifier suffix, listed once, one entry per (equipment, metric)) -> that member's equipment within the stations -> each `activity[]` entry -> binding artifact resolves -> binding artifact is a profile -> [identity coverage and identity member types, `plc-stamped` only: Task 6] -> temporal order. `EquipmentHierarchy.validate` (line 100) has already run, so an invalid hierarchy keeps its own `hierarchy.*` refusal (spec line 130).

- [ ] **Step 5.1** Add the bundle-level helpers and the negative tests to `MappingAttributionRuleTest` (red: every `refused("attribution.*")` returns `[]`):

```java
    void rule(Consumer<ObjectNode> mutation) throws Exception {change("rules/attribution-line2.json",mutation);}
    /** The profile data file is pinned by its evidence-artifact, not by the proposal: re-pin that artifact too. */
    void profileBytes(byte[] b) throws Exception {
        Files.write(bundle.resolve("data/occupancy-binding-line2.json"),b);
        change("evidence/occupancy-binding-line2.json",a->((ObjectNode)a.path("file")).put("sha256",sha0("data/occupancy-binding-line2.json")));
    }
    void profile(Consumer<ObjectNode> mutation) throws Exception {ObjectNode d=(ObjectNode)read(bundle.resolve("data/occupancy-binding-line2.json"));mutation.accept(d);profileBytes(bytes(d));}
    String sha0(String rel){try{return sha(bundle.resolve(rel));}catch(Exception e){throw new IllegalStateException(e);}}
    static ObjectNode member(ObjectNode r,int i){return (ObjectNode)r.path("members").get(i);}
    static ObjectNode activity(ObjectNode r,int i){return (ObjectNode)r.path("activity").get(i);}
    static ObjectNode ref(ObjectNode r,String field){return (ObjectNode)r.path(field);}
    static ObjectNode entry(String setId,String mappingId,String semanticId,String metric){
        ObjectNode e=object();e.set("mappingSetRef",object().put("id",setId).put("version","1.0.0"));return e.put("mappingId",mappingId).put("semanticId",semanticId).put("metric",metric);
    }
    static final String S1="synthetic-site:line2:station1",S2="synthetic-site:line2:station2",N1=S1+":nutrunner1",N2=S1+":nutrunner2";

    // hierarchy and stations
    @Test void hierarchyMissing() throws Exception {rule(r->ref(r,"equipmentRef").put("id","other-plant"));refused("attribution.hierarchy-missing");}
    @Test void anInvalidHierarchyKeepsItsOwnRefusal() throws Exception {
        // station1's parent becomes its own child: EquipmentHierarchy runs first and reports the cycle, not the rule
        change("hierarchy/0.json",h->((ObjectNode)h.path("nodes").get(2)).put("parentEquipmentInstanceId","nutrunner1"));refused("hierarchy.cycle");
    }
    @Test void stationUnresolved() throws Exception {rule(r->((ArrayNode)r.path("stations")).set(1,"synthetic-site:line2:station9"));refused("attribution.station-unresolved");}
    @Test void stationNested() throws Exception {rule(r->((ArrayNode)r.path("stations")).add("synthetic-site:line2"));refused("attribution.station-nested");}
    @Test void aStationThatIsAToolsAncestorIsNested() throws Exception {rule(r->((ArrayNode)r.path("stations")).add(N1));refused("attribution.station-nested");}
    @Test void duplicateStationsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("stations")).add(S1));refused("mapping.schema:2.27.0/attribution-rule");}
    @Test void emptyStationsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("stations")).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    // members[]: non-empty (spec line 132), resolution, metric, semanticId, the three extra checks, duplicates
    @Test void emptyMembersAreMemberUnresolved() throws Exception {rule(r->((ArrayNode)r.path("members")).removeAll());refused("attribution.member-unresolved");}
    @Test void memberMappingSetUnresolved() throws Exception {rule(r->ref(member(r,0),"mappingSetRef").put("version","9.9.9"));refused("attribution.member-unresolved");}
    @Test void memberMappingIdUnresolved() throws Exception {rule(r->member(r,0).put("mappingId","nutrunner1-speed"));refused("attribution.member-unresolved");}
    @Test void memberMappingIdOfAnotherSet() throws Exception {rule(r->member(r,0).put("mappingId","nutrunner2-torque"));refused("attribution.member-unresolved");}
    @Test void memberMetricMustEqualTheSemanticName() throws Exception {rule(r->member(r,0).put("metric","Torq"));refused("attribution.member-unresolved");}
    @Test void memberSemanticIdMustEqualTheMember() throws Exception {rule(r->member(r,0).put("semanticId","urn:bifrost:sem:Tool/Speed"));refused("attribution.member-unresolved");}
    @Test void memberListedTwice() throws Exception {rule(r->((ArrayNode)r.path("members")).add(member(r,0).deepCopy()));refused("attribution.member-unresolved");}
    @Test void twoMembersForOneEquipmentAndMetric() throws Exception {
        // a second mapping of nutrunner1's Torque: the rule may name only one entry per (equipment path, metric)
        change("mappings/nutrunner1.json",s->((ArrayNode)s.path("mappings")).add(((ObjectNode)s.path("mappings").get(0).deepCopy()).put("mappingId","nutrunner1-torque-copy")));
        rule(r->((ArrayNode)r.path("members")).add(entry("nutrunner1-mapping","nutrunner1-torque-copy","urn:bifrost:sem:Tool/Torque","Torque")));
        refused("attribution.member-unresolved");
    }
    @Test void memberSourceIdentifierMustEndWithTheMetric() throws Exception {
        change("sources/nutrunner1-torque.json",s->((ObjectNode)s.path("access")).put("identifier","Line2/Station1/Nutrunner1.Torq"));refused("attribution.member-unresolved");
    }
    @Test void duplicateLeafNamesInOneDefinitionAreRefused() throws Exception {
        change("semantics/tool.json",s->((ObjectNode)s.path("members").get(1)).put("name","Torque"));refused("attribution.member-unresolved");
    }
    /** Spec: a station and a tool may each have a member of the same name; the fixture's station-model and tool-model both carry Running. */
    @Test void aStationAndAToolMayEachHaveAMemberNamedRunning() throws Exception {
        assertEquals("Running",text(read(bundle.resolve("semantics/station.json")).path("members").get(0),"name"));
        assertEquals("Running",text(read(bundle.resolve("semantics/tool.json")).path("members").get(1),"name"));
        accepted();
    }
    @Test void memberEquipmentOutsideTheStations() throws Exception {
        // station2 alone: nutrunner1 under station1 is neither a station nor a descendant of one
        rule(r->{ArrayNode s=(ArrayNode)r.path("stations");s.removeAll();s.add(S2);});refused("attribution.member-equipment");
    }
    // activity[]
    @Test void activityMemberUnresolved() throws Exception {rule(r->activity(r,0).put("memberRef","station1-busy"));refused("attribution.activity-member");}
    @Test void activityMemberMustBeBoolean() throws Exception {rule(r->activity(r,2).put("memberRef","nutrunner1-torque"));refused("attribution.activity-member");}
    @Test void activityMemberMustBelongToItsEquipment() throws Exception {rule(r->activity(r,2).put("memberRef","nutrunner2-running"));refused("attribution.activity-member");}
    @Test void activityEquipmentMustBeTheMembers() throws Exception {rule(r->activity(r,0).put("equipmentPath","synthetic-site:line2"));refused("attribution.activity-member");}
    /** Two activity references to one mappingId (spec line 132): two activity entries for one equipment, activity-member. The
     *  different-members variant is in MappingPlcStampedRuleTest, whose station1 has a second Boolean member. */
    @Test void twoActivityEntriesForOneEquipment() throws Exception {rule(r->((ArrayNode)r.path("activity")).add(activity(r,0).deepCopy()));refused("attribution.activity-member");}
    @Test void anEquipmentWithoutAnActivityEntryIsAccepted() throws Exception {rule(r->((ArrayNode)r.path("activity")).remove(1));accepted();}
    @Test void emptyActivityIsRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("activity")).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    // occupancy binding
    @Test void bindingUnresolved() throws Exception {rule(r->ref(r,"occupancyBindingRef").put("version","9.9.9"));refused("attribution.binding-unresolved");}
    @Test void bindingMustBeAnArtifact110() throws Exception {change("evidence/occupancy-binding-line2.json",a->a.put("schemaVersion","1.0.0"));refused("attribution.binding-unresolved");}
    @Test void bindingArtifactMustCarryTheMediaType() throws Exception {
        change("evidence/occupancy-binding-line2.json",a->((ObjectNode)a.path("file")).put("mediaType","application/json"));refused("attribution.binding-profile");
    }
    @Test void bindingArtifactMustCarryThePrefix() throws Exception {
        // the artifact id must start with occupancy-binding-; rename it everywhere so only the prefix rule fails
        change("evidence/occupancy-binding-line2.json",a->a.put("id","binding-line2"));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"id").equals("occupancy-binding-line2"))((ObjectNode)e).put("id","binding-line2");rewrite(bundle.resolve("proposal.json"),p);reseal();
        rule(r->ref(r,"occupancyBindingRef").put("id","binding-line2"));
        refused("attribution.binding-profile");
    }
    @Test void bindingProfileWithAnExtraFieldIsRefused() throws Exception {profile(b->b.put("note","x"));refused("attribution.binding-profile");}
    @Test void bindingProfileWithAnAnchoredPatternIsRefused() throws Exception {profile(b->((ObjectNode)b.path("identity")).put("pattern","^[A-Z0-9]{17}$"));refused("attribution.binding-profile");}
    @Test void bindingProfileThatIsNotJsonIsRefused() throws Exception {profileBytes("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));refused("attribution.binding-profile");}
    @Test void bindingScopeIsNotComparedWithTheStations() throws Exception {
        change("evidence/occupancy-binding-line2.json",a->{ArrayNode s=(ArrayNode)a.path("scope");s.removeAll();s.add("station9");});accepted();
    }
    @Test void aProfileChangedWithoutResealIsADigestRefusal() throws Exception {
        Files.write(bundle.resolve("data/occupancy-binding-line2.json"),"{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        refused("bundle.digest:data/occupancy-binding-line2.json");
    }
    // identity under occupancy-join: namespace is optional (spec 135), identity entries are plc-stamped only
    @Test void aNamespaceIsAllowedUnderOccupancyJoin() throws Exception {rule(r->ref(r,"identity").put("namespace","urn:line2:visits"));accepted();}
    @Test void identityEntriesAreSchemaBoundToPlcStamped() throws Exception {
        rule(r->ref(r,"identity").putArray("members").addObject().put("equipmentPath",S1).put("unitMemberRef","station1-running").put("visitMemberRef","station1-running").put("presentMemberRef","station1-running"));
        refused("mapping.schema:2.27.0/attribution-rule");
    }
    @Test void crossCheckOccupancyIsAllowedUnderOccupancyJoin() throws Exception {rule(r->ref(r,"identity").put("crossCheck","occupancy"));accepted();}
    // temporal and coverage
    @Test void temporalOrder() throws Exception {rule(r->ref(r,"temporal").put("allowedLatenessMs",10000));refused("attribution.temporal-order");}
    @Test void temporalHorizonBelowLateness() throws Exception {rule(r->ref(r,"temporal").put("horizonMs",600000));refused("attribution.temporal-order");}
    @Test void temporalEqualBoundsAreAccepted() throws Exception {rule(r->ref(r,"temporal").put("outOfOrdernessMs",86400000).put("allowedLatenessMs",86400000).put("horizonMs",86400000));accepted();}
    @Test void expectedPeriodZeroIsRefusedByTheSchema() throws Exception {rule(r->ref(r,"coverage").put("expectedPeriodMs",0));refused("mapping.schema:2.27.0/attribution-rule");}
    // release
    @Test void releaseAndAttestationCarryBothRulesAndProfiles() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        Set<String> subjects=new HashSet<>();for(JsonNode s:statement.path("subject"))subjects.add(text(s.path("digest"),"sha256"));
        Map<String,String> files=new HashMap<>();for(JsonNode f:release.path("files"))files.put(text(f,"path"),text(f,"sha256"));
        for(String p:List.of("rules/attribution-line2.json","rules/impact-line2.json","evidence/occupancy-binding-line2.json","evidence/incident-binding-line2.json","data/occupancy-binding-line2.json","data/incident-binding-line2.json")){
            String h=files.entrySet().stream().filter(e->e.getKey().endsWith(p)).map(Map.Entry::getValue).findFirst().orElse(null);
            assertEquals(sha(bundle.resolve(p)),h,p);assertTrue(subjects.contains(h),p);
        }
    }
```

(`temporalEqualBoundsAreAccepted` keeps the impact rule valid: its `workRecordsMs` 604800000 is above the horizon 86400000.)

- [ ] **Step 5.2** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: 39 + 43 = 82 run; the `refused("attribution.*")` tests, `emptyMembersAreMemberUnresolved` among them (the schema admits the empty list), fail with `expected: <[attribution....]> but was: <[]>`, except `twoMembersForOneEquipmentAndMetric`, whose copied mapping is already `[mapping.duplicate-target]` from `MappingBundle.mappings()` (line 433) until the new validator refuses it first; `anInvalidHierarchyKeepsItsOwnRefusal`, the schema-bound tests, the `accepted()` tests, the digest test and the release test already pass.

- [ ] **Step 5.3** Create `AttributionRules.java` (complete for this task; the one commented line is where Task 6 inserts the identity block):

```java
package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.27 attribution-rule validator: the forseti stage-1 rule that joins governed process members with MES
 *  occupancy per station and tool. Everything resolves inside the bundle: the ISA-95 hierarchy the rule names, its stations
 *  (hierarchy paths that do not nest), its members (each a mapping of a mapping set whose equipment is a station or a tool
 *  under one, named by the metric Muninn publishes and the semantic id of the leaf it maps), one Boolean activity member per
 *  equipment, an occupancy binding profile carried by an evidence-artifact, the plc-stamped identity members, and the
 *  temporal order. Member references of activity and identity entries are mappingIds of the rule's own members[]. Refusal
 *  codes are the spec's attribution.* table; the first failure stops the rule. No forseti code is read. */
final class AttributionRules {
 static final String KIND="attribution-rule";
 interface Reader {byte[] read(String path) throws Exception;}
 /** One mapping of the bundle: its set, its equipment's hierarchy path, the semantic leaf it maps, whether its memberPath is
  *  one member step, whether the leaf names of its semantic definition are distinct, and its OPC UA node identifier (null
  *  unless the source is an opcua-node). */
 record Member(String setKey,String equipmentPath,JsonNode leaf,boolean oneStep,boolean distinctNames,String identifier) {}
 static void validate(Collection<JsonNode> docs,Reader files) throws Exception {
  for(JsonNode r:docs){
   if(!text(r,"kind").equals(KIND))continue;
   JsonNode hierarchy=find(docs,EquipmentHierarchy.KIND,r.path("equipmentRef"));
   require(hierarchy!=null,"attribution.hierarchy-missing");
   Map<String,String> paths=paths(hierarchy);Set<String> known=new HashSet<>(paths.values());
   List<String> stations=new ArrayList<>();for(JsonNode s:r.path("stations"))stations.add(s.asText());
   for(String s:stations)require(known.contains(s),"attribution.station-unresolved");
   for(String a:stations)for(String b:stations)require(!b.startsWith(a+":"),"attribution.station-nested");
   Map<String,Member> bundle=members(docs,paths),rule=new LinkedHashMap<>();Set<String> slots=new HashSet<>();
   require(r.path("members").size()>0,"attribution.member-unresolved");
   for(JsonNode m:r.path("members")){
    String id=text(m,"mappingId"),metric=text(m,"metric");Member x=bundle.get(id);
    require(x!=null&&x.setKey().equals(key(m.path("mappingSetRef")))&&x.oneStep()&&x.distinctNames()
     &&text(x.leaf(),"name").equals(metric)&&text(x.leaf(),"semanticId").equals(text(m,"semanticId"))
     &&(x.identifier()==null||x.identifier().endsWith("."+metric))
     &&rule.putIfAbsent(id,x)==null&&slots.add(x.equipmentPath()+"\n"+metric),"attribution.member-unresolved");
    require(within(stations,x.equipmentPath()),"attribution.member-equipment");
   }
   Set<String> active=new HashSet<>();
   for(JsonNode a:r.path("activity")){
    String path=text(a,"equipmentPath");Member x=rule.get(text(a,"memberRef"));
    require(x!=null&&x.equipmentPath().equals(path)&&within(stations,path)&&text(x.leaf(),"valueType").equals("Boolean")&&active.add(path),"attribution.activity-member");
   }
   JsonNode evidence=find(docs,"evidence-artifact",r.path("occupancyBindingRef"));
   require(evidence!=null&&text(evidence,"schemaVersion").equals("1.1.0"),"attribution.binding-unresolved");
   require(text(evidence,"id").startsWith(OccupancyBindingProfile.ID_PREFIX)&&text(evidence.path("file"),"mediaType").equals(OccupancyBindingProfile.MEDIA_TYPE),"attribution.binding-profile");
   OccupancyBindingProfile.parse(files.read(text(evidence.path("file"),"path")),"attribution.binding-profile");
   // plc-stamped identity: Task 6
   JsonNode t=r.path("temporal");
   require(t.path("outOfOrdernessMs").asLong()<=t.path("allowedLatenessMs").asLong()&&t.path("allowedLatenessMs").asLong()<=t.path("horizonMs").asLong(),"attribution.temporal-order");
  }
 }
 /** A path is a station of the rule or a descendant of one (a tool). Ids carry no ':', so the prefix test is exact. */
 static boolean within(List<String> stations,String path){
  for(String s:stations)if(path.equals(s)||path.startsWith(s+":"))return true;
  return false;
 }
 static String key(JsonNode ref){return text(ref,"id")+"@"+text(ref,"version");}
 /** Every mapping of the bundle by mappingId (unique across sets: mapping.duplicate-id). A mapping whose target, semantic
  *  definition, equipment or member path does not resolve is left out and is then attribution.member-unresolved here;
  *  MappingBundle.mappings() reports its own code later only when no rule check threw first. */
 static Map<String,Member> members(Collection<JsonNode> docs,Map<String,String> paths){
  Map<String,Member> out=new HashMap<>();Map<String,Boolean> distinct=new HashMap<>();
  for(JsonNode set:docs){
   if(!text(set,"kind").equals("mapping-set"))continue;
   JsonNode target=find(docs,"target-instance",set.path("targetInstanceRef"));if(target==null)continue;
   JsonNode semantic=find(docs,"semantic-definition",target.path("semanticDefinitionRef"));if(semantic==null)continue;
   String path=paths.get(text(set,"equipmentInstanceId"));if(path==null)continue;
   boolean names=distinct.computeIfAbsent(key(semantic),k->distinctNames(semantic));
   for(JsonNode m:set.path("mappings")){
    JsonNode leaf;try{leaf=LogicalStructure.resolve(semantic,m.path("memberPath"));}catch(IllegalArgumentException e){continue;}
    JsonNode v=m.path("valueRef"),source=text(v,"kind").equals("source")?find(docs,"source-definition",v.path("sourceRef")):null;
    String identifier=source!=null&&text(source.path("access"),"kind").equals("opcua-node")?text(source.path("access"),"identifier"):null;
    out.put(text(m,"mappingId"),new Member(key(set),path,leaf,m.path("memberPath").size()==1,names,identifier));
   }
  }
  return out;
 }
 /** Spec: within each semantic definition a rule uses, no two leaf members share a name (a station and a tool may each have a
  *  member of the same name, because Sparkplug metric names are scoped to one device). */
 static boolean distinctNames(JsonNode semantic){
  Set<String> names=new HashSet<>();
  try{for(LogicalStructure.Leaf l:LogicalStructure.layout(semantic).leaves().values())if(!names.add(text(l.member(),"name")))return false;}
  catch(IllegalArgumentException e){return false;}
  return true;
 }
 static JsonNode find(Collection<JsonNode> docs,String kind,JsonNode ref){
  for(JsonNode d:docs)if(text(d,"kind").equals(kind)&&text(d,"id").equals(text(ref,"id"))&&text(d,"version").equals(text(ref,"version")))return d;
  return null;
 }
 /** Each node's hierarchy path: root first, joined with ':', the string Muninn publishes as the Sparkplug device id and the
  *  occupancy readPoint carries (the rule of CommandBindings.path). EquipmentHierarchy has already refused cycles and missing
  *  parents. */
 static Map<String,String> paths(JsonNode hierarchy){
  Map<String,JsonNode> by=new HashMap<>();for(JsonNode n:hierarchy.path("nodes"))by.put(text(n,"equipmentInstanceId"),n);
  Map<String,String> out=new HashMap<>();
  for(String id:by.keySet()){
   Deque<String> p=new ArrayDeque<>();
   for(JsonNode n=by.get(id);n!=null;n=n.path("parentEquipmentInstanceId").isNull()?null:by.get(text(n,"parentEquipmentInstanceId")))p.addFirst(text(n,"equipmentInstanceId"));
   out.put(id,String.join(":",p));
  }
  return out;
 }
}
```

`LogicalStructure.resolve` on a 2.12.0 model walks `members[]` by `memberId`, so a one-step path to a leaf returns that leaf; `LogicalStructure.layout(...).leaves()` lists every leaf of the definition with the member node (`Leaf.member()`), which is what the name check reads. `key(JsonNode)` serves documents and `{id, version}` references alike.

- [ ] **Step 5.4** `MappingBundle.java`: after the `CommandBindings.validate(...)` line (102) insert

```java
            AttributionRules.validate(docs.values(),path->Files.readAllBytes(safe(root,path)));
```

and in the document-kind set (line 48) replace the literal `"attribution-rule"` with `AttributionRules.KIND`.

- [ ] **Step 5.5** Run `mvn -q -pl core -Dtest=MappingAttributionRuleTest test`. Expected: all 82 pass. Typical first-run failures and what they mean: `memberEquipmentOutsideTheStations` reporting `attribution.activity-member` means the members loop ran after the activity loop (keep the order above); `bindingArtifactMustCarryThePrefix` reporting `reference.missing` or `evidence.missing` means the rename missed the proposal entry or the rule's ref; `duplicateLeafNamesInOneDefinitionAreRefused` reporting `[]` means `distinctNames` read `memberId` instead of `name`; `aNamespaceIsAllowedUnderOccupancyJoin` reporting a schema code means step 2.6 left `namespace` out of the `occupancy-join` branch.

- [ ] **Step 5.6** `mvn -q -pl core test` - the whole core suite still green (no other fixture carries an attribution rule, so `AttributionRules.validate` is a no-op for them).

- [ ] **Step 5.7** Commit: `feat(mapping): validate attribution rules (2.27.0)`

### Task 6: The `attribution-plc-stamped` fixture bundle, `MappingPlcStampedRuleTest`, and the identity checks

**Files:**
- Create: `core/src/test/resources/mapping-fixtures/attribution-plc-stamped/` (37 files: the 29 of `attribution-impact`, 2 new semantic definitions, 6 new 2.27.0 source definitions; 8 of the copied files change)
- Create: `core/src/test/java/dev/krillin/bifrost/core/mapping/MappingPlcStampedRuleTest.java`
- Modify: `core/src/main/java/dev/krillin/bifrost/core/mapping/AttributionRules.java` (the identity block)

This is the `plc-stamped` fixture the step-1 row calls for: a rule whose String unit and visit members are typed OPC UA sources published under contract 2.27.0. Station1 and nutrunner1 carry `UnitId` (String), `VisitId` (String) and `VisitPresent` (Boolean) besides their existing members and use the semantic definitions `station-stamped-model` and `tool-stamped-model`; station2 and nutrunner2 keep `station-model`/`tool-model` and stay outside the rule, which shows that an equipment without members needs no identity entry and that station2 may be a station of the rule without an activity entry (spec line 133). The identity tests go red against the Task 5 validator, which does not look at `identity` yet; the block is added in step 6.9.

- [ ] **Step 6.1** `cp -r core/src/test/resources/mapping-fixtures/attribution-impact core/src/test/resources/mapping-fixtures/attribution-plc-stamped`, then apply the deltas below.

- [ ] **Step 6.2** Append six lines to `data/manual-line2.txt` (lines 9-14):

```
Station1 unit id: nsu=urn:bifrost:opcua:sim;s=Line2/Station1.UnitId, String
Station1 visit id: nsu=urn:bifrost:opcua:sim;s=Line2/Station1.VisitId, String
Station1 visit present: nsu=urn:bifrost:opcua:sim;s=Line2/Station1.VisitPresent, Boolean
Nutrunner1 unit id: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner1.UnitId, String
Nutrunner1 visit id: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner1.VisitId, String
Nutrunner1 visit present: nsu=urn:bifrost:opcua:sim;s=Line2/Station1/Nutrunner1.VisitPresent, Boolean
```

- [ ] **Step 6.3** New semantic definitions. `semantics/station-stamped.json`:

```json
{"kind": "semantic-definition", "schemaVersion": "2.12.0", "id": "station-stamped-model", "version": "1.0.0",
 "members": [
  {"memberId": "running", "name": "Running", "semanticId": "urn:bifrost:sem:Station/Running", "description": "Station is working",
   "valueType": "Boolean", "unit": {"status": "not-applicable"}, "role": "status", "range": null},
  {"memberId": "unit", "name": "UnitId", "semanticId": "urn:bifrost:sem:Station/UnitId", "description": "Unit present at the station, as the controller stamps it",
   "valueType": "String", "unit": {"status": "not-applicable"}, "role": "status", "range": null},
  {"memberId": "visit", "name": "VisitId", "semanticId": "urn:bifrost:sem:Station/VisitId", "description": "Producer visit id of the present unit",
   "valueType": "String", "unit": {"status": "not-applicable"}, "role": "status", "range": null},
  {"memberId": "present", "name": "VisitPresent", "semanticId": "urn:bifrost:sem:Station/VisitPresent", "description": "True while a unit is present",
   "valueType": "Boolean", "unit": {"status": "not-applicable"}, "role": "status", "range": null}]}
```

`semantics/tool-stamped.json`: id `tool-stamped-model`; the two members of `tool-model` (`torque`, `running`, unchanged bytes, same `semanticId`s so `semantic.identity-conflict` does not fire) followed by the same three members with `semanticId`s `urn:bifrost:sem:Tool/UnitId`, `urn:bifrost:sem:Tool/VisitId`, `urn:bifrost:sem:Tool/VisitPresent`.

- [ ] **Step 6.4** New source definitions (contract 2.27.0, the Task 2 schema). Template; the table gives the six variants (`rawAddressText` = `nsu=urn:bifrost:opcua:sim;s=` + identifier):

```json
{"kind": "source-definition", "schemaVersion": "2.27.0", "id": "station1-unit", "version": "1.0.0",
 "equipmentInstanceId": "station1", "connectionProfileRef": "sim-opcua-station1", "accessProfileRef": "s7-1500-opcua-v1",
 "status": "ready", "rawAddressText": "nsu=urn:bifrost:opcua:sim;s=Line2/Station1.UnitId", "addressRadix": null,
 "access": {"kind": "opcua-node", "namespaceUri": "urn:bifrost:opcua:sim", "identifierType": "string", "identifier": "Line2/Station1.UnitId"},
 "rawRepresentation": {"mode": "typed", "valueType": "String"},
 "inputStage": "already-engineered", "unit": {"status": "not-applicable"},
 "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 9}}],
 "viewOf": null, "sourceKind": "plc", "accessMode": "read"}
```

| id | equipmentInstanceId | connectionProfileRef | identifier | valueType | line |
|---|---|---|---|---|---|
| `station1-unit` | `station1` | `sim-opcua-station1` | `Line2/Station1.UnitId` | `String` | 9 |
| `station1-visit` | `station1` | `sim-opcua-station1` | `Line2/Station1.VisitId` | `String` | 10 |
| `station1-present` | `station1` | `sim-opcua-station1` | `Line2/Station1.VisitPresent` | `Boolean` | 11 |
| `nutrunner1-unit` | `nutrunner1` | `sim-opcua-nutrunner1` | `Line2/Station1/Nutrunner1.UnitId` | `String` | 12 |
| `nutrunner1-visit` | `nutrunner1` | `sim-opcua-nutrunner1` | `Line2/Station1/Nutrunner1.VisitId` | `String` | 13 |
| `nutrunner1-present` | `nutrunner1` | `sim-opcua-nutrunner1` | `Line2/Station1/Nutrunner1.VisitPresent` | `Boolean` | 14 |

- [ ] **Step 6.5** Targets and mapping sets. `targets/station1.json`: `semanticDefinitionRef.id` -> `station-stamped-model`; `targets/nutrunner1.json`: -> `tool-stamped-model`. Append three mappings to `mappings/station1.json` (template; `nutrunner1` analogues use `nutrunner1-unit`/`-visit`/`-present` and lines 12-14) so every leaf of the stamped definitions is mapped (`mapping.incomplete-object`):

```json
  {"mappingId": "station1-unit",
   "valueRef": {"kind": "source", "sourceRef": {"id": "station1-unit", "version": "1.0.0"}},
   "memberPath": [{"kind": "member", "memberId": "unit"}],
   "transform": [],
   "outputUnit": {"status": "not-applicable"}, "invalidValuePolicy": "bad-quality",
   "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 9}}],
   "temporalPolicy": {"timestampBasis": "source", "maxAgeMs": 5000, "maxSkewMs": 0, "uncertainInput": "reject",
                      "missingInput": "reject", "badInput": "propagate", "assembly": "latest"}}
```

| mapping-set | added mappingId -> sourceRef.id, memberId, line |
|---|---|
| `station1-mapping` | `station1-unit` -> `station1-unit`, `unit`, 9; `station1-visit` -> `station1-visit`, `visit`, 10; `station1-present` -> `station1-present`, `present`, 11 |
| `nutrunner1-mapping` | `nutrunner1-unit` (12), `nutrunner1-visit` (13), `nutrunner1-present` (14) |

- [ ] **Step 6.6** Replace `rules/attribution-line2.json` (same id `line2-attribution`, so `rules/impact-line2.json` is unchanged):

```json
{
  "kind": "attribution-rule",
  "schemaVersion": "2.27.0",
  "id": "line2-attribution",
  "version": "1.0.0",
  "label": "Line 2 plc-stamped attribution",
  "description": "Attributes nutrunner torque samples to the visit the station controller stamps in the same message.",
  "equipmentRef": {"id": "line2-plant", "version": "1.0.0"},
  "stations": ["synthetic-site:line2:station1", "synthetic-site:line2:station2"],
  "members": [
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-torque", "semanticId": "urn:bifrost:sem:Tool/Torque", "metric": "Torque"},
    {"mappingSetRef": {"id": "station1-mapping", "version": "1.0.0"}, "mappingId": "station1-running", "semanticId": "urn:bifrost:sem:Station/Running", "metric": "Running"},
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-running", "semanticId": "urn:bifrost:sem:Tool/Running", "metric": "Running"},
    {"mappingSetRef": {"id": "station1-mapping", "version": "1.0.0"}, "mappingId": "station1-unit", "semanticId": "urn:bifrost:sem:Station/UnitId", "metric": "UnitId"},
    {"mappingSetRef": {"id": "station1-mapping", "version": "1.0.0"}, "mappingId": "station1-visit", "semanticId": "urn:bifrost:sem:Station/VisitId", "metric": "VisitId"},
    {"mappingSetRef": {"id": "station1-mapping", "version": "1.0.0"}, "mappingId": "station1-present", "semanticId": "urn:bifrost:sem:Station/VisitPresent", "metric": "VisitPresent"},
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-unit", "semanticId": "urn:bifrost:sem:Tool/UnitId", "metric": "UnitId"},
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-visit", "semanticId": "urn:bifrost:sem:Tool/VisitId", "metric": "VisitId"},
    {"mappingSetRef": {"id": "nutrunner1-mapping", "version": "1.0.0"}, "mappingId": "nutrunner1-present", "semanticId": "urn:bifrost:sem:Tool/VisitPresent", "metric": "VisitPresent"}
  ],
  "activity": [
    {"equipmentPath": "synthetic-site:line2:station1", "memberRef": "station1-running", "activeWhen": true},
    {"equipmentPath": "synthetic-site:line2:station1:nutrunner1", "memberRef": "nutrunner1-running", "activeWhen": true}
  ],
  "occupancyBindingRef": {"id": "occupancy-binding-line2", "version": "1.0.0"},
  "identity": {
    "mode": "plc-stamped",
    "namespace": "urn:line2:visits",
    "members": [
      {"equipmentPath": "synthetic-site:line2:station1", "unitMemberRef": "station1-unit", "visitMemberRef": "station1-visit", "presentMemberRef": "station1-present"},
      {"equipmentPath": "synthetic-site:line2:station1:nutrunner1", "unitMemberRef": "nutrunner1-unit", "visitMemberRef": "nutrunner1-visit", "presentMemberRef": "nutrunner1-present"}
    ],
    "crossCheck": "occupancy"
  },
  "temporal": {"timestampBasis": "source", "outOfOrdernessMs": 30000, "allowedLatenessMs": 720000, "horizonMs": 86400000,
               "enterToleranceMs": 45000, "leaveToleranceMs": 45000},
  "quality": {"uncertainInput": "reject", "maxBadShare": 0.1},
  "coverage": {"expectedPeriodMs": 1000, "maxMissingPeriods": 3},
  "overlap": {"policy": "reject-ambiguous"},
  "evidenceRefs": [{"artifactId": "manual-line2", "locator": {"kind": "text-line", "line": 9}}]
}
```

- [ ] **Step 6.7** `proposal.json`: add eight entries (after `semantics/tool.json` and after `sources/nutrunner2-running.json` respectively):

```json
  {"path": "semantics/station-stamped.json", "kind": "semantic-definition", "id": "station-stamped-model", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "semantics/tool-stamped.json", "kind": "semantic-definition", "id": "tool-stamped-model", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/station1-unit.json", "kind": "source-definition", "id": "station1-unit", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/station1-visit.json", "kind": "source-definition", "id": "station1-visit", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/station1-present.json", "kind": "source-definition", "id": "station1-present", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner1-unit.json", "kind": "source-definition", "id": "nutrunner1-unit", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner1-visit.json", "kind": "source-definition", "id": "nutrunner1-visit", "version": "1.0.0", "sha256": "<pinned>"},
  {"path": "sources/nutrunner1-present.json", "kind": "source-definition", "id": "nutrunner1-present", "version": "1.0.0", "sha256": "<pinned>"}
```

`submission.json`: `id` -> `attribution-plc-stamped-fixture` (stream `line2` unchanged). Run `python -I pin-fixture.py core/src/test/resources/mapping-fixtures/attribution-plc-stamped`. Expected: `pinned 31 files`; `git status --short` shows 37 new files under the folder.

- [ ] **Step 6.8** Create `MappingPlcStampedRuleTest` (same imports; `setup` copies `/mapping-fixtures/attribution-plc-stamped` into `bundle`; the `rewrite`/`reseal`/`change`/`rule`/`codes`/`refused`/`accepted`/`ref` helpers of Tasks 2 and 5, without the registry):

```java
    static ObjectNode identityEntry(ObjectNode r,int i){return (ObjectNode)r.path("identity").path("members").get(i);}
    static ArrayNode identityEntries(ObjectNode r){return (ArrayNode)r.path("identity").path("members");}
    static final String S1="synthetic-site:line2:station1",S2="synthetic-site:line2:station2",N1=S1+":nutrunner1";

    @Test void acceptsThePlcStampedBundle() {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
        // the unit and visit members are typed OPC UA String sources, published under contract 2.27.0
        assertEquals(4,c.documents().values().stream().filter(d->text(d,"kind").equals("source-definition")&&text(d,"schemaVersion").equals("2.27.0")&&text(d.path("rawRepresentation"),"valueType").equals("String")).count());
        JsonNode rule=c.documents().values().stream().filter(d->text(d,"kind").equals("attribution-rule")).findFirst().orElseThrow();
        assertEquals("plc-stamped",text(rule.path("identity"),"mode"));assertEquals("occupancy",text(rule.path("identity"),"crossCheck"));
    }
    @Test void crossCheckNoneIsAllowedUnderPlcStamped() throws Exception {rule(r->ref(r,"identity").put("crossCheck","none"));accepted();}
    @Test void identityEquipmentMissing() throws Exception {rule(r->identityEntries(r).remove(1));refused("attribution.identity-equipment");}
    @Test void identityEquipmentDuplicate() throws Exception {rule(r->identityEntries(r).add(identityEntry(r,0).deepCopy()));refused("attribution.identity-equipment");}
    @Test void identityEntryForAnEquipmentWithoutMembersIsRefused() throws Exception {
        // station2 is a station of the rule but has no measurement or activity member: it may not carry an identity entry
        rule(r->identityEntries(r).add(identityEntry(r,0).deepCopy().put("equipmentPath",S2)));refused("attribution.identity-equipment");
    }
    @Test void identityOnlyEquipmentMayNotCarryAnIdentityEntry() throws Exception {
        // nutrunner1 keeps its UnitId, VisitId and VisitPresent members and its identity entry, but loses its torque member and its
        // activity entry: identity members alone do not make an equipment one with measurement or activity members
        rule(r->{ArrayNode m=(ArrayNode)r.path("members");m.remove(2);m.remove(0);((ArrayNode)r.path("activity")).remove(1);});
        refused("attribution.identity-equipment");
    }
    // identity member types and equipment: the mutations point at nutrunner1's Double torque (a measurement member no other
    // reference names), so the type check, not the role check, is what refuses
    @Test void identityUnitMemberMustBeString() throws Exception {rule(r->identityEntry(r,1).put("unitMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityVisitMemberMustBeString() throws Exception {rule(r->identityEntry(r,1).put("visitMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityPresentMemberMustBeBoolean() throws Exception {rule(r->identityEntry(r,1).put("presentMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityMemberUnresolved() throws Exception {rule(r->identityEntry(r,0).put("visitMemberRef","station1-visitid"));refused("attribution.identity-member");}
    @Test void identityMemberMustBelongToTheEntrysEquipment() throws Exception {
        // station1's entry names nutrunner1's UnitId; nutrunner1's own entry is pointed elsewhere first, so no member is named twice
        // and station1's entry (checked first) fails on equipment, not on a shared reference
        rule(r->{identityEntry(r,1).put("unitMemberRef","nutrunner1-torque");identityEntry(r,0).put("unitMemberRef","nutrunner1-unit");});refused("attribution.identity-member");
    }
    // one role per mappingId (spec line 132): the role check runs after coverage and before the type check
    @Test void identityPresentRefNamingTheActivityMemberIsRefused() throws Exception {
        // station1's Running is its activity member and a Boolean of the same equipment: only the role check refuses it
        rule(r->identityEntry(r,0).put("presentMemberRef","station1-running"));refused("attribution.identity-member");
    }
    @Test void identityEntryNamingOneMemberTwiceIsRefused() throws Exception {
        // visit = unit: both are String members of station1, so the type check would accept it; the role check refuses it
        rule(r->identityEntry(r,0).put("visitMemberRef","station1-unit"));refused("attribution.identity-member");
    }
    @Test void identityRefSharedAcrossTwoEntriesIsRefused() throws Exception {
        // nutrunner1's entry names station1's UnitId: the role check refuses the second use; the equipment check would refuse it
        // too (a member belongs to one equipment and two entries have distinct equipment), with the same code
        rule(r->identityEntry(r,1).put("unitMemberRef","station1-unit"));refused("attribution.identity-member");
    }
    /** Two activity entries for one equipment naming different Boolean members (spec line 133). The rule is switched to occupancy-join
     *  first, so that station1's VisitPresent is a plain Boolean member and no identity reference is involved. */
    @Test void twoActivityEntriesWithDifferentMembersForOneEquipment() throws Exception {
        rule(r->{r.set("identity",object().put("mode","occupancy-join").put("crossCheck","none"));((ArrayNode)r.path("activity")).addObject().put("equipmentPath",S1).put("memberRef","station1-present").put("activeWhen",true);});
        refused("attribution.activity-member");
    }
    static void swap(ArrayNode a){JsonNode first=a.remove(0);a.add(first);}
    @Test void identityEntryOrderDoesNotMatter() throws Exception {rule(r->{swap(identityEntries(r));swap((ArrayNode)r.path("activity"));});accepted();}
    @Test void identityRoleCheckIsOrderIndependent() throws Exception {
        rule(r->{swap(identityEntries(r));swap((ArrayNode)r.path("activity"));identityEntry(r,1).put("presentMemberRef","station1-running");});refused("attribution.identity-member");
    }
    @Test void plcStampedNeedsANamespace() throws Exception {rule(r->ref(r,"identity").remove("namespace"));refused("mapping.schema:2.27.0/attribution-rule");}
    @Test void plcStampedNeedsIdentityEntries() throws Exception {rule(r->identityEntries(r).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    /** The same String source re-stamped 2.7.0 is refused by that version's schema: the value type is a 2.27.0 addition. */
    @Test void theStringSourceIsRefusedAt270() throws Exception {change("sources/station1-unit.json",s->s.put("schemaVersion","2.7.0"));refused("mapping.schema:2.7.0/source-definition");}
```

- [ ] **Step 6.9** Run `mvn -q -pl core -Dtest=MappingPlcStampedRuleTest test`. Expected: 20 run, 13 failures: the four `attribution.identity-equipment` and nine `attribution.identity-member` tests fail with `expected: <[attribution.identity-...]> but was: <[]>` (the Task 5 validator does not read `identity`). `acceptsThePlcStampedBundle`, `crossCheckNoneIsAllowedUnderPlcStamped`, `identityEntryOrderDoesNotMatter`, `twoActivityEntriesWithDifferentMembersForOneEquipment` (the Task 5 activity check already refuses it), the two schema tests and `theStringSourceIsRefusedAt270` pass. If `acceptsThePlcStampedBundle` fails instead, the fixture is wrong: `mapping.incomplete-object` means a stamped leaf is unmapped (step 6.5); `mapping.type` means a String source was mapped to a Boolean leaf or the reverse (step 6.4 table); `semantic.identity-conflict` means a copied member's `semanticId` kept a different signature.

- [ ] **Step 6.10** In `AttributionRules.validate`, replace the line `// plc-stamped identity: Task 6` with

```java
   JsonNode identity=r.path("identity");
   if(text(identity,"mode").equals("plc-stamped")){
    // roles by reference (spec, members[] bullet): named by activity = activity member, named by an identity entry = identity
    // member, every other entry = measurement member; the equipment with measurement or activity members are the activity
    // entries' paths plus the paths of every members[] entry no identity entry names (an identity-only equipment is not covered)
    List<String> refs=List.of("unitMemberRef","visitMemberRef","presentMemberRef");
    Set<String> identityRefs=new HashSet<>();
    for(JsonNode e:identity.path("members"))for(String k:refs)identityRefs.add(text(e,k));
    Set<String> involved=new HashSet<>();for(JsonNode a:r.path("activity"))involved.add(text(a,"equipmentPath"));
    for(Map.Entry<String,Member> m:rule.entrySet())if(!identityRefs.contains(m.getKey()))involved.add(m.getValue().equipmentPath());
    Set<String> covered=new HashSet<>();
    for(JsonNode e:identity.path("members"))require(covered.add(text(e,"equipmentPath")),"attribution.identity-equipment");
    require(covered.equals(involved),"attribution.identity-equipment");
    // one role per mappingId: no identity reference may name an activity member or a member another identity reference names
    Set<String> roles=new HashSet<>();for(JsonNode a:r.path("activity"))roles.add(text(a,"memberRef"));
    for(JsonNode e:identity.path("members"))for(String k:refs)require(roles.add(text(e,k)),"attribution.identity-member");
    for(JsonNode e:identity.path("members")){
     String path=text(e,"equipmentPath");
     require(typed(rule,text(e,"unitMemberRef"),path,"String")&&typed(rule,text(e,"visitMemberRef"),path,"String")
      &&typed(rule,text(e,"presentMemberRef"),path,"Boolean"),"attribution.identity-member");
    }
   }
```

and add, after `within`:

```java
 private static boolean typed(Map<String,Member> rule,String ref,String path,String type){
  Member x=rule.get(ref);return x!=null&&x.equipmentPath().equals(path)&&text(x.leaf(),"valueType").equals(type);
 }
```

Order of the three checks: coverage, then roles, then member types. Coverage first keeps a duplicated entry `attribution.identity-equipment` even though its references are also named twice (spec line 135); roles before types makes the role check, not the type check, report `visitMemberRef` = `unitMemberRef` (two String members, which the type check would accept) and `presentMemberRef` naming the activity member (a Boolean of the same equipment). Activity references never reach the role check: two activity entries naming one member either share an equipment (`attribution.activity-member`, the duplicate-equipment check) or name an equipment that is not the member's, which is what spec line 132 states ("two activity references to one `mappingId` are two activity entries for one equipment and fail with `attribution.activity-member`"); the role check therefore only has to refuse an identity reference that names an activity member or a member another identity reference names. A reference shared across two identity entries is refused by the role check first; the equipment check would refuse it too, since a member belongs to one equipment and two entries have distinct equipment. Every set is built from the whole arrays before any comparison, so the result does not depend on array order (`identityEntryOrderDoesNotMatter`, `identityRoleCheckIsOrderIndependent`). Classification is by reference (Conventions, "Member classification"): an entry's unit, visit and present members do not make their equipment "involved"; its activity entry or a measurement member does.

- [ ] **Step 6.11** Run `mvn -q -pl core -Dtest='MappingPlcStampedRuleTest,MappingAttributionRuleTest' test`. Expected: 20 + 82, 0 failures. Then `mvn -q -pl core test` green.

- [ ] **Step 6.12** Commit: `feat(mapping): validate plc-stamped identity members over typed String sources (2.27.0)`

---

## Chunk 4: Impact validator and the completion gate

### Task 7: `ImpactRules` - the five `impact.*` codes

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/mapping/ImpactRules.java`
- Modify: `MappingBundle.java` (+1 call, constant at line 48)
- Test: `MappingImpactRuleTest.java`

- [ ] **Step 7.1** Add to `MappingImpactRuleTest` the same `rewrite`/`reseal`/`change`/`codes`/`refused`/`accepted`/`sha0`/`ref` helpers as in Tasks 2 and 5 (copy them; the test classes stay independent like the precedent tests), plus `rule` on `rules/impact-line2.json`, `profile` on `data/incident-binding-line2.json` + `evidence/incident-binding-line2.json`, and the tests (red):

```java
    @Test void acceptsTyrBundle() {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());}
    @Test void attributionMissing() throws Exception {rule(r->ref(r,"attributionRuleRef").put("version","9.9.9"));refused("impact.attribution-missing");}
    @Test void scopeMustBeInTheHierarchy() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station1:nutrunner9"));refused("impact.scope-containment");}
    @Test void scopeMustBeUnderAnAttributionStation() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2"));refused("impact.scope-containment");}
    @Test void aStationItselfIsInScope() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station2"));accepted();}
    @Test void duplicateScopePathsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station1:nutrunner1"));refused("mapping.schema:2.27.0/impact-rule");}
    @Test void emptyScopeIsRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).removeAll());refused("mapping.schema:2.27.0/impact-rule");}
    @Test void bindingUnresolved() throws Exception {rule(r->ref(r,"incidentBindingRef").put("id","incident-binding-absent"));refused("impact.binding-unresolved");}
    @Test void bindingMustBeAnArtifact110() throws Exception {change("evidence/incident-binding-line2.json",a->a.put("schemaVersion","1.0.0"));refused("impact.binding-unresolved");}
    @Test void bindingArtifactMustCarryTheMediaType() throws Exception {change("evidence/incident-binding-line2.json",a->((ObjectNode)a.path("file")).put("mediaType","application/json"));refused("impact.binding-profile");}
    @Test void bindingArtifactMustCarryThePrefix() throws Exception {
        change("evidence/incident-binding-line2.json",a->a.put("id","binding-line2"));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"id").equals("incident-binding-line2"))((ObjectNode)e).put("id","binding-line2");rewrite(bundle.resolve("proposal.json"),p);reseal();
        rule(r->ref(r,"incidentBindingRef").put("id","binding-line2"));
        refused("impact.binding-profile");
    }
    @Test void bindingProfileWithEmptyKindsIsRefused() throws Exception {profile(b->((ArrayNode)b.path("kinds")).removeAll());refused("impact.binding-profile");}
    @Test void bindingProfileWithAnotherBasisIsRefused() throws Exception {profile(b->b.put("equipmentRefBasis","node-id"));refused("impact.binding-profile");}
    @Test void retentionOrder() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",3600000));refused("impact.retention-order");}
    @Test void retentionEqualToTheHorizonIsAccepted() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",86400000));accepted();}
    @Test void retentionAbove90DaysIsRefusedByTheSchema() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",7776000001L));refused("mapping.schema:2.27.0/impact-rule");}
    @Test void olderEnvelopeRefused() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.26.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        refused("mapping.schema:2.26.0/mapping-proposal");
    }
```

- [ ] **Step 7.2** Run `mvn -q -pl core -Dtest=MappingImpactRuleTest test`. Expected: 15 + 17 = 32 run; the `refused("impact.*")` tests fail with `[]` (nothing checks impact rules yet); `acceptsTyrBundle`, `aStationItselfIsInScope`, `retentionEqualToTheHorizonIsAccepted`, the schema tests and `olderEnvelopeRefused` already pass.

- [ ] **Step 7.3** Create `ImpactRules.java` (complete):

```java
package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.27 impact-rule validator: the forseti stage-2 rule that judges quality incidents against the visits an
 *  attribution rule of the same bundle produces. The attribution rule resolves, every incident scope path is a hierarchy node
 *  that is a station of that rule or below one, the incident binding profile is an evidence-artifact Bifrost can read, and
 *  work-record retention is at least the attribution horizon. Refusal codes are the spec's impact.* table. AttributionRules
 *  runs first, so a referenced rule's hierarchy and stations are already known to resolve. */
final class ImpactRules {
 static final String KIND="impact-rule";
 static void validate(Collection<JsonNode> docs,AttributionRules.Reader files) throws Exception {
  for(JsonNode r:docs){
   if(!text(r,"kind").equals(KIND))continue;
   JsonNode a=AttributionRules.find(docs,AttributionRules.KIND,r.path("attributionRuleRef"));
   require(a!=null,"impact.attribution-missing");
   Set<String> known=new HashSet<>(AttributionRules.paths(AttributionRules.find(docs,EquipmentHierarchy.KIND,a.path("equipmentRef"))).values());
   List<String> stations=new ArrayList<>();for(JsonNode s:a.path("stations"))stations.add(s.asText());
   for(JsonNode s:r.path("incidentScope"))require(known.contains(s.asText())&&AttributionRules.within(stations,s.asText()),"impact.scope-containment");
   JsonNode evidence=AttributionRules.find(docs,"evidence-artifact",r.path("incidentBindingRef"));
   require(evidence!=null&&text(evidence,"schemaVersion").equals("1.1.0"),"impact.binding-unresolved");
   require(text(evidence,"id").startsWith(IncidentBindingProfile.ID_PREFIX)&&text(evidence.path("file"),"mediaType").equals(IncidentBindingProfile.MEDIA_TYPE),"impact.binding-profile");
   IncidentBindingProfile.parse(files.read(text(evidence.path("file"),"path")),"impact.binding-profile");
   require(a.path("temporal").path("horizonMs").asLong()<=r.path("retention").path("workRecordsMs").asLong(),"impact.retention-order");
  }
 }
}
```

- [ ] **Step 7.4** `MappingBundle.java`: directly after the `AttributionRules.validate(...)` line insert

```java
            ImpactRules.validate(docs.values(),path->Files.readAllBytes(safe(root,path)));
```

and in the document-kind set (line 48) replace the literal `"impact-rule"` with `ImpactRules.KIND`. The region now reads (lines 100-110 after the edits):

```java
            EquipmentHierarchy.validate(docs.values(),equipment);
            MetricDefinitions.validate(docs.values());
            CommandBindings.validate(docs.values(),path->Files.readAllBytes(safe(root,path)));
            AttributionRules.validate(docs.values(),path->Files.readAllBytes(safe(root,path)));
            ImpactRules.validate(docs.values(),path->Files.readAllBytes(safe(root,path)));
            if(docs.values().stream().anyMatch(d->MappingTemplates.KINDS.contains(text(d,"kind"))))MappingTemplates.validate(docs.values(),List.of());
            if(docs.values().stream().anyMatch(d->text(d,"kind").equals("record-mapping")))RecordMappings.validate(docs.values(),List.of(),this::validateDerived);
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.22.0")))require(Set.of("2.22.0","2.23.0","2.24.0","2.25.0","2.26.0","2.27.0").contains(text(p,"schemaVersion")),"broadcast.envelope");
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.21.0"))){require(Set.of("2.21.0","2.22.0","2.23.0","2.24.0","2.25.0","2.26.0","2.27.0").contains(text(p,"schemaVersion")),"record-field.envelope");RecordFields.validate(docs.values());}
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.26.0")))require(Set.of("2.26.0","2.27.0").contains(text(p,"schemaVersion")),"command-binding.envelope");
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.27.0")))require(text(p,"schemaVersion").equals("2.27.0"),"rule.envelope");
```

- [ ] **Step 7.5** Run `mvn -q -pl core -Dtest='MappingImpactRuleTest,MappingAttributionRuleTest,MappingPlcStampedRuleTest' test`. Expected: 0 failures (32 impact, 82 attribution, 20 plc-stamped tests).

- [ ] **Step 7.6** Run `mvn -q -pl core test`. Expected: `BUILD SUCCESS`, 0 failures, 0 errors.

- [ ] **Step 7.7** Commit: `feat(mapping): validate impact rules (2.27.0)`

### Task 8: Both fixture bundles through `gates mapping approve`

**Files:**
- Modify: `gates/src/test/java/dev/krillin/bifrost/gates/MappingGateTest.java` (+3 tests, +1 helper)

The completion gate of the step-1 row is the CLI, not the core API: `gates mapping approve <registry> <bundle> <approval-id> --by ... --by-key ... --approved-by ... --approved-by-key ...` (`MappingGate` line 24 requires exactly these 12 arguments) must exit 0 and write a receipt for each fixture bundle. `MappingGateTest.signedPublishAndVerifyHeadThroughTheCli` already drives `GatesCli.run` in-process against the `valid` fixture; these tests do the same against the new ones, and one shows that a refused bundle leaves no receipt (`MappingRegistry.approve` line 57: `mapping.validation-refused:` + findings).

- [ ] **Step 8.1** Add to `MappingGateTest`:

```java
    /** Copies a core fixture bundle and builds a two-key registry whose publication policy names stream line2:
     *  {bundle, registry, proposer key, approver key}. */
    static Path[] staged(Path dir,String fixture) throws Exception {
        Path source=Path.of("../core/src/test/resources/mapping-fixtures/"+fixture);assertTrue(java.nio.file.Files.isDirectory(source),"core mapping fixture "+fixture);
        Path bundle=dir.resolve("bundle");try(var walk=java.nio.file.Files.walk(source)){for(Path p:walk.toList()){Path t=bundle.resolve(source.relativize(p).toString());if(java.nio.file.Files.isDirectory(p))java.nio.file.Files.createDirectories(t);else java.nio.file.Files.copy(p,t);}}
        Path reg=dir.resolve("registry"),keys=dir.resolve("keys");java.nio.file.Files.createDirectories(reg.resolve("identity"));
        StringBuilder pub=new StringBuilder();
        for(String who:new String[]{"proposer","approver"}){
            PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();
            try{System.setOut(new PrintStream(sink));assertEquals(0,IdentityGate.run(new String[]{"keygen",who,"--out",keys.toString()}));}finally{System.setOut(old);}
            pub.append(sink.toString(StandardCharsets.UTF_8).strip()).append('\n');
        }
        java.nio.file.Files.writeString(reg.resolve("identity/authorized-keys.jsonl"),pub.toString());
        java.nio.file.Files.writeString(reg.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"p\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"},{\"id\":\"a\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"}]}");
        return new Path[]{bundle,reg,keys.resolve("proposer.key"),keys.resolve("approver.key")};
    }
    /** The forseti step-1 completion gate: a contract 2.27.0 bundle validates and is approved through the CLI. */
    static void approves(Path dir,String fixture) throws Exception {
        Path[] s=staged(dir,fixture);
        var validated=cli(0,"mapping","validate",s[0].toString());assertTrue(validated.path("accepted").asBoolean(),validated.toString());
        var receipt=cli(0,"mapping","approve",s[1].toString(),s[0].toString(),"approval-1","--by","proposer","--by-key",s[2].toString(),"--approved-by","approver","--approved-by-key",s[3].toString());
        assertEquals("mapping-approval",text(receipt,"kind"));assertEquals("line2",text(receipt.path("payload"),"streamId"));assertEquals("excluded",text(receipt.path("payload"),"execution"));
        assertTrue(java.nio.file.Files.isRegularFile(s[1].resolve("mappings/approvals/approval-1.json")));
        assertTrue(java.nio.file.Files.isRegularFile(s[1].resolve("mappings/attestations/approval-1.dsse.json")));
    }
    @Test void approvesTheAttributionImpactBundleThroughTheCli(@TempDir Path dir) throws Exception {approves(dir,"attribution-impact");}
    @Test void approvesThePlcStampedBundleThroughTheCli(@TempDir Path dir) throws Exception {approves(dir,"attribution-plc-stamped");}
    /** A rule the validators refuse is refused by the CLI too, with the code in the error, and leaves no receipt. */
    @Test void refusesAnImpactRetentionBelowTheHorizonThroughTheCli(@TempDir Path dir) throws Exception {
        Path[] s=staged(dir,"attribution-impact");Path rule=s[0].resolve("rules/impact-line2.json");
        var r=(com.fasterxml.jackson.databind.node.ObjectNode)read(rule);((com.fasterxml.jackson.databind.node.ObjectNode)r.path("retention")).put("workRecordsMs",3600000);java.nio.file.Files.write(rule,bytes(r));
        var p=(com.fasterxml.jackson.databind.node.ObjectNode)read(s[0].resolve("proposal.json"));
        for(var e:p.path("files"))if(text(e,"path").equals("rules/impact-line2.json"))((com.fasterxml.jackson.databind.node.ObjectNode)e).put("sha256",sha(rule));
        java.nio.file.Files.write(s[0].resolve("proposal.json"),bytes(p));
        var sub=(com.fasterxml.jackson.databind.node.ObjectNode)read(s[0].resolve("submission.json"));sub.put("proposalSha256",sha(s[0].resolve("proposal.json")));java.nio.file.Files.write(s[0].resolve("submission.json"),bytes(sub));
        var validated=cli(1,"mapping","validate",s[0].toString());assertEquals("impact.retention-order",text(validated.path("findings").get(0),"ruleCode"));
        var refused=cli(1,"mapping","approve",s[1].toString(),s[0].toString(),"approval-1","--by","proposer","--by-key",s[2].toString(),"--approved-by","approver","--approved-by-key",s[3].toString());
        assertTrue(text(refused,"error").startsWith("mapping.validation-refused:")&&text(refused,"error").contains("impact.retention-order"),refused.toString());
        assertFalse(java.nio.file.Files.exists(s[1].resolve("mappings/approvals/approval-1.json")));
    }
```

- [ ] **Step 8.2** Red first: `mvn -q -pl core -am install -DskipTests` is a prerequisite (gates reads the installed core); then comment out the `AttributionRules.validate`/`ImpactRules.validate` lines in `MappingBundle` and run `mvn -q -pl core -am install -DskipTests && mvn -q -pl gates -Dtest=MappingGateTest test`. Expected: `refusesAnImpactRetentionBelowTheHorizonThroughTheCli` fails (`validate` exits 0), the two `approves` tests pass. Restore the two lines (`git diff core/src/main` is empty again). Do not commit the mutation.

- [ ] **Step 8.3** Run `mvn -q -pl core -am install -DskipTests && mvn -q -pl gates -Dtest=MappingGateTest test`. Expected: `Tests run: 6, Failures: 0` (the three new tests plus the three existing ones). If an approve call exits 1 with `mapping.identity-refused` or `mapping.unauthorized`, the policy `ref` does not match the submission's `streamId` `line2`.

- [ ] **Step 8.4** Commit: `test(gates): approve the attribution bundles through the mapping CLI`

---

## Chunk 5: Documentation, full build, pull request

### Task 9: MAPPING-PUBLICATION section

**Files:**
- Modify: `docs/MAPPING-PUBLICATION.md` (append after "Command binding 2.26", the last section, line 174)

- [ ] **Step 9.1** Append the section. Same register as the 2.23-2.26 sections; every sentence below is backed by code of this plan or by the spec:

```markdown
## Attribution and impact rules 2.27

Proposal 2.27.0 adds two document kinds authored in Tyr for forseti: `attribution-rule` and `impact-rule`. Forseti runs the stage-1 and stage-2 jobs of the yggdrasil family, late-binding process samples to unit visits and judging quality incidents against them. Both kinds are declarative; neither carries SQL or scripts. One contract version holds both because an impact rule cannot be validated without its attribution rule. Schemas are located under `mapping-contracts/2.27.0/` (`attribution-rule`, `impact-rule`, `source-definition`, `common`, `mapping-proposal`). The 2.27.0 `common` schema differs from 2.26.0 in its `$id`, the two new entries of the proposal file-entry kind list, and `String` in the value types of a typed (OPC UA) source representation. The 2.27.0 `source-definition` schema re-issues the 2.7.0 `plc` source under 2.27.0 so that a plant controller's unit id and visit id can be published as String members (a 2.7.0 source still cannot declare `String`). A 2.26.0 proposal cannot list the new kinds and fails schema validation. Any document whose `schemaVersion` is 2.27.0, whether a rule or a 2.27.0 source definition, must be listed in a 2.27.0 proposal (`rule.envelope`). Command bindings from 2.26.0 ride unchanged in a 2.27.0 proposal (`command-binding.envelope` accepts 2.26.0 and 2.27.0); the 2.21 record-field and 2.22 broadcast envelope checks accept a 2.27.0 proposal.

An attribution rule names the ISA-95 hierarchy (`equipmentRef`, contract 2.23.0), its `stations[]` as hierarchy paths (root first, joined with `:`, the string Muninn publishes as the Sparkplug device id; non-empty, distinct, not nested), and its `members[]` (`mappingSetRef`, `mappingId`, `semanticId`, `metric`: every member the rule reads, measurement and activity alike). It defines one Boolean `activity[]` entry per station or tool that has one, an `occupancyBindingRef`, and an `identity` block (`occupancy-join` with an optional `namespace`, or `plc-stamped` with a required `namespace` and one entry per equipment naming its String unit and visit members and its Boolean present member; `crossCheck` `none` or `occupancy` under either mode). It also defines `temporal` bounds (0 to 86400000 ms each, as the 2.x `temporalPolicy`), `quality`, `coverage` (`expectedPeriodMs` 1 to 86400000), `overlap`, and `evidenceRefs`. An impact rule names its `attributionRuleRef`, `incidentScope[]` paths (non-empty, distinct), `incidentBindingRef`, `interval`, `evidence`, `retention.workRecordsMs` (at most 90 d), and `evidenceRefs`.

`AttributionRules` and `ImpactRules` validate independently of Tyr. A `members[]` entry resolves by `mappingSetRef` and `mappingId` to one mapping of the bundle (a `mappingId` is unique across the mapping sets of a bundle). Its equipment is the mapping set's `equipmentInstanceId` as a hierarchy path. Its type, metric name, and semantic id match the semantic leaf the mapping's one-step `memberPath` resolves to: `metric` equals the leaf's `name` byte for byte, which is the Sparkplug metric Muninn publishes. Member references (`memberRef`, `unitMemberRef`, `visitMemberRef`, `presentMemberRef`) are `mappingId`s of the rule's own `members[]`. Each `members[]` entry has exactly one role, given by the references that name it: an entry named by an `activity[].memberRef` is an activity member, an entry named by an identity entry's `unitMemberRef`, `visitMemberRef` or `presentMemberRef` is an identity member, and every other entry is a measurement member. A `mappingId` named by both an activity reference and an identity reference, or by more than one identity reference, fails with `attribution.identity-member`. Two activity references to one `mappingId` are two activity entries for one equipment and fail with `attribution.activity-member`. Within each semantic definition a rule uses, no two leaf members share a `name` (a station and a tool may each have a member of the same name, because Sparkplug metric names are scoped to one device). Refusal codes for attribution rules are `attribution.hierarchy-missing` (an invalid hierarchy keeps its own `hierarchy.*` refusal), `attribution.station-unresolved`, `attribution.station-nested` (a station that is an ancestor of another), `attribution.member-unresolved` (mapping set or `mappingId` absent, `metric` or `semanticId` differs from the leaf, a `memberPath` of more than one step, two leaves of one semantic definition sharing a name, an `opcua-node` identifier that does not end with `.` + `metric`, a `mappingId` listed twice, or two entries for one equipment and metric), `attribution.member-equipment` (member equipment is not a station or a descendant), `attribution.activity-member` (reference names no member, not Boolean, equipment differs, equipment outside the stations, or two entries for one equipment, including two activity references to one `mappingId`), `attribution.binding-unresolved`, `attribution.binding-profile`, `attribution.identity-equipment` (under `plc-stamped`, an equipment with measurement or activity members is not covered by exactly one identity entry, or an entry names an equipment that has none, only identity members or no member at all), `attribution.identity-member` (reference names no member, wrong type, equipment differs, or a `mappingId` is named by both an activity and an identity reference or by more than one identity reference), and `attribution.temporal-order` (`outOfOrdernessMs <= allowedLatenessMs <= horizonMs` violated). Refusal codes for impact rules are `impact.attribution-missing`, `impact.scope-containment` (a scope path is not in the hierarchy or not a station of the attribution rule or below one), `impact.binding-unresolved`, `impact.binding-profile`, and `impact.retention-order` (`horizonMs` above `workRecordsMs`). Duplicate or empty `stations[]` and `incidentScope[]`, and an `expectedPeriodMs` of 0, are schema refusals.

The two binding profiles are files of evidence-artifact 1.1.0 documents, as the Vor read binding is for command bindings: id prefix `occupancy-binding-` / `incident-binding-`, `file.mediaType` `application/vnd.forseti.occupancy-binding+json` / `application/vnd.forseti.incident-binding+json`, `profileVersion` `0.1.0`. `OccupancyBindingProfile` and `IncidentBindingProfile` read them with Bifrost's own code (exact field set, constant versions and schema ids, non-empty values, a `schemaSha256` that is a JSON string of 64 lowercase hexadecimal characters, checked for its form only, distinct non-empty `sources[]` and `kinds[]`, `correction.reasons` a non-empty distinct subset of the two EPCIS CBV reasons). `identity.pattern` accepts only the regular-expression syntax common to Java and ECMA-262: literals, `.`, bracket classes with ranges and negation, a backslash before a non-alphanumeric ASCII character as a literal, the quantifiers `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}`, alternation, and non-capturing groups; anchors, lookaround, backreferences, flags, named or capturing groups, shorthand, property or POSIX classes, lazy or possessive quantifiers, Java's class intersection `&&`, and a bare `{` are refused. A profile that fails any of this, or has a wrong artifact id prefix or media type, refuses publication with `attribution.binding-profile` / `impact.binding-profile`; a reference that is not an evidence-artifact 1.1.0 of the bundle refuses with `*.binding-unresolved`. Bifrost does not compare the artifact `scope` with the rule's stations. Verifying whether `schemaSha256` equals forseti's built-in schema is forseti's start-up check (`binding.schema-mismatch`), not Bifrost's.

Both rules and both profile files are part of the approved bundle, so they are in the release file list and the in-toto/DSSE attestation subject set. Pre-2.27 releases verify unchanged. Data-only fixtures live in `core/src/test/resources/mapping-fixtures/attribution-impact` (two stations, two nutrunners under one of them, an `occupancy-join` rule) and `mapping-fixtures/attribution-plc-stamped` (the same plant with String unit and visit members, a `plc-stamped` rule); `MappingGateTest` approves both through `gates mapping approve`.
```

- [ ] **Step 9.2** `bash scripts/check-ascii-names.sh` -> `product names: ASCII only` (the new section writes Tyr and Mimir in ASCII; the only non-ASCII spelling the script allows is the pre-existing first-use form on line 3 of the document).

- [ ] **Step 9.3** Commit: `docs(mapping): describe attribution and impact rules 2.27`

### Task 10: Full build, CI, pull request

**Files:** none

- [ ] **Step 10.1** `mvn -B -ntp install` from the repository root. Expected: `BUILD SUCCESS` for `bifrost-parent`, `bifrost-core`, `bifrost-heimdall`, `bifrost-gates`, `bifrost-sim`; surefire totals show 0 failures, 0 errors, 0 skipped in every module; core's count is the previous count plus 134 (82 attribution, 20 plc-stamped, 32 impact) and gates' plus 3. Record the exact numbers in the PR body.
- [ ] **Step 10.2** `node scripts/check-ascii-output.mjs .` -> passes (no non-ASCII literal is printed by the new code).
- [ ] **Step 10.3** `bash scripts/run-schema-gate.sh` and `bash scripts/run-provenance-gate.sh` (two of the broker-free gates CI runs; they read the mapping and registry code paths) -> `[GATE] PASS`. The remaining CI gates (`spec`, `template-conformance`, `command-authz`, `break-glass`, `model-reconciliation`, and `build-opa-wasm.sh --check` with the pinned OPA 1.21.4) touch no file of this plan; CI runs them on the PR.
- [ ] **Step 10.4** `git status --short` is empty; `git diff --check cc103e9...HEAD` prints nothing; `git diff --name-only cc103e9...HEAD` lists only the files of File Structure (no file under `mapping-contracts/2.26.0` or older, no existing fixture); `git log --oneline main..` shows the nine commits of Tasks 1-9; `file core/src/main/resources/mapping-contracts/2.27.0/*.json core/src/test/resources/mapping-fixtures/attribution-*/proposal.json` reports no `CRLF`.
- [ ] **Step 10.5** Push the branch and open the PR against `main` (title `feat(mapping): attribution and impact rules (2.27.0)`; body: scope of the step-1 row, spec row 1 (line 711), the refusal-code coverage table below, the two fixtures, the verification output). Wait for both CI jobs (Linux `tests + pure-CLI gates`, Windows `tests on Windows`) to pass: `gh run list --workflow ci.yml --branch feat/attribution-impact-rules --limit 1`, then `gh run watch <id> --exit-status`. Merge only after the maintainers' explicit approval; do not use `--delete-branch` on a stacked base.

---

## Open points

The text above applies everything the spec settles and does not repeat it here. All items come from forseti PR #2: the 2.27.0 source-definition schema and `rule.envelope` are in row 1 (line 711), and the per-definition leaf-name rule and the one-role-per-entry classification are in the `members[]` bullet (line 132). One point remains.

1. **ISA-95 level for tools.** Both fixtures put the nutrunners at `WORKUNIT_11` under `WORKCELL_6` stations. Bifrost has no parent/child level-pair matrix (MAPPING-PUBLICATION "Equipment hierarchy 2.23"; `EquipmentHierarchy.java` checks structure only), so any level validates. Decision 15 (spec line 87) names the parent relation but no level. Confirm the level Tyr will author in step 2 so its fixtures and these agree. If it differs, only `data/hierarchy-0.csv` and `hierarchy/0.json` of both fixtures change (and are re-pinned).

## Verification

Run from the bifrost repository root on the feature branch, after Task 10; every command must end as stated.

```bash
git status --short                                   # empty
git log --oneline main..                             # 9 commits, Tasks 1-9
git diff --check cc103e9...HEAD                      # nothing

# 1. unit and integration tests of the new code
mvn -q -pl core -Dtest='MappingAttributionRuleTest,MappingPlcStampedRuleTest,MappingImpactRuleTest' test   # BUILD SUCCESS, 0 failures (134 tests)
mvn -q -pl core -am install -DskipTests
mvn -q -pl gates -Dtest=MappingGateTest test                                      # BUILD SUCCESS, 6 tests, 0 failures

# 2. the whole build CI runs (Linux and Windows jobs)
mvn -B -ntp install                                  # BUILD SUCCESS; every module Failures: 0, Errors: 0, Skipped: 0
bash scripts/check-ascii-names.sh                    # product names: ASCII only
node scripts/check-ascii-output.mjs .                # passes
bash scripts/run-schema-gate.sh                      # [GATE] PASS
bash scripts/run-provenance-gate.sh                  # [GATE] PASS

# 3. the step-1 completion gate at the CLI, outside JUnit, for both fixtures (gates/target/bifrost-gates.jar from step 2;
#    `identity keygen` prints the authorized-keys line on stdout, as scripts/run-identity-gate.sh uses it)
for F in attribution-impact attribution-plc-stamped; do
  W=build/step1/$F; rm -rf "$W" && mkdir -p "$W/keys" "$W/reg/identity"
  for who in proposer approver; do
    java -jar gates/target/bifrost-gates.jar identity keygen "$who" --out "$W/keys" >> "$W/reg/identity/authorized-keys.jsonl"
  done
  cat > "$W/reg/identity/activation-policy.json" <<'JSON'
{"version":"1.0.0","default":"deny","rules":[
 {"id":"p","principal":"proposer","action":"publish","target":"mapping-publication","kind":"mapping-release","ref":"line2"},
 {"id":"a","principal":"approver","action":"approve","target":"mapping-publication","kind":"mapping-release","ref":"line2"}]}
JSON
  B=core/src/test/resources/mapping-fixtures/$F
  java -jar gates/target/bifrost-gates.jar mapping validate "$B"
  #   -> {"kind":"mapping-validation",...,"accepted":true,"findings":[],...}  exit 0
  java -jar gates/target/bifrost-gates.jar mapping approve "$W/reg" "$B" approval-1 \
    --by proposer --by-key "$W/keys/proposer.key" --approved-by approver --approved-by-key "$W/keys/approver.key"
  #   -> {"kind":"mapping-approval","schemaVersion":"2.9.0","payload":{"streamId":"line2",...,"execution":"excluded"},...}  exit 0
  ls "$W/reg/mappings/approvals/approval-1.json" "$W/reg/mappings/attestations/approval-1.dsse.json"   # both exist
done

# 4. a 2.26.0 proposal cannot carry the new kinds (also a JUnit test; here at the CLI)
cp -r core/src/test/resources/mapping-fixtures/attribution-impact build/step1/old && python -I - <<'PY'
import hashlib, json
from pathlib import Path
r = Path("build/step1/old"); p = json.loads((r/"proposal.json").read_bytes()); p["schemaVersion"] = "2.26.0"
(r/"proposal.json").write_bytes((json.dumps(p, indent=2) + "\n").encode())
s = json.loads((r/"submission.json").read_bytes()); s["proposalSha256"] = hashlib.sha256((r/"proposal.json").read_bytes()).hexdigest()
(r/"submission.json").write_bytes((json.dumps(s, indent=2) + "\n").encode())
PY
java -jar gates/target/bifrost-gates.jar mapping validate build/step1/old
#   -> "accepted":false, one finding "ruleCode":"mapping.schema:2.26.0/mapping-proposal"  exit 1

# 5. on GitHub: both CI jobs green on the PR; main unchanged until the maintainers approve
```

(On Windows under Git Bash, pass the jar, registry, bundle and key paths through `cygpath -m` if `java` cannot open them, as the gate scripts do.)

### Refusal-code coverage

Every code of the spec's three tables has at least one negative test through `MappingBundle`; every list and profile rule of the Contracts section has a negative test under its assigned code.

| Code | Test(s) |
|---|---|
| `attribution.hierarchy-missing` | `hierarchyMissing`; precedence of `hierarchy.*`: `anInvalidHierarchyKeepsItsOwnRefusal` |
| `attribution.station-unresolved` | `stationUnresolved` |
| `attribution.station-nested` | `stationNested`, `aStationThatIsAToolsAncestorIsNested` |
| `attribution.member-unresolved` | `emptyMembersAreMemberUnresolved`, `memberMappingSetUnresolved`, `memberMappingIdUnresolved`, `memberMappingIdOfAnotherSet`, `memberMetricMustEqualTheSemanticName`, `memberSemanticIdMustEqualTheMember`, `memberListedTwice`, `twoMembersForOneEquipmentAndMetric`, `memberSourceIdentifierMustEndWithTheMetric`, `duplicateLeafNamesInOneDefinitionAreRefused`; allowed across definitions: `aStationAndAToolMayEachHaveAMemberNamedRunning` |
| `attribution.member-equipment` | `memberEquipmentOutsideTheStations` |
| `attribution.activity-member` | `activityMemberUnresolved`, `activityMemberMustBeBoolean`, `activityMemberMustBelongToItsEquipment`, `activityEquipmentMustBeTheMembers`, `twoActivityEntriesForOneEquipment` (same `mappingId`), `twoActivityEntriesWithDifferentMembersForOneEquipment` (plc-stamped test class); allowed case: `anEquipmentWithoutAnActivityEntryIsAccepted` |
| `attribution.binding-unresolved` | `bindingUnresolved`, `bindingMustBeAnArtifact110` |
| `attribution.binding-profile` | `bindingArtifactMustCarryTheMediaType`, `bindingArtifactMustCarryThePrefix`, `bindingProfileWithAnExtraFieldIsRefused`, `bindingProfileWithAnAnchoredPatternIsRefused`, `bindingProfileThatIsNotJsonIsRefused`, and the 29 direct `OccupancyBindingProfile.parse` refusal tests (reasons subset, sources, digest form including a numeric digest, pattern subset including `&&`); scope not compared: `bindingScopeIsNotComparedWithTheStations` |
| `attribution.identity-member` | types and equipment: `identityUnitMemberMustBeString`, `identityVisitMemberMustBeString`, `identityPresentMemberMustBeBoolean`, `identityMemberUnresolved`, `identityMemberMustBelongToTheEntrysEquipment`; one role per `mappingId` (spec line 132: activity + identity, or two identity references): `identityPresentRefNamingTheActivityMemberIsRefused`, `identityEntryNamingOneMemberTwiceIsRefused`, `identityRefSharedAcrossTwoEntriesIsRefused`, `identityRoleCheckIsOrderIndependent`; order independence accepted: `identityEntryOrderDoesNotMatter` (plc-stamped test class) |
| `attribution.identity-equipment` | `identityEquipmentMissing`, `identityEquipmentDuplicate`, `identityEntryForAnEquipmentWithoutMembersIsRefused`, `identityOnlyEquipmentMayNotCarryAnIdentityEntry` (plc-stamped test class) |
| `attribution.temporal-order` | `temporalOrder`, `temporalHorizonBelowLateness`; boundary: `temporalEqualBoundsAreAccepted` |
| `mapping.schema:2.27.0/attribution-rule` (list rules the spec names no code for, and bounds) | `duplicateStationsAreRefusedByTheSchema`, `emptyStationsAreRefusedByTheSchema`, `emptyActivityIsRefusedByTheSchema`, `expectedPeriodZeroIsRefusedByTheSchema`, `identityEntriesAreSchemaBoundToPlcStamped` (`identity.members` under `occupancy-join`), `plcStampedNeedsANamespace`, `plcStampedNeedsIdentityEntries` |
| optional `namespace` under `occupancy-join` (spec 135) | `aNamespaceIsAllowedUnderOccupancyJoin` |
| `crossCheck: occupancy` under both modes | `crossCheckOccupancyIsAllowedUnderOccupancyJoin`, `acceptsThePlcStampedBundle`, `crossCheckNoneIsAllowedUnderPlcStamped` |
| `impact.attribution-missing` | `attributionMissing` |
| `impact.scope-containment` | `scopeMustBeInTheHierarchy`, `scopeMustBeUnderAnAttributionStation`; allowed: `aStationItselfIsInScope` |
| `impact.binding-unresolved` | `bindingUnresolved`, `bindingMustBeAnArtifact110` (impact class) |
| `impact.binding-profile` | `bindingArtifactMustCarryTheMediaType`, `bindingArtifactMustCarryThePrefix`, `bindingProfileWithEmptyKindsIsRefused`, `bindingProfileWithAnotherBasisIsRefused`, and the 13 direct `IncidentBindingProfile.parse` refusal tests (including a numeric digest) |
| `impact.retention-order` | `retentionOrder`; boundary: `retentionEqualToTheHorizonIsAccepted` |
| `mapping.schema:2.27.0/impact-rule` (list rules the spec names no code for, and bounds) | `duplicateScopePathsAreRefusedByTheSchema`, `emptyScopeIsRefusedByTheSchema`, `retentionAbove90DaysIsRefusedByTheSchema` |
| typed `String` (spec line 711) | accepted at 2.27.0: `acceptsThePlcStampedBundle`; refused at 2.7.0: `aTypedStringSourceIsStillRefusedAt270`, `theStringSourceIsRefusedAt270` |
| `rule.envelope` (spec line 711) | `a227SourceAloneNeedsA227Proposal` (a 2.27.0 source alone in a 2.26.0 proposal); the rule kinds in a 2.26.0 proposal stay `mapping.schema:2.26.0/mapping-proposal` (`a226ProposalCannotCarryTheRules`, `olderEnvelopeRefused`); a 2.26.0 link in a 2.27.0 proposal accepted (`a226CommandBindingRidesInA227Proposal`); `MappingCommandBindingTest.a226LinkNeedsA226Proposal` unchanged |
| step-1 row compatibility | `a226ProposalCannotCarryTheRules`, `olderEnvelopeRefused` (impact), `a226CommandBindingRidesInA227Proposal`, `a222BroadcastRidesInA227Proposal`, `a221RecordFieldRidesInA227Proposal`, `acceptsTyrBundle` (existing kinds mixed with the rules) |
| immutable approved bytes | `aProfileChangedWithoutResealIsADigestRefusal`, `releaseAndAttestationCarryBothRulesAndProfiles` |
| completion gate | `MappingGateTest.approvesTheAttributionImpactBundleThroughTheCli`, `approvesThePlcStampedBundleThroughTheCli`, `refusesAnImpactRetentionBelowTheHorizonThroughTheCli`, Verification step 3 |
