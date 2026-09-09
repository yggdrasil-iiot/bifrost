# R6 — Governed model vs vendor runtime: the verify direction

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read a vendor's exported model back, compare it against the governed `UdtDefinition`, and report divergence as findings — with the port declaring **granularity**, so a product whose only remediation unit is a whole entity blob is recorded as weaker rather than reported as equal.

**Architecture:** Reuse the inbound anti-corruption layer. A vendor export is normalized through the existing `TemplateAdapter` into a `UdtDefinition`, and the reconciler then diffs two canonical definitions — so `core` gains no new vendor knowledge. A new `VendorModelSource` port carries product, direction and granularity; the verdict carries the findings plus the remediation unit that granularity implies.

**Tech Stack:** Java 17, Jackson, the existing `TemplateAdapter` implementations, bash gate.

---

## What `ENTERPRISE.md` §13 already decided, and this plan obeys

The row was written on top of vendor-API measurements taken 2026-09-07, and it settles three things this plan does not relitigate:

1. **Verify comes first.** It needs no write access to a system somebody else operates, and it answers the question actually in doubt rather than the one that is comfortable to answer.
2. **The port must express granularity, not just direction.** `canRead`/`canWrite` would report all three products as fully supported and hide the only difference that changes how this is operated.
3. **`core` owns the abstraction and stays ignorant of every vendor**, exactly as `TemplateAdapter` does inbound — it takes a `JsonNode`, not an Ignition type.

## The scope line, stated before anything is built

**This does not connect to a live Kepware, Ignition or ThingWorx.** None of them is in this repository, and a stub HTTP server would prove the plumbing while licensing the sentence "it reconciles against the vendor", which would be false.

The source is a **file**. That is not a reduction: a Composer export, `GET /data/api/v1/tags/export` and a Kepware `GET` all produce one, and `ADOPTION.md` §2 already specifies this posture — *"read that copy back and compare it — read-only, same as the traffic side."* It is structurally what Huginn does with a pcap in phase 0: the artifact is handed over, the tool is offline, and nothing it does can reach the plant.

So the honest sentence, which goes in the docs verbatim: **the comparison is built and gated; the fetch is not.**

### A second limit, found while reading the code rather than assumed

`TemplateAdapter.adapt(external, ref, version)` **takes the ref and version as parameters** — its javadoc says why: *"the external doc may not carry Bifrost's"*. So a vendor export does not know which governed definition it corresponds to.

Two consequences, both of which must be built in rather than papered over:

- **There is no `templateRef` or `version` finding.** A comparison of those fields would compare an operator-supplied argument against itself and could never fire. Adding one would be a vacuous assertion of exactly the kind R5's K6 turned out to be, and this plan names it here so nobody adds it later thinking it was an oversight.
- **Which governed definition to compare against is an operator input.** The reconciliation therefore answers *"does this vendor object agree with this governed definition"*, and **not** *"is every governed definition present in the vendor"*. The second question needs an inventory the export does not carry.

### What a divergence finding does and does not say

A diff proves the two copies **disagree**. It does not prove which one is right — the governed side is the *declared* intent, and deciding that the vendor's copy is the mistake is a human act with an owner. The value is that divergence stops being invisible, which is the same claim §5 makes one layer up.

---

## File structure

| File | Responsibility |
|---|---|
| `core/.../vendor/Granularity.java` | **new** — `PER_OBJECT` \| `WHOLE_SET`, with the operational consequence in its javadoc |
| `core/.../vendor/VendorCapability.java` | **new** — product name, granularity, `canRead`, `canWrite` |
| `core/.../vendor/VendorModelSource.java` | **new** — the port: `capability()` + `read(ref)` returning a foreign `JsonNode` |
| `core/.../vendor/FileVendorModelSource.java` | **new** — the only implementation: an export on disk |
| `core/.../vendor/ModelReconciler.java` | **new** — diff two `UdtDefinition`s, emit findings |
| `core/.../vendor/ReconciliationVerdict.java` | **new** — findings + the remediation unit granularity implies |
| `gates/.../ModelReconcileGate.java` | **new** — the CLI |
| `gates/.../GatesCli.java` | dispatch |
| `scripts/run-model-reconciliation-gate.sh` | **new** — V1–V9 |
| `scripts/fixtures/vendor/` | **new** — divergent Ignition exports derived from the existing matching pair |

**Package placement.** `core/conformance/adapter` holds the inbound adapters; the outbound concern gets its own package `core/vendor` because it is a different question (agreement between two copies) and depends on the adapter package rather than belonging to it.

---

## Chunk 1: The port and the reconciler

### Task 1: The capability, with granularity as a first-class field

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/Granularity.java`
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/VendorCapability.java`
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/VendorModelSource.java`
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/FileVendorModelSource.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/vendor/FileVendorModelSourceTest.java`

- [ ] **Step 1: Write the failing tests**

1. `FileVendorModelSource` reads a JSON export from disk and returns its tree
2. an absent file yields **empty**, not an exception — "the vendor has no copy" is a legitimate answer and a different one from "the export is corrupt"
3. a malformed file is a **coded exception**, never an empty tree, because an empty tree would silently read as "the vendor has nothing" and produce a confident, wrong finding
4. `capability()` returns what the source was constructed with, and `PER_OBJECT`/`WHOLE_SET` round-trip
5. a `WHOLE_SET` source is still readable — granularity constrains remediation, not reading

- [ ] **Step 2: Run to verify red**

```bash
mvn -q -pl core test -Dtest=FileVendorModelSourceTest -Dsurefire.failIfNoSpecifiedTests=false
```

- [ ] **Step 3: Implement**

```java
/**
 * The unit at which a vendor product can be reconciled — and, more to the point, CORRECTED.
 *
 * <p>This is a property of the product's API, not of any particular export file: the same JSON
 * could come from a product with a per-object write API or from one whose only ingest path is a
 * whole entity blob. Declaring it on the SOURCE rather than inferring it from the data is what
 * keeps that distinction honest.
 */
public enum Granularity {
    /** Kepware, Ignition: a correction touches one object. Divergence is actionable per member. */
    PER_OBJECT,
    /** ThingWorx: there is no per-object write, so a correction re-imports the entity set. */
    WHOLE_SET
}
```

`VendorCapability(String product, Granularity granularity, boolean canRead, boolean canWrite)`.

`VendorModelSource` is `capability()` plus `Optional<JsonNode> read(String ref) throws IOException`.

- [ ] **Step 4: Green** · **Step 5: Commit**

### Task 2: The diff

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/ReconciliationVerdict.java`
- Create: `core/src/main/java/dev/krillin/bifrost/core/vendor/ModelReconciler.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/vendor/ModelReconcilerTest.java`

- [ ] **Step 1: Write the failing tests**

Findings, one test each, asserting the **exact** rule string (the house discipline — a test that accepts any failure proves the code failed, not that it failed correctly):

| rule | when |
|---|---|
| `vendor.member.missing` | the governed definition has a member the vendor's copy does not |
| `vendor.member.unexpected` | the vendor's copy has a member the governed definition does not |
| `vendor.member.type-mismatch` | same name, different canonical type |
| `vendor.member.range-mismatch` | same name, different `Range` (including one side null) |
| `vendor.member.semantic-id-mismatch` | same name, different `semanticId` (including one side null) |

Plus:
6. an identical pair yields **no findings** and `agreed() == true`
7. **all** divergences are reported, not just the first — an operator fixing one at a time across four round trips is a worse outcome than a list
8. member order does not matter: the same members in a different order agree
9. a member differing in two ways (type AND range) produces **both** findings, so the report is not truncated per member
10. **no `templateRef` or `version` finding exists** — a test that pins the absence, with the reason, so it is not "fixed" later

- [ ] **Step 2: Red** · **Step 3: Implement**

`ReconciliationVerdict(boolean agreed, Granularity remediationUnit, List<Violation> findings)`, reusing the existing `Violation(rule, detail)` rather than inventing a parallel vocabulary.

- [ ] **Step 4: Green** · **Step 5: Commit**

### Task 3: Granularity reaches the verdict

**Files:**
- Modify: `core/.../vendor/ModelReconciler.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/vendor/ModelReconcilerGranularityTest.java`

- [ ] **Step 1: Write the failing tests**

1. the **same** divergent pair yields the **same findings** under both granularities — the findings come from the data, the remediation unit from the product
2. `remediationUnit` is `PER_OBJECT` when the source declares it, `WHOLE_SET` when it does not
3. an agreed pair still carries the remediation unit, so a caller can print it without a special case

**A refinement of the row, worth stating.** `ENTERPRISE.md` §13 currently says that for a blob product *"the smallest unit of both the finding and the fix is much larger"*. Building it shows that is half right: the **fetch** and the **fix** are whole-set, but once the blob is parsed the **finding** is still per member. Keeping the per-member detail is strictly better for the operator, and the verdict records the remediation unit separately rather than degrading the diagnosis to match it. Task 7 corrects the row.

- [ ] **Step 2: Red** · **Step 3: Implement** · **Step 4: Green** · **Step 5: Commit**

---

## Chunk 2: CLI and gate

### Task 4: `gates model-reconcile`

**Files:**
- Create: `gates/src/main/java/dev/krillin/bifrost/gates/ModelReconcileGate.java`
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/GatesCli.java` (dispatch **and** the two usage strings)
- Test: `gates/src/test/java/dev/krillin/bifrost/gates/ModelReconcileGateTest.java`

`model-reconcile <reg> <ref> <version> --vendor <file> --adapter <ignition|cfihos|aas> [--granularity per-object|whole-set]`

Exit codes follow the house convention: **0** agreed, **1** divergence found, **2** usage or input error.

- [ ] **Step 1: Write the failing tests**

1. agreed → 0, and the output says which product and remediation unit
2. divergence → 1, with every finding printed as `- [rule] detail`
3. an unknown adapter kind → 2 (reuse `AdaptTemplate`'s vocabulary: `ignition|cfihos|aas`)
4. a missing `--vendor` file → 2, **not** 0. "The vendor has no copy" is a finding an operator must see, never a silent pass
5. **a governed definition absent from the registry → 2, not a report that every vendor member is unexpected.** An empty governed side would produce a long, confident, meaningless finding list — fail closed instead
6. `--granularity` defaults to `per-object` and an unrecognized value is a usage error rather than a silent default

- [ ] **Step 2: Red** · **Step 3: Implement** · **Step 4: Green** · **Step 5: Commit**

### Task 5: `scripts/run-model-reconciliation-gate.sh`

Broker-free — no sim, no Docker, no edge. House idiom: `cygpath` shim, `fail`, staged registry, exact rule strings.

Fixtures under `scripts/fixtures/vendor/`, each derived from the existing `scripts/fixtures/template/ext-ignition.json`, which already adapts exactly onto `native-template.json`:

| fixture | change |
|---|---|
| `ignition-agreed.json` | none (a copy, so the baseline is explicit rather than implied) |
| `ignition-missing-member.json` | `ElectrodeForce` removed |
| `ignition-extra-member.json` | a `CoolantTemp` tag added |
| `ignition-type-drift.json` | `WeldCurrent` retyped `Int4` |
| `ignition-range-drift.json` | `WeldTime` `engHigh` 600 → 900 |
| `ignition-semantic-drift.json` | `WeldCurrent` semanticId repointed |

| | Asserts |
|---|---|
| **V1** | the agreed export reports **no divergence**, exit 0. Run first: without it a later "divergence found" proves nothing about the comparison working |
| **V2** | a member missing from the vendor copy → `vendor.member.missing`, exit 1 |
| **V3** | an extra member in the vendor copy → `vendor.member.unexpected`, exit 1 |
| **V4** | a retyped tag → `vendor.member.type-mismatch` |
| **V5** | a widened range → `vendor.member.range-mismatch` |
| **V6** | a repointed semanticId → `vendor.member.semantic-id-mismatch` |
| **V7** | **granularity is the product's, not the file's**: the same divergent fixture under `--granularity whole-set` yields the **same findings** and a **different remediation unit** |
| **V8** | fail-closed inputs: a missing `--vendor` file, an unknown adapter and an unrecognized granularity are each exit 2, and **none of them prints "agreed"** |
| **V9** | **a governed ref absent from the registry is exit 2, not a wall of `unexpected` findings.** The assertion is on the absence of findings as much as on the exit code |

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: commit**

**Injection discipline, with R5's lesson attached.** Three of R5's ten injections were ineffective on the first attempt — one flipped a different assertion, one renamed a rule string the gate matched by substring anyway, one landed in a branch the gate never reached. **Read the failure message of every injection and confirm it names the assertion being proved**, not merely that the gate went red.

---

## Chunk 3: Documents

### Task 6

- [ ] `ENTERPRISE.md` row 13 **open → partial**, naming what is built (the comparison, the port, the granularity distinction) and what is not (**the fetch**; no live product; no projection direction)
- [ ] `ENTERPRISE.md` §13 — **correct the "smallest unit of both the finding and the fix" sentence**: the fetch and the fix are whole-set, the finding is per member once parsed, and the verdict carries the two separately
- [ ] `ENTERPRISE.md` §13 — record the identity limit: the export carries no Bifrost ref/version, so the governed side is an operator input and this answers *"does this object agree"*, not *"is everything present"*
- [ ] `ENTERPRISE.md` limitations — a divergence finding proves disagreement, **not** which side is right
- [ ] `ADOPTION.md` phase 2 — the second reconciliation now has a command; state that the export is handed over like a pcap, and that a version check belongs in the phase-0 survey (the row already says the Ignition endpoint does not exist before 8.3.2)
- [ ] Counts: gates 21→22, tests, `README.md` badge, per-module split, gate list
- [ ] **Add the gate to `.github/workflows/ci.yml`** — it is broker-free, so the "six of the twenty-one need no broker" sentence becomes **seven of the twenty-two**, and a broker-free gate not in CI would contradict it
- [ ] Readiness board SVG: **open 1 → 0**, partial 5 → 6. The counts are baked into the SVG text and the alt text; regenerate the dark variant and **render and look at it**

---

## Definition of done

- [ ] `mvn test` green; no pre-existing test changed
- [ ] `run-model-reconciliation-gate.sh` PASS, **every V1–V9 proved by injecting its defect**, each injection's failure message naming its own assertion
- [ ] **V1 and V7 pass** — the agreed baseline, and granularity being the product's property rather than the file's. Without V1 every other row is unfalsifiable; V7 is the reason the port exists at all
- [ ] Every other gate still PASS (21 of them, Docker up)
- [ ] `TemplateAdapter` and its three implementations **untouched** — the outbound side reuses the inbound anti-corruption layer, and changing it here would mean the reuse was not real
- [ ] The new gate is in CI

## What R6 explicitly does not fix

| | |
|---|---|
| **No live vendor connection.** The source is a file; the fetch is not built | stated, not deferred silently |
| **No projection direction.** Nothing generates or pushes a vendor configuration | row 13's other half |
| A finding proves disagreement, not which side is right | inherent to comparison |
| No inventory: this answers "does this object agree", not "is every governed definition present" | the export carries no Bifrost identity |
| Only the three existing adapters; no Kepware or ThingWorx adapter | row 8's concern, not this one |
| Nothing schedules the check — it is a command an operator runs | later |
