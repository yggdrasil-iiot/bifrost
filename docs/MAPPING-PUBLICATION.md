# Offline mapping publication

Bifrost independently validates a Tyr (Týr) proposal and submission 2.9 envelope, including pinned equipment/connection context and the complete evidence inventory. Bundled schemas are wire data copies; Tyr code is neither imported nor invoked.

The gates jar dispatches mapping validate/diff/approve/publish/status. Approval requires distinct registered Ed25519 keys plus deny-by-default policy. A new publish action applies to target mapping-publication, kind mapping-release, ref streamId. Existing activation grants do not grant mapping publication.

Immutable submission IDs identify snapshots; stable stream IDs identify release sequences. Approval binds exact proposal and bundle hashes, identities and base release. Publication revalidates these and current key/policy state under a registry lock, stages and verifies complete bytes, then uses atomic directory and HEAD moves. Unsupported atomic operations refuse.

Identity/policy files and the filesystem are operator-controlled trust roots. This path does not write the activation ledger or claim external-anchor rollback evidence. Failed staging or unreferenced complete directories may remain for investigation; recovery/GC and power-loss durability are deferred.

The receiver rejects draft/unresolved/unsupported definitions and requires confirmed units. XLSX locator validation does not claim vendor parser completeness. MappingPublicationTest uses real temporary keys and shared wire data to exercise stale approval/base, tampering and prior-head preservation. Device access, external SQL, writes and operational activation remain excluded.


## Approval digests

In a mapping approval receipt, `payloadSha256` and `changeSha256` are SHA-256 digests over Bifrost's own serialization: Jackson, keys sorted, compact (`MappingJson.bytes`), not RFC 8785 (JCS). Bifrost computes them at approval and recomputes them with the same code at publication and recovery; no other program is expected to reproduce them. Consumers outside Bifrost verify a release by raw-byte SHA-256: the head's `sha256` over `release.json` bytes and `files[].sha256` over each payload file.

## Approval attestation (in-toto Statement v1 + DSSE)

`mapping approve` also writes `mappings/attestations/<approvalId>.dsse.json`: a DSSE v1.0.2 envelope (`payloadType` `application/vnd.in-toto+json`) holding an in-toto Statement v1, signed with the same two Ed25519 keys and at the same moment as the receipt. Each signature covers PAE(payloadType, payload). In the statement, `subject` is every file of the approved bundle, named as `release.json` will name it (`payload/<path>`), with `digest.sha256` over the file's raw bytes; `predicateType` is `https://github.com/yggdrasil-iiot/bifrost/attestation/mapping-approval/v1`; `predicate` is the receipt's `payload`, field for field.

The attestation is written before the receipt. A process stopped between the two leaves an envelope no receipt refers to; approving again with the same approval id replaces it. An approval id that already has a receipt is refused before anything is written. Receipts, `release.json`, heads and payload files are byte-identical to before; `publish`, `recover` and the intent journal are unchanged. `gc` includes `attestations/` in `rootsSha256` and quarantines stale `.pending` files there like elsewhere.

`mapping verify-attestation <registry> <release-id> <version> <release-sha256>` verifies the release, then the envelope. An outside verifier needs no Bifrost code or serialization:
1. Read `approval.payload.approvalId` from `release.json` and open the envelope.
2. Verify both signatures over PAE with the keys registered for `proposedBy` and `approvedBy` in `identity/authorized-keys.jsonl`, and require two different keys; `keyid` is only a hint.
3. Check that `predicate` equals the receipt payload.
4. Check that the `subject` set equals `files[]` and that each file's raw SHA-256 matches.

A key retired later still verifies the attestations it signed, as it does for receipts. The activation policy and key validity windows were checked by Bifrost at approval; the envelope does not carry them. A recipe publication can be signed by a single publisher with an in-toto `Statement` whose predicate is SLSA Provenance v1, described in [RECIPE-PUBLICATION.md](RECIPE-PUBLICATION.md).

## Explicit integer-word views (2026-10-18)

The bundled 2.10.0 source-definition schema adds read-only PLC alias/bit views. Existing schema bytes and proposal/submission/approval/release formats remain unchanged. The receiver resolves exact parent id/version, a maximum of 16 relations, cycles/missing parents, equipment/connection/access/raw snapshots, parent readiness/readability, integer widths and bit bounds. Aliases inherit the logical value/unit; bit views produce Boolean with no physical unit. Array/codec/native-bit/non-PLC parents are outside this capability.

Every mapping/graph must include the evidence of the entire parent chain. Changed parent snapshots are refused by the receiver even when the editor retains them as an unresolved draft. Views cannot be write destinations. Four-eyes approval and publication revalidate the complete inventory and bind its bytes and receiver diff. Publication does not activate or execute the mapping.

The capability family remains bifrost-mapping-v1 and the signed envelopes remain 2.9.0. This family string alone is not a schema-version negotiation: an older receiver without 2.10.0 resources must refuse such documents.

Data-only fixtures live in core/src/test/resources/mapping-fixtures/a07. The independent Java suite checks the valid four-profile publication plus 12 resealed negative view mutations. The measured A07 mapping/CLI run is 60 tests (58 core + 2 CLI), including the prior mapping cases; this is not a new whole-reactor count. Maven package and these tests ran offline. No Tyr Python/JavaScript code is shared or invoked.


## Bounded math graph 2.11.0

The bundled value-graph/common schemas retain all 2.5.0 nodes and add sqrt and clamp. The independent receiver checks numeric input, dimensionless sqrt, equal known input/output units and ordered exact decimal clamp bounds. Schema validation fixes sqrt precision to 34 and rounding to half-even. Older graph versions cannot carry these operations.

Java validates the declared graph; Tyr evaluates virtual samples. Approval and immutable file publication bind the complete graph bytes without executing device reads, SQL or writes. Workspace, proposal and signed 2.9.0 envelope formats remain unchanged. An older receiver without 2.11.0 resources must refuse the new graph version. Data-only p3cb fixtures and boundedMath tests cover independent acceptance/publication, reversed bounds, dimensional sqrt and old-version refusal.


## Logical structures 2.12.0

Bundled semantic-definition/mapping-set/common schemas add bounded inline Structure/StructureArray models and explicit member/index paths. The independent Java receiver validates depth/node/expanded-leaf limits, shape/lower bounds, exact leaf resolution, full-path uniqueness and completeness, container/leaf semantic identity, scalar types/units and evidence closure. Recursive local schema refs are retained and bounded preflight precedes schema evaluation.

Publication still binds immutable JSON/file evidence and does not decode native PLC structs, evaluate object samples or activate runtime mappings. Existing contracts and signed envelopes stay unchanged. A receiver without 2.12.0 resources must refuse these documents. Data-only p3eb fixtures exercise four profiles and 40 leaf mappings; native vendor layouts and field PoV are separate.


## Process interruption and conservative quarantine

`mapping recover <registry>` verifies the persisted transaction, signed approval, release files and expected base before completing the original atomic publication. Pending transactions block new approve/publish/GC; a completed head needs only journal cleanup. Corrupt journals or payloads and conflicting heads fail closed without deleting evidence. This is process-restart recovery, not power-loss/filesystem durability certification or external rollback anchoring.

`mapping gc <registry> <grace-seconds>` previews old recognized staging/approval/head temporary files. `--quarantine <plan-sha256>` recalculates the plan under the same registry lock and atomically moves candidates to quarantine. Grace is at least one hour. All approvals, releases (including historical unheaded releases), payloads, heads and identity are retained. Corrupt historical releases block GC. Unknown files are retained. No permanent deletion or runtime activation occurs. Interrupted quarantine is resumed with a new preview. Test-only fault hooks are not CLI inputs.


## Bounded scalar arithmetic 2.15.0

The bundled graph/common schemas add add/multiply/divide with named left/right inputs and Decimal output. The independent Java receiver accepts only explicit linear-unit cases: same-unit addition, multiplication with at least one dimensionless input, division by dimensionless input or a same-unit ratio. Unknown/not-applicable units, Cel/K and unsupported products/inverse dimensions are refused. Divide requires precision 34 and half-even. Existing schemas and 2.9 submission/approval/release envelopes remain unchanged.

Bifrost validates definitions, references, types, units, policy and evidence closure, then signs/publishes files. It does not execute arithmetic samples, read a PLC or establish absence of a zero denominator at runtime. Tyr's virtual preview separately diagnoses zero division and precision/final cast loss. General expressions/dimensional inference/temperature deltas, physical field meaning and runtime activation remain separate.


## Registry-wide semantic catalog

`mapping catalog <registry>` derives a 2.16.0 report from all verified immutable releases, including unheaded history. Scalar signatures are role/valueType/unit; structure signatures recursively include member IDs and child URIs, and arrays include shape/lowerBounds. Labels, descriptions and ranges do not define URI identity. Approve and publish recheck this catalog under the registry lock; recovery also checks compatibility. Conflicting historical variants remain visible and block new approvals/publications; corrupt history and pending recovery refuse catalog queries. Existing 2.9 signed receipts/releases are unchanged. Limits: 256 releases, 4096 URIs, 4 MiB report. This does not establish physical semantic equivalence, federation, external rollback anchoring or runtime activation.


## Pinned cross-graph scalar results (2.17.0)

A value-graph input may pin another graph by `{kind: graph, graphRef: {id, version}, nodeId}`. The receiver validates the complete proposal dependency closure independently. Same equipment and scalar outputs only; missing versions/nodes, graph-level cycles (including unused candidates), incorrect type/unit/evidence, and whole-array endpoints are rejected. External dependencies are bounded to 32 graph levels, 128 nodes per evaluated dependency path and 8192 total graph nodes. Existing schema files and envelopes remain supported. Older receivers without 2.17 resources fail closed. Approval/publication preserves all graph boundaries and transitive artifacts; there is no device access, calculation runtime, external SQL, write execution or activation.


## Semantic URI lifecycle (2.18)

The independent Java receiver accepts immutable semantic-lifecycle records and proposal2.18 alongside existing contracts. URI signatures remain fixed. Metadata revise, deprecate and terminal retire form a hash-pinned contiguous history. Explicit replacement URIs do not imply aliasing or automatic remapping. New retired URI bindings, including structure/array ancestors and write definitions, are refused; historical releases remain readable.

`mapping lifecycle <registry>` derives states, history, event-to-release origins and read/write impacts from verified history, distinguishing current heads and prior releases. Approve/publish/recover merge and recheck history under the existing lock. Omitted lifecycle records and approvals predating another stream's retirement cannot bypass policy.

A 2.18 proposal with lifecycle records may omit mapping sets for governance-only publication, retaining definitions and full predecessor chains. Existing two-principal key/policy approval and immutable file release apply. Device communication, external SQL, write execution and runtime activation remain excluded. URI ownership policy, operational IAM/federation and field PoV remain separate.


## Mapping templates 2.19

Accepts immutable mapping-template and template-application wire records with legacy document kinds. An independent Java compiler reproduces all generated semantic/target/graph/mapping artifacts, pins decoded slot type/unit/stage and complete concrete source snapshots, and verifies template/app predecessor hashes. Approval/publication/recovery compare against all verified registry release history; omission of known managed provenance, forks, stale application revisions and changed generated files fail closed. Existing two-key approval, catalog/lifecycle rules and file release machinery remain authoritative. No Python dependency, device IO, external SQL, write execution or runtime activation.


## Offline record/result-set definitions (2.20)

A proposal may include `record-mapping` definitions, pinned 2.19 mapping templates, canonical element models, declaration evidence, and their immutable history closure. Record-only proposals are supported. Virtual row snapshots and SQLite scenarios are never release documents. Queries are preserved as opaque metadata; this gate contains no SQL driver or query execution path.

The independent Java `RecordMappings` validator checks field/slot type, unit and input-stage signatures, required String composite keys, nullable/default policies, explicit key selection, object/array 0/1/N and bounded cardinality, template/schema pins and linear mapping history. It deterministically projects definitions into existing external-value/target/graph/mapping contracts and runs existing static validation in an isolated scope. Cross-language fixture projections verify equivalence without invoking Python.

Approval, publication and recovery check registry-wide record/schema/template version conflicts and semantic lifecycle policy. Derived `record-<id>-<version>` mapping identifiers expose definition-level semantic impacts; they are not actual row inventories. Retired semantic URIs block new approvals/releases. Existing bundle versions remain supported; 2.20 documents in old envelopes fail closed.

Runtime row values, actual DB key stability, result snapshot consistency, provider/export semantics and operator acceptance require separate field PoV. Device communication, external SQL, writes and activation remain excluded.


## Mixed-object record-field sources (2.21)

Read-only typed external-value sources may opt into source-definition2.21 with a pinned recordMappingRef, fieldId and nullable/default policy. They expose the selected record's raw field rather than the record template's engineered output. Existing sources/graphs/mappings/templates compose PLC, record fields, constants and external values into one canonical target object.

RecordFields independently verifies exact field type/unit/input stage, logical equipment, object cardinality, provider/value key, non-executable expression, defaults and pins. Registry history prevents rewriting or downgrading a published pinned source under the same ID/version, including otherwise locally valid legacy bundles. The proposal closure retains record declarations, their templates/models/history/evidence and existing application proof. Old envelopes reject2.21 documents. Virtual result sets and object/scalar scenarios are not release documents.

SQL/drivers/device communication/writes/activation remain excluded. Per-binding temporal policies do not promise cross-member object atomicity or skew. Actual provider/native data, timing and operator acceptance require separate field PoV.


### Opt-in 2.22 finite row broadcast

Record mappings may bind some template2.19 slots to raw typed result-set fields and the rest to immutable common PLC/constant/solution-tag/external source definitions. The 2.22 recipe fixes bounded array cardinality, canonical record keys, a single virtual frame, freshness/skew/quality and explicit reject-all/omit-invalid row policy. The receiver validates declaration structure, slot signatures, source canonical pins and independent deterministic template projection. Common source pins remain immutable across registry streams, including attempts to rewrite them through legacy source packages. Approval/publication/recovery retain existing semantic and template history checks. Virtual records, common samples and preview scenarios are not released. No provider/PLC/SQL/write execution is introduced; actual temporal correctness and omission permission remain field PoV concerns.

## Equipment hierarchy 2.23

Proposal 2.23.0 adds the `equipment-hierarchy` document kind: an ISA-95 (IEC 62264) equipment hierarchy authored in Tyr as governed metadata. Each node defines an `equipmentInstanceId`, a label, an `equipmentLevel`, a parent (`parentEquipmentInstanceId`, null for a root), and its own evidence references. Levels match OPC 10030 v1.00 `ISA95EquipmentElementLevelEnum` Table 36 names verbatim, including `PRODUCTIONUINT_7`. `OTHER_14` requires an `otherLevel` name; any other level forbids it, and the schema enforces both without a parent/child level-pair matrix.

`EquipmentHierarchy` validates independently of Tyr, with its own code and byte-identical schema copies under `mapping-contracts/2.23.0/`. Node evidence passes standard document evidence verification. Validation enforces the following refusal codes: `hierarchy.multiple` (more than one hierarchy in a bundle), `hierarchy.duplicate-node`, `hierarchy.parent-missing`, `hierarchy.cycle` (including self-parent), `hierarchy.depth` (root-to-node path over 64 nodes), `hierarchy.context-equipment` (node ID missing from submission context equipment), and `hierarchy.unresolved-instance` (any other document referencing an `equipmentInstanceId` absent from the hierarchy).

A 2.22.0 proposal cannot list the new kind and fails schema validation, while 2.21 record-field and 2.22 broadcast envelope checks accept a 2.23.0 proposal. The hierarchy file is part of the approved bundle, placing it in the release file list and the in-toto/DSSE attestation subject set; pre-2.23 releases verify unchanged. Sparkplug group and edge node IDs, topics, and the `Target(group, edge, device)` authorization key do not change. Muninn does not consume the hierarchy yet.
