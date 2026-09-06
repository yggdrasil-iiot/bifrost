# Taking this to an enterprise

Bifrost is a reference implementation that runs on one machine. This document is about the
distance between that and a real deployment: **which scale problems are already answered, which
are deliberately deferred, and which are open** — for the Yggdrasil spine as a whole
(Bifrost, Heimdall, Mímir, Muninn, Huginn).

**The rule this document follows.** A row marked *built* must point at a gate or a test that
proves it. A row marked *deferred* must name the concrete trigger that would force the work.
A row with neither is a wish, and wishes do not belong here.

Evidence dates from **2026-09-06**, when all 15 gates were last run green (Docker 26.1.4) and
the suites measured 352 tests in Bifrost and 242 in Huginn.

---

## The board

| # | Axis | Status | Evidence, or the trigger that forces it |
|---|---|---|---|
| 1 | Multi-site authority, site specialization | **built** | `run-federation-gate.sh` F1 · `run-template-conformance-gate.sh` (site ⊨ enterprise, 3 adapters ≡ native) |
| 2 | Governance propagation to a site | **built, with a boundary** | F2 — `git pull`, then effective at that site's **next Heimdall restart** ([why](#2-propagation-is-restart-scoped-on-purpose)) |
| 3 | Site keeps running while disconnected | **built** | F4 — offline serving, reconcile on reconnect |
| 4 | Tamper-evidence, insider rollback | **built** | LN1–LN4 · I1–I7 · AN1–AN8 · F5 (cross-domain anchor) |
| 5 | **Conduit inventory (IEC 62443 SR 6.2)** | **partial** | Huginn produces the *observed* list and reconciles it; frequency, ownership and non-TCP conduits are missing ([detail](#5-conduit-inventory)) |
| 6 | **Identity lifecycle** | **deferred, with a path** | Trigger: the second site on real hardware, or the first certificate expiry ([detail](#6-identity-lifecycle)) |
| 7 | **Supply chain / EU CRA** | **partial** | Ledger, provenance manifest and a CycloneDX SBOM exist; **no vulnerability-handling process, and the ledger does not reach the build** ([detail](#7-supply-chain-and-the-cra)) |
| 8 | Brownfield vendor heterogeneity | **partial** | 3 `TemplateAdapter` implementations; the vendor-front gateway posture is designed, not built |
| 9 | AAS alignment → conformance | **deferred** | Trigger: a customer asking for an IDTA submodel template by number |
| 10 | Certificate expiry, key rotation | **open** | No mechanism. Trigger: any deployment that outlives its first certificate |
| 11 | Audit query at scale | **measured** | `scripts/bench-ledger.sh` — growth is exactly 434 B/entry (645 signed); signature verification costs ~8× the chain walk, and anchoring is free on top of it ([detail](#11-audit-query-at-scale)) |

Rows 5, 6 and 7 carry this document. Rows 1–4 are the easy ones to write because they are done;
on their own they would be a feature list.

---

## 2. Propagation is restart-scoped on purpose

A site pulls governance changes with `git pull`, and they take effect at that site's **next
Heimdall restart** — not on the next command. F2 asserts exactly this, including the revocation
case: a principal removed at the enterprise stays able to act until the site's edge restarts.

That is a real limit and it is worth stating rather than burying, because it is the first thing
an operator asks. It is also the deliberate choice. Heimdall reads policy, conformance bounds,
the activation ledger and the anchor **once, at startup**, and then authorizes every command
against that fixed picture. Re-reading them per command would mean a write-boundary authorizer
whose verdict can change underneath a running batch because someone merged a pull request, and
whose availability now depends on the registry being reachable at command time.

The cost is bounded and known: revocation latency equals the time to the next edge restart. The
alternative's cost is unbounded and only shows up during an incident. If revocation needs to be
faster than a restart, the fix is a short-lived credential rather than a hot-reloading gate, and
that lands in §6.

---

## 5. Conduit inventory

IEC 62443 organises a plant into **zones** and the **conduits** between them. The operational
requirement is not a one-time drawing: guidance describes a **living list** of every
communication path with protocol, frequency, affected assets and responsibilities, and notes
that auditors explicitly ask for it. SR 6.2 (continuous monitoring) is the same idea in the
system requirements.

**What Yggdrasil does differently.** The prevailing practice is to *baseline* normal traffic and
alert on deviation, because nobody declared the conduits. Here the conduits **are** declared — a
deny-by-default `CommunicationPolicy` — so Huginn compares rather than learns. There is no
model to train and no drift in the baseline, because there is no baseline.

**Built:**
- Huginn decodes Modbus/TCP and S7comm out of a capture and reports every undeclared
  source → target → protocol → access path, with the object touched.
- Cross-checked against **tshark**: S7 request counts match exactly (23,732 / 86,403 / 53,217
  across three 4SICS captures), and responses are never counted as requests.
- Coverage is reported next to violations, so "0 findings" cannot hide "we read almost nothing".

**What a real conduit register needs that Huginn does not yet produce:**
- **Frequency.** A finding says a path exists, not how often it is used. An auditor's register
  wants both. The data is in the capture; the report does not aggregate it over time.
- **Responsibility.** Who owns this conduit is not derivable from traffic. It has to come from
  the declaration side, which means `CommunicationPolicy` needs an owner field.
- **Non-TCP conduits.** UDP, and anything not Modbus/TCP or S7comm, is counted as out of scope
  rather than enumerated. A register that silently omits a protocol is worse than no register.
- **S7comm-plus**, which is what S7-1200/1500 speak natively. Zero frames in the sample set, so
  there is nothing to verify an implementation against.
- **Live capture.** Today it reads a pcap. The decode path is identical either way, but a
  register that is refreshed manually is not "living".

**Trigger:** the first time this is used to answer an audit rather than to demonstrate a
mechanism. That is when frequency and ownership stop being optional.

---

## 6. Identity lifecycle

The trust anchor today is a plaintext `authorized-keys.jsonl` in the registry. Signing keys are
Ed25519 from the JDK. Bootstrap, distribution and revocation are all out-of-band. This is the
single largest gap between this implementation and a deployment, and it is deliberate: identity
is where a governance system either integrates with what the enterprise already runs, or invents
a second one that nobody maintains.

**The path is specific.** OPC UA already defines the answer for the OT side: a **Global Discovery
Server** provides centralised certificate management across an enterprise and integrates with an
enterprise PKI for enrolment, renewal and revocation. Siemens ships **GDS Push** on the S7-1500,
so the endpoint side of this is not hypothetical.

**What the literature says breaks at scale, and why it decides the design:**
- Heterogeneous fleets with long equipment lifecycles make manual certificate handling
  unworkable well before the fleet is large.
- **A disconnected asset cannot reach the GDS to renew.** This is not an edge case in a plant; it
  is Tuesday. Any design that assumes reachability at renewal time will fail closed at exactly
  the wrong moment, which for a write-boundary authorizer means a stopped line.
- Availability requirements mean the failure mode of an expired certificate has to be decided in
  advance, not discovered.

That last point is why this is deferred rather than half-built. Heimdall fails closed by design.
Wiring it to a certificate authority without first deciding what it does when renewal is
unreachable would convert a security control into an outage generator. The order has to be:
decide the disconnected-renewal behaviour, then integrate.

**Trigger:** the second site running on real hardware, or the first certificate expiry —
whichever comes first. Both make the current design untenable in the same week.

---

## 7. Supply chain and the CRA

Regulation (EU) 2024/2847 came into force on 2024-12-10. **Reporting obligations apply from
2026-09-11** — actively exploited vulnerabilities and severe incidents, on a 24-hour early
warning / 72-hour notification / 14-day final report cascade. The main design, documentation and
CE-marking obligations follow on 2027-12-11.

The useful framing from the OT security discourse is that **the CRA defines the *what* and
IEC 62443 delivers the *how***. Read together, they ask an operator for three artefacts: an asset
inventory, a conduit register (§5), and a documented vulnerability-handling process backed by an
SBOM, which is described as becoming a standard artefact in 2026.

**What already lines up, structurally:**
- The **provenance manifest** is a git-anchored SHA-256 over the registry bytes, verified before
  anything is birthed into the UNS.
- The **activation ledger** answers "which version was live, when, approved by whom" with
  four-eyes separation of duties, a hash chain, dual Ed25519 signatures and an external anchor.
  That is a non-repudiable lifecycle record, which is the shape the CRA asks for.

- **An SBOM is generated.** `mvn package` emits `target/bifrost-sbom.{json,xml}` — one
  CycloneDX 1.6 document for the whole reactor, 40 components with licences resolved. It is a
  build artefact, so it is not committed; it belongs attached to a release.

**What is missing, plainly:**
- **No vulnerability-handling process.** No security policy, no disclosure contact, no advisory
  channel. The reporting obligation above is a *process* obligation, and processes are not code.
  Producing an SBOM is the input to that process, not the process.
- **The ledger covers the governed model, not the software.** It records which *spec* was
  activated, not which *build* is running. Connecting the two is the real work, and it is exactly
  where SLSA-style build provenance would slot in. Today the SBOM and the activation ledger are
  two records with no link between them.
- **Nothing consumes the SBOM.** No dependency scanning, no advisory matching. A component
  inventory that nobody diffs against a vulnerability feed changes an audit answer, not a risk.

**Trigger:** already live. The reporting date is not conditional on adoption.

---

## 11. Audit query at scale

The ledger only grows. Reproduce with `bash scripts/bench-ledger.sh` (add `MODE=signed` for the
signed ladder); it asserts nothing and prints numbers.

### Growth is exact

| entries | plain ledger | signed ledger |
|---:|---:|---:|
| 25 | 10,847 B | 16,122 B |
| 100 | 43,397 B | 64,497 B |
| 500 | 216,997 B | 322,497 B |
| 2,000 | 867,997 B | 1,289,997 B |

`plain = 434n − 3` and `signed = 645n − 3` fit every row with no residual, because a chained
entry is a fixed set of fields plus one SHA-256. **434 bytes per activation, 645 once signed.**

The 211-byte difference is fully accounted for: two Ed25519 signatures at 64 bytes each are 88
base64 characters apiece (176), and the two JSON field wrappers `,"activatorSig":""` and
`,"approverSig":""` are the remaining 35. Nothing unexplained is being stored.

Two smaller files sit beside the ledger. The **anchor** is append-only, one record per
activation of the form `{"target":"Line1","seq":N,"tailEntryHash":"<64 hex>"}` — that is
`109 + digits(N)` bytes, and 109×2000 + 6,890 comes to exactly the 224,890 B measured. The
**head** is a single 347-byte file regardless of ledger length.

At 645 B/entry plus 112, ten thousand signed activations is about 7.6 MB of newline-delimited
JSON.

### Verification, measured back to back on one 2,000-entry signed ledger

| | wall clock | minus JVM start | per entry |
|---|---:|---:|---:|
| bare `java -jar`, no arguments | 283 ms | — | — |
| `activation verify-chain` | 820 ms | 537 ms | 0.27 ms |
| `identity verify-signed` | 4,639 ms | 4,356 ms | 2.18 ms |
| `identity verify-anchored` | 4,469 ms | 4,186 ms | 2.09 ms |

Medians of five, all four interleaved in one loop so they share the same machine conditions. An
earlier two-way run reproduced the chain and signed figures (842 ms and 5,103 ms).

Two things fall out, and the second is the more useful.

**Signature verification costs roughly eight times the plain chain walk** — 2.2 ms per entry
against 0.27 — which is about 1 ms for each of the two Ed25519 verifications per entry. That
ratio is the number to carry, because it was measured on one ledger in one sitting.

**Anchoring is free on top of signing.** `verify-anchored` measured *below* `verify-signed`
here, and the spreads overlap almost completely (anchored 4,346–5,183, signed 4,352–5,178). That
is what the mechanism predicts: the anchor check compares one `(seq, tailEntryHash)` pair against
the head, while the cost of both commands is the per-entry signature walk they share. **The
strongest tier on the ladder costs no more than the tier below it**, so the reason to leave
`REQUIRE_ANCHORED_ACTIVATION` off is not performance.

### The two anchor stores cost differently, and not where you would guess

The figures above use the on-box `file` anchor. The `git` store is the one that actually
defends a co-rollback, so what it costs matters. Measured on two registries of the same size
(20 signed activations each), so the per-entry signature work is identical and the difference is
the store:

| | per activation | per verification |
|---|---:|---:|
| `file` anchor | 1,402 ms | 1,096 ms |
| `git` anchor | 1,939 ms | 1,140 ms |
| difference | **+537 ms** | **+44 ms** |

**Cheap to check, expensive to write.** Verification adds about 45 ms once, because it is a
single `git show HEAD:<file>` regardless of how long the ledger is. Activation adds about half a
second every time, because it commits. The anchor repository was 171 KB after 20 commits, loose
and un-repacked.

Operationally that lands in the harmless column: an extra half-second on an event that happens
ten times a day is nothing, and the check that runs at every edge bind is the cheap one. Choosing
`file` over `git` is not a performance decision either — it is the topological one described in
§4, and the gate says as much itself.

Note the two stores are alternatives, not layers: a git-anchored activation writes no file
anchor.

### Why there is no per-entry slope from the ladder

The ladder runs produced timings that cannot be used, and it is worth saying why rather than
quietly reporting the ones that looked plausible. In the signed ladder, 500 entries measured
6,924 ms while 1,000 entries measured 3,044 ms. The work is monotonic in n, so that inversion is
machine load, not the software. Across three runs on this laptop the bare JVM start alone moved
between 281 ms and 842 ms. **A CLI-level stopwatch on a developer machine cannot resolve a
sub-millisecond-per-entry signal.** The byte counts are a property of the format and reproduced
identically every time; the timings are a property of one laptop's afternoon. Getting a real
slope needs in-JVM timing or a quiet machine, and neither has been done.

### The operational reading

This is not the binding constraint. An entry is created by a governed activation, not by traffic.
A site performing ten governed activations a day reaches 2,000 entries in about seven months, at
which point the signed ledger is 1.3 MB and verifying every signature in it takes five seconds.
Something else will hurt first.

**Not measured:** `federation audit` across many sites, how the git anchor repository grows once
git repacks it, and any of this on server hardware rather than a laptop.

---

## Where this sits next to what shipped

Broker-side governance arrived while this was being built. EMQX Enterprise 6.2 ships a UNS
Governance plugin that enforces topic structure at ACL check time and validates payload schemas
at publish, rejecting non-conforming publishes at the source. That is a genuine validation of the
premise that a flat namespace needs an enforced contract.

It is also a different axis, and the difference matters for anyone sizing this work:

| | Broker-side UNS governance | Yggdrasil |
|---|---|---|
| Axis | data | **control** |
| When | publish, at runtime | **pre-deploy gate, plus re-authorization at the edge** |
| Object | topic structure, payload shape | **the model's lifecycle** — admit, version, seal, activate — plus command authorization and genealogy |
| Blind spot | **whatever does not go through the broker** | that blind spot is Huginn's reason to exist |

An engineering workstation cabled to a PLC publishes nothing. Broker-side enforcement cannot see
it, by construction. That is not a criticism of the broker; it is the boundary of where that
control applies, and it is why the observation arm is a separate component rather than a feature.

---

## Rollout shape

Reported experience with federated multi-site UNS puts a full deployment at **6–18 months**, with
subsequent plants at **4–8 weeks** each once the model is settled, and locates the hard part in
the data model and its ownership rather than the technology. The recurring conclusion is
*standardization with flexibility*: templates help, but sites have legitimate differences.

That conclusion is the requirement F1 implements. `site ⊨ enterprise` admits a conforming site
specialization and rejects a non-conforming one with a non-zero exit, and the three
`TemplateAdapter` implementations mean the enterprise template does not have to be expressed in
one vendor's dialect. The claim worth making is narrow and testable: this shortens the *governance*
part of a site rollout, not the rollout.

---

## What this document does not claim

- **Not enterprise-proven.** The federation gate stands both "sites" up on one machine. It proves
  the topology, not multi-site operation. Nothing here has run in a plant.
- **The edge bars above signing are opt-in.** `REQUIRE_SIGNED_ACTIVATION` and
  `REQUIRE_ANCHORED_ACTIVATION` both default to `false`. Statements of the form "Heimdall
  fail-closes on an unsigned ledger" are true only once you turn it on.
- **Authorization is direct principal grants**, not roles or attributes, and the policy file is
  plaintext with change control out of band.
- **F5's rollback resistance is topological, not cryptographic.** It holds because the enterprise
  anchor lives in a repository the site never rewrites. Real closure needs a tamper-resistant
  off-box witness.
- **ISA-95 and AAS are alignments, not certifications.** For ISA-95 no certification scheme
  exists; for AAS, conformance means IDTA submodel templates this does not yet implement.
- **Huginn is not wired to Bifrost.** It reads its own `CommunicationPolicy`; there is no
  reference to the governed registry in its code. Connecting them is the next real test of the
  seam, and it has not been taken.

## How to falsify this document

Every *built* row above names a script. Clone, run it, and read the exit code — five of the
fifteen need no broker at all. If a row's gate does not prove what the row claims, the row is
wrong and should be reported as a bug in this document, not excused.

---

*References for the external claims on this page: EU Cyber Resilience Act timeline
([EC](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)); the CRA/62443
"what and how" framing and the conduit-register expectation
([Security Today](https://www.securitytoday.de/en/2026/04/20/ot-security-2026-why-iec-62443-and-the-eu-cyber-resilience/));
zones and conduits ([Trout](https://www.trout.software/blog/iec-62443-zones-and-conduits-explained));
OPC UA GDS and enterprise PKI
([Integration Objects](https://integrationobjects.com/blog/opc-ua-global-discovery-server-gds-explained-centralized-certificate-management-for-opc-ua/),
[Siemens GDS Push](https://support.industry.siemens.com/cs/attachments/109799888/109799888_OPCUA_GDSPush_DOC_V1.0_en.pdf));
broker-side UNS governance ([EMQX](https://www.emqx.com/en/blog/native-mqtt-governance-for-uns));
multi-site UNS experience ([Automation World](https://www.automationworld.com/factory/iiot/article/33016191/unified-namespace-real-world-applications-and-challenges)).*
