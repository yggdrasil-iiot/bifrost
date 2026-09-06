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
| 11 | Audit query at scale | **unmeasured** | Ledger growth and `verify-chain` latency are measurable today and have not been measured |

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
