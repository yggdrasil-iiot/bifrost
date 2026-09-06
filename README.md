# Bifrost

[![CI](https://github.com/yggdrasil-iiot/bifrost/actions/workflows/ci.yml/badge.svg)](https://github.com/yggdrasil-iiot/bifrost/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)
![Build](https://img.shields.io/badge/build-Maven%20multi--module-blue)
![Tests](https://img.shields.io/badge/tests-362-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

**The governance core of the [Yggdrasil](https://github.com/yggdrasil-iiot) IIoT spine — the "IAM" for the OT governance boundary.**

Bifrost decides *what is allowed to cross the OT/IT boundary*. Nothing — no equipment model, no process spec, no runtime command, no version activation — reaches the plant floor or the unified namespace except as a **governed, fail-closed, provenance-verified contract**. Governance is enforced twice: **pre-deploy** (a CLI gate that rejects a bad change before it merges) and **at the runtime edge** (Heimdall, which refuses a bad command or a bad activation at the OPC-UA write boundary). Every claim in this README is backed by an **executable gate** (`scripts/run-*-gate.sh`), not just unit tests.

## What it governs

Two independent governed models, with distinct owners and lifecycles:

| Model | Answers | Artifact | Gate |
|---|---|---|---|
| **Equipment** | *what exists* — the type of a piece of equipment | `UdtDefinition` (AAS-aligned, SemVer'd) | `gates schema` — compatibility (rejects breaking changes) |
| **Process spec** | *how it must run* — admissible ranges, recipes, setpoints | `MasterSpec` + `ConformancePolicy` | `gates spec` / `gates template` — conformance |

Bifrost is the **registry-of-record**: it admits, versions, seals, and activates. Sibling apps only *propose* (Mímir derives models) or *consume* (Muninn feeds the UNS); Bifrost remains the authority, and the apps share **zero code** — they compose only through the governed data/wire contract.

## The gate CLI (pre-deploy, fail-closed)

One `gates` jar, deny-by-default, exit `0` admit / `1` governance-refuse / `2` usage:

| Subcommand | Governs |
|---|---|
| `schema` | UDT schema compatibility (FORWARD/BACKWARD/FULL, Confluent vocabulary) |
| `spec` | `MasterSpec` conformance against the governed `ConformancePolicy` |
| `template` · `adapt-template` | **site ⊨ enterprise** prescriptive governance; a ports-&-adapters core proven standard-agnostic (Ignition / CFIHOS / AAS adapt ≡ native) |
| `policy` | deny-by-default NCMD command authorization (also as an OPA/Rego policy evaluated in-JVM via WebAssembly) |
| `provenance` | git-anchored SHA-256 manifest for the recipe store |
| `activate` · `active` · `activation-log` | the governed **activation** lifecycle (below) |
| `activation verify-chain` | T4 — tamper-evidence of the activation ledger |
| `identity keygen` · `identity verify-signed` | T5 — cryptographic identity over activations |
| `identity authorize` | T6 — deny-by-default authorization: who may activate/approve a resource |
| `identity verify-anchored` | T7 — external-anchor cross-check + four-eyes head (rollback-evident) |
| `federation audit` | multi-site — aggregates per-site activation ledgers into one cross-site view of what is active where |

## The governed activation lifecycle

"Which version is live at an edge" is itself a **governed event** — and the record of those events is progressively hardened from an audit trail into an authenticated, non-repudiable history:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/activation-ladder.dark.svg">
  <img alt="The activation ladder, T3 to T7: what each tier adds on the left, what it still leaves open on the right" src="docs/diagrams/activation-ladder.svg">
</picture>

Each rung closes the hole the rung below left open, and names the hole it leaves. The top rung's hole is stated rather than hidden, and T6 is marked as what it is — a second axis, not a rung.

- **Governed activation (T3)** — activation requires **four-eyes SoD** (a distinct approver), seals the **exact runtime bytes** by SHA-256, appends to an audit ledger, and supports guarded rollback. Heimdall **binds the ledger's active version** at startup and re-checks the content hash at the edge (verify-then-trust).
- **Lineage / record-of-record (T4)** — the ledger is **hash-chained** (`LedgerChain`, one canonical-preimage SHA-256 per entry), so any retroactive edit / delete / reorder / mid-truncation is detectable from the ledger alone. Heimdall **fail-closes on a broken chain** before binding.
- **Identity / signed activation (T5)** — each activation is **dual-signed** (activator + approver Ed25519, JDK built-in) and the ledger tail is anchored by a **signed head**, closing the full-re-chain and tail-truncation gaps a bare hash chain leaves open. Signatures cover T4's `entryHash`, so structural verification is untouched and unsigned ledgers stay valid. Heimdall's `REQUIRE_SIGNED_ACTIVATION` (default off) fail-closes on a broken *signed* ledger.
- **Authorization (T6)** — a **deny-by-default** policy (`registry/identity/activation-policy.json`) decides *whether the authenticated principal is permitted*: **maker-checker**, where the activator needs an `activate` grant and the approver an `approve` grant on the same `(target, kind, ref)` — pairing 1:1 with T5's dual signature. Enforced at the gate and re-verified at the edge (revocation takes effect at the next bind). This is authN (T5) → authZ (T6): the IAM story.
- **Anchored activation (T7)** — the last gap T5's *singly-signed* head leaves open is **rollback by a registered insider**: truncate the ledger, re-sign a shorter head, and signed-verification passes. T7 closes it with two additions. The head becomes **four-eyes** (a second distinct registered co-signer over the same preimage), and the tail is cross-checked against an **external anchor witness** — the highest `(seq, tailEntryHash)` the ledger ever reached — through a pluggable `AnchorStore` seam. The default `FileAnchorStore` is an append-only on-box projection (it catches a *lone* re-anchor: the witness still records the higher `seq`); the opt-in `GitAnchorStore` reads the anchor from **committed git history** (`git show HEAD:<file>`, never the working tree), so a witness committed to a protected remote survives even a **co-rollback** that also rewrites the on-box anchor. Heimdall's `REQUIRE_ANCHORED_ACTIVATION` (default off, with `ANCHOR_STORE`/`ANCHOR_DIR`) raises the edge bar to this tier and fail-closes `activation.edge.anchor-denied` on a rollback / behind / four-eyes-missing fault before binding.

Each step is additive and backward-compatible — a T3/T4 ledger still verifies, turning on signing does not rewrite history, authZ is enforced only over an authenticated (signed) subject, and anchoring layers strictly above the signed check (`ANCHORED` ⊃ `SIGNED`).

## Heimdall — the runtime edge

`heimdall` is the write-boundary authorizer (a Sparkplug **NCMD** → OPC-UA bridge). Deny-by-default, it independently re-authorizes every command *at the edge* — without trusting any upstream authorization — enforcing command ACLs, conformance bounds, and the governed active version, and fails closed on any uncertainty (bad quality, broken/unsigned ledger, content mismatch, rogue command). It closes the loop the gate opens: *observe → command → observe*.

## Federation — one authority, many sites

Single-line governance is not enterprise governance, so the same primitives recombine into a
multi-site topology: an **enterprise git registry** (the authority) plus a **separate enterprise
anchor repository**, with per-site mirror clones that run local-first. Identity trust
(`authorized-keys`, `activation-policy`) federates **down** with the mirror; each site keeps its
**own** activation ledger and anchors it **up** to the enterprise anchor.

`run-federation-gate.sh` proves six properties on two sites:

| | Property |
|---|---|
| F1 | the enterprise template governs both sites — a conforming site specialization passes `site ⊨ enterprise`, a non-conforming one is rejected (exit 1) |
| F2 | governance propagates by `git pull` and takes effect at that site's **next Heimdall restart** (Heimdall reads policy, conformance, ledger and anchor once, at start) |
| F3 | each site activates and enforces independently, and denies a rogue command on its own |
| F4 | a site keeps serving while offline, then reconciles on reconnect |
| F5 | **cross-domain rollback is evident** — a site insider who co-rolls-back the local ledger, head *and* anchor is still caught, because the enterprise anchor is a different trust domain and witnesses the higher `seq` |
| F6 | `federation audit` aggregates both sites' ledgers into one cross-site view of what is active where |

F1/F5/F6 are pure CLI and always run; F2/F3/F4 need Docker and can be skipped.

**Honest, and the gate says so itself:** F5's "cannot rewrite" is **topological**, not
cryptographic. It holds because the enterprise anchor lives in a repository the site never
rewrites. Real closure still needs a genuinely tamper-resistant off-box witness, exactly as in T7.

## Modules

```
core/      the governed model + evaluators — schema, spec/conformance, acl (+OPA-in-wasm),
           template, provenance, activation (T3/T4/T5 identity, T7 anchor). Pure logic, no broker.
gates/     the pre-deploy CLI over core (the `gates` jar).
heimdall/  the runtime edge — NCMD authorization + activation binding, fail-closed.
sim/       an embedded Eclipse Milo OPC-UA server the gates drive end-to-end.
```

## Build & test

```bash
mvn install     # Java 17 · 362 tests (core 223 · heimdall 52 · gates 76 · sim 11)
                # also writes target/bifrost-sbom.{json,xml} — one CycloneDX 1.6 SBOM
                # for the whole reactor (40 components, licences resolved)
```

## Executable gates — the proof

Governance is demonstrated end-to-end, not asserted. Pure-CLI gates need no broker; edge gates need Docker (HiveMQ CE) + host port 1883.
All 15 last ran green on 2026-09-06 (Docker 26.1.4); the broker gates start and stop HiveMQ CE themselves.

```bash
scripts/run-schema-gate.sh                 # schema compatibility admit/reject
scripts/run-spec-gate.sh                   # MasterSpec conformance
scripts/run-template-conformance-gate.sh   # site ⊨ enterprise + 3-adapter equivalence
scripts/run-composable-conformance-gate.sh # ONE ConformancePolicy at design-time AND runtime
scripts/run-provenance-gate.sh             # git-anchored provenance manifest
scripts/run-command-authz-gate.sh          # deny-by-default NCMD authorization
scripts/run-ncmd-runtime-gate.sh           # Heimdall edge authz over a live broker
scripts/run-activation-gate.sh             # T3 — four-eyes SoD, content seal, rollback, edge bind
scripts/run-lineage-gate.sh                # T4 — tamper-evident hash chain, edge fail-close
scripts/run-identity-gate.sh               # T5 — dual-signed activation, signed head, edge fail-close
scripts/run-activation-authz-gate.sh       # T6 — deny-by-default authZ, maker-checker, edge revocation
scripts/run-anchored-activation-gate.sh    # T7 — four-eyes head + external anchor, rollback/co-rollback caught
scripts/run-federation-gate.sh             # multi-site — enterprise template + cross-domain anchor + federated audit
scripts/run-yggdrasil-spine-gate.sh        # Mímir → Bifrost → Muninn northbound spine
scripts/run-yggdrasil-full-loop-gate.sh    # closed loop: observe → command → observe
```

## Honest scope & limitations

This is a systems-architecture reference implementation; it records its limits rather than hiding them.
For the distance between this and a real deployment — which scale problems are answered, which are
deferred and why, and which are open — see **[docs/ENTERPRISE.md](docs/ENTERPRISE.md)**. For the
order any of it could go into a plant that is already running, and the phase where that turns
risky, see **[docs/ADOPTION.md](docs/ADOPTION.md)**.

- **Authorization is direct principal grants, not roles/attributes (T6).** The policy names each principal explicitly (deny-by-default, maker-checker); RBAC roles and ABAC attributes are future threads, and the policy file is plaintext (bootstrap/change-control out-of-band, no policy-signing yet). authZ presupposes authN — with signing off there is no authorization, because there is no authenticated subject to authorize. Revocation is bind-fresh (a running edge re-checks at the next startup).
- **Anchoring is only as strong as the anchor's off-box protection (T7).** The four-eyes head plus external witness make rollback *evident*, but a `FileAnchorStore` is a local projection that a co-rollback can rewrite in place — it defends the lone re-anchor, not the co-rollback. Real rollback-resistance rests on the witness being genuinely tamper-resistant off-box (a protected git remote / signed tag / TPM monotonic counter); the `GitAnchorStore` demonstrates the seam but a locally-committed anchor repo is still on-box. If the git anchor dir resolves *inside* the registry, both the gate and Heimdall **WARN loudly** — a co-located witness is rolled back with the tree it is meant to witness, so `ANCHOR_DIR` must point at a separate off-box repo to actually close the co-rollback. Anchoring presupposes signing (`ANCHORED` ⊃ `SIGNED`), so it does nothing with signing off.
- **Enforcement can be switched off, and that is a supported mode.** `ENFORCEMENT_LOG_ONLY` (default off) makes the edge evaluate every command and refuse none — what would have been denied is logged `[BRIDGE] LOG-ONLY would-deny` and applied anyway. It exists so an edge can be introduced at a running plant without being able to stop the line on day one ([docs/ADOPTION.md](docs/ADOPTION.md) phase 4), and the startup line `[BRIDGE] enforcement = …` prints in both states so the mode is always readable from the log. It does **not** shadow the malformed-payload rejection or the startup ledger-trust checks: a bridge that cannot trust the model it checks against fails to start rather than waving traffic past. Any deployment left in this mode is not enforcing anything.
- **The trust anchor is a plaintext registry file** (`authorized-keys.jsonl`); key bootstrap / distribution / revocation are out-of-band (no PKI/OIDC/CRL yet).
- **Conformance egress is structural + range**, and the activation seal binds the runtime `MasterSpec`, not the git-anchored recipe manifest (that unification is future work).
- **Demo scale** — single broker, single edge, single instance, localhost; the sim's transfer is instant setpoint = PV (a governance loop, not process physics). **The federation gate is no exception: it stands both "sites" up on one machine.** It proves the multi-site *topology*, not multi-site operation.
- Parts were developed with AI assistance; all designs and gate results were verified against live services by the author.

## License

[Apache-2.0](LICENSE)
