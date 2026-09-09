# R7 — The Huginn seam: is the governed edge the only write path?

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Project the governed registry into the `CommunicationPolicy` vocabulary Huginn already reads, so a write to governed equipment from anything that is not the governed edge shows up as a violation on the wire — and prove it by actually running Huginn.

**Architecture:** A projection, in the posture `acl-project` established: Bifrost emits an artifact and enforces nothing. `gates conduit-project` reads the governed registry, takes an operator-declared equipment→address binding, and writes YAML that Huginn parses unchanged. **No Huginn source changes.**

**Tech Stack:** Java 17, Jackson (YAML written directly — see Task 1), Huginn's existing CLI and the 4SICS sample captures.

---

## Why this has not been built, stated precisely

`ADOPTION.md` calls this "the Huginn ↔ Bifrost seam, **including the surface mismatch**" and hard-blocks phase 4 on it. The mismatch is deeper than vocabulary:

| | Huginn sees | Bifrost knows |
|---|---|---|
| identity | an **IP address** (peer id → address) | a **principal name**, backed by an Ed25519 key |
| target | a device's IP | `(group, edge)` plus an OPC-UA node id |
| protocol | **Modbus/TCP, S7comm** | **MQTT/Sparkplug → OPC-UA** |
| verb | READ / WRITE / CONTROL / UNDECIDABLE | a command on a node |

**The two surfaces do not overlap on protocol at all.** Heimdall's traffic is invisible to Huginn's decoders and Huginn's traffic is invisible to Bifrost. So any design that "maps the vocabularies" is a lie: there is no shared observation to map.

## The question the seam can honestly answer

**Is there a write path to governed equipment that is not the governed edge?**

That is row 12's other half, and `ENTERPRISE.md` already says so: *"that blind spot is Huginn's reason to exist."* It needs no protocol overlap — the opposite. A Modbus write landing on a governed mixer, over a protocol the edge does not even speak, **is** the bypass.

### The one irreducible human input

Answering it needs exactly one thing that cannot be observed: **which Bifrost governed equipment is which Huginn peer.** No byte on the wire says "10.10.10.10 is Line1-Mixer". That binding is a declaration, it is the operator's, and the projected artifact must say so in its own text rather than letting a reader assume it was discovered.

### What the projection is not

**It is a fragment, not a site policy.** Bifrost knows which edge may write governed equipment. It does not know which HMIs and historians may legitimately *read* it — nothing in the registry records them. So a projected fragment used alone reports every legitimate read as a violation. The operator merges it into the site's declaration; the command says this, and the gate is written so it does not quietly depend on the fragment being complete.

---

## File structure

| File | Responsibility |
|---|---|
| `core/.../conduit/ConduitProjection.java` | **new** — the governed conduits a registry implies, as data |
| `core/.../conduit/ConduitPolicyWriter.java` | **new** — that data as Huginn's `CommunicationPolicy` YAML |
| `gates/.../ConduitProjectGate.java` | **new** — the CLI |
| `gates/.../GatesCli.java` | dispatch + both usage strings |
| `scripts/run-huginn-seam-gate.sh` | **new** — H1–H8, calls the real Huginn |

**YAML is written directly, not through a Jackson YAML module.** `core` has no YAML dependency (`jackson-dataformat-yaml` is `test` scope only, checked), and the document is four keys deep with values Bifrost controls. Adding a compile-scope dependency to emit twenty lines would be the wrong trade — but the writer must then quote and validate rather than concatenate, so Task 1 tests exactly that.

---

## Chunk 1: The projection

### Task 1: The governed conduits a registry implies

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/conduit/ConduitProjection.java`
- Create: `core/src/main/java/dev/krillin/bifrost/core/conduit/ConduitPolicyWriter.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/conduit/ConduitPolicyWriterTest.java`

The projection is `(edgePeer, List<GovernedEquipment>)` where equipment is `(ref, address)`. The emitted document, for every equipment and **every protocol Huginn decodes**:

```yaml
version: 1
peers:
  - id: heimdall-edge
    address: 10.10.10.20
  - id: Line1-Mixer
    address: 10.10.10.10
allowed:
  - from: heimdall-edge
    to: Line1-Mixer
    protocol: MODBUS_TCP
    access: [READ, WRITE]
  - from: heimdall-edge
    to: Line1-Mixer
    protocol: S7COMM
    access: [READ, WRITE]
```

**Why both protocols, including ones the edge does not speak.** The claim is *only the edge may write this equipment*. Over a protocol the edge does not speak, its rule is simply never exercised and costs nothing — while every other host's write to that equipment becomes a violation, which is the finding the seam exists to produce. Enumerating only the protocol the edge happens to use would silently exempt the others.

- [ ] **Step 1: Write the failing tests**

1. one equipment yields a document with two peers and two rules (one per protocol)
2. two equipments yield three peers and four rules; the edge peer appears **once**
3. the output **parses** — the test asserts against the structure, not a golden string, so reformatting does not break it
4. an equipment ref that is not a valid YAML scalar (contains `:`, `#`, a leading `-`, or a quote) is **quoted**, and a ref that cannot be made safe at all is a **coded refusal** rather than a corrupt document
5. an address is validated as an IPv4 literal — a hostname would be accepted by Huginn's loader and then never match a decoded packet, which is a finding that silently cannot fire
6. an empty equipment list is a coded refusal: a document declaring an edge and nothing else governs nothing, and emitting it would look like success
7. the document carries a **header comment** naming the registry it came from and saying the binding is a declaration

- [ ] **Step 2: Run to verify red**

```bash
mvn -q -pl core test -Dtest=ConduitPolicyWriterTest -Dsurefire.failIfNoSpecifiedTests=false
```

- [ ] **Step 3: Implement** · **Step 4: Green** · **Step 5: Commit**

### Task 2: `gates conduit-project`

**Files:**
- Create: `gates/src/main/java/dev/krillin/bifrost/gates/ConduitProjectGate.java`
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/GatesCli.java`
- Test: `gates/src/test/java/dev/krillin/bifrost/gates/ConduitProjectGateTest.java`

`conduit-project <reg> --edge <address> --bind <ref>=<address> [--bind ...] [--out <file>]`

- [ ] **Step 1: Write the failing tests**

1. a valid projection exits 0 and writes the document; without `--out` it prints to stdout
2. **a `--bind` naming a ref that is not in the governed registry is exit 2**, `conduit.equipment.ungoverned`. This is the check that makes it a Bifrost command rather than a YAML templater: projecting governance for equipment nobody governs would produce a confident, meaningless policy
3. a malformed `--bind` (no `=`, empty either side) is exit 2
4. the same address bound to two refs is exit 2 — two peer ids at one address make the finding ambiguous about which equipment was reached
5. the edge address equal to a bound equipment address is exit 2: the edge cannot be the equipment it governs, and allowing it would make every bypass invisible
6. no `--bind` at all is exit 2, not an empty policy
7. the printed output says the binding is operator-declared and the fragment is not a complete site policy

- [ ] **Step 2: Red** · **Step 3: Implement** · **Step 4: Green** · **Step 5: Commit**

---

## Chunk 2: The gate that actually runs Huginn

### Task 3: `scripts/run-huginn-seam-gate.sh`

**This is the round.** A projection nobody feeds to Huginn proves the YAML is well-formed, not that the seam exists.

**Locating Huginn.** `HUGINN_HOME`, defaulting to `../huginn` relative to the Bifrost root. If the directory or its jar is absent the gate **skips with a clear message and exits 0** — the same posture as the Docker-gated gates. It is therefore **not added to CI**, and the broker-free count is unchanged.

**Grep ASCII only.** Huginn's report is in Korean and this gate must not depend on its wording — match the IP addresses, `S7COMM`, `WRITE` and `[HIGH]`, which are stable and language-independent. Anything else couples a Bifrost gate to Huginn's prose.

**The fixture story.** `samples/4SICS-GeekLounge-151020.pcap` contains S7comm writes to `10.10.10.10:102` from **two** hosts, `10.10.10.20` and `10.10.10.30`. Bind the PLC as governed equipment and declare `10.10.10.20` the governed edge; `10.10.10.30` is then a host reaching governed equipment without being the edge, which is exactly the bypass.

| | Asserts |
|---|---|
| **H1** | `conduit-project` emits a document and **Huginn parses it** — a contract error would exit 2, so this is the seam's minimum claim |
| **H2** | **the bypass is found**: `10.10.10.30` appears as a violation writing to `10.10.10.10` over S7COMM |
| **H3** | **the declaration is honoured**: `10.10.10.20`, the declared edge, does **not** appear as a violation. Without this, H2 is satisfied by deny-by-default flagging everything, which would prove nothing about the projection |
| **H4** | Huginn exits **1** (violations found), not 2 (contract error). The two are easy to confuse from a non-zero exit alone |
| **H5** | swapping the binding — declaring `10.10.10.30` the edge — moves the violation to `10.10.10.20`. The projection drives the verdict; the capture is constant |
| **H6** | a ref not in the governed registry is refused before any YAML is written (`conduit.equipment.ungoverned`), and **no output file is created** |
| **H7** | the emitted document names the registry and says the binding is declared, not discovered |
| **H8** | with **no equipment governed at that address** — the PLC bound to a different governed ref whose address is a host with no traffic — Huginn reports **no violation for that equipment**, so H2's finding is attributable to the binding rather than to the capture |

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: commit**

**Injection discipline.** R5 had three ineffective injections and R6 one; in every case the gate went red for the wrong reason. **Read each injection's failure message and confirm it names the assertion being proved.** An injection that produces a crash, a usage error, or a failure in an earlier assertion has not proved its own.

---

## Chunk 3: Documents

### Task 4

- [ ] `ENTERPRISE.md` — the "**Huginn is not wired to Bifrost**" limitation is now wrong as written; replace it with what exists (a projection Huginn parses, and a bypass finding proved against a real capture) and what does not (**Bifrost still holds no reference to Huginn, and Huginn still holds none to the registry** — the seam is an artifact handed across, not a dependency)
- [ ] `ENTERPRISE.md` row 12 — the write-exclusivity row gains its other half: the OPC-UA side is enforced by the server, and a bypass *over another protocol* is now visible rather than merely acknowledged. Say plainly that visibility is not enforcement
- [ ] `ENTERPRISE.md` §5 — the conduit register now has a declared-source input for the governed conduits; the frequency, ownership and exclusion gaps are untouched
- [ ] `ADOPTION.md` — the gap table row "Huginn ↔ Bifrost seam, including the surface mismatch" becomes **built in part**, and phase 2 gains the command with the binding step called out as the human input it is
- [ ] `ADOPTION.md` — the "first phase that needs code that does not exist" paragraph narrows again
- [ ] Counts: gates 22→23, tests, `README.md` badge, per-module split, gate list
- [ ] **Not added to CI** — it needs the Huginn repo beside Bifrost, so the broker-free sentence stays seven of the twenty-three, with the reason stated

---

## Definition of done

- [ ] `mvn test` green; no pre-existing test changed
- [ ] `run-huginn-seam-gate.sh` PASS with Huginn present, **every H1–H8 proved by injecting its defect**
- [ ] **H2, H3 and H5 pass** — the bypass is found, the declared edge is not flagged, and swapping the binding moves the finding. The three together are what distinguishes a working seam from deny-by-default noise
- [ ] The gate **skips cleanly** with `HUGINN_HOME` unset and no sibling checkout, exiting 0
- [ ] Every other gate still PASS (22 of them, Docker up)
- [ ] **No file under the Huginn repository is modified** — if one is, the claim that the projection satisfies an existing contract is false

## What R7 explicitly does not fix

| | |
|---|---|
| **The binding is declared, not discovered.** Nothing on the wire says an IP is a governed equipment | irreducible |
| **The fragment is not a site policy.** Bifrost does not know the legitimate readers, so it cannot declare them | the registry has no such field |
| **Visibility is not enforcement.** A bypass becomes a finding with an owner; nothing blocks it | row 12's server-side half is the plant's |
| Modbus/TCP and S7comm only — Huginn's decoders bound the seam, and a path nothing decodes is unaccounted for rather than out of scope | §5, unchanged |
| Neither repository depends on the other; the artifact is handed across | deliberate |
| Nothing schedules it — a command an operator runs against a capture somebody pulled | phase 0's posture |
