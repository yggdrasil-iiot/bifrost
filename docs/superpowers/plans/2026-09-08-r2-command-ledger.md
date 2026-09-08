# R2 — Command Ledger Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the commands that move the plant a tamper-evident record, so that `ENTERPRISE.md`'s "a record of who authorized what" is auditable on the command path and not only on the model-activation path.

**Architecture:** A hash-chained, day-segmented command ledger written by the edge on every verdict — applied, denied, would-denied, unreachable alike. It reuses the activation ledger's preimage discipline and none of its types, because a command is not an activation and pretending otherwise would put two meanings in one record.

**Tech Stack:** Java 17, `core/activation`'s `Sha256` and chain idiom, Jackson JSONL, JUnit 5.10.3, Docker (broker for the gate).

---

## Why this round exists

R1 gave a command a verified requester. The record of it is a log line:

```java
System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=" + r.ok());
```

`NcmdOpcUaBridge` holds no ledger reference at all. So the board's tamper-evidence row (4, **built**) and its audit-at-scale row (11, **measured**) both describe the **activation** ledger — the record of which *model version* is live. The commands themselves, the things that actually change a setpoint, are audited by stdout.

That is the asymmetry this round closes: **the audited object is the model, and the unaudited object is the action.**

**What this round does NOT claim** — carried into the docs in Chunk 5:

- It is the **T4 rung for commands, not T5.** The chain makes an edit, deletion or reorder detectable from the file alone. It does **not** survive a wholesale rewrite, because nothing signs it — see decision (b).
- It records **what the edge decided**, not what the plant did. The apply result is in the entry, but the entry is written by the same process that applied it.
- Reads stay out. `handle()` short-circuits observation before authorization and this ledger sits with the verdict, so a read leaves no entry — the same boundary R1 drew, for the same reason.

---

## Facts verified against the source on 2026-09-08

| Fact | Verified |
|---|---|
| The bridge has no ledger reference | `grep -c ledger NcmdOpcUaBridge.java` → 0. The activation ledger is consulted at **startup** by `NcmdOpcUaBridgeMain`, never per command |
| **`ActivationLedger.append` is not synchronized** | It reads `tailEntryHash(f)` then appends — a read-modify-write with no lock. Safe for ~10 activations/day from one writer; **not** safe for commands, which R0 spread across four `CommandExecutor` stripes |
| The chain idiom to follow | `LedgerChain` — ordered, delimiter-joined (`SEP = ''`), `NULL_SENTINEL`, **not JSON**; `entryHash = SHA-256(preimage)`, `prevHash` = the prior entry's hash, `GENESIS` = 64 zeros |
| Signatures sit outside the hash | `LedgerEntry` javadoc — `activatorSig`/`approverSig` are NOT in `entryHash`, so structural verification is unaffected and unsigned lines still verify. R2 inherits that layering |
| The measured growth is for activations | §11: `plain = 434n − 3` bytes, measured on a ledger of **activation** events at roughly ten a day. Commands are a different volume class and the plan must not reuse that number as if it transferred |
| The edge has no signing key | R1 gave it a **verifying** trust anchor; R3 gave it an OPC-UA **application** identity (RSA, for TLS). Neither is a ledger signing key |

### Decisions locked here

**(a) New types, borrowed discipline.**
`CommandEvent` and `CommandLedger`, not a reuse of `ActivationEvent`/`LedgerEntry`. An activation records *which version became live*; a command records *who asked for what and what happened*. Forcing one record to mean both is how a ledger stops being readable. What **is** reused is the preimage discipline — ordered, delimiter-joined, not JSON — and `Sha256`.

**(b) Chained, not signed. This is T4 for commands, and the docs must say T4.**
Signing every command entry would need a signing key **on the edge**, which is a trust question this round has not earned: R1 gave the edge keys to *verify* with, deliberately, and giving it a key to *sign* with changes what a compromised edge can forge. So the chain is the whole mechanism, and its limit is the same one `LedgerChain` already documents for T4 — re-chaining every entry produces a consistent file. Say "tamper-evident against edits and reordering", never "tamper-proof".

**(c) The append must be serialized, because the activation ledger's is not.**
`ActivationLedger.append` reads the tail hash and then appends with no lock. Two commands on two stripes doing that concurrently produce two entries claiming the same `prevHash` — a broken chain written by the ledger itself. `CommandLedger.append` is `synchronized`, and a test drives it from multiple threads and verifies the chain afterwards.

**(d) Every verdict is recorded, not only the successful ones.**
Applied, denied, log-only would-denied, plant-unreachable, overloaded. A ledger of what succeeded is the least interesting half, and a denial is exactly the event an auditor came for.

**(e) A write failure refuses the command — behind an opt-in bar, and not shadowed by log-only.**
If the claim is "no command without a record", then applying a command whose record could not be written breaks it. So when `REQUIRE_COMMAND_LEDGER` is on and the append fails, the command is refused with `command.ledger.unwritable`. Off by default, like every other bar. And **not routed through `refuse()`** — for the same reason R1's bar is not: log-only inverts *verdicts*, and "I could not record this" is not a verdict. R1's C8 has a sibling here.

**(f) Day segments, and retention is named rather than solved.**
One file per UTC day per edge: `commands/<group>/<edge>/<yyyy-MM-dd>.jsonl`. The chain is **per segment**, so a segment is verifiable on its own and a day's file can be archived without breaking the next. That is a deliberate trade: it also means the chain does not link across days, so a whole missing day is invisible to the chain alone. Name that in the docs as the cost of segmenting, and name retention as unsolved rather than implying a policy exists.

---

## Chunk 1: The record

### Task 1: `CommandEvent` and its preimage

**Files:** create `core/src/main/java/dev/krillin/bifrost/core/command/CommandEvent.java`, `CommandChain.java`; test both.

Fields, in preimage order: `group`, `edge`, `cmdId`, `subject`, `command`, `value`, `type`, `outcome`, `reason`, `at` (ISO-8601 UTC). `subject` and `reason` are nullable, so the `NULL_SENTINEL` treatment carries over.

- [ ] **Step 1: failing tests** — the preimage binds every field (change any one, the hash changes); a field-boundary case; `GENESIS` for the first entry; `verify` finds the first break and names its index, as `LedgerChain.verify` does
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

### Task 2: `CommandLedger` — append, segment, verify

**Files:** create `core/src/main/java/dev/krillin/bifrost/core/command/CommandLedger.java`; test.

- [ ] **Step 1: failing tests**, including the two that matter:
  - **concurrent append keeps the chain intact** — drive `append` from 8 threads and verify afterwards. Without `synchronized` this fails, which is the point
  - **a new UTC day starts a new segment at `GENESIS`**, and the previous segment still verifies on its own
- [ ] **Step 2: red · Step 3: implement** (`synchronized append`, day-segmented paths, `verify(segment)`) **· Step 4: green · Step 5: commit**

---

## Chunk 2: The edge writes it

### Task 3: `NcmdOpcUaBridge` records every verdict

**Files:** modify `NcmdOpcUaBridge.java`, `NcmdOpcUaBridgeMain.java`; test.

The seam: the widest constructor gains a `CommandLedger` (nullable = no ledger, today's behaviour) and a `boolean requireCommandLedger`. `Config` gains `COMMAND_LEDGER_PATH` and `REQUIRE_COMMAND_LEDGER`. **Three existing tests construct `Config` directly and will break on arity — again, as in R0, R3 and R1.**

Every exit from `handle()`'s write path records first:

| Outcome | When |
|---|---|
| `applied` | the applier confirmed |
| `denied` | authz or conformance refused, enforcing |
| `would-deny` | log-only shadowed a refusal — **recorded as its own outcome**, because "what the rollout would have blocked" is the question log-only exists to answer |
| `unverified` | R1's signature bar refused |
| `unreachable` | R0's plant-unreachable |
| `overloaded` | R0's queue-full refusal |

- [ ] **Step 1: failing tests** — one per outcome; a ledger-write failure refuses with `command.ledger.unwritable` when the bar is on; **bar on + log-only ⇒ still refused** (R1's C8 sibling); bar off ⇒ unchanged
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: whole suite · Step 6: commit**

### Task 4: `gates command-log` — read it back

**Files:** `gates/src/main/java/dev/krillin/bifrost/gates/CommandLogGate.java`, wired into `GatesCli` (**which duplicates its usage string in two places**).

`verify <segment>` → 0 intact / 1 broken with the index; `tail <segment> [n]`. A ledger nobody can read back is a write-only file.

- [ ] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

---

## Chunk 3: Evidence

### Task 5: `run-command-ledger-gate.sh`

Reuse the R0/R1/R3 idiom: `cygpath`, `fail`, `kill_by_jvmarg`, **a fresh log per bridge run**, count-based assertions, no grep of an accumulating log without a baseline.

| | Asserts |
|---|---|
| **D1** | An applied command appears in the segment with its subject, and `command-log verify` says intact |
| **D2** | A **denied** command appears too — the refusal is the entry an auditor came for |
| **D3** | Editing one entry's value makes `verify` report a break **at that index** |
| **D4** | Truncating the tail is detected |
| **D5** | With the bar on and the ledger path unwritable, the command is **refused** `command.ledger.unwritable` and not applied |
| **D6** | Bar on **plus log-only**: still refused, and not as a shadowed would-deny |
| **D7** | Bar off: the same unwritable path applies the command — proving D5 came from the bar |
| **D8** | Commands from four stripes concurrently leave a chain that verifies |

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: all other gates · Step 5: commit**

---

## Chunk 4: Documents

### Task 6

- [ ] `ENTERPRISE.md` row 4 (tamper-evidence) and row 11 (audit at scale) currently describe the activation ledger only — say that the command ledger exists and that it is **T4, not T5**
- [ ] Add the limits: no signatures, per-segment chains do not link across days, retention unsolved, reads not recorded, and the entry is written by the process that applied the command
- [ ] Remove the R1 limitation bullet that says commands leave no tamper-evident record — **it is the claim this round changes, and leaving it would be the drift these rounds exist to prevent**
- [ ] `ADOPTION.md` phase 4; `README.md` gate list, counts, badge; `ENTERPRISE.md` gate count 18→19

---

## Definition of done

- [ ] `mvn test` green
- [ ] `run-command-ledger-gate.sh` PASS, **every D1–D8 proved by injecting its defect**
- [ ] All eight pre-existing NCMD gates still PASS, still without a command ledger
- [ ] Docs say **T4, not T5**, and no longer say commands leave no record

## What R2 explicitly does not fix

| | |
|---|---|
| No signatures on command entries — a wholesale rewrite is undetectable | later |
| Segments do not chain across days, so a missing day is invisible to the chain | accepted cost of segmenting |
| Retention and archival are unsolved, only named | later |
| Reads leave no entry | open |
| The entry is written by the process that applied the command | inherent to an edge-local ledger |
