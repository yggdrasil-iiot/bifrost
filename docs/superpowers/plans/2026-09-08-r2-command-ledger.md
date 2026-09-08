# R2 — Command Ledger Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the commands that move the plant a tamper-evident record — an **intent** entry written before the plant is touched and an **outcome** entry written after, hash-chained across day segments. With R1's signature bar on, that record names the requester; without it, it records what was decided and not by whom, and this plan says so wherever it would otherwise be read as more.

**Architecture:** Two entries per command, not one. The intent entry is what makes "no command reaches the plant without a record" a claim the code can keep; the outcome entry carries what actually happened, which is only knowable after the applier has run. Both go through a `synchronized`, day-segmented, chained ledger whose segments are linked by their tail hashes.

**Tech Stack:** Java 17, `core/activation`'s `Sha256` and chain idiom, `java.time.Clock` for a testable segment boundary, Jackson JSONL, JUnit 5.10.3, Docker.

---

## Why this round exists

R1 gave a command a verified requester. The record of it is a log line:

```java
System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=" + r.ok());
```

`NcmdOpcUaBridge` holds no ledger reference. The board's tamper-evidence row (4, **built**) and audit-at-scale row (11, **measured**) both describe the **activation** ledger — the record of which model version is live. The commands themselves are audited by stdout.

**The audited object is the model; the unaudited object is the action.** That is what this round closes, and only that.

---

## Facts verified against the source on 2026-09-08

| Fact | Verified |
|---|---|
| The bridge has no ledger reference | The activation ledger is consulted at **startup** by `NcmdOpcUaBridgeMain`, never per command |
| **`ActivationLedger.append` is not synchronized** | It reads `tailEntryHash(f)` then appends — read-modify-write, no lock. Safe for ~10 activations/day from one writer; not safe for commands, which R0 spread across four `CommandExecutor` stripes |
| **A chain does NOT detect truncation** | `LedgerChain.verify` (`LedgerChain.java:42-53`) checks genesis at `i==0`, each self-hash, each prev-link. **Deleting trailing lines leaves every check satisfied.** That is precisely why the activation ladder adds a signed head (T5) and an external anchor (T7), both of which R2 declines. See decision (b) |
| **`applied` is known only after the plant was touched** | `NcmdOpcUaBridge.java:338-343` — `applier.write()`/`call()` runs, *then* the outcome exists. No single entry can be both written-before and carry the result |
| **`subject` is populated only with R1's bar on** | Assigned at `:262`, inside `if (requireSignedCommand)`; `:241` initialises it to null. `REQUIRE_SIGNED_COMMAND` defaults to false |
| **`overloaded` is not an exit from `handle()`** | It is in `messageArrived` at `:516`, on the Paho callback thread, before `handle` is called |
| Log-only makes an apply *also* a would-deny | `shadowed` is set at `:274`/`:311` and the command still reaches the applier at `:336`. The two are not alternatives |
| The chain idiom to follow | `LedgerChain` — ordered, delimiter-joined (`SEP = ''`), `NULL_SENTINEL`, not JSON; `entryHash = SHA-256(preimage)`; `GENESIS` = 64 zeros |
| A `Clock` seam is house style | `ActivateGate` already takes `Clock.systemUTC()`; the segment boundary must too, or the rollover test cannot be written |
| §11's growth number is for activations | `plain = 434n − 3`, measured on ~10 events/day. It does not transfer, and R2 does not replace it — see "does not fix" |

### Decisions locked here

**(a) New types, borrowed discipline.**
`CommandEvent`, `CommandChain`, `CommandLedger` — not a reuse of `ActivationEvent`/`LedgerEntry`. An activation records *which version became live*; a command records *who asked for what and what happened*. What is reused is the preimage discipline and `Sha256`.

**(b) Chained, not signed — and the limit is bigger than "no signatures".**
Signing would need a signing key **on the edge**. R1 deliberately gave it keys to *verify* with; a key to *sign* with changes what a compromised edge can forge, and that is a trust question this round has not earned.

The consequence must be stated precisely, because the obvious phrasing understates it. A chain detects an **edit, a deletion in the middle, or a reorder**. It does **not** detect **truncation** — deleting the last N entries leaves a file that verifies as intact — and it does not detect a wholesale rewrite. Truncation is the cheap attack, not the expensive one. The docs say *"tamper-evident against edits and reordering"* and never *"tamper-proof"*, and they name truncation explicitly.

**(c) The append is `synchronized`, because the activation ledger's is not.**
Two commands on two stripes doing read-tail-then-append concurrently produce two entries claiming the same `prevHash` — a chain broken by the ledger itself. There is a second failure mode too: two unsynchronized appends can interleave into a malformed line, so the verifier must report an unparseable line as its own named verdict rather than dying in the parser.

**(d) Two entries per command: `intent` then `outcome`.**
This is the correction that makes the round's claim keepable. `applied` is only knowable after the applier ran, so one entry cannot be both written-first and carry the result. Instead:

- **intent** — written *before* `applier.write()`/`call()`, carrying subject, command, value, type and the verdict that let it through (including a log-only `shadowed` reason). If this append fails and the bar is on, the command is **refused and the plant is never touched**.
- **outcome** — written after, carrying `applied` / `apply-failed` / `unreachable` and the detail.

A pre-apply refusal (`denied`, `unverified`, `conformance-error`, `malformed`) writes **one** entry, because there is no apply to follow.

It also resolves the log-only case cleanly: a shadowed command produces an intent entry carrying the would-deny reason and an outcome entry saying it was applied — two facts, two entries, which is what actually happened.

The cost is roughly two entries per applied command. Say so; do not let §11's activation figure imply otherwise.

**(e) A failed *intent* append refuses the command — behind an opt-in bar, not shadowed by log-only.**
`REQUIRE_COMMAND_LEDGER` off by default. When on and the intent append fails, refuse with `command.ledger.unwritable` via `refuseUnverified`, **not** `refuse` — same reasoning as R1's bar: log-only inverts *verdicts*, and "I could not record this" is not a verdict. A failed **outcome** append cannot refuse anything (the plant has already moved); it is logged loudly and counted, and that asymmetry is named in the docs.

**(f) Segments are linked by their tail hash.**
One file per UTC day per edge, and **each new segment's first entry carries the previous segment's tail hash as its `prevHash`**, not `GENESIS`. Without that link any segment — including today's — could be deleted or rewritten from genesis with nothing to contradict it, which is materially weaker than the activation ledger's single chain and is not a trade worth making for free. `CommandChain.verify(entries, expectedPrev)` takes the expected predecessor so a lone archived segment still verifies internally. Only the very first segment starts at `GENESIS`.

**(g) `overloaded` is not recorded, and that is a named gap.**
The queue-full refusal happens on the Paho callback thread before `handle` runs, where a `synchronized` filesystem append is the worst possible addition — the file already documents that rule for `connectComplete`. So an overloaded edge refuses commands that leave no ledger entry. It goes in "does not fix" rather than being quietly omitted.

---

## Chunk 1: The record

### Task 1: `CommandEvent` and `CommandChain`

**Files:** create `core/src/main/java/dev/krillin/bifrost/core/command/{CommandEvent,CommandChain,CommandChainVerdict}.java`; test `CommandChainTest`.

Preimage field order: `group`, `edge`, `cmdId`, `subject`, `command`, `value`, `type`, `phase` (`intent`|`outcome`), `outcome`, `reason`, `at`.

**Nullable fields are more than the obvious two.** `subject` is null whenever R1's bar is off; `reason` is null on a clean apply; **`cmdId` is `req.getUuid()` and is nullable** (the blank-cmdId refusal only fires with the bar on); **`value` is `m.getValue()`** and can be null on a malformed metric. All four take `NULL_SENTINEL`.

- [ ] **Step 1: Write the failing tests** — every field participates in the hash (change one, the hash changes); a field-boundary case; `verify(entries, expectedPrev)` accepts a matching predecessor and rejects a mismatched one; a mid-list edit is reported at its index; **a truncation is NOT reported** (an explicit test that documents the limit rather than leaving it to be discovered)

- [ ] **Step 2: Run to verify red**

Run: `mvn -q -pl core test -Dtest=CommandChainTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: class CommandChain`

- [ ] **Step 3: Implement** · **Step 4:** `mvn -q -pl core test -Dtest=CommandChainTest -Dsurefire.failIfNoSpecifiedTests=false` → PASS · **Step 5: Commit**

### Task 2: `CommandLedger`

**Files:** create `core/src/main/java/dev/krillin/bifrost/core/command/CommandLedger.java`; test `CommandLedgerTest`.

Constructor takes the root path **and a `Clock`** — the segment boundary is derived from it, and without the seam the rollover test cannot be written.

- [ ] **Step 1: Write the failing tests**

```java
    /**
     * Probabilistic by nature: this drives the race, it does not prove its absence. 8 threads x 200
     * appends, released together by a barrier, repeated. Without `synchronized` this fails in one of
     * two ways, and the test distinguishes them: two entries claiming the same prevHash (a BROKEN
     * verdict), or two interleaved writes producing an unparseable line (an UNPARSEABLE verdict).
     * Dying in the JSON parser would be a third, and is what the named verdict exists to prevent.
     */
    @RepeatedTest(3)
    void concurrent_appends_leave_a_verifiable_chain() { … }

    @Test void a_new_utc_day_starts_a_new_segment_linked_to_the_previous_tail() { … }
    @Test void the_previous_segment_still_verifies_on_its_own_given_its_expected_predecessor() { … }
    @Test void an_unparseable_line_is_a_named_verdict_not_an_exception() { … }
```

- [ ] **Step 2: red** — `mvn -q -pl core test -Dtest=CommandLedgerTest -Dsurefire.failIfNoSpecifiedTests=false`
- [ ] **Step 3: implement** (`synchronized append`, `Clock`-derived segment path, tail-hash linking) · **Step 4: green** · **Step 5: Commit**

---

## Chunk 2: The edge writes it

### Task 3: Record intent and outcome

**Files:** modify `NcmdOpcUaBridge.java`, `NcmdOpcUaBridgeMain.java`; test `NcmdOpcUaBridgeTest`.

**The recording is scattered across the return sites, not centralised — say so and enumerate them.** `handle()`'s write path exits at roughly eight places:

| Site | Entry |
|---|---|
| `:207` no command metric | one `malformed` |
| R1 bar refusals (`:245`, `:250`, `:255`, `:258`) | one `unverified` |
| authz refusal, enforcing (`:274`) | one `denied` |
| conformance refusal, enforcing (`:311`) | one `denied` |
| unreachable in ② (`:313`) | one `unreachable` |
| **before the applier** (`:336`) | **intent**, carrying `shadowed` when log-only let it through |
| apply returned (`:343`) | **outcome** — `applied` when `r.ok()`, `apply-failed` when not |
| unreachable / error in apply (`:348`, `:354`) | **outcome** — `unreachable` / `apply-error` |

The seam: the widest constructor gains a nullable `CommandLedger` and `boolean requireCommandLedger`; `Config` gains `COMMAND_LEDGER_PATH` and `REQUIRE_COMMAND_LEDGER`. **Three existing tests construct `Config` directly and will break on arity — as in R0, R3 and R1. Add the values to each.**

- [ ] **Step 1: Write the failing tests** — one per entry kind; intent-then-outcome for an applied command; a log-only shadowed apply produces an intent carrying the reason **and** an outcome saying applied; a failed intent append with the bar on refuses `command.ledger.unwritable` and **never calls the applier**; bar on + log-only ⇒ still refused; bar off ⇒ unchanged
- [ ] **Step 2: red · Step 3: implement · Step 4: green** — `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeTest -Dsurefire.failIfNoSpecifiedTests=false` · **Step 5:** `mvn -q test` · **Step 6: Commit**

### Task 4: `gates command-log`

**Files:** `gates/src/main/java/dev/krillin/bifrost/gates/CommandLogGate.java`; wire into `GatesCli`, **which duplicates its usage string in two places**.

`verify <segment> [--expect-prev <hash>]` → **0** intact / **1** broken (with the index) / **2** no such segment — the third case matters because the gate deliberately makes a path unwritable and must distinguish that from a broken chain. `tail <segment> [n]`.

- [ ] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: Commit**

---

## Chunk 3: Evidence

### Task 5: `run-command-ledger-gate.sh`

Reuse the R0/R1/R3 idiom. **Wipe the ledger directory at every edge start**, exactly as the house rule wipes each log (`: > "$LOG"`): a ledger under `build/gate` accumulates across runs and every count-based assertion would otherwise inherit the defect that rule exists to prevent.

**D1 runs with R1's bar ON**, or the subject is null and the leg proves nothing about "who".

| | Asserts |
|---|---|
| **D1** | An applied command leaves **intent then outcome**, the intent carries the signing principal, and `command-log verify` says intact |
| **D2** | A **denied** command leaves one entry — the refusal is the entry an auditor came for |
| **D3** | Editing one entry's value makes `verify` report a break **at that index** |
| **D4** | A **log-only shadowed** command leaves an intent carrying the would-deny reason and an outcome saying applied |
| **D5** | Bar on, the segment's parent path occupied by a **regular file** so `createDirectories` fails: the command is refused `command.ledger.unwritable` and **the sim never witnesses the value** |
| **D6** | Bar on **plus log-only**: still refused, and not as a shadowed would-deny |
| **D7** | Bar off, same unwritable path: the command **is** applied — proving D5 came from the bar |
| **D8** | A new segment's first entry carries the previous segment's tail hash, and the old segment still verifies with `--expect-prev` |

**Concurrency evidence lives in Task 2's unit test, not here.** Over a broker, MQTT round-trips and an OPC-UA write space the appends so far apart that removing `synchronized` would still pass — an injection whose outcome depends on timing proves nothing.

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: Commit**

---

## Chunk 4: Documents

### Task 6

- [ ] `ENTERPRISE.md` rows 4 and 11 — say the command ledger exists and that it is **T4 within a linked segment chain**, not T5
- [ ] **Remove the R1 limitation bullet saying commands leave no tamper-evident record** — it is the claim this round changes, and leaving it is exactly the drift these rounds exist to prevent
- [ ] Add, in its place, the limits that are real: **truncation is not detected**; no signatures; the requester is recorded **only with `REQUIRE_SIGNED_COMMAND` on**, which is off by default, so the default deployment records *what was decided* and not *by whom*; an overloaded edge refuses without an entry; reads leave none; the entry is written by the process that applied the command, and the requester gets no receipt tying an NDATA response to a ledger line; growth is **unmeasured** and retention **unsolved**
- [ ] `ADOPTION.md` phase 4
- [ ] Counts, all of them: `ENTERPRISE.md:12` ("all 18 gates"), `ENTERPRISE.md:596` ("five of the eighteen need no broker" — the new gate needs one, so **both numbers move**), `ENTERPRISE.md:13` (test count), `README.md:6` (badge), `README.md:140` (test count **and** the per-module split, all four of which change), and the README gate list

---

## Definition of done

- [ ] `mvn test` green
- [ ] `run-command-ledger-gate.sh` PASS, **every D1–D8 proved by injecting its defect**
- [ ] All eight pre-existing NCMD gates still PASS, still without a command ledger
- [ ] The docs say **truncation is not detected** and that the requester is recorded only with R1's bar on

## What R2 explicitly does not fix

| | |
|---|---|
| **Truncation is undetectable** — deleting the last N entries leaves a file that verifies. The cheap attack, not the expensive one | needs a signed head (T5) |
| No signatures, so a wholesale rewrite of a segment chain is undetectable | later |
| **With `REQUIRE_SIGNED_COMMAND` off — the default — the requester is null.** The record says what was decided, not by whom | R1's bar, opt-in |
| An overloaded edge refuses commands that leave no entry: the refusal happens on the Paho callback thread, where a blocking append does not belong | later |
| A failed **outcome** append cannot refuse anything; the plant has already moved | inherent |
| Reads leave no entry | open |
| No receipt: the NDATA response carries no entry hash, so a requester cannot check its command was recorded | later |
| Growth is unmeasured and retention unsolved — §11's `434n − 3` is an activation figure and does not transfer | later |
