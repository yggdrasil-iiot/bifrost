# R4 — Break-Glass Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the four-eyes activation rule an emergency path that is **recorded, time-boxed, single-use and loud** — so that the first time it is genuinely needed at two in the morning, the site uses the governed route instead of going around the system permanently.

**Architecture:** A break-glass **grant**: a four-eyes-signed, expiring, single-use credential minted *in advance* for a named target. Presenting a valid grant lets one person activate alone. The activation is recorded with its own action and grant id, and until it is ratified after the fact, further activations on that target are refused.

**Tech Stack:** Java 17, `core/activation` and `core/identity` (Ed25519, `AuthorizedKeys`), JUnit 5.10.3, Docker.

---

## Why this round exists

`ADOPTION.md:165` still says it plainly:

> There is still no break-glass.

`ActivationService.activate` requires a distinct approver unconditionally (`activation.approval.missing`, `activation.approval.self`). At two in the morning with one person on site, there is no governed way to activate — so the activation happens **outside the system**, and the moment a bypass works once it becomes the normal path. The governance value of an emergency route is not that it does not exist; it is that **it is recorded and it is noisy.**

**The load-bearing idea, and the one thing this plan must not fudge:** you cannot both require two people and not require two people. **Break-glass does not remove four-eyes — it moves it earlier in time.** A grant is minted by two people while both are available, and spent by one when only one is. Anything that mints a grant with one signature is not break-glass, it is a hole.

**What this round does NOT claim:**

- It does not help a site that never minted a grant. That is the deliberate cost of not having a single-signature path that exists on demand
- A minted grant is a **standing single-signature capability sitting in a drawer**. Its expiry, its single target and its single use are the whole of the protection, and each is stated rather than assumed
- Ratification is enforced by **refusing later activations**, not by undoing the emergency one. The plant already moved

---

## Facts verified against the source on 2026-09-08

| Fact | Verified |
|---|---|
| Four-eyes is unconditional | `ActivationService.java:22-26` — `approvedBy` must be present and must differ from `by`, before any signing path is considered |
| The signer binds to the named principals | `:33-38` — the two signing keys must equal the named activator/approver, so a grant cannot simply be "sign twice with one key" |
| T6 authZ is on the signed path only | `:40-50` — `authZ presupposes authN`, and both principals are authorized separately |
| The event has an `action` field | `ActivationEvent` — currently `ACTIVATE | ROLLBACK`. A third value is the natural place for this, and it makes every existing verifier see break-glass without being taught to |
| The ledger append is the same for all actions | `ActivationLedger.append(e, signer)` — so a break-glass event is chained, signed and anchored exactly like any other |
| `IdentityGate keygen` already mints keys | Prints the `authorized-keys.jsonl` line; R1's gate uses it. Grant minting reuses it rather than inventing key handling |
| `docs/ADOPTION.md:165` asserts the gap | "There is still no break-glass" — the sentence this round removes |

### Decisions locked here

**(a) A grant is minted by two people, in advance, or it is not a grant.**
`gates activation break-glass-mint` requires **two** signing keys, exactly as an activation does. What it produces is a signed document naming: target, kind, ref, the single principal permitted to spend it, an expiry, and a nonce. The four-eyes has happened; it has simply happened earlier.

**(b) Spending a grant is single-use, and the ledger is what enforces it.**
The nonce is recorded in the break-glass event. A second activation presenting the same nonce is refused `activation.breakglass.spent`. There is no separate state file to lose: **the ledger already is the state.**

**(c) The event action is `BREAK_GLASS`, not `ACTIVATE` with a flag.**
Every existing reader — `activation-log`, `federation audit`, the edge's bind check — sees the action. Making break-glass a distinct action means none of them has to be taught what a flag means, and none of them can accidentally not notice.

**(d) Loud means loud in the two places an operator actually looks.**
A `[GATE] BREAK-GLASS` line on stderr with the grant id and the expiry, and the event itself. This round does **not** invent an alerting transport — saying "it pages someone" when nothing pages anyone would be exactly the kind of claim these rounds exist to remove.

**(e) Ratification refuses the NEXT activation; it does not undo the emergency one.**
After a break-glass event, an activation on that target is refused `activation.breakglass.unratified` until a `break-glass-ratify` entry naming that nonce is appended by **two** principals. The plant already moved — the leverage is on what happens next, and that is honest about what an after-the-fact control can do.

**(f) The window is a policy input, not a constant.**
`--ratify-within <hours>`, recorded in the grant. A site that wants a four-hour window and a site that wants a week are both legitimate, and hard-coding either is a claim about someone else's operations.

---

## Chunk 1: The grant

### Task 1: `BreakGlassGrant` — shape, preimage, verification

**Files:** create `core/src/main/java/dev/krillin/bifrost/core/activation/BreakGlassGrant.java`; test `BreakGlassGrantTest`.

Fields: `target`, `kind`, `ref`, `spender` (the one principal who may use it), `expiresAtMillis`, `ratifyWithinHours`, `nonce`, `mintedBy`, `mintedApprovedBy`, and two signatures.

Preimage discipline as everywhere else: ordered, delimiter-joined, not JSON.

- [ ] **Step 1: failing tests** — a two-signature grant verifies; a grant signed twice by the same key does not (that is the hole this round must not open); an expired grant does not; a grant for another target does not; a grant naming another spender does not; every field participates in the preimage
- [ ] **Step 2: red** — `mvn -q -pl core test -Dtest=BreakGlassGrantTest -Dsurefire.failIfNoSpecifiedTests=false`
- [ ] **Step 3: implement · Step 4: green · Step 5: commit**

### Task 2: `gates activation break-glass-mint`

**Files:** extend `ActivateGate`; wire into `GatesCli` (**usage string duplicated in two places**).

`break-glass-mint <reg> <target> <kind> <ref> --spender <p> --expires-in <hours> --ratify-within <hours> --by <p> --by-key <f> --approved-by <p> --approved-by-key <f>` → writes the grant, prints its nonce. **Refuses when the two keys are the same**, with the same reason shape `ActivationService` uses for the self-approval case.

- [ ] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

---

## Chunk 2: Spending it

### Task 3: `ActivationService` accepts a grant

**Files:** modify `ActivationService.java`, `ActivationRequest`; test.

A new overload `activate(r, signer, policy, grant)`. When a grant is present:

1. verify it (two signatures, unexpired, target/kind/ref match, spender equals `r.by()`)
2. **skip the distinct-approver requirement** — that is the whole point
3. refuse `activation.breakglass.spent` when the nonce already appears in the ledger
4. record `action = BREAK_GLASS`, with `approvedBy` set to the grant's nonce-bearing identity so the record shows *which grant* authorised it

**The signer path needs care.** `:33-38` binds two signing keys to the named activator and approver. On the break-glass path there is one person, so the check must become "the activator's key matches `r.by()`", and the approver half is satisfied by the grant's own signatures rather than by a second live key. Getting this wrong in either direction is the round's main risk: too strict and break-glass cannot be signed at all, too loose and a single key can forge a normal activation.

- [ ] **Step 1: failing tests** — a valid grant activates with no approver; the same grant twice is `spent`; a grant whose spender differs from `by` is refused; an expired grant is refused; **an ordinary activation with no grant still requires a distinct approver** (the regression that matters); a single signing key still cannot produce a normal four-eyes activation
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: whole suite · Step 6: commit**

### Task 4: Unratified break-glass locks the next activation

**Files:** modify `ActivationService`; add `break-glass-ratify` to `ActivateGate`; test.

- [ ] **Step 1: failing tests** — after a break-glass event, a normal activation on that target is refused `activation.breakglass.unratified`; after a two-principal ratify naming that nonce, it succeeds; a ratify signed by one key is refused; a ratify naming a different nonce does not unlock; **a different target is unaffected** (the lock must not be global)
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

---

## Chunk 3: Evidence

### Task 5: `run-break-glass-gate.sh`

House idiom: `cygpath`, `fail`, fresh working dirs, staged registry, count-based assertions.

| | Asserts |
|---|---|
| **B1** | Without a grant, a single-person activation is refused `activation.approval.missing` — the pre-R4 behaviour, unchanged |
| **B2** | Minting a grant with the **same key twice** is refused |
| **B3** | With a valid grant, one person activates alone; the ledger line has `action=BREAK_GLASS` and the grant nonce; `activation verify-chain` is intact |
| **B4** | The emergency is **loud**: a `BREAK-GLASS` line naming the grant and its expiry |
| **B5** | The same grant a second time is refused `activation.breakglass.spent` |
| **B6** | A normal activation on that target is now refused `activation.breakglass.unratified` |
| **B7** | After a two-principal ratify, that normal activation succeeds |
| **B8** | A **different target** was never locked |
| **B9** | An expired grant is refused |

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: commit**

---

## Chunk 4: Documents

### Task 6

- [ ] `ADOPTION.md:165` — **remove "There is still no break-glass"**, and say what exists and what it costs: a grant must be minted in advance, so a site that never minted one still has no route
- [ ] `ENTERPRISE.md` — break-glass in the limitations list, phrased as **four-eyes moved earlier in time, not removed**; a minted grant is a standing single-signature capability whose expiry and single use are the whole protection; ratification refuses the next activation rather than undoing the emergency one; no alerting transport is claimed
- [ ] Counts: `ENTERPRISE.md:12` (19→20 gates), `:596` (five of the nineteen→twenty), `:13` (tests), `README.md:6` (badge), `:140` (tests + per-module split), and the gate list

---

## Definition of done

- [ ] `mvn test` green; the existing four-eyes tests unchanged and still passing
- [ ] `run-break-glass-gate.sh` PASS, **every B1–B9 proved by injecting its defect**
- [ ] All eight pre-existing NCMD gates and the activation ladder gates still PASS
- [ ] `ADOPTION.md` no longer says there is no break-glass, and says what it costs

## What R4 explicitly does not fix

| | |
|---|---|
| A site that never minted a grant still has no emergency route — the deliberate cost | inherent |
| A minted grant is a standing single-signature capability until it expires | bounded, not removed |
| Ratification refuses the next activation; it does not undo the emergency one | inherent to after-the-fact control |
| No alerting transport: loud means a log line and a ledger entry, not a page | later |
| Break-glass covers **activation**, not runtime commands — a command bar has no emergency path | open |
