# R4 — Break-Glass Implementation Plan (design B: the duty key)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the four-eyes activation rule an emergency path that one person can use at two in the morning, that is **recorded as an emergency by construction rather than by the operator's honesty**, and that requires **no change to the verifier the whole activation ladder rests on**.

**Architecture:** A **duty key** — an Ed25519 keypair minted by two people, registered in `authorized-keys.jsonl` as an ordinary principal, and granted a new `BREAK_GLASS_APPROVE` action instead of `APPROVE`. The on-call person signs with their own key and the duty key. To `SignedLedgerVerifier` this is an ordinary four-eyes line: two signatures, two registered principals, two distinct keys. What makes it an emergency is **which principal approved**, and that is a policy fact the operator cannot restate.

---

## Why this design, and why not the obvious one

The first draft of this plan used a per-target, single-use **grant** that let one person activate alone. **It would have bricked the edge**, and the check is not subtle:

```java
// SignedLedgerVerifier.verifyEntries — never looks at action()
if (en.activatorSig() == null || en.approverSig() == null)   -> identity.sig.missing
if (aKey.isEmpty() || pKey.isEmpty())                        -> identity.key.unregistered
if (!verify(activatorSig) || !verify(approverSig))           -> identity.sig.invalid
if (Arrays.equals(aKey, pKey))                               -> identity.four-eyes.same-key
```

A single-key line fails one of those whatever shape it takes, the ledger is append-only, and the failure is per-entry at a fixed index — so it is **permanent**. Under `REQUIRE_SIGNED_ACTIVATION` the edge then refuses to start with `activation.edge.signed-ledger-broken`. **The emergency route would take the line down instead of restoring it.**

Teaching the verifier a one-key case was the alternative. It is the change most likely to be wrong and least likely to be noticed in a governance product, because T5, T6 and T7 all rest on that method.

And the grant design fails operationally before it fails technically: a grant is bound to `(target, kind, ref)`, so it must be minted **for the target that will fail**. An emergency is by definition the one nobody predicted. A break-glass that only covers foreseen emergencies is a change-management shortcut wearing the name.

**The duty key moves four-eyes earlier in time structurally rather than rhetorically.** Two people mint it; the verifier sees two real registered principals with two distinct keys, because that is what they are.

---

## Facts verified against the source on 2026-09-08

| Fact | Verified |
|---|---|
| The verifier ignores `action()` and demands two distinct registered keys | `SignedLedgerVerifier.java:64-82` |
| The signer holds two private key files | `KeyFileLedgerSigner.sign` returns `Signatures(activatorSig, approverSig)` from two `PrivateKey` fields |
| `preflight` binds each key file to its **registered** principal | `KeyFileLedgerSigner:42-64` — probe-sign against the registered pubkey, then require the two registered pubkeys distinct. A duty key therefore has to be genuinely registered |
| The approve leg is a policy question already | `ActivationService.java:46-49` — `authz.authorize(policy, approvedBy, APPROVE, target, kind, ref)`, deny-by-default first-match |
| `ActivationAction` is an enum | So a third action is a type change the compiler polices, not a string convention |
| `ActivationRule` matches on action + principal + target/kind/ref | `ActivationRule.matches` — a duty principal can be scoped to named targets with existing machinery |
| **Revoking a principal breaks history** | `verifyEntries` resolves `forPrincipal` for **every** entry, and `AuthorizedKeys`' own javadoc says *"revoking is deleting one"*. Deleting a key retroactively fails every past entry it signed with `identity.key.unregistered`, and the edge then will not start. **Pre-existing, and R4 makes it routine** |
| `ActivationLedger.active` ignores `action()` | `ActivationLedger.java:86-93` — last match on `(kind, ref)` wins, so a BREAK_GLASS event becomes the bound active pointer silently. The edge is not taught anything by this round |
| ASCII only in `src/main` string literals | `scripts/check-ascii-output.mjs` fails CI otherwise — no em-dashes in new messages |

### Decisions locked here

**(a) The emergency marking is derived from policy, never claimed by the operator.**
This is the load-bearing decision. If break-glass were a flag on the request, the person holding both keys could simply *not set it* and the emergency would look like an ordinary change — which is the failure mode the round exists to prevent. Instead: the duty principal is granted `BREAK_GLASS_APPROVE` and **not** `APPROVE`. The approve leg tries `APPROVE` first; if that is denied and `BREAK_GLASS_APPROVE` is allowed, the action becomes `BREAK_GLASS`. A duty key cannot produce an unmarked activation, because it has no grant that would authorize one.

**(b) No change to `SignedLedgerVerifier`, `LedgerChain`, `ActivationEvent`'s fields, or the preimage.**
The line is an ordinary four-eyes line. If this plan finds itself editing any of those four, the design has drifted and should stop.

**(c) Scope is `ActivationPolicy`'s job, not a new mechanism.**
The narrow blast radius the grant design bought is recoverable here for free: grant the duty principal `BREAK_GLASS_APPROVE` on named targets rather than `*`. That is a policy line, and `PolicyGate`-style linting can say so.

**(d) Rotation is additive. Deleting a key is the landmine.**
Retire a duty principal by removing its **policy grants**, never by deleting its `authorized-keys.jsonl` line — deletion retroactively breaks every entry it ever signed and stops the edge. This is pre-existing behaviour that R4 makes routine, so **the gate proves it** rather than the docs merely asserting it.

**(e) Loud means a log line and a distinguishable ledger action. No alerting transport is claimed.**
`[GATE] BREAK-GLASS` naming the duty principal, and `action=BREAK_GLASS` in the record. Saying "it pages someone" when nothing pages anyone is the kind of claim these rounds exist to remove.

**(f) The edge is not taught, and the docs must say so.**
`ActivationLedger.active` ignores the action, so a BREAK_GLASS event becomes the bound active version like any other and the edge prints its ordinary bind line. The loudness and the audit trail are **control-plane only**. Wiring the edge is a separate round.

---

## Chunk 1: The action

### Task 1: `BREAK_GLASS_APPROVE` and the derived action

**Files:** modify `core/.../activation/ActivationAction.java`, `ActivationService.java`, `ActivationEvent.java` (javadoc only); test `ActivationServiceTest` / a new `BreakGlassTest`.

- [x] **Step 1: Write the failing tests**

```java
    @Test void a_duty_principal_approving_yields_a_BREAK_GLASS_action() { … }
    @Test void a_duty_principal_cannot_produce_an_ordinary_ACTIVATE() { … }   // no APPROVE grant
    @Test void an_ordinary_approver_still_yields_ACTIVATE() { … }             // the regression that matters
    @Test void a_principal_with_neither_grant_is_still_denied() { … }
    @Test void the_activator_may_not_be_the_duty_principal() { … }            // duty has no ACTIVATE grant
    @Test void four_eyes_still_requires_a_distinct_approver() { … }           // approvedBy != by, unchanged
```

- [x] **Step 2: Run to verify red** — `mvn -q -pl core test -Dtest=BreakGlassTest -Dsurefire.failIfNoSpecifiedTests=false`
- [x] **Step 3: Implement**

`ActivationAction` gains `BREAK_GLASS_APPROVE`. In `ActivationService`, replace the approve leg:

```java
                AuthzDecision app = authz.authorize(p, r.approvedBy(), ActivationAction.APPROVE, …);
                boolean breakGlass = false;
                if (!app.allowed()) {
                    // Derived, never claimed. A duty principal is granted BREAK_GLASS_APPROVE and NOT
                    // APPROVE, so it cannot produce an unmarked activation - which is the failure this
                    // whole round exists to prevent, and a request flag could not have prevented it.
                    AuthzDecision bg = authz.authorize(p, r.approvedBy(),
                            ActivationAction.BREAK_GLASS_APPROVE, …);
                    if (!bg.allowed()) {
                        return refuse("activation.authz.denied", …);   // unchanged wording
                    }
                    breakGlass = true;
                    System.err.println("[GATE] BREAK-GLASS approver=" + r.approvedBy()
                            + " target=" + r.target() + "/" + r.kind() + "/" + r.ref());
                }
```

and the action becomes `breakGlass ? "BREAK_GLASS" : (r.rollback() ? "ROLLBACK" : "ACTIVATE")`.

**Note the ordering:** `APPROVE` is tried first, so an ordinary approver's path is byte-for-byte what it was and the existing tests are untouched. A rollback approved by a duty key is `BREAK_GLASS`, not `ROLLBACK` — the emergency fact outranks the direction, and the record still carries `priorVersion`.

- [x] **Step 4: green · Step 5:** `mvn -q test` · **Step 6: commit**

### Task 2: `ActivationPolicy` lint — a duty principal must not hold both

**Files:** wherever activation policies are linted (mirror `PolicyGate`'s `[lint-N]` idiom); test.

A principal granted **both** `APPROVE` and `BREAK_GLASS_APPROVE` on the same resource silently defeats decision (a): it could approve normally and never be marked. That is one JSON line away and nothing would catch it.

- [x] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

---

## Chunk 2: Minting and evidence

### Task 3: `gates activation duty-key-mint`

**Files:** extend `ActivateGate`; wire into `GatesCli`. **The usage string appears in `GatesCli:15`, its switch, `ActivateGate`'s switch, `ActivateGate`'s usage and the class javadoc — five places, not two.**

`duty-key-mint <reg> <principal> --out <dir> --by <p> --by-key <f> --approved-by <p> --approved-by-key <f>`:

1. `preflight` both minter keys through `KeyFileLedgerSigner`'s existing discipline — registered, bound, distinct
2. generate the duty keypair, write `<principal>.key`/`.pub`, print the `authorized-keys.jsonl` line
3. print the policy lines the operator must add, and **say plainly that the mint is not itself recorded in the ledger** — the four-eyes here is enforced by requiring two registered keys, not by an audit entry

- [x] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

### Task 4: `run-break-glass-gate.sh`

House idiom: `cygpath`, `fail`, staged registry, fresh dirs, count-based assertions.

| | Asserts |
|---|---|
| **B1** | Minting a duty key with **one key file used twice** is refused — four-eyes at mint is real |
| **B2** | An ordinary two-person activation still yields `action=ACTIVATE` (the regression that matters) |
| **B3** | One person signing with their own key **plus the duty key** activates, and the entry reads `action=BREAK_GLASS` with the duty principal as approver |
| **B4** | It is loud: a `BREAK-GLASS` line naming the duty principal and target |
| **B5** | **The ledger still verifies at every tier** — `activation verify-chain`, `identity verify-signed` and `verify-anchored`. This is the assertion the first design would have failed |
| **B6** | **The edge still boots after a break-glass activation** with `REQUIRE_SIGNED_ACTIVATION=on`, then again with `REQUIRE_ANCHORED_ACTIVATION=on`. The emergency must restore the line, not take it down |
| **B7** | The duty principal **cannot** perform an ordinary activation: used as approver where it holds no `BREAK_GLASS_APPROVE` grant for that target, it is denied |
| **B8** | Scope holds: a duty key granted on target A cannot approve on target B |
| **B9** | **Deleting the duty key's line from `authorized-keys.jsonl` breaks the whole ledger** with `identity.key.unregistered` and the edge refuses to start — the landmine, proved rather than asserted, so nobody retires a key that way |

- [x] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: commit**

---

## Chunk 3: Documents

### Task 5

- [x] `ADOPTION.md:165` — **remove "There is still no break-glass"**; say what exists, and that retiring a duty key means removing its policy grants and **never** deleting its key line
- [x] `ENTERPRISE.md` limitations — four-eyes **moved earlier in time, not removed**; a duty key is a standing credential until its grants are removed, so sealing, custody and rotation are the whole protection; the marking is derived from policy so it cannot be omitted, but **the edge is not taught** — loudness and the trail are control-plane only; no alerting transport
- [x] **Add the revocation landmine to the limitations**: deleting any principal's key retroactively breaks the ledger and stops the edge. Pre-existing, now routine, and B9 proves it
- [x] Counts: `ENTERPRISE.md:12` (19→20 gates), the "five of the nineteen" sentence (**it is at `:610`, not `:596`, and the new gate is broker-free so it becomes "six of the twenty"**), `:13` tests; `README.md:6` badge, `:141` per-module split, and the gate list at `:107-125`
- [x] **`.github/workflows/ci.yml:40-52` runs exactly the broker-free gates** — a broker-free twentieth gate that is not added there is not run by CI, which would contradict the sentence written in the same commit

---

## Definition of done

- [x] `mvn test` green; the existing four-eyes and authz tests unchanged and passing
- [x] `run-break-glass-gate.sh` PASS, **every B1–B9 proved by injecting its defect**
- [x] **B5 and B6 pass** — the ledger verifies at all three tiers and the edge boots after a break-glass. These are the two the first design would have failed
- [x] Every activation-ladder gate still PASS: activation, lineage, identity, activation-authz, anchored, federation
- [x] `SignedLedgerVerifier`, `LedgerChain`, `ActivationEvent`'s field list and the preimage are **untouched** — if any changed, decision (b) was violated
- [x] The new gate is in CI

## What R4 explicitly does not fix

| | |
|---|---|
| A duty key is a standing credential until its grants are removed — sealing, custody and rotation are the whole protection | inherent to any break-glass |
| **Deleting a key line retroactively breaks the ledger and stops the edge.** Retire by policy, never by deletion | pre-existing; B9 proves it |
| ~~The edge is not taught~~ | **had to be fixed.** `assertActivationAuthorized` asked only for `APPROVE`, so with `REQUIRE_SIGNED_ACTIVATION=on` the edge fail-closed on exactly the entry an emergency writes — permanently, the ledger being append-only. The approver leg now falls back to `BREAK_GLASS_APPROVE` and announces it. `ActivationLedger.active` still ignores the action, which is fine: the bind is legitimate |
| No alerting transport — loud is a log line and a ledger action | later |
| The mint is not recorded in the ledger; its four-eyes is enforced by requiring two registered keys | later |
| Break-glass covers **activation**, not runtime commands | open |
