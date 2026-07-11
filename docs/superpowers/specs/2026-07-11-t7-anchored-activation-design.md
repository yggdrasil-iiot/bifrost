# T7 — Anchored Activation (dual-signed / external-anchor head)

**Status:** design approved (Eisen, 2026-07-11) — ready for implementation planning
**Track:** Yggdrasil governance-spine, follow-on to T5 (signed activation) / T6 (activation authZ)
**Predecessors:** T4 hash-chain, T5 dual-signed entries + signed head, T6 maker-checker authZ

---

## 1. Problem — the two gaps T5's singly-signed head leaves open

T5 anchors the activation ledger's tail with a **single** `SignedHead`
(`registry/identity/<target>.head`): fields `(target, seq, tailEntryHash)` signed by **one**
approver key. `SignedLedgerVerifier` checks tail-match, `seq == size-1`, and that one signature
against any registered key. Two attacks survive this:

1. **Lone-insider truncation re-anchor.** One registered key holder truncates the ledger to a
   shorter tail, then writes a fresh head at the lower `seq` signed by their *own* key. The
   verifier passes — the head is internally consistent and the signer is registered. The per-entry
   dual signatures do not help: the attack *drops* validly-signed entries, it never forges one.

2. **Ledger + head simultaneous co-rollback.** An insider restores *both* files to an earlier,
   genuinely-dual-signed snapshot (e.g. to re-activate a superseded spec version). Both files are
   internally consistent and validly signed; nothing local remembers that `seq` was ever higher.

These were named as honest residuals in the T5 spec §9.

## 2. Thesis — a layered fix

Two complementary mechanisms, both **backward-compatible and default-OFF**:

- **Four-eyes head** — an infra-free, purely-local cryptographic invariant. The head is co-signed
  by two distinct registered principals, so a lone key holder can no longer re-anchor. Works
  offline. Closes #1. Does **not** close #2 (a genuinely two-signed old snapshot still verifies).

- **External monotonic anchor** — an append-only witness of the highest `seq` ever reached, living
  behind an `AnchorStore` seam with a **git** reference adapter. A truncation or a co-rollback both
  *lower* `seq` below the witness's record → detected. Closes **both** #1 and #2, but shifts the
  root of trust to the anchor store's off-box protection (Section 5).

Layered, they give: a local invariant that holds even offline (four-eyes head) **plus** the actual
monotonicity witness (anchor).

This adds a **third trust tier** to the existing ladder — every tier opt-in, default-OFF:

```
structural (T4)  →  signed (T5)        →  anchored (T7)
 hash chain          + dual-sig entries    + four-eyes head
                     + signed head         + monotonic external anchor
```

## 3. Components

All new core types are pure JDK (no new Maven dependency), in `core.identity` / `core.activation`.

### 3.1 Anchor seam (ports & adapters — mirrors T1's standard-agnostic core)

- **`AnchorRecord(target, seq, tailEntryHash)`** — the minimal monotonic-witness datum.
- **`AnchorStore`** interface:
  - `Optional<AnchorRecord> latest(String target) throws IOException`
  - `void record(AnchorRecord r) throws IOException`
  - Contract: append-only, **strictly seq-increasing** — `record` throws if `r.seq() <= latest.seq()`.
- **`FileAnchorStore`** — append-only JSONL at `registry/anchor/<target>.anchor.jsonl`, `latest` =
  last line. Pure JDK, offline-testable. **Explicitly a test/offline convenience, not a real
  witness on its own** (Section 5) — it is the *local projection* of the off-box witness.
- **`GitAnchorStore`** — decorator (or standalone) that also `git add`/`git commit`s each record
  into a **dedicated anchor repo** and reads `latest` from the committed HEAD. Opt-in via
  `ProcessBuilder` (JDK only, no new Maven dep); instantiated **only** at the gate/Heimdall wiring
  layer, never on core's default path.

### 3.2 Four-eyes head

`SignedHead` gains a **nullable** second signer/sig pair (keeps old single-sig heads parseable):

```
SignedHead(target, seq, tailEntryHash, signedBy, sig, coSignedBy, coSig)
```

- Both signatures cover the **same existing preimage** `target ␟ seq ␟ tailEntryHash`
  (`SignedHeadStore.preimage`, unchanged).
- The two signers are the tail event's **activator + approver** — reusing the dual identity that
  already signs the entry, so **no new key material**. Convention: `signedBy` = approver (as today,
  backward-compat), `coSignedBy` = activator.
- New writes are **always** dual-head. `signed` (T5) mode ignores the co-pair; `anchored` (T7) mode
  requires it present, valid, and key-distinct.

### 3.3 Signing seam change

`LedgerSigner.signHead(String preimage)` returns `String` today → change to
**`HeadSignatures signHead(String preimage)`** where `HeadSignatures(approverSig, activatorSig)`
carries both signatures over the one preimage. `KeyFileLedgerSigner` signs the preimage with both
key files (it already holds both). Internal, breaking-but-contained interface change.

## 4. Data flow

### 4.1 Write (`ActivationLedger.append(e, signer)`, anchored wiring)

Order: **ledger line → dual-sig head → `anchorStore.record(...)`**. Each step is the catch-up
witness for the prior one; a crash between head-write and anchor-record leaves the **anchor one
behind**, caught fail-closed at verify (`identity.anchor.behind`) — same discipline as T5's
head-one-behind. `ActivationLedger` gains a **nullable** `AnchorStore` (null = exact T5 behavior).

### 4.2 Verify (`SignedLedgerVerifier`, `anchored` level)

A `TrustLevel { STRUCTURAL, SIGNED, ANCHORED }` parameter (minimal-churn wiring) selects depth.
`ANCHORED` runs all T5 checks, then:

**Head four-eyes:**
- co-sig absent → `identity.head.four-eyes.missing`
- co-sig invalid vs `coSignedBy`'s registered key → `identity.head.four-eyes.invalid`
- the two head keys are the same → `identity.head.four-eyes.same-key`

**Anchor cross-check** against `AnchorStore.latest(target)`:
- absent while ledger non-empty → `identity.anchor.missing`
- `head.seq <  latest.seq` → **`identity.anchor.rollback`** — catches truncation-reanchor #1 and co-rollback #2
- `head.seq == latest.seq` but `tailEntryHash != latest.tailEntryHash` → `identity.anchor.tail-mismatch` (forked history at same seq)
- `head.seq >  latest.seq` → `identity.anchor.behind` (crash window; fail-closed until an operator re-anchors)

All fail-closed; every fault is a distinct coded string in the existing `identity.*` vocabulary.

## 5. The git-witness trust model (the honest core)

**Why FileAnchorStore alone is insufficient.** If the anchor is a local file, the insider who rolls
back ledger+head can roll back the anchor file too — a local append-only file cannot defend the
memory of "seq was already 10" against a rollback that includes it. **The anchor's power comes only
from a store outside the insider's unilateral write control.**

**How GitAnchorStore realizes the witness.** Each record is committed to a separate anchor repo;
`latest` reads the highest seq from **committed git history**. The threat model is stated plainly:

> **Assumption:** the attacker can write the registry working tree (ledger, head, FileAnchorStore
> files) but **cannot rewrite the anchor repo's protected history.**

Under it: #1 lowers `head.seq` but the committed anchor's max seq is unchanged → `anchor.rollback`;
#2 restores ledger+head+local-anchor to an old snapshot but the anchor repo's commits are not
rewritten → still witnesses the higher seq → caught.

**Gate demonstration.** The anchor repo is a **physically separate directory**; the attack script
mutates only the registry, never the anchor repo (the threat model verbatim) — so #2 is caught
offline, deterministically.

**Residual, out of code.** Real protection requires the anchor repo to be a *protected remote
branch / signed tag / TPM counter* — branch protection and commit-signature verification are
**operations configuration, out of T7's code scope**. `FileAnchorStore` is documented as the local
projection of that off-box witness; `GitAnchorStore` stands in for it in the lab.

## 6. Backward-compat posture & Heimdall edge

- **`REQUIRE_ANCHORED_ACTIVATION`** (Heimdall, **default OFF**) — ON ⇒ all signed checks +
  four-eyes head + anchor cross-check. Log line `[BRIDGE] activation trust=structural|signed|anchored`.
  Anchor store wired from config: `ANCHOR_STORE=file|git`, `ANCHOR_DIR=...`.
- **Edge re-check (extends T6).** T6's edge authZ re-check is already fail-closed; `anchored` mode
  adds the anchor cross-check before binding — a rolled-back registry is denied at bind with audit
  line `activation.edge.anchor-rollback`.
- **No regression.** Default-OFF ⇒ the 4 no-regression gates + all tests pass unchanged. Even though
  new writes are always dual-head, `signed` mode ignores the co-pair so T5 `verify-signed` still
  passes.

## 7. Testing

### 7.1 Gate — `run-anchored-activation-gate.sh` (controller-run, never trust subagent PASS)

- **AN1** happy path: dual-head + anchor recorded → `verify-anchored` PASS
- **AN2** lone-insider truncation re-anchor: truncate ledger + single-key head re-sign → FAIL
  (`identity.head.four-eyes.*` blocks it first + `identity.anchor.rollback`)
- **AN3** co-rollback (#2 core demo): restore ledger+head to an old dual-signed snapshot, anchor
  repo untouched → `identity.anchor.rollback`
- **AN4** anchor file also tampered: attacker lowers the local FileAnchorStore file too →
  GitAnchorStore reads committed history → still caught (git-witness property)
- **AN5** four-eyes head same key: both head sigs the same principal → `identity.head.four-eyes.same-key`
- **AN6** crash window: anchor behind head → `identity.anchor.behind` fail-closed
- **AN7** Heimdall edge: `REQUIRE_ANCHORED` ON + rolled-back registry → bind denied `activation.edge.anchor-rollback`
- **No-regression:** `run-activation-gate` (A1–A5), `run-lineage-gate` (LN1–LN4),
  `run-identity-gate` (I1–I7), `run-activation-authz-gate` (AZ1–AZ7), `run-template-conformance`,
  `run-yggdrasil-full-loop` all green.

### 7.2 Unit tests

- `AnchorStore` / `FileAnchorStore` — monotonicity, append-only, reject seq regression
- `GitAnchorStore` — commit on record, `latest` reads committed HEAD, survives a working-tree revert
- `SignedLedgerVerifier` (anchored) — each of the 6 fault codes + the whole-ledger pass
- `SignedHead` dual-pair serde round-trip; single-sig legacy head still parses

## 8. Honest residuals (spec §)

1. **Both keys compromised.** If an insider steals *both* activator+approver keys, four-eyes head is
   defeated — the anchor's monotonicity still catches the rollback.
2. **Anchor protection compromised.** If the attacker also rewrites the anchor repo's protected
   history, detection fails. The ultimate root of trust is the anchor store's off-box protection
   (protected remote / signed tag / TPM) — operations config, out of code.
3. **FileAnchorStore is not a real witness alone** — it is the local projection; GitAnchorStore
   committed to a protected remote is what makes it real.

## 9. YAGNI — deliberately cut

- Notary / RFC-3161 TSA adapter (network dep, not offline-gate-friendly).
- Generalized N-signer head list (fixed at activator+approver dual).
- Self-signing the anchor record (the git commit provides integrity/attribution; the head already
  carries the seq→tail binding signature).

## 10. Threat-coverage summary

| Attack                                   | Four-eyes head | External anchor | Covered |
|------------------------------------------|:--------------:|:---------------:|:-------:|
| #1 lone-insider truncation re-anchor     | ✅ (blocks re-sign) | ✅ (seq lowered) | ✅ |
| #2 ledger+head co-rollback               | ❌             | ✅ (git witness) | ✅ |
| both keys stolen + rollback              | ❌             | ✅ (seq lowered) | ✅ |
| anchor protected-history rewritten       | ❌             | ❌              | ❌ (residual §8.2) |
