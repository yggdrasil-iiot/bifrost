# T7 — Anchored Activation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close T5's two singly-signed-head residuals — lone-insider truncation re-anchor (#1) and ledger+head co-rollback (#2) — with a layered fix: a four-eyes head plus a monotonic external anchor behind an `AnchorStore` seam with a git reference adapter.

**Architecture:** A third opt-in trust tier `anchored` above `structural`(T4)/`signed`(T5), default-OFF everywhere. Four-eyes head = the head is co-signed by two distinct registered keys (activator + approver over the same preimage). External anchor = an append-only, monotonic witness of the highest `seq`, read at verify time; `FileAnchorStore` (pure JDK) for offline/tests, `GitAnchorStore` (opt-in `ProcessBuilder`) for the real committed-history witness. `SignedLedgerVerifier` gains a reordered `ANCHORED` path so a fully-emptied ledger is still caught.

**Tech Stack:** Java 17, Maven multi-module (core / gates / heimdall / sim), JDK `java.security` Ed25519 (no new dep), Jackson for JSONL serde, bash gate scripts.

**Spec:** `docs/superpowers/specs/2026-07-11-t7-anchored-activation-design.md` (read it before starting — §3 components, §4 data flow, §5 git-witness trust model, §7 test matrix).

**Global conventions (match existing code):**
- Fault codes are `identity.*` slugs returned via `SignedVerdict.broken(index, rule)`; head-level faults use index `-1`.
- Backward-compat: every new check is gated by `TrustLevel.ANCHORED`; `SIGNED`/`STRUCTURAL` behavior is byte-for-byte unchanged. New writes are always dual-head (old single-sig heads still parse; `signed` mode ignores the co-pair).
- Registries are gate-regenerated — no on-disk migration.
- Run `mvn -q install` from repo root; module tests via `mvn -q -pl core test` etc. **The controller runs every gate/build personally — never trust a subagent's PASS.**

---

## Chunk 1: Anchor seam + FileAnchorStore (core)

**New unit responsibilities:**
- `AnchorRecord` — immutable `(target, seq, tailEntryHash)` witness datum.
- `AnchorStore` — the port: `latest` + `record`, append-only monotonic contract.
- `FileAnchorStore` — pure-JDK adapter at `registry/anchor/<target>.anchor.jsonl`.

### Task 1.1: AnchorRecord value type

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/activation/AnchorRecord.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/activation/AnchorStoreTest.java` (shared with 1.3)

- [ ] **Step 1: Write the record**

```java
package dev.krillin.bifrost.core.activation;

/** The minimal external-anchor witness datum: the highest ledger seq reached for a target and the
 *  entryHash it anchored. Persisted as one JSON line per record by an {@link AnchorStore}. */
public record AnchorRecord(String target, long seq, String tailEntryHash) {}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/AnchorRecord.java
git commit -m "feat(core): AnchorRecord — external-anchor witness datum (target, seq, tailEntryHash)"
```

### Task 1.2: AnchorStore port

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/activation/AnchorStore.java`

- [ ] **Step 1: Write the interface**

```java
package dev.krillin.bifrost.core.activation;

import java.io.IOException;
import java.util.Optional;

/** The monotonic external-anchor witness port (ports & adapters — the core stays anchor-agnostic,
 *  mirroring T1's standard-agnostic core). Contract:
 *   - append-only, monotonic NON-DECREASING: record(r) throws on r.seq() < latest.seq() (regression)
 *     and on a same-seq / different-tail conflict; a byte-identical same-(seq,tailEntryHash) record is
 *     an idempotent no-op (safe crash-retry re-anchor).
 *   - latest(target) returns the highest recorded record, or empty if the target was never anchored. */
public interface AnchorStore {
    Optional<AnchorRecord> latest(String target) throws IOException;
    void record(AnchorRecord r) throws IOException;
}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/AnchorStore.java
git commit -m "feat(core): AnchorStore port — monotonic append-only anchor witness contract"
```

### Task 1.3: FileAnchorStore adapter (TDD)

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/activation/FileAnchorStore.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/activation/AnchorStoreTest.java`

- [ ] **Step 1: Write the failing tests**

```java
package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class AnchorStoreTest {
    @TempDir Path reg;
    private FileAnchorStore store;

    @BeforeEach void setup() { store = new FileAnchorStore(reg); }

    @Test void latestEmptyWhenNeverAnchored() throws IOException {
        assertTrue(store.latest("mixer-01").isEmpty());
    }

    @Test void recordThenLatestRoundTrips() throws IOException {
        store.record(new AnchorRecord("mixer-01", 0, "h0"));
        store.record(new AnchorRecord("mixer-01", 1, "h1"));
        Optional<AnchorRecord> l = store.latest("mixer-01");
        assertTrue(l.isPresent());
        assertEquals(1, l.get().seq());
        assertEquals("h1", l.get().tailEntryHash());
    }

    @Test void perTargetIsolation() throws IOException {
        store.record(new AnchorRecord("mixer-01", 0, "h0"));
        assertTrue(store.latest("mixer-02").isEmpty());
    }

    @Test void seqRegressionThrows() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        assertThrows(IllegalStateException.class,
                () -> store.record(new AnchorRecord("mixer-01", 4, "h4")));
    }

    @Test void sameSeqDifferentTailThrows() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        assertThrows(IllegalStateException.class,
                () -> store.record(new AnchorRecord("mixer-01", 5, "hDIFFERENT")));
    }

    @Test void identicalReRecordIsIdempotentNoop() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        store.record(new AnchorRecord("mixer-01", 5, "h5"));   // no throw
        // still exactly one logical latest; file must not have grown a conflicting tail
        assertEquals(5, store.latest("mixer-01").orElseThrow().seq());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=AnchorStoreTest`
Expected: FAIL — `FileAnchorStore` does not exist (compile error).

- [ ] **Step 3: Implement FileAnchorStore**

```java
package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;

/** Pure-JDK append-only anchor witness at registry/anchor/<target>.anchor.jsonl, one AnchorRecord per
 *  line, latest = last line. This is the LOCAL PROJECTION of the off-box witness — on its own it does
 *  NOT defend against a co-rollback that also rolls back this file (see spec §5). The real witness is
 *  GitAnchorStore committed to a protected remote. Single control-plane writer (no concurrency). */
public final class FileAnchorStore implements AnchorStore {
    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public FileAnchorStore(Path registryRoot) { this.root = registryRoot; }

    private Path file(String target) { return root.resolve("anchor").resolve(target + ".anchor.jsonl"); }

    @Override public Optional<AnchorRecord> latest(String target) throws IOException {
        Path f = file(target);
        if (!Files.isRegularFile(f)) return Optional.empty();
        AnchorRecord last = null;
        for (String line : Files.readAllLines(f))
            if (!line.isBlank()) last = mapper.readValue(line, AnchorRecord.class);
        return Optional.ofNullable(last);
    }

    @Override public void record(AnchorRecord r) throws IOException {
        Optional<AnchorRecord> cur = latest(r.target());
        if (cur.isPresent()) {
            AnchorRecord l = cur.get();
            if (r.seq() == l.seq()) {
                if (!r.tailEntryHash().equals(l.tailEntryHash()))
                    throw new IllegalStateException("anchor.same-seq-conflict: target=" + r.target()
                            + " seq=" + r.seq() + " tail " + r.tailEntryHash() + " != " + l.tailEntryHash());
                return;   // idempotent no-op
            }
            if (r.seq() < l.seq())
                throw new IllegalStateException("anchor.seq-regression: target=" + r.target()
                        + " new seq=" + r.seq() + " < latest seq=" + l.seq());
        }
        Path f = file(r.target());
        Files.createDirectories(f.getParent());
        Files.writeString(f, mapper.writeValueAsString(r) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `mvn -q -pl core test -Dtest=AnchorStoreTest`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/FileAnchorStore.java \
        core/src/test/java/dev/krillin/bifrost/core/activation/AnchorStoreTest.java
git commit -m "feat(core): FileAnchorStore — monotonic append-only anchor adapter (idempotent re-record, regression fail-closed)"
```

---

## Chunk 2: Four-eyes head + dual-head write + anchor wiring (core)

**Unit responsibilities:**
- `HeadSignatures` — the two head sigs over one preimage.
- `SignedHead` — gains nullable `coSignedBy` / `coSig`.
- `LedgerSigner.signHead` — returns `HeadSignatures`.
- `KeyFileLedgerSigner` — signs the head preimage with both keys.
- `ActivationLedger` — writes a dual-head and records the anchor (nullable `AnchorStore`).

### Task 2.1: HeadSignatures value type

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/activation/HeadSignatures.java`

- [ ] **Step 1: Write it**

```java
package dev.krillin.bifrost.core.activation;

/** The two Ed25519 signatures over a SignedHead's preimage (base64). approverSig is the historical
 *  single-head signature (SignedHead.sig / signedBy=approver); activatorSig is the four-eyes co-sig
 *  (SignedHead.coSig / coSignedBy=activator). Both cover the identical preimage. */
public record HeadSignatures(String approverSig, String activatorSig) {}
```

- [ ] **Step 2: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/HeadSignatures.java
git commit -m "feat(core): HeadSignatures — dual head signatures over one preimage"
```

### Task 2.2: SignedHead gains the nullable co-pair

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/SignedHead.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/SignedHeadStoreTest.java` (add cases)

- [ ] **Step 1: Add the failing serde tests** (append to `SignedHeadStoreTest`)

```java
    @Test void dualHeadRoundTrips() throws Exception {
        SignedHeadStore s = new SignedHeadStore(reg);
        s.write(new SignedHead("mixer-01", 3, "hTail", "boss", "sigA", "eng", "sigB"));
        SignedHead h = s.read("mixer-01").orElseThrow();
        assertEquals("eng", h.coSignedBy());
        assertEquals("sigB", h.coSig());
    }

    @Test void legacySingleSigHeadStillParses() throws Exception {
        // a T5-era head line with no co-pair must deserialize with null co-fields
        Path f = reg.resolve("identity").resolve("mixer-legacy.head");
        Files.createDirectories(f.getParent());
        Files.writeString(f, "{\"target\":\"mixer-legacy\",\"seq\":0,\"tailEntryHash\":\"h\",\"signedBy\":\"boss\",\"sig\":\"s\"}\n");
        SignedHead h = new SignedHeadStore(reg).read("mixer-legacy").orElseThrow();
        assertNull(h.coSignedBy());
        assertNull(h.coSig());
    }
```
(Ensure `reg` `@TempDir` and needed imports — `java.nio.file.*`, `Files`, `assertNull` — exist in the test class.)

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=SignedHeadStoreTest`
Expected: FAIL — `SignedHead` has no `coSignedBy()` accessor (compile error).

- [ ] **Step 3: Extend the record** (with `@JsonInclude(NON_NULL)` so legacy lines stay byte-identical)

```java
package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The signed anchor for a target's ledger tail. seq is monotonic per target and MUST equal
 *  (entryCount - 1) at verify time. sig is the approver's Ed25519 signature over
 *  {@link SignedHeadStore#preimage}; coSig is the four-eyes co-signature by a SECOND distinct
 *  registered principal (coSignedBy) over the SAME preimage (T7). coSignedBy/coSig are nullable so
 *  T5-era single-sig heads still parse; T7 `anchored` verification requires them. Persisted as one
 *  JSON line at registry/identity/<target>.head. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SignedHead(String target, long seq, String tailEntryHash,
                         String signedBy, String sig, String coSignedBy, String coSig) {
    /** T5-compatible single-sig head (co-pair null). */
    public SignedHead(String target, long seq, String tailEntryHash, String signedBy, String sig) {
        this(target, seq, tailEntryHash, signedBy, sig, null, null);
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `mvn -q -pl core test -Dtest=SignedHeadStoreTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/identity/SignedHead.java \
        core/src/test/java/dev/krillin/bifrost/core/identity/SignedHeadStoreTest.java
git commit -m "feat(core): SignedHead nullable four-eyes co-pair (coSignedBy/coSig), legacy single-sig still parses"
```

### Task 2.3: LedgerSigner.signHead returns HeadSignatures

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/activation/LedgerSigner.java`
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSigner.java:70-72`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSignerTest.java` (add a case)

- [ ] **Step 1: Add a failing test** — the head is signed by BOTH keys over the preimage

```java
    @Test void signHeadProducesBothSignaturesOverPreimage() {
        // build a signer from two registered keypairs (reuse this test's existing fixture helpers)
        HeadSignatures hs = signer.signHead("mixer-010hTail");
        assertNotNull(hs.approverSig());
        assertNotNull(hs.activatorSig());
        assertNotEquals(hs.approverSig(), hs.activatorSig());  // two distinct keys => two distinct sigs
    }
```
(Reuse whatever `signer` fixture `KeyFileLedgerSignerTest` already constructs; import `dev.krillin.bifrost.core.activation.HeadSignatures`.)

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=KeyFileLedgerSignerTest`
Expected: FAIL — `signHead` returns `String`, not `HeadSignatures`.

- [ ] **Step 3: Change the interface** (`LedgerSigner.java`) — replace the `signHead` line:

```java
    /** Both head signatures over the head preimage: approverSig (signedBy) + activatorSig (coSignedBy). */
    HeadSignatures signHead(String headPreimage);
```
(Add `import` is unneeded — same package. Update the javadoc line above accordingly.)

- [ ] **Step 4: Change the impl** (`KeyFileLedgerSigner.java:70-72`):

```java
    @Override public HeadSignatures signHead(String headPreimage) {
        byte[] msg = headPreimage.getBytes(StandardCharsets.UTF_8);
        return new HeadSignatures(Ed25519Keys.sign(msg, approverKey), Ed25519Keys.sign(msg, activatorKey));
    }
```
(Add `import dev.krillin.bifrost.core.activation.HeadSignatures;`.)

- [ ] **Step 5: Run to verify pass**

Run: `mvn -q -pl core test -Dtest=KeyFileLedgerSignerTest`
Expected: PASS. (`ActivationLedger` will not compile yet — fixed in 2.4; run the full module build only after 2.4.)

- [ ] **Step 6: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/LedgerSigner.java \
        core/src/main/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSigner.java \
        core/src/test/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSignerTest.java
git commit -m "feat(core): LedgerSigner.signHead returns HeadSignatures (dual head sign in KeyFileLedgerSigner)"
```

### Task 2.4: ActivationLedger writes a dual-head + records the anchor

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/activation/ActivationLedger.java` (constructor, `advanceHead`)
- Test: `core/src/test/java/dev/krillin/bifrost/core/activation/ActivationLedgerSignedTest.java` (add cases)

- [ ] **Step 1: Add failing tests** — a signed append writes a dual-head AND (when an AnchorStore is wired) records the anchor at the head's seq/tail.

```java
    @Test void signedAppendWritesDualHead() throws Exception {
        // reuse this class's existing signer fixture + registry TempDir `reg`
        ActivationLedger led = new ActivationLedger(reg);
        led.append(event("mixer-01", "recipe", "R1", "v1"), signer);
        SignedHead h = new SignedHeadStore(reg).read("mixer-01").orElseThrow();
        assertNotNull(h.sig());
        assertNotNull(h.coSig());
        assertNotEquals(h.signedBy(), h.coSignedBy());
    }

    @Test void signedAppendWithAnchorStoreRecordsAnchor() throws Exception {
        FileAnchorStore anchor = new FileAnchorStore(reg);
        ActivationLedger led = new ActivationLedger(reg, anchor);
        led.append(event("mixer-01", "recipe", "R1", "v1"), signer);
        AnchorRecord a = anchor.latest("mixer-01").orElseThrow();
        assertEquals(0, a.seq());
        SignedHead h = new SignedHeadStore(reg).read("mixer-01").orElseThrow();
        assertEquals(h.tailEntryHash(), a.tailEntryHash());
    }
```
(Use the class's existing `event(...)`/`signer` helpers; import `FileAnchorStore`, `AnchorRecord`, `SignedHeadStore`, `SignedHead`.)

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=ActivationLedgerSignedTest`
Expected: FAIL — no `ActivationLedger(Path, AnchorStore)` ctor; head has no co-sig.

- [ ] **Step 3: Modify ActivationLedger**

Add a nullable `AnchorStore` field + a second constructor (keep the existing one delegating with `null`):

```java
    private final AnchorStore anchors;
    public ActivationLedger(Path registryRoot) { this(registryRoot, null); }
    public ActivationLedger(Path registryRoot, AnchorStore anchors) {
        this.root = registryRoot;
        this.heads = new dev.krillin.bifrost.core.identity.SignedHeadStore(registryRoot);
        this.anchors = anchors;
    }
```

Rewrite `advanceHead` to write a dual-head from `HeadSignatures`, then record the anchor (order: head already written after the ledger line in `append`; anchor is recorded last):

```java
    private void advanceHead(String target, String tailEntryHash, LedgerSigner signer) throws IOException {
        long seq = heads.read(target).map(h -> h.seq() + 1).orElse(0L);
        String preimage = dev.krillin.bifrost.core.identity.SignedHeadStore.preimage(target, seq, tailEntryHash);
        HeadSignatures hs = signer.signHead(preimage);
        heads.write(new dev.krillin.bifrost.core.identity.SignedHead(
                target, seq, tailEntryHash, signer.approverPrincipal(), hs.approverSig(),
                signer.activatorPrincipal(), hs.activatorSig()));
        if (anchors != null) anchors.record(new AnchorRecord(target, seq, tailEntryHash));  // last = the catch-up witness
    }
```
(Update the class javadoc write-order note to "ledger line → dual head → anchor".)

- [ ] **Step 4: Run module build + tests**

Run: `mvn -q -pl core test`
Expected: PASS — all core tests including the two new ones. (This is the first full-core compile after the 2.3 interface change; fix any stray `signHead`/head-construction call sites the compiler flags.)

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/activation/ActivationLedger.java \
        core/src/test/java/dev/krillin/bifrost/core/activation/ActivationLedgerSignedTest.java
git commit -m "feat(core): ActivationLedger writes a four-eyes dual-head and records the anchor (nullable AnchorStore=exact T5 behavior)"
```

---

## Chunk 3: Anchored verification (core)

**Unit responsibilities:**
- `TrustLevel` — STRUCTURAL / SIGNED / ANCHORED depth selector.
- `SignedLedgerVerifier` — a reordered `verify(target, level, anchorStore)` path adding four-eyes-head + anchor cross-check, with the empty-ledger rollback caught independently of the head-existence branch.

### Task 3.1: TrustLevel enum

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/identity/TrustLevel.java`

- [ ] **Step 1: Write it**

```java
package dev.krillin.bifrost.core.identity;

/** Activation-ledger trust depth. STRUCTURAL = T4 hash chain; SIGNED = T5 dual-sig entries + signed
 *  head; ANCHORED = T7 four-eyes head + monotonic external anchor cross-check. Each tier is opt-in. */
public enum TrustLevel { STRUCTURAL, SIGNED, ANCHORED }
```

- [ ] **Step 2: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/identity/TrustLevel.java
git commit -m "feat(core): TrustLevel enum (STRUCTURAL/SIGNED/ANCHORED)"
```

### Task 3.2: SignedLedgerVerifier anchored path (TDD — the security core)

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifier.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifierAnchoredTest.java` (new)

**Design of the new API (minimal churn):**
- Keep `verify(target)` = today's `SIGNED`-mode behavior (unchanged; delegates to `verifySigned`).
- Add `verify(String target, TrustLevel level, AnchorStore anchors)`:
  - `STRUCTURAL` → `LedgerChain.verify` only (wrap into a SignedVerdict).
  - `SIGNED` → existing logic verbatim.
  - `ANCHORED` → structure + per-entry sigs (reuse the T5 helper), then **the anchor cross-check FIRST** (so empty+no-head is caught), then head four-eyes when a head exists.
- The `ANCHORED` path MUST NOT be `verifySigned()` + extras — see spec §4.2 implementation note (T5 returns `whole()` for empty+no-head).

- [ ] **Step 1: Write the failing tests** — one per fault code + the happy path. Build helper fixtures that produce a valid dual-head anchored ledger, then mutate to trigger each fault.

```java
package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class SignedLedgerVerifierAnchoredTest {
    @TempDir Path reg;
    // Helpers: seedTwoRegisteredKeys(reg) -> KeyFileLedgerSigner; appendAnchored(led, anchor, ...);
    // (mirror the existing SignedLedgerVerifierTest fixtures — reuse its keygen/authorized-keys setup.)

    private FileAnchorStore anchor;
    private KeyFileLedgerSigner signer;
    private ActivationLedger led;

    @BeforeEach void setup() throws Exception {
        anchor = new FileAnchorStore(reg);
        signer = /* seed activator+approver keys + authorized-keys.jsonl, build signer */ null;
        led = new ActivationLedger(reg, anchor);
    }

    private SignedVerdict verify() throws Exception {
        return new SignedLedgerVerifier(new ActivationLedger(reg),
                AuthorizedKeys.load(reg), new SignedHeadStore(reg))
                .verify("mixer-01", TrustLevel.ANCHORED, anchor);
    }

    @Test void happyPathWhole() throws Exception {
        led.append(ev(0), signer);
        assertTrue(verify().intact());
    }

    @Test void anchorAbsentWhileLedgerNonEmpty() throws Exception {
        // append WITHOUT an anchor store, so head exists but no anchor line
        new ActivationLedger(reg).append(ev(0), signer);
        assertEquals("identity.anchor.missing", verify().rule());
    }

    @Test void anchorRollbackWhenHeadSeqBelowLatest() throws Exception {
        led.append(ev(0), signer);
        led.append(ev(1), signer);              // anchor latest seq=1
        // simulate truncation+re-anchor of the HEAD back to seq 0 (rewrite head file to seq 0)
        rewriteHeadToSeq(0);
        assertEquals("identity.anchor.rollback", verify().rule());
    }

    @Test void anchorRollbackWhenLedgerEmptiedAndHeadDeleted() throws Exception {
        led.append(ev(0), signer);              // anchor latest seq=0 remains
        Files.deleteIfExists(reg.resolve("activation").resolve("mixer-01.jsonl"));
        Files.deleteIfExists(reg.resolve("identity").resolve("mixer-01.head"));
        assertEquals("identity.anchor.rollback", verify().rule());   // strongest form of #2
    }

    @Test void anchorTailMismatchAtSameSeq() throws Exception {
        led.append(ev(0), signer);
        rewriteHeadTail("DIFFERENThash");       // seq stays 0, tail differs from anchor
        assertEquals("identity.anchor.tail-mismatch", verify().rule());
    }

    @Test void anchorBehindWhenHeadSeqAboveLatest() throws Exception {
        led.append(ev(0), signer);
        // simulate crash: append a second ledger line + head at seq 1 but DON'T record the anchor
        new ActivationLedger(reg).append(ev(1), signer);   // no anchor store => anchor still seq 0
        assertEquals("identity.anchor.behind", verify().rule());
    }

    @Test void headFourEyesMissingWhenCoSigAbsent() throws Exception {
        led.append(ev(0), signer);
        stripHeadCoPair();                       // rewrite head without coSignedBy/coSig
        assertEquals("identity.head.four-eyes.missing", verify().rule());
    }

    @Test void headFourEyesSameKey() throws Exception {
        led.append(ev(0), signer);
        rewriteHeadCoSignerToApprover();         // coSignedBy == signedBy
        assertEquals("identity.head.four-eyes.same-key", verify().rule());
    }

    @Test void headFourEyesInvalidWhenCoSigForged() throws Exception {
        led.append(ev(0), signer);
        corruptHeadCoSig();                      // coSig no longer verifies under coSignedBy's key
        assertEquals("identity.head.four-eyes.invalid", verify().rule());
    }
}
```
(Implement the `rewriteHead*` / `strip*` helpers with `SignedHeadStore` read → mutate record → write. `ev(n)` builds an `ActivationEvent` for `mixer-01`.)

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=SignedLedgerVerifierAnchoredTest`
Expected: FAIL — new `verify(target, level, anchors)` overload does not exist.

- [ ] **Step 3: Implement the anchored path.** Refactor `SignedLedgerVerifier` so the existing per-entry-signature loop is a private helper reused by both SIGNED and ANCHORED; add the overload:

```java
    /** T7: depth-selectable verification. STRUCTURAL=chain only; SIGNED=today's verify(target);
     *  ANCHORED=structure + per-entry sigs + anchor cross-check + four-eyes head. */
    public SignedVerdict verify(String target, TrustLevel level, AnchorStore anchors) throws IOException {
        List<LedgerEntry> hist = ledger.history(target);
        ChainVerdict structural = LedgerChain.verify(hist);
        if (!structural.intact()) return SignedVerdict.broken(structural.brokenIndex(), structural.rule());
        if (level == TrustLevel.STRUCTURAL) return SignedVerdict.whole();

        SignedVerdict entries = verifyEntries(hist);         // per-entry dual-sig loop (extracted)
        if (!entries.intact()) return entries;

        if (level == TrustLevel.SIGNED) return verifySignedHead(target, hist);   // existing head step

        // ANCHORED — anchor cross-check FIRST so empty+no-head is not short-circuited by verifySignedHead
        SignedVerdict anchorV = verifyAnchor(target, hist, anchors);
        if (!anchorV.intact()) return anchorV;
        if (hist.isEmpty()) return SignedVerdict.whole();     // empty + anchor absent already passed
        return verifyFourEyesHead(target, hist);
    }

    private SignedVerdict verifyAnchor(String target, List<LedgerEntry> hist, AnchorStore anchors)
            throws IOException {
        Optional<AnchorRecord> latest = anchors.latest(target);
        Optional<SignedHead> head = heads.read(target);
        if (hist.isEmpty() || head.isEmpty()) {
            // a present witness attesting an anchored tail that is now gone = the strongest rollback
            return latest.isPresent()
                    ? SignedVerdict.broken(-1, "identity.anchor.rollback")
                    : SignedVerdict.whole();
        }
        if (latest.isEmpty()) return SignedVerdict.broken(-1, "identity.anchor.missing");
        long headSeq = head.get().seq();
        AnchorRecord a = latest.get();
        if (headSeq < a.seq()) return SignedVerdict.broken(-1, "identity.anchor.rollback");
        if (headSeq > a.seq()) return SignedVerdict.broken(-1, "identity.anchor.behind");
        if (!head.get().tailEntryHash().equals(a.tailEntryHash()))
            return SignedVerdict.broken(-1, "identity.anchor.tail-mismatch");
        return SignedVerdict.whole();
    }

    private SignedVerdict verifyFourEyesHead(String target, List<LedgerEntry> hist) throws IOException {
        // structural head checks (tail/seq/approver-sig) reuse verifySignedHead's logic; then the co-pair:
        SignedVerdict base = verifySignedHead(target, hist);
        if (!base.intact()) return base;
        SignedHead head = heads.read(target).orElseThrow();
        if (head.coSignedBy() == null || head.coSig() == null)
            return SignedVerdict.broken(-1, "identity.head.four-eyes.missing");
        Optional<PublicKey> coKey = authorized.forPrincipal(head.coSignedBy());
        byte[] hp = SignedHeadStore.preimage(head.target(), head.seq(), head.tailEntryHash())
                .getBytes(StandardCharsets.UTF_8);
        if (coKey.isEmpty() || !Ed25519Keys.verify(hp, head.coSig(), coKey.get()))
            return SignedVerdict.broken(-1, "identity.head.four-eyes.invalid");
        Optional<PublicKey> primary = authorized.forPrincipal(head.signedBy());
        if (primary.isPresent() && java.util.Arrays.equals(primary.get().getEncoded(), coKey.get().getEncoded()))
            return SignedVerdict.broken(-1, "identity.head.four-eyes.same-key");
        return SignedVerdict.whole();
    }
```
Extract `verifyEntries(hist)` (the current for-loop, lines 41–56) and `verifySignedHead(target, hist)` (the current head block, lines 60–77) as private helpers; keep `verify(target)` delegating to them so SIGNED behavior is unchanged.
Add imports: `dev.krillin.bifrost.core.activation.AnchorStore`, `AnchorRecord`, `java.util.Optional` (present).

- [ ] **Step 4: Run to verify pass**

Run: `mvn -q -pl core test -Dtest=SignedLedgerVerifierAnchoredTest,SignedLedgerVerifierTest`
Expected: PASS — all anchored cases + the untouched SIGNED cases.

- [ ] **Step 5: Full core build**

Run: `mvn -q -pl core test`
Expected: PASS (no regression).

- [ ] **Step 6: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifier.java \
        core/src/test/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifierAnchoredTest.java
git commit -m "feat(core): SignedLedgerVerifier ANCHORED path — four-eyes head + anchor cross-check (empty-rollback caught independently of head branch)"
```

---

## Chunk 4: GitAnchorStore (core, opt-in committed-history witness)

**Unit responsibility:** `GitAnchorStore` — writes each record into a dedicated anchor git repo and commits it; `latest` reads the anchor from the **committed HEAD**, never the working tree. This is what makes the witness survive a working-tree co-rollback (spec §5, AN4).

### Task 4.1: GitAnchorStore (TDD)

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/identity/GitAnchorStore.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/GitAnchorStoreTest.java`

**Behavior:**
- Constructor takes an anchor-repo `Path` (a directory that is a git repo; the store `git init`s it if absent).
- `record(r)`: enforce the same monotonic contract as FileAnchorStore (read committed `latest` first), write `<target>.anchor.jsonl` (append a line) in the repo working tree, then `git add` + `git commit -m "anchor <target> seq=<n>"`.
- `latest(target)`: read the file **from committed HEAD** via `git show HEAD:<target>.anchor.jsonl` (parse last line). If the path is absent at HEAD → empty. Never read the working-tree file.
- Shells out with `ProcessBuilder`; no new Maven dependency. Guard: if `git` is unavailable, throw a clear `IllegalStateException("anchor.git.unavailable")`.

- [ ] **Step 1: Write the failing tests**

```java
package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class GitAnchorStoreTest {
    @TempDir Path repo;

    @Test void recordCommitsAndLatestReadsCommittedHead() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        s.record(new AnchorRecord("mixer-01", 0, "h0"));
        s.record(new AnchorRecord("mixer-01", 1, "h1"));
        assertEquals(1, s.latest("mixer-01").orElseThrow().seq());
    }

    @Test void latestSurvivesWorkingTreeRollback() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        s.record(new AnchorRecord("mixer-01", 0, "h0"));
        s.record(new AnchorRecord("mixer-01", 1, "h1"));
        // attacker rewrites the WORKING-TREE file back to seq 0 WITHOUT committing
        Path f = repo.resolve("mixer-01.anchor.jsonl");
        Files.writeString(f, "{\"target\":\"mixer-01\",\"seq\":0,\"tailEntryHash\":\"h0\"}\n");
        // committed HEAD still witnesses seq 1  (this is the AN4 property)
        assertEquals(1, s.latest("mixer-01").orElseThrow().seq());
    }

    @Test void latestEmptyForUnknownTarget() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        assertTrue(s.latest("nope").isEmpty());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `mvn -q -pl core test -Dtest=GitAnchorStoreTest`
Expected: FAIL — `GitAnchorStore` missing.

- [ ] **Step 3: Implement GitAnchorStore** (ProcessBuilder git; `record` reuses `FileAnchorStore` serde via a shared Jackson mapper; `latest` parses `git show HEAD:<file>`). Set `user.name`/`user.email` locally on init so commits work in a clean CI env. Enforce monotonicity against the committed `latest` before writing.

- [ ] **Step 4: Run to verify pass**

Run: `mvn -q -pl core test -Dtest=GitAnchorStoreTest`
Expected: PASS (3 tests). If the CI/dev box lacks `git`, the tests are environment-gated — the controller runs them on a box with git.

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/krillin/bifrost/core/identity/GitAnchorStore.java \
        core/src/test/java/dev/krillin/bifrost/core/identity/GitAnchorStoreTest.java
git commit -m "feat(core): GitAnchorStore — latest() reads committed HEAD (survives working-tree co-rollback; AN4 witness property)"
```

---

## Chunk 5: Gate CLI — `identity verify-anchored` + anchored `activate`

**Unit responsibilities:**
- `IdentityGate` — new `verify-anchored <reg> <target> [--anchor-store file|git] [--anchor-dir <dir>]` verb (0 intact / 1 broken+rule / 2 usage).
- `ActivateGate` — when a signer is present, wire an `AnchorStore` (default `FileAnchorStore(reg)`; `--anchor-dir`/`--anchor-store git` for the git witness) into `ActivationLedger` so `activate` records the anchor.

### Task 5.1: `identity verify-anchored` (TDD via gate)

**Files:**
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/IdentityGate.java`
- Test: `gates/src/test/java/dev/krillin/bifrost/gates/IdentityGateAnchoredTest.java` (new; model on `ActivateGateSignedTest`)

- [ ] **Step 1:** Failing test — seed a dual-head anchored ledger (via `ActivationLedger(reg, new FileAnchorStore(reg))`), run `IdentityGate.run("verify-anchored", reg, "mixer-01")`, assert exit 0 and `INTACT (anchored)`; then a rolled-back head → exit 1 with the `identity.anchor.rollback` code printed.
- [ ] **Step 2:** Run → FAIL (no `verify-anchored` case).
- [ ] **Step 3:** Add the `case "verify-anchored"` dispatch + method: parse `--anchor-store`/`--anchor-dir` (default file store at `reg`), build `SignedLedgerVerifier.forRegistry(reg)`, call `verify(target, TrustLevel.ANCHORED, anchorStore)`, print `INTACT (anchored)` / `BROKEN ... rule=<code>`, return 0/1/2. Update the usage string + class javadoc.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(gates): identity verify-anchored — TrustLevel.ANCHORED CLI (0 intact / 1 broken / 2 usage)`.

### Task 5.2: anchored `activate` wiring

**Files:**
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/ActivateGate.java` (the signed `activate` path, ~lines 40–60)
- Test: `gates/src/test/java/dev/krillin/bifrost/gates/ActivateGateSignedTest.java` (add a case)

- [ ] **Step 1:** Failing test — `activate ... --by-key ... --approved-by-key ... --anchor-dir <reg>` records an anchor line for the target (assert `FileAnchorStore(reg).latest(target)` present with seq 0).
- [ ] **Step 2:** Run → FAIL (activate ignores anchor).
- [ ] **Step 3:** Add `--anchor-dir` / `--anchor-store` parsing; when a signer is built, construct `new ActivationLedger(reg, anchorStore)` (default `FileAnchorStore(reg)`) instead of the bare ledger. Unsigned path unchanged (no anchor). Keep `--anchor-store git` → `GitAnchorStore(anchorDir)`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(gates): activate records the anchor on the signed path (--anchor-store file|git, --anchor-dir)`.

### Task 5.3: gates module build

- [ ] **Step 1:** Run `mvn -q -pl gates test` → PASS (new + existing).
- [ ] **Step 2:** No commit (verification step).

---

## Chunk 6: Heimdall edge — `REQUIRE_ANCHORED_ACTIVATION`

**Unit responsibility:** `NcmdOpcUaBridgeMain` — a new default-OFF `REQUIRE_ANCHORED_ACTIVATION` tier that selects `TrustLevel.ANCHORED`, wires the anchor store from config, and runs the anchor cross-check at the bind edge, denying with `activation.edge.anchor-denied reason=<code>`.

### Task 6.1: Config + trust-level selection

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java` (Config record, `env` parsing, `assertLedgerTrustworthy`)
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/RequireAnchoredActivationTest.java` (new; model on `RequireSignedActivationTest`)

- [ ] **Step 1:** Failing tests:
  - anchored ON + valid dual-head anchored ledger → bind succeeds, logs `activation trust=anchored`.
  - anchored ON + rolled-back head (seq below anchor) → bind denied, message contains `activation.edge.anchor-denied` and `reason=identity.anchor.rollback`.
  - anchored OFF (default) → existing signed/structural behavior unchanged.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement:
  - Add `boolean requireAnchoredActivation` + `String anchorStore` + `String anchorDir` to `Config`; parse `REQUIRE_ANCHORED_ACTIVATION` (same `true/on/1` + fail-to-OFF-loudly discipline as `REQUIRE_SIGNED_ACTIVATION`), `ANCHOR_STORE` (default `file`), `ANCHOR_DIR` (default the activation registry dir). Anchored implies signed.
  - Extend `assertLedgerTrustworthy`: when anchored, build the `AnchorStore` (file or git) and call `SignedLedgerVerifier.forRegistry(ledgerDir).verify(target, TrustLevel.ANCHORED, anchorStore)`; on a broken verdict throw `IllegalStateException("activation.edge.anchor-denied reason=" + verdict.rule())`.
  - Log line: `[BRIDGE] activation trust=structural|signed|anchored`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(heimdall): REQUIRE_ANCHORED_ACTIVATION edge tier — anchor cross-check fail-closed, audit activation.edge.anchor-denied reason=<code>`.

### Task 6.2: heimdall module build

- [ ] **Step 1:** Run `mvn -q -pl heimdall test` → PASS.

---

## Chunk 7: Gate script + docs + full verification

### Task 7.1: `run-anchored-activation-gate.sh`

**Files:**
- Create: `scripts/run-anchored-activation-gate.sh` (model on `run-identity-gate.sh` / `run-activation-authz-gate.sh`)

- [ ] **Step 1:** Write the script. Build a temp registry, `identity keygen` an activator + approver + a third principal, seed `authorized-keys.jsonl` + `activation-policy.json` (so T6 authZ passes). Cases:
  - **AN1** activate (dual-head + anchor) → `verify-anchored` exit 0 `INTACT (anchored)`.
  - **AN2** truncate ledger + re-sign a single-key head at lower seq → `verify-anchored` exit 1, rule `identity.head.four-eyes.*` or `identity.anchor.rollback`.
  - **AN3** co-rollback: restore ledger+head to the seq-0 snapshot, anchor **git** repo untouched → exit 1 `identity.anchor.rollback`.
  - **AN4** also roll back the working-tree anchor file → git `latest` (committed HEAD) still catches → exit 1 `identity.anchor.rollback`.
  - **AN5** rewrite head so coSignedBy == signedBy → `identity.head.four-eyes.same-key`.
  - **AN6** append a second entry without recording the anchor → `identity.anchor.behind`.
  - **AN7** empty the ledger + delete head, keep anchor → `identity.anchor.rollback`.
  - **AN8** Heimdall: `REQUIRE_ANCHORED_ACTIVATION=on` + rolled-back registry → bridge denies, log contains `activation.edge.anchor-denied`.
  Each case prints `[GATE] ANx ... => PASS/FAIL` and the script exits non-zero on any failure.
- [ ] **Step 2:** `chmod +x scripts/run-anchored-activation-gate.sh`.
- [ ] **Step 3:** Commit `test(gate): run-anchored-activation — AN1..AN8 four-eyes head + git-anchor witness`.

### Task 7.2: README + spec cross-reference

**Files:**
- Modify: `README.md` (add the `anchored` tier to the trust ladder + gate suite; note honest residual §8.2)

- [ ] **Step 1:** Document the third tier, the `AnchorStore` seam + git adapter, `REQUIRE_ANCHORED_ACTIVATION`, and the honest residual (trust rests on the anchor's off-box protection). Commit `docs: README documents the anchored trust tier (four-eyes head + external git anchor)`.

### Task 7.3: Full controller verification (no-regression)

- [ ] **Step 1:** `mvn -q install` from repo root → all modules green (record counts: core / heimdall / gates / sim).
- [ ] **Step 2:** Run the new gate: `bash scripts/run-anchored-activation-gate.sh` → AN1–AN8 PASS.
- [ ] **Step 3:** Run the 4+ no-regression gates: `run-activation-gate`, `run-lineage-gate`, `run-identity-gate`, `run-activation-authz-gate`, `run-template-conformance-gate`, `run-yggdrasil-full-loop-gate` → all PASS.
- [ ] **Step 4:** No commit (verification). Report the full green matrix to the controller.

---

## Post-implementation

- **Final holistic review** (superpowers:requesting-code-review + a security-focused pass on the anchor/verifier logic) before surfacing to Eisen.
- **Branch disposition is Eisen-gated** — do NOT merge or push. Leave on `feat/t7-anchored-activation`.
- Update memory (`activation-authorization-t6.md` follow-on / new `anchored-activation-t7.md`) once controller-verified.
