# R5 — Certificate expiry and key rotation: an identity that outlives its first credential

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the half of `ENTERPRISE.md` axis 10 that does not need a CA — an Ed25519 signing key can be rotated offline without breaking history, and an expiring OPC-UA certificate is diagnosed and announced before it stops the line.

**Architecture:** `AuthorizedKeys` becomes principal → **set of keys** with optional validity windows. Verification asks "which of this principal's registered keys verifies this signature?", so history stays verifiable forever; *signing* is what the validity window restricts, so rotation takes effect going forward. On the certificate side `EdgeIdentity` learns its own expiry, the edge says so loudly and precisely instead of failing opaquely at connect, and a renewal command mints a successor while preserving the old identity — the overlap being the server's trust list holding both thumbprints.

**Tech Stack:** Java 17, Jackson, Ed25519 (JDK), Eclipse Milo (sim + edge), bash gates.

---

## Why this shape, and what it deliberately does not do

`ENTERPRISE.md` §6 already fixed the order: *"decide the disconnected-renewal behaviour, then integrate."* R5 is the first half. **No CA, no GDS, no enrolment protocol.** Wiring Heimdall to a certificate authority before deciding what it does when renewal is unreachable would convert a security control into an outage generator, which is the failure §6 exists to warn about.

**Compromise-revocation is explicitly out of scope**, and the reason is the same one this repository already gives for command replay freshness: invalidating past signatures needs a time source the site trusts, and OT sites frequently have none. A ledger entry's `at` is self-asserted, so it cannot be used to decide which key was valid when. R5 therefore separates two things that are usually conflated:

| | what it is | what R5 does |
|---|---|---|
| **Rotation** | the key is fine; we are moving to a successor | built, offline, additive |
| **Revocation** | the key was stolen; past signatures are suspect | **not built** — documented as needing trusted time |

**The R4 landmine is what makes this urgent.** `docs/ADOPTION.md` now tells an operator to retire a key by removing its policy grants and *never* by deleting its key line, because `SignedLedgerVerifier` resolves `forPrincipal` for every historical entry. That instruction currently has no mechanism behind it: `AuthorizedKeys.load` throws on a duplicate principal with a different key, so there is literally no way to express "this principal's old key and its new one". R5 gives that sentence a mechanism.

### The decision this round records

**An expired certificate does NOT stop the edge.** Same reasoning as R0's plant-unreachable handling: a transport credential is an *operational* fault, an untrustworthy ledger is a *governance* one, and only the second justifies refusing to start. What the edge does instead is diagnose precisely (`identity.cert.expired` with the exact `notAfter`) rather than surfacing an opaque Milo connect failure, and warn for a configurable window beforehand so the fault is actionable while it is still cheap.

---

## File structure

| File | Responsibility | Change |
|---|---|---|
| `core/.../identity/AuthorizedKey.java` | one registry line | **+2 optional fields** (`notBefore`, `notAfter`) |
| `core/.../identity/AuthorizedKeys.java` | the trust anchor | principal → **List**; `verifying(...)`, `allForPrincipal(...)` |
| `core/.../identity/SignedLedgerVerifier.java` | ledger authentication | resolve by *which key verified*; distinctness on those keys |
| `core/.../identity/KeyFileLedgerSigner.java` | signing + preflight | refuse a key outside its window **at signing time** |
| `core/.../acl/CommandEnvelope.java` | command authentication | anchor becomes `Function<String, List<PublicKey>>` |
| `heimdall/.../NcmdOpcUaBridgeMain.java` | edge wiring | anchor function; certificate diagnosis + warn window |
| `heimdall/.../EdgeIdentity.java` | the edge's X.509 identity | expiry accessors; `renew` preserving the old identity |
| `heimdall/.../EdgeIdentityCli.java` | **new** | `renew` / `show` — an operator command, not a startup flag |
| `heimdall/.../EdgeHealth.java` | health surface | `cert_days_remaining` |
| `sim/.../EmbeddedMiloSim.java`, `GovernedWriteFilter.java` | the bundled server | trust **a set** of thumbprints — a real server's trust list |
| `gates/.../IdentityGate.java` | the CLI | `rotate-key` |
| `scripts/run-key-rotation-gate.sh` | **new** | K1–K10 |

**Two API changes ripple.** `AuthorizedKeys.forPrincipal` has 8 call sites and `CommandEnvelope.verify` has its own; both are changed deliberately rather than shimmed, because a compatibility overload returning "the first key" would silently keep the old single-key semantics at any site that was missed.

---

## Chunk 1: Key rotation

### Task 1: A principal may hold more than one key

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/AuthorizedKey.java`
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/AuthorizedKeys.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/AuthorizedKeysRotationTest.java` (new)

- [ ] **Step 1: Write the failing tests**

Cover, at minimum:
1. two lines for one principal with different keys **load** (today: `IllegalStateException`)
2. `verifying(p, msg, sig)` returns the key that verifies, trying every key registered to `p`
3. `verifying` returns empty for an unregistered principal, and for a signature no key verifies
4. an identical duplicate line is still tolerated (unchanged)
5. `notBefore`/`notAfter` absent means unbounded, and round-trip through Jackson (a line without them must still parse — every existing registry is such a line)
6. **order independence**: the successor line before or after the predecessor gives the same result

- [ ] **Step 2: Run to verify red**

```bash
mvn -q -pl core test -Dtest=AuthorizedKeysRotationTest -Dsurefire.failIfNoSpecifiedTests=false
```

- [ ] **Step 3: Implement**

```java
public record AuthorizedKey(String principal, String publicKey,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Instant notBefore,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Instant notAfter) {
    /** Every registry written before rotation existed is this shape. */
    public AuthorizedKey(String principal, String publicKey) { this(principal, publicKey, null, null); }
    public boolean validAt(Instant t) {
        return (notBefore == null || !t.isBefore(notBefore)) && (notAfter == null || t.isBefore(notAfter));
    }
}
```

`AuthorizedKeys` holds `Map<String, List<RegisteredKey>>` where `RegisteredKey` pairs the decoded `PublicKey` with its window. The duplicate-principal-different-key error is **removed** — that is now how rotation is expressed. Keep the identical-duplicate tolerance and the `bad-public-key` fail-closed.

```java
/** Which of this principal's registered keys verifies this signature, if any. This is THE resolution
 *  primitive: history must stay verifiable after a rotation, and an entry carries no key id, so the
 *  only honest question is "did any key this principal is registered with sign this?". Deliberately
 *  NOT time-filtered — an entry's timestamp is self-asserted and cannot select a key. */
public Optional<PublicKey> verifying(String principal, byte[] msg, String sigB64) { ... }

/** Every key registered to a principal, in file order. */
public List<PublicKey> allForPrincipal(String principal) { ... }

/** The keys a principal may SIGN with right now. Rotation takes effect here, not in verification. */
public List<PublicKey> validForPrincipal(String principal, Instant at) { ... }
```

- [ ] **Step 4: Green, then the whole reactor** (many call sites still compile against `forPrincipal` — remove it and fix them in Tasks 2–4; the reactor is expected red until Task 4)
- [ ] **Step 5: Commit**

### Task 2: The ledger verifier resolves by which key actually verified

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifier.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/SignedLedgerVerifierRotationTest.java` (new)

- [ ] **Step 1: Write the failing tests**

1. **the point of the round**: sign entries with key A, register a successor key B for the same principal, and the old entries **still verify** — `identity.key.unregistered` does not appear
2. entries signed with the successor verify too, in the same ledger
3. a principal with no registered key still yields `identity.key.unregistered`
4. a signature no registered key verifies still yields `identity.sig.invalid`
5. **four-eyes distinctness survives**: activator and approver resolving to the same key is still `identity.four-eyes.same-key` — and, the new case, the same *person* signing both legs with two different keys of theirs must ALSO be caught
6. the head and the four-eyes co-pair resolve the same way

Case 5's second half is the one worth thinking about. Distinctness has always been enforced on *keys*, but its purpose is two *people*. Once one principal can hold two keys, key-distinctness stops implying principal-distinctness. The verifier must compare principals as well.

- [ ] **Step 2: Red** — case 1 fails today
- [ ] **Step 3: Implement**

`verifyEntries` becomes: resolve `aKey = authorized.verifying(e.activatedBy(), msg, en.activatorSig())`, same for the approver; empty when the principal has no keys at all → `identity.key.unregistered`, else → `identity.sig.invalid`. Then distinctness on **both** the resolved keys and the two principal names.

- [ ] **Step 4: Green** · **Step 5: Commit**

### Task 3: Signing is what the validity window restricts

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSigner.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/identity/KeyFileLedgerSignerRotationTest.java` (new)

- [ ] **Step 1: Write the failing tests**

1. a key file bound to a key whose `notAfter` has passed is refused with `identity.key.expired`
2. a key file bound to a key whose `notBefore` is in the future is refused with `identity.key.not-yet-valid`
3. a key file bound to an in-window key passes, **while the principal also holds a retired key**
4. the four-eyes check compares the two *bound* keys, not "the principal's key"
5. an unbounded key (both fields null) still passes — every existing registry

`Clock` is injected (constructor overload, `Clock.systemUTC()` default) so tests are deterministic and do not sleep. This matches `ActivationService` and `CommandLedger`.

- [ ] **Step 2: Red** · **Step 3: Implement** — `bindsToPrincipal` returns *which* key the probe verified under, then `preflight` checks that key's window · **Step 4: Green** · **Step 5: Commit**

### Task 4: The command path resolves the same way

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/acl/CommandEnvelope.java`
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java:357`
- Test: `core/src/test/java/dev/krillin/bifrost/core/acl/CommandEnvelopeRotationTest.java` (new)

- [ ] **Step 1: Write the failing tests**

1. an envelope signed with a rotated-in key verifies when the anchor offers both keys
2. an envelope signed with the retired key **still verifies** — the same reasoning as the ledger: no key id travels with the command either, and refusing here would break a command in flight across a rotation
3. an empty key list is `UNKNOWN_PRINCIPAL`, unchanged
4. a signature none of the keys verify is `BAD_SIGNATURE`, unchanged

- [ ] **Step 2: Red** · **Step 3: Implement**

`verify(Function<String, List<PublicKey>> anchor, ...)`. Heimdall wires `name -> keys.allForPrincipal(name)`.

- [ ] **Step 4: Green — and now the FULL reactor must be green** (`mvn -q test`); `forPrincipal` is gone and every site is converted
- [ ] **Step 5: Commit**

### Task 5: `gates identity rotate-key`

**Files:**
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/IdentityGate.java`
- Modify: `gates/src/main/java/dev/krillin/bifrost/gates/ActivateGate.java` (duty-key-mint's already-registered message now points at `rotate-key`)
- Test: `gates/src/test/java/dev/krillin/bifrost/gates/IdentityGateRotateKeyTest.java` (new)

`rotate-key <reg> <principal> --out <dir> [--retire-at <instant>]`:

1. refuse when the principal has **no** current key — rotation replaces, it does not enrol (`identity.principal.not-registered`)
2. mint the successor keypair with `writeKeyPair` (the R4 helper — same owner-only custody)
3. print the **complete replacement block**: every existing line for that principal re-emitted with `notAfter` set (default: now), plus the successor line
4. say plainly that the operator **replaces** those lines and **never deletes** them, and that until the successor line is in place the principal cannot sign

Printing the whole block rather than editing the file in place is deliberate and matches `duty-key-mint`: the trust anchor is the one file whose change control is out-of-band, and a CLI that rewrites it silently is exactly the wrong tool.

- [ ] **Step 1: failing test · Step 2: red · Step 3: implement · Step 4: green · Step 5: commit**

---

## Chunk 2: Certificate expiry

### Task 6: The edge knows its own expiry

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentity.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeIdentityExpiryTest.java` (new)

- [ ] **Step 1: Write the failing tests**

1. `notAfter()` matches the certificate's `getNotAfter()`
2. `daysUntilExpiry(Clock)` is correct, and **negative** past expiry rather than clamped — an operator needs to know how long it has been broken
3. `expired(Clock)` is true past `notAfter` and false before
4. `loadOrCreate` on an **expired** cert still returns an identity (it does not throw) — the decision this round records
5. a freshly generated identity has ~2 years remaining

`Clock`-injected overloads, as everywhere else.

- [ ] **Step 2: Red · Step 3: Implement · Step 4: Green · Step 5: Commit**

### Task 7: Say it, early and precisely

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java`
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeHealth.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMainDefaultsTest.java` (extend)

- [ ] **Step 1: Write the failing tests**

1. `HEIMDALL_CERT_WARN_DAYS` defaults to 30 and parses like every other int env — an unparseable value falls back with a loud WARN (`intEnv`, already there)
2. `EdgeHealth.report()` carries `cert_days_remaining` when an identity is configured, and **omits it** when none is
3. `healthy()` is **unchanged** — an expired certificate does not by itself flip health; its consequence (writes failing) already flips `plant_reachable`, and reporting the same fault twice in one boolean would make the signal harder to read, not easier

- [ ] **Step 2: Red · Step 3: Implement**

At startup, after the identity line:
- expired → `System.err.println("[BRIDGE] identity.cert.expired notAfter=… daysAgo=… - the OPC-UA server will refuse this certificate; renew with EdgeIdentityCli renew")`
- within the window → `[BRIDGE] WARN identity.cert.expiring days=… notAfter=…`
- otherwise → the days remaining on the existing identity line, so the number is in the log of every healthy boot too

**Do not throw.** The startup ledger-trust checks keep failing closed; this one does not, and the difference is stated in the code comment.

- [ ] **Step 4: Green · Step 5: Commit**

### Task 8: `EdgeIdentityCli renew`

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentityCli.java`
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentity.java` (a `renew` that preserves the predecessor)
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeIdentityRenewTest.java` (new)

`renew <dir> <applicationUri>` and `show <dir>`. An **operator command, not a startup flag** — a restart that could mint an identity is a restart that can silently become a new principal to the server, which is the failure `loadOrCreate`'s javadoc already warns about.

- [ ] **Step 1: Write the failing tests**

1. `renew` writes a **new** cert and key, and the thumbprint differs from the predecessor's
2. the predecessor is **preserved** on disk under a timestamped name, not overwritten — the overlap window is only usable if the old identity still exists
3. the new certificate carries the same `applicationUri` in its subjectAltName (a renewal that changed it would be rejected at connect for a reason that reads like a server fault)
4. `renew` on a directory with no identity is a usage error, not a silent create
5. `show` prints the thumbprint, `notAfter` and days remaining, and exits 2 when there is no identity
6. the renewed private key file is owner-only, like the original

- [ ] **Step 2: Red · Step 3: Implement · Step 4: Green · Step 5: Commit**

### Task 9: The server's trust list holds more than one thumbprint

**Files:**
- Modify: `sim/src/main/java/dev/krillin/bifrost/sim/EmbeddedMiloSim.java`
- Modify: `sim/src/main/java/dev/krillin/bifrost/sim/GovernedWriteFilter.java`
- Test: `sim/src/test/java/dev/krillin/bifrost/sim/GovernedWriteFilterTest.java` (extend)

`GOVERNED_WRITER_THUMBPRINT` becomes comma-separated. This is not a convenience: **a rotation with a single-valued trust list is a rotation that stops the line**, and the whole point of K8 below is to prove it does not have to.

- [ ] **Step 1: Write the failing tests**

1. either thumbprint in the list grants write; a third is denied
2. whitespace and case are tolerated per element (today's `trim`/`equalsIgnoreCase`, per element now)
3. an empty or absent list still **fails closed** (R3's rule: an unconfigured thumbprint denies)
4. an empty session thumbprint is still an internal read, not an anonymous writer (R3's rule, unchanged)

- [ ] **Step 2: Red · Step 3: Implement · Step 4: Green · Step 5: Commit**

---

## Chunk 3: Gate and documents

### Task 10: `scripts/run-key-rotation-gate.sh`

House idiom: `cygpath` shim, `fail`, staged registry, fresh dirs, count-based assertions, `HEALTH_PORT` named per edge (R4's federation fix).

| | Asserts |
|---|---|
| **K1** | `rotate-key` on an unregistered principal is refused — rotation replaces, it does not enrol |
| **K2** | after rotation, **entries signed with the retired key still verify** at every tier (chain, signed, anchored). The R4 landmine, now defused rather than merely documented |
| **K3** | the retired key **cannot sign a new activation** — `identity.key.expired`, refused at preflight |
| **K4** | the successor key **can**, and the resulting ledger verifies at every tier |
| **K5** | the **edge still boots** on a rotated registry with `REQUIRE_SIGNED_ACTIVATION=on` and again with `REQUIRE_ANCHORED_ACTIVATION=on` — the R4-B6 lesson applied: a rotation that stops the edge is not a rotation |
| **K6** | one person signing both legs with **two different keys of their own** is refused — key-distinctness no longer implies person-distinctness, so the four-eyes check must say so |
| **K7** | **deleting** the retired line still breaks the ledger — the landmine has a safe path now, but it did not go away, and the gate must keep saying so |
| **K8** | **the rotation overlap holds end to end**: with the sim trusting both thumbprints, a write succeeds before renewal and again after, with the edge restarted on the renewed identity. This is the assertion the round exists for |
| **K9** | an **expired** certificate is diagnosed (`identity.cert.expired`) and **the edge still starts** |
| **K10** | a certificate inside the warning window logs `identity.cert.expiring` with the days remaining, and `/healthz` reports `cert_days_remaining` |

K9/K10 need a certificate with a chosen `notAfter`. Generate a short-lived one in the test fixture rather than waiting — `SelfSignedCertificateBuilder` takes a validity period, and a `Clock` shifted forward is the alternative if the builder will not accept a past date.

- [ ] **Step 1: write · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: every other gate · Step 5: commit**

### Task 11: Documents

- [ ] `ENTERPRISE.md` axis 10 **open → partial**, naming exactly what is closed (offline rotation; expiry decided and announced) and what is not (no CA/GDS, no enrolment, no compromise-revocation, and renewal still changes the thumbprint so the server must be re-told)
- [ ] `ENTERPRISE.md` §6 — the "decide, then integrate" order now has its first half done; say so, and keep the trigger for the second half
- [ ] `ENTERPRISE.md` limitations — **rotation is not revocation**, and why: a retired key still verifies its own history by design, so retirement stops future signing and nothing else. Anyone reading "rotated" as "the old key can no longer hurt me" is wrong, and the document must say it
- [ ] `ADOPTION.md` — the R4 retirement instruction gains its mechanism (`rotate-key`); add certificate renewal to phase 5 with the overlap procedure (**put the successor thumbprint in the server's trust list BEFORE restarting the edge**)
- [ ] Counts: gates 20→21, tests, `README.md` badge, per-module split, gate list; **add the gate to `.github/workflows/ci.yml`** if it is broker-free — K8 needs the sim but no broker, so check honestly whether the whole gate can run there and place it accordingly
- [ ] `docs/superpowers/plans/2026-09-08-r4-break-glass.md` needs no change; R4's landmine row in `ENTERPRISE.md` gains a pointer to the safe path

---

## Definition of done

- [ ] `mvn test` green; **every pre-existing identity test unchanged and passing** — a registry with one unbounded key per principal must behave exactly as before
- [ ] `run-key-rotation-gate.sh` PASS, **every K1–K10 proved by injecting its defect**
- [ ] **K2, K5 and K8 pass** — history survives rotation, the edge still boots, and the write path survives the certificate change. These three are the round
- [ ] Every activation-ladder gate still PASS: activation, lineage, identity, activation-authz, anchored, federation, break-glass
- [ ] `LedgerEntry`, `LedgerChain`, `ActivationEvent` and both preimages **untouched** — rotation must not change what is signed, or every existing ledger breaks
- [ ] The new gate is in CI if it is broker-free

## What R5 explicitly does not fix

| | |
|---|---|
| **Rotation is not revocation.** A retired key still verifies the history it signed; retirement stops future signing only | needs trusted time — see §6 |
| No CA, no GDS, no enrolment: renewal is manual and the successor thumbprint must reach the server out of band | §6's second half, deliberately deferred |
| Renewal changes the thumbprint, so an operator who restarts the edge before updating the server's trust list stops the line | inherent to self-signed; the gate proves the correct order works |
| Nothing expires a *policy grant* — a principal's authorization has no window, only its keys do | later |
| The certificate warning has no transport: it is a log line and a health metric, like R4's break-glass loudness | later |
