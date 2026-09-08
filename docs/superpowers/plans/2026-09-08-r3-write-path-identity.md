# R3 — Write-Path Identity Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Heimdall edge an OPC-UA identity it can present, and make the bundled server enforce that only that identity may write the controlled nodes — so that `ENTERPRISE.md` row 12 stops being described as work this repository does not owe.

**Architecture:** Two halves that meet at the wire. The client half configures `OpcUaApplier` with an application-instance certificate, a `Basic256Sha256`/`SignAndEncrypt` endpoint and an X.509 user identity. The server half gives `EmbeddedMiloSim` a second, secured endpoint guarded by an `X509IdentityValidator`, plus a per-session `UserAccessLevel` filter that makes the controlled nodes read-only for every other session. Both halves are **opt-in and off by default**, so every existing gate keeps running against the anonymous `None` endpoint unchanged.

**Tech Stack:** Java 17, Eclipse Milo 1.0 (client + server SDK), `SelfSignedCertificateBuilder`, JUnit 5.10.3, Docker (broker for the gate).

---

## Why this round exists

`ENTERPRISE.md` row 12 is one of the two rows the board says bound every other row, and it is open:

> Today, nothing does. The bundled OPC-UA server runs `AnonymousIdentityValidator` with `SecurityPolicy.None`, and the controlled nodes carry `UserAccessLevel = 3` — read and write, for anyone who can open a session. **Heimdall is therefore a chokepoint by convention, not by construction.**

Both documents then send the work elsewhere. `ENTERPRISE.md §12`: *"What closes it is mostly not code"*. `ADOPTION.md`'s gap table: **"not this project's code to write"**.

**That is wrong, and the code says so.** `OpcUaApplier.connect()` is:

```java
client = OpcUaClient.create(endpoint);   // anonymous, SecurityPolicy.None, no way to pass a cert
```

The moment a plant does what §12 asks — configure the server so only a governed identity may write — **the first client locked out is Heimdall**, because it has no identity to present. The server-side setting is indeed the plant's; the key that setting checks for is this repository's, and it does not exist. R3 builds the key and proves the lock works against it.

**What this round does NOT claim.** Written into the docs in Task 10, and worth holding in mind while implementing:

- It proves the mechanism **on the OPC-UA surface, against the bundled sim**. A plant's server is a Kepware or a Siemens PLC, not `EmbeddedMiloSim`. What transfers is that the edge can present an identity and that a server which requires one refuses everyone else.
- **Modbus/TCP is untouched.** It has no identity to authenticate; there exclusivity remains a network position, exactly as §12 says.
- **Axis 10 does not close — it starts biting.** The certificate here is self-signed, trusted by a fixed predicate, with no rotation, no revocation and no GDS. R3 is what makes the certificate-lifecycle gap operational rather than theoretical.
- Row 12 therefore moves **open → partial**, not open → built.

---

## Facts verified against the jars and the source on 2026-09-08

Checked with `javap`/`unzip` against the exact artifacts in `~/.m2`, so a surprise during implementation is a mistake in the edit rather than a wrong assumption here.

| Fact | Verified |
|---|---|
| The client can present a certificate | `OpcUaClientConfigBuilder` has `setCertificate(X509Certificate)`, `setCertificateChain(X509Certificate[])`, `setKeyPair(KeyPair)`, `setIdentityProvider(IdentityProvider)`, `setCertificateValidator(CertificateValidator)` |
| There is a factory that accepts all of it | `OpcUaClient.create(String endpointUrl, Function<List<EndpointDescription>, Optional<EndpointDescription>> selector, Consumer<OpcTcpClientTransportConfigBuilder>, Consumer<OpcUaClientConfigBuilder>)`. The 1-arg `create(String)` currently used is the anonymous/None path |
| The server can require an X.509 user token | `X509IdentityValidator(Predicate<X509Certificate>)` in `org.eclipse.milo.opcua.sdk.server.identity`, alongside `AnonymousIdentityValidator` and `UsernameIdentityValidator` |
| **A custom `AccessController` cannot be installed** | `OpcUaServer` exposes `getAccessController()` and **no setter**; `OpcUaServerConfig` has no access-control property. The interface exists (`checkWriteAccess(Session, List<WriteValue>)`) but is not pluggable in 1.0. **This is why the design uses `UserAccessLevel`, not an AccessController** |
| Attribute reads are session-aware | `AttributeFilterContext` has `getSession(): Optional<Session>` and is constructed with the `Session`. `AttributeFilter` is the per-node hook; `AttributeFilters` provides `getValue`/`setValue`/`getSetValue` helpers for the Value attribute, so a `UserAccessLevel` filter is written against `AttributeFilter` directly |
| The session carries the authenticated identity | `Session.getIdentity(): Identity`, `Session.getIdentityToken(): UserIdentityToken` |
| Certificates can be generated in-process | `SelfSignedCertificateBuilder` and `SelfSignedCertificateGenerator` in `org.eclipse.milo.opcua.stack.core.util` |
| The sim's nodes are wide open today | `EmbeddedMiloSim.java:227,240` — `.setAccessLevel(ubyte(3)).setUserAccessLevel(ubyte(3))` on every Boolean and Double node; `:357` uses `1` for the read-only EURange properties |
| The sim offers exactly one endpoint | `EmbeddedMiloSim.start()` builds a single `EndpointConfig` with `SecurityPolicy.None`, `MessageSecurityMode.None`, one anonymous `UserTokenPolicy`, and `AnonymousIdentityValidator.INSTANCE` |

### Three decisions locked here — do not re-open during implementation

**(a) Enforcement is per-session `UserAccessLevel`, not an `AccessController`.**
`AccessController` is the obvious place for "may this session write this node", and Milo 1.0 does not let you install one — the server only exposes a getter. The supported path is that `DefaultAccessController` consults the node's `UserAccessLevel`, and an `AttributeFilter` can compute that attribute per session because its context carries the `Session`. Write the reason in the filter's javadoc; the next reader will otherwise go looking for the setter that is not there.

**(b) The sim keeps its anonymous endpoint, and adds a second secured one.**
The tempting move is to remove the `None` endpoint so nothing unauthenticated can connect at all. That is a *stronger* claim than §12 makes and a *worse* model of a plant: real sites need read-only clients — historians, HMIs, Huginn's own future live capture — and locking them out is not what "write-path exclusivity" means. Two endpoints, with the anonymous one demoted to read-only on the controlled nodes, is both the honest model and the only shape in which the gate can prove the distinction. It also keeps every existing gate green.

**(c) Both halves default OFF.**
No `HEIMDALL_IDENTITY_DIR` means the client behaves exactly as today. No `SIM_REQUIRE_IDENTITY=on` means the sim behaves exactly as today. Fifteen gates currently run against the anonymous path and none of them should change, because this round adds a capability rather than changing the default posture. The new gate turns both on.

---

## File structure

**Create:**

| Path | Responsibility |
|---|---|
| `heimdall/src/main/java/…/EdgeIdentity.java` | Load-or-generate the edge's keypair + self-signed application-instance certificate from a directory |
| `sim/src/main/java/…/GovernedWriteFilter.java` | The per-session `UserAccessLevel` filter — the whole server-side mechanism |
| `scripts/run-write-exclusivity-gate.sh` | Proves a second client's write is refused **by the server** |
| `heimdall/src/test/java/…/EdgeIdentityTest.java` | Generate, persist, reload, and the thumbprint being stable |
| `sim/src/test/java/…/GovernedWriteFilterTest.java` | Read-only for an unknown session, writable for the governed one |

**Modify:**

| Path | Change |
|---|---|
| `heimdall/src/main/java/…/OpcUaApplier.java` | Secure-endpoint selection + certificate + X.509 identity, behind the opt-in |
| `heimdall/src/main/java/…/NcmdOpcUaBridgeMain.java` | `HEIMDALL_IDENTITY_DIR` config and wiring |
| `sim/src/main/java/…/EmbeddedMiloSim.java` | Second secured endpoint, `X509IdentityValidator`, filter attachment, `SIM_REQUIRE_IDENTITY` |
| `docs/ENTERPRISE.md` | Row 12 open → partial; §12 rewritten to split key from lock |
| `docs/ADOPTION.md` | Gap table row 12 corrected; phase 4 note |
| `README.md` | Gate list, test count |

---

## Chunk 1: The edge's identity material

### Task 1: `EdgeIdentity` — load or generate

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentity.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeIdentityTest.java`

- [ ] **Step 1: Write the failing test**

```java
package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EdgeIdentityTest {

    @Test
    void generatesAKeypairAndCertificateOnFirstUse(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:test");
        assertNotNull(id.certificate());
        assertNotNull(id.keyPair());
        assertTrue(Files.exists(dir.resolve("edge-cert.der")), "the certificate must be persisted");
        assertTrue(Files.exists(dir.resolve("edge-key.pkcs8")), "the private key must be persisted");
    }

    /** The identity has to survive a restart, or every restart is a new principal to the server. */
    @Test
    void reloadsTheSameIdentity(@TempDir Path dir) throws Exception {
        EdgeIdentity first = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:test");
        EdgeIdentity again = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:test");
        assertArrayEquals(first.certificate().getEncoded(), again.certificate().getEncoded(),
                "a restart must present the SAME certificate, not a new one");
        assertEquals(first.thumbprint(), again.thumbprint());
    }

    @Test
    void thumbprintIsASha1HexOfTheEncodedCertificate(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:test");
        assertEquals(40, id.thumbprint().length(), "SHA-1 hex is 40 chars: " + id.thumbprint());
        assertTrue(id.thumbprint().matches("[0-9a-f]{40}"), id.thumbprint());
    }

    /** The application URI in the certificate must match the one the client announces, or Milo
     *  rejects its own certificate at connect time with a validation failure that reads like a
     *  server problem. */
    @Test
    void certificateCarriesTheApplicationUriAsASubjectAltName(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:test");
        boolean found = id.certificate().getSubjectAlternativeNames().stream()
                .anyMatch(e -> "urn:bifrost:heimdall:test".equals(String.valueOf(e.get(1))));
        assertTrue(found, "application URI missing from SAN: " + id.certificate().getSubjectAlternativeNames());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=EdgeIdentityTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: class EdgeIdentity`

- [ ] **Step 3: Write minimal implementation**

Use `SelfSignedCertificateBuilder` with an RSA 2048 keypair, `setApplicationUri(...)`, and `addApplicationUri(...)` for the SAN. Persist as `edge-cert.der` (`X509Certificate.getEncoded()`) and `edge-key.pkcs8` (`PKCS8EncodedKeySpec`). `thumbprint()` is lowercase hex of `SHA-1(certificate.getEncoded())` — SHA-1 because that is what OPC-UA thumbprints are, not because it is a security choice; say so in the javadoc.

The class javadoc must carry the round's honesty:

```java
/**
 * The edge's OPC-UA application-instance identity: an RSA keypair and a self-signed certificate,
 * generated once into a directory and reloaded thereafter.
 *
 * <p>This exists because {@code ENTERPRISE.md} row 12 asks a plant to make its controlled nodes
 * writable only by a governed identity — and until now Heimdall had no identity to present, so
 * that configuration would have locked out the very edge it was meant to privilege.
 *
 * <p><b>Self-signed, and that is a real limitation, not a shortcut to be forgotten.</b> There is no
 * CA, no rotation, no revocation and no Global Discovery Server here. Trust is established by the
 * server holding this certificate's thumbprint. That is row 10, it is still open, and R3 is what
 * makes it bite: an identity that cannot be rotated is a deployment that cannot outlive it.
 */
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=EdgeIdentityTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 4 tests

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentity.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeIdentityTest.java
git commit -m "feat(heimdall): give the edge an OPC-UA application-instance identity

Row 12 asks a plant to let only a governed identity write. The edge had
none to present, so that configuration would have locked out the edge.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 2: The client presents it

### Task 2: `OpcUaApplier` connects with a certificate

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/OpcUaApplier.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/OpcUaApplierFaultTest.java` (add a case)

The applier gains an optional `EdgeIdentity`. When absent, `ensureConnected()` keeps calling `OpcUaClient.create(endpoint)` exactly as today — this is what keeps fifteen gates green. When present, it uses the 4-arg factory.

- [ ] **Step 1: Write the failing test**

Endpoint *selection* is the part that is unit-testable without a server: given a list of endpoint descriptions, the secure one must be chosen, and the absence of one must be a clear failure rather than a silent downgrade to `None`.

```java
    @Test
    void securePickerChoosesSignAndEncryptAndRejectsNone() {
        // A silent fall back to None would be the worst possible failure here: the edge would
        // report success while presenting no identity at all.
        assertTrue(OpcUaApplier.isSecure(descriptionWith("Basic256Sha256", MessageSecurityMode.SignAndEncrypt)));
        assertFalse(OpcUaApplier.isSecure(descriptionWith("None", MessageSecurityMode.None)));
        assertFalse(OpcUaApplier.isSecure(descriptionWith("Basic256Sha256", MessageSecurityMode.Sign)));
    }
```

with a small `descriptionWith(String policyUri, MessageSecurityMode)` helper building an `EndpointDescription`.

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=OpcUaApplierFaultTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: method isSecure`

- [ ] **Step 3: Write minimal implementation**

Add `static boolean isSecure(EndpointDescription e)` requiring both `SecurityPolicy.Basic256Sha256.getUri().equals(e.getSecurityPolicyUri())` and `MessageSecurityMode.SignAndEncrypt.equals(e.getSecurityMode())`, and use it in `ensureConnected()`:

```java
            if (identity == null) {
                // Unchanged legacy path: anonymous, SecurityPolicy.None. Every gate that predates
                // R3 runs here, which is why this branch stays exactly as it was.
                client = OpcUaClient.create(endpoint);
            } else {
                client = OpcUaClient.create(
                        endpoint,
                        endpoints -> endpoints.stream().filter(OpcUaApplier::isSecure).findFirst(),
                        transport -> { },
                        cfg -> cfg
                                .setApplicationUri(identity.applicationUri())
                                .setCertificate(identity.certificate())
                                .setKeyPair(identity.keyPair())
                                .setIdentityProvider(new X509IdentityProvider(
                                        identity.certificate(), identity.keyPair().getPrivate())));
            }
```

**The selector returning empty must fail loudly.** Milo surfaces that as a connect failure, which `ensureConnected` already converts to `PlantUnreachableException` — check the message reads usefully and, if it does not, pre-check the endpoint list and throw with "no Basic256Sha256/SignAndEncrypt endpoint offered by <url>". An edge that silently connected anonymously because the secure endpoint was missing would be the exact defect this round exists to remove.

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=OpcUaApplierFaultTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS

- [ ] **Step 5: Run the whole suite**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS — the legacy branch is untouched.

- [ ] **Step 6: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/OpcUaApplier.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/OpcUaApplierFaultTest.java
git commit -m "feat(heimdall): connect with a certificate on a secured endpoint

Opt-in: with no identity configured the anonymous SecurityPolicy.None
path is byte-for-byte what it was, which is what keeps the existing
gates meaningful.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Configuration

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMainConfigTest.java`

- [ ] **Step 1: Write the failing test**

```java
    @Test
    void identityDirDefaultsToUnset() {
        assertNull(NcmdOpcUaBridgeMain.resolve(k -> null).identityDir());
    }

    @Test
    void identityDirIsReadFromTheEnvironment() {
        assertEquals("/etc/heimdall/pki", NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_IDENTITY_DIR".equals(k) ? "/etc/heimdall/pki" : null).identityDir());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeMainConfigTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — no `identityDir()` on the record

- [ ] **Step 3: Write minimal implementation**

Add `String identityDir` to `Config` (default null) via the existing `env(...)` helper. **Three existing tests construct `Config` directly** — `LoadConformanceActivationTest.java:37`, `NcmdOpcUaBridgeMainDefaultsTest.java:67,104` — and adding a record component breaks their arity, exactly as it did in R0. Add `null` to each.

In `main`, when the value is set, build the identity and hand it to the applier; log the thumbprint at startup so an operator can match it against what the server trusts:

```java
        System.out.println("[BRIDGE] OPC-UA identity " + identity.thumbprint() + " (" + identity.applicationUri() + ")");
```

Extend the env javadoc block.

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/
git commit -m "feat(heimdall): configure HEIMDALL_IDENTITY_DIR

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 3: The server enforces it

### Task 4: `GovernedWriteFilter`

**Files:**
- Create: `sim/src/main/java/dev/krillin/bifrost/sim/GovernedWriteFilter.java`
- Test: `sim/src/test/java/dev/krillin/bifrost/sim/GovernedWriteFilterTest.java`

This is the entire server-side mechanism, and it is small.

- [ ] **Step 1: Write the failing test**

Test the decision function in isolation rather than fighting to construct a `Session`:

```java
    @Test
    void anUnknownSessionGetsReadOnly() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor(null, "aabb"));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("ffff", "aabb"));
    }

    @Test
    void theGovernedThumbprintGetsReadWrite() {
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("aabb", "aabb"));
    }

    /** Case must not decide authorization: thumbprints are hex and both cases occur in the wild. */
    @Test
    void thumbprintComparisonIsCaseInsensitive() {
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("AABB", "aabb"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,sim test -Dtest=GovernedWriteFilterTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: class GovernedWriteFilter`

- [ ] **Step 3: Write minimal implementation**

An `AttributeFilter` whose `getAttribute` intercepts `AttributeId.UserAccessLevel`, reads the session's X.509 identity from `ctx.getSession()`, and returns `ubyte(3)` or `ubyte(1)`. Everything else delegates.

The javadoc must record decision (a), because the next reader will look for the `AccessController`:

```java
/**
 * Makes the controlled nodes writable only by the governed identity, and read-only for every other
 * session. This is the mechanism {@code ENTERPRISE.md} §12 names as "server-side write permission".
 *
 * <p><b>Why a UserAccessLevel filter and not an AccessController.</b> Milo 1.0 has exactly the
 * right interface — {@code AccessController.checkWriteAccess(Session, List&lt;WriteValue&gt;)} — and
 * no way to install one: {@code OpcUaServer} exposes {@code getAccessController()} with no setter
 * and {@code OpcUaServerConfig} has no property for it. What the default controller does consult is
 * the node's {@code UserAccessLevel}, and {@link AttributeFilterContext} carries the {@code Session},
 * so the attribute can be computed per session. Do not go looking for the setter; it is not there.
 *
 * <p>Read stays open to everyone on purpose. A plant needs read-only clients — historians, HMIs —
 * and locking them out is not what write-path exclusivity means.
 */
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,sim test -Dtest=GovernedWriteFilterTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add sim/src/main/java/dev/krillin/bifrost/sim/GovernedWriteFilter.java sim/src/test/java/dev/krillin/bifrost/sim/GovernedWriteFilterTest.java
git commit -m "feat(sim): per-session UserAccessLevel filter for the controlled nodes

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: The sim offers a secured endpoint

**Files:**
- Modify: `sim/src/main/java/dev/krillin/bifrost/sim/EmbeddedMiloSim.java:76-105` (the `start()` config) and the node builders at `:227,240`

- [ ] **Step 1: Add the second endpoint and the validator, behind `SIM_REQUIRE_IDENTITY`**

When the flag is off, `start()` is exactly what it is today. When on:

- keep the existing `None`/anonymous `EndpointConfig`, and add a second with `SecurityPolicy.Basic256Sha256`, `MessageSecurityMode.SignAndEncrypt`, and a `UserTokenPolicy` of `UserTokenType.Certificate`
- the server needs its own application-instance certificate — reuse `EdgeIdentity`'s approach; the sim module must not depend on `heimdall`, so either move the generator to a shared place or duplicate the ~20 lines with a comment saying why. **Prefer duplication over a new module dependency here** and say so in the comment: the sim is a test fixture and coupling it to the runtime edge to save twenty lines is the wrong trade.
- `setIdentityValidator(new X509IdentityValidator(cert -> thumbprintOf(cert).equalsIgnoreCase(governedThumbprint)))`, the thumbprint coming from `SIM_GOVERNED_THUMBPRINT`
- attach `GovernedWriteFilter` to the Rpm/Temp/Running/Weld nodes

- [ ] **Step 2: Verify by hand that the default is unchanged**

```bash
mvn -q -pl core,heimdall,sim install -DskipTests
java -jar sim/target/bifrost-sim.jar
```
Expected: `OPC-UA sim listening` and, with `SIM_REQUIRE_IDENTITY` unset, no second endpoint and no behaviour change.

- [ ] **Step 3: Run the sim and heimdall suites**

Run: `mvn -q -pl core,heimdall,sim test`
Expected: PASS

- [ ] **Step 4: Run the gates that use the sim — this is the regression that matters**

```bash
timeout 600 bash scripts/run-ncmd-runtime-gate.sh
timeout 900 bash scripts/run-edge-resilience-gate.sh
timeout 900 bash scripts/run-yggdrasil-spine-gate.sh
timeout 900 bash scripts/run-yggdrasil-full-loop-gate.sh
```
Expected: all PASS, all still on the anonymous endpoint.

- [ ] **Step 5: Commit**

```bash
git add sim/src/main/java/dev/krillin/bifrost/sim/EmbeddedMiloSim.java
git commit -m "feat(sim): optional secured endpoint requiring a governed X.509 identity

Off by default: the anonymous endpoint stays, so every gate that predates
R3 still exercises the path it was written against.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 4: Evidence

### Task 6: `run-write-exclusivity-gate.sh`

**Files:**
- Create: `scripts/run-write-exclusivity-gate.sh`

Reuse the R0 gate's idiom: `cygpath` shim, `fail()`, `kill_by_jvmarg`/`kill_by_mainclass`, `cleanup`/`trap`, count-based assertions. **Do not grep for a line that also appears at startup, and do not grep an accumulating log without a baseline** — that trap cost three separate fixes in R0.

| | Asserts | Method |
|---|---|---|
| **X1** | The governed edge writes | Start the sim with `SIM_REQUIRE_IDENTITY=on` and the edge's thumbprint; start the edge with `HEIMDALL_IDENTITY_DIR`; publish an authorized NCMD; require an APPLY count **increase** and the sim to witness the value |
| **X2** | **A second client's write is refused by the SERVER** | A small `AnonymousWriter` main connects to the `None` endpoint and writes the same node directly. Require a bad `StatusCode` and require the sim's value to be **unchanged**. This is the row-12 assertion; everything else is setup |
| **X3** | Read is still open | The same anonymous client reads the node successfully — proving the mechanism is write permission, not a blanket lockout |
| **X4** | An untrusted certificate cannot get in | Start a second edge with a *different* identity directory; require its session to be rejected and no APPLY to appear |
| **X5** | The default posture is unchanged | With `SIM_REQUIRE_IDENTITY` unset, the anonymous write succeeds — the same write X2 requires to fail. Without this the gate cannot show that the refusal came from the new configuration rather than from something incidental |

- [ ] **Step 1: Write `AnonymousWriter`** (`heimdall/src/main/java/…/AnonymousWriter.java`), a `RogueNcmd`-shaped main that takes a node id and value, connects anonymously, writes, and prints the resulting `StatusCode` — the second client that row 12 is about.

- [ ] **Step 2: Write the gate**

- [ ] **Step 3: Run it**

Run: `timeout 900 bash scripts/run-write-exclusivity-gate.sh`
Expected: `[GATE] PASS run-write-exclusivity-gate.sh`, exit 0

- [ ] **Step 4: Prove the gate by injecting the defect**

| Injection | Must fail |
|---|---|
| `GovernedWriteFilter.userAccessLevelFor` always returns 3 | X2 |
| The filter returns 1 for everyone | X1 |
| `X509IdentityValidator` predicate always true | X4 |
| `OpcUaApplier.isSecure` also accepts `None` | X1 (the edge would connect anonymously and be read-only) |

- [ ] **Step 5: Run every other gate**

- [ ] **Step 6: Commit**

---

## Chunk 5: Correct the documents

### Task 7: `ENTERPRISE.md` row 12 and §12

- [ ] **Step 1: Board row**

`open` → `partial`, evidence `run-write-exclusivity-gate.sh` X1–X5, and the remaining scope named: proven against the bundled sim on the OPC-UA surface only; Modbus unchanged; a plant's own server still has to be configured.

- [ ] **Step 2: §12**

The sentence *"What closes it is mostly not code"* has to be corrected rather than softened. The honest split:

- **the key is this repository's** — an edge with no identity cannot benefit from a server that requires one, and that was true when the row was written
- **the lock is the plant's** — the server-side configuration, and the network position for protocols with no identity

Keep the closing consequence, which is still true: an edge without an exclusive write credential governs the cooperating clients and nothing else.

- [ ] **Step 3: Row 10 gets sharper, not closed**

§6/row 10 stay open. Add: R3 makes the trigger concrete — the certificate now exists, is self-signed, and has no rotation path.

- [ ] **Step 4: Commit**

### Task 8: `ADOPTION.md` and `README.md`

- [ ] **Step 1:** Gap table row 12: replace **"not this project's code to write"** with the two-part statement, and strike through only the half R3 built. The paragraph beginning *"Why the last row is listed anyway"* is now partly wrong and must be rewritten — its point stands, its premise moved.
- [ ] **Step 2:** Phase 4's *"Make the edge the only way in"* paragraph: the edge can now present an identity; the server config is still the site's.
- [ ] **Step 3:** `README.md` gate list and test count.
- [ ] **Step 4: Commit**

---

## Definition of done

- [ ] `mvn test` green across the reactor
- [ ] `run-write-exclusivity-gate.sh` PASS, every X1–X5 proved by injecting its defect
- [ ] All five pre-existing runtime gates still PASS, still on the anonymous endpoint
- [ ] `ENTERPRISE.md` row 12 reads **partial** with the gate named and the remaining scope stated
- [ ] `ADOPTION.md` no longer says write-path exclusivity is not this project's code
- [ ] Row 10 still reads **open** — R3 does not close certificate lifecycle, it makes it bite

## What R3 explicitly does not fix

| | Round |
|---|---|
| Certificate rotation, revocation, expiry, GDS — the identity is self-signed and permanent | R10 / axis 10 |
| Modbus/TCP has no identity; exclusivity there is a network position | not code |
| The command path still has no requester identity — this is the *edge's* identity to the server, not the *operator's* to the edge | R1 |
| Commands still leave no tamper-evident record | R2 |
| Proven against `EmbeddedMiloSim`, not against a Kepware, an Ignition or a real PLC | open |
