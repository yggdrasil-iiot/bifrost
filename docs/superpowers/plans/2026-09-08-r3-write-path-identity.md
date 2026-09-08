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
| The server can require an X.509 user token | `X509IdentityValidator(Predicate<X509Certificate>)` in `org.eclipse.milo.opcua.sdk.server.identity`. `AbstractX509IdentityValidator` falls back to the channel's security policy when the `UserTokenPolicy` carries a null `securityPolicyUri`, so `new UserTokenPolicy("x509", UserTokenType.Certificate, null, null, null)` on a Basic256Sha256 endpoint is correct |
| **A secured endpoint needs a certificate group, which the sim has none of** | `EmbeddedMiloSim.java:91-92` builds `new DefaultCertificateManager(new MemoryCertificateQuarantine(), List.of())` — zero groups, with a comment saying it is never consulted. A `Basic256Sha256` endpoint needs `DefaultApplicationGroup.createAndInitialize(TrustListManager, CertificateStore, CertificateFactory, CertificateValidator)`, and `RsaSha256CertificateFactory` is **abstract** (`protected abstract createRsaSha256CertificateChain(KeyPair)`). This is Task 5's real size |
| The controlled writable nodes are five, not four | `Recipe/Rpm` (`:149`), `Recipe/Temp` (`:160`), `Recipe/ApplyRecipe` (`:175`), `Recipe/ApplyDone` (`:174`), `Weld/WeldCurrent` (`:190`). `Running` is a `typeMember` at access level 1 and is already read-only |
| A failed endpoint bind is only a WARN | `OpcUaServer.lambda$startup$2` catches `Exception` around `transport.bind(...)` and logs `"Failed to bind endpoint …"`. The sim would still print `OPC-UA sim listening`, so the gate must assert the secure endpoint is actually offered |
| **A custom `AccessController` cannot be installed** | `OpcUaServer` exposes `getAccessController()` and **no setter**; `OpcUaServerConfig` has no access-control property. The interface exists (`checkWriteAccess(Session, List<WriteValue>)`) but is not pluggable in 1.0. **This is why the design uses `UserAccessLevel`, not an AccessController** |
| Attribute reads are session-aware | `AttributeFilterContext` has `getSession(): Optional<Session>` and is constructed with the `Session`. `AttributeFilter` is the per-node hook; `AttributeFilters` provides `getValue`/`setValue`/`getSetValue` helpers for the Value attribute, so a `UserAccessLevel` filter is written against `AttributeFilter` directly |
| The session carries the authenticated identity | `Session.getIdentity(): Identity`, `Session.getIdentityToken(): UserIdentityToken` |
| Certificates can be generated in-process | `SelfSignedCertificateBuilder` and `SelfSignedCertificateGenerator` in `org.eclipse.milo.opcua.stack.core.util` |
| The sim's nodes are wide open today | `EmbeddedMiloSim.java:227,240` — `.setAccessLevel(ubyte(3)).setUserAccessLevel(ubyte(3))` in `makeBooleanNode`/`makeDoubleNode`. `:357` is `typeMember(...)`, which builds the *type and instance* members at `1`; the EURange properties in `attachEuRange` (`:361-373`) set no access level at all |
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

### Task 3: Configuration and the application URI

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMainConfigTest.java`

**Decision, because the plan previously left it open.** The application URI is derived, not configured: `urn:bifrost:heimdall:<group>:<edge>` with `:`/`/` folded, mirroring R0's client-id decision. Two edges are therefore two principals, which is what a per-edge write permission needs. It must be derived in exactly one place and used for both `EdgeIdentity.loadOrCreate` and `cfg.setApplicationUri(...)`: a mismatch between the certificate's SAN and the announced URI is rejected at connect time with an error that reads like a server fault.

- [ ] **Step 1: Write the failing tests**

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

    /** Derived, and per-edge: two edges must be two principals to the server. */
    @Test
    void applicationUriIsDerivedFromGroupAndEdge() {
        assertEquals("urn:bifrost:heimdall:Bifrost-Line1:recipe-edge",
                NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "recipe-edge"));
        assertNotEquals(NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "recipe-edge"),
                        NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "mixer-edge"));
    }
```

- [ ] **Step 2: Run to verify red**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeMainConfigTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — no `identityDir()`, no `applicationUri(String,String)`

- [ ] **Step 3: Implement**

Add `String identityDir` to `Config` (default null). **Three existing tests construct `Config` directly** — `LoadConformanceActivationTest.java:37`, `NcmdOpcUaBridgeMainDefaultsTest.java:67,104` — and a new record component breaks their arity, exactly as it did in R0. Add `null` to each.

In `main`, when `identityDir` is set, build the identity and pass it to the applier via the three-arg `OpcUaApplier(String, EdgeHealth, EdgeIdentity)` constructor, and print the thumbprint so an operator can match it to what the server trusts:

```java
        System.out.println("[BRIDGE] OPC-UA identity " + identity.thumbprint()
                + " (" + identity.applicationUri() + ")");
```

- [ ] **Step 4: Green, then the whole suite** — `mvn -q -pl core,heimdall test`
- [ ] **Step 5: Commit**

---

### Task 3b: `--print-thumbprint`, so the gate can bootstrap

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeIdentity.java`

The gate must start the sim with `SIM_GOVERNED_THUMBPRINT=<edge thumbprint>`, and the thumbprint only exists once the identity has been generated. Without this, Task 6 depends on something no earlier task delivers, and the alternative — start the edge against a sim that is not up, scrape its log, then start the sim — leans on R0's cold-start behaviour and the 5s backoff for no reason.

- [ ] **Step 1: Add a `main`**

```java
    /**
     * {@code java -cp bifrost-heimdall.jar …EdgeIdentity --print-thumbprint <dir> <applicationUri>}
     * — generate the identity if absent, then print only the thumbprint. Exists so the write
     * exclusivity gate can configure the SERVER with the client's thumbprint before either starts.
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !"--print-thumbprint".equals(args[0])) {
            System.err.println("usage: EdgeIdentity --print-thumbprint <dir> <applicationUri>");
            System.exit(2);
        }
        System.out.println(loadOrCreate(Path.of(args[1]), args[2]).thumbprint());
    }
```

- [ ] **Step 2: Verify by hand**

```bash
java -cp heimdall/target/bifrost-heimdall.jar dev.krillin.bifrost.heimdall.EdgeIdentity --print-thumbprint build/gate/pki urn:bifrost:heimdall:test
```
Expected: one 40-char lowercase hex line, identical on a second run.

- [ ] **Step 3: Commit**

---

### Task 3c: Decide the no-secure-endpoint behaviour

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/OpcUaApplier.java`

The earlier draft said to *"check the message reads usefully and, if it does not, pre-check"* — conditional prose, where the plan itself calls a silent anonymous fallback "the exact defect this round exists to remove". Decide it.

**Decided:** `createGoverned()` wraps the failure and rethrows a `PlantUnreachableException` naming the cause — `no Basic256Sha256/SignAndEncrypt endpoint at <url>; an identity is configured so the anonymous endpoint is deliberately not used`. The edge refuses to run degraded rather than connecting anonymously. X6 asserts it.

- [ ] **Step 1: Implement the wrap**
- [ ] **Step 2: Whole suite green**
- [ ] **Step 3: Commit**

---

## Chunk 3: The server enforces it

### Task 4: `GovernedWriteFilter`

**Files:**
- Create: `sim/src/main/java/dev/krillin/bifrost/sim/GovernedWriteFilter.java`
- Test: `sim/src/test/java/dev/krillin/bifrost/sim/GovernedWriteFilterTest.java`

- [ ] **Step 1: Write the failing test**

The decision function is tested in isolation rather than fighting to construct a `Session`. **The null-governed-thumbprint case is the one that matters**: `SIM_REQUIRE_IDENTITY=on` with `SIM_GOVERNED_THUMBPRINT` unset must fail CLOSED. An `Objects.equals(null, null)` implementation would hand write access to an unauthenticated session, which is the exact inversion of this round.

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

    /** No configured thumbprint means nobody is governed - never everybody. */
    @Test
    void anUnconfiguredGovernedThumbprintFailsClosed() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor(null, null));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", null));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", "   "));
    }
```

- [ ] **Step 2: Run to verify red**

Run: `mvn -q -pl core,sim test -Dtest=GovernedWriteFilterTest -Dsurefire.failIfNoSpecifiedTests=false`

- [ ] **Step 3: Implement**

An `AttributeFilter` overriding `getAttribute(AttributeFilterContext, AttributeId)`; intercept `AttributeId.UserAccessLevel` only, read the session's `Identity.X509UserIdentity.getCertificate()`, and return `ubyte(3)` or `ubyte(1)`. Everything else delegates via `ctx.getAttribute(attributeId)`.

The javadoc must record two things the next reader will otherwise undo:

```java
/**
 * Makes the controlled nodes writable only by the governed identity, and read-only for every other
 * session. This is the mechanism {@code ENTERPRISE.md} §12 names as "server-side write permission".
 *
 * <p><b>Why a UserAccessLevel filter and not an AccessController.</b> Milo 1.0 has exactly the
 * right interface — {@code AccessController.checkWriteAccess(Session, List<WriteValue>)} — and no
 * way to install one: {@code OpcUaServer} exposes {@code getAccessController()} with no setter and
 * {@code OpcUaServerConfig} has no property for it. What the default controller does consult is the
 * node's {@code UserAccessLevel}, via a session-scoped read that goes through this filter chain.
 * Do not go looking for the setter; it is not there.
 *
 * <p><b>An absent session is an internal read, not an anonymous one.</b> The chain has session-less
 * overloads and the sim's own {@code setValue(...)} calls take them, so an empty
 * {@code getSession()} must NOT be treated as deny — that would break the sim writing its own
 * ApplyDone. Deny applies to a session that is present and not governed.
 *
 * <p>Read stays open to everyone on purpose. A plant needs read-only clients — historians, HMIs —
 * and locking them out is not what write-path exclusivity means.
 */
```

- [ ] **Step 4: Green**
- [ ] **Step 5: Commit**

---

### Task 5: The sim offers a secured endpoint

**Files:**
- Modify: `sim/src/main/java/dev/krillin/bifrost/sim/EmbeddedMiloSim.java`, `sim/src/main/java/dev/krillin/bifrost/sim/SimMain.java`
- Test: `sim/src/test/java/dev/krillin/bifrost/sim/EmbeddedMiloSimConfigTest.java`

**This task is substantially bigger than the earlier draft claimed** ("~20 lines of certificate generation"). A `Basic256Sha256` endpoint requires the server to hold its own key material, and the sim currently has **no certificate groups at all**. What is actually needed:

- a `MemoryTrustListManager` and a `MemoryCertificateStore`
- a concrete subclass of the **abstract** `RsaSha256CertificateFactory`, implementing `createRsaSha256CertificateChain(KeyPair)` with `SelfSignedCertificateBuilder`
- `DefaultApplicationGroup.createAndInitialize(trustList, store, factory, validator)` added to the `DefaultCertificateManager`

**A decision the earlier draft never made, and it silently gates two assertions.** That `CertificateValidator` validates *incoming client application certificates*, before any user token is examined. Use `CertificateValidator.InsecureCertificateValidator`, and say why:

> This round's claim is that the **user identity** decides write permission. A strict `DefaultServerCertificateValidator` over an empty trust list would reject the governed edge's secure channel before its user token was ever looked at — X1 would fail for a reason unrelated to identity, and X4 would pass for a reason unrelated to the thumbprint. Accepting the application certificate and letting the thumbprint predicate be the decision keeps the gate measuring the thing it names. **It is also precisely axis 10's gap:** real trust needs a populated trust list, which is the same missing PKI that has no rotation.

The client needs no matching config: `OpcUaClientConfigBuilder`'s default `certificateValidator` is already `InsecureCertificateValidator`.

**The sim must not depend on `heimdall`** — correct and cheap: `sim` already gets `milo-stack-core` (and BouncyCastle) transitively via `milo-sdk-server`, so `SelfSignedCertificateBuilder` compiles with no POM change, whereas depending on `heimdall` would drag tahu, Paho, Jackson, Chicory and `bifrost-core` into the shaded `bifrost-sim.jar`.

- [ ] **Step 1: Env resolution goes in `SimMain`, per the module's own convention**

`SimMain.java:26-34` already puts env parsing in testable `resolvePort(Map)`/`resolveHost(Map)` statics covered by `EmbeddedMiloSimConfigTest`. Add `resolveRequireIdentity(Map)` and `resolveGovernedThumbprint(Map)` there, warn loudly on an unrecognised flag value the way heimdall's `flag()` does, and pass both into the `EmbeddedMiloSim` constructor. **Write the tests first** — these are the two most security-relevant toggles in the sim and would otherwise be its only untested ones.

- [ ] **Step 2: Add the certificate group and the second endpoint**

Keep the existing `None`/anonymous `EndpointConfig`. When `requireIdentity` is on, add a second with `SecurityPolicy.Basic256Sha256`, `MessageSecurityMode.SignAndEncrypt`, and `new UserTokenPolicy("x509", UserTokenType.Certificate, null, null, null)`, and set `setIdentityValidator(new X509IdentityValidator(cert -> thumbprintOf(cert).equalsIgnoreCase(governedThumbprint)))` — failing closed when `governedThumbprint` is null or blank, matching Task 4.

- [ ] **Step 3: Attach the filter to all FIVE controlled nodes**

`Recipe/Rpm` (`:149`), `Recipe/Temp` (`:160`), `Recipe/ApplyRecipe` (`:175`), `Recipe/ApplyDone` (`:174`), `Weld/WeldCurrent` (`:190`) — via `node.getFilterChain().addFirst(filter)`.

**`Recipe/ApplyRecipe` is the one the earlier draft missed, and it is not incidental**: it is the Boolean activate trigger that `OpcUaApplier.call()` writes. An anonymous client able to fire a recipe apply, while the round claims write-path exclusivity, would be a hole in the claim itself. `ApplyDone` is included for the mirror-image reason — a client writing it fakes a confirmation. `Running` needs nothing; `typeMember` already builds it at access level 1.

- [ ] **Step 4: Print a line the gate can assert on**

A failed endpoint bind is only a WARN inside `OpcUaServer.startup`, so the sim would still print `OPC-UA sim listening` with no secure endpoint at all. After startup succeeds, print `[SIM] secured endpoint Basic256Sha256/SignAndEncrypt, governed thumbprint <thumb>` and have the gate require it.

- [ ] **Step 5: Verify the default is unchanged by hand**

```bash
mvn -q -pl core,heimdall,sim install -DskipTests
java -jar sim/target/bifrost-sim.jar
```
Expected: `OPC-UA sim listening`, no secure-endpoint line, no behaviour change.

- [ ] **Step 6: Run every gate that uses the sim — the regression that matters**

```bash
timeout 600 bash scripts/run-ncmd-runtime-gate.sh
timeout 900 bash scripts/run-edge-resilience-gate.sh
timeout 900 bash scripts/run-yggdrasil-spine-gate.sh
timeout 900 bash scripts/run-yggdrasil-full-loop-gate.sh
```

- [ ] **Step 7: Commit**

---

## Chunk 4: Evidence

### Task 6: `run-write-exclusivity-gate.sh`

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/AnonymousWriter.java`
- Create: `scripts/run-write-exclusivity-gate.sh`

Reuse the R0 gate's idiom. **Do not grep a line that also appears at startup, and never grep an accumulating log without a baseline** — that trap cost three separate fixes in R0.

`AnonymousWriter` connects anonymously to the `None` endpoint and, in **one process against one session**, reads the node and then writes it, printing both outcomes with the exact `StatusCode`. One process matters: X3 is what proves the client in X2 was genuinely connected, and a separate process would decouple the guard from the thing it guards.

| | Asserts | Method |
|---|---|---|
| **X1** | The governed edge writes | Sim with `SIM_REQUIRE_IDENTITY=on` and the thumbprint from Task 3b; edge with `HEIMDALL_IDENTITY_DIR`; publish an authorized NCMD; require an APPLY **count increase** and the sim to witness the value |
| **X2** | **A second client's write is refused by the SERVER** | `AnonymousWriter` writes a **distinct value**, against a baseline read taken **between X1 and X2**. Require `Bad_UserAccessDenied` specifically — "a bad StatusCode" also admits `Bad_NodeIdUnknown` from a node-id typo, `Bad_TypeMismatch`, or an outright connect failure — and require the value unchanged from that baseline |
| **X3** | Read is still open | Same process, same session, reads the node successfully — the mechanism is write permission, not a lockout |
| **X4** | An untrusted certificate cannot write | A second identity directory; that session must not obtain write access, and the node value must be unchanged |
| **X5** | The default posture is unchanged | With `SIM_REQUIRE_IDENTITY` unset, the same anonymous write **succeeds** — without this the gate cannot show the refusal came from the new configuration rather than from something incidental |
| **X6** | No silent downgrade | Sim WITHOUT `SIM_REQUIRE_IDENTITY`, edge WITH an identity: require the edge to refuse with the "no Basic256Sha256/SignAndEncrypt endpoint" message, and require **no** APPLY |

- [ ] **Step 1: Write `AnonymousWriter`**
- [ ] **Step 2: Write the gate**
- [ ] **Step 3: Run it** — expect `[GATE] PASS run-write-exclusivity-gate.sh`, exit 0
- [ ] **Step 4: Prove the gate by injecting the defect — one row per assertion**

| Injection | Must fail |
|---|---|
| `userAccessLevelFor` always returns 3 | X2 |
| `userAccessLevelFor` always returns 1 | X1 |
| `userAccessLevelFor` returns 0 for unknown sessions | X3 |
| `X509IdentityValidator` predicate always true | X4 |
| Make the secured endpoint and the filter unconditional (ignore `SIM_REQUIRE_IDENTITY`) | X5 |
| Make `createGoverned()` fall back to `createAnonymous()` when no secure endpoint is found | X6 |

The earlier draft's *"`isSecure` also accepts `None`"* injection is **removed**: the selector is `findFirst()` over the server's endpoint ordering, so it only breaks X1 if `None` happens to come first. An injection whose outcome depends on ordering proves nothing. The X6 fallback injection is deterministic and tests the same property.

- [ ] **Step 5: Run every other gate**
- [ ] **Step 6: Commit**

---

## Chunk 5: Correct the documents

### Task 7: `ENTERPRISE.md` — every place row 12 is called open

The board row is not the only claim. **All of these move together, or the document contradicts itself:**

- [ ] **Step 1:** board row 12 `open` → **partial**, evidence `run-write-exclusivity-gate.sh` X1–X6, remaining scope named
- [ ] **Step 2:** `:56-57` — *"**Rows 12 and 13 bound everything else on the board**, and both are open"* — now only row 13 is
- [ ] **Step 3:** `:545-548` limitations bullet — *"**The edge is not an exclusive write path.** … Read every enforcement claim here as scoped to the cooperating client until that is closed"* — the sharpest statement of the thing this round changes. Rewrite to what is now true and what is not
- [ ] **Step 4:** §12 itself — correct *"What closes it is mostly not code"* rather than soften it. The honest split: **the key is this repository's** (an edge with no identity cannot benefit from a server that requires one), **the lock is the plant's** (server configuration; network position where there is no identity). Keep the closing consequence, which still holds. **State prominently that both halves of the proof are code in this repository** — "the lock is the plant's" is precisely the half R3 does not demonstrate against anything foreign
- [ ] **Step 5:** row 10 / §6 stay **open**, with a sentence that R3 makes the trigger concrete
- [ ] **Step 6:** **the board diagram** — `docs/diagrams/readiness-board.svg` **and** `readiness-board.dark.svg` hardcode `PARTIAL · 3` / `OPEN · 3`, place row 12 in the OPEN column, and close with "Five of thirteen are answered… the other eight". The `<img alt>` at `:34` repeats "three partial … three open". Regenerate both files and the alt text, or the figure contradicts the table beneath it
- [ ] **Step 7:** gate counts — `:12` "all 15 gates", `:558` "five of the fifteen need no broker". `scripts/` already holds **16** (R0 added one without updating these); R3 makes **17**
- [ ] **Step 8: Commit**

### Task 8: `ADOPTION.md` and `README.md`

- [ ] **Step 1:** gap table row 12 — replace **"not this project's code to write"** with the two-part statement; strike through only the half R3 built
- [ ] **Step 2:** `:234` — *"two rows are code this project owes… The last row is not code at all"* — the same claim in miniature, and now wrong
- [ ] **Step 3:** `:237` — the *"Why the last row is listed anyway"* paragraph: its point stands, its premise moved
- [ ] **Step 4:** phase 4's *"Make the edge the only way in"* — the edge can now present an identity; the server configuration is still the site's
- [ ] **Step 5:** `README.md` — gate list, `:19` "All 15 last ran green", and the **`tests-362` badge at `:6`**, which already contradicts "383 tests" at `:138`
- [ ] **Step 6: Commit**

---

## Definition of done

- [ ] `mvn test` green across the reactor
- [ ] `run-write-exclusivity-gate.sh` PASS, **every X1–X6 proved by injecting its defect**
- [ ] All six pre-existing runtime gates still PASS, still on the anonymous endpoint
- [ ] `ENTERPRISE.md` row 12 reads **partial** — in the table, in both board SVGs, in the alt text, at `:56` and at `:545`
- [ ] `ADOPTION.md` no longer says write-path exclusivity is not this project's code, at `:234` or in the gap table
- [ ] Gate counts and the README test badge are current
- [ ] Row 10 still reads **open** — R3 does not close certificate lifecycle, it makes it bite

## What R3 explicitly does not fix

| | Round |
|---|---|
| Certificate rotation, revocation, expiry, GDS — the identity is self-signed and permanent, and the sim accepts any application certificate | axis 10 |
| Modbus/TCP has no identity; exclusivity there is a network position | not code |
| The command path still has no requester identity — this is the *edge's* identity to the server, not the *operator's* to the edge | R1 |
| Commands still leave no tamper-evident record | R2 |
| Proven against `EmbeddedMiloSim`, not against a Kepware, an Ignition or a real PLC | open |
