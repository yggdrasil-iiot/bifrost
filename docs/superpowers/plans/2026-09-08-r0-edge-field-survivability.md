# R0 — Edge Field Survivability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Heimdall edge survive an unattended night at a plant — it starts whether or not the plant is up, reconnects to both the broker and the OPC-UA server on its own, announces its own death, keeps per-node command order, and reports its health — so that `docs/ADOPTION.md` phase 4 stops violating the rule that governs the whole document.

**Architecture:** All work is in the Paho/Milo *shell* around `NcmdOpcUaBridge.handle(...)`. The pure core stays pure and its existing tests stay green. Four seams are added: a striped executor replacing per-message `new Thread()`, a `PlantUnreachableException` that separates "the plant is not visible" from "policy said no", an `MqttCallbackExtended` reconnect path with a retained status will, and a JDK-only health endpoint.

**Tech Stack:** Java 17, Maven (`bifrost-parent` 0.2.0-SNAPSHOT), Eclipse Paho MQTT v3 (1.2.5), Eclipse Milo 1.0 (OPC-UA client), Eclipse Tahu (Sparkplug B), JUnit 5.10.3, `com.sun.net.httpserver` (JDK built-in — no new dependency), Docker.

---

## Why this round exists

`docs/ADOPTION.md:15` states the rule that orders every phase:

> **Nothing installed in the first phases may be capable of stopping the line.**

Phase 4 puts Heimdall in the command path. Today that violates the rule in four separate ways, none of which `ENFORCEMENT_LOG_ONLY` addresses — log-only inverts *refusal*, and each of these is *unavailability*:

| # | Today | Consequence at a plant |
|---|---|---|
| 1 | `NcmdOpcUaBridgeMain.java:245` does `new OpcUaApplier(config.opcua()).connect()` and lets the exception abort `main` | An edge that boots while its OPC-UA server is down **dies**, and under a restart policy it crash-loops. A site power event restarts both machines at once, so this is the ordinary case |
| 2 | `connectionLost()` only prints. No `setAutomaticReconnect`, `cleanSession(true)` | A broker blip leaves the process alive and subscribed to nothing, silently, forever |
| 3 | The OPC-UA client is built once at startup and never re-established. Every read failure hits `catch (Exception confEx) // fail-closed: … DENIES` | One OPC-UA server restart denies **every** command until a human restarts the bridge, and the operator is told `conformance-error`, which points at the model |
| 4 | No will message, no health endpoint, no counters anywhere in the repo | Nobody learns about 1–3 except by reading a log file |

Two more defects are in scope because they live in the same shell and are cheap:

| # | Today | Consequence |
|---|---|---|
| 5 | `NcmdOpcUaBridge.java:242` — `new MqttClient(broker, "bifrost-ncmd-bridge", …)`, a constant | Two edges on one broker take each other's session in a loop. `scripts/run-ncmd-runtime-gate.sh:161` already carries a `sleep 3` workaround commented "let the broker drop the session before the next edge claims the same client id" |
| 6 | `new Thread(() -> …).start()` per NCMD | No ordering between two setpoints for one node; no bound on thread creation |

**Not in scope, deliberately:** command identity (R1), a command ledger (R2), OPC-UA client certificates (R3), break-glass (R4), the Huginn↔Heimdall surface mismatch. This round moves no row on the `ENTERPRISE.md` board. It makes the row that phase 4 depends on honest.

---

## File structure

**Create:**

| Path | Responsibility |
|---|---|
| `heimdall/src/main/java/…/EdgeHealth.java` | Counters, liveness state, and the `/healthz` HTTP surface |
| `heimdall/src/main/java/…/PlantUnreachableException.java` | One job: mark a failure as "the plant is not visible", so it can never be confused with a verdict |
| `heimdall/src/main/java/…/CommandExecutor.java` | Striped, bounded dispatch — per-node FIFO with a fixed thread count and an explicit overload answer |
| `heimdall/src/main/java/…/TopicWatcher.java` | Gate-support: a tiny MQTT subscriber, the counterpart to the existing `RogueNcmd` publisher |
| `heimdall/Dockerfile`, `.dockerignore` | The edge as a deployable artifact |
| `scripts/run-edge-resilience-gate.sh` | The gate that proves all of the above by killing things |
| `heimdall/src/test/java/…/EdgeHealthTest.java` | Counters and the 200/503 rule |
| `heimdall/src/test/java/…/BridgeIdentityTest.java` | Client id derivation |
| `heimdall/src/test/java/…/CommandExecutorTest.java` | Ordering, concurrency, overload |
| `heimdall/src/test/java/…/OpcUaApplierFaultTest.java` | Connection-fault classification |

**Modify:**

| Path | Change |
|---|---|
| `heimdall/src/main/java/…/NcmdOpcUaBridge.java` | client id, `MqttCallbackExtended`, resubscribe, retained status + will, executor, unreachable branch, health wiring |
| `heimdall/src/main/java/…/OpcUaApplier.java` | connection-fault classification, lazy reconnect with backoff, thread safety |
| `heimdall/src/main/java/…/Applier.java` | javadoc only — name the new contract |
| `heimdall/src/main/java/…/NcmdOpcUaBridgeMain.java` | non-fatal first connect, `HEALTH_PORT`, `HEIMDALL_APPLY_THREADS`, `stopHttp()` in the existing shutdown hook |
| `heimdall/src/test/java/…/NcmdOpcUaBridgeTest.java` | the unreachable tests go **here**, where the fixtures already are |
| `heimdall/src/test/java/…/NcmdOpcUaBridgeMainConfigTest.java` | new config cases |
| `docker-compose.yml` | a `heimdall` service behind a compose profile |
| `docs/ADOPTION.md`, `README.md` | phase 4 properties; the new gate in the gate list; the test count |

### Facts verified against the real repo on 2026-09-08

Checked directly, so a surprise during implementation is read as a mistake in the edit rather than as a wrong assumption here.

| Fact | Verified |
|---|---|
| **`mvn -q -pl core,heimdall test -Dtest=X` FAILS** | Ran it. Surefire aborts in `bifrost-core` with `No tests matching pattern … were executed!` before heimdall is reached. **Every test command in this plan therefore appends `-Dsurefire.failIfNoSpecifiedTests=false`.** Do not drop it |
| The fake-applier idiom lives in `NcmdOpcUaBridgeTest` | `FakeApplier` is a package-private `static final class` at `NcmdOpcUaBridgeTest.java:235`, reused cross-file by qualified name at `NcmdBridgeLogOnlyTest.java:75`. `NcmdBridgePolicyTest` constructs **no** bridge and has no applier — it tests `CommandAuthorizer` directly |
| `bridge(applier)` has conformance **off** | `NcmdOpcUaBridgeTest.java:50` passes `null, null, null`, so `handle` skips the ② block entirely. The conformance-path catch needs `weldBridge(...)` (`:164`), whose policy has a real `CrossConstraint` and so actually calls `readDouble` |
| The shipped conformance fixture has no cross-constraints | `heimdall/registry/conformance/Line1-Mixer/1.0.0.json` — `"crossConstraints": []`. This is why Task 6 must log in **both** catches |
| A shutdown hook already exists | `NcmdOpcUaBridgeMain.java:250-257` calls `bridge.close()` then `applier.close()`. Do not add a second one |
| `MqttCallbackExtended` exists | Paho 1.2.5. It extends `MqttCallback`, so the bridge keeps its current methods and adds `connectComplete` |
| `StatusCodes.Bad_*` are usable | milo-stack-core 1.0.0. Declared on superclass `StatusCodes0` as `public static final long`, inherited, so `StatusCodes.Bad_ConnectionClosed` compiles. All nine used in Task 7 exist |
| `new StatusCode(long)`, `StatusCode.getValue(): long`, `StatusCode.GOOD`, `UaException.getStatusCode()` | All present |
| The log token for a denial is `[BRIDGE] DENY cmd=` | `NcmdOpcUaBridge.java:226`. The string `denied:` appears only in the NDATA **response**, never in the log — Task 13's E3 must assert against the right one |

### Two decisions locked here — do not re-open during implementation

**(a) The status topic is `bifrost/{group}/STATUS/{edge}`, not Sparkplug `NDEATH`.**
The obvious move is a Sparkplug death certificate, and it is wrong for this round. In `scripts/run-yggdrasil-spine-gate.sh`, Muninn is the node that births `Bifrost:Line1/recipe-edge`. Two components birthing one edge is a protocol error rather than a detail, and deciding who owns the Sparkplug node identity for an edge that Heimdall commands and Muninn feeds is a larger question than R0. `bifrost/…/STATUS/…` follows the existing `bifrost/…/QUERY/…` convention, carries retained `online`/`offline` bytes, needs no ownership decision, and gives ops what it actually needs. **Put this reason in the code comment** so the next reader does not "fix" it.

**(b) `PlantUnreachableException extends Exception`, not `UaException`.**
Extending `UaException` would be shorter and would fit inside `OpcUaApplier`'s existing `throws` clause. It would also drag Milo into the `Applier` seam, whose entire purpose is that the bridge core is testable with no OPC-UA present. Widen `OpcUaApplier`'s signatures to `throws Exception` instead — the `Applier` interface already declares exactly that. A useful consequence: the existing `catch (UaException transientRead)` in `OpcUaApplier.call`'s poll loop (`:128`) then lets a `PlantUnreachableException` propagate automatically, because it is not a `UaException`. No edit needed there beyond the signature.

---

## Chunk 1: Foundations

`EdgeHealth` comes first because Tasks 6 and 9 both call into it. Building it last would leave two tasks in the middle of the plan that cannot compile.

### Task 1: Health counters and `/healthz`

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeHealth.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeHealthTest.java`

Use `com.sun.net.httpserver.HttpServer` from the JDK. Do not add a dependency — the repo has no metrics stack and R0 is not the round that picks one.

- [ ] **Step 1: Write the failing test**

```java
package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EdgeHealthTest {

    @Test
    void startsUnhealthyUntilBothLegsAreUp() {
        EdgeHealth h = new EdgeHealth();
        assertFalse(h.healthy(), "an edge that has connected to nothing is not healthy");
        h.brokerConnected();
        assertFalse(h.healthy(), "broker alone is not enough - the plant leg matters too");
        h.plantReachable();
        assertTrue(h.healthy());
    }

    @Test
    void anUnreachablePlantMakesTheEdgeUnhealthy() {
        EdgeHealth h = new EdgeHealth();
        h.brokerConnected();
        h.plantReachable();
        h.plantUnreachable();
        assertFalse(h.healthy(), "the edge cannot be healthy while it cannot see the plant");
        assertEquals(1, h.unreachableCount());
    }

    @Test
    void aRecoveredPlantMakesItHealthyAgain() {
        EdgeHealth h = new EdgeHealth();
        h.brokerConnected();
        h.plantUnreachable();
        h.plantReachable();
        assertTrue(h.healthy(), "recovery must be reported, or /healthz latches unhealthy forever");
    }

    @Test
    void countersSeparateTheThreeOutcomes() {
        EdgeHealth h = new EdgeHealth();
        h.applied(); h.applied(); h.denied(); h.plantUnreachable();
        assertEquals(2, h.appliedCount());
        assertEquals(1, h.deniedCount());
        assertEquals(1, h.unreachableCount());
        String body = h.report();
        assertTrue(body.contains("applied 2"), body);
        assertTrue(body.contains("denied 1"), body);
        assertTrue(body.contains("plant_unreachable 1"), body);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=EdgeHealthTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: class EdgeHealth`

- [ ] **Step 3: Write minimal implementation**

```java
package dev.krillin.bifrost.heimdall;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

import com.sun.net.httpserver.HttpServer;

/**
 * The edge's own liveness and counters, plus a JDK-only {@code /healthz}.
 *
 * <p>The repo previously had no health surface at all, which meant the two failure modes this
 * round fixes — a deaf broker connection and an invisible plant — were discoverable only by
 * reading a log file. Health is deliberately the AND of both legs: an edge that is connected to
 * the broker but cannot see the plant answers every command with a refusal, and reporting that as
 * healthy is how a monitoring system learns to lie.
 */
public final class EdgeHealth {

    private final AtomicLong applied = new AtomicLong();
    private final AtomicLong denied = new AtomicLong();
    private final AtomicLong unreachable = new AtomicLong();

    private volatile boolean broker;
    private volatile boolean plant;
    private HttpServer server;

    public void brokerConnected()    { broker = true; }
    public void brokerDisconnected() { broker = false; }
    public void plantReachable()     { plant = true; }
    public void plantUnreachable()   { plant = false; unreachable.incrementAndGet(); }
    public void applied()            { applied.incrementAndGet(); plant = true; }
    public void denied()             { denied.incrementAndGet(); }

    public boolean healthy()       { return broker && plant; }
    public long appliedCount()     { return applied.get(); }
    public long deniedCount()      { return denied.get(); }
    public long unreachableCount() { return unreachable.get(); }

    /** Plain text, one metric per line — readable by a human and by a scraper, with no dependency. */
    public String report() {
        return "healthy " + (healthy() ? 1 : 0) + "\n"
             + "broker_connected " + (broker ? 1 : 0) + "\n"
             + "plant_reachable " + (plant ? 1 : 0) + "\n"
             + "applied " + applied.get() + "\n"
             + "denied " + denied.get() + "\n"
             + "plant_unreachable " + unreachable.get() + "\n";
    }

    /** @param port the listen port; {@code 0} disables the endpoint entirely. */
    public void startHttp(int port) throws IOException {
        if (port == 0) return;
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/healthz", exchange -> {
            byte[] body = report().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(healthy() ? 200 : 503, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("[BRIDGE] health endpoint on :" + port + "/healthz");
    }

    public void stopHttp() { if (server != null) server.stop(0); }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=EdgeHealthTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 4 tests

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/EdgeHealth.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/EdgeHealthTest.java
git commit -m "feat(heimdall): add edge health counters and a /healthz endpoint

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Derive the MQTT client id from the edge

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java:242`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/BridgeIdentityTest.java`

- [ ] **Step 1: Write the failing test**

```java
package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class BridgeIdentityTest {

    @Test
    void clientIdIsDerivedFromGroupAndEdge() {
        assertEquals("heimdall-Bifrost-Line1-recipe-edge",
                NcmdOpcUaBridge.clientId("Bifrost:Line1", "recipe-edge"));
    }

    @Test
    void twoEdgesNeverShareAClientId() {
        assertNotEquals(NcmdOpcUaBridge.clientId("Bifrost:Line1", "recipe-edge"),
                        NcmdOpcUaBridge.clientId("Bifrost:Line1", "mixer-edge"));
    }

    /** A group like "Bifrost:Line1" carries separators a broker rejects in a client id. */
    @Test
    void separatorsAreFolded() {
        assertEquals("heimdall-a-b-c-d", NcmdOpcUaBridge.clientId("a/b:c", "d"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=BridgeIdentityTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: method clientId(String,String)`

- [ ] **Step 3: Write minimal implementation**

Add to `NcmdOpcUaBridge` (package-private static, so the test reaches it without widening the public API):

```java
    /**
     * MQTT client id for this edge. It MUST be per-edge: two bridges sharing an id take each
     * other's session in a loop, which is exactly what the previous constant caused. ':' and '/'
     * are folded because a group such as "Bifrost:Line1" carries the Sparkplug topic separator,
     * which brokers reject inside a client id.
     *
     * <p>The result can exceed the 23 characters MQTT 3.1 guaranteed; 3.1.1 removed that limit and
     * HiveMQ accepts it. If another broker is ever targeted, this is the line to shorten.
     */
    static String clientId(String group, String edge) {
        return ("heimdall-" + group + "-" + edge).replaceAll("[:/]", "-");
    }
```

Then in `connect(String broker)` replace the constant:

```java
        client = new MqttClient(broker, clientId(group, edge), new MemoryPersistence());
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=BridgeIdentityTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/BridgeIdentityTest.java
git commit -m "fix(heimdall): derive the MQTT client id from the edge

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Striped, bounded command dispatch

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/CommandExecutor.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/CommandExecutorTest.java`

Background: `messageArrived` currently does `new Thread(...).start()` per message. One correctness problem — two setpoints for the same node can be applied out of order, and in a write path order is not cosmetic — and one resource problem: anything that can publish can create threads without limit. The fix is a fixed set of single-threaded executors with the node id hashed onto one, so FIFO holds per node while the thread count stays fixed.

- [ ] **Step 1: Write the failing test**

```java
package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class CommandExecutorTest {

    /** The reason this class exists: same node, same order, whatever the stripe count. */
    @Test
    void commandsForOneNodeRunInSubmissionOrder() throws Exception {
        try (CommandExecutor ex = new CommandExecutor(4, 64)) {
            List<Integer> seen = Collections.synchronizedList(new ArrayList<>());
            CountDownLatch done = new CountDownLatch(50);
            for (int i = 0; i < 50; i++) {
                final int n = i;
                assertTrue(ex.submit("ns=2;s=Recipe/Rpm", () -> { seen.add(n); done.countDown(); }));
            }
            assertTrue(done.await(10, TimeUnit.SECONDS), "tasks did not finish");
            for (int i = 0; i < 50; i++) assertEquals(i, seen.get(i), "reordered at " + i);
        }
    }

    /** Ordering is per node, not global: a slow node must not block a different one. */
    @Test
    void differentNodesAreNotSerializedBehindEachOther() throws Exception {
        try (CommandExecutor ex = new CommandExecutor(8, 64)) {
            CountDownLatch hold = new CountDownLatch(1);
            CountDownLatch other = new CountDownLatch(1);
            String slow = "node-a";
            String fast = keyOnADifferentStripe(slow, 8);
            ex.submit(slow, () -> await(hold));
            ex.submit(fast, other::countDown);
            assertTrue(other.await(5, TimeUnit.SECONDS), fast + " waited behind " + slow);
            hold.countDown();
        }
    }

    /** Overload is answered, never silently dropped — the operator has to be told something true. */
    @Test
    void submitReturnsFalseWhenTheQueueIsFull() throws Exception {
        try (CommandExecutor ex = new CommandExecutor(1, 1)) {
            CountDownLatch hold = new CountDownLatch(1);
            AtomicInteger rejected = new AtomicInteger();
            ex.submit("n", () -> await(hold));
            for (int i = 0; i < 20; i++) if (!ex.submit("n", () -> { })) rejected.incrementAndGet();
            assertTrue(rejected.get() > 0, "a full bounded queue must reject rather than grow");
            hold.countDown();
        }
    }

    private static void await(CountDownLatch l) {
        try { l.await(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
    }

    /** Pick a key on another stripe, so the concurrency test asserts a property and not luck. */
    private static String keyOnADifferentStripe(String other, int stripes) {
        int target = Math.floorMod(other.hashCode(), stripes);
        for (int i = 0; i < 10_000; i++) {
            String c = "node-" + i;
            if (Math.floorMod(c.hashCode(), stripes) != target) return c;
        }
        throw new IllegalStateException("no key on a different stripe");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=CommandExecutorTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: class CommandExecutor`

- [ ] **Step 3: Write minimal implementation**

```java
package dev.krillin.bifrost.heimdall;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Bounded, striped dispatch for incoming commands — the replacement for one {@code new Thread()}
 * per NCMD.
 *
 * <p>Two properties the thread-per-message version lacked:
 * <ul>
 *   <li><b>Per-node order.</b> A node id always hashes to the same single-threaded stripe, so two
 *       setpoints for one node are applied in arrival order. Order in a write path is a
 *       correctness property, not a nicety.</li>
 *   <li><b>A bound.</b> The thread count is fixed and each stripe's queue is bounded, so publish
 *       volume cannot become thread count. A full queue is REPORTED ({@code submit} returns false)
 *       rather than dropped, because the operator who issued the command has to be answered.</li>
 * </ul>
 */
public final class CommandExecutor implements AutoCloseable {

    private final ThreadPoolExecutor[] stripes;

    public CommandExecutor(int stripeCount, int queueDepth) {
        if (stripeCount < 1) throw new IllegalArgumentException("stripeCount < 1");
        if (queueDepth < 1) throw new IllegalArgumentException("queueDepth < 1");
        this.stripes = new ThreadPoolExecutor[stripeCount];
        for (int i = 0; i < stripeCount; i++) {
            final int n = i;
            stripes[i] = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(queueDepth),
                    r -> {
                        Thread t = new Thread(r, "heimdall-apply-" + n);
                        t.setDaemon(true);
                        return t;
                    });
        }
    }

    /** @return true if accepted; false if this node's stripe queue is full. */
    public boolean submit(String nodeId, Runnable task) {
        int idx = Math.floorMod(nodeId == null ? 0 : nodeId.hashCode(), stripes.length);
        try {
            stripes[idx].execute(task);
            return true;
        } catch (RejectedExecutionException full) {
            return false;
        }
    }

    @Override
    public void close() {
        for (ThreadPoolExecutor s : stripes) s.shutdownNow();
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=CommandExecutorTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/CommandExecutor.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/CommandExecutorTest.java
git commit -m "feat(heimdall): add striped bounded command dispatch

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Wire health and the executor into the bridge

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeTest.java` (add cases)

- [ ] **Step 1: Add the fields and the final constructor**

`NcmdOpcUaBridgeMain.java:248` calls the existing 8-arg constructor. **Adding parameters to it breaks `main`'s compile.** Add a new widest constructor and have both existing ones delegate, so no current caller or test changes:

```java
    private final CommandExecutor executor;
    private final EdgeHealth health;

    /** The widest constructor. The two shorter ones below delegate here with the field defaults. */
    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy,
                           MasterSpec activeRecipe, boolean logOnly,
                           EdgeHealth health, int applyThreads, int applyQueueDepth) { … }
```

The existing 8-arg constructor delegates with `new EdgeHealth(), 4, 64`; the existing 7-arg one keeps delegating to the 8-arg one. Add `public EdgeHealth health() { return health; }` for `NcmdOpcUaBridgeMain`.

Wire the counters:

- `health.denied()` inside `refuse(...)` **on the enforcing path only** — a log-only would-deny is not a denial and must not be counted as one, exactly as the two log tokens are kept distinct there.
- `health.applied()` where `[BRIDGE] APPLY` is printed, when `r.ok()`.

- [ ] **Step 2: Replace the thread-per-message dispatch**

```java
    @Override public void messageArrived(String topic, MqttMessage message) {
        // Publishing from the MQTT callback thread is not allowed; dispatch off-thread. The stripe
        // key is the command's node id, so two setpoints for one node keep their arrival order.
        byte[] payload = message.getPayload();
        final SparkplugBPayload req;
        try {
            req = decoder.buildFromByteArray(payload, null);
        } catch (Exception decodeFailure) {
            System.out.println("[BRIDGE] DROP undecodable payload on " + topic + ": " + decodeFailure);
            return;
        }
        String stripeKey = (req.getMetrics() == null || req.getMetrics().isEmpty())
                ? "" : String.valueOf(req.getMetrics().get(0).getName());
        boolean accepted = executor.submit(stripeKey, () -> {
            try {
                NcmdResponse resp = handle(topic, req);
                client.publish(ndataTopic, encodeResponse(resp), 1, false);
            } catch (Exception e) {
                System.out.println("[BRIDGE] response publish failed for " + stripeKey + ": " + e);
            }
        });
        if (!accepted) {
            System.out.println("[BRIDGE] OVERLOAD cmd=" + stripeKey + " - queue full, command refused");
            try {
                client.publish(ndataTopic,
                        encodeResponse(overloaded(req.getUuid())), 1, false);
            } catch (Exception e) {
                System.out.println("[BRIDGE] overload response publish failed: " + e);
            }
        }
    }

    /** The overload refusal, extracted so a unit test can assert its wording without a broker. */
    static NcmdResponse overloaded(String cmdId) {
        return NcmdResponse.apply(cmdId, false, "overloaded: edge queue full");
    }
```

Add `executor.close();` as the first statement of `close()`.

- [ ] **Step 3: Write the tests for what this task introduced**

`messageArrived` needs a live `MqttClient`, so it is gate territory. The two decisions inside it are not — assert those. Add to `NcmdOpcUaBridgeTest`:

```java
    @Test void overload_refusal_is_a_refusal_and_says_why() {
        NcmdResponse r = NcmdOpcUaBridge.overloaded("c-9");
        assertFalse(r.ok(), "an overloaded edge must not report success for a command it never ran");
        assertEquals("c-9", r.cmdId(), "the refusal must correlate, or the caller cannot match it");
        assertTrue(r.detail().contains("overloaded"), r.detail());
    }

    @Test void counters_separate_applied_from_denied() throws Exception {
        EdgeHealth h = new EdgeHealth();
        NcmdOpcUaBridge b = new NcmdOpcUaBridge(GROUP, EDGE, policy(), new FakeApplier(),
                null, null, null, false, h, 4, 64);
        b.handle(NCMD_TOPIC, cmd("c-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        b.handle(NCMD_TOPIC, cmd("c-2", "write", "ns=2;s=Nope", 1.0, MetricDataType.Double, null, null));
        assertEquals(1, h.appliedCount());
        assertEquals(1, h.deniedCount());
    }
```

- [ ] **Step 4: Run the whole heimdall suite**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS — every pre-existing test still green. `handle(...)`'s logic was not changed, which is the point of the seam.

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeTest.java
git commit -m "fix(heimdall): dispatch NCMD through the striped executor, and count outcomes

Also stops an undecodable payload from becoming an unhandled throw on a
throwaway thread, and answers an overloaded queue instead of dropping it.
A log-only would-deny is not counted as a denial, matching the existing
rule that keeps the two log tokens distinct.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 2: Reachability

The load-bearing chunk. Today an OPC-UA outage is reported as `conformance-error`, which tells the operator the model is wrong, and denies every command until a human restarts the process.

**A warning for the implementer.** Unreachable must NOT become an allow. The bridge still refuses to act — it cannot confirm a write it cannot make. What changes is the *reason* the operator is given, the counter it increments, and the fact that the next command retries the connection instead of inheriting a dead client.

### Task 5: The exception

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/PlantUnreachableException.java`
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/Applier.java` (javadoc only)

- [ ] **Step 1: Write the class**

```java
package dev.krillin.bifrost.heimdall;

/**
 * The plant could not be reached, so no verdict was possible.
 *
 * <p>This exists to keep one distinction the bridge previously lost: <b>"policy refused this
 * command" and "I cannot see the machine" are different events</b>, and collapsing them told the
 * operator that the model was wrong when the truth was that a server had restarted. It also drives
 * reconnection — a verdict is final, an unreachable plant is worth retrying.
 *
 * <p>It deliberately extends {@link Exception} rather than Milo's {@code UaException}: the
 * {@link Applier} seam exists so the bridge core is testable with no OPC-UA present, and typing the
 * seam to Milo would give that up for one line of brevity.
 */
public final class PlantUnreachableException extends Exception {
    public PlantUnreachableException(String message, Throwable cause) { super(message, cause); }
    public PlantUnreachableException(String message) { super(message); }
}
```

In `Applier`, extend the interface javadoc with one paragraph:

```java
 * <p>Any method here may throw {@link PlantUnreachableException} to say the plant was not visible.
 * That is not a verdict: the bridge answers with a distinct reason code and retries the connection,
 * rather than reporting it as a policy or conformance refusal.
```

- [ ] **Step 2: Compile**

Run: `mvn -q -pl core,heimdall test-compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/PlantUnreachableException.java heimdall/src/main/java/dev/krillin/bifrost/heimdall/Applier.java
git commit -m "feat(heimdall): name the unreachable-plant failure

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: The bridge answers unreachable distinctly

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java:190` (the `catch (Exception confEx)` block) and the apply-path catch near `:208`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeTest.java` (add cases)

The tests go in `NcmdOpcUaBridgeTest` because that is where `FakeApplier`, `policy()`, `bridge(...)`, `weldBridge(...)` and `cmd(...)` already live. Do not create a parallel helper class.

- [ ] **Step 1: Extend `FakeApplier`, then write two failing tests**

`FakeApplier` already has `throwOnReadDoubleNode` (`NcmdOpcUaBridgeTest.java:245`), which throws a plain `Exception`. Add one field beside it so a test can choose *which* failure:

```java
        boolean readDoubleUnreachable;   // when set, readDouble throws PlantUnreachableException
        boolean writeUnreachable;        // when set, write throws PlantUnreachableException
```

and honour them in `readDouble` and `write` (both already declare `throws Exception` on the interface; widen `write`'s signature in `FakeApplier` to match).

**Two tests, because there are two catches and they take different paths.** The conformance-path one needs `weldBridge(...)`: `bridge(applier)` passes `null, null, null` for conformance, so `handle` skips the ② block entirely and would never reach that catch.

```java
    @Test void unreachable_plant_on_the_apply_path_is_not_reported_as_a_denial() throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.writeUnreachable = true;
        // Rpm=1500 is ALLOWED by registry/policy.json, so any refusal here is about reachability.
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("u-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));

        assertFalse(r.ok(), "the edge must not claim success for a write it could not make");
        assertTrue(r.detail().contains("plant-unreachable"), r.detail());
        assertFalse(r.detail().contains("denied:"), "not a policy denial: " + r.detail());
    }

    @Test void unreachable_plant_on_the_conformance_path_is_not_reported_as_conformance_error()
            throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.readDoubleUnreachable = true;   // the cross-member sibling read is what fails
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("u-2", "write", WELD_NODE, 5.0, MetricDataType.Double, null, null));

        assertFalse(r.ok());
        assertTrue(r.detail().contains("plant-unreachable"), r.detail());
        assertFalse(r.detail().contains("conformance-error"),
                "an outage must not send the operator to look at the model: " + r.detail());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL on both. The apply-path detail reads `apply error: …`; the conformance-path detail reads `denied: conformance-error: …`. **The second is the one this round is about.**

- [ ] **Step 3: Write minimal implementation**

Conformance-path catch, inserted **before** the existing `catch (Exception confEx)`:

```java
                } catch (PlantUnreachableException unreachable) {
                    // NOT a verdict. The plant is not visible, so ② could not be evaluated at all.
                    // Reported separately so an operator is never sent to look at the model because
                    // a server restarted, and counted separately so /healthz can go unhealthy.
                    System.out.println("[BRIDGE] UNREACHABLE cmd=" + name + " reason=" + unreachable.getMessage());
                    health.plantUnreachable();
                    return NcmdResponse.apply(cmdId, false,
                            detail(shadowed, "plant-unreachable: " + unreachable.getMessage()));
                } catch (Exception confEx) {   // fail-closed: any conformance/read error DENIES
```

Apply-path catch:

```java
        } catch (PlantUnreachableException unreachable) {
            System.out.println("[BRIDGE] UNREACHABLE cmd=" + name + " reason=" + unreachable.getMessage());
            health.plantUnreachable();
            return NcmdResponse.apply(cmdId, false,
                    detail(shadowed, "plant-unreachable: " + unreachable.getMessage()));
        } catch (Exception e) {
```

**Two properties both catches must share, and both are easy to get wrong:**

1. **Both print `[BRIDGE] UNREACHABLE`.** Task 13's E3 reads stdout. The shipped fixture `heimdall/registry/conformance/Line1-Mixer/1.0.0.json` has `"crossConstraints": []`, so `readDouble` is never called there and an outage always surfaces on the apply path. Log only there and E3 passes for a reason unrelated to the conformance branch — then someone adds one cross-constraint to that fixture and the gate breaks with no code change.
2. **Both go through `detail(shadowed, …)`.** In log-only mode a ① authz verdict is already recorded in `shadowed` (`NcmdOpcUaBridge.java:149-153`). Returning the bare string drops it, contradicting the rule documented at `:230-237` — *"the operator who issued the command is the person who most needs to know it would have been blocked"*.

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS

- [ ] **Step 5: Run the whole suite — this is the regression that matters**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS. In particular `NcmdBridgeLogOnlyTest` and the existing `conformance_cross_member_violation_*` tests must be untouched: a genuine conformance failure must still read `conformance-error`, and a genuine policy refusal must still read `denied:`. If either changed, the new catch is too wide.

- [ ] **Step 6: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeTest.java
git commit -m "fix(heimdall): separate an unreachable plant from a verdict

An OPC-UA outage was reported as conformance-error, which sends the
operator to look at the model. It is still a refusal; it is not a denial.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: The OPC-UA client re-establishes its own session

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/OpcUaApplier.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/OpcUaApplierFaultTest.java`

Only the status-code classification is unit-testable without a server; the reconnect itself is proved by the gate in Task 13. Test what can be tested purely, and do not fake a server to feel covered.

- [ ] **Step 1: Write the failing test**

```java
package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.junit.jupiter.api.Test;

class OpcUaApplierFaultTest {

    @Test
    void transportFaultsAreConnectionFaults() {
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_ConnectionClosed)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_SessionIdInvalid)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_ServerNotConnected)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_NotConnected)));
    }

    /** A value-level fault is NOT a connection fault — misclassifying it would hide a real refusal. */
    @Test
    void valueFaultsAreNotConnectionFaults() {
        assertFalse(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_OutOfRange)));
        assertFalse(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_TypeMismatch)));
        assertFalse(OpcUaApplier.isConnectionFault(StatusCode.GOOD));
        assertFalse(OpcUaApplier.isConnectionFault(null));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl core,heimdall test -Dtest=OpcUaApplierFaultTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — `cannot find symbol: method isConnectionFault`

- [ ] **Step 3: Write minimal implementation**

Widen the `throws` on `read`, `readDouble`, `write` and `call` from `UaException` to `Exception` (the `Applier` interface already permits it), and add:

```java
    private static final long BACKOFF_MS = 5_000L;

    /**
     * Written by {@link #ensureConnected()} under its own lock and read by every apply stripe, so
     * it must be volatile: Task 3 made the apply path genuinely concurrent, and before that this
     * field was written exactly once at startup.
     */
    private volatile OpcUaClient client;
    private volatile boolean connected;
    private volatile long nextRetryAt;

    /**
     * Is this status a transport/session fault rather than a verdict about a value? Only the former
     * means "the plant is not visible"; classifying Bad_OutOfRange as a connection fault would hide
     * a real refusal behind a retry.
     *
     * <p>{@code Bad_Timeout} is included as a judgement call: a server slow enough to time out is
     * one the edge cannot confirm a write against, and the backoff bounds the cost. If a site sees
     * healthy-but-slow servers flapping into plant-unreachable, this is the line to revisit.
     */
    static boolean isConnectionFault(StatusCode sc) {
        if (sc == null) return false;
        long v = sc.getValue();
        return v == StatusCodes.Bad_ConnectionClosed
                || v == StatusCodes.Bad_SessionIdInvalid
                || v == StatusCodes.Bad_SessionClosed
                || v == StatusCodes.Bad_ServerNotConnected
                || v == StatusCodes.Bad_NotConnected
                || v == StatusCodes.Bad_SecureChannelClosed
                || v == StatusCodes.Bad_Timeout;
    }

    /**
     * Ensure a usable session, or say the plant is unreachable.
     *
     * <p>{@code synchronized} because the apply path is striped: without it two stripes can both
     * enter, both call {@code OpcUaClient.create(...).connect()}, and one client leaks while other
     * threads see a half-published reference. The backoff guard is the second point — a dead server
     * must not be hammered once per command, and a command arriving inside the window is answered
     * immediately rather than made to wait out a connect timeout.
     */
    private synchronized void ensureConnected() throws PlantUnreachableException {
        if (connected && client != null) return;
        long now = System.currentTimeMillis();
        if (now < nextRetryAt) {
            throw new PlantUnreachableException("OPC-UA disconnected; next retry in " + (nextRetryAt - now) + "ms");
        }
        try {
            if (client != null) {
                try { client.disconnect(); } catch (Exception ignore) { /* best-effort */ }
            }
            client = OpcUaClient.create(endpoint);
            client.connect();
            connected = true;
            if (health != null) health.plantReachable();
            System.out.println("[BRIDGE] OPC-UA session re-established to " + endpoint);
        } catch (Exception e) {
            connected = false;
            nextRetryAt = now + BACKOFF_MS;
            throw new PlantUnreachableException("OPC-UA connect to " + endpoint + " failed: " + e.getMessage(), e);
        }
    }

    /** Mark the session dead so the next command reconnects instead of inheriting a dead client. */
    private synchronized PlantUnreachableException fault(String what, Throwable cause) {
        connected = false;
        nextRetryAt = System.currentTimeMillis() + BACKOFF_MS;
        if (health != null) health.plantUnreachable();
        return new PlantUnreachableException(what, cause);
    }
```

`OpcUaApplier` gains an `EdgeHealth health` constructor parameter (nullable — keep the existing one-arg constructor delegating with `null` so current tests are untouched). `connect()` sets `connected = true` and calls `health.plantReachable()` on success.

Every operation begins with `ensureConnected();`, wraps its Milo call so a thrown `UaException` whose status `isConnectionFault` becomes `throw fault(...)`, and converts a returned bad `StatusCode` the same way. A non-connection fault keeps its current behaviour exactly.

Worked example for `read`:

```java
    @Override
    public ReadBack read(String nodeId) throws Exception {
        ensureConnected();
        DataValue dv;
        try {
            dv = client.readValue(0.0, TimestampsToReturn.Neither, NodeId.parse(nodeId));
        } catch (UaException e) {
            if (isConnectionFault(e.getStatusCode())) throw fault("read " + nodeId + ": " + e.getMessage(), e);
            throw e;
        }
        if (isConnectionFault(dv.getStatusCode())) {
            throw fault("read " + nodeId + ": " + dv.getStatusCode(), null);
        }
        Object v = dv.getValue() != null ? dv.getValue().getValue() : null;
        boolean good = dv.getStatusCode() != null && dv.getStatusCode().isGood();
        return new ReadBack(v != null ? v.toString() : null, good);
    }
```

**`call` has three separate Milo call sites** — the baseline read, the trigger write, and the poll loop — and each needs the same treatment. The poll loop's existing `catch (UaException transientRead)` (`:128`) needs **no change**: a `PlantUnreachableException` is not a `UaException`, so it propagates out of the method by itself once the signature is widened. A closed session must not be swallowed into the deadline.

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl core,heimdall test -Dtest=OpcUaApplierFaultTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS, 2 tests

- [ ] **Step 5: Run the whole suite**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/OpcUaApplier.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/OpcUaApplierFaultTest.java
git commit -m "feat(heimdall): re-establish the OPC-UA session after a fault

The client was built once at startup, so one server restart denied every
command until a human restarted the bridge. Lazy reconnect behind a
backoff, guarded for the striped apply path, and only transport faults
count as unreachable.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: The edge boots while the plant is down

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java:245`

Task 7 makes reconnect lazy *after* a successful start. Startup itself is still eager and still fatal:

```java
        OpcUaApplier applier = new OpcUaApplier(config.opcua()).connect();   // throws, aborts main
```

An edge that boots while the OPC-UA server is down dies on this line — and under Task 11's `restart: unless-stopped` it crash-loops. A site power event restarts both machines at once, so this is the ordinary case.

**Keep one distinction sharp.** This removes die-on-boot for *"the plant is not up yet"*. It does **not** touch `assertLedgerTrustworthy` / `assertActivationAuthorized`, which fail closed on purpose: a bridge that cannot trust the model it checks against must not start. An invisible machine is transient; an untrustworthy model is not.

- [ ] **Step 1: Make the first connect non-fatal**

```java
        // Connect eagerly so a healthy start is still reported as one, but do NOT die if the plant
        // is down: a site power event restarts the server and this edge together, and an edge that
        // exits here crash-loops under a restart policy instead of waiting. Task 7's lazy reconnect
        // brings the session up on the first command that needs it.
        //
        // This does not weaken the startup ledger-trust checks above. Those still fail closed: an
        // invisible machine is transient, an untrustworthy model is not.
        OpcUaApplier applier = new OpcUaApplier(config.opcua(), health);
        try {
            applier.connect();
            System.out.println("[BRIDGE] OPC-UA connected " + config.opcua());
        } catch (Exception plantDown) {
            System.out.println("[BRIDGE] OPC-UA not reachable at start (" + plantDown.getMessage()
                    + ") - starting anyway, commands will answer plant-unreachable until it returns");
        }
```

- [ ] **Step 2: Verify by hand, with the sim deliberately not running**

```bash
mvn -q -pl core,heimdall,sim install
docker compose -f docker-compose.yml up -d hivemq-ce
java -jar heimdall/target/bifrost-heimdall.jar
```
Expected: the log prints `OPC-UA not reachable at start` **and then `[BRIDGE] ready`**, and the process stays up. Before this change it exits without reaching `ready`. Stop it with Ctrl-C.

- [ ] **Step 3: Run the whole suite**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java
git commit -m "fix(heimdall): boot the edge even when the plant is down

The eager connect at startup threw and killed the process, so an edge
that came up before its OPC-UA server crash-looped under a restart
policy. The ledger-trust checks still fail closed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 3: Liveness

### Task 9: MQTT auto-reconnect, resubscribe, and a retained status will

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java`

Paho detail the implementer needs: with `setAutomaticReconnect(true)` and `cleanSession(true)`, the broker discards the session on disconnect, so **subscriptions do not come back by themselves**. The hook is `MqttCallbackExtended.connectComplete(boolean reconnect, String serverURI)`. Change the class to implement `MqttCallbackExtended` (it extends `MqttCallback`, so the existing methods stay) and resubscribe there. Without the resubscribe, auto-reconnect produces a *connected* bridge that receives nothing, which is worse than the current bug because the log looks healthy.

- [ ] **Step 1: Rewrite `connect` and add `connectComplete`**

Add `statusTopic` to the constructor: `"bifrost/" + group + "/STATUS/" + edge`.

```java
    public void connect(String broker) throws Exception {
        client = new MqttClient(broker, clientId(group, edge), new MemoryPersistence());
        client.setCallback(this);
        MqttConnectOptions opts = new MqttConnectOptions();
        opts.setCleanSession(true);
        opts.setAutomaticReconnect(true);
        // Explicit, because the will's latency is this value: the broker cannot declare us dead
        // until the keepalive lapses, and the default 60s makes a death take ~90s to appear.
        opts.setKeepAliveInterval(20);
        // The will is the whole liveness story: if this process dies, is partitioned, or hangs past
        // the keepalive, the BROKER publishes "offline" on our behalf. Nothing else can report a
        // death the dying process did not notice.
        //
        // This is deliberately NOT the Sparkplug NDEATH topic. In the spine, Muninn is the node that
        // births this group/edge, and two components birthing one edge is a protocol error rather
        // than a detail. Deciding who owns the Sparkplug node identity is a larger question than
        // this change; "bifrost/.../STATUS/..." follows the existing "bifrost/.../QUERY/..."
        // convention and needs no ownership decision.
        opts.setWill(statusTopic, "offline".getBytes(StandardCharsets.UTF_8), 1, true);
        client.connect(opts);
        subscribeAll();
        publishStatus("online");
        System.out.println("[BRIDGE] subscribed NCMD=" + ncmdTopic + " QUERY=" + queryTopic
                + " (policy rules=" + policy.rules().size() + ")");
    }

    private void subscribeAll() throws Exception {
        client.subscribe(ncmdTopic, 1);
        client.subscribe(queryTopic, 1);
    }

    private void publishStatus(String state) {
        try {
            client.publish(statusTopic, state.getBytes(StandardCharsets.UTF_8), 1, true);
        } catch (Exception e) {
            System.out.println("[BRIDGE] status publish failed (" + state + "): " + e);
        }
    }

    @Override
    public void connectComplete(boolean reconnect, String serverURI) {
        health.brokerConnected();
        if (!reconnect) return;   // the initial connect already subscribed and announced
        // cleanSession(true) means the broker dropped our subscriptions with the session. Without
        // this the bridge comes back CONNECTED and deaf, which reads healthy in the log.
        //
        // This runs on Paho's callback thread and both calls below are synchronous, so the callback
        // is blocked until they ack. That is the standard resubscribe pattern and the window is
        // bounded, but it is why nothing heavier belongs here.
        try {
            subscribeAll();
            publishStatus("online");
            System.out.println("[BRIDGE] reconnected to " + serverURI + ", resubscribed");
        } catch (Exception e) {
            System.out.println("[BRIDGE] RESUBSCRIBE FAILED after reconnect: " + e);
        }
    }

    @Override public void connectionLost(Throwable cause) {
        health.brokerDisconnected();
        System.out.println("[BRIDGE] connection lost: " + cause + " (auto-reconnect armed)");
    }
```

Change the class declaration to `implements MqttCallbackExtended` and add the imports. In `close()`, publish `offline` before disconnecting, so an orderly shutdown is not reported as a death.

- [ ] **Step 2: Run the whole suite**

Run: `mvn -q -pl core,heimdall test`
Expected: PASS — no unit test covers the Paho shell; Task 13's gate is what proves this.

- [ ] **Step 3: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridge.java
git commit -m "feat(heimdall): auto-reconnect, resubscribe, and a retained status will

connectionLost only printed, so a broker blip left the process alive and
subscribed to nothing. cleanSession drops subscriptions with the session,
so the resubscribe in connectComplete is load-bearing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Chunk 4: Configuration and packaging

### Task 10: Configuration

**Files:**
- Modify: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java`
- Test: `heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMainConfigTest.java`

- [ ] **Step 1: Write the failing tests**

Add to the existing config test, following its established style:

```java
    @Test
    void healthPortDefaultsTo9090AndZeroDisables() {
        assertEquals(9090, NcmdOpcUaBridgeMain.resolve(k -> null).healthPort());
        assertEquals(0, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "0" : null).healthPort());
    }

    @Test
    void healthPortIsReadFromTheEnvironment() {
        assertEquals(9091, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "9091" : null).healthPort());
    }

    /** A garbled port must not silently pick a different one — fall to the default and say so. */
    @Test
    void anUnparseableHealthPortFallsToTheDefault() {
        assertEquals(9090, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "banana" : null).healthPort());
    }

    @Test
    void applyThreadsDefaultToFour() {
        assertEquals(4, NcmdOpcUaBridgeMain.resolve(k -> null).applyThreads());
    }

    /** The default alone is satisfied by a hard-coded 4 — prove the variable is actually read. */
    @Test
    void applyThreadsAreReadFromTheEnvironment() {
        assertEquals(8, NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_APPLY_THREADS".equals(k) ? "8" : null).applyThreads());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeMainConfigTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — no `healthPort()` on the record

- [ ] **Step 3: Write minimal implementation**

Add `int healthPort` and `int applyThreads` to the `Config` record, plus an `intEnv(getenv, key, default)` helper mirroring the existing `flag(...)` idiom — unparseable values fall to the default with a loud `WARN` on stderr, because a mis-set port that silently moves is the same class of bug the flag parser already guards.

In `main`: create the `EdgeHealth` before the applier (Task 8 hands it in), call `health.startHttp(config.healthPort())`, and pass `health` and `applyThreads` to the widest bridge constructor.

**Do not add a shutdown hook — one already exists** at `NcmdOpcUaBridgeMain.java:250-257`, calling `bridge.close()` then `applier.close()`. Task 9 makes `bridge.close()` publish `offline`, so an orderly stop is already covered. What that hook is missing is `health.stopHttp()`; add it there, or the HTTP server is started and never stopped.

Extend the class javadoc's env block:

```
 *   HEALTH_PORT            9090       (0 disables the endpoint)
 *   HEIMDALL_APPLY_THREADS 4          (per-node ordering stripes)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q -pl core,heimdall test -Dtest=NcmdOpcUaBridgeMainConfigTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMain.java heimdall/src/test/java/dev/krillin/bifrost/heimdall/NcmdOpcUaBridgeMainConfigTest.java
git commit -m "feat(heimdall): configure the health port and apply threads

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: A container for the edge

**Files:**
- Create: `heimdall/Dockerfile`, `.dockerignore`
- Modify: `docker-compose.yml`

- [ ] **Step 1: Write `.dockerignore`**

The build context is the repo root, which currently carries `build/`, `target/` and `.git`.

```
.git
**/target
build
docs
*.md
```

- [ ] **Step 2: Write the Dockerfile**

```dockerfile
# The edge as a deployable artifact. Build from the repo root:
#   mvn -q -pl core,heimdall,sim install
#   docker build -f heimdall/Dockerfile -t bifrost/heimdall:dev .
FROM eclipse-temurin:17-jre
WORKDIR /opt/heimdall
COPY heimdall/target/bifrost-heimdall.jar app.jar
# The registry is mounted, never baked: the governed model is the site's, and an image that
# carries one hides which copy is being run. There is deliberately no VOLUME line - it would
# create an empty anonymous volume on a `docker run` without -v and turn a clear "policy.json
# missing" into a confusing empty mount.
ENV REGISTRY_PATH=/opt/heimdall/registry \
    POLICY_PATH=/opt/heimdall/registry/policy.json \
    HEALTH_PORT=9090
EXPOSE 9090
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:9090/healthz || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]
```

Confirm `wget` exists in `eclipse-temurin:17-jre` (`docker run --rm eclipse-temurin:17-jre which wget`); if it does not, switch the HEALTHCHECK to a `java -cp app.jar` one-liner rather than installing a package.

- [ ] **Step 3: Add a profiled compose service**

Append to `docker-compose.yml`. **The profile is required**: every existing gate runs `docker compose up -d hivemq-ce`, and an unprofiled service here would change what those gates start.

```yaml
  # Not started by default. Existing gates run `up -d hivemq-ce` and must keep getting only that.
  #   docker compose --profile edge up -d heimdall
  heimdall:
    profiles: ["edge"]
    image: bifrost/heimdall:dev
    build:
      context: .
      dockerfile: heimdall/Dockerfile
    container_name: bifrost-heimdall
    depends_on:
      - hivemq-ce
    environment:
      MQTT_URL: "tcp://hivemq-ce:1883"
      OPCUA_URL: "opc.tcp://host.docker.internal:48400"
      SPB_GROUP: "Bifrost:Line1"
      SPB_EDGE: "recipe-edge"
    # Required for host.docker.internal outside Docker Desktop, and harmless on it.
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./heimdall/registry:/opt/heimdall/registry:ro
    ports:
      - "9090:9090"
    restart: unless-stopped
```

- [ ] **Step 4: Verify the build, and that the default compose set is unchanged**

```bash
mvn -q -pl core,heimdall,sim install
docker build -f heimdall/Dockerfile -t bifrost/heimdall:dev .
docker compose config --services
docker compose up -d hivemq-ce
docker compose ps --services
docker compose down
```
Expected: the image builds. `config --services` lists `hivemq-ce` and `hivemq-ce-b` (a profiled service is omitted). **`ps --services` after `up -d hivemq-ce` lists only `hivemq-ce`** — that is the load-bearing check; `config` proves the profile parses, not what `up` starts.

- [ ] **Step 5: Commit**

```bash
git add heimdall/Dockerfile .dockerignore docker-compose.yml
git commit -m "build(heimdall): package the edge as a container

Profiled so the existing gates' 'up -d hivemq-ce' still starts only the
broker. The registry is mounted, never baked.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

**Note for Task 14:** nothing here is exercised by a gate. `docker build` succeeding is the whole of this task's evidence, and the docs must not imply more.

---

## Chunk 5: Evidence

### Task 12: `TopicWatcher` — the subscriber the gates never had

**Files:**
- Create: `heimdall/src/main/java/dev/krillin/bifrost/heimdall/TopicWatcher.java`

The repo has a publisher for gates (`RogueNcmd`) and **no subscriber**: `grep` across `scripts/*.sh` finds no `mosquitto_sub`, and Muninn's observer is Sparkplug-group-scoped rather than arbitrary-topic. E2, E3 and the retained-state cleanup in Task 13 all need one. This is the counterpart, in the same shape as `RogueNcmd` so it needs no new dependency.

- [ ] **Step 1: Write the class**

```java
package dev.krillin.bifrost.heimdall;

import java.nio.charset.StandardCharsets;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

/**
 * Gate support: subscribe to one topic and print what arrives, one line per message. The
 * counterpart to {@link RogueNcmd}, which publishes. The gates had no way to observe a topic at
 * all, which is why the status will and the NDATA response detail were previously unassertable.
 *
 * <pre>
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher &lt;topic&gt; [seconds]
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher --clear &lt;topic&gt;
 * </pre>
 *
 * <p>{@code --clear} publishes a zero-length retained message, which is how MQTT deletes a retained
 * value. The gate needs it because a retained "offline" left by a PREVIOUS run would otherwise
 * satisfy this run's assertion that the will fired.
 */
public final class TopicWatcher {

    public static void main(String[] args) throws Exception {
        String broker = System.getenv().getOrDefault("MQTT_URL", "tcp://localhost:1883");
        boolean clear = args.length > 0 && "--clear".equals(args[0]);
        String topic = clear ? args[1] : args[0];
        long seconds = (!clear && args.length > 1) ? Long.parseLong(args[1]) : 60L;

        MqttClient c = new MqttClient(broker, "topic-watcher-" + System.nanoTime(), new MemoryPersistence());
        MqttConnectOptions opts = new MqttConnectOptions();
        opts.setCleanSession(true);
        c.connect(opts);

        if (clear) {
            // Zero-length + retained deletes the retained value for this topic.
            c.publish(topic, new MqttMessage(new byte[0]) {{ setRetained(true); setQos(1); }});
            System.out.println("[WATCH] cleared retained " + topic);
            c.disconnect();
            c.close();
            return;
        }

        c.setCallback(new org.eclipse.paho.client.mqttv3.MqttCallback() {
            @Override public void connectionLost(Throwable cause) { }
            @Override public void deliveryComplete(org.eclipse.paho.client.mqttv3.IMqttDeliveryToken t) { }
            @Override public void messageArrived(String t, MqttMessage m) {
                System.out.println("[WATCH] " + t + " = " + new String(m.getPayload(), StandardCharsets.UTF_8));
                System.out.flush();
            }
        });
        c.subscribe(topic, 1);
        System.out.println("[WATCH] subscribed " + topic);
        System.out.flush();
        Thread.sleep(seconds * 1000L);
        c.disconnect();
        c.close();
    }

    private TopicWatcher() {}
}
```

- [ ] **Step 2: Verify it round-trips against a live broker**

```bash
mvn -q -pl core,heimdall install
docker compose up -d hivemq-ce
java -cp heimdall/target/bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher "test/topic" 10 &
sleep 2
java -cp heimdall/target/bifrost-heimdall.jar dev.krillin.bifrost.heimdall.RogueNcmd "ns=2;s=X" 1.0 Double || true
```
Expected: `[WATCH] subscribed test/topic` appears. (The `RogueNcmd` call publishes elsewhere; the point of this step is only that the watcher connects and prints.) Then confirm a real match by publishing to `test/topic` with a second `TopicWatcher --clear test/topic`, which should print `[WATCH] cleared retained test/topic`.

- [ ] **Step 3: Commit**

```bash
git add heimdall/src/main/java/dev/krillin/bifrost/heimdall/TopicWatcher.java
git commit -m "test(heimdall): add TopicWatcher, the gate-side MQTT subscriber

RogueNcmd could publish and nothing could observe, so a retained status
topic and an NDATA response detail were both unassertable from a gate.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: `run-edge-resilience-gate.sh`

**Files:**
- Create: `scripts/run-edge-resilience-gate.sh`

This is the round's only evidence. Every *built* row on the `ENTERPRISE.md` board names a script that proves it. **Read `scripts/run-ncmd-runtime-gate.sh` in full first** — this gate reuses its `cygpath` shim, `fail()`, `cleanup`/`trap EXIT` pair and `apply_count` verbatim, and extends its `start_bridge` because E6 needs two edges at once.

Three traps this gate has to avoid, each of which would make it green for the wrong reason:

1. **The accumulating log.** `run-ncmd-runtime-gate.sh:143-145` already documents this: greping one file lets an earlier run's line satisfy a later assertion. E1 and E4 must capture `apply_count` **before** and require it to *increase*.
2. **The retained will.** A retained `offline` from a previous run satisfies "an `offline` arrives" with `setWill` deleted. Clear the topic first.
3. **The shutdown hook.** `bridge.close()` now publishes `offline` itself, so a graceful stop proves nothing about the will. E2 must kill with `taskkill //F`, which bypasses the hook.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# EDGE RESILIENCE GATE (R0 acceptance): prove the Heimdall edge survives an unattended night.
# Everything here is asserted by BREAKING something and requiring recovery without human action.
#
#   E1 broker restart : restart HiveMQ; the edge reconnects AND resubscribes. Asserted by a command
#                       APPLIED AFTER the restart (an APPLY *count increase*), because a reconnect
#                       that failed to resubscribe still logs "reconnected" and then hears nothing.
#   E2 death cert     : taskkill //F the edge (bypassing the shutdown hook) and require the BROKER
#                       to deliver the retained will. The topic is cleared first, so a previous
#                       run's retained "offline" cannot satisfy this.
#   E3 outage != deny : kill the OPC-UA sim, send an AUTHORIZED command, require [BRIDGE] UNREACHABLE
#                       and NO [BRIDGE] DENY line, and require the NDATA detail to say
#                       plant-unreachable rather than conformance-error.
#   E4 plant recovery : restart the sim, wait out the 5s backoff, send again -> session re-established
#                       and the APPLY count increases. NO bridge restart in between.
#   E5 health         : /healthz is 200 healthy, 503 while the sim is down, 200 again after recovery.
#   E6 two edges      : a second edge (mixer-edge, its own HEALTH_PORT) coexists on one broker.
#                       Neither may lose its session to the other.
#
# Run from the bifrost repo root (needs Docker Desktop + host ports 1883, 9090, 9091, 48400 free):
#   timeout 900 bash scripts/run-edge-resilience-gate.sh
#   # expect: [GATE] PASS run-edge-resilience-gate.sh ... exit 0
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cygpath >/dev/null 2>&1 || cygpath() { printf '%s\n' "${@: -1}"; }

WORK="build/gate"
mkdir -p "$WORK"
SIM_LOG="$WORK/res-sim.log"
A_LOG="$WORK/res-edge-a.log"
B_LOG="$WORK/res-edge-b.log"
WATCH_LOG="$WORK/res-watch.log"
PUB_LOG="$WORK/res-pub.log"
: > "$PUB_LOG"; : > "$WATCH_LOG"

GROUP="Bifrost:Line1"
EDGE_A="recipe-edge"
EDGE_B="mixer-edge"
RPM_NODE="ns=2;s=Recipe/Rpm"
STATUS_A="bifrost/$GROUP/STATUS/$EDGE_A"

command -v docker >/dev/null 2>&1 || { echo "[GATE] FAIL: docker not found on PATH"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "[GATE] FAIL: curl not found on PATH"; exit 1; }

fail() {
  echo "[GATE] FAIL: $*"
  for f in "$SIM_LOG" "$A_LOG" "$B_LOG" "$WATCH_LOG" "$PUB_LOG"; do
    [ -s "$f" ] && { echo "--- $(basename "$f") tail ---"; tail -50 "$f"; } || true
  done
  exit 1
}

# jps -lm reports the JAR PATH for a `-jar` launch, so two heimdall JVMs are indistinguishable
# there. `jps -v` reports JVM ARGS, so each edge is started with a -D that names it and can be
# killed on its own -- which E6 needs, since it runs two at once.
kill_by_jvmarg() {   # $1 = the -D value substring
  { jps -v 2>/dev/null | grep -F "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}
kill_by_mainclass() {  # $1 = substring of the jps -lm line
  { jps -lm 2>/dev/null | grep -i "$1" || true; } | awk '{print $1}' | while read -r p; do
    taskkill //F //T //PID "$p" >/dev/null 2>&1 || true
  done
}

COMPOSE_WIN="$(cygpath -m "$(pwd)/docker-compose.yml")"

cleanup() {
  kill_by_jvmarg "heimdall.gate=A" || true
  kill_by_jvmarg "heimdall.gate=B" || true
  kill_by_mainclass "bifrost-sim.jar" || true
  kill_by_mainclass "TopicWatcher" || true
  # Leave no retained state that could pre-satisfy the NEXT run of this gate.
  java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher --clear "$STATUS_A" >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE_WIN" stop hivemq-ce >/dev/null 2>&1 || true
}
trap cleanup EXIT

kill_by_jvmarg "heimdall.gate=" || true
kill_by_mainclass "bifrost-sim.jar" || true

# ---------------------------------------------------------------------------
echo "[GATE] step 0: build jars if missing"
if [ ! -f heimdall/target/bifrost-heimdall.jar ] || [ ! -f sim/target/bifrost-sim.jar ]; then
  mvn -q -pl core,heimdall,sim install
fi
HEIMDALL_JAR_WIN="$(cygpath -m "$(pwd)/heimdall/target/bifrost-heimdall.jar")"
SIM_JAR_WIN="$(cygpath -m "$(pwd)/sim/target/bifrost-sim.jar")"
[ -f "$(pwd)/heimdall/registry/policy.json" ] || fail "heimdall/registry/policy.json fixture missing"

export MQTT_URL="tcp://localhost:1883"
export OPCUA_URL="opc.tcp://localhost:48400"
export SPB_GROUP="$GROUP"
export POLICY_PATH="$(cygpath -m "$(pwd)/heimdall/registry/policy.json")"
export REGISTRY_PATH="$(cygpath -m "$(pwd)/heimdall/registry")"
export CONFORMANCE_PATH="$(cygpath -m "$(pwd)/heimdall/registry/conformance/Line1-Mixer/1.0.0.json")"

# ---------------------------------------------------------------------------
echo "[GATE] step 1: broker + sim"
docker compose -f "$COMPOSE_WIN" up -d hivemq-ce >/dev/null 2>&1 || fail "failed to start hivemq-ce"
for i in $(seq 1 30); do bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && break; sleep 2; done
bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 || fail "HiveMQ CE did not open :1883"

start_sim() {
  : > "$SIM_LOG"
  java -jar "$SIM_JAR_WIN" >"$SIM_LOG" 2>&1 &
  for _ in $(seq 1 30); do grep -q "OPC-UA sim listening" "$SIM_LOG" 2>/dev/null && return 0; sleep 2; done
  return 1
}
start_sim || fail "OPC-UA sim did not start"

# Clear any retained status from a previous run BEFORE the edge starts: E2 must observe THIS run's
# will, and a stale retained "offline" would satisfy it with setWill deleted.
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher --clear "$STATUS_A" >>"$WATCH_LOG" 2>&1 || true

# ---------------------------------------------------------------------------
# $1 = gate tag (A|B), $2 = log file, $3 = edge name, $4 = health port
start_edge() {
  : > "$2"
  SPB_EDGE="$3" HEALTH_PORT="$4" \
    java "-Dheimdall.gate=$1" -jar "$HEIMDALL_JAR_WIN" >"$2" 2>&1 &
  for _ in $(seq 1 45); do grep -q "\[BRIDGE\] ready" "$2" 2>/dev/null && return 0; sleep 2; done
  return 1
}

wait_line() {   # $1=file $2=regex $3=tries (2s each)
  for _ in $(seq 1 "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 2; done
  return 1
}

# grep -c PRINTS 0 and EXITS 1 on no match, so `|| echo 0` would print a SECOND zero and break
# every comparison. This is the same shape as run-ncmd-runtime-gate.sh:176.
apply_count() {  # $1=node $2=log
  grep -c "\[BRIDGE\] APPLY cmd=$1 ok=true" "$2" 2>/dev/null || true
}

pub() {  # $1=node $2=value $3=type $4=edge
  MQTT_URL="tcp://localhost:1883" SPB_GROUP="$GROUP" SPB_EDGE="$4" \
    java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.RogueNcmd "$1" "$2" "$3" >>"$PUB_LOG" 2>&1
}

health_code() { curl -s -o /dev/null -w "%{http_code}" "http://localhost:$1/healthz" || echo "000"; }

echo "[GATE] step 2: start edge A"
start_edge A "$A_LOG" "$EDGE_A" 9090 || fail "edge A did not reach '[BRIDGE] ready'"

pub "$RPM_NODE" 1500.0 Double
wait_line "$A_LOG" "\[BRIDGE\] APPLY cmd=$RPM_NODE ok=true" 10 || fail "baseline command was not applied"
[ "$(health_code 9090)" = "200" ] || fail "E5 /healthz is not 200 with both legs up"
echo "[GATE] baseline OK: command applied, /healthz 200"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E1: broker restart is survived without human action ====="
BEFORE="$(apply_count "$RPM_NODE" "$A_LOG")"
docker compose -f "$COMPOSE_WIN" restart hivemq-ce >/dev/null 2>&1 || fail "E1 could not restart the broker"
for i in $(seq 1 30); do bash -c "echo > /dev/tcp/localhost/1883" >/dev/null 2>&1 && break; sleep 2; done
# Paho's auto-reconnect backoff doubles (1s, 2s, 4s...), so allow generously.
wait_line "$A_LOG" "\[BRIDGE\] reconnected to .*resubscribed" 30 || fail "E1 the edge never reported reconnect+resubscribe"
sleep 2
pub "$RPM_NODE" 1500.0 Double
# The load-bearing assertion: a reconnect that did NOT resubscribe still logs "reconnected".
for _ in $(seq 1 15); do [ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] \
  || fail "E1 no NEW command was applied after the broker restart - reconnected but not resubscribed"
echo "[GATE] E1 OK: reconnected, resubscribed, and a new command was applied"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E3: an OPC-UA outage is not a denial ====="
kill_by_mainclass "bifrost-sim.jar"
sleep 3
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher "spBv1.0/$GROUP/NDATA/$EDGE_A" 40 >>"$WATCH_LOG" 2>&1 &
sleep 2
DENY_BEFORE="$(grep -c "\[BRIDGE\] DENY cmd=" "$A_LOG" 2>/dev/null || true)"
pub "$RPM_NODE" 1500.0 Double
wait_line "$A_LOG" "\[BRIDGE\] UNREACHABLE cmd=$RPM_NODE" 15 || fail "E3 the edge did not report UNREACHABLE"
[ "$(grep -c "\[BRIDGE\] DENY cmd=" "$A_LOG" 2>/dev/null || true)" = "$DENY_BEFORE" ] \
  || fail "E3 an outage produced a DENY line - unreachable was reported as a denial"
grep -q "conformance-error" "$A_LOG" && fail "E3 an outage was reported as conformance-error" || true
wait_line "$WATCH_LOG" "plant-unreachable" 10 || fail "E3 the NDATA response detail did not say plant-unreachable"
[ "$(health_code 9090)" = "503" ] || fail "E5 /healthz is not 503 while the plant is unreachable"
echo "[GATE] E3 OK: UNREACHABLE, no DENY, response says plant-unreachable, /healthz 503"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E4: the plant leg recovers with NO bridge restart ====="
BEFORE="$(apply_count "$RPM_NODE" "$A_LOG")"
start_sim || fail "E4 the sim did not restart"
sleep 6      # outlast the 5s reconnect backoff
pub "$RPM_NODE" 1500.0 Double
wait_line "$A_LOG" "OPC-UA session re-established" 15 || fail "E4 the session was never re-established"
for _ in $(seq 1 15); do [ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] && break; sleep 2; done
[ "$(apply_count "$RPM_NODE" "$A_LOG")" -gt "$BEFORE" ] || fail "E4 no NEW command applied after the sim returned"
for _ in $(seq 1 10); do [ "$(health_code 9090)" = "200" ] && break; sleep 2; done
[ "$(health_code 9090)" = "200" ] || fail "E5 /healthz did not return to 200 after recovery"
echo "[GATE] E4+E5 OK: session re-established, new command applied, /healthz back to 200"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E6: two edges coexist on one broker ====="
start_edge B "$B_LOG" "$EDGE_B" 9091 || fail "E6 edge B did not reach '[BRIDGE] ready'"
LOST_A="$(grep -c "connection lost" "$A_LOG" 2>/dev/null || true)"
sleep 15
[ "$(grep -c "connection lost" "$A_LOG" 2>/dev/null || true)" = "$LOST_A" ] \
  || fail "E6 edge A lost its session after edge B started - the client id is shared"
[ "$(grep -c "connection lost" "$B_LOG" 2>/dev/null || true)" = "0" ] \
  || fail "E6 edge B lost its session - the client id is shared"
[ "$(health_code 9091)" != "000" ] || fail "E6 edge B is not serving /healthz - it did not stay up"
echo "[GATE] E6 OK: both edges held their sessions for 15s"
kill_by_jvmarg "heimdall.gate=B"

# ---------------------------------------------------------------------------
echo "[GATE] ===== E2: the broker announces a death the process did not report ====="
java -cp "$HEIMDALL_JAR_WIN" dev.krillin.bifrost.heimdall.TopicWatcher "$STATUS_A" 90 >>"$WATCH_LOG" 2>&1 &
wait_line "$WATCH_LOG" "\[WATCH\] subscribed $STATUS_A" 10 || fail "E2 the watcher did not subscribe"
wait_line "$WATCH_LOG" "STATUS/$EDGE_A = online" 10 || fail "E2 no retained 'online' - the edge never announced itself"
# taskkill //F is a hard kill: the JVM shutdown hook does NOT run, so the "offline" that arrives
# can only have come from the broker publishing our will.
kill_by_jvmarg "heimdall.gate=A"
wait_line "$WATCH_LOG" "STATUS/$EDGE_A = offline" 45 || fail "E2 the broker never published the will"
echo "[GATE] E2 OK: the will fired on a hard kill"

echo ""
echo "[GATE] PASS run-edge-resilience-gate.sh"
exit 0
```

- [ ] **Step 2: Run it**

Run: `timeout 900 bash scripts/run-edge-resilience-gate.sh`
Expected: `[GATE] PASS run-edge-resilience-gate.sh`, exit 0

- [ ] **Step 3: Prove the gate by breaking the code, not by trusting the green**

This repo's standard, stated in `ADOPTION.md` about the log-only work: *"Both directions were checked by injecting the defect rather than by trusting the green."* Do the same, one at a time, reverting each after:

| Injection | Must fail |
|---|---|
| Remove `subscribeAll()` from `connectComplete` | E1 |
| Remove `opts.setWill(...)` | E2 |
| Collapse Task 6's two catches back into one `catch (Exception)` | E3 |
| Make `ensureConnected()` return without reconnecting when `connected` is false | E4 |
| Make `EdgeHealth.healthy()` always return `true` | E5 |
| Restore the constant client id | E6 |

If any injection leaves the gate green, that assertion is not testing what it claims and must be fixed before the round is finished.

- [ ] **Step 4: Run every other gate — this round touched the shell they all run through**

```bash
timeout 600 bash scripts/run-ncmd-runtime-gate.sh
timeout 900 bash scripts/run-yggdrasil-spine-gate.sh
timeout 900 bash scripts/run-yggdrasil-full-loop-gate.sh
```
Expected: all PASS. The runtime gate matters most: T4/T5 restart the edge three times, and Task 2 changed the client id those restarts claim.

- [ ] **Step 5: Commit**

```bash
git add scripts/run-edge-resilience-gate.sh
git commit -m "test(gates): add the edge resilience gate

Kills the broker and the OPC-UA server and requires the edge to come back
without human action, to announce its own death, and to call an outage
plant-unreachable rather than a conformance failure. Each assertion was
checked by injecting its defect.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 14: Say so in the documents

**Files:**
- Modify: `docs/ADOPTION.md`, `README.md`

Only after the gate is green. The board's rule is that a claim names the script that proves it, so nothing here is written before Task 13 passes.

- [ ] **Step 1: Update `ADOPTION.md` phase 4**

In "### 4 — Heimdall in the path", after the log-only paragraph, add a paragraph naming the availability properties and their gate. It must say what is now true and what is still not:

- the edge starts whether or not the plant is up, reconnects to the broker and to the OPC-UA server without human action, and `run-edge-resilience-gate.sh` proves it by killing both
- an unreachable plant is reported as `plant-unreachable` and is visible on `/healthz`, so an outage is not read as a model problem
- **still true and unchanged:** the startup ledger-trust checks fail closed, so a bridge that cannot trust its model still refuses to start, and there is still no break-glass. R0 removed the *unattended* stop-the-line paths; it did not remove that one, and it is R4's.
- **do not claim the container is proven.** Task 11 has no gate; `docker build` succeeding is its whole evidence.

- [ ] **Step 2: Do not touch the gap table**

Nothing in `ADOPTION.md`'s "What the current code cannot do in this plan" table is closed by R0. Add nothing, **strike nothing through**.

- [ ] **Step 3: Update `README.md`**

Two lines go stale and both are in an otherwise-exhaustive list:

- the gate list (`README.md:107-121`) enumerates every script; add `scripts/run-edge-resilience-gate.sh # edge survives broker/OPC-UA loss, announces its own death`
- the build line (`README.md:137`) reads `362 tests (core 223 · heimdall 52 · gates 76 · sim 11)`. Recount heimdall from the actual suite output and update both the total and the heimdall figure.

**Leave `docs/ENTERPRISE.md:13` alone.** It says 352 where the README says 362; that inconsistency predates this round and correcting it here would bury a real edit inside an unrelated one.

- [ ] **Step 4: Commit**

```bash
git add docs/ADOPTION.md README.md
git commit -m "docs: phase 4 survives an unattended night, and what still does not

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Definition of done

- [ ] `mvn -q test` green across the reactor
- [ ] `run-edge-resilience-gate.sh` PASS, and **every one of E1–E6 proved by injecting its defect**
- [ ] `run-ncmd-runtime-gate.sh`, `run-yggdrasil-spine-gate.sh`, `run-yggdrasil-full-loop-gate.sh` still PASS
- [ ] `docker compose up -d hivemq-ce` still starts only the broker (`docker compose ps --services`)
- [ ] An edge started with no OPC-UA server reaches `[BRIDGE] ready` and stays up
- [ ] `docs/ADOPTION.md` phase 4 states the new properties and names the gate; `README.md`'s gate list and test count are current
- [ ] No row on the `ENTERPRISE.md` board changed status — R0 does not claim one

## What R0 explicitly does not fix

Carry these forward; they are the following rounds, and none is closed here.

| | Round |
|---|---|
| The command path has no requester identity, and `CommandAuthorizer` still ignores `Rule.principal()` | R1 |
| `BrokerAclProjector` is still used only by its own unit test | R1 |
| Commands still leave no tamper-evident record — `NcmdOpcUaBridge` has no ledger reference | R2 |
| `OpcUaApplier` still connects anonymously with `SecurityPolicy.None`, so the edge has no identity to present and axis 12 stays open | R3 |
| No break-glass. A bridge that cannot trust its ledger still refuses to start, by design | R4 |
| The container is built but never exercised by a gate | later |
| Huginn decodes Modbus/S7comm while Heimdall guards Sparkplug→OPC UA | separate arc |
