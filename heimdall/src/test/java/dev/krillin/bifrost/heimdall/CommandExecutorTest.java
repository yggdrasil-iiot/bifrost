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
            for (int i = 0; i < 50; i++) {
                assertEquals(i, seen.get(i), "reordered at " + i);
            }
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
            for (int i = 0; i < 20; i++) {
                if (!ex.submit("n", () -> { })) {
                    rejected.incrementAndGet();
                }
            }
            assertTrue(rejected.get() > 0, "a full bounded queue must reject rather than grow");
            hold.countDown();
        }
    }

    private static void await(CountDownLatch l) {
        try {
            l.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    /** Pick a key on another stripe, so the concurrency test asserts a property and not luck. */
    private static String keyOnADifferentStripe(String other, int stripes) {
        int target = Math.floorMod(other.hashCode(), stripes);
        for (int i = 0; i < 10_000; i++) {
            String c = "node-" + i;
            if (Math.floorMod(c.hashCode(), stripes) != target) {
                return c;
            }
        }
        throw new IllegalStateException("no key on a different stripe");
    }
}
