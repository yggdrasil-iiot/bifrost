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
        if (stripeCount < 1) {
            throw new IllegalArgumentException("stripeCount < 1");
        }
        if (queueDepth < 1) {
            throw new IllegalArgumentException("queueDepth < 1");
        }
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

    /**
     * Hand a command to its node's stripe.
     *
     * @return true if accepted; false if this node's stripe queue is full.
     */
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
        for (ThreadPoolExecutor s : stripes) {
            s.shutdownNow();
        }
    }
}
